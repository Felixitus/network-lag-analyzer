"""Network health in the LAN: DHCP and ARP, judged from what was actually seen.

Sources: the capture (ARP claims, DHCP broadcasts, `collectors/lanwatch.py`) and Pi-hole's DHCP
log (`collectors/dhcp_log.py`). Every check says "not measurable" when its source saw nothing -
silence of a source is never reported as "no problem".

Thresholds, from the home network this was built on (45 h of captures, 2026-11-05): a device
that scans the network sent up to ~530 ARP packets a minute, most devices fewer than 30. A
switching loop sends tens of thousands. Roaming between FRITZ!Box and repeater moves an
address to another MAC once; a conflict flips it back and forth.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque

KEEP = 86400
FLIP_WINDOW = 600              # flips of one address within this time ...
FLIPS_CONFLICT = 3             # ... from this many on: two devices use it
ARP_BUSY = 100                 # ARP packets a minute (hourly mean): scans the network, harmless
ARP_STORM = 2000               # a minute, in 3 of the last 5 minutes: a loop or a broken device
OFFERS_MIN = 10                # address requests in 24 h before a low success rate counts
SERVER_KINDS = ("offer", "ack", "nak")
RANK = {"na": 0, "ok": 1, "warning": 2, "problem": 3}

# What to do, per finding. Paths are those of Pi-hole v6 and FRITZ!OS 8.
ADVICE = {
    "dhcp_retry": [
        "Check where the device stands: a weak Wi-Fi signal is the most common reason why answers get "
        "lost. A mesh unit or repeater closer to it, or the 2.4 GHz band, helps.",
        "Restart the device - many recover from a stuck network state that way.",
        "If it keeps failing: give it a fixed address in Pi-hole (Settings → DHCP → Static DHCP "
        "configuration). It then gets the same address every time.",
        "Repeaters and mesh units must work as access points only, without a DHCP server of their own."],
    "decline": [
        "Look for a device with a manually set IP address inside Pi-hole's DHCP range. Move that address "
        "out of the range, or enter it as a fixed address in Pi-hole (Settings → DHCP)."],
    "pool_full": ["Enlarge the address range or shorten the lease time in Pi-hole (Settings → DHCP)."],
    "nak": ["Usually harmless: the device remembered an address from another network (work, hotel). "
            "Only if it repeats every day: forget the Wi-Fi on the device and connect again."],
    "second_server": [
        "Keep one DHCP server - here Pi-hole. Find the other device by its MAC (FRITZ!Box: Home Network "
        "→ Network) and switch off its DHCP server; repeaters and mesh units belong in access point mode.",
        "If it is the FRITZ!Box: Home Network → Network → Network Settings → IPv4 settings → switch off "
        "\"Enable DHCP server\"."],
    "conflict": [
        "One of the two devices most likely has a manually set IP address. Set it to automatic (DHCP), or "
        "choose an address outside Pi-hole's DHCP range.",
        "Restart both devices afterwards so that each gets its own address."],
    "gateway": [
        "If you know the device: check its network settings - VPN, hotspot or sharing software can act "
        "as a router.",
        "If you do not know it: block it in the FRITZ!Box (Home Network → Network → device → block "
        "internet use, or remove it from the Wi-Fi) and change the Wi-Fi password."],
    "storm": [
        "Look for a loop: a cable between two ports of the same switch, or a mesh unit connected by cable "
        "and by Wi-Fi at the same time. Unplug cables one by one until the storm stops.",
        "If the device named above causes it alone: restart it or unplug it."],
}


def check(cid: str, title: str, status: str, summary: str, details: list[str] | None = None,
          source: str = "", advice: list[str] | None = None) -> dict:
    return {"id": cid, "title": title, "status": status, "summary": summary, "details": details or [],
            "source": source, "advice": advice or []}


def _advice(*keys: str) -> list[str]:
    out: list[str] = []
    for k in keys:
        out += [a for a in ADVICE[k] if a not in out]
    return out


class LanHealth:
    def __init__(self) -> None:
        self.since: float | None = None                       # first capture observation
        self.owner: dict[str, tuple[str, float]] = {}         # ip → (mac, last seen)
        self.flips: dict[str, deque] = defaultdict(deque)     # ip → (ts, old mac, new mac)
        self.arp_minutes: dict[int, Counter] = {}             # minute → packets per mac
        self.servers: dict[str, dict] = {}                    # DHCP server → what it sent
        self.dropped = 0

    # ------------------------------------------------------------------ input
    def observe(self, obs: dict, now: float) -> None:
        if self.since is None:
            self.since = now
        for ip, mac, ts in sorted(obs.get("arp") or [], key=lambda r: r[2]):
            last = self.owner.get(ip)
            if last and last[0] != mac:
                self.flips[ip].append((ts, last[0], mac))
            self.owner[ip] = (mac, ts)
        minute = int(now // 60)
        c = self.arp_minutes.setdefault(minute, Counter())
        c.update(obs.get("arp_n") or {})
        for ts, kind, _client, server, src_mac, src_ip, _offered in obs.get("dhcp") or []:
            if kind not in SERVER_KINDS:
                continue
            key = server or src_ip
            s = self.servers.setdefault(key, {"first": ts, "mac": src_mac, "n": Counter()})
            s["last"], s["mac"] = ts, src_mac
            s["n"][kind] += 1
        self.dropped += obs.get("dropped") or 0
        self._prune(now)

    def _prune(self, now: float) -> None:
        cut = now - KEEP
        for ip in [ip for ip, (_, t) in self.owner.items() if t < cut]:
            del self.owner[ip]
        for ip in list(self.flips):
            q = self.flips[ip]
            while q and q[0][0] < cut:
                q.popleft()
            if not q:
                del self.flips[ip]
        for m in [m for m in self.arp_minutes if m < now // 60 - 60]:
            del self.arp_minutes[m]
        for k in [k for k, s in self.servers.items() if s.get("last", s["first"]) < cut]:
            del self.servers[k]

    # ------------------------------------------------------------------ verdicts
    def conflicts(self, router_macs: set[str]) -> list[dict]:
        out = []
        for ip, q in self.flips.items():
            flips = [f for f in q if not (f[1] in router_macs and f[2] in router_macs)]
            for i in range(len(flips)):
                window = [f for f in flips[i:] if f[0] - flips[i][0] <= FLIP_WINDOW]
                if len(window) >= FLIPS_CONFLICT:
                    macs = sorted({m for f in window for m in f[1:]})
                    out.append({"ip": ip, "macs": macs, "last": flips[-1][0], "flips": len(flips)})
                    break
        return out

    def arp_rates(self, now: float) -> tuple[dict[str, float], dict[str, int]]:
        """Mean ARP packets a minute per device over the last hour, and minutes over ARP_STORM
        within the last five."""
        cur = int(now // 60)
        minutes = [m for m in self.arp_minutes if m < cur]       # only complete minutes
        total: Counter = Counter()
        for m in minutes:
            total.update(self.arp_minutes[m])
        mean = {mac: n / len(minutes) for mac, n in total.items()} if minutes else {}
        storm: Counter = Counter()
        for m in minutes:
            if m >= cur - 5:
                for mac, n in self.arp_minutes[m].items():
                    if n >= ARP_STORM:
                        storm[mac] += 1
        return mean, dict(storm)

    def checks(self, now: float, *, gateway: str | None, gateway_mac: str | None, router_macs: set[str],
               name, dhcp_events: list[tuple] | None, dhcp_since: float | None, dhcp_error: str | None,
               capture_running: bool) -> list[dict]:
        routers = set(router_macs) | ({gateway_mac} if gateway_mac else set())
        cap_na = None if capture_running and self.since is not None else (
            "The capture is not running, so ARP and DHCP in the network cannot be seen.")
        return [self._dhcp_clients(dhcp_events, dhcp_error, name),
                self._dhcp_servers(cap_na, name),
                self._conflicts(cap_na, routers, name),
                self._gateway(cap_na, gateway, gateway_mac, routers, name),
                self._arp(cap_na, now, routers, name)]

    def _dhcp_clients(self, events, error, name) -> dict:
        title = "Address requests"
        src = "Pi-hole DHCP log"
        if error:
            return check("dhcp_clients", title, "na", f"Pi-hole's log cannot be read: {error}", source=src)
        if not events:
            return check("dhcp_clients", title, "na",
                         "Pi-hole's log shows no DHCP in the last 24 h - another device (usually the "
                         "FRITZ!Box) probably hands out the addresses.", source=src)
        per: dict[str, Counter] = defaultdict(Counter)
        pool_full = 0
        for _ts, kind, mac, _ip, note in events:
            per[mac][kind] += 1
            if "no address available" in note:
                pool_full += 1
        details, status, found = [], "ok", []
        if pool_full:
            status = "problem"
            found.append("pool_full")
            details.append(f"{pool_full} times no address was free: the address pool is full.")
        for mac, n in sorted(per.items(), key=lambda kv: -kv[1]["discover"]):
            label = name(mac)
            if n["decline"]:
                status = "problem"
                found.append("decline")
                details.append(f"{label} refused its address {n['decline']} times: another device already "
                               "uses it.")
            if n["discover"] >= OFFERS_MIN and n["ack"] < n["discover"] / 2:
                status = max(status, "warning", key=RANK.get)
                found.append("dhcp_retry")
                details.append(f"{label} asked {n['discover']} times for an address and received one "
                               f"{n['ack']} times. Pi-hole's answers seem not to reach it, or it takes an "
                               "address from another DHCP server.")
            if n["nak"]:
                status = max(status, "warning", key=RANK.get)
                found.append("nak")
                details.append(f"{label}: Pi-hole refused a requested address {n['nak']} times (the device "
                               "asked for one from another network, e.g. after a change of network).")
        devices = len(per)
        acks = sum(n["ack"] for n in per.values())
        summary = (f"{devices} devices asked, {acks} addresses handed out in 24 h"
                   + ("; no device had trouble getting one." if status == "ok" else "."))
        return check("dhcp_clients", title, status, summary, details, src, _advice(*found))

    def _dhcp_servers(self, cap_na, name) -> dict:
        title, src = "DHCP servers", "Capture (broadcasts only)"
        if cap_na:
            return check("dhcp_servers", title, "na", cap_na, source=src)
        if not self.servers:
            return check("dhcp_servers", title, "na",
                         "No DHCP answer seen yet. Answers sent straight to a device do not pass the "
                         "capture, so this check only sees servers that answer by broadcast.", source=src)
        rows = []
        for ip, s in self.servers.items():
            n = sum(s["n"].values())
            rows.append(f"{ip} ({name(s['mac'])}): {n} answer{'s' if n != 1 else ''}")
        if len(self.servers) > 1:
            return check("dhcp_servers", title, "problem",
                         f"{len(self.servers)} DHCP servers answer. Devices take whichever is first and can "
                         "get a wrong router or DNS server - usually a repeater or second router with its "
                         "DHCP still on.", rows, src, _advice("second_server"))
        return check("dhcp_servers", title, "ok", "One DHCP server answers.", rows, src)

    def _conflicts(self, cap_na, routers, name) -> dict:
        title, src = "Address conflicts", "Capture (ARP)"
        if cap_na:
            return check("ip_conflicts", title, "na", cap_na, source=src)
        found = self.conflicts(routers)
        if not found:
            return check("ip_conflicts", title, "ok",
                         f"No address used by two devices ({len(self.owner)} addresses seen).", source=src)
        rows = [f"{c['ip']}: " + " and ".join(name(m) for m in c["macs"]) + f" ({c['flips']} changes)"
                for c in found]
        return check("ip_conflicts", title, "problem",
                     f"{len(found)} address{'es are' if len(found) > 1 else ' is'} used by two devices at once. "
                     "Both lose connections while they take it from each other.", rows, src, _advice("conflict"))

    def _gateway(self, cap_na, gateway, gateway_mac, routers, name) -> dict:
        title, src = "Router address", "Capture (ARP)"
        if cap_na:
            return check("gateway", title, "na", cap_na, source=src)
        if not gateway or not gateway_mac:
            return check("gateway", title, "na", "The router's address or MAC is not known yet.", source=src)
        # the FRITZ!Box may answer with more than one MAC of its own
        others = sorted({f[2] for f in self.flips.get(gateway, ()) if f[2] not in routers}
                        | ({self.owner[gateway][0]} if gateway in self.owner
                           and self.owner[gateway][0] not in routers else set()))
        if others:
            return check("gateway", title, "problem",
                         f"Another device answered for the router's address {gateway}. Devices then send "
                         "their internet traffic to it: a misconfigured device, or someone reading along.",
                         [name(m) for m in others], src, _advice("gateway"))
        if gateway not in self.owner:
            return check("gateway", title, "na", f"No ARP answer for {gateway} seen yet.", source=src)
        return check("gateway", title, "ok", f"Only the router answers for {gateway}.", source=src)

    def _arp(self, cap_na, now, routers, name) -> dict:
        title, src = "ARP traffic", "Capture (ARP)"
        if cap_na:
            return check("arp_rate", title, "na", cap_na, source=src)
        mean, storm = self.arp_rates(now)
        if not mean:
            return check("arp_rate", title, "na", "Less than a minute measured.", source=src)
        if storm:
            return check("arp_rate", title, "problem",
                         "ARP storm: thousands of packets a minute. Usually a network loop (a cable plugged "
                         "in twice, two connected repeaters) or a broken device.",
                         [f"{name(m)}: over {ARP_STORM} a minute in {n} of the last 5 minutes"
                          for m, n in storm.items()], src, _advice("storm"))
        busy = sorted(((n, m) for m, n in mean.items() if n >= ARP_BUSY and m not in routers), reverse=True)
        details = [f"{name(m)}: {n:.0f} a minute (mean of the last hour). It checks which devices are present, "
                   "as mesh systems, smart home hubs and network apps do - nothing to do." for n, m in busy]
        return check("arp_rate", title, "ok", f"Normal: {sum(mean.values()):.0f} ARP packets a minute in total.",
                     details, src)


def overall(checks: list[dict]) -> str:
    return max((c["status"] for c in checks), key=RANK.get, default="na")
