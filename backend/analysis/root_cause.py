"""Root cause analysis (root cause rules).

Each rule is a separate function `rule_*` with documented logic. A rule receives a
`Window` (all measurements around the incident) and returns either None (does not
apply) or a `Finding` with a score and a list of evidence.

The rule with the highest score is chosen as the cause. The confidence is derived
from the score and deliberately worded cautiously:

    score >= 80  → high   → "likely cause"
    score >= 55  → medium → "possible cause"
    otherwise    → low    → "temporally correlated"

Principles:
* Do not fake causality: simultaneity alone yields at most "low".
* A device is only named if traffic per device was actually measured.
* Missing data sources are stated explicitly in `notes`.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Callable

from . import bufferbloat
from .events import (CONNECTION_DROP, DNS_FAILURE)

CATEGORY_LABELS = {
    "upload": "Upload saturation / bufferbloat",
    "download": "Download saturation / bufferbloat",
    "local": "LAN/Wi-Fi/router problem",
    "wan": "WAN/ISP problem",
    "target": "Target server/routing",
    "game_server": "Game server/routing",
    "loss": "Packet loss/transmission problems",
    "dns": "DNS disruption",
    "drop_wan": "Internet outage (WAN)",
    "drop_local": "Connection loss in the LAN",
    "unknown": "Unknown",
}
CONFIDENCE_LABELS = {"high": "likely cause", "medium": "possible cause",
                     "low": "temporally correlated"}

TARGET_DELTA_MS = 25.0       # from this increase on a target counts as "affected"
UTIL_HIGH = 0.6              # utilization from which a line counts as "highly utilized"
DOMINANT_SHARE = 0.6         # share of total traffic from which a device dominates


# =============================================================================== data model
@dataclass
class Window:
    rows: list[dict]                   # 1 s rows [t0 - pre, t1 + post]
    t0: int                            # start of the anomaly
    t1: int                            # end of the anomaly
    targets: dict[int, dict]           # target_id → {"address", "name", "kind"}
    events: list[dict] = field(default_factory=list)
    cap_down: float | None = None      # bit/s
    cap_up: float | None = None
    cap_source: str | None = None      # config | tr064 | learned
    thresholds: object | None = None
    device_label: Callable[[str], dict] = lambda mac: {"mac": mac, "name": mac, "ip": None}
    gaming: dict | None = None         # active gaming session (server_ip, mac, …)

    # ---- derived values (lazy) ----
    def pre(self) -> list[dict]:
        return [r for r in self.rows if r["ts"] < self.t0]

    def inside(self) -> list[dict]:
        return [r for r in self.rows if self.t0 <= r["ts"] <= self.t1]

    def around(self, before: int = 10) -> list[dict]:
        return [r for r in self.rows if self.t0 - before <= r["ts"] <= self.t1]

    @property
    def traffic_available(self) -> bool:
        return any(r.get("up_bps") is not None for r in self.inside())

    @property
    def per_device_available(self) -> bool:
        return any((r.get("traffic_src") or "").startswith("capture") for r in self.inside())

    def events_of(self, *types: str) -> list[dict]:
        return [e for e in self.events if e["type"] in types]


@dataclass
class Finding:
    rule: str
    category: str
    score: int
    cause: str
    evidence: list[str]
    device: dict | None = None
    details: dict = field(default_factory=dict)


# =============================================================================== helpers
def _med(vals: list[float | None]) -> float | None:
    v = [x for x in vals if x is not None]
    return statistics.median(v) if v else None


def _max(vals: list[float | None]) -> float | None:
    v = [x for x in vals if x is not None]
    return max(v) if v else None


def _mbit(bps: float | None) -> str:
    return "n/a" if bps is None else f"{bps / 1e6:.1f} Mbit/s"


def _gw_threshold(w: Window) -> float:
    t = w.thresholds
    base = _med([r.get("gw_rtt") for r in w.pre()]) or 1.0
    return max(getattr(t, "gateway_warning", 20.0), base * 3 + 2)


def gateway_stats(w: Window) -> dict:
    ins = w.inside()
    return {
        "before": _med([r.get("gw_rtt") for r in w.pre()]),
        "peak": _max([r.get("gw_rtt") for r in ins]),
        "lost": sum(r.get("gw_lost") or 0 for r in ins),
        "probes": sum(r.get("gw_probes") or 0 for r in ins),
    }


def gateway_stable(w: Window) -> bool | None:
    g = gateway_stats(w)
    if g["probes"] == 0:
        return None
    return (g["peak"] is None or g["peak"] < _gw_threshold(w)) and g["lost"] == 0


def target_impact(w: Window) -> dict[int, dict]:
    """Per internet/game target: baseline, peak, losses, affected yes/no."""
    out: dict[int, dict] = {}
    for tid, info in w.targets.items():
        if info["kind"] == "gateway":
            continue
        pre = [r["targets"].get(tid, {}).get("rtt") for r in w.pre() if r.get("targets")]
        ins = [r["targets"].get(tid, {}) for r in w.inside() if r.get("targets")]
        base = _med(pre)
        peak = _max([x.get("max") for x in ins])
        lost = sum(x.get("lost") or 0 for x in ins)
        probes = sum(x.get("probes") or 0 for x in ins)
        if probes == 0:
            continue
        elevated = peak is not None and base is not None and peak - base >= TARGET_DELTA_MS and peak >= base * 1.8
        out[tid] = {"address": info["address"], "name": info.get("name"), "kind": info["kind"], "base": base,
                    "peak": peak, "lost": lost, "probes": probes, "affected": elevated or lost > 0,
                    "elevated": elevated}
    return out


def utilization(w: Window, direction: str) -> tuple[list[float], float | None]:
    """Utilization per second in the incident (0..1) relative to the capacity."""
    cap = w.cap_up if direction == "up" else w.cap_down
    key = "up_bps" if direction == "up" else "down_bps"
    if not cap:
        return [], None
    vals = [r[key] / cap for r in w.inside() if r.get(key) is not None]
    return vals, (max(vals) if vals else None)


def device_rates(w: Window, rows: list[dict], direction: str) -> dict[str, list[tuple[int, float]]]:
    """mac → [(ts, bit/s)] for upload (tx) or download (rx)."""
    idx = 1 if direction == "up" else 0
    out: dict[str, list[tuple[int, float]]] = {}
    for r in rows:
        for mac, v in (r.get("devices") or {}).items():
            out.setdefault(mac, []).append((r["ts"], v[idx] * 8.0))
    return out


def top_device(w: Window, direction: str) -> tuple[str | None, float, float]:
    """(mac, share of total traffic in the incident, peak rate) of the strongest device."""
    rates = device_rates(w, w.inside(), direction)
    if not rates:
        return None, 0.0, 0.0
    totals = {m: sum(v for _, v in s) for m, s in rates.items()}
    grand = sum(totals.values())
    if grand <= 0:
        return None, 0.0, 0.0
    mac = max(totals, key=totals.get)
    return mac, totals[mac] / grand, max(v for _, v in rates[mac])


def onset(w: Window, series: list[tuple[int, float]], level: float) -> int | None:
    """Start of the contiguous section >= level that touches the incident start."""
    by_ts = dict(series)
    t = None
    s = w.t0 + 1
    # search backwards from the incident start
    for ts in range(s, w.t0 - 60, -1):
        if by_ts.get(ts, 0.0) >= level:
            t = ts
        elif t is not None:
            break
    if t is not None:
        return t
    # otherwise: first point in time inside the incident
    for ts in range(w.t0, w.t1 + 1):
        if by_ts.get(ts, 0.0) >= level:
            return ts
    return None


def latency_onset(w: Window) -> int:
    """First second in which the internet RTT was clearly above the baseline or loss occurred."""
    base = _med([r.get("rtt_avg") for r in w.pre()])
    for r in w.around(0):
        rtt = r.get("rtt_avg")
        if (r.get("lost") or 0) > 0 or (rtt is not None and base is not None and rtt - base >= TARGET_DELTA_MS):
            return r["ts"]
    return w.t0


def _confidence(score: int) -> str:
    return "high" if score >= 80 else "medium" if score >= 55 else "low"


# =============================================================================== rules
def _saturation_rule(w: Window, direction: str) -> Finding | None:
    """Shared logic for upload and download saturation (bufferbloat).

    Background: if one direction of the line is fully utilized, the buffers in the
    router/modem fill up and ALL packets (game packets and pings too) wait.
    Typical: router ping stays low, all internet targets rise at the same time.

    Evidence and points:
      E1 (required, 40) direction >= 60 % utilized in the incident (at least half of the seconds)
      E2 (20)           traffic increase started before or with the latency increase
      E3 (15)           router latency stayed stable (speaks against a LAN/Wi-Fi problem)
      E4 (10)           several internet targets affected at once (common bottleneck)
      E5 (15)           one device causes >= 60 % of the traffic → it is named
    """
    utils, peak_util = utilization(w, direction)
    name = "Upload" if direction == "up" else "Download"
    key = "up_bps" if direction == "up" else "down_bps"
    if peak_util is None:
        return None
    high_secs = sum(1 for u in utils if u >= UTIL_HIGH)
    if not utils or high_secs < max(1, len(utils) / 2):
        return None
    score = 40
    ev = [f"{name} utilization up to {peak_util * 100:.0f} % of the line "
          f"({_mbit(_max([r.get(key) for r in w.inside()]))} of {_mbit(w.cap_up if direction == 'up' else w.cap_down)}"
          f"{', capacity estimated' if w.cap_source == 'learned' else ''})"]
    cap = w.cap_up if direction == "up" else w.cap_down
    total_series = [(r["ts"], r.get(key) or 0.0) for r in w.rows]
    lat_on = latency_onset(w)
    t_on = onset(w, total_series, cap * UTIL_HIGH * 0.8)
    if t_on is not None and t_on <= lat_on + 1:
        score += 20
        ev.append(f"{name} increase started {'before' if t_on < lat_on else 'together with'} the latency increase "
                  f"({lat_on - t_on} s earlier)" if t_on < lat_on else f"{name} increase at the same time as the latency increase")
    if high_secs >= len(utils) * 0.8:
        ev.append(f"{name} stayed high for almost the entire incident")
    gs = gateway_stable(w)
    if gs:
        score += 15
        ev.append("Router latency stayed stable")
    impacted = [t for t in target_impact(w).values() if t["affected"] and t["kind"] == "internet"]
    if len(impacted) >= 2:
        score += 10
        ev.append(f"{len(impacted)} external targets showed increased latency/loss at the same time")
    device = None
    if w.per_device_available:
        mac, share, dev_peak = top_device(w, direction)
        if mac and share >= DOMINANT_SHARE:
            score += 15
            device = {**w.device_label(mac), "share": round(share, 2), "peak_bps": dev_peak}
            ev.append(f"{device['name']} caused {share * 100:.0f} % of the {name.lower()} (peak {_mbit(dev_peak)})")
            dev_on = onset(w, device_rates(w, w.rows, direction).get(mac, []), dev_peak * 0.5)
            if dev_on is not None:
                device["onset"] = dev_on
        elif mac:
            ev.append(f"No single device dominates (strongest: {w.device_label(mac)['name']} with {share * 100:.0f} %)")
    cause = f"{name} saturation" + (f" by {device['name']}" if device else "")
    if not w.per_device_available:
        cause += " (device not identifiable - no traffic per device available)"
    return Finding(f"rule_{direction}load_saturation", "upload" if direction == "up" else "download",
                   score, cause, ev, device, {"peak_util": round(peak_util, 3), "onset": t_on})


def rule_upload_saturation(w: Window) -> Finding | None:
    """High upload of a device + internet ping/jitter high at the same time → upload saturation/bufferbloat."""
    return _saturation_rule(w, "up")


def rule_download_saturation(w: Window) -> Finding | None:
    """High download + ping spike → download saturation/bufferbloat."""
    return _saturation_rule(w, "down")


def rule_local_problem(w: Window) -> Finding | None:
    """Gateway ping high + internet ping high → possible LAN/Wi-Fi/router problem.

    The router is only one hop away. If its latency already rises (or it does
    not answer), the problem lies before the internet connection: LAN, Wi-Fi,
    router CPU - or the connection of the Raspberry Pi itself.
      required (50) router latency above threshold or router losses
      +20           internet targets affected at the same time
      +15           router increase did not start after the internet increase
    Deduction -25 if a line is heavily utilized at the same time (a busy
    router often answers ICMP with a delay).
    """
    g = gateway_stats(w)
    if g["probes"] == 0:
        return None
    thr = _gw_threshold(w)
    bad = (g["peak"] is not None and g["peak"] >= thr) or g["lost"] > 0
    if not bad:
        return None
    score = 50
    ev = [f"Router latency {g['before'] or 0:.1f} → {g['peak'] or 0:.1f} ms"
          + (f", {g['lost']}/{g['probes']} router probes lost" if g["lost"] else "")]
    impacted = [t for t in target_impact(w).values() if t["affected"]]
    if impacted:
        score += 20
        ev.append("Internet targets affected at the same time")
    gw_series = [(r["ts"], r.get("gw_rtt") or (thr if (r.get("gw_lost") or 0) else 0.0)) for r in w.rows]
    gw_on = onset(w, gw_series, thr)
    if gw_on is not None and gw_on <= latency_onset(w):
        score += 15
        ev.append("Router latency rose first or at the same time")
    for d in ("up", "down"):
        _, pu = utilization(w, d)
        if pu is not None and pu >= 0.85:
            score -= 25
            ev.append(f"Caution: {'upload' if d == 'up' else 'download'} heavily utilized at the same time - "
                      "the router might answer pings slowly only because of the load")
    ev.append("Note: measured from the Raspberry Pi - its own LAN/Wi-Fi connection may be affected too")
    return Finding("rule_local_problem", "local", score, "LAN/Wi-Fi or router problem", ev)


def rule_wan_isp(w: Window) -> Finding | None:
    """Gateway normal + internet ping high → WAN/ISP/bufferbloat possible.

    The router answers normally, but several external targets are bad at once and
    your own line is not utilized → bottleneck behind the router (connection/ISP).
      required (45) router stable AND at least 2 internet targets affected
      +15           all internet targets affected
      +10           no line above 50 % utilization (own traffic unlikely)
      +10           retransmissions in download direction increased (losses before the router)
    """
    if not gateway_stable(w):
        return None
    ti = [t for t in target_impact(w).values() if t["kind"] == "internet"]
    impacted = [t for t in ti if t["affected"]]
    if len(impacted) < 2:
        return None
    score = 45
    ev = ["Router latency stayed stable",
          f"{len(impacted)} of {len(ti)} external targets affected: " +
          ", ".join(f"{t['name'] or t['address']}" for t in impacted)]
    if len(impacted) == len(ti):
        score += 15
    utils = [utilization(w, d)[1] for d in ("up", "down")]
    if all(u is not None for u in utils) and max(utils) < 0.5:
        score += 10
        ev.append("Own line not utilized - bottleneck probably at the connection/ISP")
    elif all(u is None for u in utils):
        ev.append("Line utilization unknown - upload/download saturation cannot be ruled out")
    rd = sum(r.get("retrans_down") or 0 for r in w.inside())
    if rd >= 5:
        score += 10
        ev.append(f"{rd} TCP retransmissions from the internet (losses before the router)")
    return Finding("rule_wan_isp", "wan", score, "WAN/ISP problem or bufferbloat at the connection", ev)


def rule_multi_target_loss(w: Window) -> Finding | None:
    """Several external targets with packet loss at once → WAN/ISP more likely than a single server.

      required (55) losses at >= 2 internet targets in the same second, router without loss
      +15           occurred in several seconds
      +10           router latency stable
    """
    ids = [tid for tid, i in w.targets.items() if i["kind"] == "internet"]
    multi_secs = 0
    for r in w.inside():
        lost_targets = sum(1 for tid in ids if (r.get("targets") or {}).get(tid, {}).get("lost"))
        if lost_targets >= 2:
            multi_secs += 1
    g = gateway_stats(w)
    if multi_secs == 0 or g["lost"] > 0:
        return None
    score = 55 + (15 if multi_secs >= 2 else 0)
    ev = [f"Packet loss at several external targets at once in {multi_secs} second(s)",
          "Router without packet loss"]
    if gateway_stable(w):
        score += 10
    # Own saturation can cause losses as well → deduction
    for d in ("up", "down"):
        _, pu = utilization(w, d)
        if pu is not None and pu >= 0.85:
            score -= 30
            ev.append(f"{'Upload' if d == 'up' else 'Download'} heavily utilized at the same time - losses possibly caused by own traffic")
    return Finding("rule_multi_target_loss", "wan", score, "Packet loss behind the router (WAN/ISP)", ev)


def rule_single_target(w: Window) -> Finding | None:
    """Gateway normal + internet normal + a single target problematic → target server/routing problem possible.
    Only one external target affected → routing/target server more likely.

      required (50) exactly one target affected, all others normal, router stable
      +10           the target had packet loss
      +10           the target is the game server
    """
    ti = target_impact(w)
    impacted = [t for t in ti.values() if t["affected"]]
    normal = [t for t in ti.values() if not t["affected"]]
    if len(impacted) != 1 or not normal or gateway_stable(w) is False:
        return None
    t = impacted[0]
    score = 50
    ev = [f"Only {t['name'] or t['address']} affected "
          f"({(t['base'] or 0):.0f} → {(t['peak'] or 0):.0f} ms, {t['lost']}/{t['probes']} lost)",
          f"{len(normal)} other targets normal", "Router latency stable"]
    if t["lost"]:
        score += 10
    cat = "target"
    if t["kind"] == "game":
        score += 10
        cat = "game_server"
    return Finding("rule_single_target", cat, score,
                   f"Problem at the target {t['name'] or t['address']} or the routing to it", ev)


def rule_tcp_retransmissions(w: Window) -> Finding | None:
    """TCP retransmissions strongly increased → possible packet loss/transmission problems.

    Retransmissions are an indirect loss signal. The direction helps:
    * download direction (server resends): loss between server and router
    * upload direction (client resends): loss on the upload or in the LAN/Wi-Fi
      required (35) >= 3 % retransmissions with >= 50 data segments
      +10           ICMP losses at the same time
    """
    segs = sum(r.get("tcp_segs") or 0 for r in w.inside())
    rd = sum(r.get("retrans_down") or 0 for r in w.inside())
    ru = sum(r.get("retrans_up") or 0 for r in w.inside())
    if segs < 50 or (rd + ru) / segs < 0.03:
        return None
    score = 35
    ev = [f"{(rd + ru) / segs * 100:.1f} % TCP retransmissions ({rd} from the internet, {ru} from LAN devices)"]
    if sum(r.get("lost") or 0 for r in w.inside()) > 0:
        score += 10
        ev.append("ICMP packet loss at the same time")
    where = "between internet servers and router" if rd >= ru else "in the upload or LAN/Wi-Fi"
    return Finding("rule_tcp_retransmissions", "loss", score, f"Packet loss/transmission problems ({where})", ev)


def rule_game_server(w: Window) -> Finding | None:
    """Router and internet normal, but the game connection has problems → game server/routing (case C).

    Only evaluable during a gaming session (otherwise it is not known whether the
    observed UDP stream is a game at all). Signal: gaps in the downstream of the
    game flow (no packets from the server) or increased ICMP RTT to the game server,
    while all reference targets are normal.
      required (55) game packet gap or game RTT increase, reference targets normal, router stable
      +10           gap >= 500 ms
    """
    if not w.gaming:
        return None          # without a running session no game flow was observed
    ins = w.inside()
    gaps = [r.get("game_gap_ms") for r in ins if r.get("game_gap_ms") is not None]
    game_rtt_pre = _med([r.get("game_rtt") for r in w.pre()])
    game_rtt_peak = _max([r.get("game_rtt") for r in ins])
    thr = getattr(w.thresholds, "game_gap_ms", 250)
    gap_bad = bool(gaps) and max(gaps) >= thr
    rtt_bad = game_rtt_pre is not None and game_rtt_peak is not None and game_rtt_peak - game_rtt_pre >= TARGET_DELTA_MS
    if not (gap_bad or rtt_bad):
        return None
    inet = [t for t in target_impact(w).values() if t["kind"] == "internet"]
    if any(t["affected"] for t in inet) or gateway_stable(w) is False:
        return None
    score = 55
    ev = ["Reference targets (internet) and router normal"]
    if gap_bad:
        ev.append(f"Game flow: up to {max(gaps):.0f} ms without packets from the server")
        if max(gaps) >= 500:
            score += 10
    if rtt_bad:
        ev.append(f"Ping to the game server {game_rtt_pre:.0f} → {game_rtt_peak:.0f} ms")
    srv = (w.gaming or {}).get("server_ip")
    return Finding("rule_game_server", "game_server", score,
                   "Problem at the game server or in the routing to it" + (f" ({srv})" if srv else ""), ev)


def rule_dns_failure(w: Window) -> Finding | None:
    """DNS failure with normal reachability → DNS problem (no in-game lag).

      required (60) DNS probes failed, ICMP targets reachable without loss
      +15           only the local resolver (Pi-hole) affected → check Pi-hole/Pi
    """
    dns = [x for r in w.around(5) for x in (r.get("dns") or [])]
    fails = [x for x in dns if x[1] is None or x[2] == "servfail"]
    if not fails and not w.events_of(DNS_FAILURE):
        return None
    if sum(r.get("lost") or 0 for r in w.inside()) > 0:
        return None
    failed_servers = sorted({x[0] for x in fails} | {e.get("target") for e in w.events_of(DNS_FAILURE) if e.get("target")})
    ok_servers = sorted({x[0] for x in dns if x[1] is not None} - set(failed_servers))
    score = 60
    ev = [f"DNS queries failed at: {', '.join(failed_servers)}", "ICMP reachability normal"]
    cause = "DNS disruption"
    # If only the uncached probe failed, the resolver still works, but resolution
    # to the outside does not - that is the upstream, not Pi-hole.
    kinds = {x[3] for x in fails if len(x) > 3}
    if kinds == {"uncached"}:
        cause = "DNS disruption at the upstream resolver"
        ev.append("Cached answers kept coming - the local resolver is running, "
                  "resolution to the outside is not")
    elif failed_servers == ["127.0.0.1"] or (ok_servers and all(s != "127.0.0.1" for s in ok_servers)):
        score += 15
        cause = "DNS disruption of the local resolver (Pi-hole)"
        ev.append("Upstream DNS worked → check Pi-hole/FTL")
    ev.append("DNS does not affect a running game connection, but connection setup/matchmaking")
    return Finding("rule_dns_failure", "dns", score, cause, ev)


def rule_connection_drop(w: Window) -> Finding | None:
    """Complete loss of connection.

    * router still reachable → internet connection down (WAN/ISP), 75 points
    * router not reachable either → connection loss in the LAN (or Pi), 70 points
    """
    drops = w.events_of(CONNECTION_DROP)
    if not drops:
        return None
    g = gateway_stats(w)
    dur = sum(((e.get("ts_end") or w.t1) - e["ts_start"] + 1) for e in drops)
    if g["probes"] and g["lost"] < g["probes"] * 0.5:
        return Finding("rule_connection_drop", "drop_wan", 75, "Internet outage (router reachable, internet not)",
                       [f"All external targets unreachable for {dur:.0f} s", "Router kept answering"])
    return Finding("rule_connection_drop", "drop_local", 70, "Connection loss in the LAN/to the router",
                   [f"All external targets unreachable for {dur:.0f} s", "The router did not answer either"])


RULES: list[Callable[[Window], Finding | None]] = [
    rule_upload_saturation,
    rule_download_saturation,
    rule_local_problem,
    rule_wan_isp,
    rule_multi_target_loss,
    rule_single_target,
    rule_tcp_retransmissions,
    rule_game_server,
    rule_dns_failure,
    rule_connection_drop,
]


# =============================================================================== recommendations
# Every category comes with a concrete action - the diagnosis alone does not help.
# `scope` says honestly whether it can be fixed by yourself at all:
#   self     → in your own hands (device, router, Wi-Fi)
#   provider → only the internet provider can change it
#   remote   → lies with the target server/routing, cannot be fixed locally
RECOMMENDATIONS: dict[str, dict] = {
    "upload": {
        "scope": "self",
        "headline": "Limit the upload or prioritize the game",
        "steps": [
            "FRITZ!Box → Internet → Filters → Prioritization: add {device_or_gamer} as a \"real-time application\". "
            "On the upload the queue sits in your own router, so prioritization really works here.",
            "Throttle or pause {uploader} while gaming "
            "(cloud backup, video upload, streaming, seeding).",
            "Permanently: limit the upload rate of the causing application to about 80 % of the line - "
            "a 100 % full upload causes the lag, not the amount of data itself.",
        ],
    },
    "download": {
        "scope": "self",
        "headline": "Throttle the download - prioritization does not help here",
        "steps": [
            "Slow down {uploader}: Steam → Settings → Downloads → limit bandwidth, "
            "pause PS5/Xbox downloads, lower streaming quality.",
            "Important: the queue sits at the provider, not in your own router. "
            "Prioritization in the FRITZ!Box cannot overtake packets that are already waiting at the provider.",
            "A permanent solution would be a router with SQM/CAKE that limits the download to just below the "
            "line limit - the FRITZ!Box cannot do that.",
        ],
    },
    "local": {
        "scope": "self",
        "headline": "Check the connection in your own network",
        "steps": [
            "Is the gaming PC on Wi-Fi? Test with a cable - that is the most common single finding.",
            "Wi-Fi: check channel and band (5 GHz instead of 2.4 GHz), distance to the access point, "
            "keep an eye on mesh handovers (Deco).",
            "Check router load (FRITZ!Box → System → Event Log), restart the router as a last test.",
            "For context: measurements are taken from the Raspberry Pi. If the Pi itself is on Wi-Fi, "
            "its own connection may be the cause - then the game may not be affected at all.",
        ],
    },
    "wan": {
        "scope": "provider",
        "headline": "Document the connection and report it to the provider",
        "steps": [
            "FRITZ!Box → Internet → DSL Information → Line Quality: note the error counters (ES/SES, CRC) "
            "and line attenuation - rising values are solid arguments.",
            "Keep this incident as evidence: time, duration and affected targets are already recorded here.",
            "If it repeats at the same time of day, that points to overbooking in the provider's segment - "
            "that cannot be fixed locally, only reported.",
            "Locally only damage control remains: keep your own line free while gaming.",
        ],
    },
    "target": {
        "scope": "remote",
        "headline": "Lies with the target or the path to it",
        "steps": [
            "Only one target was affected - your own line and the router were fine.",
            "If it is the game or matchmaking server: choose another server or region.",
            "Otherwise no local action makes sense; if the pattern repeats, a traceroute to the target "
            "during the problem helps.",
        ],
    },
    "game_server": {
        "scope": "remote",
        "headline": "Game server or the routing to it",
        "steps": [
            "Reference targets and router were unremarkable at the same time - the problem lies on the path to the game server.",
            "Choose another server / region in the game and watch whether it disappears.",
            "Check the game's server status before tinkering with your own network.",
        ],
    },
    "loss": {
        "scope": "self",
        "headline": "Narrow down transmission errors",
        "steps": [
            "Note the direction: losses from the internet point to the connection/provider, "
            "losses when sending to upload saturation or Wi-Fi.",
            "Connect Wi-Fi devices by cable as a test to rule out radio interference.",
            "If it persists, have the connection checked (DSL error counters as above).",
        ],
    },
    "dns": {
        "scope": "self",
        "headline": "Check Pi-hole / DNS",
        "steps": [
            "Check the Pi-hole service: `pihole status`, then `sudo systemctl restart pihole-FTL`.",
            "Check the upstream DNS in Pi-hole (Settings → DNS) and add a second upstream.",
            "For context: DNS does not interrupt a running game - it affects connection setup, "
            "matchmaking, updates and websites.",
        ],
    },
    "drop_wan": {
        "scope": "provider",
        "headline": "Document the internet outage",
        "steps": [
            "The router was reachable, the internet was not - the outage was behind the router.",
            "FRITZ!Box → System → Event Log: it shows whether the PPP/DSL connection was dropped.",
            "If the disconnections pile up, report them to the provider with timestamps. "
            "A daily forced disconnection at night, on the other hand, is normal.",
        ],
    },
    "drop_local": {
        "scope": "self",
        "headline": "Check the connection of the measuring device and the LAN",
        "steps": [
            "The router was not reachable either - this concerns the path Pi ↔ router.",
            "Check cable/port on the Raspberry Pi; if the Pi is on Wi-Fi, switch to a cable.",
            "Check the access point or switch for restarts (Deco app → event log).",
        ],
    },
    "unknown": {
        "scope": "none",
        "headline": "No reliable recommendation",
        "steps": [
            "The measurements are not enough for a clear assignment. "
            "Missing data sources are listed under \"Notes\" - once they are added, the next analysis gets more precise.",
        ],
    },
}


def recommend(w: Window, best: Finding) -> dict:
    """Concrete action for the detected category - with device names where known."""
    tpl = RECOMMENDATIONS.get(best.category) or RECOMMENDATIONS["unknown"]
    dev = (best.device or {}).get("name")
    gmac = (w.gaming or {}).get("mac")
    gamer = f"\"{w.device_label(gmac)['name']}\"" if gmac else "the gaming PC"
    fields = {
        "uploader": f"\"{dev}\"" if dev else "the causing device",
        "device_or_gamer": gamer,
    }
    steps = [s.format(**fields) for s in tpl["steps"]]
    if best.category in ("upload", "download") and not w.per_device_available:
        steps.append("No traffic per device available - which device fills the line is only shown "
                     "by a running FRITZ!Box capture (Settings → FRITZ!Box).")
    return {"category": best.category, "scope": tpl["scope"], "headline": tpl["headline"], "steps": steps}


# =============================================================================== evaluation
def summarize_metrics(w: Window) -> dict:
    pre, ins = w.pre(), w.inside()
    probes = sum(r.get("probes") or 0 for r in ins)
    lost = sum(r.get("lost") or 0 for r in ins)
    g = gateway_stats(w)
    return {
        "duration": w.t1 - w.t0 + 1,
        "ping_before": _med([r.get("rtt_avg") for r in pre]),
        "ping_peak": _max([r.get("rtt_max") for r in ins]),
        "ping_peak_median": _max([r.get("rtt_avg") for r in ins]),
        "jitter_before": _med([r.get("jitter") for r in pre]),
        "jitter_peak": _max([r.get("jitter") for r in ins]),
        "loss_pct": round(100.0 * lost / probes, 1) if probes else None,
        "lost": lost, "probes": probes,
        "gw_before": g["before"], "gw_peak": g["peak"], "gw_lost": g["lost"],
        "up_peak": _max([r.get("up_bps") for r in ins]),
        "down_peak": _max([r.get("down_bps") for r in ins]),
        "traffic_source": next((r.get("traffic_src") for r in ins if r.get("traffic_src")), None),
        "game_gap_peak": _max([r.get("game_gap_ms") for r in ins]),
        "game_rtt_peak": _max([r.get("game_rtt") for r in ins]),
        # Latency under load: quiet seconds ↔ saturated seconds in the window.
        # Baseline from the whole window if needed, because the incident itself may be loaded throughout.
        "latency_under_load": bufferbloat.measure(ins, w.cap_down, w.cap_up, idle_rows=w.rows),
    }


def top_talkers(w: Window, rows: list[dict] | None = None, n: int = 5) -> list[dict]:
    rows = rows if rows is not None else w.inside()
    acc: dict[str, list[float]] = {}
    peak: dict[str, list[float]] = {}
    for r in rows:
        for mac, v in (r.get("devices") or {}).items():
            a = acc.setdefault(mac, [0.0, 0.0])
            a[0] += v[1] * 8
            a[1] += v[0] * 8
            p = peak.setdefault(mac, [0.0, 0.0])
            p[0] = max(p[0], v[1] * 8)
            p[1] = max(p[1], v[0] * 8)
    secs = max(1, len(rows))
    out = []
    for mac, (up, down) in sorted(acc.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))[:n]:
        if up + down <= 0:
            continue
        out.append({**w.device_label(mac), "up_bps": up / secs, "down_bps": down / secs,
                    "up_peak_bps": peak[mac][0], "down_peak_bps": peak[mac][1]})
    return out


def analyze(w: Window) -> dict:
    """Applies all rules and returns the analysis result (JSON-serializable)."""
    findings = []
    for rule in RULES:
        try:
            f = rule(w)
        except Exception as e:  # pragma: no cover - a broken rule must not stop the analysis
            f = Finding(rule.__name__, "unknown", 0, f"Rule failed: {e}", [])
        if f is not None:
            findings.append(f)
    findings.sort(key=lambda f: f.score, reverse=True)
    notes = []
    if not w.traffic_available:
        notes.append("Traffic data not available - upload/download saturation cannot be assessed.")
    elif not w.per_device_available:
        notes.append("Only total traffic (FRITZ!Box TR-064) available - no traffic per device, so no device can be named.")
    if w.cap_up is None or w.cap_down is None:
        notes.append("Line capacity unknown - utilization in % cannot be calculated.")
    elif w.cap_source == "learned":
        notes.append("Line capacity estimated from the peak values measured so far.")
    if not w.gaming:
        notes.append("No gaming session active - the connection to the game server was not observed.")

    if findings and findings[0].score > 0:
        best = findings[0]
        conf = _confidence(best.score)
    else:
        best = Finding("fallback", "unknown", 10, "No clear cause identifiable",
                       ["No rule clearly applied"])
        conf = "low"
    # Competing explanations with a similar score → lower the confidence
    if len(findings) >= 2 and findings[1].score >= best.score - 5 and findings[1].category != best.category:
        conf = {"high": "medium", "medium": "low", "low": "low"}[conf]
        notes.append(f"Alternative explanation similarly plausible: {findings[1].cause}")

    correlated = []
    if w.per_device_available:
        # Only devices whose traffic changed clearly during the incident (not permanent background)
        pre = {t["mac"]: t for t in top_talkers(w, rows=w.pre(), n=50)}
        for t in top_talkers(w, n=3):
            if best.device and t["mac"] == best.device.get("mac"):
                continue
            p = pre.get(t["mac"])
            before = (p["up_bps"] + p["down_bps"]) if p else 0.0
            if t["up_peak_bps"] + t["down_peak_bps"] >= max(1e6, 2 * before):
                correlated.append({**t, "label": CONFIDENCE_LABELS["low"]})
    return {
        "cause": best.cause,
        "category": best.category,
        "category_label": CATEGORY_LABELS.get(best.category, best.category),
        "confidence": conf,
        "confidence_label": CONFIDENCE_LABELS[conf],
        "evidence": best.evidence,
        "recommendation": recommend(w, best),
        "device": best.device,
        "rules": [{"rule": f.rule, "category": f.category, "score": f.score, "cause": f.cause,
                   "evidence": f.evidence} for f in findings],
        "metrics": summarize_metrics(w),
        "targets": list(target_impact(w).values()),
        "top_talkers": top_talkers(w),
        "correlated_devices": correlated,
        "notes": notes,
        "capacity": {"down_bps": w.cap_down, "up_bps": w.cap_up, "source": w.cap_source},
    }
