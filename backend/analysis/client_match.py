"""Do FRITZ!Box and Pi-hole identify the same clients? Evidence for the DNS statistics.

The DNS statistics stand on Pi-hole's view (client IP → MAC). The FRITZ!Box host
list is an independent second view of the same network. Comparing both shows
where the statistics can be trusted and where not:

* consistent     same MAC, and the FRITZ!Box's current IP is known to Pi-hole for it
* ip_mismatch    same MAC, but the IPs disagree (stale entry on one side)
* ip_conflict    one IP, different MACs in the two sources - queries of that IP
                 cannot be attributed with certainty
* not_using_pihole  active in the FRITZ!Box, but Pi-hole never saw a query from it:
                 the device resolves names elsewhere (hard-coded DNS, DNS over
                 HTTPS, VPN) - its DNS usage is missing from these statistics
* pihole_only    known to Pi-hole only (an older device, or one the FRITZ!Box no
                 longer lists)

Nothing is merged or guessed from this: it is a report, not a mapping.
"""
from __future__ import annotations

from typing import Iterable

from ..collectors.fritzbox import HostEntry
from ..collectors.ftl_queries import NetworkAddress, normalize_ip, normalize_mac

# Above this share of all queries one client IP probably is a forwarder (a router
# with its own DNS proxy in front of Pi-hole) and hides the devices behind it.
FORWARDER_SHARE = 0.5


def compare(fritz: Iterable[HostEntry], pihole: Iterable[NetworkAddress], gateway_ip: str | None = None,
            queries_by_ip: dict[str, int] | None = None) -> dict:
    fb = {}
    for h in fritz:
        mac = normalize_mac(h.mac)
        if mac:
            fb[mac] = h
    ph_ips: dict[str, set[str]] = {}
    ph_names: dict[str, str | None] = {}
    ip_owner: dict[str, str] = {}
    for a in pihole:
        if a.mac:
            ph_ips.setdefault(a.mac, set()).add(a.ip)
            ph_names[a.mac] = ph_names.get(a.mac) or a.name
            ip_owner[a.ip] = a.mac

    rows = []
    for mac in sorted(set(fb) | set(ph_ips)):
        h = fb.get(mac)
        f_ip = normalize_ip(h.ip) if h and h.ip else None
        if h is None:
            status = "pihole_only"
        elif mac not in ph_ips:
            status = "not_using_pihole" if h.active else "fritz_only_inactive"
        elif f_ip and ip_owner.get(f_ip) not in (None, mac):
            status = "ip_conflict"
        elif f_ip and f_ip not in ph_ips[mac]:
            status = "ip_mismatch"
        else:
            status = "consistent"
        rows.append({"mac": mac, "status": status, "fritz_ip": f_ip, "pihole_ips": sorted(ph_ips.get(mac, ())),
                     "fritz_name": h.name if h else None, "pihole_name": ph_names.get(mac),
                     "active": h.active if h else None, "interface": h.interface if h else None,
                     "randomized": bool(int(mac.split(":")[0], 16) & 2)})

    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    findings = []
    if counts.get("not_using_pihole"):
        findings.append(f"{counts['not_using_pihole']} active device(s) never asked Pi-hole: they resolve names "
                        "elsewhere (fixed DNS server, DNS over HTTPS, VPN). Their DNS usage is missing here.")
    if counts.get("ip_conflict"):
        findings.append(f"{counts['ip_conflict']} IP address(es) belong to different devices in FRITZ!Box and "
                        "Pi-hole - queries of these IPs may be attributed to the wrong device.")
    if counts.get("ip_mismatch"):
        findings.append(f"{counts['ip_mismatch']} device(s) have a different IP in FRITZ!Box and Pi-hole "
                        "(usually a stale entry on one side; it resolves with the next DHCP renewal).")
    active = [h for h in fb.values() if h.active]
    ifaces = {h.interface for h in active if h.interface}
    if active and ifaces <= {"Ethernet"}:
        findings.append("The FRITZ!Box sees every active device as connected by cable - typical for mesh access "
                        "points (e.g. TP-Link Deco in access point mode). Wi-Fi or LAN cannot be told apart here.")
    if queries_by_ip:
        total = sum(queries_by_ip.values())
        if gateway_ip and total and queries_by_ip.get(normalize_ip(gateway_ip), 0) / total >= FORWARDER_SHARE:
            findings.append("Most queries come from the router itself: it forwards the devices' DNS to Pi-hole and "
                            "hides them. Per-device statistics are not possible - give the devices Pi-hole as DNS "
                            "server (DHCP) instead.")
    both = sum(1 for r in rows if r["status"] in ("consistent", "ip_mismatch", "ip_conflict"))
    return {"rows": rows, "counts": counts, "findings": findings,
            "fritz_devices": len(fb), "pihole_devices": len(ph_ips), "in_both": both,
            "consistent_share": (counts.get("consistent", 0) / both) if both else None}
