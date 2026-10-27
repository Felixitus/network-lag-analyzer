"""Does a device resolve names past Pi-hole? Then its DNS numbers are incomplete.

Three independent signs, none of them proof on its own:

* it looked up VPN, proxy or DNS-over-HTTPS services, or iCloud Private Relay - after
  such a lookup, names can travel encrypted to another resolver;
* the FRITZ!Box reports it active, but Pi-hole never heard from it;
* it was in the network for many hours, but asked Pi-hole in few of them - a phone or
  laptop looks up names every few minutes while it is on.

The verdict says how complete the numbers are likely to be, never what the device did.
"""
from __future__ import annotations

CANARY = "use-application-dns.net"      # Firefox asks this before switching to DoH; Pi-hole answers "no"
MIN_PRESENT_HOURS = 6                   # below that, quiet hours say nothing
QUIET_SHARE = 0.5                       # present, but no lookup in more than half of those hours


def assess(*, vpn_lookups: int = 0, vpn_names: list[str] | None = None, present_hours: int | None = None,
           dns_hours: int | None = None, not_using_pihole: bool = False, canary: int = 0) -> dict:
    reasons, level = [], "complete"
    if not_using_pihole:
        reasons.append("Active according to the FRITZ!Box, but never asked Pi-hole: it uses another DNS server.")
        level = "bypassing"
    if vpn_lookups:
        names = ", ".join((vpn_names or [])[:3])
        reasons.append(f"{vpn_lookups} lookups of VPN, proxy or DNS-over-HTTPS services ({names}). "
                       "Names after that may go to another resolver.")
        level = "bypassing" if level == "bypassing" else "partial"
    if present_hours is not None and dns_hours is not None and present_hours >= MIN_PRESENT_HOURS:
        quiet = 1 - dns_hours / present_hours
        if quiet > QUIET_SHARE:
            reasons.append(f"In the network for {present_hours} h, but asked Pi-hole in only {dns_hours} of them.")
            level = "bypassing" if level == "bypassing" else "partial"
    notes = []
    if canary:
        notes.append("Firefox checked whether it may use DNS over HTTPS; Pi-hole answers no, so Firefox keeps using it.")
    return {"level": level, "reasons": reasons, "notes": notes}


LEVEL_TEXT = {"complete": "No sign of DNS past Pi-hole",
              "partial": "Probably incomplete: some names may go past Pi-hole",
              "bypassing": "Largely missing: the device resolves names past Pi-hole"}
