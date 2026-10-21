"""Which device sent a DNS query? IP → device attribution for the DNS usage module.

Pi-hole logs the client IP only. The device behind an IP comes from FTL's
`network_addresses`, which knows the *current* owner of each IP - not its history.
So an attribution is only as good as its basis, and the basis travels with it:

* `mac`     IP is known to Pi-hole with a real MAC, and the device already existed
            when the query was made.
* `ip`      No MAC to go by: Pi-hole has none (`ip-…` hwaddr, typical for IPv6 or
            clients behind another router), the IP is not in the network table, or
            the query is older than the device that holds the IP now - then the IP
            belonged to someone else at the time and naming today's owner would be
            made up.
* `local`   The Pi itself (loopback or its own address). Not a household device.

Known gap: two long-known devices that swap IPs are not detected from FTL data
alone; that needs an own IP history (planned in the data model phase).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Literal

from ..collectors.ftl_queries import DnsQuery, NetworkAddress, normalize_ip

Basis = Literal["mac", "ip", "local"]

LOOPBACK = {"127.0.0.1", "::1"}
# Clock skew between FTL's firstSeen and query timestamps (both written by FTL,
# but in different code paths and at different times).
FIRST_SEEN_SLACK = 120.0
# Share of all queries from a single non-local IP above which the data looks like
# "everything is forwarded through one router" instead of per-device clients.
SINGLE_FORWARDER_SHARE = 0.9


@dataclass(slots=True, frozen=True)
class Attribution:
    key: str              # "mac:…", "ip:…" or "local"
    basis: Basis
    ip: str
    mac: str | None = None
    name: str | None = None
    vendor: str | None = None
    reason: str | None = None   # why it is not "mac"


class ClientResolver:
    def __init__(self, addresses: Iterable[NetworkAddress], own_ips: Iterable[str] = ()):
        self.by_ip: dict[str, NetworkAddress] = {a.ip: a for a in addresses}
        self.local = LOOPBACK | {n for n in (normalize_ip(ip) for ip in own_ips) if n}

    def resolve(self, ip: str, ts: float | None = None) -> Attribution:
        ip = normalize_ip(ip) or ip
        if ip in self.local:
            return Attribution(key="local", basis="local", ip=ip, name="This Pi")
        a = self.by_ip.get(ip)
        if a is None:
            return Attribution(key=f"ip:{ip}", basis="ip", ip=ip, reason="IP unknown to Pi-hole's network table")
        if a.mac is None:
            return Attribution(key=f"ip:{ip}", basis="ip", ip=ip, name=a.name,
                               reason="Pi-hole knows no MAC address for this IP")
        if ts is not None and a.device_first_seen is not None and ts < a.device_first_seen - FIRST_SEEN_SLACK:
            return Attribution(key=f"ip:{ip}", basis="ip", ip=ip,
                               reason="query is older than the device now using this IP")
        return Attribution(key=f"mac:{a.mac}", basis="mac", ip=ip, mac=a.mac, name=a.name, vendor=a.vendor)

    def cache_key(self, ip: str, ts: float) -> tuple[str, bool]:
        """Key under which `resolve(ip, ts)` can be cached: same IP, same side of the first-seen line."""
        a = self.by_ip.get(ip)
        before = bool(a and a.mac and a.device_first_seen is not None
                      and ts < a.device_first_seen - FIRST_SEEN_SLACK)
        return ip, before


@dataclass
class ClientStats:
    attribution: Attribution
    queries: int = 0          # without duplicates
    blocked: int = 0
    duplicates: int = 0
    unknown_status: int = 0
    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    first: float | None = None
    last: float | None = None


def summarize(queries: Iterable[DnsQuery], resolver: ClientResolver) -> dict:
    """Per-client counts plus the evidence whether per-client evaluation is possible at all."""
    clients: dict[str, ClientStats] = {}
    by_basis: dict[str, int] = defaultdict(int)
    by_ip: dict[str, int] = defaultdict(int)
    total = duplicates = 0
    cache: dict[tuple[str, bool], Attribution] = {}
    for q in queries:
        # The same IP can resolve differently before and after its current owner
        # appeared, so the cache key includes that side.
        ck = resolver.cache_key(q.client, q.ts)
        att = cache.get(ck)
        if att is None:
            att = cache[ck] = resolver.resolve(q.client, q.ts)
        st = clients.get(att.key)
        if st is None:
            st = clients[att.key] = ClientStats(att)
        st.ips.add(q.client)
        if q.outcome == "duplicate":
            st.duplicates += 1
            duplicates += 1
            continue
        total += 1
        st.queries += 1
        by_basis[att.basis] += 1
        by_ip[q.client] += 1
        if q.outcome == "blocked":
            st.blocked += 1
        elif q.outcome == "unknown":
            st.unknown_status += 1
        st.domains.add(q.domain)
        st.first = q.ts if st.first is None else min(st.first, q.ts)
        st.last = q.ts if st.last is None else max(st.last, q.ts)

    warnings = []
    non_local = {ip: n for ip, n in by_ip.items() if resolver.resolve(ip).basis != "local"}
    nl_total = sum(non_local.values())
    if nl_total and len(non_local) == 1:
        warnings.append("All queries come from a single address - Pi-hole probably sees a router "
                        "or DNS forwarder, not the devices. Per-device evaluation is not possible.")
    elif nl_total:
        ip, n = max(non_local.items(), key=lambda kv: kv[1])
        if n / nl_total >= SINGLE_FORWARDER_SHARE:
            warnings.append(f"{n / nl_total:.0%} of all queries come from {ip} - check whether this is "
                            "a router or DNS forwarder hiding the devices behind it.")
    multi_ip = sorted(k for k, s in clients.items() if s.attribution.basis == "mac" and len(s.ips) > 1)
    return {
        "queries": total,
        "duplicates": duplicates,
        "by_basis": {b: by_basis.get(b, 0) for b in ("mac", "ip", "local")},
        # The Pi's own queries are not household traffic and would dilute the share.
        "attributable_share": (by_basis["mac"] / household) if (household := by_basis["mac"] + by_basis["ip"]) else None,
        "clients": sorted(clients.values(), key=lambda s: -s.queries),
        "devices_with_several_ips": multi_ip,
        "warnings": warnings,
    }
