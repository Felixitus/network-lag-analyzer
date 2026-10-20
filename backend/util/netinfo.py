"""Netzwerk-Informationen des Raspberry Pi (ohne Shell-Aufrufe, nur /proc und psutil)."""
from __future__ import annotations

import ipaddress
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

import psutil

PRIVATE_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT – auf LAN-Seite nicht vorkommend, aber nicht "Internet"
]


@dataclass
class DefaultRoute:
    interface: str
    gateway: str


def default_route(proc_route: str = "/proc/net/route") -> DefaultRoute | None:
    try:
        lines = Path(proc_route).read_text().splitlines()[1:]
    except OSError:
        return None
    best: tuple[int, DefaultRoute] | None = None
    for line in lines:
        f = line.split()
        if len(f) < 8 or f[1] != "00000000":
            continue
        flags = int(f[3], 16)
        if not flags & 0x2:  # RTF_GATEWAY
            continue
        gw = socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
        metric = int(f[6])
        if best is None or metric < best[0]:
            best = (metric, DefaultRoute(interface=f[0], gateway=gw))
    return best[1] if best else None


def interface_addresses() -> dict[str, dict]:
    out: dict[str, dict] = {}
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        info = {"ipv4": [], "ipv6": [], "mac": None, "up": bool(stats.get(name) and stats[name].isup),
                "speed": stats[name].speed if name in stats else None}
        for a in addrs:
            if a.family == socket.AF_INET:
                info["ipv4"].append({"address": a.address, "netmask": a.netmask})
            elif a.family == socket.AF_INET6:
                info["ipv6"].append(a.address.split("%")[0])
            elif a.family == psutil.AF_LINK:
                info["mac"] = a.address.lower()
        out[name] = info
    return out


def local_networks(extra: list[str] | None = None) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for name, info in interface_addresses().items():
        if name == "lo":
            continue
        for a in info["ipv4"]:
            if a["netmask"]:
                n = ipaddress.ip_network(f"{a['address']}/{a['netmask']}", strict=False)
                if n.prefixlen < 32 and n not in nets:
                    nets.append(n)
    for e in extra or []:
        n = ipaddress.ip_network(e, strict=False)
        if n not in nets:
            nets.append(n)
    return nets


def primary_ipv4(interface: str | None = None) -> str | None:
    addrs = interface_addresses()
    if interface and interface in addrs and addrs[interface]["ipv4"]:
        return addrs[interface]["ipv4"][0]["address"]
    for name, info in addrs.items():
        if name != "lo" and info["ipv4"]:
            return info["ipv4"][0]["address"]
    return None


def arp_table(path: str = "/proc/net/arp") -> dict[str, str]:
    """IP → MAC aus der Neighbor-Tabelle des Pi (nur vollständige Einträge)."""
    out: dict[str, str] = {}
    try:
        lines = Path(path).read_text().splitlines()[1:]
    except OSError:
        return out
    for line in lines:
        f = line.split()
        if len(f) >= 6 and f[3] != "00:00:00:00:00:00" and int(f[2], 16) & 0x2:
            out[f[0]] = f[3].lower()
    return out


def ip_forwarding() -> bool | None:
    try:
        return Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    except OSError:
        return None


def ping_group_range() -> tuple[int, int] | None:
    try:
        a, b = Path("/proc/sys/net/ipv4/ping_group_range").read_text().split()
        return int(a), int(b)
    except (OSError, ValueError):
        return None


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 4:
        return any(a in n for n in PRIVATE_V4) or a.is_multicast or a.is_loopback
    return a.is_link_local or a.is_private or a.is_multicast or a.is_loopback


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    m = mac.strip().lower().replace("-", ":")
    parts = m.split(":")
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return None
