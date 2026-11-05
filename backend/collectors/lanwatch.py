"""ARP and DHCP as the capture sees them: who claims which address, which DHCP servers answer.

Runs inside the packet analyzer (capture process) and only collects; the verdicts are made in
`analysis/lan_health.py`. The capture shows what passes the FRITZ!Box: every ARP request and
most replies, every DHCP request a device broadcasts, but of the server replies only those
sent as broadcast - a reply sent straight to a device may never pass it. So a second DHCP
server can stay unseen here; a seen one is real.
"""
from __future__ import annotations

import socket
import struct

ETH_ARP = 0x0806
DHCP_TYPES = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}
DHCP_MAGIC = b"\x63\x82\x53\x63"
MAX_PAIRS = 2048          # per window: a scan of the whole subnet must not flood the queue
MAX_DHCP = 200

_unpack_arp = struct.Struct("!HHBBH").unpack_from


def _ip(b: bytes) -> str:
    return socket.inet_ntoa(b)


class LanWatch:
    def __init__(self) -> None:
        self.arp_pairs: dict[tuple[str, str], float] = {}     # (ip, mac) → last time in this window
        self.arp_count: dict[str, int] = {}
        self.dhcp: list[list] = []
        self.dropped = 0

    def arp(self, ts: float, data: bytes, off: int, mac_of) -> None:
        if len(data) < off + 28:
            return
        _, ptype, hlen, plen, _op = _unpack_arp(data, off)
        if ptype != 0x0800 or hlen != 6 or plen != 4:
            return
        mac = mac_of(data[off + 8:off + 14])
        self.arp_count[mac] = self.arp_count.get(mac, 0) + 1
        sip = data[off + 14:off + 18]
        # 0.0.0.0 is a probe ("is this address free?"), not a claim
        if sip == b"\0\0\0\0" or sip[0] in (0, 127) or sip[0] >= 224 or data[off + 8] & 1:
            return
        key = (_ip(sip), mac)
        if key in self.arp_pairs or len(self.arp_pairs) < MAX_PAIRS:
            self.arp_pairs[key] = ts
        else:
            self.dropped += 1

    def dhcp_packet(self, ts: float, data: bytes, bootp: int, src_mac: str, src_ip: bytes) -> None:
        if len(data) < bootp + 240 or data[bootp + 236:bootp + 240] != DHCP_MAGIC:
            return
        if len(self.dhcp) >= MAX_DHCP:
            self.dropped += 1
            return
        kind = server = None
        i, end = bootp + 240, len(data)
        while i < end:
            code = data[i]
            if code == 255:
                break
            if code == 0:
                i += 1
                continue
            if i + 2 > end:
                break
            n = data[i + 1]
            val = data[i + 2:i + 2 + n]
            if len(val) < n:
                break                                   # cut by the snaplen
            if code == 53 and n == 1:
                kind = DHCP_TYPES.get(val[0])
            elif code == 54 and n == 4:
                server = _ip(val)
            i += 2 + n
        if kind is None:
            return
        client = ":".join(f"{x:02x}" for x in data[bootp + 28:bootp + 34])
        offered = data[bootp + 16:bootp + 20]
        self.dhcp.append([round(ts, 1), kind, client, server, src_mac, _ip(src_ip),
                          _ip(offered) if offered != b"\0\0\0\0" else None])

    def take(self) -> dict | None:
        if not (self.arp_count or self.dhcp or self.dropped):
            return None
        out = {"arp": [[ip, mac, round(t, 1)] for (ip, mac), t in self.arp_pairs.items()],
               "arp_n": self.arp_count, "dhcp": self.dhcp, "dropped": self.dropped}
        self.arp_pairs, self.arp_count, self.dhcp, self.dropped = {}, {}, [], 0
        return out
