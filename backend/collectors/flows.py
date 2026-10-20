"""Packet analysis: traffic per device, flows, TCP retransmissions, game flow gaps.

Works exclusively on header metadata. Payload is never read or stored.

Direction logic (capture on the LAN side of the router):
* src_mac = client, dst_mac = router, peer public → upload (tx) of the client
* src_mac = router, dst_mac = client, peer public → download (rx) of the client
* everything else → LAN-internal (lan_bytes)
"""
from __future__ import annotations

import ipaddress
import socket
import struct
from collections import defaultdict
from time import time as time_now

RX, TX, RXP, TXP, UDP, LAN, RETR = range(7)
ETH_IPV4, ETH_IPV6, ETH_VLAN, ETH_QINQ = 0x0800, 0x86DD, 0x8100, 0x88A8
PROTO_TCP, PROTO_UDP = 6, 17
TCP_FIN, TCP_SYN, TCP_RST = 0x01, 0x02, 0x04
SEQ_MOD = 1 << 32
HALF = 1 << 31

_unpack_H = struct.Struct("!H").unpack_from
_unpack_HH = struct.Struct("!HH").unpack_from
_unpack_I = struct.Struct("!I").unpack_from


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def mac_bytes(s: str) -> bytes:
    return bytes(int(p, 16) for p in s.split(":"))


def seq_after(a: int, b: int) -> bool:
    """a is after b (modulo 2^32)."""
    return a != b and ((a - b) % SEQ_MOD) < HALF


def _v4_private(ip: bytes) -> bool:
    a, b = ip[0], ip[1]
    return (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254)
            or a == 127 or a >= 224 or a == 0 or (a == 100 and 64 <= b <= 127))


def _v6_global(ip: bytes) -> bool:
    return (ip[0] & 0xE0) == 0x20


class Flow:
    __slots__ = ("first", "last", "mac", "proto", "lip", "lport", "rip", "rport",
                 "bu", "bd", "pu", "pd", "retrans", "resets", "max_up", "max_down",
                 "last_down", "max_gap", "fin", "win_bytes", "win_pkts_up", "win_pkts_down",
                 "sec_pkts_up", "sec_pkts_down", "sec_gap")

    def __init__(self, ts: float, mac: str, proto: int, lip: bytes, lport: int, rip: bytes, rport: int):
        self.first = self.last = ts
        self.mac, self.proto, self.lip, self.lport, self.rip, self.rport = mac, proto, lip, lport, rip, rport
        self.bu = self.bd = self.pu = self.pd = self.retrans = self.resets = 0
        self.max_up: int | None = None
        self.max_down: int | None = None
        self.last_down: float | None = None
        self.max_gap = 0.0
        self.fin = False
        self.win_bytes = 0
        self.win_pkts_up = self.win_pkts_down = 0
        self.sec_pkts_up = self.sec_pkts_down = 0
        self.sec_gap = 0.0


def ip_str(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET if len(b) == 4 else socket.AF_INET6, b)


class PacketAnalyzer:
    """Stateful analysis of a packet stream (runs in the capture process)."""

    def __init__(self, local_nets: list[str] | None = None, router_macs: list[str] | None = None,
                 ignore_pair: tuple[str, str] | None = None, gaming_mac: str | None = None,
                 flow_idle_udp: float = 30, flow_idle_tcp: float = 120, flow_min_bytes: int = 20000):
        self.local_nets = [(int(n.network_address), int(n.netmask)) for n in
                           (ipaddress.ip_network(x, strict=False) for x in (local_nets or [])) if n.version == 4]
        self.router_macs: set[bytes] = {mac_bytes(m) for m in (router_macs or [])}
        self._router_votes: dict[bytes, int] = defaultdict(int)
        self.ignore_pair: set[bytes] | None = None
        if ignore_pair:
            try:
                self.ignore_pair = {socket.inet_aton(ignore_pair[0]), socket.inet_aton(ignore_pair[1])}
            except OSError:
                self.ignore_pair = None   # no IPv4 pair → filter nothing
        self.gaming_mac = gaming_mac
        self.flow_idle_udp = flow_idle_udp
        self.flow_idle_tcp = flow_idle_tcp
        self.flow_min_bytes = flow_min_bytes
        self.level = 0                     # load guard level
        self.sample_n = 4
        self._sample_i = 0
        self.bins: dict[int, dict] = {}    # sec → {"dev": {mac: [7]}, "g": {...}}
        self.flows: dict[tuple, Flow] = {}
        self.closed: list[tuple] = []
        self.macip: dict[str, str] = {}
        self._macip_new: dict[str, str] = {}
        self._mac_cache: dict[bytes, str] = {}
        self.clock_offset = 0.0
        self.packets = 0
        self.ignored = 0
        self._cand_t = 0.0

    # ------------------------------------------------------------------ helpers
    def set_router_macs(self, macs: list[str]) -> None:
        self.router_macs = {mac_bytes(m) for m in macs if m}

    def _mac(self, b: bytes) -> str:
        s = self._mac_cache.get(b)
        if s is None:
            s = mac_str(b)
            if len(self._mac_cache) > 4096:
                self._mac_cache.clear()
            self._mac_cache[b] = s
        return s

    def _bin(self, sec: int) -> dict:
        b = self.bins.get(sec)
        if b is None:
            b = {"dev": {}, "g": {"wan_rx": 0, "wan_tx": 0, "tcp_segs": 0, "retrans_down": 0,
                                  "retrans_up": 0, "pkts": 0}}
            self.bins[sec] = b
        return b

    def _dev(self, b: dict, mac: str) -> list[int]:
        d = b["dev"].get(mac)
        if d is None:
            d = [0, 0, 0, 0, 0, 0, 0]
            b["dev"][mac] = d
        return d

    def is_local_v4(self, ip: bytes) -> bool:
        if _v4_private(ip):
            return True
        if self.local_nets:
            a = int.from_bytes(ip, "big")
            for net, mask in self.local_nets:
                if a & mask == net:
                    return True
        return False

    # ------------------------------------------------------------------ main routine
    def process(self, ts: float, data: bytes, orig_len: int, linktype: int = 1) -> None:
        if linktype != 1 or len(data) < 14:
            return
        self.packets += 1
        scale = 1
        if self.level >= 2:
            self._sample_i += 1
            if self._sample_i % self.sample_n:
                return
            scale = self.sample_n

        dst_mac = data[0:6]
        src_mac = data[6:12]
        etype = _unpack_H(data, 12)[0]
        off = 14
        while etype in (ETH_VLAN, ETH_QINQ) and len(data) >= off + 4:
            etype = _unpack_H(data, off + 2)[0]
            off += 4

        wall = ts + self.clock_offset
        sec = int(wall)
        b = self._bin(sec)
        g = b["g"]
        g["pkts"] += scale
        size = orig_len * scale

        if etype == ETH_IPV4:
            if len(data) < off + 20:
                return
            ihl = (data[off] & 0x0F) * 4
            total = _unpack_H(data, off + 2)[0]
            proto = data[off + 9]
            sip = data[off + 12:off + 16]
            dip = data[off + 16:off + 20]
            l4 = off + ihl
            l4len = total - ihl
            if self.ignore_pair and sip in self.ignore_pair and dip in self.ignore_pair:
                self.ignored += 1
                return
            s_local = self.is_local_v4(sip)
            d_local = self.is_local_v4(dip)
            # Learn router MAC: sends packets with a public source IP into the LAN
            # (even if a MAC is known from ARP - the FRITZ!Box may use several MACs)
            if not s_local and d_local and src_mac not in self.router_macs:
                self._vote_router(src_mac)
        elif etype == ETH_IPV6:
            if len(data) < off + 40:
                return
            proto = data[off + 6]
            l4len = _unpack_H(data, off + 4)[0]
            sip = data[off + 8:off + 24]
            dip = data[off + 24:off + 40]
            l4 = off + 40
            s_local = not _v6_global(sip)
            d_local = not _v6_global(dip)
        else:
            # ARP & co.: only the sender's LAN counter
            if not (src_mac in self.router_macs):
                self._dev(b, self._mac(src_mac))[LAN] += size
            return

        up = dst_mac in self.router_macs and src_mac not in self.router_macs and not d_local
        down = src_mac in self.router_macs and dst_mac not in self.router_macs and not s_local
        if up:
            mac = self._mac(src_mac)
            d = self._dev(b, mac)
            d[TX] += size
            d[TXP] += scale
            g["wan_tx"] += size
            lip, rip = sip, dip
            if etype == ETH_IPV4 and mac not in self.macip:
                self._learn(mac, sip)
        elif down:
            mac = self._mac(dst_mac)
            d = self._dev(b, mac)
            d[RX] += size
            d[RXP] += scale
            g["wan_rx"] += size
            lip, rip = dip, sip
            if etype == ETH_IPV4 and mac not in self.macip:
                self._learn(mac, dip)
        else:
            if dst_mac[0] & 1:  # Broadcast/Multicast
                return
            if src_mac not in self.router_macs:
                smac = self._mac(src_mac)
                self._dev(b, smac)[LAN] += size
                if etype == ETH_IPV4 and s_local and smac not in self.macip:
                    self._learn(smac, sip)
            return

        if proto == PROTO_UDP:
            d[UDP] += size
        elif proto != PROTO_TCP:
            return
        if self.level >= 1 or len(data) < l4 + 4:
            return
        # ---------------------------------------------------------- flow analysis
        sport, dport = _unpack_HH(data, l4)
        lport, rport = (sport, dport) if up else (dport, sport)
        key = (proto, lip, lport, rip, rport)
        f = self.flows.get(key)
        if f is None:
            f = Flow(wall, mac, proto, lip, lport, rip, rport)
            self.flows[key] = f
        f.last = wall
        f.win_bytes += size
        if up:
            f.bu += size
            f.pu += scale
            f.sec_pkts_up += scale
        else:
            f.bd += size
            f.pd += scale
            f.sec_pkts_down += scale
            if f.last_down is not None:
                gap = wall - f.last_down
                if gap > f.sec_gap:
                    f.sec_gap = gap
                if gap > f.max_gap:
                    f.max_gap = gap
            f.last_down = wall
        if proto == PROTO_UDP and mac == self.gaming_mac:
            # Game flow statistics directly in the per-second bin (exact time assignment)
            gf = b.get("gf")
            if gf is None:
                gf = b["gf"] = {}
            e = gf.get(key)
            if e is None:
                e = gf[key] = [0, 0, 0.0]
            if up:
                e[0] += scale
            else:
                e[1] += scale
                if f.sec_gap > e[2]:
                    e[2] = f.sec_gap

        if proto == PROTO_TCP and len(data) >= l4 + 14:
            seq = _unpack_I(data, l4 + 4)[0]
            doff = (data[l4 + 12] >> 4) * 4
            flags = data[l4 + 13]
            payload = l4len - doff
            if flags & TCP_RST:
                f.resets += 1
            if flags & TCP_FIN:
                f.fin = True
            if payload > 0:
                g["tcp_segs"] += scale
                end = (seq + payload) % SEQ_MOD
                mx = f.max_up if up else f.max_down
                if mx is None or seq_after(end, mx):
                    if up:
                        f.max_up = end
                    else:
                        f.max_down = end
                elif payload > 1:  # payload 1 = TCP keepalive, not a retransmission
                    f.retrans += 1
                    d[RETR] += scale
                    if up:
                        g["retrans_up"] += scale
                    else:
                        g["retrans_down"] += scale

    def _vote_router(self, mac: bytes) -> None:
        if mac[0] & 1:
            return
        self._router_votes[mac] += 1
        if self._router_votes[mac] >= 50:
            self.router_macs.add(mac)
            self._router_votes.pop(mac, None)

    def _learn(self, mac: str, ip: bytes) -> None:
        ips = ip_str(ip)
        if ips.endswith(".0") or ips.endswith(".255") or ips.startswith("0."):
            return
        self.macip[mac] = ips
        self._macip_new[mac] = ips

    # ------------------------------------------------------------------ output
    def take_bins(self, upto_sec: int, fill_from: int | None = None) -> list[tuple[int, dict]]:
        """Returns finished bins (<= upto_sec). Gaps are filled with empty bins."""
        out = []
        secs = sorted(s for s in self.bins if s <= upto_sec)
        start = fill_from if fill_from is not None else (secs[0] if secs else None)
        if start is None:
            return out
        for s in range(start, upto_sec + 1):
            b = self.bins.pop(s, None) or {"dev": {}, "g": {"wan_rx": 0, "wan_tx": 0, "tcp_segs": 0,
                                                            "retrans_down": 0, "retrans_up": 0, "pkts": 0}}
            for rm in self.router_macs:           # the router itself is not a "device"
                b["dev"].pop(self._mac(rm), None)
            b["g"]["tcp_analysis"] = self.level == 0
            gf = b.pop("gf", None)
            if gf:
                key, e = max(gf.items(), key=lambda kv: kv[1][0] + kv[1][1])
                b["g"]["game_pps"] = e[0] + e[1]
                b["g"]["game_gap_ms"] = round(e[2] * 1000, 1)
                b["g"]["game_remote"] = f"{ip_str(key[3])}:{key[4]}"
            if self.level >= 2:
                b["g"]["sampled"] = self.sample_n
            out.append((s, b))
        for s in [s for s in self.bins if s < start]:
            del self.bins[s]
        return out

    def udp_candidates(self) -> list[dict]:
        """UDP flows with packets in both directions since the last call (for game detection).

        Returns packet rates per second; resets the counters.
        """
        now = time_now()
        dt = max(0.2, now - self._cand_t) if self._cand_t else 1.0
        self._cand_t = now
        out = []
        for f in self.flows.values():
            if f.proto == PROTO_UDP and f.sec_pkts_up and f.sec_pkts_down:
                up, down = f.sec_pkts_up / dt, f.sec_pkts_down / dt
                if up >= 5 and down >= 5:
                    out.append({"mac": f.mac, "remote_ip": ip_str(f.rip), "remote_port": f.rport,
                                "local_port": f.lport, "pps_up": round(up, 1), "pps_down": round(down, 1)})
            f.sec_pkts_up = f.sec_pkts_down = 0
            f.sec_gap = 0.0
        return out

    def active_flows(self, top: int = 30) -> list[dict]:
        fl = sorted(self.flows.values(), key=lambda f: f.win_bytes, reverse=True)[:top]
        out = [self._flow_dict(f, recent=f.win_bytes) for f in fl if f.win_bytes > 0]
        for f in self.flows.values():
            f.win_bytes = 0
        return out

    def expire_flows(self, now_wall: float, force: bool = False) -> list[tuple]:
        out = []
        for key, f in list(self.flows.items()):
            idle = now_wall - f.last
            limit = self.flow_idle_tcp if f.proto == PROTO_TCP else self.flow_idle_udp
            if force or idle > limit or (f.fin and idle > 5):
                del self.flows[key]
                if f.bu + f.bd >= self.flow_min_bytes or (f.proto == PROTO_UDP and f.pu + f.pd >= 200):
                    out.append(self.flow_tuple(f))
        return out

    def flow_tuple(self, f: Flow) -> tuple:
        return (round(f.first, 3), round(f.last, 3), "tcp" if f.proto == PROTO_TCP else "udp", f.mac,
                ip_str(f.lip), f.lport, ip_str(f.rip), f.rport, f.bu, f.bd, f.pu, f.pd, f.retrans, f.resets,
                round(f.max_gap * 1000, 1) if f.proto == PROTO_UDP else None, None)

    def _flow_dict(self, f: Flow, recent: int = 0) -> dict:
        return {"proto": "tcp" if f.proto == PROTO_TCP else "udp", "mac": f.mac, "local_ip": ip_str(f.lip),
                "local_port": f.lport, "remote_ip": ip_str(f.rip), "remote_port": f.rport,
                "bytes_up": f.bu, "bytes_down": f.bd, "recent_bytes": recent, "retrans": f.retrans,
                "first": round(f.first, 1), "last": round(f.last, 1)}

    def take_macip(self) -> dict[str, str]:
        out, self._macip_new = self._macip_new, {}
        return out
