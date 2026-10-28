"""Path measurement (traceroute in the style of mtr) with ICMP echo and rising TTL.

One measurement sends every TTL from 1 up to the target `rounds` times, so that each hop
gets a loss share and not just one lucky answer. Routers on the way answer with ICMP
"time exceeded", the target with an echo reply.

* Its own raw socket, only open during a measurement. A raw ICMP socket sees every ICMP
  packet of the host, so answers are matched by identifier and sequence number - also
  those quoted inside a "time exceeded". The ping prober uses another identifier.
* Probes go out ~25 ms apart, not as a burst: routers limit how many "time exceeded"
  they send, and a burst would show up as loss at every hop (see the ping trap).
* A hop that does not answer is `None`, not loss of the path: many routers never answer
  a traceroute but forward traffic just fine. `analysis/path.py` reads the result.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import random
import socket
import struct
import time
from collections import Counter
from dataclasses import dataclass, field

from .ping import SO_TIMESTAMPNS, _timespec_from_cmsg, build_echo

log = logging.getLogger(__name__)

ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11
SPACING_S = 0.025


@dataclass
class Hop:
    ttl: int
    sent: int = 0
    rtts: list[float] = field(default_factory=list)
    ips: Counter = field(default_factory=Counter)

    @property
    def received(self) -> int:
        return len(self.rtts)

    @property
    def ip(self) -> str | None:
        """The address that answered most often (load balancers can answer with several)."""
        return self.ips.most_common(1)[0][0] if self.ips else None

    def to_dict(self) -> dict:
        r = self.rtts
        return {"ttl": self.ttl, "ip": self.ip, "other_ips": [ip for ip, _ in self.ips.most_common()[1:]],
                "sent": self.sent, "received": len(r),
                "loss_pct": round(100 * (self.sent - len(r)) / self.sent, 1) if self.sent else None,
                "rtt_avg": round(sum(r) / len(r), 2) if r else None,
                "rtt_min": round(min(r), 2) if r else None, "rtt_max": round(max(r), 2) if r else None}


def parse_answer(data: bytes) -> tuple[int, int, int] | None:
    """Raw ICMP packet (with IP header) → (type, ident, seq) of OUR echo request.

    For an echo reply that is in the ICMP header; for "time exceeded" and "unreachable"
    the router quotes our IP header plus the first 8 bytes of our ICMP header.
    """
    if len(data) < 20:
        return None
    off = (data[0] & 0x0F) * 4
    if len(data) < off + 8:
        return None
    typ = data[off]
    if typ == ICMP_ECHO_REPLY:
        ident, seq = struct.unpack_from("!HH", data, off + 4)
        return typ, ident, seq
    if typ in (ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACH):
        inner = off + 8
        if len(data) < inner + 20:
            return None
        ioff = inner + (data[inner] & 0x0F) * 4
        if len(data) < ioff + 8 or data[inner + 9] != socket.IPPROTO_ICMP or data[ioff] != ICMP_ECHO_REQUEST:
            return None
        ident, seq = struct.unpack_from("!HH", data, ioff + 4)
        return typ, ident, seq
    return None


def open_raw() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)


def seq_of(rnd: int, ttl: int) -> int:
    return ((rnd & 0xFF) << 8) | (ttl & 0xFF)


class Tracer:
    def __init__(self, max_hops: int = 20, rounds: int = 10, interval: float = 1.0, timeout: float = 2.0):
        self.max_hops = max_hops
        self.rounds = rounds
        self.interval = interval
        self.timeout = timeout
        self._busy = asyncio.Lock()

    @property
    def busy(self) -> bool:
        return self._busy.locked()

    async def trace(self, address: str) -> dict:
        """One measurement. Never raises: a failure is returned as `error`."""
        started = time.time()
        out = {"address": address, "ts": started, "hops": [], "reached": False, "error": None}
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            out["error"] = "not an IPv4 address"
            return out
        async with self._busy:
            try:
                s = open_raw()
            except OSError as e:
                out["error"] = f"no raw ICMP socket ({e.strerror or e}) - needs CAP_NET_RAW"
                return out
            try:
                hops, reached = await self._run(s, address)
            except OSError as e:
                log.warning("Path measurement to %s failed: %s", address, e)
                out["error"] = f"sending failed ({e.strerror or e})"
                return out
            finally:
                s.close()
        out["hops"] = [h.to_dict() for h in hops]
        out["reached"] = reached
        out["duration_s"] = round(time.time() - started, 1)
        return out

    async def _run(self, s: socket.socket, address: str) -> tuple[list[Hop], bool]:
        loop = asyncio.get_running_loop()
        s.setblocking(False)
        kernel_ts = True
        try:
            s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        except OSError:
            kernel_ts = False
        ident = random.randint(1, 0xFFFF)
        if ident == os.getpid() & 0xFFFF:        # the ping prober's identifier
            ident ^= 0x8000
        hops = {t: Hop(t) for t in range(1, self.max_hops + 1)}
        sent_at: dict[int, tuple[float, float]] = {}        # seq → (wall, monotonic)
        last_ttl = self.max_hops                              # lowered once the target answers
        reached = False

        def on_readable() -> None:
            nonlocal last_ttl, reached
            while True:
                try:
                    data, anc, _f, addr = s.recvmsg(2048, 64)
                except (BlockingIOError, InterruptedError):
                    return
                except OSError:
                    return
                mono = time.monotonic()
                p = parse_answer(data)
                if not p or p[1] != ident or p[2] not in sent_at:
                    continue
                typ, _, seq = p
                wall, sent_mono = sent_at.pop(seq)
                rtt = (mono - sent_mono) * 1000
                k = _timespec_from_cmsg(anc) if kernel_ts else None
                if k is not None and 0 <= (k - wall) * 1000 <= rtt + 1:
                    rtt = (k - wall) * 1000
                ttl = seq & 0xFF
                if rtt > self.timeout * 1000 or ttl not in hops:
                    continue
                hops[ttl].rtts.append(rtt)
                hops[ttl].ips[addr[0]] += 1
                if typ == ICMP_ECHO_REPLY or addr[0] == address:
                    reached = True
                    last_ttl = min(last_ttl, ttl)

        loop.add_reader(s.fileno(), on_readable)
        try:
            for rnd in range(self.rounds):
                t_round = time.monotonic()
                for ttl in range(1, last_ttl + 1):
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                    seq = seq_of(rnd, ttl)
                    sent_at[seq] = (time.time(), time.monotonic())
                    try:
                        s.sendto(build_echo(ident, seq, b"NLATRACE"), (address, 0))
                    except OSError as e:
                        sent_at.pop(seq, None)
                        if ttl == 1:
                            raise                       # nothing goes out at all
                        log.debug("traceroute sendto ttl %d: %s", ttl, e)
                        continue
                    hops[ttl].sent += 1
                    await asyncio.sleep(SPACING_S)
                await asyncio.sleep(max(0.0, self.interval - (time.monotonic() - t_round)))
            await asyncio.sleep(self.timeout)
        finally:
            loop.remove_reader(s.fileno())
        # Probes beyond the target were sent in early rounds before it was known; drop those hops.
        return [hops[t] for t in range(1, last_ttl + 1)], reached
