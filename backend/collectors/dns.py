"""DNS prober: measures response time and failures of Pi-hole (local) and an upstream resolver.

A DNS outage is not in-game lag, but it explains "the internet is down" moments.
"""
from __future__ import annotations

import asyncio
import logging
import random
import socket
import struct
import time
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)

DnsCallback = Callable[[str, float, "float | None", str, str], None]  # server, ts, ms, status, kind


def build_query(name: str, qid: int, qtype: int = 1) -> bytes:
    hdr = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.strip(".").split(".")) + b"\x00"
    return hdr + q + struct.pack("!HH", qtype, 1)


def parse_response(data: bytes, qid: int) -> str:
    if len(data) < 12:
        return "malformed"
    rid, flags, _qd, an = struct.unpack_from("!HHHH", data)
    if rid != qid:
        return "mismatch"
    rcode = flags & 0x0F
    return {0: "ok" if an > 0 else "nodata", 2: "servfail", 3: "nxdomain", 5: "refused"}.get(rcode, f"rcode{rcode}")


def system_resolver() -> str | None:
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            f = line.split()
            if len(f) >= 2 and f[0] == "nameserver":
                return f[1]
    except OSError:
        pass
    return None


async def query(server: str, name: str, timeout: float) -> tuple[float | None, str]:
    loop = asyncio.get_running_loop()
    qid = random.randint(0, 0xFFFF)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    try:
        t0 = time.perf_counter()
        await loop.sock_sendto(s, build_query(name, qid), (server, 53))
        deadline = t0 + timeout
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return None, "timeout"
            try:
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(s, 1500), remaining)
            except asyncio.TimeoutError:
                return None, "timeout"
            status = parse_response(data, qid)
            if status == "mismatch":
                continue
            ms = (time.perf_counter() - t0) * 1000
            return (round(ms, 2) if status in ("ok", "nodata", "nxdomain") else None), status
    except OSError as e:
        return None, f"error:{e.strerror or e}"
    finally:
        s.close()


def random_label(n: int = 10) -> str:
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


# Answers that mean "the path worked". nxdomain is the normal case for the uncached
# probe and explicitly a success: the name does not exist, but resolution
# went all the way through.
OK_STATUS = frozenset({"ok", "nodata", "nxdomain"})


class DnsProber:
    """Measures DNS in two variants, because they tell different things.

    * **cached** (`query_name`, e.g. example.com): Pi-hole answers from its
      own cache. This measures whether the resolver still responds at all - and
      nothing else. A value of 0.3 ms does not mean name resolution works.
    * **uncached** (random name under `uncached_suffix`, default
      `.invalid`): the name cannot be in the cache, so the query really goes
      all the way to the upstream. The answer is NXDOMAIN - that counts as success.
      `.invalid` is reserved for exactly this purpose by RFC 2606; no foreign
      zone is burdened.

    The variants alternate so that the query rate stays constant.
    """

    def __init__(self, servers: list[str], name: str, interval: float, timeout: float,
                 on_result: DnsCallback, pihole_present: bool, uncached_suffix: str | None = None):
        self.servers = []
        for s in servers:
            if s == "local":
                s = "127.0.0.1" if pihole_present else (system_resolver() or "127.0.0.1")
            if s not in self.servers:
                self.servers.append(s)
        self.name = name
        self.uncached_suffix = (uncached_suffix or "").strip(".") or None
        self.interval = interval
        self.timeout = timeout
        self.on_result = on_result
        self._task: asyncio.Task | None = None
        self.last: dict[str, dict] = {}
        self._uncached_turn = False

    def next_query(self) -> tuple[str, str]:
        """(name to query, kind). Alternates between cached and uncached."""
        if self.uncached_suffix and self._uncached_turn:
            return f"{random_label()}.{self.uncached_suffix}", "uncached"
        return self.name, "cached"

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="dns-prober")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _run(self) -> None:
        while True:
            ts = time.time()
            name, kind = self.next_query()
            self._uncached_turn = not self._uncached_turn
            results = await asyncio.gather(*(query(s, name, self.timeout) for s in self.servers))
            for server, (ms, status) in zip(self.servers, results):
                self.last[server] = {"ts": ts, "ms": ms, "status": status, "kind": kind, "name": name}
                self.on_result(server, ts, ms, status, kind)
            await asyncio.sleep(max(0.1, self.interval - (time.time() - ts)))
