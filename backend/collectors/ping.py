"""ICMP-Latenzmessung ohne externe Prozesse.

* Ein einziger Socket für alle Ziele, eingebunden in die asyncio-Eventloop.
* Bevorzugt unprivilegierter ICMP-Datagram-Socket (net.ipv4.ping_group_range),
  sonst Raw-Socket (benötigt CAP_NET_RAW, wird vom systemd-Service gesetzt).
* Empfangszeitpunkt über Kernel-Zeitstempel (SO_TIMESTAMPNS), damit Verzögerungen
  der Eventloop die RTT nicht verfälschen.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger(__name__)

SO_TIMESTAMPNS = 35  # Linux, nicht in Pythons socket-Modul definiert
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

ResultCallback = Callable[[int, float, "float | None"], None]  # target_id, send_ts, rtt_ms


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_echo(ident: int, seq: int, payload: bytes) -> bytes:
    hdr = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    csum = checksum(hdr + payload)
    return struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, csum, ident, seq) + payload


def parse_reply(data: bytes, raw: bool) -> tuple[int, int, int] | None:
    """Gibt (type, ident, seq) zurück. Raw-Sockets liefern den IP-Header mit."""
    off = 0
    if raw:
        if len(data) < 20:
            return None
        off = (data[0] & 0x0F) * 4
    if len(data) < off + 8:
        return None
    typ, _code, _cs, ident, seq = struct.unpack_from("!BBHHH", data, off)
    return typ, ident, seq


def _timespec_from_cmsg(ancdata: list) -> float | None:
    for level, ctype, cdata in ancdata:
        if level == socket.SOL_SOCKET and ctype == SO_TIMESTAMPNS:
            if len(cdata) >= 16:
                sec, nsec = struct.unpack_from("qq", cdata)
            elif len(cdata) >= 8:           # 32-bit armhf
                sec, nsec = struct.unpack_from("ii", cdata)
            else:
                return None
            return sec + nsec / 1e9
    return None


@dataclass
class _Pending:
    target_id: int
    address: str
    send_wall: float
    send_mono: float
    deadline: float


@dataclass
class ProbeTarget:
    target_id: int
    address: str            # Hostname oder IP
    kind: str               # gateway | internet | game
    name: str | None = None
    resolved: str | None = None
    resolved_at: float = 0.0
    fast: bool = False      # im Gaming-Modus erhöhte Frequenz


class IcmpProber:
    def __init__(self, on_result: ResultCallback, timeout: float = 1.5):
        self._on_result = on_result
        # Zusätzliche Mithörer, z. B. die Ziel-Prüfung im Setup-Wizard. Sie bekommen
        # dieselben Ergebnisse, ohne dass ein zweiter Socket geöffnet werden muss.
        self.extra_callbacks: list[ResultCallback] = []
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.mode: str | None = None
        self.error: str | None = None
        self.ident = os.getpid() & 0xFFFF
        self._seq = 0
        self._pending: dict[int, _Pending] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._sweeper: asyncio.Task | None = None
        self.kernel_ts = False
        self.sent = 0
        self.received = 0

    def _emit(self, target_id: int, send_ts: float, rtt: float | None) -> None:
        self._on_result(target_id, send_ts, rtt)
        for cb in list(self.extra_callbacks):
            try:
                cb(target_id, send_ts, rtt)
            except Exception:                      # pragma: no cover - Mithörer darf nie stören
                log.exception("Zusätzlicher Ping-Callback fehlgeschlagen")

    # --------------------------------------------------------------- lifecycle
    def open(self) -> bool:
        errors = []
        for mode, stype in (("dgram", socket.SOCK_DGRAM), ("raw", socket.SOCK_RAW)):
            try:
                s = socket.socket(socket.AF_INET, stype, socket.IPPROTO_ICMP)
            except OSError as e:
                errors.append(f"{mode}: {e.strerror or e}")
                continue
            s.setblocking(False)
            try:
                s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
                self.kernel_ts = True
            except OSError:
                self.kernel_ts = False
            self.sock, self.mode = s, mode
            self.error = None
            log.info("ICMP-Socket geöffnet (%s, Kernel-Zeitstempel=%s)", mode, self.kernel_ts)
            return True
        self.error = "ICMP nicht möglich – " + "; ".join(errors) + \
            " (CAP_NET_RAW fehlt oder net.ipv4.ping_group_range schließt die Gruppe aus)"
        log.error(self.error)
        return False

    async def start(self) -> bool:
        self._loop = asyncio.get_running_loop()
        if not self.open():
            return False
        assert self.sock is not None
        self._loop.add_reader(self.sock.fileno(), self._on_readable)
        self._sweeper = asyncio.create_task(self._sweep_loop(), name="icmp-sweeper")
        return True

    async def stop(self) -> None:
        if self._sweeper:
            self._sweeper.cancel()
        if self.sock and self._loop:
            self._loop.remove_reader(self.sock.fileno())
            self.sock.close()
        self.sock = None

    # --------------------------------------------------------------- sending
    def send(self, target_id: int, address: str) -> None:
        now_wall = time.time()
        if self.sock is None:
            self._emit(target_id, now_wall, None)
            return
        self._seq = (self._seq + 1) & 0xFFFF
        seq = self._seq
        # Payload: 8 Byte Kennung, damit fremde Replies sicher verworfen werden
        pkt = build_echo(self.ident, seq, b"NLAPROBE" + struct.pack("!d", now_wall))
        send_mono = time.monotonic()
        send_wall = time.time()
        try:
            self.sock.sendto(pkt, (address, 0))
        except OSError as e:
            # z. B. Netz nicht erreichbar → sofort als verloren werten
            log.debug("sendto %s: %s", address, e)
            self._emit(target_id, send_wall, None)
            return
        self.sent += 1
        old = self._pending.pop(seq, None)
        if old:  # Sequenz-Überlauf nach 65536 Probes ohne Antwort
            self._emit(old.target_id, old.send_wall, None)
        self._pending[seq] = _Pending(target_id, address, send_wall, send_mono, send_mono + self.timeout)

    # --------------------------------------------------------------- receiving
    def _on_readable(self) -> None:
        assert self.sock is not None
        while True:
            try:
                data, anc, _flags, addr = self.sock.recvmsg(2048, 64)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as e:
                log.debug("recvmsg: %s", e)
                return
            recv_mono = time.monotonic()
            recv_kernel = _timespec_from_cmsg(anc) if self.kernel_ts else None
            parsed = parse_reply(data, raw=(self.mode == "raw"))
            if not parsed:
                continue
            typ, ident, seq = parsed
            if typ != ICMP_ECHO_REPLY:
                continue
            if self.mode == "raw" and ident != self.ident:
                continue  # Antwort auf fremden Ping
            p = self._pending.get(seq)
            if p is None or addr[0] != p.address:
                continue
            del self._pending[seq]
            rtt = (recv_mono - p.send_mono) * 1000.0
            if recv_kernel is not None:
                k = (recv_kernel - p.send_wall) * 1000.0
                # Kernel-Zeit bevorzugen, außer bei Uhrsprung (NTP) → dann monotone Zeit
                if 0 <= k <= rtt + 1.0:
                    rtt = k
            if rtt > self.timeout * 1000:
                self._emit(p.target_id, p.send_wall, None)
            else:
                self.received += 1
                self._emit(p.target_id, p.send_wall, round(rtt, 3))

    async def _sweep_loop(self) -> None:
        while True:
            await asyncio.sleep(0.05)
            now = time.monotonic()
            expired = [s for s, p in self._pending.items() if p.deadline <= now]
            for s in expired:
                p = self._pending.pop(s)
                self._emit(p.target_id, p.send_wall, None)


class ProbeScheduler:
    """Sendet periodisch Probes an alle Ziele, ausgerichtet am Sekundenraster."""

    def __init__(self, prober: IcmpProber, interval: float, fast_interval: float):
        self.prober = prober
        self.interval = interval
        self.fast_interval = fast_interval
        self.fast_mode = False
        self.targets: list[ProbeTarget] = []
        self._task: asyncio.Task | None = None
        self._resolve_errors: dict[int, str] = {}

    def set_targets(self, targets: list[ProbeTarget]) -> None:
        self.targets = targets

    def add_target(self, t: ProbeTarget) -> None:
        if all(x.target_id != t.target_id for x in self.targets):
            self.targets.append(t)

    def remove_kind(self, kind: str) -> None:
        self.targets = [t for t in self.targets if t.kind != kind]

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="probe-scheduler")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _resolve(self, t: ProbeTarget) -> str | None:
        try:
            ipaddress.IPv4Address(t.address)
            return t.address
        except ValueError:
            pass
        if t.resolved and time.time() - t.resolved_at < 600:
            return t.resolved
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(t.address, None, family=socket.AF_INET)
            t.resolved = infos[0][4][0]
            t.resolved_at = time.time()
            self._resolve_errors.pop(t.target_id, None)
        except OSError as e:
            self._resolve_errors[t.target_id] = str(e)
            # Alte Auflösung weiterverwenden, falls vorhanden
        return t.resolved

    async def _run(self) -> None:
        while True:
            # Ein Zyklus je Messintervall (im Gaming-Modus entsprechend kürzer),
            # ausgerichtet am Sekundenraster.
            cycle = self.fast_interval if self.fast_mode else self.interval
            now = time.time()
            nxt = (int(now / cycle) + 1) * cycle
            await asyncio.sleep(max(0.0, nxt - time.time()))
            due = list(self.targets)
            if not due:
                await asyncio.sleep(cycle)
                continue
            # Pings gleichmäßig über das Intervall verteilen statt als Bündel zu senden.
            # Ein Burst aus mehreren ICMP-Paketen innerhalb weniger Millisekunden wird von
            # Routern, Providern und Zielservern häufig rate-limitiert – das sähe wie
            # Paketverlust aus, obwohl die Leitung in Ordnung ist.
            spacing = max(0.01, min(0.25, cycle * 0.7 / len(due)))
            for i, t in enumerate(due):
                addr = await self._resolve(t)
                if addr is None:
                    # Name nicht auflösbar: kein ICMP-Verlust, sondern DNS-Problem → keine Probe
                    continue
                self.prober.send(t.target_id, addr)
                if i < len(due) - 1:
                    await asyncio.sleep(spacing)
