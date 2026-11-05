"""Pi-hole's DHCP log, read-only: what devices asked for and what Pi-hole answered.

When Pi-hole hands out the addresses, its dnsmasq writes every DHCP step to pihole.log. That
is the complete record - the capture only sees the part that passes the FRITZ!Box as
broadcast. The file is rotated at midnight to pihole.log.1; on start both are read, after
that only what was added.
"""
from __future__ import annotations

import logging
import os
import re
import time

log = logging.getLogger(__name__)

KEEP = 86400
MAX_EVENTS = 50000
_LINE = re.compile(rb"^([A-Z][a-z]{2}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) dnsmasq-dhcp\[\d+\]: (?:\d+ )?"
                   rb"DHCP([A-Z]+)\([^)]*\) (.*)$")
_MAC = re.compile(rb"\b((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\b")
_IPV4 = re.compile(rb"^(\d{1,3}(?:\.\d{1,3}){3}) ")
_MONTHS = {m.encode(): i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_line(line: bytes, now: float) -> tuple | None:
    """(ts, kind, mac, ip, note) of one dnsmasq-dhcp line, else None."""
    m = _LINE.match(line.rstrip(b"\r\n"))
    if not m:
        return None
    mon = _MONTHS.get(m.group(1))
    if mon is None:
        return None
    rest = m.group(7)
    mac = _MAC.search(rest)
    if not mac:
        return None
    # syslog lines carry no year: take this year, unless that lies in the future (log from December)
    year = time.localtime(now).tm_year
    parts = (int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
    try:
        ts = time.mktime((year, mon, *parts, 0, 0, -1))
        if ts > now + 86400:
            ts = time.mktime((year - 1, mon, *parts, 0, 0, -1))
    except (OverflowError, ValueError):
        return None
    ip = _IPV4.match(rest)
    note = rest[mac.end():].strip().decode("utf-8", "replace")[:80]
    return (ts, m.group(6).decode().lower(), mac.group(1).decode(), ip.group(1).decode() if ip else None, note)


class DhcpLog:
    def __init__(self, path: str):
        self.path = path
        self.events: list[tuple] = []
        self.error: str | None = None
        self._ino: int | None = None
        self._pos = 0
        self.read_since: float | None = None

    def poll(self, now: float | None = None) -> int:
        """Reads what was added; returns the number of new DHCP events."""
        now = now or time.time()
        try:
            st = os.stat(self.path)
        except OSError as e:
            self.error = f"{self.path}: {e.strerror or e}"
            return 0
        added = 0
        try:
            if self._ino is None:
                added += self._read(self.path + ".1", 0, now)
                # yesterday's file covers the whole day; without it the record starts at midnight
                self.read_since = now - KEEP if os.path.exists(self.path + ".1") else (
                    time.mktime(time.localtime(now)[:3] + (0, 0, 0, 0, 0, -1)))
            elif st.st_ino != self._ino or st.st_size < self._pos:
                # rotated: the rest of the old file is now pihole.log.1
                try:
                    if os.stat(self.path + ".1").st_ino == self._ino:
                        added += self._read(self.path + ".1", self._pos, now)
                except OSError:
                    pass
                self._pos = 0
            self._ino = st.st_ino
            added += self._read(self.path, self._pos, now, current=True)
            self.error = None
        except OSError as e:
            self.error = f"{self.path}: {e.strerror or e}"
        cut = now - KEEP
        if self.events and self.events[0][0] < cut:
            self.events = [e for e in self.events if e[0] >= cut]
        return added

    def _read(self, path: str, pos: int, now: float, current: bool = False) -> int:
        added = 0
        try:
            fh = open(path, "rb")
        except FileNotFoundError:
            return 0
        with fh:
            fh.seek(pos)
            cut = now - KEEP
            for line in fh:
                if not line.endswith(b"\n"):
                    break                       # half-written line: read it next time
                pos += len(line)
                if b"dnsmasq-dhcp" not in line:
                    continue
                ev = parse_line(line, now)
                if ev and ev[0] >= cut:
                    self.events.append(ev)
                    added += 1
            if current:
                self._pos = pos
        if len(self.events) > MAX_EVENTS:
            del self.events[:len(self.events) - MAX_EVENTS]
        return added
