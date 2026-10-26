"""Pi-hole integration (read-only).

Reads the FTL database (`/etc/pihole/pihole-FTL.db`, Pi-hole v5 and v6):
* `network` / `network_addresses`: MAC, IP, hostname, vendor
* `queries`: DNS queries per client → activity and top domains per minute

IMPORTANT: DNS queries are NOT a measure of bandwidth. They are only used to
map IP → device and as context ("device just queried icloud.com").
By default FTL writes to the database once per minute,
so DNS data is delayed by up to ~60 s.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from collections import Counter, defaultdict
from dataclasses import dataclass

log = logging.getLogger(__name__)

# Pi-hole status codes that mean a block (v5 and v6)
BLOCKED_STATUS = {1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18}


@dataclass
class PiholeHost:
    mac: str | None
    ip: str
    name: str | None
    vendor: str | None
    last_query: float | None


class PiholeReader:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.error: str | None = None
        self._last_id: int | None = None
        self._buckets: dict[int, dict[str, list]] = defaultdict(dict)
        self.version: str | None = None

    def available(self) -> bool:
        return os.path.exists(self.db_path)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=5)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA query_only = ON")
        return c

    def check(self) -> tuple[bool, str]:
        if not self.available():
            return False, f"{self.db_path} not found"
        try:
            with self._conn() as c:
                c.execute("SELECT 1 FROM network LIMIT 1").fetchall()
                self.version = "v6" if os.path.exists("/etc/pihole/pihole.toml") else "v5"
            return True, f"FTL database readable ({self.version})"
        except sqlite3.Error as e:
            return False, f"FTL database not readable: {e} (user in group 'pihole'?)"

    def hosts(self) -> list[PiholeHost]:
        """One entry per device: its newest IPv4 and its newest host name.

        FTL keeps every IP a device ever had (one device here had 34 rows). Reading
        all of them let whichever row came last set the device's IP and name - often
        an address from weeks ago.
        """
        out: list[PiholeHost] = []
        try:
            with self._conn() as c:
                rows = c.execute(
                    "SELECT n.hwaddr AS mac, n.macVendor AS vendor, n.lastQuery AS lastq, "
                    "a.ip AS ip, a.name AS name, a.lastSeen AS seen FROM network n "
                    "JOIN network_addresses a ON a.network_id = n.id ORDER BY a.lastSeen"
                ).fetchall()
            self.error = None
        except sqlite3.Error as e:
            self.error = str(e)
            return out
        newest: dict[str, dict] = {}
        for r in rows:                                  # ordered by lastSeen: later rows win
            mac = (r["mac"] or "").lower()
            if not mac or mac.startswith("ip-") or ":" not in mac:  # Pi-hole uses "ip-..." for clients without a MAC
                out.append(PiholeHost(mac=None, ip=r["ip"], name=r["name"] or None, vendor=None,
                                      last_query=r["lastq"] or None))
                continue
            e = newest.setdefault(mac, {"ip": None, "name": None, "vendor": r["vendor"], "lastq": r["lastq"]})
            if ":" not in (r["ip"] or ":"):
                e["ip"] = r["ip"]
            if r["name"]:
                e["name"] = r["name"]
        for mac, e in newest.items():
            out.append(PiholeHost(mac=mac, ip=e["ip"], name=e["name"], vendor=e["vendor"] or None,
                                  last_query=e["lastq"] or None))
        return out


    def poll_queries(self, max_rows: int = 50000) -> list[tuple]:
        """Reads new DNS queries and returns dns_queries rows (ts, client, n, blocked, top_json)."""
        try:
            with self._conn() as c:
                if self._last_id is None:
                    # The v6 view `queries` joins four tables; through it this lookup took 27 s on the Pi.
                    # The table behind it has the timestamp index.
                    table = "query_storage" if _has_table(c, "query_storage") else "queries"
                    r = c.execute(f"SELECT MIN(id) FROM {table} WHERE timestamp > ?", (time.time() - 900,)).fetchone()
                    start = (r[0] - 1) if r and r[0] else None
                    if start is None:
                        r = c.execute("SELECT MAX(id) FROM queries").fetchone()
                        start = r[0] or 0
                    self._last_id = start
                rows = c.execute(
                    "SELECT id, timestamp, status, domain, client FROM queries WHERE id > ? ORDER BY id LIMIT ?",
                    (self._last_id, max_rows),
                ).fetchall()
            self.error = None
        except sqlite3.Error as e:
            self.error = str(e)
            return []
        touched: set[tuple[int, str]] = set()
        for r in rows:
            self._last_id = r["id"]
            minute = int(r["timestamp"]) // 60 * 60
            b = self._buckets[minute].setdefault(r["client"], [0, 0, Counter()])
            b[0] += 1
            if r["status"] in BLOCKED_STATUS:
                b[1] += 1
            b[2][r["domain"]] += 1
            touched.add((minute, r["client"]))
        out = []
        for minute, client in touched:
            n, blocked, dom = self._buckets[minute][client]
            out.append((minute, client, n, blocked, json.dumps(dom.most_common(8))))
        cutoff = time.time() - 600
        for m in [m for m in self._buckets if m < cutoff]:
            del self._buckets[m]
        return out


def _has_table(c: sqlite3.Connection, name: str) -> bool:
    return c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def read_dhcp_leases(path: str) -> list[PiholeHost]:
    """Pi-hole's (dnsmasq's) current DHCP leases: `expiry mac ip hostname client-id`.

    Read-only, and only meaningful where Pi-hole is the DHCP server. A missing or
    unreadable file simply yields nothing.
    """
    out: list[PiholeHost] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                p = line.split()
                if len(p) < 4 or p[1].count(":") != 5:
                    continue                            # DHCPv6 lines (duid) have no MAC
                out.append(PiholeHost(mac=p[1].lower(), ip=p[2], name=None if p[3] == "*" else p[3],
                                      vendor=None, last_query=None))
    except OSError:
        pass
    return out
