"""Pi-hole-Integration (nur lesend).

Liest die FTL-Datenbank (`/etc/pihole/pihole-FTL.db`, Pi-hole v5 und v6):
* `network` / `network_addresses`: MAC, IP, Hostname, Hersteller
* `queries`: DNS-Anfragen je Client → Aktivität und Top-Domains pro Minute

WICHTIG: DNS-Anfragen sind KEIN Maß für Bandbreite. Sie werden nur für die
Zuordnung IP → Gerät und als Kontext ("Gerät fragte gerade icloud.com an")
verwendet. FTL schreibt standardmäßig einmal pro Minute in die Datenbank,
daher sind DNS-Daten bis zu ~60 s verzögert.
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

# Pi-hole Status-Codes, die eine Blockierung bedeuten (v5 und v6)
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
            return False, f"{self.db_path} nicht gefunden"
        try:
            with self._conn() as c:
                c.execute("SELECT 1 FROM network LIMIT 1").fetchall()
                self.version = "v6" if os.path.exists("/etc/pihole/pihole.toml") else "v5"
            return True, f"FTL-Datenbank lesbar ({self.version})"
        except sqlite3.Error as e:
            return False, f"FTL-Datenbank nicht lesbar: {e} (Benutzer in Gruppe 'pihole'?)"

    def hosts(self) -> list[PiholeHost]:
        out: list[PiholeHost] = []
        try:
            with self._conn() as c:
                rows = c.execute(
                    "SELECT n.hwaddr AS mac, n.macVendor AS vendor, n.lastQuery AS lastq, "
                    "a.ip AS ip, a.name AS name FROM network n "
                    "JOIN network_addresses a ON a.network_id = n.id"
                ).fetchall()
            self.error = None
        except sqlite3.Error as e:
            self.error = str(e)
            return out
        for r in rows:
            mac = (r["mac"] or "").lower()
            if not mac or mac.startswith("ip-") or ":" not in mac:  # Pi-hole nutzt "ip-..." für MAC-lose Clients
                mac = None
            out.append(PiholeHost(mac=mac, ip=r["ip"], name=r["name"] or None,
                                  vendor=r["vendor"] or None, last_query=r["lastq"] or None))
        return out

    def poll_queries(self, max_rows: int = 50000) -> list[tuple]:
        """Liest neue DNS-Anfragen und liefert dns_queries-Zeilen (ts, client, n, blocked, top_json)."""
        try:
            with self._conn() as c:
                if self._last_id is None:
                    r = c.execute("SELECT MIN(id) FROM queries WHERE timestamp > ?", (time.time() - 900,)).fetchone()
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
