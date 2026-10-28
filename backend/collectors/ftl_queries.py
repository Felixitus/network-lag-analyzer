"""Read-only access to the DNS query log in Pi-hole's FTL database.

`PiholeReader.poll_queries` only feeds the per-minute DNS context of the lag
analysis. The DNS usage module needs whole time ranges per client, and on a log
with ~10 million rows that is only affordable on what FTL indexes: the only index
on `query_storage` is `timestamp`. So every range query here filters on the
timestamp first and on the integer client id second - never on the client IP
through the `queries` view, which would join first and filter afterwards.

Two schemas exist in the wild:
* normalized (later v5 releases and all of v6): `query_storage` with integer domain/client
  references into `domain_by_id` / `client_by_id`, plus a `queries` view.
* legacy (older v5): `queries` is a plain table with domain and client as text.

The schema is detected from `sqlite_master`, never from the Pi-hole version
string, because the version string is not in the database.

Pi-hole is never modified: connections are opened with `mode=ro` and
`PRAGMA query_only`. The process needs read access to the file only (group
`pihole`, see install.sh) - never `sudo sqlite3`, which leaves root-owned
`-wal`/`-shm` files behind and locks FTL out of its own database.
"""
from __future__ import annotations

import ipaddress
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterable, Iterator, Literal

from .pihole import BLOCKED_STATUS

# FTL status codes (https://docs.pi-hole.net/database/query-database/#query-status)
ALLOWED_STATUS = {2, 3, 17}          # forwarded, answered from cache, answered from stale cache
# 12/13 = the client retried a query, 14 = identical query already in flight.
# They are the same lookup again, not a new one - counting them would inflate
# the request count of clients with flaky connectivity.
DUPLICATE_STATUS = {12, 13, 14}

Outcome = Literal["allowed", "blocked", "duplicate", "unknown"]


# What each FTL status code (Pi-hole v6) means, for people.
STATUS_TEXT = {
    1: "blocked by a blocklist (gravity)", 2: "forwarded to the upstream DNS server", 3: "answered from the cache",
    4: "blocked by a regex rule", 5: "blocked by your denylist", 6: "blocked by the upstream server (blocking IP)",
    7: "blocked by the upstream server (null answer)", 8: "blocked by the upstream server (NXDOMAIN)",
    9: "blocked by a blocklist (via CNAME)", 10: "blocked by a regex rule (via CNAME)",
    11: "blocked by your denylist (via CNAME)", 12: "retry of an earlier query", 13: "retry (DNSSEC)",
    14: "duplicate of a query in progress", 15: "blocked because the database was busy",
    16: "special domain answered by Pi-hole itself (e.g. Private Relay or DoH canary)",
    17: "answered from the cache (stale)", 18: "blocked by the upstream server (EDE 15)",
}


def outcome(status: int | None) -> Outcome:
    if status in BLOCKED_STATUS:
        return "blocked"
    if status in ALLOWED_STATUS:
        return "allowed"
    if status in DUPLICATE_STATUS:
        return "duplicate"
    return "unknown"


def normalize_ip(raw: str | None) -> str | None:
    """Canonical form, so that `::FFFF:192.0.2.1`, `192.0.2.1` and `fe80::0:1` compare equal."""
    if not raw:
        return None
    s = raw.strip()
    try:
        ip = ipaddress.ip_address(s.split("%", 1)[0])   # strip an IPv6 zone id ("fe80::1%eth0")
    except ValueError:
        return s.lower()
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return str(ip.ipv4_mapped)
    return ip.compressed


def normalize_mac(raw: str | None) -> str | None:
    """Real MAC or None. FTL uses `ip-<address>` as hwaddr for clients without a known MAC."""
    if not raw:
        return None
    s = raw.strip().lower()
    if s.startswith("ip-") or s.count(":") != 5:
        return None
    return s


@dataclass(slots=True, frozen=True)
class DnsQuery:
    id: int
    ts: float
    client: str          # normalized IP
    domain: str
    status: int

    @property
    def outcome(self) -> Outcome:
        return outcome(self.status)


@dataclass(slots=True, frozen=True)
class NetworkAddress:
    """One row of FTL's `network` × `network_addresses`: what Pi-hole knows about an IP right now."""
    ip: str
    mac: str | None
    name: str | None
    vendor: str | None
    device_first_seen: float | None
    ip_last_seen: float | None


@dataclass(slots=True, frozen=True)
class FtlSchema:
    normalized: bool


class FtlSchemaError(RuntimeError):
    """The database does not look like any FTL schema this module knows."""


class FtlQueryLog:
    def __init__(self, db_path: str, timeout: float = 5.0):
        self.db_path = db_path
        self.timeout = timeout
        self._schema: FtlSchema | None = None

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        c = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=self.timeout)
        try:
            c.row_factory = sqlite3.Row
            # FTL stores query names as they arrived, including bytes that are not
            # UTF-8 (malformed or malicious queries). Strict decoding aborted a whole
            # 30-day evaluation on the Pi because of a single such row.
            c.text_factory = lambda b: b.decode("utf-8", "replace")
            c.execute("PRAGMA query_only = ON")
            yield c
        finally:
            c.close()

    def schema(self) -> FtlSchema:
        if self._schema is None:
            with self.connect() as c:
                self._schema = self._detect(c)
        return self._schema

    @staticmethod
    def _detect(c: sqlite3.Connection) -> FtlSchema:
        kinds = {r["name"]: r["type"] for r in c.execute(
            "SELECT name, type FROM sqlite_master WHERE name IN "
            "('query_storage', 'queries', 'domain_by_id', 'client_by_id')")}
        if kinds.get("query_storage") == "table" and "domain_by_id" in kinds and "client_by_id" in kinds:
            return FtlSchema(normalized=True)
        if kinds.get("queries") == "table":
            return FtlSchema(normalized=False)
        raise FtlSchemaError("neither query_storage nor a queries table found - not an FTL database?")

    def _table(self) -> str:
        return "query_storage" if self.schema().normalized else "queries"

    def time_range(self) -> tuple[float | None, float | None]:
        """Oldest and newest query timestamp. MIN/MAX on the indexed column, no COUNT(*) scan."""
        with self.connect() as c:
            r = c.execute(f"SELECT MIN(timestamp), MAX(timestamp) FROM {self._table()}").fetchone()
        return (r[0], r[1]) if r else (None, None)

    def max_id(self) -> int:
        with self.connect() as c:
            return c.execute(f"SELECT MAX(id) FROM {self._table()}").fetchone()[0] or 0

    def id_before(self, ts: float) -> int:
        """Largest id that is safe as `last_id` to start reading at timestamp `ts`.

        Uses the timestamp index (MIN(id) over a range), not a scan by id.
        """
        with self.connect() as c:
            r = c.execute(f"SELECT MIN(id) FROM {self._table()} WHERE timestamp >= ?", (ts,)).fetchone()[0]
            if r is None:
                return c.execute(f"SELECT MAX(id) FROM {self._table()}").fetchone()[0] or 0
            return r - 1

    def status_counts(self, domain: str, since: float) -> dict[int, int]:
        """How Pi-hole answered one name since `since`: FTL status code → count.
        The time range uses the index; the name is filtered in that range only."""
        with self.connect() as c:
            if self.schema().normalized:
                ids = [r[0] for r in c.execute("SELECT id FROM domain_by_id WHERE domain = ?", (domain,))]
                if not ids:
                    return {}
                sql = (f"SELECT status, COUNT(*) FROM query_storage WHERE timestamp >= ? "
                       f"AND domain IN ({','.join('?' * len(ids))}) GROUP BY status")
                args: list = [since, *ids]
            else:
                sql = "SELECT status, COUNT(*) FROM queries WHERE timestamp >= ? AND domain = ? GROUP BY status"
                args = [since, domain]
            return {int(s): n for s, n in c.execute(sql, args)}

    def client_ids(self, ips: Iterable[str]) -> list[int]:
        """All `client_by_id` ids for these IPs. One IP has several ids when its name changed."""
        want = {normalize_ip(ip) for ip in ips}
        with self.connect() as c:
            return [r["id"] for r in c.execute("SELECT id, ip FROM client_by_id")
                    if normalize_ip(r["ip"]) in want]

    def iter_range(self, start: float, end: float, clients: Iterable[str] | None = None,
                   batch: int = 5000) -> Iterator[DnsQuery]:
        """Queries with start <= timestamp < end, in time order, streamed in batches.

        `clients` limits the result to these IPs. An empty iterable yields nothing.
        """
        if self.schema().normalized:
            sql = ("SELECT q.id, q.timestamp, q.status, COALESCE(d.domain, q.domain) AS domain, "
                   "COALESCE(c.ip, q.client) AS client FROM query_storage q "
                   "LEFT JOIN domain_by_id d ON d.id = q.domain "
                   "LEFT JOIN client_by_id c ON c.id = q.client "
                   "WHERE q.timestamp >= ? AND q.timestamp < ?")
            col = "q.client"
        else:
            sql = ("SELECT id, timestamp, status, domain, client FROM queries "
                   "WHERE timestamp >= ? AND timestamp < ?")
            col = "client"
        args: list = [start, end]
        if clients is not None:
            if self.schema().normalized:
                keys: list = self.client_ids(clients)
            else:
                # Legacy rows store the IP as text exactly as FTL saw it; match all spellings.
                want = {normalize_ip(ip) for ip in clients}
                with self.connect() as c:
                    keys = [r[0] for r in c.execute("SELECT DISTINCT client FROM queries")
                            if normalize_ip(r[0]) in want]
            if not keys:
                return
            sql += f" AND {col} IN ({','.join('?' * len(keys))})"
            args += keys
        sql += (" ORDER BY q.timestamp, q.id" if self.schema().normalized else " ORDER BY timestamp, id")
        with self.connect() as c:
            cur = c.execute(sql, args)
            while rows := cur.fetchmany(batch):
                for r in rows:
                    yield _row(r)

    def read_since(self, last_id: int, limit: int = 50000) -> list[DnsQuery]:
        """Queries with id > last_id, for incremental processing. Ordered by id."""
        with self.connect() as c:
            if self.schema().normalized:
                rows = c.execute(
                    "SELECT q.id, q.timestamp, q.status, COALESCE(d.domain, q.domain) AS domain, "
                    "COALESCE(c.ip, q.client) AS client FROM query_storage q "
                    "LEFT JOIN domain_by_id d ON d.id = q.domain "
                    "LEFT JOIN client_by_id c ON c.id = q.client "
                    "WHERE q.id > ? ORDER BY q.id LIMIT ?", (last_id, limit)).fetchall()
            else:
                rows = c.execute("SELECT id, timestamp, status, domain, client FROM queries "
                                 "WHERE id > ? ORDER BY id LIMIT ?", (last_id, limit)).fetchall()
        return [_row(r) for r in rows]

    def forwarded(self, start: float, end: float) -> list[tuple[float, str, float | None]] | None:
        """Queries Pi-hole sent to an upstream server: (timestamp, upstream "ip#port", reply time in
        seconds or None). None when this FTL version records no reply times."""
        with self.connect() as c:
            if self.schema().normalized:
                if not _has_column(c, "query_storage", "reply_time"):
                    return None
                fwd = "COALESCE(f.forward, q.forward)" if _has_table(c, "forward_by_id") else "q.forward"
                join = "LEFT JOIN forward_by_id f ON f.id = q.forward " if _has_table(c, "forward_by_id") else ""
                sql = (f"SELECT q.timestamp, {fwd} AS fwd, q.reply_time FROM query_storage q {join}"
                       "WHERE q.timestamp >= ? AND q.timestamp < ? AND q.status = 2")
            else:
                if not _has_column(c, "queries", "reply_time"):
                    return None
                sql = "SELECT timestamp, forward AS fwd, reply_time FROM queries WHERE timestamp >= ? AND timestamp < ? AND status = 2"
            return [(float(r[0]), str(r[1]), r[2]) for r in c.execute(sql, (start, end)) if r[1]]

    def network(self) -> list[NetworkAddress]:
        with self.connect() as c:
            rows = c.execute(
                "SELECT a.ip, n.hwaddr, a.name, n.macVendor AS vendor, n.firstSeen, a.lastSeen "
                "FROM network_addresses a JOIN network n ON n.id = a.network_id").fetchall()
        out = []
        for r in rows:
            ip = normalize_ip(r["ip"])
            if ip is None:
                continue
            out.append(NetworkAddress(ip=ip, mac=normalize_mac(r["hwaddr"]), name=r["name"] or None,
                                      vendor=r["vendor"] or None, device_first_seen=r["firstSeen"] or None,
                                      ip_last_seen=r["lastSeen"] or None))
        return out


def _row(r: sqlite3.Row) -> DnsQuery:
    return DnsQuery(id=r["id"], ts=float(r["timestamp"]), client=normalize_ip(str(r["client"])) or "",
                    domain=str(r["domain"] or "").lower().rstrip("."), status=r["status"])


def _has_table(c: sqlite3.Connection, name: str) -> bool:
    return c.execute("SELECT 1 FROM sqlite_master WHERE name=?", (name,)).fetchone() is not None


def _has_column(c: sqlite3.Connection, table: str, column: str) -> bool:
    return any(r[1] == column for r in c.execute(f"PRAGMA table_info({table})"))
