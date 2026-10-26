"""Database access: one writer thread with batch inserts, readers via their own connections.

* WAL mode allows parallel readers while writing.
* All writes go through exactly one thread (no lock conflicts).
* High-frequency inserts are collected and written once per second in one
  transaction (`enqueue` + `flush`).
"""
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Iterable, TypeVar

from . import migrations
from .models import SCHEMA, SCHEMA_VERSION

log = logging.getLogger(__name__)
T = TypeVar("T")


def _connect(path: str, readonly: bool = False) -> sqlite3.Connection:
    if readonly and path != ":memory:":
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False, timeout=10)
    else:
        conn = sqlite3.connect(path, check_same_thread=False, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    if not readonly:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")   # WAL + NORMAL: safe enough, little fsync
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA cache_size = -8000")     # 8 MB
        conn.execute("PRAGMA wal_autocheckpoint = 2000")
    return conn


class Database:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._writer = ThreadPoolExecutor(max_workers=1, thread_name_prefix="db-writer")
        self._readers = ThreadPoolExecutor(max_workers=3, thread_name_prefix="db-reader")
        self._local = threading.local()
        self._wconn: sqlite3.Connection | None = None
        self._pending: dict[str, list[tuple]] = defaultdict(list)
        self._pending_lock = threading.Lock()
        self.stats = {"flushes": 0, "rows": 0, "last_flush_ms": 0.0}
        self.migration: dict | None = None      # report of the last start, for /api/status

    # ------------------------------------------------------------------ setup
    def init_sync(self) -> None:
        """Apply due migrations, then create the schema. Runs in the writer thread."""
        def _init() -> None:
            self._wconn = _connect(self.path)
            # Order: first rebuild what already exists, then create new tables.
            self.migration = migrations.migrate(self._wconn, self.path, SCHEMA_VERSION)
            self._wconn.executescript(SCHEMA)
            self._wconn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        self._writer.submit(_init).result()

    async def init(self) -> None:
        await asyncio.get_running_loop().run_in_executor(None, self.init_sync)

    def close(self) -> None:
        try:
            self.flush_sync()
        except Exception:  # pragma: no cover
            log.exception("Flush on shutdown failed")
        def _close() -> None:
            if self._wconn:
                self._wconn.execute("PRAGMA optimize")
                self._wconn.close()
        self._writer.submit(_close).result()
        self._writer.shutdown(wait=True)
        self._readers.shutdown(wait=False)

    # ---------------------------------------------------------------- writing
    def enqueue(self, sql: str, params: tuple) -> None:
        with self._pending_lock:
            self._pending[sql].append(params)

    def enqueue_many(self, sql: str, rows: Iterable[tuple]) -> None:
        with self._pending_lock:
            self._pending[sql].extend(rows)

    def flush_sync(self) -> int:
        with self._pending_lock:
            batch, self._pending = self._pending, defaultdict(list)
        if not batch:
            return 0

        def _flush() -> int:
            assert self._wconn is not None
            t0 = time.perf_counter()
            n = 0
            self._wconn.execute("BEGIN")
            try:
                for sql, rows in batch.items():
                    self._wconn.executemany(sql, rows)
                    n += len(rows)
                self._wconn.execute("COMMIT")
            except Exception:
                self._wconn.execute("ROLLBACK")
                raise
            self.stats["flushes"] += 1
            self.stats["rows"] += n
            self.stats["last_flush_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            return n

        return self._writer.submit(_flush).result()

    async def flush(self) -> int:
        return await asyncio.get_running_loop().run_in_executor(None, self.flush_sync)

    async def write(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        """Runs fn(conn) in the writer thread inside a transaction."""
        def _run() -> T:
            assert self._wconn is not None
            self._wconn.execute("BEGIN IMMEDIATE")
            try:
                res = fn(self._wconn)
                self._wconn.execute("COMMIT")
                return res
            except Exception:
                self._wconn.execute("ROLLBACK")
                raise
        return await asyncio.get_running_loop().run_in_executor(self._writer, _run)

    def write_sync(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        def _run() -> T:
            assert self._wconn is not None
            self._wconn.execute("BEGIN IMMEDIATE")
            try:
                res = fn(self._wconn)
                self._wconn.execute("COMMIT")
                return res
            except Exception:
                self._wconn.execute("ROLLBACK")
                raise
        return self._writer.submit(_run).result()

    # ---------------------------------------------------------------- reading
    def _rconn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            if self.path == ":memory:":
                # In-memory (tests): readers use the writer connection
                assert self._wconn is not None
                c = self._wconn
            else:
                c = _connect(self.path, readonly=False)
                c.execute("PRAGMA query_only = ON")
            self._local.conn = c
        return c

    async def read(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        if self.path == ":memory:":
            return await asyncio.get_running_loop().run_in_executor(self._writer, lambda: fn(self._wconn))
        return await asyncio.get_running_loop().run_in_executor(self._readers, lambda: fn(self._rconn()))

    def read_sync(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        if self.path == ":memory:":
            return self._writer.submit(lambda: fn(self._wconn)).result()
        return self._readers.submit(lambda: fn(self._rconn())).result()

    # ------------------------------------------------------------- maintenance
    def maintenance_sync(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        """Like write_sync, but WITHOUT a transaction - for VACUUM and checkpoints."""
        def _run() -> T:
            assert self._wconn is not None
            return fn(self._wconn)
        return self._writer.submit(_run).result()

    async def maintenance(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        return await asyncio.get_running_loop().run_in_executor(
            None, lambda: self.maintenance_sync(fn))


# ====================================================================== SQL
INSERT_PING = "INSERT INTO ping_samples(ts, target_id, rtt_ms, lost) VALUES (?,?,?,?)"

MEASUREMENT_COLS = (
    "rtt_avg", "rtt_min", "rtt_max", "gw_rtt", "jitter", "loss_pct", "probes", "lost",
    "down_bps", "up_bps", "traffic_src", "retrans", "tcp_segs", "retrans_down", "retrans_up",
    "dns_ms", "dns_fail", "game_rtt", "game_pps", "game_gap_ms",
)
INSERT_MEASUREMENT = (
    f"INSERT OR REPLACE INTO measurements(res, ts, {', '.join(MEASUREMENT_COLS)}) "
    f"VALUES (?, ?, {', '.join('?' * len(MEASUREMENT_COLS))})"
)
INSERT_TARGET_MEAS = (
    "INSERT OR REPLACE INTO target_measurements(res, ts, target_id, rtt_avg, rtt_max, probes, lost) "
    "VALUES (?,?,?,?,?,?,?)"
)
INSERT_DEVICE_TRAFFIC = (
    "INSERT OR REPLACE INTO device_traffic(res, ts, dev, rx_bytes, tx_bytes) VALUES (?,?,?,?,?)"
)

# ------------------------------------------------- units (see models.py)
CENTI = 100          # 1/100 ms or 1/100 %
CENTI_COLS = frozenset({"rtt_avg", "rtt_min", "rtt_max", "gw_rtt", "jitter", "loss_pct",
                        "dns_ms", "game_rtt", "game_pps", "game_gap_ms"})
ROUND_COLS = frozenset({"down_bps", "up_bps"})          # whole bit/s


def enc(value: float | None, col: str) -> int | None:
    """Measured value → stored integer."""
    if value is None:
        return None
    if col in CENTI_COLS:
        return int(round(value * CENTI))
    if col in ROUND_COLS:
        return int(round(value))
    return value if isinstance(value, (int, str)) else int(round(value))


def dec(value, col: str):
    """Stored integer → measured value."""
    if value is None:
        return None
    return value / CENTI if col in CENTI_COLS else value


def decode_row(row) -> dict:
    """sqlite3.Row of a measurement table → dict with milliseconds/percent."""
    return {k: dec(row[k], k) for k in row.keys()}
INSERT_FLOW = (
    "INSERT INTO network_flows(ts_start, ts_end, proto, mac, local_ip, local_port, remote_ip, "
    "remote_port, bytes_up, bytes_down, pkts_up, pkts_down, retrans, resets, max_gap_ms, dns_name) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
)


def measurement_params(res: int, row: dict) -> tuple:
    return (res, int(row["ts"]), *[enc(row.get(c), c) for c in MEASUREMENT_COLS])


def target_params(res: int, ts: int, target_id: int, v: dict) -> tuple:
    return (res, int(ts), target_id, enc(v.get("rtt"), "rtt_avg"), enc(v.get("max"), "rtt_max"),
            v.get("probes"), v.get("lost"))


# ------------------------------------------------- internet line (FRITZ!Box)
LINE_COLS = ("dsl_up", "down_kbit", "up_kbit", "down_max_kbit", "up_max_kbit", "down_snr", "up_snr",
             "down_atten", "up_atten", "crc", "fec", "errored_secs", "severe_secs", "retrains",
             "wan_connected", "wan_uptime")
_LINE_DB = {"down_snr_db": "down_snr", "up_snr_db": "up_snr", "down_atten_db": "down_atten", "up_atten_db": "up_atten"}
DECI = 10            # dB in 1/10 dB, as the FRITZ!Box reports it
INSERT_LINE = f"INSERT OR REPLACE INTO line_stats(ts, {', '.join(LINE_COLS)}) VALUES ({', '.join('?' * (len(LINE_COLS) + 1))})"
INSERT_FRITZ_EVENT = "INSERT OR IGNORE INTO fritz_events(ts, kind, grp, msg) VALUES (?,?,?,?)"


def line_params(ts: int, dsl: dict | None, wan: dict | None) -> tuple:
    """DSL values (dB, kbit/s, counters) and connection state → one line_stats row."""
    dsl, wan = dsl or {}, wan or {}
    v = {db: (None if dsl.get(k) is None else int(round(dsl[k] * DECI))) for k, db in _LINE_DB.items()}
    v.update({k: (None if dsl.get(k) is None else int(dsl[k]))
              for k in ("down_kbit", "up_kbit", "down_max_kbit", "up_max_kbit", "crc", "fec",
                        "errored_secs", "severe_secs", "retrains")})
    v["dsl_up"] = None if not dsl.get("status") else int(dsl["status"].lower() == "up")
    v["wan_connected"] = None if not wan.get("status") else int(wan["status"].lower() == "connected")
    v["wan_uptime"] = wan.get("uptime_s")
    return (int(ts), *[v.get(c) for c in LINE_COLS])


def decode_line(row) -> dict:
    d = dict(row)
    for k, db in _LINE_DB.items():
        d[k] = None if d.get(db) is None else d.pop(db) / DECI
        d.pop(db, None)
    return d


# ------------------------------------------------- the Pi itself
PI_COLS = ("boot_ts", "temp", "cpu_pct", "mem_avail_mb", "swap_used_mb", "disk_free_mb", "undervolt", "carrier",
           "speed_mbit", "carrier_changes", "rx_errors", "tx_errors", "sd_written_mb", "pihole_active")
INSERT_PI_HEALTH = f"INSERT OR REPLACE INTO pi_health(ts, {', '.join(PI_COLS)}) VALUES ({', '.join('?' * (len(PI_COLS) + 1))})"


def _opt(v, scale: float = 1):
    return None if v is None else int(round(v * scale))


def pi_health_params(h: dict) -> tuple:
    lk = h.get("link") or {}
    return (int(h["ts"]), _opt(h.get("boot_ts")), _opt(h.get("temp_c"), DECI), _opt(h.get("cpu_pct"), CENTI),
            h.get("mem_available_mb"), h.get("swap_used_mb"), h.get("disk_free_mb"), _opt(h.get("undervoltage")),
            lk.get("carrier"), lk.get("speed_mbit"), lk.get("carrier_changes"), lk.get("rx_errors"), lk.get("tx_errors"),
            None if h.get("sd_written_bytes") is None else h["sd_written_bytes"] // 1048576, _opt(h.get("pihole_active")))


def decode_pi_health(row) -> dict:
    d = dict(row)
    d["temp_c"] = None if d.get("temp") is None else d.pop("temp") / DECI
    d.pop("temp", None)
    d["cpu_pct"] = None if d.get("cpu_pct") is None else d["cpu_pct"] / CENTI
    return d


INSERT_BUFFERBLOAT = (
    "INSERT OR REPLACE INTO bufferbloat(ts, idle_ms, idle_secs, up_ms, up_worst_ms, up_secs, "
    "down_ms, down_worst_ms, down_secs) VALUES (?,?,?,?,?,?,?,?,?)"
)
_BLOAT_MS = ("idle_ms", "up_ms", "up_worst_ms", "down_ms", "down_worst_ms")


def bufferbloat_params(ts: int, m: dict) -> tuple | None:
    """Result of bufferbloat.measure() → row (times in 1/100 ms)."""
    if m["idle_ms"] is None or (m["up"] is None and m["down"] is None):
        return None
    up, down = m["up"], m["down"]
    c = lambda v: None if v is None else int(round(v * CENTI))   # noqa: E731
    return (int(ts), c(m["idle_ms"]), m["samples"]["idle"],
            c(up["loaded_ms"]) if up else None, c(up["worst_ms"]) if up else None, up["seconds"] if up else 0,
            c(down["loaded_ms"]) if down else None, c(down["worst_ms"]) if down else None,
            down["seconds"] if down else 0)


def read_bufferbloat(conn: sqlite3.Connection, start: int, end: int) -> list[dict]:
    out = []
    for r in conn.execute("SELECT * FROM bufferbloat WHERE ts BETWEEN ? AND ? ORDER BY ts", (start, end)):
        d = dict(r)
        for k in _BLOAT_MS:
            if d.get(k) is not None:
                d[k] = d[k] / CENTI
        out.append(d)
    return out


# ------------------------------------------------------------- settings
def get_setting(conn: sqlite3.Connection, key: str, default: Any = None) -> Any:
    r = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return json.loads(r["value"]) if r else default


def set_setting(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        "INSERT INTO settings(key, value, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, json.dumps(value), time.time()),
    )


def ensure_target(conn: sqlite3.Connection, address: str, name: str | None, kind: str) -> int:
    r = conn.execute("SELECT id, name, kind FROM targets WHERE address=?", (address,)).fetchone()
    if r:
        if r["name"] != name or r["kind"] != kind:
            conn.execute("UPDATE targets SET name=?, kind=? WHERE id=?", (name, kind, r["id"]))
        return int(r["id"])
    cur = conn.execute("INSERT INTO targets(address, name, kind) VALUES (?,?,?)", (address, name, kind))
    return int(cur.lastrowid)


# ------------------------------------------------------------- aggregation
# All values are integers; AVG() returns floats, so the value is rounded
# when written back. The unit stays the same as in the source.
_AVG = "CAST(ROUND(AVG({0})) AS INTEGER)"

AGG_MEASUREMENTS = f"""
INSERT OR REPLACE INTO measurements(res, ts, rtt_avg, rtt_min, rtt_max, gw_rtt, jitter, loss_pct,
    probes, lost, down_bps, up_bps, traffic_src, retrans, tcp_segs, retrans_down, retrans_up,
    dns_ms, dns_fail, game_rtt, game_pps, game_gap_ms)
SELECT :dst, (ts / :dst) * :dst,
    {_AVG.format('rtt_avg')}, MIN(rtt_min), MAX(rtt_max), {_AVG.format('gw_rtt')}, {_AVG.format('jitter')},
    CASE WHEN SUM(probes) > 0 THEN CAST(ROUND(10000.0 * SUM(lost) / SUM(probes)) AS INTEGER) END,
    SUM(probes), SUM(lost),
    {_AVG.format('down_bps')}, {_AVG.format('up_bps')}, MAX(traffic_src),
    SUM(retrans), SUM(tcp_segs), SUM(retrans_down), SUM(retrans_up),
    {_AVG.format('dns_ms')}, SUM(dns_fail), {_AVG.format('game_rtt')}, {_AVG.format('game_pps')},
    MAX(game_gap_ms)
FROM measurements
WHERE res = :src AND ts >= :t0 AND ts < :t1
GROUP BY ts / :dst
"""
# Note: AVG(down_bps) is correct over the bucket because every 1 s value is a rate.
# MAX in the 60 s bucket is additionally kept via rtt_max.

AGG_TARGETS = f"""
INSERT OR REPLACE INTO target_measurements(res, ts, target_id, rtt_avg, rtt_max, probes, lost)
SELECT :dst, (ts / :dst) * :dst, target_id, {_AVG.format('rtt_avg')}, MAX(rtt_max),
    SUM(probes), SUM(lost)
FROM target_measurements
WHERE res = :src AND ts >= :t0 AND ts < :t1
GROUP BY target_id, ts / :dst
"""

AGG_DEVICE = """
INSERT OR REPLACE INTO device_traffic(res, ts, dev, rx_bytes, tx_bytes)
SELECT :dst, (ts / :dst) * :dst, dev, SUM(rx_bytes), SUM(tx_bytes)
FROM device_traffic
WHERE res = :src AND ts >= :t0 AND ts < :t1
GROUP BY dev, ts / :dst
"""


def aggregate(conn: sqlite3.Connection, src: int, dst: int, t0: int, t1: int) -> None:
    """Condenses [t0, t1) from resolution src to dst. t0/t1 must be aligned to dst."""
    p = {"src": src, "dst": dst, "t0": t0, "t1": t1}
    conn.execute(AGG_MEASUREMENTS, p)
    conn.execute(AGG_TARGETS, p)
    conn.execute(AGG_DEVICE, p)


def apply_retention(conn: sqlite3.Connection, now: float, ret: Any) -> dict[str, int]:
    day = 86400
    out = {}
    cut_raw = now - ret.raw_days * day
    cut_det = now - ret.detailed_days * day
    cut_agg = now - ret.aggregate_days * day
    stmts = [
        ("ping_samples", "DELETE FROM ping_samples WHERE ts < ?", cut_raw),
        ("meas_1", "DELETE FROM measurements WHERE res=1 AND ts < ?", cut_raw),
        ("meas_10", "DELETE FROM measurements WHERE res=10 AND ts < ?", cut_det),
        ("meas_60", "DELETE FROM measurements WHERE res=60 AND ts < ?", cut_agg),
        ("tm_1", "DELETE FROM target_measurements WHERE res=1 AND ts < ?", cut_raw),
        ("tm_10", "DELETE FROM target_measurements WHERE res=10 AND ts < ?", cut_det),
        ("tm_60", "DELETE FROM target_measurements WHERE res=60 AND ts < ?", cut_agg),
        ("dt_1", "DELETE FROM device_traffic WHERE res=1 AND ts < ?", cut_raw),
        ("dt_10", "DELETE FROM device_traffic WHERE res=10 AND ts < ?", cut_det),
        ("dt_60", "DELETE FROM device_traffic WHERE res=60 AND ts < ?", cut_agg),
        ("flows", "DELETE FROM network_flows WHERE ts_end < ?", now - ret.flow_days * day),
        # Bufferbloat windows are tiny (9 numbers per 10 min) and are meant to show the long-term
        # history → they are kept as long as events, not as long as the 1 s raw values.
        ("bufferbloat", "DELETE FROM bufferbloat WHERE ts < ?", now - ret.event_days * day),
        ("dns", "DELETE FROM dns_queries WHERE ts < ?", cut_det),
        ("dns_hourly", "DELETE FROM dns_client_hourly WHERE ts < ?", now - ret.dns_hourly_days * day),
        ("dns_domains", "DELETE FROM dns_domain_daily WHERE day < ?", now - ret.dns_domain_days * day),
        ("dns_domains_hourly", "DELETE FROM dns_domain_hourly WHERE ts < ?", now - ret.dns_domain_hourly_hours * 3600),
        ("dns_minutes", "DELETE FROM dns_service_minutes WHERE ts < ?", now - ret.dns_minute_days * day),
        ("dns_ip_history", "DELETE FROM dns_ip_history WHERE last_seen < ?", now - ret.dns_hourly_days * day),
        ("events", "DELETE FROM events WHERE ts_start < ?", now - ret.event_days * day),
        ("line_stats", "DELETE FROM line_stats WHERE ts < ?", now - ret.line_days * day),
        ("pi_health", "DELETE FROM pi_health WHERE ts < ?", now - ret.aggregate_days * day),
        ("device_presence", "DELETE FROM device_presence WHERE ts_end < ?", now - ret.event_days * day),
        ("fritz_events", "DELETE FROM fritz_events WHERE ts < ?", now - ret.line_days * day),
        ("incidents", "DELETE FROM incidents WHERE ts_start < ?", now - ret.event_days * day),
    ]
    for name, sql, cut in stmts:
        out[name] = conn.execute(sql, (cut,)).rowcount
    return out


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict]:
    return [dict(r) for r in rows]


# ------------------------------------------------------------- space & cleanup
# Which table hangs on which time column? Basis for deleting by date
# and for the size report. daily_stats is deliberately missing: the daily summary
# is tiny and is meant to survive for long-term comparison.
TIME_TABLES: dict[str, tuple[str, str]] = {
    "measurements": ("ts", "Measurements per second/minute"),
    "target_measurements": ("ts", "Measurements per target"),
    "device_traffic": ("ts", "Traffic per device"),
    "ping_samples": ("ts", "Individual pings (raw data)"),
    "network_flows": ("ts_end", "Connections (metadata only)"),
    "dns_queries": ("ts", "DNS activity per client"),
    "dns_client_hourly": ("ts", "DNS queries per device and hour"),
    "dns_domain_daily": ("day", "DNS domains per device and day"),
    "dns_domain_hourly": ("ts", "DNS domains per device and hour (short term)"),
    "dns_service_minutes": ("ts", "Activity minutes per device and service"),
    "dns_ip_history": ("last_seen", "Which device held which IP"),
    "events": ("ts_start", "Detected events"),
    "line_stats": ("ts", "Internet line values (FRITZ!Box)"),
    "pi_health": ("ts", "Raspberry Pi health"),
    "device_presence": ("ts_end", "When devices were in the network"),
    "fritz_events": ("ts", "FRITZ!Box event log"),
    "incidents": ("ts_start", "Incidents incl. analysis"),
    "bufferbloat": ("ts", "Latency under load (10-minute windows)"),
    "gaming_sessions": ("ts_start", "Gaming Sessions"),
}
PROTECTED_TABLES = ("daily_stats", "devices", "targets", "settings", "meta", "auth_sessions")


def table_sizes(conn: sqlite3.Connection) -> list[dict]:
    """Space used per table. Falls back to row counts if dbstat is missing."""
    sizes: dict[str, int] = {}
    try:
        for r in conn.execute("SELECT name, SUM(pgsize) AS b FROM dbstat GROUP BY name"):
            sizes[r["name"]] = sizes.get(r["name"], 0) + (r["b"] or 0)
    except sqlite3.Error:
        sizes = {}
    out = []
    for table, (_tcol, label) in TIME_TABLES.items():
        try:
            n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.Error:
            continue
        out.append({"table": table, "label": label, "rows": n,
                    "bytes": sizes.get(table), "exact": bool(sizes)})
    out.sort(key=lambda x: -(x["bytes"] if x["bytes"] is not None else x["rows"]))
    return out


def oldest_data(conn: sqlite3.Connection) -> float | None:
    """Oldest timestamp across all time tables - for the date picker."""
    best = None
    for table, (col, _l) in TIME_TABLES.items():
        try:
            v = conn.execute(f"SELECT MIN({col}) FROM {table}").fetchone()[0]
        except sqlite3.Error:
            continue
        if v is not None and (best is None or v < best):
            best = v
    return best


def count_range(conn: sqlite3.Connection, start: float | None, end: float,
                tables: Iterable[str] | None = None) -> dict[str, int]:
    """How many rows would `delete_range` hit? For the preview before deleting."""
    out: dict[str, int] = {}
    for table in (tables or TIME_TABLES):
        if table not in TIME_TABLES:
            raise ValueError(f"Unknown table: {table}")
        col = TIME_TABLES[table][0]
        if start is None:
            q, p = f"SELECT COUNT(*) FROM {table} WHERE {col} < ?", (end,)
        else:
            q, p = f"SELECT COUNT(*) FROM {table} WHERE {col} >= ? AND {col} < ?", (start, end)
        try:
            out[table] = conn.execute(q, p).fetchone()[0]
        except sqlite3.Error:                       # pragma: no cover
            out[table] = 0
    return out


def delete_range(conn: sqlite3.Connection, start: float | None, end: float,
                 tables: Iterable[str] | None = None) -> dict[str, int]:
    """Deletes measurements in [start, end). start=None means "everything before".

    Devices, targets, settings and the daily summary are kept -
    otherwise all device names would be gone after the cleanup.
    """
    names = list(tables) if tables else list(TIME_TABLES)
    out: dict[str, int] = {}
    for table in names:
        if table not in TIME_TABLES:
            raise ValueError(f"Unknown table: {table}")
        col = TIME_TABLES[table][0]
        if start is None:
            cur = conn.execute(f"DELETE FROM {table} WHERE {col} < ?", (end,))
        else:
            cur = conn.execute(f"DELETE FROM {table} WHERE {col} >= ? AND {col} < ?", (start, end))
        out[table] = cur.rowcount
    return out


def db_size(conn: sqlite3.Connection) -> dict:
    """Space used. `used` does not count free pages.

    That is the crucial difference for the size limit: after a DELETE the
    file stays the same size, the pages are only marked as free. Without
    this distinction the emergency brake would keep deleting forever.
    """
    page = conn.execute("PRAGMA page_size").fetchone()[0]
    total = conn.execute("PRAGMA page_count").fetchone()[0]
    free = conn.execute("PRAGMA freelist_count").fetchone()[0]
    return {"file": page * total, "used": page * (total - free), "free": page * free}


# Order in which data is sacrificed when space runs out - from "nobody misses it" down.
SIZE_GUARD_STEPS: list[tuple[str, str]] = [
    ("ping_samples", "DELETE FROM ping_samples"),
    ("meas_1", "DELETE FROM measurements WHERE res=1 AND ts < ?"),
    ("tm_1", "DELETE FROM target_measurements WHERE res=1 AND ts < ?"),
    ("dt_1", "DELETE FROM device_traffic WHERE res=1 AND ts < ?"),
    ("flows", "DELETE FROM network_flows WHERE ts_end < ?"),
    ("meas_10", "DELETE FROM measurements WHERE res=10 AND ts < ?"),
    ("tm_10", "DELETE FROM target_measurements WHERE res=10 AND ts < ?"),
    ("dt_10", "DELETE FROM device_traffic WHERE res=10 AND ts < ?"),
]
SIZE_GUARD_AGES = (12, 6, 1)      # hours: sacrifice old data first, then ever younger


def vacuum(conn: sqlite3.Connection) -> dict:
    """Actually shrink the file. Must run outside a transaction."""
    before = db_size(conn)["file"]
    conn.execute("VACUUM")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    after = db_size(conn)["file"]
    return {"before": before, "after": after, "freed": before - after}
