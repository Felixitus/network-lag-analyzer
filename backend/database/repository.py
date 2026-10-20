"""Datenbankzugriff: ein Writer-Thread mit Batch-Inserts, Leser über eigene Verbindungen.

* WAL-Modus erlaubt parallele Leser während geschrieben wird.
* Alle Schreibzugriffe laufen über genau einen Thread (keine Lock-Konflikte).
* Hochfrequente Inserts werden gesammelt und einmal pro Sekunde in einer
  Transaktion geschrieben (`enqueue` + `flush`).
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
        conn.execute("PRAGMA synchronous = NORMAL")   # WAL + NORMAL: sicher genug, wenig fsync
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
        self.migration: dict | None = None      # Bericht des letzten Starts, für /api/status

    # ------------------------------------------------------------------ setup
    def init_sync(self) -> None:
        """Fällige Migrationen anwenden, dann das Schema anlegen. Läuft im Writer-Thread."""
        def _init() -> None:
            self._wconn = _connect(self.path)
            # Reihenfolge: erst umbauen, was es schon gibt, dann neue Tabellen anlegen.
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
            log.exception("Flush beim Beenden fehlgeschlagen")
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
        """Führt fn(conn) im Writer-Thread in einer Transaktion aus."""
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
                # In-Memory (Tests): Leser nutzen die Writer-Verbindung
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

    # ------------------------------------------------------------- Wartung
    def maintenance_sync(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        """Wie write_sync, aber OHNE Transaktion – für VACUUM und Checkpoints."""
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

# ------------------------------------------------- Einheiten (siehe models.py)
CENTI = 100          # 1/100 ms bzw. 1/100 %
CENTI_COLS = frozenset({"rtt_avg", "rtt_min", "rtt_max", "gw_rtt", "jitter", "loss_pct",
                        "dns_ms", "game_rtt", "game_pps", "game_gap_ms"})
ROUND_COLS = frozenset({"down_bps", "up_bps"})          # ganze bit/s


def enc(value: float | None, col: str) -> int | None:
    """Messwert → gespeicherte Ganzzahl."""
    if value is None:
        return None
    if col in CENTI_COLS:
        return int(round(value * CENTI))
    if col in ROUND_COLS:
        return int(round(value))
    return value if isinstance(value, (int, str)) else int(round(value))


def dec(value, col: str):
    """Gespeicherte Ganzzahl → Messwert."""
    if value is None:
        return None
    return value / CENTI if col in CENTI_COLS else value


def decode_row(row) -> dict:
    """sqlite3.Row einer Messtabelle → Dict mit Millisekunden/Prozent."""
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


INSERT_BUFFERBLOAT = (
    "INSERT OR REPLACE INTO bufferbloat(ts, idle_ms, idle_secs, up_ms, up_worst_ms, up_secs, "
    "down_ms, down_worst_ms, down_secs) VALUES (?,?,?,?,?,?,?,?,?)"
)
_BLOAT_MS = ("idle_ms", "up_ms", "up_worst_ms", "down_ms", "down_worst_ms")


def bufferbloat_params(ts: int, m: dict) -> tuple | None:
    """Ergebnis von bufferbloat.measure() → Zeile (Zeiten in 1/100 ms)."""
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
# Alle Werte liegen als Ganzzahlen vor; AVG() liefert Fließkomma, deshalb wird
# beim Zurückschreiben gerundet. Die Einheit bleibt dieselbe wie in der Quelle.
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
# Hinweis: AVG(down_bps) ist über den Bucket korrekt, weil jeder 1-s-Wert eine Rate ist.
# MAX im 60-s-Bucket wird zusätzlich über rtt_max erhalten.

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
    """Verdichtet [t0, t1) von Auflösung src auf dst. t0/t1 müssen auf dst ausgerichtet sein."""
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
        # Bufferbloat-Fenster sind winzig (9 Zahlen je 10 min) und sollen den Langzeitverlauf zeigen
        # → sie bleiben so lange wie Events, nicht so lange wie die 1-s-Rohwerte.
        ("bufferbloat", "DELETE FROM bufferbloat WHERE ts < ?", now - ret.event_days * day),
        ("dns", "DELETE FROM dns_queries WHERE ts < ?", cut_det),
        ("events", "DELETE FROM events WHERE ts_start < ?", now - ret.event_days * day),
        ("incidents", "DELETE FROM incidents WHERE ts_start < ?", now - ret.event_days * day),
    ]
    for name, sql, cut in stmts:
        out[name] = conn.execute(sql, (cut,)).rowcount
    return out


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict]:
    return [dict(r) for r in rows]


# ------------------------------------------------------------- Platz & Aufräumen
# Welche Tabelle hängt an welcher Zeitspalte? Grundlage für das Löschen nach Datum
# und für den Größenbericht. daily_stats fehlt hier bewusst: Die Tages-Zusammenfassung
# ist winzig und soll den Langzeitvergleich überleben.
TIME_TABLES: dict[str, tuple[str, str]] = {
    "measurements": ("ts", "Messwerte je Sekunde/Minute"),
    "target_measurements": ("ts", "Messwerte je Ziel"),
    "device_traffic": ("ts", "Traffic je Gerät"),
    "ping_samples": ("ts", "einzelne Pings (Rohdaten)"),
    "network_flows": ("ts_end", "Verbindungen (nur Metadaten)"),
    "dns_queries": ("ts", "DNS-Aktivität je Client"),
    "events": ("ts_start", "erkannte Events"),
    "incidents": ("ts_start", "Incidents inkl. Analyse"),
    "bufferbloat": ("ts", "Latenz unter Last (10-Minuten-Fenster)"),
    "gaming_sessions": ("ts_start", "Gaming Sessions"),
}
PROTECTED_TABLES = ("daily_stats", "devices", "targets", "settings", "meta")


def table_sizes(conn: sqlite3.Connection) -> list[dict]:
    """Belegter Platz je Tabelle. Fällt auf Zeilenzahlen zurück, wenn dbstat fehlt."""
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
    """Ältester Zeitstempel über alle Zeittabellen – für die Datumsauswahl."""
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
    """Wie viele Zeilen würde `delete_range` treffen? Für die Vorschau vor dem Löschen."""
    out: dict[str, int] = {}
    for table in (tables or TIME_TABLES):
        if table not in TIME_TABLES:
            raise ValueError(f"Unbekannte Tabelle: {table}")
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
    """Löscht Messdaten in [start, end). start=None bedeutet "alles davor".

    Geräte, Ziele, Einstellungen und die Tages-Zusammenfassung bleiben erhalten –
    sonst wären nach dem Aufräumen die Namen aller Geräte weg.
    """
    names = list(tables) if tables else list(TIME_TABLES)
    out: dict[str, int] = {}
    for table in names:
        if table not in TIME_TABLES:
            raise ValueError(f"Unbekannte Tabelle: {table}")
        col = TIME_TABLES[table][0]
        if start is None:
            cur = conn.execute(f"DELETE FROM {table} WHERE {col} < ?", (end,))
        else:
            cur = conn.execute(f"DELETE FROM {table} WHERE {col} >= ? AND {col} < ?", (start, end))
        out[table] = cur.rowcount
    return out


def db_size(conn: sqlite3.Connection) -> dict:
    """Belegter Platz. `used` zählt freie Seiten nicht mit.

    Das ist der entscheidende Unterschied für die Größengrenze: Nach einem DELETE
    bleibt die Datei gleich groß, die Seiten sind nur als frei markiert. Ohne
    diese Unterscheidung würde die Notbremse endlos weiterlöschen.
    """
    page = conn.execute("PRAGMA page_size").fetchone()[0]
    total = conn.execute("PRAGMA page_count").fetchone()[0]
    free = conn.execute("PRAGMA freelist_count").fetchone()[0]
    return {"file": page * total, "used": page * (total - free), "free": page * free}


# Reihenfolge, in der bei Platznot geopfert wird – von "vermisst niemand" abwärts.
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
SIZE_GUARD_AGES = (12, 6, 1)      # Stunden: erst Altes opfern, dann immer Jüngeres


def vacuum(conn: sqlite3.Connection) -> dict:
    """Datei tatsächlich verkleinern. Muss außerhalb einer Transaktion laufen."""
    before = db_size(conn)["file"]
    conn.execute("VACUUM")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    after = db_size(conn)["file"]
    return {"before": before, "after": after, "freed": before - after}
