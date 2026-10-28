"""Schema migrations.

Up to version 2 the schema was only created with `CREATE TABLE IF NOT EXISTS`.
That is enough for new tables, but not for changed columns: an existing
installation would silently not have received the change and the code
would have tripped over it. That is why there are real, numbered steps
from version 3 on.

Sequence on start:

1. Read `schema_version` from `meta` (if missing, it is a new database).
2. Apply all steps with a higher number in order, each in its
   own transaction.
3. Then create the current schema (new tables) and write the version.

Before the first step a backup copy is made - but only if there is
enough free space for it. If there is not, this is logged and the
migration continues, instead of keeping the service from starting.
"""
from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import time
from pathlib import Path

log = logging.getLogger(__name__)

BACKUP_SUFFIX = ".pre-migration.bak"


def current_version(conn: sqlite3.Connection) -> int:
    """0 = empty database, otherwise the stored version."""
    try:
        r = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    except sqlite3.OperationalError:
        return 0                      # table meta does not exist yet
    if r is None:
        # meta exists, but without an entry: either really empty or a very old DB
        n = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        return 0 if n <= 1 else 1
    try:
        return int(r[0])
    except (TypeError, ValueError):
        return 1


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


# ===================================================================== steps
def _v3_compact_storage(conn: sqlite3.Connection) -> None:
    """Version 3: more compact storage.

    * `measurements` / `target_measurements`: REAL → INTEGER in fixed units
      (1/100 ms or 1/100 %). SQLite cannot change the column type, so the
      table is rebuilt and converted along the way.
    * `devices` gets a numeric `id`.
    * `device_traffic` is reduced to (res, ts, dev, rx_bytes, tx_bytes);
      the never-read packet/UDP/LAN columns are dropped.
    """
    # ---- devices: add id --------------------------------------------------------
    if _table_exists(conn, "devices") and "id" not in _columns(conn, "devices"):
        conn.execute("ALTER TABLE devices RENAME TO devices_old")
        conn.execute("""
            CREATE TABLE devices (
                id INTEGER PRIMARY KEY, mac TEXT NOT NULL UNIQUE, ip TEXT, hostname TEXT,
                custom_name TEXT, vendor TEXT, sources TEXT, interface TEXT,
                first_seen REAL NOT NULL, last_seen REAL NOT NULL, active INTEGER NOT NULL DEFAULT 0)""")
        conn.execute("""
            INSERT INTO devices(id, mac, ip, hostname, custom_name, vendor, sources, interface,
                                first_seen, last_seen, active)
            SELECT NULL, mac, ip, hostname, custom_name, vendor, sources, interface,
                   first_seen, last_seen, active FROM devices_old ORDER BY first_seen""")
        conn.execute("DROP TABLE devices_old")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_devices_ip ON devices(ip)")

    # ---- device_traffic: MAC → id, drop unneeded columns ----------------------
    if _table_exists(conn, "device_traffic") and "mac" in _columns(conn, "device_traffic"):
        conn.execute("ALTER TABLE device_traffic RENAME TO device_traffic_old")
        conn.execute("""
            CREATE TABLE device_traffic (
                res INTEGER NOT NULL, ts INTEGER NOT NULL, dev INTEGER NOT NULL,
                rx_bytes INTEGER NOT NULL, tx_bytes INTEGER NOT NULL,
                PRIMARY KEY (res, ts, dev)) WITHOUT ROWID""")
        # Create devices that only occur in the traffic (e.g. deleted since) first,
        # so that no measurements are lost.
        conn.execute("""
            INSERT OR IGNORE INTO devices(mac, first_seen, last_seen, sources, active)
            SELECT DISTINCT o.mac, 0, 0, '["capture"]', 0 FROM device_traffic_old o
            WHERE o.mac NOT IN (SELECT mac FROM devices)""")
        conn.execute("""
            INSERT OR REPLACE INTO device_traffic(res, ts, dev, rx_bytes, tx_bytes)
            SELECT o.res, o.ts, d.id, o.rx_bytes, o.tx_bytes
            FROM device_traffic_old o JOIN devices d ON d.mac = o.mac""")
        conn.execute("DROP TABLE device_traffic_old")

    # ---- measurements: REAL → INTEGER ----------------------------------------
    if _table_exists(conn, "measurements") and _is_real(conn, "measurements", "rtt_avg"):
        conn.execute("ALTER TABLE measurements RENAME TO measurements_old")
        conn.execute("""
            CREATE TABLE measurements (
                res INTEGER NOT NULL, ts INTEGER NOT NULL,
                rtt_avg INTEGER, rtt_min INTEGER, rtt_max INTEGER, gw_rtt INTEGER, jitter INTEGER,
                loss_pct INTEGER, probes INTEGER, lost INTEGER, down_bps INTEGER, up_bps INTEGER,
                traffic_src TEXT, retrans INTEGER, tcp_segs INTEGER, retrans_down INTEGER,
                retrans_up INTEGER, dns_ms INTEGER, dns_fail INTEGER, game_rtt INTEGER,
                game_pps INTEGER, game_gap_ms INTEGER,
                PRIMARY KEY (res, ts)) WITHOUT ROWID""")
        c100 = lambda col: f"CAST(ROUND({col} * 100) AS INTEGER)"   # noqa: E731
        conn.execute(f"""
            INSERT INTO measurements SELECT res, ts,
                {c100('rtt_avg')}, {c100('rtt_min')}, {c100('rtt_max')}, {c100('gw_rtt')},
                {c100('jitter')}, {c100('loss_pct')}, probes, lost,
                CAST(ROUND(down_bps) AS INTEGER), CAST(ROUND(up_bps) AS INTEGER), traffic_src,
                retrans, tcp_segs, retrans_down, retrans_up, {c100('dns_ms')}, dns_fail,
                {c100('game_rtt')}, {c100('game_pps')}, {c100('game_gap_ms')}
            FROM measurements_old""")
        conn.execute("DROP TABLE measurements_old")

    if _table_exists(conn, "target_measurements") and _is_real(conn, "target_measurements", "rtt_avg"):
        conn.execute("ALTER TABLE target_measurements RENAME TO tm_old")
        conn.execute("""
            CREATE TABLE target_measurements (
                res INTEGER NOT NULL, ts INTEGER NOT NULL, target_id INTEGER NOT NULL,
                rtt_avg INTEGER, rtt_max INTEGER, probes INTEGER, lost INTEGER,
                PRIMARY KEY (res, target_id, ts)) WITHOUT ROWID""")
        conn.execute("""
            INSERT INTO target_measurements SELECT res, ts, target_id,
                CAST(ROUND(rtt_avg * 100) AS INTEGER), CAST(ROUND(rtt_max * 100) AS INTEGER),
                probes, lost FROM tm_old""")
        conn.execute("DROP TABLE tm_old")

    # ---- bufferbloat: also in 1/100 ms -----------------------------------------
    if _table_exists(conn, "bufferbloat") and _is_real(conn, "bufferbloat", "idle_ms"):
        conn.execute("ALTER TABLE bufferbloat RENAME TO bb_old")
        conn.execute("""
            CREATE TABLE bufferbloat (
                ts INTEGER PRIMARY KEY, idle_ms INTEGER NOT NULL, idle_secs INTEGER NOT NULL,
                up_ms INTEGER, up_worst_ms INTEGER, up_secs INTEGER NOT NULL DEFAULT 0,
                down_ms INTEGER, down_worst_ms INTEGER, down_secs INTEGER NOT NULL DEFAULT 0
            ) WITHOUT ROWID""")
        conn.execute("""
            INSERT INTO bufferbloat SELECT ts, CAST(ROUND(idle_ms*100) AS INTEGER), idle_secs,
                CAST(ROUND(up_ms*100) AS INTEGER), CAST(ROUND(up_worst_ms*100) AS INTEGER), up_secs,
                CAST(ROUND(down_ms*100) AS INTEGER), CAST(ROUND(down_worst_ms*100) AS INTEGER), down_secs
            FROM bb_old""")
        conn.execute("DROP TABLE bb_old")


def _v10_presence_source(conn: sqlite3.Connection) -> None:
    """Version 10: presence periods know their source (registry or DNS lookups)."""
    if _table_exists(conn, "device_presence") and "source" not in _columns(conn, "device_presence"):
        conn.execute("ALTER TABLE device_presence ADD COLUMN source TEXT")


def _v11_fritz_events_order(conn: sqlite3.Connection) -> None:
    """Version 11: key columns of fritz_events first (false integrity_check errors in SQLite 3.40)."""
    if not _table_exists(conn, "fritz_events") or _columns(conn, "fritz_events")[:2] == ["ts", "msg"]:
        return
    conn.execute("ALTER TABLE fritz_events RENAME TO fritz_events_old")
    conn.execute("""CREATE TABLE fritz_events (ts INTEGER NOT NULL, msg TEXT NOT NULL, kind TEXT NOT NULL,
                    grp TEXT, PRIMARY KEY (ts, msg)) WITHOUT ROWID""")
    conn.execute("INSERT INTO fritz_events (ts, msg, kind, grp) SELECT ts, msg, kind, grp FROM fritz_events_old")
    conn.execute("DROP TABLE fritz_events_old")


def _v12_compress_incidents(conn: sqlite3.Connection) -> None:
    """Version 12: incident analyses compressed, without the copy of the events (they are in
    the events table with their incident_id). Half the database on the Pi was these JSONs."""
    from .repository import ANALYSIS_MAGIC, dec_analysis, enc_analysis
    if not _table_exists(conn, "incidents"):
        return
    rows = conn.execute("SELECT id, source, analysis FROM incidents").fetchall()
    for iid, source, analysis in rows:
        if analysis is None or (isinstance(analysis, bytes) and analysis.startswith(ANALYSIS_MAGIC)):
            continue
        try:
            a = dec_analysis(analysis)
        except ValueError:
            continue                    # unreadable stays as it was
        if source == "auto":
            a.pop("events", None)       # a lag report keeps its list: those events belong to other incidents
        conn.execute("UPDATE incidents SET analysis=? WHERE id=?", (enc_analysis(a), iid))


def _v13_flow_sni(conn: sqlite3.Connection) -> None:
    """Version 13: the TLS server name of a connection, next to the DNS guess."""
    if _table_exists(conn, "network_flows") and "sni" not in _columns(conn, "network_flows"):
        conn.execute("ALTER TABLE network_flows ADD COLUMN sni TEXT")


def _is_real(conn: sqlite3.Connection, table: str, column: str) -> bool:
    for r in conn.execute(f"PRAGMA table_info({table})"):
        if r[1] == column:
            return str(r[2]).upper().startswith("REAL")
    return False


# (version, description, function) - sorted ascending.
# Versions 4 (DNS usage tables), 5 (activity minutes), 6 (login sessions), 7 (internet line),
# 8 (Pi health), 9 (presence) and 14 (path measurements) only add new tables, which SCHEMA
# creates after the steps.
STEPS: list[tuple[int, str, object]] = [
    (3, "More compact storage (INTEGER units, device_id, slim device_traffic)",
     _v3_compact_storage),
    (10, "Source column for presence periods", _v10_presence_source),
    (11, "Key columns of fritz_events first", _v11_fritz_events_order),
    (12, "Incident analyses compressed, events by reference", _v12_compress_incidents),
    (13, "TLS server name of connections", _v13_flow_sni),
]


# ===================================================================== flow
def backup(path: str) -> str | None:
    """Backup copy next to the database. None if there is too little free space."""
    if path == ":memory:" or not os.path.exists(path):
        return None
    size = os.path.getsize(path)
    free = shutil.disk_usage(Path(path).parent).free
    if free < size * 3:
        log.warning("No backup copy before the migration: only %.0f MB free, %.0f MB needed",
                    free / 1e6, size * 3 / 1e6)
        return None
    dst = path + BACKUP_SUFFIX
    src = sqlite3.connect(path)
    try:
        with sqlite3.connect(dst) as out:
            src.backup(out)
    finally:
        src.close()
    log.info("Backup copy before the migration: %s (%.0f MB)", dst, size / 1e6)
    return dst


def migrate(conn: sqlite3.Connection, path: str, target: int) -> dict:
    """Applies all due steps. Returns a report for the log."""
    have = current_version(conn)
    todo = [s for s in STEPS if have < s[0] <= target]
    report = {"from": have, "to": target, "steps": [], "backup": None, "seconds": 0.0}
    if have == 0 or not todo:
        return report                      # new database or nothing to do
    report["backup"] = backup(path)
    t0 = time.perf_counter()
    for version, desc, fn in todo:
        log.info("Migrating to version %s: %s", version, desc)
        conn.execute("BEGIN IMMEDIATE")
        try:
            fn(conn)
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)", (str(version),))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            log.exception("Migration to version %s failed", version)
            raise
        report["steps"].append({"version": version, "description": desc})
    report["seconds"] = round(time.perf_counter() - t0, 2)
    # After a table rebuild many pages are free - the file may shrink.
    # The checkpoint afterwards is needed because in WAL mode otherwise only the
    # write-ahead log shrinks and the actual file keeps its old size.
    try:
        conn.execute("VACUUM")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.OperationalError:       # pragma: no cover - e.g. not enough space
        log.warning("VACUUM after the migration not possible")
    log.info("Migration finished: %s → %s in %.1f s", have, target, report["seconds"])
    return report
