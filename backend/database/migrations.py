"""Schema-Migrationen.

Bis Version 2 wurde das Schema nur mit `CREATE TABLE IF NOT EXISTS` angelegt.
Das reicht für neue Tabellen, aber nicht für geänderte Spalten: Eine bestehende
Installation hätte die Änderung stillschweigend nicht bekommen und der Code
wäre darüber gestolpert. Deshalb gibt es ab Version 3 echte, nummerierte
Schritte.

Ablauf beim Start:

1. `schema_version` aus `meta` lesen (fehlt sie, ist es eine neue Datenbank).
2. Alle Schritte mit höherer Nummer der Reihe nach anwenden, jeder in einer
   eigenen Transaktion.
3. Danach das aktuelle Schema anlegen (neue Tabellen) und die Version schreiben.

Vor dem ersten Schritt wird eine Sicherungskopie angelegt – aber nur, wenn
dafür genug Platz frei ist. Ist er es nicht, wird das protokolliert und
weitergemacht, statt den Dienst nicht starten zu lassen.
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
    """0 = leere Datenbank, sonst die gespeicherte Version."""
    try:
        r = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    except sqlite3.OperationalError:
        return 0                      # Tabelle meta gibt es noch nicht
    if r is None:
        # meta existiert, aber ohne Eintrag: entweder wirklich leer oder eine sehr alte DB
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


# ===================================================================== Schritte
def _v3_compact_storage(conn: sqlite3.Connection) -> None:
    """Version 3: kompaktere Speicherung.

    * `measurements` / `target_measurements`: REAL → INTEGER in festen Einheiten
      (1/100 ms bzw. 1/100 %). SQLite kann den Spaltentyp nicht ändern, deshalb
      wird die Tabelle neu aufgebaut und dabei umgerechnet.
    * `devices` bekommt eine numerische `id`.
    * `device_traffic` wird auf (res, ts, dev, rx_bytes, tx_bytes) verkleinert;
      die nie gelesenen Paket-/UDP-/LAN-Spalten entfallen.
    """
    # ---- devices: id ergänzen -------------------------------------------------
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

    # ---- device_traffic: MAC → id, überflüssige Spalten weg -------------------
    if _table_exists(conn, "device_traffic") and "mac" in _columns(conn, "device_traffic"):
        conn.execute("ALTER TABLE device_traffic RENAME TO device_traffic_old")
        conn.execute("""
            CREATE TABLE device_traffic (
                res INTEGER NOT NULL, ts INTEGER NOT NULL, dev INTEGER NOT NULL,
                rx_bytes INTEGER NOT NULL, tx_bytes INTEGER NOT NULL,
                PRIMARY KEY (res, ts, dev)) WITHOUT ROWID""")
        # Geräte, die nur im Traffic vorkommen (z. B. inzwischen gelöschte), zuerst anlegen,
        # damit keine Messwerte verloren gehen.
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

    # ---- bufferbloat: ebenfalls in 1/100 ms ----------------------------------
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


def _is_real(conn: sqlite3.Connection, table: str, column: str) -> bool:
    for r in conn.execute(f"PRAGMA table_info({table})"):
        if r[1] == column:
            return str(r[2]).upper().startswith("REAL")
    return False


# (Version, Beschreibung, Funktion) – aufsteigend sortiert.
STEPS: list[tuple[int, str, object]] = [
    (3, "Kompaktere Speicherung (INTEGER-Einheiten, device_id, schlankes device_traffic)",
     _v3_compact_storage),
]


# ===================================================================== Ablauf
def backup(path: str) -> str | None:
    """Sicherungskopie neben der Datenbank. None, wenn zu wenig Platz frei ist."""
    if path == ":memory:" or not os.path.exists(path):
        return None
    size = os.path.getsize(path)
    free = shutil.disk_usage(Path(path).parent).free
    if free < size * 3:
        log.warning("Keine Sicherungskopie vor der Migration: nur %.0f MB frei, %.0f MB nötig",
                    free / 1e6, size * 3 / 1e6)
        return None
    dst = path + BACKUP_SUFFIX
    src = sqlite3.connect(path)
    try:
        with sqlite3.connect(dst) as out:
            src.backup(out)
    finally:
        src.close()
    log.info("Sicherungskopie vor der Migration: %s (%.0f MB)", dst, size / 1e6)
    return dst


def migrate(conn: sqlite3.Connection, path: str, target: int) -> dict:
    """Wendet alle fälligen Schritte an. Liefert einen Bericht für das Protokoll."""
    have = current_version(conn)
    todo = [s for s in STEPS if have < s[0] <= target]
    report = {"from": have, "to": target, "steps": [], "backup": None, "seconds": 0.0}
    if have == 0 or not todo:
        return report                      # neue Datenbank oder nichts zu tun
    report["backup"] = backup(path)
    t0 = time.perf_counter()
    for version, desc, fn in todo:
        log.info("Migration auf Version %s: %s", version, desc)
        conn.execute("BEGIN IMMEDIATE")
        try:
            fn(conn)
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)", (str(version),))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            log.exception("Migration auf Version %s fehlgeschlagen", version)
            raise
        report["steps"].append({"version": version, "description": desc})
    report["seconds"] = round(time.perf_counter() - t0, 2)
    # Nach einem Tabellenumbau liegen viele Seiten frei – die Datei darf schrumpfen.
    # Der Checkpoint danach ist nötig, weil im WAL-Modus sonst erst das Write-Ahead-Log
    # schrumpft und die eigentliche Datei ihre alte Größe behält.
    try:
        conn.execute("VACUUM")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.OperationalError:       # pragma: no cover - z. B. zu wenig Platz
        log.warning("VACUUM nach der Migration nicht möglich")
    log.info("Migration abgeschlossen: %s → %s in %.1f s", have, target, report["seconds"])
    return report
