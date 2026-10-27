"""Migration of an existing database to the compact format."""
import os
import sqlite3

from backend.database import migrations, repository as repo
from backend.database.models import SCHEMA_VERSION
from backend.database.repository import Database

# The schema as version 2 had it - deliberately as a copy, so that the test still
# builds a real old database when models.py evolves.
SCHEMA_V2 = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at REAL NOT NULL);
CREATE TABLE targets (id INTEGER PRIMARY KEY, address TEXT NOT NULL UNIQUE, name TEXT, kind TEXT NOT NULL);
CREATE TABLE ping_samples (ts REAL NOT NULL, target_id INTEGER NOT NULL, rtt_ms REAL, lost INTEGER NOT NULL);
CREATE TABLE measurements (
    res INTEGER NOT NULL, ts INTEGER NOT NULL, rtt_avg REAL, rtt_min REAL, rtt_max REAL, gw_rtt REAL,
    jitter REAL, loss_pct REAL, probes INTEGER, lost INTEGER, down_bps REAL, up_bps REAL,
    traffic_src TEXT, retrans INTEGER, tcp_segs INTEGER, retrans_down INTEGER, retrans_up INTEGER,
    dns_ms REAL, dns_fail INTEGER, game_rtt REAL, game_pps REAL, game_gap_ms REAL,
    PRIMARY KEY (res, ts)) WITHOUT ROWID;
CREATE TABLE target_measurements (
    res INTEGER NOT NULL, ts INTEGER NOT NULL, target_id INTEGER NOT NULL, rtt_avg REAL, rtt_max REAL,
    probes INTEGER, lost INTEGER, PRIMARY KEY (res, target_id, ts)) WITHOUT ROWID;
CREATE TABLE devices (
    mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, custom_name TEXT, vendor TEXT, sources TEXT,
    interface TEXT, first_seen REAL NOT NULL, last_seen REAL NOT NULL, active INTEGER NOT NULL DEFAULT 0);
CREATE TABLE device_traffic (
    res INTEGER NOT NULL, ts INTEGER NOT NULL, mac TEXT NOT NULL, rx_bytes INTEGER NOT NULL,
    tx_bytes INTEGER NOT NULL, rx_pkts INTEGER NOT NULL, tx_pkts INTEGER NOT NULL,
    udp_bytes INTEGER NOT NULL, lan_bytes INTEGER NOT NULL, retrans INTEGER NOT NULL,
    PRIMARY KEY (res, ts, mac)) WITHOUT ROWID;
CREATE TABLE bufferbloat (
    ts INTEGER PRIMARY KEY, idle_ms REAL NOT NULL, idle_secs INTEGER NOT NULL, up_ms REAL,
    up_worst_ms REAL, up_secs INTEGER NOT NULL DEFAULT 0, down_ms REAL, down_worst_ms REAL,
    down_secs INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
CREATE TABLE network_flows (id INTEGER PRIMARY KEY, ts_start REAL NOT NULL, ts_end REAL NOT NULL,
    proto TEXT NOT NULL, mac TEXT, local_ip TEXT NOT NULL, local_port INTEGER, remote_ip TEXT NOT NULL,
    remote_port INTEGER, bytes_up INTEGER NOT NULL, bytes_down INTEGER NOT NULL, pkts_up INTEGER NOT NULL,
    pkts_down INTEGER NOT NULL, retrans INTEGER NOT NULL, resets INTEGER NOT NULL, max_gap_ms REAL, dns_name TEXT);
CREATE TABLE events (id INTEGER PRIMARY KEY, type TEXT NOT NULL, severity TEXT NOT NULL, ts_start REAL NOT NULL,
    ts_end REAL, peak REAL, baseline REAL, target TEXT, mac TEXT, details TEXT, incident_id INTEGER);
CREATE TABLE incidents (id INTEGER PRIMARY KEY, source TEXT NOT NULL, ts_start REAL NOT NULL, ts_end REAL,
    reported_at REAL, title TEXT, cause TEXT, category TEXT, confidence TEXT, analysis TEXT,
    session_id INTEGER, pcap_protected INTEGER NOT NULL DEFAULT 0);
CREATE TABLE dns_queries (ts INTEGER NOT NULL, client_ip TEXT NOT NULL, queries INTEGER NOT NULL,
    blocked INTEGER NOT NULL, top_domains TEXT, PRIMARY KEY (ts, client_ip)) WITHOUT ROWID;
CREATE TABLE gaming_sessions (id INTEGER PRIMARY KEY, ts_start REAL NOT NULL, ts_end REAL, mac TEXT,
    device_ip TEXT, server_ip TEXT, server_port INTEGER, auto_detected INTEGER NOT NULL DEFAULT 0, summary TEXT);
CREATE TABLE pcap_files (id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, ts_start REAL NOT NULL,
    ts_end REAL, size INTEGER NOT NULL DEFAULT 0, protected INTEGER NOT NULL DEFAULT 0, incident_id INTEGER);
"""

T0 = 1_700_000_000
MAC_A, MAC_B = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"


def make_v2(path, seconds=600):
    c = sqlite3.connect(path)
    c.executescript(SCHEMA_V2)
    c.execute("INSERT INTO meta VALUES('schema_version', '2')")
    c.execute("INSERT INTO devices(mac, hostname, custom_name, first_seen, last_seen, active) "
              "VALUES(?,?,?,?,?,1)", (MAC_A, "ps5", "PS5 living room", T0, T0))
    # MAC_B is deliberately NOT in devices - only in the traffic. It must not get lost.
    for i in range(seconds):
        c.execute("INSERT INTO measurements(res, ts, rtt_avg, rtt_min, rtt_max, gw_rtt, jitter, loss_pct, "
                  "probes, lost, down_bps, up_bps, traffic_src, retrans, tcp_segs, retrans_down, retrans_up, "
                  "dns_ms, dns_fail, game_rtt, game_pps, game_gap_ms) "
                  "VALUES(1,?,?,?,?,?,?,?,?,?,?,?, 'capture', 0,100,0,0, ?,0, NULL,NULL,NULL)",
                  (T0 + i, 18.34, 17.0, 25.5, 1.23, 0.87, 2.9, 4, 0, 3_200_000.0, 400_000.0, 12.5))
        c.execute("INSERT INTO target_measurements VALUES(1,?,?,?,?,?,?)", (T0 + i, 2, 18.34, 20.1, 1, 0))
        for mac in (MAC_A, MAC_B):
            c.execute("INSERT INTO device_traffic VALUES(1,?,?,?,?,?,?,?,?,?)",
                      (T0 + i, mac, 4000, 900, 8, 6, 200, 0, 0))
    c.execute("INSERT INTO bufferbloat VALUES(?,?,?,?,?,?,?,?,?)", (T0, 18.0, 300, None, None, 0, 140.5, 190.0, 40))
    c.commit()
    c.close()


def test_migration_converts_and_keeps_every_value(tmp_path):
    p = str(tmp_path / "old.sqlite3")
    make_v2(p)
    size_before = os.path.getsize(p)

    db = Database(p)
    db.init_sync()
    assert db.migration["from"] == 2 and db.migration["steps"], db.migration

    # Measurements come back unchanged (now decoded from integers)
    row = db.read_sync(lambda c: repo.decode_row(
        c.execute("SELECT * FROM measurements WHERE res=1 ORDER BY ts").fetchone()))
    assert row["rtt_avg"] == 18.34 and row["gw_rtt"] == 1.23 and row["loss_pct"] == 2.9
    assert row["down_bps"] == 3_200_000 and row["dns_ms"] == 12.5
    raw = db.read_sync(lambda c: c.execute("SELECT rtt_avg, down_bps FROM measurements WHERE res=1").fetchone())
    assert isinstance(raw["rtt_avg"], int) and raw["rtt_avg"] == 1834

    t = db.read_sync(lambda c: c.execute("SELECT * FROM target_measurements LIMIT 1").fetchone())
    assert repo.dec(t["rtt_avg"], "rtt_avg") == 18.34

    bb = db.read_sync(lambda c: repo.read_bufferbloat(c, T0 - 1, T0 + 1))
    assert bb[0]["idle_ms"] == 18.0 and bb[0]["down_worst_ms"] == 190.0

    # The device name survives, and the device known only from traffic gets an entry
    devs = db.read_sync(lambda c: {r["mac"]: dict(r) for r in c.execute("SELECT * FROM devices")})
    assert devs[MAC_A]["custom_name"] == "PS5 living room"
    assert MAC_B in devs, "device only from device_traffic was not created"
    assert all(d["id"] for d in devs.values())

    # Traffic is complete and hangs on the right MAC
    n, s = db.read_sync(lambda c: c.execute(
        "SELECT COUNT(*), SUM(rx_bytes) FROM device_traffic t JOIN devices d ON d.id=t.dev "
        "WHERE d.mac=?", (MAC_A,)).fetchone())
    assert n == 600 and s == 600 * 4000

    assert os.path.getsize(p) < size_before, "the more compact format must be smaller"
    db.close()


def test_migration_is_idempotent_and_backs_up(tmp_path):
    p = str(tmp_path / "old.sqlite3")
    make_v2(p, seconds=60)
    db = Database(p)
    db.init_sync()
    assert os.path.exists(p + migrations.BACKUP_SUFFIX), "backup copy missing"
    db.close()

    db2 = Database(p)                       # second start: nothing left to do
    db2.init_sync()
    assert db2.migration["steps"] == []
    assert db2.read_sync(lambda c: migrations.current_version(c)) == SCHEMA_VERSION
    db2.close()


def test_fresh_database_needs_no_migration(tmp_path):
    db = Database(str(tmp_path / "new.sqlite3"))
    db.init_sync()
    assert db.migration == {"from": 0, "to": SCHEMA_VERSION, "steps": [], "backup": None, "seconds": 0.0}
    assert not os.path.exists(str(tmp_path / "new.sqlite3") + migrations.BACKUP_SUFFIX)
    db.close()


def test_compact_format_is_much_smaller(tmp_path):
    """The rebuild should pay off - otherwise it would not be worth the effort."""
    p = str(tmp_path / "gross.sqlite3")
    make_v2(p, seconds=3000)
    size_before = os.path.getsize(p)
    db = Database(p)
    db.init_sync()
    db.close()
    # Compare the data, not the fixed cost of empty tables: every new table adds
    # a few pages that have nothing to do with the storage format.
    empty_v2 = str(tmp_path / "empty_v2.sqlite3")
    make_v2(empty_v2, seconds=0)
    empty = Database(str(tmp_path / "empty.sqlite3"))
    empty.init_sync()
    empty.close()
    before = size_before - os.path.getsize(empty_v2)
    after = os.path.getsize(p) - os.path.getsize(str(tmp_path / "empty.sqlite3"))
    assert after < before * 0.6, f"only {100 - after / before * 100:.0f} % saved"


def test_incident_analyses_are_compressed_and_lose_only_the_event_copy(tmp_path):
    import json
    import sqlite3 as sq
    from backend.database.repository import ANALYSIS_MAGIC, dec_analysis
    path = str(tmp_path / "v11.sqlite3")
    c = sq.connect(path)
    c.executescript("""CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO meta VALUES ('schema_version', '11');
        CREATE TABLE incidents (id INTEGER PRIMARY KEY, source TEXT NOT NULL, ts_start REAL NOT NULL, ts_end REAL,
            reported_at REAL, title TEXT, cause TEXT, category TEXT, confidence TEXT, analysis TEXT, session_id INTEGER,
            pcap_protected INTEGER NOT NULL DEFAULT 0);""")
    big = {"cause": "Packet loss", "metrics": {"loss_pct": 12.5}, "evidence": ["x" * 50] * 40,
           "events": [{"id": i, "type": "PACKET_LOSS", "details": {"k": "v" * 40}} for i in range(30)]}
    c.execute("INSERT INTO incidents (id, source, ts_start, analysis) VALUES (1, 'auto', 1, ?)", (json.dumps(big),))
    c.execute("INSERT INTO incidents (id, source, ts_start, analysis) VALUES (2, 'user', 1, ?)", (json.dumps(big),))
    c.commit()
    before = c.execute("SELECT SUM(length(analysis)) FROM incidents").fetchone()[0]
    migrations.migrate(c, path, SCHEMA_VERSION)
    rows = {r[0]: r[1] for r in c.execute("SELECT id, analysis FROM incidents")}
    assert all(isinstance(v, bytes) and v.startswith(ANALYSIS_MAGIC) for v in rows.values())
    auto, user = dec_analysis(rows[1]), dec_analysis(rows[2])
    assert "events" not in auto and auto["metrics"] == {"loss_pct": 12.5} and auto["evidence"] == big["evidence"]
    assert len(user["events"]) == 30            # a lag report keeps its window's events
    after = c.execute("SELECT SUM(length(analysis)) FROM incidents").fetchone()[0]
    assert after < before / 5


def test_both_analysis_formats_are_read():
    from backend.database.repository import dec_analysis, enc_analysis
    a = {"cause": "x", "metrics": {"n": 1}}
    assert dec_analysis(enc_analysis(a)) == a
    assert dec_analysis('{"cause": "x"}') == {"cause": "x"} and dec_analysis(None) == {}
