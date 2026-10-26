"""Filling gaps afterwards from Pi-hole's log: DNS minutes and presence before the tracking."""
import asyncio
import os
import sqlite3
import time
from types import SimpleNamespace as Q

import pytest
from fastapi.testclient import TestClient

from backend.analysis import backfill as bf
from backend.collectors.ftl_queries import FtlQueryLog
from backend.database import migrations
from backend.database.models import SCHEMA_VERSION
from ftl_fake import FakeFtl


def test_minute_rows_count_like_the_live_poll():
    rows = bf.minute_rows([Q(ts=120.5, client="192.0.2.10", domain="a.example", status=2),
                           Q(ts=150, client="192.0.2.10", domain="a.example", status=1),
                           Q(ts=200, client="192.0.2.11", domain="b.example", status=2)])
    assert [(m, c, n, b) for m, c, n, b, _ in rows] == [(120, "192.0.2.10", 2, 1), (180, "192.0.2.11", 1, 0)]


def test_hours_counted_in_full_or_already_checked_are_not_read_again():
    full = set(range(3600, 7200, 60))
    partly = {7200 + 60 * i for i in range(30)}
    assert bf.hours_to_fill(full | partly, {10800}, 3600, 14400) == [7200]


def test_presence_from_dns_hours_merges_consecutive_hours():
    assert bf.presence_periods([(1, 3600), (1, 7200), (1, 14400), (2, 3600)]) == \
        [(1, 3600, 10800), (1, 14400, 18000), (2, 3600, 7200)]


def test_presence_source_column_is_added_by_a_migration(tmp_path):
    db = str(tmp_path / "old.sqlite3")
    c = sqlite3.connect(db)
    c.executescript("""CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO meta VALUES ('schema_version', '9');
        CREATE TABLE device_presence (id INTEGER PRIMARY KEY, dev INTEGER NOT NULL,
            ts_start INTEGER NOT NULL, ts_end INTEGER NOT NULL);
        INSERT INTO device_presence (dev, ts_start, ts_end) VALUES (1, 100, 200);""")
    rep = migrations.migrate(c, db, SCHEMA_VERSION)
    assert [s for s in rep["steps"]] and "source" in [r[1] for r in c.execute("PRAGMA table_info(device_presence)")]
    assert c.execute("SELECT dev, source FROM device_presence").fetchall() == [(1, None)]


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-backfill")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "missing.yaml")
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core())) as c:
        c.get("/")
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


def run(core, coro):
    return asyncio.run_coroutine_threadsafe(coro, core.loop).result(30)


def test_missing_dns_minutes_are_counted_from_the_log_once(client, tmp_path):
    core = client.app.state.core
    core.loadguard.evaluate = lambda: 0
    core.loadguard.level = 0
    now = time.time()
    h = int(now - 3 * 3600) // 3600 * 3600
    ftl = FakeFtl(tmp_path / "ftl.db")
    ftl.add([(h + 65, "192.0.2.10", "a.example", 2), (h + 70, "192.0.2.10", "ads.example", 1),
             (h + 1800, "192.0.2.11", "b.example", 2)])
    ftl.c.close()
    # the live poll had counted minute h+1800 already - it must stay as it was
    core.db.write_sync(lambda c: c.execute(
        "INSERT INTO dns_queries(ts, client_ip, queries, blocked, top_domains) VALUES (?,?,?,?,?)",
        (h + 1800, "192.0.2.11", 9, 0, "[]")))
    log = FtlQueryLog(str(tmp_path / "ftl.db"))
    assert run(core, core._backfill_dns_minutes(now, log)) == 1
    rows = core.db.read_sync(lambda c: c.execute(
        "SELECT ts, client_ip, queries, blocked FROM dns_queries WHERE ts >= ? ORDER BY ts", (h,)).fetchall())
    assert [tuple(r) for r in rows] == [(h + 60, "192.0.2.10", 2, 1), (h + 1800, "192.0.2.11", 9, 0)]
    assert run(core, core._backfill_dns_minutes(now, log)) == 0          # checked hours are not read again


def test_presence_before_tracking_comes_from_dns_hours_and_is_marked(client):
    core = client.app.state.core
    mac = next(iter(core.devices.by_mac))
    dev = core.devices.id_for(mac)
    core._persist_devices()
    core.db.flush_sync()
    first = min(int(time.time()) // 3600 * 3600 - 600, core.db.read_sync(lambda c: c.execute(
        "SELECT MIN(ts_start) FROM device_presence WHERE source IS NULL").fetchone()[0] or 1e12))
    h0 = first // 3600 * 3600 - 5 * 3600

    def setup(c):
        c.execute("INSERT INTO device_presence(dev, ts_start, ts_end) VALUES (?,?,?)", (dev, first, first + 60))
        c.execute("INSERT OR IGNORE INTO dns_clients(key, basis, mac, first_seen, last_seen) VALUES (?, 'mac', ?, 0, 0)",
                  (f"mac:{mac}", mac))
        cid = c.execute("SELECT id FROM dns_clients WHERE key=?", (f"mac:{mac}",)).fetchone()[0]
        c.execute("DELETE FROM dns_client_hourly WHERE client=?", (cid,))
        c.executemany("INSERT INTO dns_client_hourly(ts, client, queries, blocked, duplicates) VALUES (?,?,?,0,0)",
                      [(h0, cid, 5), (h0 + 3600, cid, 3), (h0 + 3 * 3600, cid, 1), (h0 + 4 * 3600, cid, 0)])
    core.db.write_sync(setup)
    assert run(core, core._backfill_presence(time.time())) >= 2      # the demo devices have DNS hours too
    rows = core.db.read_sync(lambda c: c.execute(
        "SELECT ts_start, ts_end, source FROM device_presence WHERE dev=? ORDER BY ts_start", (dev,)).fetchall())
    assert [tuple(r) for r in rows][:2] == [(h0, h0 + 7200, "dns"), (h0 + 3 * 3600, h0 + 4 * 3600, "dns")]
    assert run(core, core._backfill_presence(time.time())) == 0          # once only
    lanes = client.get("/api/devices/presence?range=24h").json()["lanes"]
    lane = next(l for l in lanes if l["mac"] == mac)
    assert any(p[2] == "dns" for p in lane["periods"])
