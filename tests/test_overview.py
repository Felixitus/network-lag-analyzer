"""Overview page: status lights and the timeline of stored measurements."""
import os
import time

import pytest
from fastapi.testclient import TestClient

from backend.analysis import overview as ov
from backend.config import Thresholds
from backend.database.repository import Database

GW = "192.0.2.1"
T0 = 1_792_000_800          # multiple of 600


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "x.sqlite3"))
    d.init_sync()
    d.write_sync(lambda c: c.execute("INSERT INTO targets(id, address, name, kind) VALUES (1, ?, 'Router', 'gateway')", (GW,)))
    yield d
    d.close()


def minute(c, ts, probes=60, lost=0, rtt=20.0, dns_fail=0, gw_lost=0):
    c.execute("INSERT INTO measurements(res, ts, rtt_avg, probes, lost, dns_fail) VALUES (60,?,?,?,?,?)",
              (ts, int(rtt * 100), probes, lost, dns_fail))
    c.execute("INSERT INTO target_measurements(res, ts, target_id, rtt_avg, probes, lost) VALUES (60,?,1,80,60,?)", (ts, gw_lost))


def cells(db, key, n=3):
    tl = db.read_sync(lambda c: ov.timeline(c, Thresholds(), GW, T0, T0 + 600 * n, 600))
    return [(x or {}).get("level") if x else None for x in next(r for r in tl["rows"] if r["key"] == key)["cells"]]


def test_a_bucket_without_measurements_is_not_reported_as_good(db):
    db.write_sync(lambda c: [minute(c, T0 + 60 * i) for i in range(10)])
    assert cells(db, "internet") == ["good", None, None]
    assert cells(db, "dns") == ["good", None, None]


def test_one_offline_minute_makes_the_bucket_critical(db):
    db.write_sync(lambda c: [minute(c, T0 + 60 * i, lost=60 if i == 3 else 0) for i in range(10)])
    tl = db.read_sync(lambda c: ov.timeline(c, Thresholds(), GW, T0, T0 + 600, 600))
    cell = tl["rows"][0]["cells"][0]
    assert cell["level"] == "critical" and "1 min offline" in cell["text"]


def test_loss_on_the_link_to_the_router_shows_up_in_its_own_row(db):
    # the lesson from a week of silent loss on the Pi's own cable: internet and router rows differ
    db.write_sync(lambda c: [minute(c, T0 + 60 * i, lost=6, gw_lost=6) for i in range(10)])
    assert cells(db, "router", 1) == ["critical"]
    assert cells(db, "internet", 1) == ["critical"]


def test_latency_uses_the_worst_minute_and_the_configured_thresholds(db):
    db.write_sync(lambda c: [minute(c, T0 + 60 * i, rtt=120.0 if i == 5 else 15.0) for i in range(10)])
    assert cells(db, "latency", 1) == ["critical"]


def test_dns_failures_in_several_minutes_are_critical_a_single_one_a_warning(db):
    db.write_sync(lambda c: [minute(c, T0 + 60 * i, dns_fail=1 if i < 3 else 0) for i in range(10)]
                  + [minute(c, T0 + 600 + 60 * i, dns_fail=2 if i == 0 else 0) for i in range(10)])
    assert cells(db, "dns", 2) == ["critical", "warning"]


def test_reboots_are_recognized_from_a_new_boot_time():
    log = ov.record_start([], 1000.0, 900.0)
    log = ov.record_start(log, 2000.0, 900.0)       # service restart only
    log = ov.record_start(log, 5000.0, 4950.0)      # Pi rebooted
    kinds = [(r["kind"], r["ts"]) for r in ov.restarts(log, 0, 10_000)]
    assert kinds == [("boot", 900.0), ("service", 1000.0), ("service", 2000.0), ("boot", 4950.0), ("service", 5000.0)]


def test_a_boot_time_after_the_start_is_not_trusted():
    # clock jumped after boot: the computed boot time would lie in the future of the start
    log = ov.record_start([], 1000.0, 1500.0)
    assert [r["kind"] for r in ov.restarts(log, 0, 10_000)] == ["service"]


def test_restart_log_is_bounded():
    log = []
    for i in range(ov.RESTART_LOG_MAX + 20):
        log = ov.record_start(log, float(i), None)
    assert len(log) == ov.RESTART_LOG_MAX and log[-1]["ts"] == ov.RESTART_LOG_MAX + 19


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-overview")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "missing.yaml")
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core())) as c:
        c.get("/")
        time.sleep(1.5)
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


def test_overview_api_has_lights_timeline_and_this_start(client):
    r = client.get("/api/overview").json()
    keys = [l["key"] for l in r["lights"]]
    assert keys[:2] == ["internet", "router"] and {"dns", "pi"} <= set(keys)
    assert all(l["level"] in ("good", "warning", "critical", "unknown") for l in r["lights"])
    tl = r["timeline"]
    assert len(tl["starts"]) == 144 and all(len(row["cells"]) == 144 for row in tl["rows"])
    assert any(x["kind"] == "service" for x in r["restarts"])
    assert len(client.get("/api/overview?range=7d").json()["timeline"]["starts"]) == 168
    assert client.get("/api/overview?range=1y").status_code == 422
