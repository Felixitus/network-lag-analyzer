"""The weekly report: worst hours, outages, honest gaps, and when it is sent."""
import os
import time

import pytest
from fastapi.testclient import TestClient

from backend.analysis import weekly
from backend.database.repository import Database

T0 = 1_792_000_800 // 3600 * 3600


def _hour(c, h, minutes=60, lost=0, rtt_ms=20.0, outage_minutes=0):
    for i in range(minutes):
        down = i < outage_minutes
        c.execute("INSERT INTO measurements(res, ts, probes, lost, rtt_avg, rtt_max) VALUES (60,?,60,?,?,?)",
                  (T0 + h * 3600 + 60 * i, 60 if down else lost, None if down else int(rtt_ms * 100),
                   None if down else int(rtt_ms * 300)))


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "w.sqlite3"))
    d.init_sync()
    yield d
    d.close()


def test_worst_hours_rank_loss_then_ping_and_leave_out_good_hours_and_outages(db):
    def fill(c):
        _hour(c, 0)                                      # good
        _hour(c, 1, rtt_ms=80)                          # high ping, no loss
        _hour(c, 2, lost=3)                             # 5 % loss
        _hour(c, 3, lost=1, rtt_ms=30)                  # 1.7 % loss
        _hour(c, 4, outage_minutes=60)                  # an outage, not a "bad hour"
    db.write_sync(fill)
    wh = db.read_sync(lambda c: weekly.worst_hours(c, T0, T0 + 6 * 3600, warn_ms=50))
    assert [(x["ts"] - T0) // 3600 for x in wh] == [2, 3, 1]
    assert wh[0]["loss_pct"] == 5.0 and wh[2]["rtt_ms"] == 80.0


def test_a_week_with_gaps_says_how_much_was_measured(db):
    db.write_sync(lambda c: [_hour(c, h) for h in range(84)])            # half of the week
    r = db.read_sync(lambda c: weekly.collect(c, T0, T0 + weekly.WEEK, 50))
    assert r["measured"] == pytest.approx(0.5)
    title, text = weekly.render({**r, "start": T0, "end": T0 + weekly.WEEK, "new_devices": [], "dns": None,
                                 "dns_error": "DNS usage is not recorded"})
    assert title.startswith("Weekly report")
    assert "Measured 50 % of the week. Gaps are not counted" in text
    assert "INTERNET OUTAGES: none measured." in text and "no hour with loss" in text
    assert "DNS: not available - DNS usage is not recorded." in text


def test_report_lists_outages_new_devices_and_dns_signs(db):
    db.write_sync(lambda c: (_hour(c, 0, outage_minutes=12), _hour(c, 1, lost=6)))
    r = db.read_sync(lambda c: weekly.collect(c, T0, T0 + 2 * 3600, 50))
    dev = {"name": "Phone", "vendor": None, "mac": "02:00:00:00:00:07", "first_seen": T0 + 600}
    dns = {"devices": [{"client": {"name": "Laptop"}, "level": "bypassing", "text": "probably resolves past Pi-hole"},
                       {"client": {"name": "TV"}, "level": "complete", "text": "ok"}],
           "threats": [{"client": {"name": "Laptop"}, "lookups": 4, "names": ["bad.example"]}]}
    _title, text = weekly.render({**r, "start": T0, "end": T0 + 2 * 3600, "new_devices": [dev], "dns": dns})
    assert "INTERNET OUTAGES: 1, 12 min in total" in text
    assert "10.0 % loss" in text
    assert "NEW DEVICES: 1" in text and "Phone (02:00:00:00:00:07)" in text
    assert "- Laptop: probably resolves past Pi-hole" in text and "TV" not in text
    assert "Malware/phishing lookups: Laptop 4× (bad.example)" in text


def test_report_is_due_once_a_week_from_its_hour_on():
    monday_9 = time.mktime((2026, 10, 26, 9, 0, 0, 0, 0, -1))
    assert weekly.due(monday_9, None, weekday=0, hour=8)
    assert not weekly.due(monday_9, None, weekday=0, hour=10)            # too early
    assert not weekly.due(monday_9, monday_9 - 3600, weekday=0, hour=8)  # already sent today
    assert weekly.due(monday_9, monday_9 - 7 * 86400, weekday=0, hour=8)
    assert not weekly.due(monday_9 + 86400, None, weekday=0, hour=8)     # Tuesday


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-weekly")
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


def test_preview_does_not_send_and_sending_needs_a_channel(client):
    core = client.app.state.core
    sent = []

    async def fake_send(m):
        sent.append(m)
        return {}
    core._send = fake_send
    r = client.get("/api/notify/report").json()
    assert r["title"].startswith("Weekly report") and "Measured" in r["text"] and sent == []
    hdr = {"X-CSRF-Token": client.cookies.get("nla_csrf")}
    assert client.post("/api/notify/report", json={}, headers=hdr).status_code == 400
