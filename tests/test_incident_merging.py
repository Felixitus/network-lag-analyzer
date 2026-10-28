"""One problem, one incident: bursts close together merge, single-target issues and blips stay events."""
import pytest

from backend.analysis import correlation as corr
from backend.analysis.correlation import CLOSE_AFTER, POST_SECONDS, Correlator, Incident, dismiss_reason
from backend.analysis.events import Event


class Harness:
    def __init__(self, monkeypatch, result=None):
        self.result = result or {"cause": "Packet loss", "category": "loss", "confidence": "medium"}
        monkeypatch.setattr(corr, "analyze", lambda w: dict(self.result))
        self.closed, self.dismissed = [], []
        ids = iter(range(1, 1000))
        self.c = Correlator(lambda t0, t1: type("W", (), {"events": []})(), lambda: next(ids),
                            lambda inc, evs: self.closed.append(inc), on_dismiss=lambda inc, evs, r: self.dismissed.append((inc, r)),
                            dismiss_fn=dismiss_reason)
        self.eid = 0

    def burst(self, t, seconds=3, typ="PACKET_LOSS"):
        self.eid += 1
        ev = Event(self.eid, typ, t, "critical")
        self.c.event_started(ev)
        ev.ts_end = t + seconds
        self.c.event_ended(ev)
        for s in range(int(t), int(t + seconds) + 1):
            self.c.tick(s)

    def idle(self, t0, t1):
        for s in range(int(t0), int(t1)):
            self.c.tick(s)


def test_bursts_a_minute_apart_are_one_incident(monkeypatch):
    h = Harness(monkeypatch)
    for k in range(5):                         # a bad cable: a burst every 60 s
        h.burst(1000 + 60 * k, seconds=8)
        h.idle(1000 + 60 * k + 9, 1000 + 60 * (k + 1))
    h.idle(1300, 1300 + CLOSE_AFTER + POST_SECONDS + 2)
    assert len(h.closed) == 1 and len(h.closed[0].event_ids) == 5
    assert h.closed[0].ts_end - h.closed[0].ts_start >= 240


def test_bursts_further_apart_than_the_merge_gap_are_separate(monkeypatch):
    h = Harness(monkeypatch)
    h.burst(1000, seconds=8)
    h.idle(1009, 1009 + CLOSE_AFTER + POST_SECONDS + 2)
    h.burst(2000, seconds=8)
    h.idle(2009, 2009 + CLOSE_AFTER + POST_SECONDS + 2)
    assert len(h.closed) == 2


def test_a_long_episode_is_cut_after_the_maximum(monkeypatch):
    h = Harness(monkeypatch)
    t = 1000
    while t < 1000 + corr.MAX_INCIDENT + 600:
        h.burst(t, seconds=8)
        h.idle(t + 9, t + 30)
        t += 30
    assert 1 <= len(h.closed) <= 2 and all(i.ts_end - i.ts_start <= corr.MAX_INCIDENT for i in h.closed)


def test_problem_of_one_external_target_stays_an_event(monkeypatch):
    h = Harness(monkeypatch, {"cause": "Problem at the target", "category": "target", "confidence": "medium"})
    h.burst(1000, seconds=20)
    h.idle(1021, 1021 + CLOSE_AFTER + POST_SECONDS + 2)
    assert h.closed == [] and [r for _i, r in h.dismissed] == ["single_target"]


def test_game_server_problem_is_still_an_incident(monkeypatch):
    h = Harness(monkeypatch, {"cause": "Problem at the game server", "category": "game_server", "confidence": "medium"})
    h.burst(1000, seconds=20)
    h.idle(1021, 1021 + CLOSE_AFTER + POST_SECONDS + 2)
    assert len(h.closed) == 1 and h.dismissed == []


@pytest.mark.parametrize("seconds,confidence,category,kept", [
    (3, "low", "loss", False),          # a blip nobody can explain
    (3, "medium", "loss", True),        # short, but a rule explains it
    (3, "low", "wan", True),            # short, but a line problem
    (30, "low", "loss", True),          # long enough to matter
])
def test_short_unexplained_blips_stay_events(monkeypatch, seconds, confidence, category, kept):
    inc = Incident(id=1, source="auto", ts_start=1000, ts_end=1000 + seconds)
    reason = dismiss_reason(inc, {"category": category, "confidence": confidence})
    assert (reason is None) == kept


def test_a_lag_report_of_the_user_is_never_dismissed(monkeypatch):
    h = Harness(monkeypatch, {"cause": "x", "category": "target", "confidence": "low"})
    inc = Incident(id=99, source="user", ts_start=1000, ts_end=1002)
    h.c._finish(inc)
    assert h.closed == [inc] and h.dismissed == []


def test_dismissed_incident_leaves_no_row_but_keeps_its_events(tmp_path, monkeypatch):
    import asyncio
    from fastapi.testclient import TestClient
    monkeypatch.setenv("NLA_DEV_MODE", "1")
    monkeypatch.setenv("NLA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NLA_CONFIG", str(tmp_path / "missing.yaml"))
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core())) as c:
        core = c.app.state.core
        inc = Incident(id=4242, source="auto", ts_start=1000, ts_end=1002, title="x")
        ev = Event(777, "PACKET_LOSS", 1000, "critical", ts_end=1002, incident_id=4242)

        async def run():
            core._incident_opened(inc)
            core._incident_dismissed(inc, [ev], "blip")
        asyncio.run_coroutine_threadsafe(run(), core.loop).result(5)
        core.db.flush_sync()
        rows = core.db.read_sync(lambda c: (c.execute("SELECT COUNT(*) FROM incidents WHERE id=4242").fetchone()[0],
                                            c.execute("SELECT incident_id FROM events WHERE id=777").fetchone()))
        assert rows[0] == 0 and rows[1] is not None and rows[1][0] is None
        assert all(x["id"] != 4242 for x in core.recent_incidents)
        assert c.get("/api/status").json()["incidents_dismissed"] == {"blip": 1}


def test_incidents_left_open_by_a_stopped_service_are_closed_on_start(tmp_path):
    """Six such rows painted every chart on the Pi red - each drawn as a band up to "now"."""
    import sqlite3
    from backend.core import INTERRUPTED_TITLE, close_orphaned_incidents
    from backend.database.models import SCHEMA
    c = sqlite3.connect(tmp_path / "db.sqlite3")
    c.executescript(SCHEMA)
    c.execute("INSERT INTO incidents(id, source, ts_start, ts_end, title) VALUES (1, 'auto', 1000, NULL, 'Ongoing incident')")
    c.execute("INSERT INTO incidents(id, source, ts_start, ts_end, title) VALUES (2, 'auto', 5000, NULL, 'Ongoing incident')")
    c.execute("INSERT INTO incidents(id, source, ts_start, ts_end, title, cause) VALUES (3, 'auto', 9000, 9010, 'x', 'y')")
    c.execute("INSERT INTO events(id, type, ts_start, ts_end, severity, incident_id) VALUES (1, 'PING_SPIKE', 1001, 1042, 'warning', 1)")
    assert close_orphaned_incidents(c) == 2
    rows = c.execute("SELECT id, ts_end, title, cause FROM incidents ORDER BY id").fetchall()
    assert rows == [(1, 1042, INTERRUPTED_TITLE, None), (2, 5000, INTERRUPTED_TITLE, None), (3, 9010, "x", "y")]
