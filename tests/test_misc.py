"""FRITZ!Box login, database aggregation/retention, configuration, security, lag report."""
import time

import pytest

from backend.analysis.correlation import analyze_user_report, compress_timeline
from backend.api.security import hash_password, verify_password
from backend.collectors.fritzbox import FritzError, compute_login_response
from backend.config import RetentionCfg, build_config
from backend.database import repository as repo
from backend.database.repository import Database
from backend import simulation as sim


def test_fritz_pbkdf2_login_response_avm_example():
    # Example from the AVM documentation "Session IDs in FRITZ!OS"
    ch = "2$10000$5A1711$2000$5A1722"
    assert compute_login_response(ch, "1example!") == \
        "5A1722$1798a1672bca7c6463d6b245f82b53703b0f50813401b03e4045a5861e689adb"


def test_fritz_md5_login_is_refused_instead_of_answered():
    with pytest.raises(FritzError, match="7.24"):
        compute_login_response("1234567z", "äbc")


def test_password_hash_roundtrip():
    h = hash_password("secret123")
    assert verify_password("secret123", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", "broken")


def test_config_validation_rejects_shell_chars():
    with pytest.raises(Exception):
        build_config({"targets": [{"address": "1.1.1.1; rm -rf /"}]})
    c = build_config({"targets": ["1.1.1.1", "example.com"], "gaming_pc": {"ip": "192.168.178.20"}})
    assert [t.address for t in c.targets] == ["1.1.1.1", "example.com"]
    assert "password_hash" not in c.public_dict()["security"]


def test_aggregation_and_retention():
    db = Database(":memory:")
    db.init_sync()
    now = int(time.time()) // 60 * 60
    t0 = now - 120
    for i in range(120):
        row = {"ts": t0 + i, "rtt_avg": 10.0 + (i % 10), "rtt_min": 9.0, "rtt_max": 30.0 if i == 7 else 12.0,
               "gw_rtt": 1.0, "jitter": 1.0, "loss_pct": 0.0, "probes": 3, "lost": 1 if i < 10 else 0,
               "down_bps": 8e6, "up_bps": 1e6, "traffic_src": "capture", "retrans": 0, "tcp_segs": 10}
        db.enqueue(repo.INSERT_MEASUREMENT, repo.measurement_params(1, row))
        db.enqueue(repo.INSERT_DEVICE_TRAFFIC, (1, t0 + i, 7, 1000, 500))
    db.enqueue("INSERT OR IGNORE INTO devices(id, mac, first_seen, last_seen) VALUES(?,?,?,?)",
               (7, sim.MAC_IPHONE, t0, t0))
    db.flush_sync()
    db.write_sync(lambda c: repo.aggregate(c, 1, 10, t0, now))
    db.write_sync(lambda c: repo.aggregate(c, 10, 60, t0, now))
    r10 = db.read_sync(lambda c: [repo.decode_row(x) for x in
                                  c.execute("SELECT * FROM measurements WHERE res=10 ORDER BY ts")])
    assert len(r10) == 12
    assert r10[0]["rtt_max"] == 30.0                         # peaks are preserved
    assert round(r10[0]["loss_pct"], 2) == round(100 * 10 / 30, 2)
    # Everything is stored as integers in the file, not as floats
    raw = db.read_sync(lambda c: c.execute("SELECT rtt_max, loss_pct, down_bps FROM measurements "
                                           "WHERE res=10 ORDER BY ts").fetchone())
    assert all(isinstance(v, int) for v in raw), raw
    assert raw["rtt_max"] == 3000
    dt60 = db.read_sync(lambda c: c.execute("SELECT * FROM device_traffic WHERE res=60").fetchall())
    assert len(dt60) == 2 and dt60[0]["rx_bytes"] == 60 * 1000   # bytes are summed
    ret = RetentionCfg(raw_days=0.1, detailed_days=7, aggregate_days=30)
    db.write_sync(lambda c: repo.apply_retention(c, now + 86400, ret))
    left = db.read_sync(lambda c: c.execute("SELECT res, COUNT(*) n FROM measurements GROUP BY res").fetchall())
    assert {r["res"]: r["n"] for r in left} == {10: 12, 60: 2}  # 1 s raw data deleted
    db.close()


def test_compress_timeline():
    items = [{"ts": 100 + i, "kind": "dns", "text": "DNS 127.0.0.1: timeout", "value": None} for i in range(10)]
    items += [{"ts": 105, "kind": "ping", "text": "Ping 180 ms", "value": 180.0}]
    out = compress_timeline(items)
    dns = [x for x in out if x["kind"] == "dns"]
    assert len(dns) == 1 and dns[0]["ts_end"] == 109 and "(10×)" in dns[0]["text"]
    assert any(x["kind"] == "ping" for x in out)


def test_user_lag_report_upload_saturation(pipeline):
    p = pipeline().run("upload_saturation", seconds=30, post=0)
    reported = p.end - 5
    res = analyze_user_report(reported, lambda a, b: p.hub.range(a, b), p.window, p.thresholds, p.label, [],
                              default_window=30)
    assert res["category"] == "upload"
    assert res["device"]["mac"] == sim.MAC_IPHONE
    texts = [x["text"] for x in res["timeline"]]
    assert any("iPhone (Demo) Upload starts" in t for t in texts)
    assert any(t.startswith("Ping") for t in texts)
    assert not any("Smart-TV" in t for t in texts)          # background traffic is not reported
    assert set(res["windows"]) == {"10s", "30s", "60s", "300s"}


def test_user_lag_report_quiet_network(pipeline):
    p = pipeline().run("normal", seconds=60, post=0)
    res = analyze_user_report(p.end - 3, lambda a, b: p.hub.range(a, b), p.window, p.thresholds, p.label, [])
    assert res["category"] == "unknown" and res["confidence"] == "low"
    assert "No network anomalies" in res["cause"]


# ------------------------------------------------------- long-term & cleanup
def _seed_days(db, days=3, per_day=240):
    """Creates measurements for several completed days (roughly spread)."""
    import datetime as dt
    today = dt.date.today()
    for d in range(1, days + 1):
        day = today - dt.timedelta(days=d)
        t0 = int(dt.datetime.combine(day, dt.time(12, 0)).timestamp())
        for i in range(per_day):
            row = {"ts": t0 + i, "rtt_avg": 15.0 + (i % 40), "rtt_min": 14.0, "rtt_max": 60.0,
                   "gw_rtt": 1.2, "jitter": 1.0 + (i % 5), "probes": 4, "lost": 4 if i < 5 else 0,
                   "down_bps": 5e6, "up_bps": 1e6, "traffic_src": "capture"}
            db.enqueue(repo.INSERT_MEASUREMENT, repo.measurement_params(1, row))
    db.flush_sync()
    return today


def test_daily_stats_summarize_a_day():
    from backend.analysis import daily
    db = Database(":memory:")
    db.init_sync()
    today = _seed_days(db, days=2)
    written = db.write_sync(lambda c: daily.write_missing(c, time.time()))
    assert len(written) == 2
    rows = db.read_sync(lambda c: daily.read(c, days=10))
    r = rows[-1]
    assert r["seconds"] == 240
    assert 15.0 <= r["rtt_p50"] <= 55.0 and r["rtt_p95"] >= r["rtt_p50"]
    assert r["rtt_max"] == 60.0
    assert round(r["loss_pct"], 2) == round(100 * 20 / 960, 2)
    assert r["outage_secs"] == 5                       # seconds in which everything was lost
    assert r["down_peak"] == 5e6
    # A second run writes nothing twice
    assert db.write_sync(lambda c: daily.write_missing(c, time.time())) == []
    # And the daily rows survive retention
    ret = RetentionCfg(raw_days=0.1)
    db.write_sync(lambda c: repo.apply_retention(c, time.time() + 86400 * 400, ret))
    assert len(db.read_sync(lambda c: daily.read(c, days=3650))) == 2
    db.close()


def test_delete_range_by_date(tmp_path):
    db = Database(str(tmp_path / "x.sqlite3"))
    db.init_sync()
    t0 = int(time.time()) - 5000
    for i in range(1000):
        db.enqueue(repo.INSERT_MEASUREMENT, repo.measurement_params(1, {"ts": t0 + i, "rtt_avg": 12.0}))
    db.flush_sync()
    cut = t0 + 400
    vorschau = db.read_sync(lambda c: repo.count_range(c, None, cut))
    assert vorschau["measurements"] == 400
    deleted = db.write_sync(lambda c: repo.delete_range(c, None, cut))
    assert deleted["measurements"] == 400
    remaining = db.read_sync(lambda c: c.execute("SELECT COUNT(*) FROM measurements").fetchone()[0])
    assert remaining == 600
    # Only a slice in the middle
    db.write_sync(lambda c: repo.delete_range(c, t0 + 500, t0 + 600, ["measurements"]))
    assert db.read_sync(lambda c: c.execute("SELECT COUNT(*) FROM measurements").fetchone()[0]) == 500
    db.close()


def test_delete_range_rejects_unknown_table():
    db = Database(":memory:")
    db.init_sync()
    with pytest.raises(ValueError):
        db.write_sync(lambda c: repo.delete_range(c, None, time.time(), ["devices"]))
    db.close()


def test_vacuum_shrinks_file_after_delete(tmp_path):
    db = Database(str(tmp_path / "v.sqlite3"))
    db.init_sync()
    t0 = int(time.time()) - 90000
    for i in range(20000):
        db.enqueue(repo.INSERT_MEASUREMENT, repo.measurement_params(1, {"ts": t0 + i, "rtt_avg": 12.34}))
    db.flush_sync()
    full_size = db.read_sync(repo.db_size)["file"]
    db.write_sync(lambda c: repo.delete_range(c, None, t0 + 19000))
    after_delete = db.read_sync(repo.db_size)
    assert after_delete["file"] >= full_size * 0.9, "DELETE alone does not shrink the file"
    assert after_delete["used"] < full_size * 0.5, "used space must go down"
    res = db.maintenance_sync(repo.vacuum)
    assert res["freed"] > 0 and db.read_sync(repo.db_size)["file"] < full_size * 0.5
    db.close()


def test_hub_drops_deleted_seconds_from_ring():
    from backend.analysis.metrics import MetricsHub, TargetInfo
    h = MetricsHub(timeout=1.5)
    h.set_target(TargetInfo(2, "1.1.1.1", "internet"))
    t = 1_700_000_000
    for i in range(30):
        h.add_probe(2, t + i + 0.1, 12.0)
    h.finalize_due(now=t + 40)
    assert len(h.ring) >= 25
    weg = h.drop_range(None, t + 10)
    assert weg == 10 and all(r["ts"] >= t + 10 for r in h.ring)


def test_clock_jump_resets_only_pending_seconds():
    from backend.analysis.metrics import MetricsHub, TargetInfo
    h = MetricsHub(timeout=1.5)
    h.set_target(TargetInfo(2, "1.1.1.1", "internet"))
    t = 1_700_000_000
    for i in range(10):
        h.add_probe(2, t + i + 0.1, 12.0)
    h.finalize_due(now=t + 20)
    finished = len(h.ring)
    h.add_probe(2, t + 25.1, 12.0)               # started second
    h.reset_pending()
    assert len(h.ring) == finished, "finished seconds are kept"
    assert h.last_finalized == 0                 # time base locks in again
    h.add_probe(2, t + 100.1, 30.0)              # after the jump
    rows = h.finalize_due(now=t + 110)
    assert rows and rows[0]["ts"] == t + 100 and rows[0]["rtt_avg"] == 30.0


def test_config_aliases_keep_old_files_working():
    from backend.config import Config, apply_aliases
    data = {"retention": {"keep_raw_days": 2, "max_size_mb": 500}}
    assert apply_aliases(data)
    cfg = Config(**data)
    assert cfg.retention.raw_days == 2 and cfg.retention.max_db_mb == 500


def test_config_alias_does_not_overwrite_new_key():
    from backend.config import apply_aliases
    data = {"retention": {"keep_raw_days": 2, "raw_days": 5}}
    apply_aliases(data)
    assert data["retention"]["raw_days"] == 5


# ------------------------------------------------------- DNS probes
def test_dns_prober_alternates_cached_and_uncached():
    from backend.collectors.dns import DnsProber
    p = DnsProber(["1.1.1.1"], "example.com", 5.0, 2.0, lambda *a: None, pihole_present=False,
                  uncached_suffix="nla-probe.invalid")
    seen = []
    for _ in range(4):
        name, kind = p.next_query()
        p._uncached_turn = not p._uncached_turn
        seen.append((name, kind))
    assert [k for _n, k in seen] == ["cached", "uncached", "cached", "uncached"]
    assert seen[0][0] == "example.com"
    assert seen[1][0].endswith(".nla-probe.invalid") and seen[1][0] != seen[3][0], "name must be random"


def test_dns_prober_without_suffix_stays_cached_only():
    from backend.collectors.dns import DnsProber
    p = DnsProber(["1.1.1.1"], "example.com", 5.0, 2.0, lambda *a: None, pihole_present=False,
                  uncached_suffix="")
    p._uncached_turn = True
    assert p.next_query() == ("example.com", "cached")


def test_nxdomain_is_success_for_the_uncached_probe():
    """The uncached probe expects NXDOMAIN - that must not trigger DNS_FAILURE."""
    from backend.analysis.events import DNS_FAILURE
    from backend.analysis.metrics import MetricsHub, TargetInfo
    from backend.analysis.events import EventEngine
    from backend.config import Thresholds
    h = MetricsHub(timeout=1.5)
    h.set_target(TargetInfo(2, "192.0.2.101", "internet"))
    events = []
    eng = EventEngine(Thresholds(), lambda: (100e6, 40e6), lambda: 1, gaming_active_fn=lambda: False)
    eng.on_start.append(events.append)
    h.subscribers.append(eng.process)
    t = 1_700_000_000
    for i in range(10):
        h.add_probe(2, t + i + 0.1, 12.0)
        h.add_dns("127.0.0.1", t + i + 0.5, 0.4, "ok", "cached")
        h.add_dns("127.0.0.1", t + i + 0.6, 24.0, "nxdomain", "uncached")
    h.finalize_due(now=t + 20)
    assert not [e for e in events if e.type == DNS_FAILURE]


def test_broken_upstream_is_detected_even_when_cache_answers():
    """Only the uncached probe fails → the upstream is broken, not Pi-hole."""
    from backend.analysis.events import DNS_FAILURE, EventEngine
    from backend.analysis.metrics import MetricsHub, TargetInfo
    from backend.config import Thresholds
    h = MetricsHub(timeout=1.5)
    h.set_target(TargetInfo(2, "192.0.2.101", "internet"))
    events = []
    eng = EventEngine(Thresholds(), lambda: (100e6, 40e6), lambda: 1, gaming_active_fn=lambda: False)
    eng.on_start.append(events.append)
    h.subscribers.append(eng.process)
    t = 1_700_000_000
    for i in range(10):
        h.add_probe(2, t + i + 0.1, 12.0)
        h.add_dns("127.0.0.1", t + i + 0.5, 0.4, "ok", "cached")      # cache keeps answering
        h.add_dns("127.0.0.1", t + i + 0.6, None, "timeout", "uncached")
    h.finalize_due(now=t + 20)
    fails = [e for e in events if e.type == DNS_FAILURE]
    assert fails, "outage only on the uncached path was not detected"
    assert "ungecacht" in fails[0].target


def test_demo_data_uses_documentation_addresses():
    """Demo data must never look like a real home network."""
    import ipaddress
    from backend import simulation as sim
    doc_nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    addresses = [ip for ip, _n in sim.DEMO_DEVICES.values()] + [sim.DEMO_GATEWAY, sim.DEMO_DNS_UPSTREAM,
                                                               sim.DEMO_GAME_SERVER]
    for a in addresses:
        assert any(ipaddress.ip_address(a) in n for n in doc_nets), f"{a} lies outside the documentation ranges"
    for mac in sim.DEMO_DEVICES:
        assert int(mac.split(":")[0], 16) & 0x02, f"{mac} is not a locally administered MAC"
