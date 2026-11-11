"""Incident impact, the memory limit as the kernel applies it."""
from backend.analysis import pi_health
from backend.analysis.impact import rate


def m(**kw):
    return {"ping_before": 28.0, "ping_peak": 30.0, "loss_pct": 0.0, "duration": 40, "game_gap_peak": None, **kw}


def test_retransmissions_at_a_normal_ping_are_minor():
    assert rate("auto", m()) == "minor"


def test_lost_packets_or_a_risen_ping_are_noticeable():
    assert rate("auto", m(loss_pct=1.0)) == "noticeable"
    assert rate("auto", m(ping_peak=70.0)) == "noticeable"
    assert rate("auto", m(game_gap_peak=800.0)) == "noticeable"


def test_heavy_loss_or_a_ping_far_above_normal_is_severe():
    assert rate("auto", m(loss_pct=5.0)) == "severe"
    assert rate("auto", m(ping_peak=130.0)) == "severe"


def test_a_high_ping_that_was_already_high_before_is_no_rise():
    assert rate("auto", m(ping_before=120.0, ping_peak=130.0)) == "minor"


def test_a_blip_of_two_lost_pings_is_not_called_severe():
    assert rate("auto", m(loss_pct=50.0, duration=2)) == "noticeable"


def test_what_the_user_reported_is_never_minor():
    assert rate("user", m()) == "noticeable"
    assert rate("user", {}) == "noticeable"
    assert rate("user", m(loss_pct=12.0)) == "severe"


def test_an_incident_without_numbers_is_not_rated_instead_of_harmless():
    assert rate("auto", None) is None
    assert rate("auto", {"duration": 0}) is None


def _cgroup(tmp_path, controllers: str | None, files: dict | None = None):
    proc, sys_root = tmp_path / "proc", tmp_path / "sys"
    (proc / "self").mkdir(parents=True)
    (proc / "self/cgroup").write_text("0::/system.slice/network-lag-analyzer.service\n")
    base = sys_root / "fs/cgroup/system.slice/network-lag-analyzer.service"
    base.mkdir(parents=True)
    if controllers is not None:
        (base / "cgroup.controllers").write_text(controllers + "\n")
    for name, text in (files or {}).items():
        (base / name).write_text(text + "\n")
    return pi_health.memory_limit(proc, sys_root)


def test_a_memory_limit_the_kernel_applies_is_reported_with_its_use(tmp_path):
    ml = _cgroup(tmp_path, "cpu memory pids", {"memory.max": str(350 * 1048576), "memory.current": str(210 * 1048576)})
    assert ml == {"controller": True, "limit_mb": 350, "used_mb": 210}


def test_without_the_memory_controller_the_limit_is_not_in_effect_and_that_is_a_finding(tmp_path):
    ml = _cgroup(tmp_path, "cpu pids")
    assert ml == {"controller": False, "limit_mb": None, "used_mb": None}
    level, notes = pi_health.assess({"memory_limit": ml})
    assert level == "warning" and "cgroup_enable=memory" in notes[0]


def test_no_limit_set_is_no_finding_and_no_cgroup_is_not_available(tmp_path):
    ml = _cgroup(tmp_path, "cpu memory", {"memory.max": "max"})
    assert ml["controller"] and ml["limit_mb"] is None
    assert pi_health.assess({"memory_limit": ml}) == ("good", [])
    assert pi_health.memory_limit(tmp_path / "nothing", tmp_path / "nothing") is None
    assert pi_health.assess({"memory_limit": None}) == ("good", [])


def test_the_incident_list_rates_every_incident(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv("NLA_DEV_MODE", "1")
    monkeypatch.setenv("NLA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NLA_CONFIG", str(tmp_path / "none.yaml"))
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core(str(tmp_path / "none.yaml")))) as c:
        c.get("/")                                   # sets the CSRF cookie
        assert c.post("/api/lag-report", json={"window": 30},
                      headers={"X-CSRF-Token": c.cookies.get("nla_csrf")}).status_code == 200
        rows = c.get("/api/incidents").json()["incidents"]
        assert rows and all(r["impact"] in ("severe", "noticeable", "minor", None) for r in rows)
        assert "impact" in c.get(f"/api/incidents/{rows[0]['id']}").json()
