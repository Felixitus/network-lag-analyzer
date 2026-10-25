"""The Pi watching itself: sysfs values, port counters, findings, and where LAN losses lie."""
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.analysis import overview as ov
from backend.analysis import pi_health as ph
from backend.config import Config, Thresholds
from backend.database import repository as repo
from backend.database.repository import Database


def fake_sys(root: Path, temp="45123", alarm="0", carrier="1", speed="1000", flaps="3", rx="0"):
    (root / "class/thermal/thermal_zone0").mkdir(parents=True)
    (root / "class/thermal/thermal_zone0/temp").write_text(temp + "\n")
    hw = root / "class/hwmon/hwmon1"
    hw.mkdir(parents=True)
    (hw / "name").write_text("rpi_volt\n")
    (hw / "in0_lcrit_alarm").write_text(alarm + "\n")
    net = root / "class/net/eth0"
    (net / "statistics").mkdir(parents=True)
    for k, v in {"carrier": carrier, "speed": speed, "duplex": "full", "carrier_changes": flaps}.items():
        (net / k).write_text(v + "\n")
    for k, v in {"rx_errors": rx, "tx_errors": "0"}.items():
        (net / "statistics" / k).write_text(v + "\n")
    (root / "block/mmcblk0").mkdir(parents=True)
    (root / "block/mmcblk0/stat").write_text("1 2 3 4 5 6 2048 8 9 10 11\n")
    return root


def test_sysfs_values_are_read(tmp_path):
    s = fake_sys(tmp_path)
    assert ph.temperature(s) == 45.1 and ph.undervoltage(s) is False
    lk = ph.link("eth0", s)
    assert (lk["carrier"], lk["speed_mbit"], lk["carrier_changes"], lk["rx_errors"], lk["rx_crc_errors"]) == (1, 1000, 3, 0, None)
    assert ph.sd_written_bytes(s) == 2048 * 512


def test_missing_sensors_are_not_available_instead_of_zero(tmp_path):
    assert ph.temperature(tmp_path) is None and ph.undervoltage(tmp_path) is None
    assert ph.link("eth0", tmp_path) is None and ph.link(None, tmp_path) is None
    assert ph.sd_written_bytes(tmp_path) is None


def test_port_counters_become_increases_and_restart_after_a_reboot():
    rows = [{"ts": 0, "boot_ts": 100, "rx_errors": 10}, {"ts": 60, "boot_ts": 100, "rx_errors": 14},
            {"ts": 120, "boot_ts": 900, "rx_errors": 2}, {"ts": 180, "boot_ts": 900, "rx_errors": None},
            {"ts": 240, "boot_ts": 900, "rx_errors": 5}]
    assert [d["rx_errors"] for d in ph.deltas(rows, keys=("rx_errors",))] == [None, 4, 2, None, 5]


@pytest.mark.parametrize("h,recent,level,text", [
    ({"temp_c": 50.0}, None, "good", None),
    ({"temp_c": 74.0}, None, "warning", "74 °C"),
    ({"temp_c": 82.0}, None, "critical", "throttled"),
    ({"undervoltage": True}, None, "critical", "Under-voltage"),
    ({"pihole_active": False}, None, "critical", "pihole-FTL"),
    ({"disk_free_mb": 800, "disk_total_mb": 60000}, None, "critical", "0.8 GB free"),
    ({"link": {"iface": "eth0", "carrier": 1, "speed_mbit": 100}}, None, "warning", "100 Mbit/s"),
    ({"link": {"iface": "eth0", "carrier": 0}}, None, "critical", "No network link"),
    ({}, {"rx_errors": 12}, "warning", "12 receive errors"),
    ({}, {"carrier_changes": 2}, "warning", "dropped 2×"),
])
def test_findings(h, recent, level, text):
    lvl, notes = ph.assess(h, recent)
    assert lvl == level
    assert (text is None and not notes) or any(text in n for n in notes)


def test_link_verdict_tells_the_pis_own_cable_from_the_router():
    bad, ok = {"probes": 120, "loss_pct": 12.0}, {"probes": 120, "loss_pct": 0.0}
    assert ph.link_verdict(bad, bad, 1)["where"] == "pi_link"
    assert ph.link_verdict(bad, ok, 1)["where"] == "router"
    assert ph.link_verdict(ok, bad, 1)["where"] == "reference"
    assert ph.link_verdict(ok, ok, 1) == {"where": "ok", "text": None}
    # without a reference there is no guess, only the hint to set one
    v = ph.link_verdict(bad, None, 1)
    assert v["where"] == "unknown" and "second LAN device" in v["text"]
    assert ph.link_verdict(None, bad, 1) is None


def test_lan_reference_must_be_a_private_address():
    assert Config(lan_reference="192.168.68.131").lan_reference == "192.168.68.131"
    assert Config(lan_reference="").lan_reference is None
    with pytest.raises(ValueError):
        Config(lan_reference="8.8.8.8")


def test_health_rows_roundtrip_and_land_in_the_overview_timeline(tmp_path):
    db = Database(str(tmp_path / "x.sqlite3"))
    db.init_sync()
    t0 = 1_792_000_800
    snaps = [{"ts": t0 + 60 * i, "boot_ts": t0 - 1000, "temp_c": 48.5 + i, "cpu_pct": 3.25, "mem_available_mb": 2800,
              "undervoltage": False, "pihole_active": True,
              "link": {"carrier": 1, "speed_mbit": 1000, "carrier_changes": 1, "rx_errors": 364 + (5 if i >= 7 else 0)}}
             for i in range(10)]
    snaps += [{**s, "ts": s["ts"] + 600, "link": {**s["link"], "rx_errors": 369}} for s in snaps]
    db.write_sync(lambda c: c.executemany(repo.INSERT_PI_HEALTH, [repo.pi_health_params(s) for s in snaps]))
    r = db.read_sync(lambda c: repo.decode_pi_health(c.execute("SELECT * FROM pi_health ORDER BY ts").fetchone()))
    assert (r["temp_c"], r["cpu_pct"], r["rx_errors"]) == (48.5, 3.25, 364)
    tl = db.read_sync(lambda c: ov.timeline(c, Thresholds(), None, t0, t0 + 1800, 600))
    pi = next(x for x in tl["rows"] if x["key"] == "pi")["cells"]
    assert pi[0]["level"] == "warning" and "5 receive errors" in pi[0]["text"]
    assert pi[1]["level"] == "good" and pi[2] is None
    db.close()


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-pi")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "missing.yaml")
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core())) as c:
        c.get("/")
        deadline = time.time() + 10
        while not c.app.state.core.pi_health and time.time() < deadline:
            time.sleep(0.2)
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


def test_pi_api_in_dev_mode(client):
    r = client.get("/api/pi").json()
    assert r["health"]["level"] in ("good", "warning", "critical") and r["health"]["disk_free_mb"] > 0
    assert len(r["series"]["ts"]) >= 1 and r["service"]["uptime_s"] >= 0
    assert r["lan_reference"] is None and any(t["kind"] == "gateway" for t in r["link_targets"])


def test_setting_a_lan_reference_adds_a_ping_target(client):
    hdr = {"X-CSRF-Token": client.cookies.get("nla_csrf")}
    assert client.put("/api/settings", json={"lan_reference": "192.0.2.77"}, headers=hdr).status_code == 200
    core = client.app.state.core
    assert any(t["kind"] == "lan" and t["address"] == "192.0.2.77" for t in core.targets.values())
    assert client.put("/api/settings", json={"lan_reference": "8.8.8.8"}, headers=hdr).status_code == 422
    assert client.put("/api/settings", json={"lan_reference": None}, headers=hdr).status_code == 200
    assert not any(t["kind"] == "lan" for t in core.targets.values())


def test_load_guard_survives_a_system_without_load_average(monkeypatch):
    # Windows without performance counters raised here every second and stopped the system loop
    import psutil
    from backend.config import LoadGuardCfg
    from backend.util.loadguard import LoadGuard

    def broken():
        raise RuntimeError("PdhAddEnglishCounterW failed")
    monkeypatch.setattr(psutil, "getloadavg", broken, raising=False)
    assert LoadGuard(LoadGuardCfg()).sample()["load1"] is None
