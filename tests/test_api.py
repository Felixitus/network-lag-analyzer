"""API-Integrationstest im Dev-Modus (simulierte Daten, echte Pipeline, echte SQLite-DB)."""
import os
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "missing.yaml")
    from backend.api import create_app
    from backend.core import Core
    core = Core()
    with TestClient(create_app(core)) as c:
        c.get("/")   # CSRF-Cookie
        time.sleep(1.5)
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


def csrf(c):
    return {"X-CSRF-Token": c.cookies.get("nla_csrf")}


def test_status_and_history(client):
    s = client.get("/api/status").json()
    assert s["dev_mode"] is True and s["last"] is not None
    h = client.get("/api/history?range=5m").json()
    assert h["res"] == 1 and len(h["series"]["ts"]) == 301
    assert sum(v is not None for v in h["series"]["rtt_avg"]) > 200


def test_security_headers_and_csrf(client):
    r = client.get("/api/status")
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert client.post("/api/gaming/start", json={}).status_code == 403
    assert client.post("/api/gaming/start", json={}, headers={"X-CSRF-Token": "falsch"}).status_code == 403


def test_lag_report_creates_incident(client):
    r = client.post("/api/lag-report", json={"window": 30}, headers=csrf(client))
    assert r.status_code == 200
    inc = r.json()
    d = client.get(f"/api/incidents/{inc['id']}").json()
    assert d["source"] == "user" and d["analysis"]["windows"]
    assert client.get("/api/incidents").json()["incidents"][0]["id"] == inc["id"]


def test_devices_and_rename(client):
    devs = client.get("/api/devices").json()["devices"]
    assert any(d["name"] == "iPhone (Demo)" for d in devs)
    mac = next(d["mac"] for d in devs if d["name"] == "iPhone (Demo)")
    r = client.patch(f"/api/devices/{mac}", json={"custom_name": "iPhone Felix"}, headers=csrf(client))
    assert r.status_code == 200 and r.json()["name"] == "iPhone Felix"
    bad = client.patch(f"/api/devices/{mac}", json={"custom_name": "<script>"}, headers=csrf(client))
    assert bad.status_code == 422


def test_settings_validation(client):
    ok = client.put("/api/settings", json={"thresholds": {"ping_warning": 60}}, headers=csrf(client))
    assert ok.status_code == 200 and ok.json()["config"]["thresholds"]["ping_warning"] == 60
    bad = client.put("/api/settings", json={"targets": [{"address": "1.1.1.1;reboot"}]}, headers=csrf(client))
    assert bad.status_code == 422
    forbidden = client.put("/api/settings", json={"security": {"login_enabled": False}}, headers=csrf(client))
    assert forbidden.status_code == 422


def test_gaming_session_roundtrip(client):
    assert client.post("/api/gaming/start", json={}, headers=csrf(client)).status_code == 200
    time.sleep(1.2)
    r = client.post("/api/gaming/stop", headers=csrf(client)).json()
    assert r["summary"]["seconds"] >= 0 and "causes" in r["summary"]


def test_pcap_download_requires_deep_capture(client):
    assert client.get("/api/incidents/1/pcap").status_code == 404


def test_bufferbloat_endpoint(client):
    r = client.get("/api/bufferbloat?range=1h")
    assert r.status_code == 200
    d = r.json()
    assert d["source"] == "live" and d["window_seconds"] == 600
    assert d["capacity"]["down_bps"] and d["summary"]["capacity_known"] is True
    assert set(d["history"]) == {"up", "down"}
    # Längere Zeiträume greifen auf die gespeicherten Fenster zurück – im frischen
    # Testlauf gibt es noch keine, das muss ehrlich gemeldet werden statt geraten.
    long = client.get("/api/bufferbloat?range=30d").json()
    assert long["source"] == "windows"
    assert long["summary"]["up"] is None and long["summary"]["down"] is None
    assert long["summary"]["note"]
    assert client.get("/api/bufferbloat?range=99d").status_code == 422


def test_bufferbloat_window_is_persisted_and_shows_up_in_the_long_range(client):
    """Der Wartungslauf schreibt 10-Minuten-Fenster, damit der Verlauf Wochen übersteht."""
    import asyncio

    from backend.analysis import bufferbloat as bb
    from backend.database import repository as repo

    core = client.app.state.core
    ts = (int(time.time()) - bb.BUCKET) // bb.BUCKET * bb.BUCKET
    cd, cu, _ = core.capacity_info()
    core.hub.ring.clear()
    for i in range(30):                                  # ruhig
        core.hub.ring.append({"ts": ts + i, "rtt_avg": 20.0, "down_bps": 1e6, "up_bps": 0.1e6})
    for i in range(30, 60):                              # Download am Anschlag
        core.hub.ring.append({"ts": ts + i, "rtt_avg": 150.0, "down_bps": cd * 0.95, "up_bps": 0.2e6})
    core._last_bloat = 0
    asyncio.get_event_loop_policy().new_event_loop().run_until_complete(core._bufferbloat_window())
    assert core.db.flush_sync() >= 0
    stored = core.db.read_sync(lambda c: repo.read_bufferbloat(c, ts - 1, ts + 1))
    assert len(stored) == 1 and stored[0]["down_ms"] == 150.0 and stored[0]["idle_ms"] == 20.0
    assert stored[0]["up_ms"] is None

    d = client.get("/api/bufferbloat?range=30d").json()
    assert d["source"] == "windows" and d["summary"]["windows"] == 1
    assert d["summary"]["down"]["delta_ms"] == 130.0
    assert d["history"]["down"][0]["delta_ms"] == 130.0


def test_database_overview_and_delete_by_date(client):
    d = client.get("/api/database").json()
    assert d["size"]["used"] > 0 and d["limit_mb"] == 1024
    names = {t["table"] for t in d["tables"]}
    assert {"measurements", "device_traffic", "ping_samples"} <= names
    assert "daily_stats" not in names, "geschützte Tabellen dürfen nicht zum Löschen angeboten werden"
    assert "daily_stats" in d["protected"]
    assert d["oldest"] is not None

    cut = time.time() - 120
    pre = client.post("/api/database/preview", json={"start": None, "end": cut},
                      headers=csrf(client)).json()
    assert pre["total"] > 0

    # Ohne Bestätigung wird nicht gelöscht
    assert client.post("/api/database/delete", json={"start": None, "end": cut},
                       headers=csrf(client)).status_code == 400

    r = client.post("/api/database/delete", json={"start": None, "end": cut, "confirm": "LOESCHEN"},
                    headers=csrf(client))
    assert r.status_code == 200
    assert r.json()["total"] == pre["total"]
    assert client.post("/api/database/preview", json={"start": None, "end": cut},
                       headers=csrf(client)).json()["total"] == 0

    # Geräte und Einstellungen überleben
    assert client.get("/api/devices").json()["devices"]


def test_database_delete_refuses_protected_tables(client):
    r = client.post("/api/database/delete",
                    json={"start": None, "end": time.time(), "tables": ["devices"], "confirm": "LOESCHEN"},
                    headers=csrf(client))
    assert r.status_code == 422


def test_database_future_end_is_clamped_to_now(client):
    r = client.post("/api/database/delete",
                    json={"start": None, "end": time.time() + 86400, "tables": ["ping_samples"],
                          "confirm": "LOESCHEN"}, headers=csrf(client))
    assert r.status_code == 200 and r.json()["end"] <= time.time() + 1


def test_database_vacuum_and_daily(client):
    assert client.post("/api/database/vacuum", headers=csrf(client)).json()["after"] > 0
    assert "days" in client.get("/api/daily").json()
    sysinfo = client.get("/api/system").json()
    assert "clock_jumps" in sysinfo and "migration" in sysinfo


def test_history_custom_span_and_gaps(client):
    """Zoom per Ziehen: freier Zeitraum, passende Auflösung, ehrliche Lücken."""
    now = int(time.time())
    r = client.get(f"/api/history?start={now - 120}&end={now}").json()
    assert r["range"] == "custom" and r["res"] == 1
    assert r["end"] - r["start"] == 120
    assert len(r["series"]["covered"]) == len(r["series"]["ts"])
    assert any(r["series"]["covered"]), "im Dev-Modus muss gemessen worden sein"

    # Ein Zeitraum, der weit vor dem Start liegt, hat gar keine Daten – und sagt das
    alt = client.get(f"/api/history?start={now - 20000}&end={now - 19000}").json()
    assert not any(alt["series"]["covered"])
    assert all(v is None for v in alt["series"]["rtt_avg"])

    # Große Spannen bekommen eine gröbere Auflösung
    assert client.get(f"/api/history?start={now - 20000}&end={now}").json()["res"] == 10
    assert client.get(f"/api/history?start={now - 200000}&end={now}").json()["res"] == 60
    dev = client.get(f"/api/history/devices?start={now - 120}&end={now}").json()
    assert dev["range"] == "custom" and dev["res"] == 1


def test_pcap_usage_is_visible_and_cleanable(client):
    """Herrenlose Mitschnitte (z. B. nach Abstürzen des Capture-Prozesses) müssen weggehen."""
    import os
    core = client.app.state.core
    d = os.path.join(core.cfg.data_dir, "pcap")
    os.makedirs(d, exist_ok=True)
    for i in range(6):
        with open(os.path.join(d, f"nla-20260101-0000{i}-000.pcap"), "wb") as fh:
            fh.write(b"\xd4\xc3\xb2\xa1" + b"\0" * 200_000)

    info = client.get("/api/database").json()
    assert info["pcap"]["files"] == 6
    assert info["pcap"]["bytes"] > 1_000_000
    assert info["pcap"]["limit_bytes"] == core.cfg.deep_capture.max_total_mb * 1_000_000
    assert info["deep_capture"]["protect_auto"] == "critical"

    r = client.post("/api/database/pcap-cleanup", headers=csrf(client)).json()
    assert r["freed_bytes"] > 1_000_000
    assert r["after"]["files"] == 0
    assert client.get("/api/database").json()["pcap"]["files"] == 0
