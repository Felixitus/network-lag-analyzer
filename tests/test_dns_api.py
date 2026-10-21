"""DNS usage API in dev mode: the real ingestion pipeline, fed from the generated demo FTL log.

Own module (and own app instance) because test_api.py deletes all data older than
two minutes on purpose - that would also wipe the DNS counters.
"""
import os
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-dns")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "missing.yaml")
    from backend.api import create_app
    from backend.core import Core
    core = Core()
    with TestClient(create_app(core)) as c:
        c.get("/")   # CSRF cookie
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


def csrf(c):
    return {"X-CSRF-Token": c.cookies.get("nla_csrf")}


def _wait_for_dns_demo(client, timeout=10):
    """Dev mode runs the real ingestion against a generated FTL database."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = client.get("/api/dns/status").json()
        if s.get("ok") and not s.get("backlog"):
            return s
        time.sleep(0.2)
    raise AssertionError(f"demo DNS ingestion did not finish: {s}")


def test_dns_usage_in_dev_mode_runs_on_demo_data_and_says_so(client):
    s = _wait_for_dns_demo(client)
    assert s["demo"] is True and s["data_from"] is not None
    assert "not how long" in s["note"]


def test_dns_overview_has_totals_categories_and_recent_queries(client):
    _wait_for_dns_demo(client)
    o = client.get("/api/dns/overview").json()
    assert o["totals"]["queries"] > 0 and o["totals"]["known_clients"] >= 4
    assert o["domains_resolution"] == "hour"
    cats = {c["category"] for c in o["categories"]}
    assert {"ads_tracking", "other"} <= cats
    assert abs(sum(c["share"] for c in o["categories"]) - 1) < 1e-9
    assert o["recent"] and {"domain", "client", "outcome", "category"} <= set(o["recent"][0])
    week = client.get(f"/api/dns/overview?start={time.time() - 7 * 86400}").json()
    assert week["domains_resolution"] == "day"


def test_dns_client_summary_domains_and_filters(client):
    _wait_for_dns_demo(client)
    cl = client.get("/api/dns/clients").json()["clients"]
    pc = next(c for c in cl if c["mac"] == "02:00:00:00:00:20")
    assert pc["basis"] == "mac" and pc["online"] is True and pc["domains"] > 0
    ip_only = next(c for c in cl if c["ip"] == "192.0.2.99")
    assert ip_only["basis"] == "ip" and ip_only["online"] is None
    s = client.get(f"/api/dns/clients/{pc['id']}/summary").json()
    assert s["totals"]["queries"] == pc["queries"]
    assert s["comparison"] is not None            # demo data covers the previous 24 h too
    # demo data is random: take whichever client had blocked lookups
    blk = max(cl, key=lambda c: c["blocked"])
    d = client.get(f"/api/dns/clients/{blk['id']}/domains?status=blocked").json()
    assert d["total"] > 0 and all(x["blocked"] > 0 for x in d["domains"])
    g = client.get(f"/api/dns/clients/{pc['id']}/domains?category=gaming").json()
    assert all(x["category"] == "gaming" for x in g["domains"])
    some = next(x["domain"] for x in client.get(f"/api/dns/clients/{pc['id']}/domains").json()["domains"]
                if not x["other"])
    part = some.split(".")[-2]
    q = client.get(f"/api/dns/clients/{pc['id']}/domains?q={part.upper()}").json()
    assert q["total"] > 0 and all(part in x["domain"] for x in q["domains"])


def test_dns_alias_comes_from_the_device_list(client):
    _wait_for_dns_demo(client)
    mac = "02:00:00:00:00:33"
    r = client.patch(f"/api/devices/{mac}", json={"custom_name": "=cmd Laptop"}, headers=csrf(client))
    assert r.status_code == 422           # same validation as on the devices page
    assert client.patch(f"/api/devices/{mac}", json={"custom_name": "Work laptop"}, headers=csrf(client)).status_code == 200
    cl = client.get("/api/dns/clients").json()["clients"]
    assert next(c for c in cl if c["mac"] == mac)["name"] == "Work laptop"


def test_manual_category_rule_wins_and_can_be_removed(client):
    assert client.get("/api/dns/classify?domain=api.weather.example").json()["primary"] == "unknown"
    r = client.put("/api/dns/rules/weather.example", json={"categories": ["smart_home"]}, headers=csrf(client))
    assert r.status_code == 200 and r.json()["source"] == "manual"
    c = client.get("/api/dns/classify?domain=api.weather.example").json()
    assert (c["primary"], c["rule"], c["confidence"]) == ("smart_home", "weather.example", "high")
    assert "weather.example" in client.get("/api/dns/rules").json()["overrides"]
    assert client.put("/api/dns/rules/weather.example", json={"categories": ["nope"]}, headers=csrf(client)).status_code == 400
    assert client.put("/api/dns/rules/bad domain", json={"categories": ["gaming"]}, headers=csrf(client)).status_code == 400
    assert client.put("/api/dns/rules/weather.example", json={"categories": ["gaming"]}).status_code == 403   # CSRF
    assert client.delete("/api/dns/rules/weather.example", headers=csrf(client)).status_code == 200
    assert client.get("/api/dns/classify?domain=api.weather.example").json()["primary"] == "unknown"


def test_dns_api_rejects_bad_ranges_and_unknown_clients(client):
    assert client.get("/api/dns/clients?start=200&end=100").status_code == 400
    assert client.get("/api/dns/clients/999999/domains").status_code == 404
    assert client.get("/api/dns/clients/abc/domains").status_code == 422
    assert client.get("/api/dns/clients/1/domains?status=weird").status_code == 422


def test_domain_lists_fall_back_to_days_where_hourly_counters_are_missing(client):
    # An installation that ingested before hourly domain counters existed has none for
    # its past - showing "no domains" there would be wrong.
    _wait_for_dns_demo(client)
    core = client.app.state.core
    core.db.write_sync(lambda c: c.execute("DELETE FROM dns_domain_hourly WHERE ts < ?", (time.time() - 3 * 3600,)))
    from backend.api import dns
    dns._invalidate()
    o = client.get("/api/dns/overview").json()
    assert o["domains_resolution"] == "day" and o["top_domains"]
    assert client.get(f"/api/dns/overview?start={time.time() - 3600}").json()["domains_resolution"] == "hour"


def test_activity_phases_are_estimated_and_labelled_as_such(client):
    _wait_for_dns_demo(client)
    cl = client.get("/api/dns/clients").json()["clients"]
    phone = next(c for c in cl if c["mac"] == "02:00:00:00:00:42")
    r = client.get(f"/api/dns/clients/{phone['id']}/activity?start={time.time() - 3 * 86400}").json()
    assert "not verified" in r["note"] and r["explanation"]
    assert r["services"], "demo phone uses several services"
    for s in r["services"]:
        assert s["confidence"] in (None, "low", "medium")
        assert (s["estimate_seconds"] is None) == (s["confidence"] is None)
        total = sum(p["seconds"] for p in s["phases"])
        if s["estimate_seconds"] is not None:
            assert s["estimate_seconds"] == total
    narrow = client.get(f"/api/dns/clients/{phone['id']}/activity?start={time.time() - 3 * 86400}&gap=1").json()
    assert sum(s["phase_count"] for s in narrow["services"]) >= sum(s["phase_count"] for s in r["services"])


def test_activity_range_is_limited(client):
    cl = client.get("/api/dns/clients").json()["clients"]
    r = client.get(f"/api/dns/clients/{cl[0]['id']}/activity?start={time.time() - 40 * 86400}")
    assert r.status_code == 400 and "limited" in r.json()["detail"]
    assert client.get(f"/api/dns/clients/{cl[0]['id']}/activity?gap=0").status_code == 422
