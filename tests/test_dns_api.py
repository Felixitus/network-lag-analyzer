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
    # The load guard measures the host, not the app: a busy CI runner reached level 2
    # and paused the demo ingestion for good (it only steps down after 60 s of calm).
    core.loadguard.evaluate = lambda: 0
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


def _csv_rows(text):
    import csv
    import io
    rows = list(csv.reader(io.StringIO(text.lstrip("﻿")), delimiter=";"))
    blank = rows.index([])
    return {r[0]: r[1] for r in rows[:blank] if len(r) > 1}, rows[blank + 1], rows[blank + 2:]


def test_csv_export_has_metadata_and_the_same_rows_as_the_page(client):
    _wait_for_dns_demo(client)
    cl = client.get("/api/dns/clients").json()["clients"]
    pc = next(c for c in cl if c["mac"] == "02:00:00:00:00:20")
    page = client.get(f"/api/dns/clients/{pc['id']}/domains?status=allowed&limit=1000").json()
    r = client.get(f"/api/dns/export?kind=domains&format=csv&client={pc['id']}&status=allowed")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"] and ".csv" in r.headers["content-disposition"]
    meta, header, rows = _csv_rows(r.content.decode("utf-8"))
    assert {"Exported at", "Range from", "Range to", "Client", "Method", "Filter: status"} <= set(meta)
    assert meta["Filter: status"] == "allowed" and "not how long" in meta["Method"]
    assert header[0] == "Domain" and len(rows) == page["total"]
    assert [x[0] for x in rows] == [d["domain"] if not d["other"] else "(other domains, folded)" for d in page["domains"]]


def test_alias_starting_with_a_formula_character_is_neutralized_in_the_export(client):
    _wait_for_dns_demo(client)
    mac = "02:00:00:00:00:51"
    assert client.patch(f"/api/devices/{mac}", json={"custom_name": "+49 TV"}, headers=csrf(client)).status_code == 200
    _meta, header, rows = _csv_rows(client.get("/api/dns/export?kind=clients&format=csv").content.decode("utf-8"))
    names = [r[header.index("Client")] for r in rows]
    assert "'+49 TV" in names and "+49 TV" not in names


def test_xlsx_exports_have_one_sheet_per_table(client):
    import io
    import zipfile
    from xml.etree import ElementTree as ET
    _wait_for_dns_demo(client)
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}

    def sheets(url):
        r = client.get(url)
        assert r.status_code == 200 and r.headers["content-type"].endswith("spreadsheetml.sheet")
        z = zipfile.ZipFile(io.BytesIO(r.content))
        return [s.get("name") for s in ET.fromstring(z.read("xl/workbook.xml")).find("m:sheets", ns)]
    assert sheets("/api/dns/export?kind=network&format=xlsx") == \
        ["About", "Clients", "Categories", "Domains", "Blocked", "Time series"]
    cid = client.get("/api/dns/clients").json()["clients"][0]["id"]
    assert sheets(f"/api/dns/export?kind=client&format=xlsx&client={cid}") == \
        ["About", "Summary", "Categories", "Domains", "Blocked", "Time series", "Activity (estimated)", "Activity phases"]


def test_export_rejects_combinations_that_make_no_sense(client):
    assert client.get("/api/dns/export?kind=network&format=csv").status_code == 400
    assert client.get("/api/dns/export?kind=phases&format=csv").status_code == 400
    assert client.get("/api/dns/export?kind=clients&format=csv&client=1").status_code == 400
    assert client.get("/api/dns/export?kind=nope&format=csv").status_code == 422
    assert client.get("/api/dns/export?kind=clients&format=pdf").status_code == 422


def test_identification_compares_fritzbox_and_pihole_and_finds_the_bypassing_device(client):
    _wait_for_dns_demo(client)
    r = client.get("/api/dns/identification").json()
    assert r["fritz_available"] is True and r["pihole_available"] is True
    by = {x["mac"]: x["status"] for x in r["rows"]}
    assert by["02:00:00:00:00:77"] == "not_using_pihole"            # demo smart speaker
    assert by["02:00:00:00:00:20"] == "consistent"
    assert any("never asked Pi-hole" in f for f in r["findings"])
    assert "Nothing is merged" in r["note"]


def test_client_list_carries_connection_and_sources(client):
    _wait_for_dns_demo(client)
    phone = next(c for c in client.get("/api/dns/clients").json()["clients"] if c["mac"] == "02:00:00:00:00:42")
    assert "simulated" in phone["sources"]
