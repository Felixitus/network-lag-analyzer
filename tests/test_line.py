"""Internet line: DSL values, FRITZ!Box event log, outages from our own pings."""
import os
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.analysis import line
from backend.collectors.fritzbox import FritzClient, FritzError
from backend.database import repository as repo
from backend.database.repository import Database
from test_fritz_tr064 import FAULT_INVALID_ACTION, response


def box(actions: dict, log_xml: str | None = None):
    def handler(request: httpx.Request):
        if request.url.path == "/tr64desc.xml":
            return httpx.Response(404)
        if request.url.path == "/devicelog.lua":
            return httpx.Response(200, content=log_xml or "<DeviceLog/>")
        action = request.headers["SOAPAction"].strip('"').split("#")[1]
        svc = request.headers["SOAPAction"].strip('"').split("#")[0]
        vals = actions.get((svc.split(":")[-2], action))
        if vals is None:
            return httpx.Response(500, content=FAULT_INVALID_ACTION)
        return httpx.Response(200, content=response(action, vals))
    fb = FritzClient("192.0.2.1", "user", "secret")
    fb._http = httpx.Client(transport=httpx.MockTransport(handler))
    return fb


DSL_INFO = {"NewStatus": "Up", "NewDownstreamCurrRate": "54167", "NewUpstreamCurrRate": "21926",
            "NewDownstreamMaxRate": "56064", "NewUpstreamMaxRate": "22797", "NewDownstreamNoiseMargin": "100",
            "NewUpstreamNoiseMargin": "80", "NewDownstreamAttenuation": "240", "NewUpstreamAttenuation": "280"}
DSL_STATS = {"NewCRCErrors": "1438", "NewFECErrors": "3070656", "NewErroredSecs": "313",
             "NewSeverelyErroredSecs": "74", "NewLinkRetrain": "2"}


def test_dsl_values_are_read_in_db_and_kbit():
    fb = box({("WANDSLInterfaceConfig", "GetInfo"): DSL_INFO, ("WANDSLInterfaceConfig", "GetStatisticsTotal"): DSL_STATS})
    d = fb.dsl_info()
    assert (d["down_snr_db"], d["up_atten_db"], d["down_kbit"], d["crc"], d["retrains"]) == (10.0, 28.0, 54167, 1438, 2)


def test_box_without_dsl_says_none_instead_of_zero():
    assert box({}).dsl_info() is None


def test_connection_state_falls_back_from_ip_to_ppp_and_fails_honestly():
    st = {"NewConnectionStatus": "Connected", "NewUptime": "199476", "NewLastConnectionError": "ERROR_NONE"}
    assert box({("WANIPConnection", "GetStatusInfo"): st}).wan_status()["uptime_s"] == 199476   # FRITZ!OS 8
    assert box({("WANPPPConnection", "GetStatusInfo"): st}).wan_status()["status"] == "Connected"
    with pytest.raises(FritzError, match="not available"):
        box({}).wan_status()


def test_event_log_is_read_and_classified():
    xml = ("<DeviceLog><Event><id>1</id><group>net</group><date>25.10.26</date><time>20:17:23</time>"
           "<msg>Internetverbindung wurde erfolgreich erneuert. IP-Adresse: 203.0.113.50</msg></Event>"
           "<Event><id>2</id><group>dsl</group><date>25.10.26</date><time>03:01:00</time>"
           "<msg>DSL antwortet nicht (Keine DSL-Synchronisierung).</msg></Event></DeviceLog>")
    fb = box({("DeviceInfo", "X_AVM-DE_GetDeviceLogPath"): {"NewDeviceLogPath": "/devicelog.lua"}}, xml)
    evs = [line.parse_event(e) for e in fb.device_log()]
    assert [e["kind"] for e in evs] == ["renewed", "dsl_down"]
    assert time.localtime(evs[0]["ts"])[:6] == (2026, 10, 25, 20, 17, 23)


@pytest.mark.parametrize("msg,kind", [
    ("Internetverbindung wurde getrennt.", "disconnected"),
    ("Internetverbindung wurde erfolgreich hergestellt. IP-Adresse: 203.0.113.50", "connected"),
    ("DSL ist verfügbar (DSL-Synchronisierung besteht mit 54167/21926 kbit/s).", "dsl_up"),
    ("FRITZ!OS wurde erfolgreich aktualisiert.", "firmware"),
    ("FRITZ!Box wurde neu gestartet.", "reboot"),
    ("Die WireGuard-Verbindung wurde gestartet.", "other"),          # not a restart of the box
    ("Internet connection established successfully.", "connected"),
])
def test_event_messages_are_classified(msg, kind):
    assert line.classify(msg) == kind


def test_unparseable_log_entries_are_skipped():
    assert line.parse_event({"date": "yesterday", "time": "noon", "msg": "x"}) is None
    assert line.parse_event({"date": "25.10.26", "time": "20:17:23", "msg": " "}) is None


def test_error_counters_become_increases_and_survive_a_resync():
    rows = [{"ts": 0, "crc": 100}, {"ts": 300, "crc": 104}, {"ts": 600, "crc": 3}, {"ts": 900, "crc": None},
            {"ts": 1200, "crc": 5}]
    assert [d["crc"] for d in line.error_deltas(rows, keys=("crc",))] == [None, 4, 3, None, None]


def test_assessment_names_a_low_noise_margin():
    assert line.assess(None) == (None, [])
    assert line.assess({"status": "Up", "down_snr_db": 10.0, "up_snr_db": 8.0})[0] == "good"
    lvl, notes = line.assess({"status": "Up", "down_snr_db": 4.5, "up_snr_db": 8.0})
    assert lvl == "warning" and "4.5 dB" in notes[0]
    assert line.assess({"status": "Up", "down_snr_db": 2.0})[0] == "critical"
    assert line.assess({"status": "Training"})[0] == "critical"


def test_line_values_roundtrip_through_the_database(tmp_path):
    db = Database(str(tmp_path / "x.sqlite3"))
    db.init_sync()
    dsl = {"status": "Up", "down_kbit": 54167, "down_snr_db": 10.0, "up_snr_db": 8.3, "crc": 12}
    db.write_sync(lambda c: c.execute(repo.INSERT_LINE, repo.line_params(1000, dsl, {"status": "Connected", "uptime_s": 5})))
    r = db.read_sync(lambda c: repo.decode_line(c.execute("SELECT * FROM line_stats").fetchone()))
    assert (r["down_snr_db"], r["up_snr_db"], r["down_kbit"], r["crc"], r["dsl_up"], r["wan_connected"]) == (10.0, 8.3, 54167, 12, 1, 1)
    assert r["down_atten_db"] is None and "down_snr" not in r
    db.close()


def _minutes(c, t0, pattern):
    for i, ch in enumerate(pattern):
        if ch == " ":
            continue                        # not measured
        c.execute("INSERT INTO measurements(res, ts, probes, lost) VALUES (60,?,60,?)", (t0 + 60 * i, 60 if ch == "x" else 0))


def test_outages_come_from_minutes_without_any_answer(tmp_path):
    db = Database(str(tmp_path / "x.sqlite3"))
    db.init_sync()
    t0 = 1_792_000_800
    db.write_sync(lambda c: _minutes(c, t0, "..xxx..x.xx xx.."))
    outs = db.read_sync(lambda c: line.outages(c, t0, t0 + 3600))
    # a minute without measurements ends an outage instead of being counted as one
    assert [(o["start"] - t0) // 60 for o in outs] == [2, 7, 9, 12]
    assert [o["minutes"] for o in outs] == [3, 1, 2, 2]
    ev = [{"ts": t0 + 150, "kind": "dsl_down"}, {"ts": t0 + 5000, "kind": "dsl_down"}, {"ts": t0 + 160, "kind": "other"}]
    assert line.match_events(outs[0], ev) == [ev[0]]
    db.close()


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-line")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "missing.yaml")
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core())) as c:
        c.get("/")
        time.sleep(1.0)
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


def test_line_page_api_in_dev_mode(client):
    r = client.get("/api/line?range=24h").json()
    assert r["status"]["has_dsl"] is True and r["status"]["dsl"]["status"] == "Up"
    s = r["series"]
    assert len(s["ts"]) >= 280 and s["crc"][0] is None and all(v is not None and v >= 0 for v in s["crc"][1:])
    week = client.get("/api/line?range=7d").json()["events"]
    assert any(e["kind"] == "dsl_down" for e in week) and all(e["kind"] != "other" for e in week)
    assert any(e["kind"] == "other" for e in client.get("/api/line?range=7d&all_events=true").json()["events"])
    o = client.get("/api/overview").json()
    assert any(l["key"] == "line" and l["level"] == "good" for l in o["lights"])
    assert o["line_events"]


def test_outage_report_is_a_german_excel_csv(client):
    r = client.get("/api/line/outages.csv?days=7")
    assert r.status_code == 200 and r.content.startswith("﻿".encode())
    text = r.content.decode("utf-8-sig")
    assert text.startswith("Outage report;") and "Start;End;Minutes;FRITZ!Box events" in text
