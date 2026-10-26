"""Presence of devices and the list of new / unnamed devices."""
import asyncio
import os
import time

import pytest
from fastapi.testclient import TestClient

from backend.analysis import presence as pr

A, B, C = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:0c"


def test_periods_open_continue_and_end_at_the_last_minute_seen():
    t = pr.PresenceTracker()
    started, ended, _ = t.step(1000, {1, 2})
    assert sorted(started) == [1, 2] and ended == []
    t.opened(1, 11, 1000)
    t.opened(2, 12, 1000)
    t.step(1060, {1, 2})
    started, ended, _ = t.step(1120, {1})
    assert started == [] and ended == [(12, 2, 1060)]       # ends when last seen, not when noticed
    assert t.open[1]["last"] == 1120


def test_open_periods_survive_a_short_restart_only():
    t = pr.PresenceTracker()
    t.load([(5, 1, 100, 1000), (6, 2, 100, 200)], now=1300)
    assert list(t.open) == [1]


def test_open_periods_are_flushed_every_ten_minutes():
    t = pr.PresenceTracker()
    flushes = [t.step(1000 + 60 * i, set())[2] for i in range(12)]
    assert flushes == [True] + [False] * 9 + [True, False]


def dev(mac, first, name=None, custom=None):
    return {"mac": mac, "first_seen": first, "hostname": name, "custom_name": custom, "name": name or mac}


def test_the_first_hour_is_the_inventory_not_new_devices():
    devs = [dev(A, 1000, "nas"), dev(B, 1000 + 1800, "tv"), dev(C, 1000 + 7200, "phone")]
    assert [d["mac"] for d in pr.new_devices(devs, {}, since=0)] == [C]
    assert pr.new_devices(devs, {C: 9999}, since=0) == []          # marked as known
    assert pr.new_devices(devs, {}, since=1000 + 8000) == []       # outside the span


def test_unknown_devices_have_no_name_from_any_source():
    devs = [dev(A, 0, "nas"), dev(B, 0), dev(C, 0, custom="Printer")]
    assert [d["mac"] for d in pr.unknown_devices(devs, {})] == [B]
    assert pr.unknown_devices(devs, {B: 1}) == []


def test_lanes_are_clipped_to_the_span():
    assert pr.lanes([(1, 0, 500, None), (1, 900, 1200, "dns"), (2, 2000, 3000, None)], 100, 1000) ==         {1: [[100, 500, None], [900, 1000, "dns"]]}


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-presence")
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


def test_presence_api_shows_periods_and_new_devices(client):
    core = client.app.state.core
    hdr = {"X-CSRF-Token": client.cookies.get("nla_csrf")}
    now = time.time()
    # a device that joins two hours after the inventory, without any name
    for m in core.devices.by_mac.values():
        m.first_seen = min(m.first_seen, now - 4 * 3600)
    newcomer = core.devices.observe("02:00:00:00:00:77", ip="192.0.2.77", source="arp", seen=now)
    newcomer.first_seen = now - 600
    fut = asyncio.run_coroutine_threadsafe(core._presence_step(now), core.loop)
    fut.result(5)
    r = client.get("/api/devices/presence").json()
    assert any(l["mac"] == "02:00:00:00:00:77" and l["active"] for l in r["lanes"])
    assert [d["mac"] for d in r["new"]] == ["02:00:00:00:00:77"]
    assert any(d["mac"] == "02:00:00:00:00:77" for d in r["unknown"])
    o = client.get("/api/overview").json()
    light = next(l for l in o["lights"] if l["key"] == "devices")
    assert light["level"] == "warning" and "1 new" in light["detail"]
    assert [d["mac"] for d in o["new_devices"]] == ["02:00:00:00:00:77"]

    assert client.post("/api/devices/known", json={"macs": ["02:00:00:00:00:77"]}, headers=hdr).json()["marked"] == 1
    r = client.get("/api/devices/presence").json()
    assert r["new"] == [] and all(d["mac"] != "02:00:00:00:00:77" for d in r["unknown"])
    assert client.post("/api/devices/known", json={"macs": []}).status_code == 403      # CSRF
