"""Simulated end-to-end scenarios: raw data → seconds → events → incident → cause."""
import pytest

from backend import simulation as sim


def main_incident(p):
    """The incident covering the scenario time span."""
    cands = [i for i in p.incidents if i.ts_start >= p.scenario_start - 2 and i.category]
    assert cands, f"no incident created; events: {[e.type for e in p.events]}"
    return max(cands, key=lambda i: (i.ts_end or i.ts_start) - i.ts_start)


def test_scenario_1_upload_saturation(pipeline):
    p = pipeline().run("upload_saturation")
    inc = main_incident(p)
    a = inc.analysis
    assert inc.category == "upload"
    assert a["device"]["mac"] == sim.MAC_IPHONE
    assert a["device"]["name"] == "iPhone (Demo)"
    assert inc.confidence == "high"
    assert any("Router latency stayed stable" in e for e in a["evidence"])
    assert any("the latency increase" in e for e in a["evidence"])
    types = {e.type for e in p.events}
    assert {"PING_SPIKE", "HIGH_UPLOAD"} <= types


def test_scenario_2_download_saturation(pipeline):
    p = pipeline().run("download_saturation")
    inc = main_incident(p)
    assert inc.category == "download"
    assert inc.analysis["device"]["mac"] == sim.MAC_TV
    assert inc.confidence in ("high", "medium")


def test_scenario_3_isp_packet_loss(pipeline):
    p = pipeline().run("isp_loss")
    inc = main_incident(p)
    assert inc.category == "wan"
    assert inc.analysis["device"] is None
    assert "PACKET_LOSS" in {e.type for e in p.events}


def test_scenario_4_local_gateway_problem(pipeline):
    p = pipeline().run("local_gateway")
    inc = main_incident(p)
    assert inc.category == "local"
    assert "GATEWAY_LATENCY" in {e.type for e in p.events}


def test_scenario_5_single_target(pipeline):
    p = pipeline().run("single_target")
    inc = main_incident(p)
    assert inc.category == "target"
    assert "Reference 2" in inc.cause or "192.0.2.102" in inc.cause


def test_scenario_6_dns_outage(pipeline):
    p = pipeline().run("dns_outage")
    inc = main_incident(p)
    assert inc.category == "dns"
    assert "Pi-hole" in inc.cause
    assert "DNS_FAILURE" in {e.type for e in p.events}


def test_normal_operation_creates_no_incident(pipeline):
    p = pipeline().run("normal", seconds=300)
    assert p.incidents == []
    assert p.events == []


def test_upload_saturation_without_per_device_traffic_names_no_device(pipeline):
    """Without traffic data no device may be named and no saturation claimed."""
    p = pipeline(cap=(None, None)).run("upload_saturation", traffic=False)
    inc = main_incident(p)
    assert inc.analysis["device"] is None
    assert inc.category != "upload"
    assert any("not available" in n for n in inc.analysis["notes"])


def test_game_server_problem_during_gaming(pipeline):
    p = pipeline(gaming={"server_ip": "203.0.113.77"}).run("game_server", gaming=True, ppt=4)
    inc = main_incident(p)
    assert inc.category == "game_server"
    assert "GAME_FLOW_GAP" in {e.type for e in p.events}


def test_game_gap_without_session_is_not_an_event(pipeline):
    """Without a running gaming session, UDP send pauses must not create game events/incidents."""
    p = pipeline().run("game_server", gaming=True, ppt=1)     # gaming=True: game flow data present
    assert "GAME_FLOW_GAP" not in {e.type for e in p.events}
    assert not [i for i in p.incidents if i.category == "game_server"]


@pytest.mark.parametrize("seed", [2, 3, 4])
def test_upload_saturation_is_stable_across_seeds(pipeline, seed):
    p = pipeline().run("upload_saturation", seed=seed)
    assert main_incident(p).category == "upload"
