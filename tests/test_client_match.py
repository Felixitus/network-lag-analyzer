"""FRITZ!Box vs Pi-hole: identification report for the DNS statistics."""
from backend.analysis.client_match import compare
from backend.collectors.fritzbox import HostEntry
from backend.collectors.ftl_queries import NetworkAddress

A, B, C, D = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:0c", "02:00:00:00:00:0d"


def fb(mac, ip, active=True, iface="802.11", name=None):
    return HostEntry(ip=ip, mac=mac.upper(), name=name, active=active, interface=iface)


def ph(mac, ip, name=None):
    return NetworkAddress(ip=ip, mac=mac, name=name, vendor=None, device_first_seen=None, ip_last_seen=None)


def status(res):
    return {r["mac"]: r["status"] for r in res["rows"]}


def test_same_devices_with_same_ips_are_consistent():
    res = compare([fb(A, "192.0.2.10"), fb(B, "192.0.2.11")], [ph(A, "192.0.2.10"), ph(B, "192.0.2.11")])
    assert status(res) == {A: "consistent", B: "consistent"}
    assert res["consistent_share"] == 1.0 and res["findings"] == []


def test_active_device_that_never_asked_pihole_is_reported_as_bypassing_it():
    res = compare([fb(A, "192.0.2.10"), fb(C, "192.0.2.12"), fb(D, "192.0.2.13", active=False)], [ph(A, "192.0.2.10")])
    assert status(res)[C] == "not_using_pihole" and status(res)[D] == "fritz_only_inactive"
    assert any("never asked Pi-hole" in f for f in res["findings"])


def test_one_ip_with_different_devices_is_a_conflict_not_a_guess():
    res = compare([fb(B, "192.0.2.10")], [ph(A, "192.0.2.10"), ph(B, "192.0.2.20")])
    assert status(res)[B] == "ip_conflict" and status(res)[A] == "pihole_only"
    assert any("wrong device" in f for f in res["findings"])


def test_stale_ip_on_one_side_is_a_mismatch():
    res = compare([fb(A, "192.0.2.30")], [ph(A, "192.0.2.10")])
    assert status(res)[A] == "ip_mismatch" and res["consistent_share"] == 0.0


def test_device_with_several_ips_in_pihole_is_consistent_if_one_matches():
    res = compare([fb(A, "192.0.2.10")], [ph(A, "192.0.2.9"), ph(A, "192.0.2.10"), ph(A, "2001:db8::a")])
    assert status(res)[A] == "consistent"


def test_mesh_access_points_hide_wifi_vs_lan():
    res = compare([fb(A, "192.0.2.10", iface="Ethernet"), fb(B, "192.0.2.11", iface="Ethernet")],
                  [ph(A, "192.0.2.10"), ph(B, "192.0.2.11")])
    assert any("mesh access points" in f for f in res["findings"])


def test_router_forwarding_all_dns_is_detected():
    res = compare([], [], gateway_ip="192.0.2.1", queries_by_ip={"192.0.2.1": 900, "192.0.2.10": 100})
    assert any("hides them" in f for f in res["findings"])


def test_randomized_macs_are_marked():
    res = compare([fb("02:aa:bb:cc:dd:ee", "192.0.2.10")], [ph("02:aa:bb:cc:dd:ee", "192.0.2.10")])
    assert res["rows"][0]["randomized"] is True


def test_without_fritzbox_nothing_is_invented():
    res = compare([], [ph(A, "192.0.2.10")])
    assert status(res) == {A: "pihole_only"} and res["consistent_share"] is None
