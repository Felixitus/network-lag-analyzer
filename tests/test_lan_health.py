"""Network health: ARP and DHCP from the capture, Pi-hole's DHCP log, and the verdicts."""
import os
import socket
import struct

from backend.analysis.lan_health import ARP_STORM, LanHealth, overall
from backend.collectors.dhcp_log import DhcpLog, parse_line
from backend.collectors.flows import PacketAnalyzer, mac_bytes

GW, GW_MAC = "192.0.2.1", "02:00:00:00:00:01"
PC, PC_MAC = "192.0.2.20", "02:00:00:00:00:20"
TV_MAC = "02:00:00:00:00:51"
BCAST = b"\xff" * 6
NOW = 1_800_000_000.0


def arp_frame(sender_mac: str, sender_ip: str, target_ip: str, op: int = 1) -> bytes:
    sm = mac_bytes(sender_mac)
    return (BCAST + sm + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, op)
            + sm + socket.inet_aton(sender_ip) + b"\0" * 6 + socket.inet_aton(target_ip))


def dhcp_frame(kind: int, src_mac: str, src_ip: str, client_mac: str, server: str | None = None,
               offered: str = "0.0.0.0", sport: int = 67) -> bytes:
    opts = bytes([53, 1, kind]) + (bytes([54, 4]) + socket.inet_aton(server) if server else b"") + b"\xff"
    bootp = (bytes([2 if sport == 67 else 1, 1, 6, 0]) + b"\0" * 12 + socket.inet_aton(offered) + b"\0" * 8
             + mac_bytes(client_mac) + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63" + opts)
    udp = struct.pack("!HHHH", sport, 68 if sport == 67 else 67, 8 + len(bootp), 0) + bootp
    ip = (struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0)
          + socket.inet_aton(src_ip) + socket.inet_aton("255.255.255.255"))
    return BCAST + mac_bytes(src_mac) + b"\x08\x00" + ip + udp


def capture(*frames: bytes) -> dict:
    an = PacketAnalyzer(local_nets=["192.0.2.0/24"])
    for i, f in enumerate(frames):
        an.process(NOW + i, f, len(f))
    return an.lan.take()


def checks(lh: LanHealth, dhcp_events=None, running=True, error=None, now=NOW + 120) -> dict:
    out = lh.checks(now, gateway=GW, gateway_mac=GW_MAC, router_macs=set(), name=lambda m: m,
                    dhcp_events=dhcp_events, dhcp_since=None, dhcp_error=error, capture_running=running)
    return {c["id"]: c for c in out}


# ---------------------------------------------------------------- capture side
def test_the_capture_reports_who_claims_which_address():
    obs = capture(arp_frame(PC_MAC, PC, GW), arp_frame(GW_MAC, GW, PC, op=2))
    assert sorted((ip, mac) for ip, mac, _ in obs["arp"]) == [(GW, GW_MAC), (PC, PC_MAC)]
    assert obs["arp_n"] == {PC_MAC: 1, GW_MAC: 1}


def test_an_address_probe_is_counted_but_claims_nothing():
    obs = capture(arp_frame(PC_MAC, "0.0.0.0", PC))
    assert obs["arp"] == [] and obs["arp_n"] == {PC_MAC: 1}


def test_dhcp_answers_name_their_server():
    obs = capture(dhcp_frame(2, GW_MAC, GW, PC_MAC, server=GW, offered=PC),
                  dhcp_frame(1, PC_MAC, "0.0.0.0", PC_MAC, sport=68))
    assert [d[1:4] for d in obs["dhcp"]] == [["offer", PC_MAC, GW], ["discover", PC_MAC, None]]
    assert obs["dhcp"][0][6] == PC


def test_a_dhcp_packet_cut_by_the_snaplen_is_skipped_without_error():
    f = dhcp_frame(2, GW_MAC, GW, PC_MAC, server=GW)
    for cut in range(14, len(f)):
        capture(f[:cut])


def test_nothing_seen_means_nothing_to_send():
    assert PacketAnalyzer().lan.take() is None


# ---------------------------------------------------------------- verdicts
def test_without_the_capture_every_capture_check_is_not_measurable():
    c = checks(LanHealth(), running=False)
    for cid in ("dhcp_servers", "ip_conflicts", "gateway", "arp_rate"):
        assert c[cid]["status"] == "na"


def test_a_device_roaming_to_a_repeater_is_no_conflict():
    lh = LanHealth()
    lh.observe({"arp": [[PC, PC_MAC, NOW], [PC, "02:00:00:00:00:99", NOW + 30]]}, NOW)
    assert checks(lh)["ip_conflicts"]["status"] == "ok"


def test_an_address_flipping_between_two_devices_is_a_conflict():
    lh = LanHealth()
    lh.observe({"arp": [[PC, PC_MAC, NOW], [PC, TV_MAC, NOW + 10], [PC, PC_MAC, NOW + 20], [PC, TV_MAC, NOW + 30]]}, NOW)
    c = checks(lh)["ip_conflicts"]
    assert c["status"] == "problem" and PC in c["details"][0]


def test_another_device_answering_for_the_router_is_a_problem():
    lh = LanHealth()
    lh.observe({"arp": [[GW, GW_MAC, NOW], [GW, PC_MAC, NOW + 5]]}, NOW)
    c = checks(lh)
    assert c["gateway"]["status"] == "problem" and PC_MAC in c["gateway"]["details"][0]


def test_only_the_router_answering_for_its_address_is_fine():
    lh = LanHealth()
    lh.observe({"arp": [[GW, GW_MAC, NOW]]}, NOW)
    assert checks(lh)["gateway"]["status"] == "ok"


def test_a_second_dhcp_server_is_a_problem_and_none_seen_is_not_measurable():
    lh = LanHealth()
    lh.observe({"arp": []}, NOW)
    assert checks(lh)["dhcp_servers"]["status"] == "na"
    lh.observe({"dhcp": [[NOW, "offer", PC_MAC, GW, GW_MAC, GW, PC]]}, NOW)
    assert checks(lh)["dhcp_servers"]["status"] == "ok"
    lh.observe({"dhcp": [[NOW, "offer", PC_MAC, "192.0.2.250", TV_MAC, "192.0.2.250", PC]]}, NOW)
    assert checks(lh)["dhcp_servers"]["status"] == "problem"


def test_a_device_scanning_the_network_is_noted_and_a_storm_is_a_problem():
    lh = LanHealth()
    for m in range(5):
        lh.observe({"arp_n": {TV_MAC: 300}}, NOW + m * 60)
    c = checks(lh, now=NOW + 5 * 60)["arp_rate"]
    assert c["status"] == "ok" and TV_MAC in c["details"][0]
    for m in range(5, 9):
        lh.observe({"arp_n": {TV_MAC: ARP_STORM + 1}}, NOW + m * 60)
    assert checks(lh, now=NOW + 9 * 60)["arp_rate"]["status"] == "problem"


def dhcp_events(mac, discover, ack):
    return [(NOW, "discover", mac, None, "")] * discover + [(NOW, "ack", mac, PC, "")] * ack


def test_a_device_that_rarely_gets_an_address_is_worth_a_look():
    c = checks(LanHealth(), dhcp_events(TV_MAC, 142, 9) + dhcp_events(PC_MAC, 2, 2))["dhcp_clients"]
    assert c["status"] == "warning" and "142" in c["details"][0] and len(c["details"]) == 1


def test_normal_address_requests_are_fine():
    assert checks(LanHealth(), dhcp_events(PC_MAC, 12, 12))["dhcp_clients"]["status"] == "ok"


def test_a_refused_address_and_a_full_pool_are_problems():
    ev = [(NOW, "decline", PC_MAC, PC, "")]
    assert checks(LanHealth(), ev)["dhcp_clients"]["status"] == "problem"
    ev = [(NOW, "discover", PC_MAC, None, "no address available")]
    assert checks(LanHealth(), ev)["dhcp_clients"]["status"] == "problem"


def test_no_dhcp_in_pihole_log_is_not_measurable_not_fine():
    assert checks(LanHealth(), [])["dhcp_clients"]["status"] == "na"
    assert checks(LanHealth(), None, error="permission denied")["dhcp_clients"]["status"] == "na"


def test_the_worst_check_decides():
    assert overall([{"status": "na"}, {"status": "ok"}]) == "ok"
    assert overall([{"status": "warning"}, {"status": "problem"}, {"status": "ok"}]) == "problem"
    assert overall([]) == "na"


# ---------------------------------------------------------------- Pi-hole's log
def test_dnsmasq_dhcp_lines_are_read():
    now = 1_793_900_000.0    # early November 2026
    ev = parse_line(b"Nov  5 00:01:41 dnsmasq-dhcp[1398]: DHCPACK(eth0) 192.0.2.56 02:00:00:00:00:56 tv\n", now)
    assert ev[1:4] == ("ack", "02:00:00:00:00:56", "192.0.2.56")
    ev = parse_line(b"Nov  5 02:18:03 dnsmasq-dhcp[1398]: 77 DHCPDISCOVER(eth0) 02:00:00:00:00:56 no address available", now)
    assert ev[1] == "discover" and ev[3] is None and ev[4] == "no address available"
    assert parse_line(b"Nov  5 02:18:03 dnsmasq[1398]: query[A] example.com from 192.0.2.5", now) is None


def test_a_line_from_last_december_is_not_put_into_the_future():
    jan = 1_798_800_000.0    # early January 2027
    ev = parse_line(b"Dec 31 23:59:00 dnsmasq-dhcp[1]: DHCPACK(eth0) 192.0.2.5 02:00:00:00:00:05", jan)
    assert ev[0] < jan


def _line(t: float, kind: str, mac: str) -> bytes:
    import time
    return time.strftime("%b %e %H:%M:%S", time.localtime(t)).encode() + \
        f" dnsmasq-dhcp[1]: DHCP{kind}(eth0) {mac}\n".encode()


def test_the_log_is_read_on_and_survives_its_rotation(tmp_path):
    import time
    now = time.time()
    path = str(tmp_path / "pihole.log")
    with open(path + ".1", "wb") as f:
        f.write(_line(now - 7200, "DISCOVER", PC_MAC))
    with open(path, "wb") as f:
        f.write(_line(now - 60, "DISCOVER", TV_MAC) + b"Nov  5 00:00:00 dnsmasq-dhcp[1]: DHCPACK(eth0) 192.0")
    dl = DhcpLog(path)
    assert dl.poll(now) == 2 and dl.error is None
    with open(path, "ab") as f:                     # the half line is completed
        f.write(b".2.5 " + PC_MAC.encode() + b"\n")
    assert dl.poll(now) == 1
    with open(path, "ab") as f:                     # written just before midnight ...
        f.write(_line(now - 30, "REQUEST", TV_MAC))
    os.replace(path, path + ".1")                    # ... then rotated
    with open(path, "wb") as f:
        f.write(_line(now - 10, "ACK", TV_MAC))
    assert dl.poll(now) == 2
    assert [e[1] for e in dl.events][-2:] == ["request", "ack"]


def test_an_unreadable_log_says_why(tmp_path):
    dl = DhcpLog(str(tmp_path / "missing.log"))
    assert dl.poll() == 0 and "missing.log" in dl.error


def test_the_devices_page_gets_every_check_with_a_status(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv("NLA_DEV_MODE", "1")
    monkeypatch.setenv("NLA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NLA_CONFIG", str(tmp_path / "none.yaml"))
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core(str(tmp_path / "none.yaml")))) as c:
        r = c.get("/api/devices/network-health").json()
    assert {x["id"] for x in r["checks"]} == {"dhcp_clients", "dhcp_servers", "ip_conflicts", "gateway", "arp_rate"}
    assert all(x["status"] in ("ok", "warning", "problem", "na") for x in r["checks"])
    # the demo TV asks often and rarely gets an address
    assert next(x for x in r["checks"] if x["id"] == "dhcp_clients")["status"] == "warning"
