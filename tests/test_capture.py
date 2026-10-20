"""pcap/pcapng stream parser and packet analysis (traffic per device, retransmissions, game flow)."""
import random
import socket
import struct

from backend.collectors.flows import PacketAnalyzer, seq_after
from backend.collectors.pcapstream import (PcapFormatError, PcapStreamParser, pcap_global_header,
                                           pcap_record)

ROUTER = "02:aa:aa:aa:aa:01"
CLIENT = "02:00:00:00:00:42"
GAMER = "02:00:00:00:00:20"


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def eth_ipv4(src_mac, dst_mac, sip, dip, proto, l4, payload_len=0):
    total = 20 + len(l4) + payload_len
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, socket.inet_aton(sip), socket.inet_aton(dip))
    return mac(dst_mac) + mac(src_mac) + b"\x08\x00" + ip + l4, 14 + total


def tcp(sport, dport, seq, flags=0x18):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0)


def udp(sport, dport, n):
    return struct.pack("!HHHH", sport, dport, 8 + n, 0)


def analyzer(**kw):
    return PacketAnalyzer(local_nets=["192.168.178.0/24"], router_macs=[ROUTER], **kw)


def test_upload_download_attribution_by_mac():
    a = analyzer()
    t = 1_700_000_000.2
    up, olen_up = eth_ipv4(CLIENT, ROUTER, "192.168.178.42", "17.1.2.3", 6, tcp(50000, 443, 1000), 1400)
    down, olen_down = eth_ipv4(ROUTER, CLIENT, "17.1.2.3", "192.168.178.42", 6, tcp(443, 50000, 5000), 1000)
    lan, olen_lan = eth_ipv4(CLIENT, GAMER, "192.168.178.42", "192.168.178.20", 17, udp(1, 2, 100), 100)
    a.process(t, up, olen_up)
    a.process(t, down, olen_down)
    a.process(t, lan, olen_lan)
    b = a.bins[int(t)]
    d = b["dev"][CLIENT]
    assert d[1] == olen_up and d[0] == olen_down       # tx = upload, rx = download
    assert d[5] == olen_lan                            # LAN-internal separately
    assert b["g"]["wan_tx"] == olen_up and b["g"]["wan_rx"] == olen_down
    assert a.macip[CLIENT] == "192.168.178.42"


def test_traffic_to_router_itself_is_not_wan():
    a = analyzer()
    pkt, olen = eth_ipv4(CLIENT, ROUTER, "192.168.178.42", "192.168.178.1", 17, udp(5353, 53, 40), 40)
    a.process(1.0, pkt, olen)
    assert a.bins[1]["g"]["wan_tx"] == 0


def test_tcp_retransmission_detected_per_direction():
    a = analyzer()
    t = 10.0
    for seq in (5000, 6000, 6000, 7000):       # 6000 twice → 1 retransmission
        pkt, olen = eth_ipv4(ROUTER, CLIENT, "17.1.2.3", "192.168.178.42", 6, tcp(443, 50000, seq), 1000)
        a.process(t, pkt, olen)
    g = a.bins[10]["g"]
    assert g["retrans_down"] == 1 and g["retrans_up"] == 0 and g["tcp_segs"] == 4


def test_tcp_keepalive_is_not_retransmission():
    a = analyzer()
    pkt, olen = eth_ipv4(CLIENT, ROUTER, "192.168.178.42", "17.1.2.3", 6, tcp(50000, 443, 1000), 100)
    a.process(1.0, pkt, olen)
    ka, olen2 = eth_ipv4(CLIENT, ROUTER, "192.168.178.42", "17.1.2.3", 6, tcp(50000, 443, 1099), 1)
    a.process(1.2, ka, olen2)
    assert a.bins[1]["g"]["retrans_up"] == 0


def test_seq_wraparound():
    assert seq_after(5, 2**32 - 5)
    assert not seq_after(2**32 - 5, 5)


def test_game_flow_gap_measured_in_bin():
    a = analyzer(gaming_mac=GAMER)
    base = 100.0
    times = [base + i * 0.016 for i in range(30)] + [base + 0.9]   # 0.9 - 0.464 ≈ 436 ms gap
    for ts in times:
        pkt, olen = eth_ipv4(ROUTER, GAMER, "20.33.44.55", "192.168.178.20", 17, udp(3074, 50000, 60), 60)
        a.process(ts, pkt, olen)
        up, olen2 = eth_ipv4(GAMER, ROUTER, "192.168.178.20", "20.33.44.55", 17, udp(50000, 3074, 60), 60)
        a.process(ts, up, olen2)
    [(sec, b)] = a.take_bins(100)
    assert b["g"]["game_pps"] == 62
    assert 430 <= b["g"]["game_gap_ms"] <= 440
    assert b["g"]["game_remote"] == "20.33.44.55:3074"


def test_router_mac_is_learned_when_unknown():
    a = PacketAnalyzer(local_nets=["192.168.178.0/24"])
    for _ in range(60):
        pkt, olen = eth_ipv4(ROUTER, CLIENT, "17.1.2.3", "192.168.178.42", 17, udp(443, 5000, 10), 10)
        a.process(1.0, pkt, olen)
    assert mac(ROUTER) in a.router_macs


def test_sampling_scales_up_at_level_2():
    a = analyzer()
    a.level = 2
    for _ in range(400):
        pkt, olen = eth_ipv4(ROUTER, CLIENT, "17.1.2.3", "192.168.178.42", 17, udp(443, 5000, 100), 100)
        a.process(1.0, pkt, olen)
    assert a.bins[1]["g"]["wan_rx"] == 400 * olen
    [(s, b)] = a.take_bins(1)
    assert b["g"]["sampled"] == 4 and b["g"]["tcp_analysis"] is False


def _records(n):
    out = []
    for i in range(n):
        pkt, olen = eth_ipv4(CLIENT, ROUTER, "192.168.178.42", "17.1.2.3", 17, udp(1000 + i, 53, 20), 20)
        out.append((1_700_000_000 + i * 0.01, pkt, olen))
    return out


def test_pcap_stream_parser_handles_arbitrary_chunking():
    recs = _records(200)
    blob = pcap_global_header(1) + b"".join(pcap_record(t, d, o) for t, d, o in recs)
    got = []
    p = PcapStreamParser(lambda ts, d, o, lt: got.append((round(ts, 3), d, o, lt)))
    rng = random.Random(3)
    i = 0
    while i < len(blob):
        n = rng.randint(1, 700)
        p.feed(blob[i:i + n])
        i += n
    assert len(got) == 200
    assert got[5][1] == recs[5][1] and got[5][3] == 1 and got[5][0] == round(recs[5][0], 3)


def modified_record(ts, data, orig_len, ifindex=2, proto=0x0800, pkt_type=0):
    """Record in the 'modified' format (magic a1b2cd34): 24 byte header instead of 16."""
    sec = int(ts)
    usec = int((ts - sec) * 1e6)
    return struct.pack("<IIIIiHBB", sec, usec, len(data), orig_len, ifindex, proto, pkt_type, 0) + data


def test_modified_pcap_format_of_fritzbox():
    """FRITZ!Box captures come with magic a1b2cd34 and 24-byte record headers."""
    recs = _records(120)
    head = struct.pack("<IHHiIII", 0xA1B2CD34, 2, 4, 0, 0, 128, 1)
    blob = head + b"".join(modified_record(t, d, o) for t, d, o in recs)
    got = []
    p = PcapStreamParser(lambda ts, d, o, lt: got.append((round(ts, 4), d, o, lt)))
    rng = random.Random(7)
    i = 0
    while i < len(blob):
        n = rng.randint(1, 500)
        p.feed(blob[i:i + n])
        i += n
    assert p.format == "pcap-modified" and p.linktype == 1
    assert len(got) == 120
    # The packet data must NOT be shifted by the 8 extra bytes
    assert got[0][1] == recs[0][1] and got[77][1] == recs[77][1]
    assert got[3][0] == round(recs[3][0], 4) and got[3][2] == recs[3][2]


def test_modified_pcap_feeds_analyzer_correctly():
    """End to end: modified format → analyzer assigns bytes to the right device."""
    a = analyzer()
    p = PcapStreamParser(lambda ts, d, o, lt: a.process(ts, d, o, lt))
    up, olen = eth_ipv4(CLIENT, ROUTER, "192.168.178.42", "17.1.2.3", 6, tcp(50000, 443, 1000), 1400)
    blob = struct.pack("<IHHiIII", 0xA1B2CD34, 2, 4, 0, 0, 128, 1)
    for i in range(10):
        blob += modified_record(50.0, up[:128], olen)
    p.feed(blob)
    assert a.bins[50]["dev"][CLIENT][1] == 10 * olen
    assert a.bins[50]["g"]["wan_tx"] == 10 * olen


def test_unknown_magic_names_supported_formats():
    p = PcapStreamParser(lambda *a: None)
    try:
        p.feed(b"\x00\x11\x22\x33" + b"\x00" * 40)
        assert False, "error expected"
    except PcapFormatError as e:
        assert "a1b2cd34" in str(e) and "pcapng" in str(e)


def test_pcap_ring_writes_standard_format(tmp_path):
    """PCAP files written from the 'modified' stream must be standard pcap (Wireshark)."""
    from backend.collectors.traffic import PcapRing
    ring = PcapRing(str(tmp_path / "pcap"), max_files=3, file_size=10_000_000, emit=lambda m: None)
    pkt, olen = eth_ipv4(CLIENT, ROUTER, "192.168.178.42", "17.1.2.3", 6, tcp(50000, 443, 1000), 1400)
    for i in range(5):
        ring.write(1_700_000_000 + i, pkt[:128], olen, 1)
    ring.close()
    data = (tmp_path / "pcap").glob("*.pcap")
    blob = b"".join(f.read_bytes() for f in sorted(data))
    got = []
    PcapStreamParser(lambda ts, d, o, lt: got.append((ts, o))).feed(blob)
    assert blob[:4] == b"\xd4\xc3\xb2\xa1"      # standard magic, not the modified one
    assert len(got) == 5 and got[0][1] == olen


def test_pcapng_stream_parser():
    recs = _records(3)

    def block(btype, body):
        body += b"\x00" * ((4 - len(body) % 4) % 4)
        n = 12 + len(body)
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 256))
    epbs = b""
    for t, d, o in recs:
        us = int(t * 1e6)
        epbs += block(6, struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(d), o) + d)
    got = []
    p = PcapStreamParser(lambda ts, d, o, lt: got.append((ts, d, o)))
    p.feed(shb + idb + epbs[:50])
    p.feed(epbs[50:])
    assert p.format == "pcapng" and len(got) == 3 and got[1][1] == recs[1][1]
    assert abs(got[2][0] - recs[2][0]) < 1e-5
