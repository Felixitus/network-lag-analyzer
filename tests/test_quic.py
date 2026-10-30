"""Server names from QUIC Initial packets (RFC 9001), also when cut off or shuffled."""
import socket
import struct

import pytest

from backend.collectors import quic
from backend.collectors.flows import PacketAnalyzer
from backend.collectors.tls import TRUNCATED

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

ROUTER, CLIENT = "02:aa:aa:aa:aa:01", "02:00:00:00:00:42"
DCID = bytes.fromhex("8394c8f03e515708")          # the connection ID of RFC 9001 appendix A


def handshake(name="www.youtube.com", key_share=1216):
    """A ClientHello as Chrome sends it over QUIC: a big post-quantum key share before the server name."""
    def ext(t, body):
        return struct.pack("!HH", t, len(body)) + body
    sni = name.encode()
    exts = (ext(51, b"\x11" * key_share) + ext(0, struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni)
            + ext(16, b"\x00\x03\x02h3"))
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x06\x13\x01\x13\x02\x13\x03" + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def crypto(off, data):
    return b"\x06" + (0x4000 | off).to_bytes(2, "big") + (0x4000 | len(data)).to_bytes(2, "big") + data


def initial(frames, version=quic.V1, pn=0, dcid=DCID, size=1200):
    """A client Initial packet, encrypted and header-protected like a real client does it."""
    key, iv, hp = quic.client_keys(dcid, version)
    head_len = 1 + 4 + 1 + len(dcid) + 1 + 1 + 2 + 2
    payload = frames + b"\x00" * max(0, size - head_len - len(frames) - 16)
    first = 0xC0 | (quic.VERSIONS[version][2] << 4) | 0x01            # 2-byte packet number
    header = (bytes([first]) + version.to_bytes(4, "big") + bytes([len(dcid)]) + dcid + b"\x00\x00"
              + (0x4000 | (2 + len(payload) + 16)).to_bytes(2, "big") + pn.to_bytes(2, "big"))
    nonce = iv[:10] + bytes(a ^ b for a, b in zip(iv[10:], pn.to_bytes(2, "big")))
    ct = AESGCM(key).encrypt(nonce, payload, header)
    mask = quic.header_mask(hp, ct[2:18])
    prot = bytearray(header)
    prot[0] ^= mask[0] & 0x0F
    prot[-2] ^= mask[1]
    prot[-1] ^= mask[2]
    return bytes(prot) + ct


def test_header_mask_is_the_aes_block_function():
    # RFC 9001 appendix A.2: sample d1b1c98dd7689fb8ec11d242b123dc9b -> mask 437b9aec36
    _key, _iv, hp = quic.client_keys(DCID)
    assert quic.header_mask(hp, bytes.fromhex("d1b1c98dd7689fb8ec11d242b123dc9b"))[:5].hex() == "437b9aec36"


def test_initial_keys_match_rfc_9001():
    key, iv, hp = quic.client_keys(DCID)
    assert key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2"


def test_name_from_one_initial_and_from_quic_v2():
    hs = handshake(key_share=32)
    for v in (quic.V1, quic.V2):
        assert quic.QuicHello().add(initial(crypto(0, hs), version=v)) == "www.youtube.com"


def test_shuffled_fragments_over_two_packets_are_joined():
    hs = handshake()
    p = hs.index(b"youtube")                                           # cut right through the name
    a, b, c = hs[:600], hs[600:p], hs[p:]
    h = quic.QuicHello()
    assert h.add(initial(crypto(p, c) + crypto(0, a))) is None         # name not complete yet: wait
    assert h.add(initial(crypto(600, b), pn=1)) == "www.youtube.com"


def test_name_in_a_fragment_without_its_start_is_found_by_its_lengths():
    hs = handshake()
    pos = hs.index(b"www.youtube.com") - 9
    h = quic.QuicHello()
    assert h.add(initial(crypto(pos - 40, hs[pos - 40:pos + 40]))) == "www.youtube.com"
    assert quic.scan_sni(b"\x00\x00\x00\x14\x00\x12\x00\x00\x10www.youtube.com!") is None   # name length disagrees


def test_cut_off_packets_say_truncated_once_the_handshake_moves_on():
    hs = handshake()
    h = quic.QuicHello()
    assert h.add(initial(crypto(0, hs[:1100]))[:600]) is None          # what snaplen 600 leaves
    assert h.add(initial(crypto(1100, hs[1100:]), pn=1)[:600]) == "www.youtube.com"
    cut = quic.QuicHello()
    assert cut.add(initial(crypto(0, hs))[:600]) is None
    assert cut.add(b"\x40" + b"\x00" * 40) == TRUNCATED                 # a 1-RTT packet: the hello is over


def test_not_quic_is_ignored():
    assert quic.decrypt_initial(b"\x40" + b"\x00" * 60) is None         # short header
    assert quic.decrypt_initial(b"\xc0\xff\x00\x00\x1d" + b"\x00" * 60) is None   # draft version
    assert quic.decrypt_initial(initial(crypto(0, b"x"))[:20]) is None   # too short for the header sample


def eth_udp(payload, sport=50000, dport=443):
    u = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(u)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                     socket.inet_aton("192.0.2.42"), socket.inet_aton("203.0.113.9"))
    m = lambda s: bytes(int(x, 16) for x in s.split(":"))   # noqa: E731
    return m(ROUTER) + m(CLIENT) + b"\x08\x00" + ip + u, 14 + total


def test_capture_names_a_quic_flow_and_counts_it():
    a = PacketAnalyzer(local_nets=["192.0.2.0/24"], router_macs=[ROUTER])
    hs = handshake()
    t = 1_700_000_000.0
    for i, frames in enumerate((crypto(0, hs[:900]), crypto(900, hs[900:]))):
        pkt, olen = eth_udp(initial(frames, pn=i))
        a.process(t + i * 0.01, pkt, olen)
    f = next(iter(a.flows.values()))
    assert f.sni == "www.youtube.com" and f.quic is None
    assert (a.sni_stats["quic"], a.sni_stats["quic_named"]) == (1, 1)
    assert a.flow_tuple(f)[16] == "www.youtube.com"
    other = PacketAnalyzer(local_nets=["192.0.2.0/24"], router_macs=[ROUTER])
    pkt, olen = eth_udp(b"\x40" + b"\x00" * 60)                         # flow seen mid-connection
    other.process(t, pkt, olen)
    g = next(iter(other.flows.values()))
    assert g.sni_done and g.sni is None and other.sni_stats["quic"] == 0


def test_a_name_cut_in_two_far_from_the_start_is_joined_from_its_halves():
    # Chrome cuts at random offsets; with snaplen 600 the start of the hello is often missing
    hs = handshake()
    pos = hs.index(b"youtube")
    h = quic.QuicHello()
    assert h.add(initial(crypto(pos, hs[pos:pos + 60]))) is None
    assert h.add(initial(crypto(pos - 50, hs[pos - 50:pos]), pn=1)) == "www.youtube.com"


def test_flows_without_a_readable_hello_are_counted_by_reason():
    a = PacketAnalyzer(local_nets=["192.0.2.0/24"], router_macs=[ROUTER])
    pkt, olen = eth_udp(b"\x40" + b"\x00" * 60, sport=50001)               # short header: midway
    a.process(1.0, pkt, olen)
    for i in range(quic.MAX_PACKETS + 2):                                   # gQUIC-like long headers
        pkt, olen = eth_udp(b"\xc0Q050" + b"\x00" * 60, sport=50002)
        a.process(2.0 + i, pkt, olen)
    assert a.sni_stats["quic_midway"] == 1 and a.sni_stats["quic_unreadable"] == 1
