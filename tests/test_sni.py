"""TLS server names from the capture, and measured sessions per service."""
import socket
import struct

from backend.analysis import connections
from backend.analysis.categories import BUILTIN_PATH, Classifier
from backend.collectors.flows import PacketAnalyzer
from backend.collectors.tls import TRUNCATED, parse_sni

ROUTER, CLIENT = "02:aa:aa:aa:aa:01", "02:00:00:00:00:42"


def ext(etype, body):
    return struct.pack("!HH", etype, len(body)) + body


def client_hello(name="www.youtube.com", before=3, cipher_suites=16):
    """A ClientHello like a browser sends: GREASE/ALPN/other extensions before the server name."""
    sni = name.encode()
    server_name = ext(0, struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni)
    others = b"".join(ext(0x0a0a + i, b"\0" * 40) for i in range(before))
    exts = others + server_name + ext(16, b"\x00\x03\x02h2")
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x20" + b"\x22" * 32 + struct.pack("!H", cipher_suites * 2)
            + b"\x13\x01" * cipher_suites + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def test_server_name_is_found_behind_other_extensions():
    assert parse_sni(client_hello()) == "www.youtube.com"
    assert parse_sni(client_hello("Example.ORG.")) == "example.org"


def test_cut_off_hello_says_truncated_not_none():
    hello = client_hello(before=6)
    assert parse_sni(hello[:128]) == TRUNCATED          # the default snaplen leaves ~70 bytes of payload
    assert parse_sni(hello[:len(hello) - 10]) in ("www.youtube.com", TRUNCATED)


def test_other_payloads_are_not_server_names():
    assert parse_sni(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None
    assert parse_sni(b"\x17\x03\x03\x00\x10" + b"\0" * 16) is None          # application data, not a hello
    bad = client_hello("evil<script>.example")
    assert parse_sni(bad) is None


def eth_tcp(src, dst, sip, dip, sport, dport, payload):
    t = struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 5 << 4, 0x18, 65535, 0, 0)
    total = 20 + len(t) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0, socket.inet_aton(sip), socket.inet_aton(dip))
    m = lambda s: bytes(int(x, 16) for x in s.split(":"))   # noqa: E731
    return m(dst) + m(src) + b"\x08\x00" + ip + t + payload, 14 + total


def test_capture_takes_the_name_from_the_first_client_packet_only():
    a = PacketAnalyzer(local_nets=["192.0.2.0/24"], router_macs=[ROUTER])
    t = 1_700_000_000.2
    pkt, olen = eth_tcp(CLIENT, ROUTER, "192.0.2.42", "203.0.113.7", 50000, 443, client_hello("i.ytimg.com"))
    a.process(t, pkt, olen)
    later, olen2 = eth_tcp(CLIENT, ROUTER, "192.0.2.42", "203.0.113.7", 50000, 443, client_hello("other.example"))
    a.process(t + 0.1, later, olen2)
    f = next(iter(a.flows.values()))
    assert f.sni == "i.ytimg.com" and a.sni_stats == {"hellos": 1, "named": 1, "truncated": 0}
    assert a.flow_tuple(f)[16] == "i.ytimg.com"
    short = PacketAnalyzer(local_nets=["192.0.2.0/24"], router_macs=[ROUTER])
    short.process(t, pkt[:128], olen)                    # what snaplen 128 leaves
    assert short.sni_stats["truncated"] == 1 and next(iter(short.flows.values())).sni is None


CLF = Classifier.load(builtin=BUILTIN_PATH)


def flow(t0, t1, sni, up=1000, down=9000, proto="tcp", port=443):
    return {"ts_start": t0, "ts_end": t1, "sni": sni, "bytes_up": up, "bytes_down": down, "proto": proto, "remote_port": port}


def test_sessions_merge_connections_closer_than_two_minutes():
    fl = [flow(0, 60, "www.youtube.com"), flow(100, 300, "i.ytimg.com"), flow(1000, 1100, "www.youtube.com"),
          flow(50, 70, "d1.cloudfront.net")]
    s = {x["service"]: x for x in connections.sessions(fl, CLF)}
    yt = s["youtube"]
    assert yt["session_count"] == 2 and yt["seconds"] == 300 + 100 and yt["bytes"] == 3 * 10000
    assert yt["sessions"][0]["connections"] == 2
    cdn = next(x for k, x in s.items() if k.startswith("~"))
    assert cdn["category"] == "infrastructure"                 # a CDN stays a provider, not a service


def test_coverage_names_what_is_not_seen():
    cv = connections.coverage([flow(0, 1, "a.example"), flow(0, 1, None), flow(0, 1, None, proto="udp")])
    assert round(cv["named_share"], 3) == 0.333 and round(cv["quic_share"], 3) == 0.333
    assert connections.coverage([])["named_share"] is None


def test_connections_api_reads_stored_flows(tmp_path, monkeypatch):
    import time
    from fastapi.testclient import TestClient
    monkeypatch.setenv("NLA_DEV_MODE", "1")
    monkeypatch.setenv("NLA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NLA_CONFIG", str(tmp_path / "missing.yaml"))
    from backend.api import create_app
    from backend.core import Core
    from backend.database import repository as repo
    with TestClient(create_app(Core())) as c:
        core = c.app.state.core
        now = time.time()
        rows = [(now - 600, now - 500, "tcp", CLIENT, "192.0.2.42", 50000, "203.0.113.7", 443, 1000, 50000, 10, 40, 0, 0,
                 None, None, "www.netflix.com"),
                (now - 400, now - 300, "udp", CLIENT, "192.0.2.42", 50001, "203.0.113.8", 443, 500, 20000, 5, 20, 0, 0,
                 None, None, None)]
        core.db.write_sync(lambda conn: conn.executemany(repo.INSERT_FLOW, rows))
        r = c.get(f"/api/devices/{CLIENT}/connections").json()
        assert [s["name"] for s in r["services"]] == ["Netflix"] and r["services"][0]["bytes"] == 51000
        assert r["coverage"]["quic_bytes"] == 20500 and "QUIC" in r["note"]
        assert c.get("/api/devices/not-a-mac/connections").status_code == 400
