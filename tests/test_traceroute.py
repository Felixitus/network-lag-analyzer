"""Path measurement: matching ICMP answers to our probes, and reading where losses begin."""
import asyncio
import socket
import sqlite3
import struct
import sys

import pytest

from backend.analysis import path
from backend.collectors import traceroute as tr
from backend.collectors.ping import build_echo
from backend.config import RetentionCfg
from backend.database import repository as repo
from backend.database.models import SCHEMA

TARGET = "203.0.113.7"
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="AF_UNIX datagram socketpair, add_reader")


def ip_header(src: str, dst: str, proto: int = 1, ttl: int = 64) -> bytes:
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 0, 0, 0, ttl, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))


def echo_reply(src: str, ident: int, seq: int) -> bytes:
    return ip_header(src, "192.0.2.2") + struct.pack("!BBHHH", 0, 0, 0, ident, seq) + b"NLATRACE"


def time_exceeded(router: str, ident: int, seq: int, typ: int = 11) -> bytes:
    quoted = ip_header("192.0.2.2", TARGET, ttl=1) + build_echo(ident, seq, b"NLATRACE")[:8]
    return ip_header(router, "192.0.2.2") + struct.pack("!BBHI", typ, 0, 0, 0) + quoted


def test_answers_are_matched_by_our_identifier_also_when_a_router_quotes_the_probe():
    assert tr.parse_answer(echo_reply(TARGET, 0x1234, 0x0305)) == (0, 0x1234, 0x0305)
    assert tr.parse_answer(time_exceeded("192.168.178.1", 0x1234, 0x0001)) == (11, 0x1234, 0x0001)
    assert tr.parse_answer(time_exceeded("198.51.100.1", 7, 9, typ=3)) == (3, 7, 9)


def test_foreign_and_cut_icmp_packets_are_ignored():
    udp_quoted = (ip_header("198.51.100.1", "192.0.2.2") + struct.pack("!BBHI", 11, 0, 0, 0)
                  + ip_header("192.0.2.2", TARGET, proto=17) + bytes(8))
    assert tr.parse_answer(udp_quoted) is None                       # a UDP traceroute of another program
    assert tr.parse_answer(time_exceeded("192.0.2.1", 1, 1)[:40]) is None
    redirect = ip_header("192.0.2.1", "192.0.2.2") + struct.pack("!BBHI", 5, 0, 0, 0) + bytes(28)
    assert tr.parse_answer(redirect) is None
    assert tr.parse_answer(b"\x45") is None


class FakeNet:
    """Stands in for the raw socket: hop n answers from 198.51.100.n (hop 1 is the router),
    the target at TTL `depth`. `drop(ttl, round)` decides which answers get lost."""

    def __init__(self, depth=4, drop=lambda ttl, rnd: False):
        self.depth, self.drop = depth, drop
        self.a, self.b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.ttl = 64
        self.sources: list[str] = []

    def setblocking(self, flag):
        self.a.setblocking(flag)

    def fileno(self):
        return self.a.fileno()

    def close(self):
        self.a.close()
        self.b.close()

    def setsockopt(self, level, opt, value):
        if opt == socket.IP_TTL:
            self.ttl = value

    def sendto(self, pkt, addr):
        _t, _c, _cs, ident, seq = struct.unpack_from("!BBHHH", pkt)
        if self.drop(self.ttl, seq >> 8):
            return len(pkt)
        if self.ttl >= self.depth:
            self.sources.append(addr[0])
            self.b.send(echo_reply(addr[0], ident, seq))
        else:
            src = f"198.51.100.{self.ttl}" if self.ttl > 1 else "192.168.178.1"
            self.sources.append(src)
            self.b.send(time_exceeded(src, ident, seq))
        return len(pkt)

    def recvmsg(self, n, anc):
        data, ancdata, flags, _ = self.a.recvmsg(n, anc)
        return data, ancdata, flags, (self.sources.pop(0), 0)


def run_trace(monkeypatch, net, rounds=5):
    monkeypatch.setattr(tr, "open_raw", lambda: net)
    monkeypatch.setattr(tr, "SPACING_S", 0)
    return asyncio.run(tr.Tracer(max_hops=8, rounds=rounds, interval=0.01, timeout=0.05).trace(TARGET))


@POSIX_ONLY
def test_a_trace_stops_at_the_target_and_a_hop_that_only_drops_answers_is_not_blamed(monkeypatch):
    net = FakeNet(depth=4, drop=lambda ttl, rnd: ttl == 2 and rnd % 2 == 0)
    r = run_trace(monkeypatch, net, rounds=4)
    assert r["error"] is None and r["reached"] is True
    assert [h["ttl"] for h in r["hops"]] == [1, 2, 3, 4]
    assert [h["ip"] for h in r["hops"]] == ["192.168.178.1", "198.51.100.2", "198.51.100.3", TARGET]
    assert r["hops"][1]["loss_pct"] == 50.0 and r["hops"][3]["loss_pct"] == 0.0
    a = path.assess(r)
    assert a["verdict"] == "clean"
    assert any(f.startswith("Hop 2 (198.51.100.2") and "traffic passes" in f for f in a["findings"])


@POSIX_ONLY
def test_loss_that_starts_at_a_hop_and_lasts_to_the_target_is_located(monkeypatch):
    net = FakeNet(depth=5, drop=lambda ttl, rnd: ttl >= 3 and rnd in (1, 3))
    a = path.assess(run_trace(monkeypatch, net, rounds=5))
    assert a["verdict"] == "loss"
    assert a["findings"][0].startswith("Losses begin at hop 3 (198.51.100.3, further along the path)")


def test_a_trace_without_raw_socket_says_why_instead_of_measuring_nothing(monkeypatch):
    def denied():
        raise PermissionError(1, "Operation not permitted")
    monkeypatch.setattr(tr, "open_raw", denied)
    r = asyncio.run(tr.Tracer().trace(TARGET))
    assert r["hops"] == [] and "CAP_NET_RAW" in r["error"]
    assert path.assess(r)["verdict"] == "error"
    assert asyncio.run(tr.Tracer().trace("example.com"))["error"] == "not an IPv4 address"


def hop(ttl, ip, loss=0.0, rtt=10.0, sent=10):
    rec = round(sent * (1 - loss / 100))
    return {"ttl": ttl, "ip": ip if rec else None, "sent": sent, "received": rec, "loss_pct": loss,
            "rtt_avg": rtt if rec else None}


def test_segments_come_from_the_address_and_documentation_ranges_are_not_home():
    hops = path.annotate([hop(1, "192.168.178.1"), hop(2, "100.64.0.1"), hop(3, "198.51.100.9"), hop(4, TARGET)])
    assert [h["segment"] for h in hops] == ["home", "provider", "provider", "beyond"]


def test_a_delay_jump_that_stays_is_named_and_a_silent_hop_is_harmless():
    t = {"reached": True, "hops": [hop(1, "192.168.178.1", rtt=1), hop(2, "198.51.100.2", rtt=9), hop(3, None, loss=100),
                                   hop(4, "198.51.100.4", rtt=95), hop(5, TARGET, rtt=97)]}
    a = path.assess(t)
    assert a["verdict"] == "delay"
    assert any("grows by 86 ms at hop 4" in f for f in a["findings"])
    assert any(f.startswith("Hop 3 never answered") for f in a["findings"])


def test_an_unreached_target_names_the_last_hop_that_answered():
    t = {"reached": False, "hops": [hop(1, "192.168.178.1"), hop(2, "198.51.100.2"), hop(3, None, loss=100)]}
    a = path.assess(t)
    assert a["verdict"] == "unreached" and "last hop that answered was hop 2 (198.51.100.2" in a["findings"][0]


def test_the_game_target_and_then_the_worst_internet_target_are_measured():
    targets = [{"target_id": 1, "address": "192.168.178.1", "kind": "gateway"},
               {"target_id": 2, "address": "198.51.100.1", "kind": "internet"},
               {"target_id": 3, "address": "198.51.100.2", "kind": "internet"},
               {"target_id": 4, "address": "203.0.113.9", "kind": "game"}]
    rows = [{"targets": {2: {"lost": 0, "rtt": 20}, 3: {"lost": 2, "rtt": None}, 1: {"lost": 9}}}] * 3
    assert [t["target_id"] for t in path.pick_targets(targets, rows, 2)] == [4, 3]
    assert [t["target_id"] for t in path.pick_targets(targets[:3], [], 2)] == [2, 3]


def test_a_measurement_is_stored_with_its_hops_in_fixed_units_and_expires_with_the_events(tmp_path):
    c = sqlite3.connect(tmp_path / "db.sqlite3")
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    t = {"ts": 1000.0, "address": TARGET, "reached": True, "duration_s": 12.5, "error": None,
         "hops": [{"ttl": 1, "ip": "192.168.178.1", "sent": 10, "received": 10, "rtt_avg": 1.23, "rtt_min": 0.9, "rtt_max": 2.0},
                  {"ttl": 2, "ip": None, "sent": 10, "received": 0, "rtt_avg": None, "rtt_min": None, "rtt_max": None}]}
    tid = repo.save_trace(c, "incident", 2, t)
    assert c.execute("SELECT rtt_avg FROM traceroute_hops WHERE trace_id=? AND ttl=1", (tid,)).fetchone()[0] == 123
    (got,) = repo.load_traces(c, 900, 1100)
    assert got["reached"] is True and got["reason"] == "incident"
    assert got["hops"][0]["rtt_avg"] == 1.23 and got["hops"][1]["ip"] is None and got["hops"][1]["loss_pct"] == 100.0
    assert repo.load_traces(c, 1100, 2000) == []
    repo.apply_retention(c, 1000 + 91 * 86400, RetentionCfg())
    assert c.execute("SELECT COUNT(*) FROM traceroute_hops").fetchone()[0] == 0
    assert c.execute("SELECT COUNT(*) FROM traceroutes").fetchone()[0] == 0
