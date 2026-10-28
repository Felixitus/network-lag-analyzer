"""Reply times of Pi-hole's upstream DNS servers, read from its query log."""
from backend.analysis import dns_upstreams as up
from tests.ftl_fake import T0, FakeFtl


def test_reply_times_per_upstream_come_from_the_v6_log_with_server_names(tmp_path):
    rows = [(T0 + i, "9.9.9.10#53", 0.010 + i * 0.0001) for i in range(40)]
    rows += [(T0 + i, "203.0.113.53#53", 0.080) for i in range(30)] + [(T0 + 50, "203.0.113.53#53", None)]
    ftl = FakeFtl(tmp_path / "ftl.db").forwarded(rows)
    ftl.add([(T0 + 5, "192.0.2.10", "cached.example", 3)])          # from the cache: never reached an upstream
    got = ftl.log().forwarded(T0, T0 + 3600)
    assert len(got) == 71 and {g[1] for g in got} == {"9.9.9.10#53", "203.0.113.53#53"}

    r = up.summarize(got, T0, T0 + 3600, now=T0 + 7200)
    quad9, other = r["servers"]
    assert (quad9["upstream"], quad9["name"], quad9["forwarded"]) == ("9.9.9.10", "Quad9 (unfiltered)", 40)
    assert 11 < quad9["median_ms"] < 12.5 and quad9["no_reply"] == 0
    assert (other["upstream"], other["name"], other["median_ms"], other["no_reply"]) == ("203.0.113.53", None, 80.0, 1)
    assert any("203.0.113.53 answers clearly slower than 9.9.9.10" in n for n in r["notes"])


def test_queries_still_waiting_for_their_reply_do_not_count_as_unanswered():
    now = T0 + 1000
    rows = [(now - 30, "192.0.2.53#53", None)] * 30 + [(now - 30, "192.0.2.53#53", 0.02)] * 30
    s = up.summarize(rows, T0, now, now=now)["servers"][0]
    assert s["no_reply"] == 0 and s["no_reply_pct"] is None and s["answered"] == 30


def test_frequent_missing_replies_are_named_without_calling_them_timeouts():
    rows = [(T0 + i, "192.0.2.53#53", None if i % 5 == 0 else 0.02) for i in range(100)]
    r = up.summarize(rows, T0, T0 + 200, now=T0 + 10_000)
    assert r["servers"][0]["no_reply_pct"] == 20.0
    assert any("no reply was recorded" in n and "another one answered first" in n for n in r["notes"])


def test_a_local_resolver_keeps_its_port_and_quantiles_are_nearest_rank():
    assert up.label("127.0.0.1#5335") == ("127.0.0.1#5335", "local resolver (e.g. unbound)")
    assert up.label("2001:4860:4860::8888#53") == ("2001:4860:4860::8888", "Google")
    assert up._q([1.0, 2.0, 3.0, 4.0], 0.5) == 2.0 and up._q([1.0, 2.0, 3.0, 4.0], 0.95) == 4.0


def test_an_old_log_without_reply_times_is_not_available_rather_than_zero(tmp_path):
    ftl = FakeFtl(tmp_path / "v5.db", legacy=True).forwarded([(T0, "192.0.2.53#53", None)])
    assert ftl.log().forwarded(T0 - 10, T0 + 10) is None


def test_no_forwarded_queries_says_so():
    r = up.summarize([], T0, T0 + 3600, now=T0 + 7200)
    assert r["servers"] == [] and "everything came from the cache" in r["notes"][0]
