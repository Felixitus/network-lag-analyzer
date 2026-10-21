"""FTL query log access and IP → device attribution for the DNS usage module."""
import hashlib
import sqlite3
import time
import tracemalloc

import pytest

from backend import dns_mapping_report
from backend.analysis.dns_clients import ClientResolver, summarize
from backend.collectors.ftl_queries import (FtlQueryLog, FtlSchemaError, NetworkAddress, normalize_ip,
                                            normalize_mac, outcome)
from ftl_fake import MAC_A, MAC_B, T0, FakeFtl


@pytest.fixture
def ftl(tmp_path):
    return FakeFtl(tmp_path / "pihole-FTL.db")


def _resolver(log, **kw):
    return ClientResolver(log.network(), **kw)


# --- reading the query log -------------------------------------------------------

def test_normalized_v6_schema_resolves_domain_and_client_through_lookup_tables(ftl):
    log = ftl.add([(T0, "192.0.2.10", "example.com", 2)]).close()
    assert log.schema().normalized
    (q,) = list(log.iter_range(T0 - 1, T0 + 1))
    assert (q.client, q.domain, q.outcome) == ("192.0.2.10", "example.com", "allowed")


def test_legacy_v5_queries_table_is_read_as_well(tmp_path):
    log = FakeFtl(tmp_path / "v5.db", legacy=True).add([(T0, "192.0.2.10", "example.com", 1)]).close()
    assert not log.schema().normalized
    (q,) = list(log.iter_range(T0 - 1, T0 + 1, clients=["192.0.2.10"]))
    assert (q.domain, q.outcome) == ("example.com", "blocked")
    assert [r.id for r in log.read_since(0)] == [q.id]


def test_database_without_query_table_is_rejected_with_a_clear_error(tmp_path):
    p = tmp_path / "other.db"
    sqlite3.connect(p).execute("CREATE TABLE something (x)").connection.commit()
    with pytest.raises(FtlSchemaError, match="not an FTL database"):
        FtlQueryLog(str(p)).schema()


def test_reading_never_modifies_the_pihole_database(ftl):
    log = ftl.add([(T0, "192.0.2.10", "example.com", 2)]).device(MAC_A, ["192.0.2.10"]).close()
    before = hashlib.sha256(open(log.db_path, "rb").read()).hexdigest()
    list(log.iter_range(0, T0 + 10))
    log.read_since(0)
    log.network()
    log.time_range()
    with log.connect() as c, pytest.raises(sqlite3.OperationalError):
        c.execute("DELETE FROM query_storage")
    assert hashlib.sha256(open(log.db_path, "rb").read()).hexdigest() == before


def test_domain_with_invalid_utf8_does_not_abort_the_evaluation(ftl):
    ftl.add([(T0, "192.0.2.10", "a.example", 2), (T0 + 1, "192.0.2.10", "b.example", 2)])
    ftl.c.execute("UPDATE domain_by_id SET domain = CAST(X'C328FF' AS TEXT) WHERE domain = 'a.example'")
    ftl.c.commit()
    log = ftl.close()
    assert [q.domain for q in log.iter_range(T0, T0 + 5)] == ["�(�", "b.example"]


def test_time_range_includes_start_and_excludes_end(ftl):
    log = ftl.add([(T0 - 1, "192.0.2.10", "a.example", 2), (T0, "192.0.2.10", "b.example", 2),
                   (T0 + 10, "192.0.2.10", "c.example", 2)]).close()
    assert [q.domain for q in log.iter_range(T0, T0 + 10)] == ["b.example"]
    assert log.time_range() == (T0 - 1, T0 + 10)


def test_client_filter_includes_all_names_an_ip_had(ftl):
    # FTL creates a new client_by_id row when the host name of an IP changes.
    log = ftl.add([(T0, "192.0.2.10", "a.example", 2, "old-name"), (T0 + 1, "192.0.2.10", "b.example", 2, "new-name"),
                   (T0 + 2, "192.0.2.11", "c.example", 2)]).close()
    assert [q.domain for q in log.iter_range(T0, T0 + 5, clients=["192.0.2.10"])] == ["a.example", "b.example"]


def test_client_filter_with_unknown_ip_yields_nothing(ftl):
    log = ftl.add([(T0, "192.0.2.10", "a.example", 2)]).close()
    assert list(log.iter_range(T0, T0 + 5, clients=["192.0.2.99"])) == []
    assert list(log.iter_range(T0, T0 + 5, clients=[])) == []


def test_ipv6_and_ipv4_mapped_addresses_are_normalized():
    assert normalize_ip("2001:DB8:0:0::1") == "2001:db8::1"
    assert normalize_ip("::ffff:192.0.2.10") == "192.0.2.10"
    assert normalize_ip("fe80::1%eth0") == "fe80::1"
    assert normalize_ip("not-an-ip") == "not-an-ip"
    assert normalize_ip("") is None


def test_ftl_placeholder_hwaddr_is_not_a_mac():
    assert normalize_mac("ip-2001:db8::1") is None
    assert normalize_mac("02:00:00:00:00:0A") == MAC_A


def test_retries_and_in_flight_duplicates_are_their_own_outcome():
    assert [outcome(s) for s in (2, 3, 17, 1, 5, 16, 12, 13, 14, 0, None)] == \
        ["allowed"] * 3 + ["blocked"] * 3 + ["duplicate"] * 3 + ["unknown"] * 2


# --- attribution to devices -------------------------------------------------------

def test_queries_of_several_clients_are_attributed_to_their_macs(ftl):
    log = (ftl.device(MAC_A, ["192.0.2.10"], name="laptop.lan").device(MAC_B, ["192.0.2.11"])
           .add([(T0, "192.0.2.10", "a.example", 2), (T0, "192.0.2.11", "b.example", 2),
                 (T0 + 1, "192.0.2.11", "c.example", 1)]).close())
    s = summarize(log.iter_range(T0, T0 + 5), _resolver(log))
    by = {st.attribution.key: st for st in s["clients"]}
    assert by[f"mac:{MAC_A}"].queries == 1 and by[f"mac:{MAC_A}"].attribution.name == "laptop.lan"
    assert by[f"mac:{MAC_B}"].queries == 2 and by[f"mac:{MAC_B}"].blocked == 1
    assert s["attributable_share"] == 1.0 and s["warnings"] == []


def test_client_without_hostname_is_still_attributed_by_mac(ftl):
    log = ftl.device(MAC_A, ["192.0.2.10"], name=None).add([(T0, "192.0.2.10", "a.example", 2)]).close()
    att = _resolver(log).resolve("192.0.2.10", T0)
    assert (att.basis, att.mac, att.name) == ("mac", MAC_A, None)


def test_device_with_ipv4_and_ipv6_is_one_client(ftl):
    log = (ftl.device(MAC_A, ["192.0.2.10", "2001:db8::10"])
           .add([(T0, "192.0.2.10", "a.example", 2), (T0 + 1, "2001:DB8::10", "b.example", 2)]).close())
    s = summarize(log.iter_range(T0, T0 + 5), _resolver(log))
    (st,) = s["clients"]
    assert st.attribution.key == f"mac:{MAC_A}" and st.ips == {"192.0.2.10", "2001:db8::10"}
    assert s["devices_with_several_ips"] == [f"mac:{MAC_A}"]


def test_ip_without_known_mac_stays_an_ip_only_client(ftl):
    log = ftl.device("ip-2001:db8::20", ["2001:db8::20"]).close()
    att = _resolver(log).resolve("2001:db8::20", T0)
    assert att.basis == "ip" and att.mac is None and "no MAC" in att.reason


def test_ip_missing_from_the_network_table_is_not_guessed(ftl):
    log = ftl.close()
    att = _resolver(log).resolve("192.0.2.77", T0)
    assert att.key == "ip:192.0.2.77" and att.basis == "ip"


def test_query_older_than_the_current_owner_of_the_ip_is_not_given_to_that_device(ftl):
    # The IP changed hands: today's owner appeared after the query was made.
    log = ftl.device(MAC_B, ["192.0.2.10"], first_seen=T0 + 3600).close()
    r = _resolver(log)
    assert r.resolve("192.0.2.10", T0).basis == "ip"
    assert r.resolve("192.0.2.10", T0 + 7200).key == f"mac:{MAC_B}"


def test_changing_ip_owner_splits_queries_of_one_ip_by_time(ftl):
    log = (ftl.device(MAC_B, ["192.0.2.10"], first_seen=T0 + 3600)
           .add([(T0, "192.0.2.10", "old.example", 2), (T0 + 7200, "192.0.2.10", "new.example", 2)]).close())
    s = summarize(log.iter_range(T0, T0 + 9000), _resolver(log))
    by = {st.attribution.key: st.domains for st in s["clients"]}
    assert by == {"ip:192.0.2.10": {"old.example"}, f"mac:{MAC_B}": {"new.example"}}


def test_pi_itself_is_reported_separately_and_not_as_a_device(ftl):
    log = ftl.add([(T0, "127.0.0.1", "a.example", 2), (T0, "192.0.2.55", "b.example", 2),
                   (T0, "192.0.2.10", "c.example", 2)]).device(MAC_A, ["192.0.2.10"]).close()
    s = summarize(log.iter_range(T0, T0 + 5), _resolver(log, own_ips=["192.0.2.55"]))
    assert s["by_basis"] == {"mac": 1, "ip": 0, "local": 2}
    assert {st.attribution.key for st in s["clients"]} == {"local", f"mac:{MAC_A}"}


def test_duplicate_queries_are_not_counted_as_requests(ftl):
    log = ftl.device(MAC_A, ["192.0.2.10"]).add(
        [(T0, "192.0.2.10", "a.example", 2), (T0, "192.0.2.10", "a.example", 14),
         (T0 + 1, "192.0.2.10", "a.example", 12)]).close()
    s = summarize(log.iter_range(T0, T0 + 5), _resolver(log))
    assert s["queries"] == 1 and s["duplicates"] == 2
    assert s["clients"][0].queries == 1 and s["clients"][0].duplicates == 2


def test_everything_from_one_address_is_flagged_as_a_forwarder_problem(ftl):
    log = ftl.add([(T0 + i, "192.0.2.1", f"d{i}.example", 2) for i in range(20)]).close()
    s = summarize(log.iter_range(T0, T0 + 30), _resolver(log))
    assert len(s["warnings"]) == 1 and "single address" in s["warnings"][0]


def test_empty_log_reports_not_available_instead_of_zero_share(ftl):
    log = ftl.close()
    s = summarize(log.iter_range(0, T0), _resolver(log))
    assert s["queries"] == 0 and s["attributable_share"] is None and s["clients"] == []
    assert log.time_range() == (None, None)


def test_large_range_is_streamed_with_bounded_memory(ftl):
    n = 100_000
    ftl.device(MAC_A, ["192.0.2.10"])
    log = ftl.add([(T0 + i, "192.0.2.10", f"d{i % 50}.example", 2) for i in range(n)]).close()
    tracemalloc.start()
    s = summarize(log.iter_range(T0, T0 + n), _resolver(log))
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert s["queries"] == n
    assert peak < 10 * 1024 * 1024


# --- report tool -----------------------------------------------------------------

def test_report_prints_attribution_share(ftl, capsys, monkeypatch):
    now = time.time()
    log = ftl.device(MAC_A, ["192.0.2.10"]).add([(now - 60, "192.0.2.10", "a.example", 2)]).close()
    assert dns_mapping_report.main(["--db", log.db_path, "--hours", "1"]) == 0
    out = capsys.readouterr().out
    assert "attributed to a MAC: 100.0%" in out and MAC_A in out


def test_report_on_missing_database_fails_with_message(tmp_path, capsys):
    assert dns_mapping_report.main(["--db", str(tmp_path / "missing.db")]) == 2
    assert "not readable" in capsys.readouterr().err


def test_network_address_rows_keep_the_device_first_seen(ftl):
    log = ftl.device(MAC_A, ["192.0.2.10"], first_seen=T0, vendor="Example Inc.").close()
    assert log.network() == [NetworkAddress(ip="192.0.2.10", mac=MAC_A, name=None, vendor="Example Inc.",
                                            device_first_seen=T0, ip_last_seen=T0)]
