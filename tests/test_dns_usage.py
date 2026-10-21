"""DNS usage data model: incremental ingestion of the FTL log into per-device counters."""
import os
import sqlite3
import time

import pytest

from backend.analysis.dns_clients import IpHistory, NOT_COVERED
from backend.analysis.dns_ingest import DnsIngestor, delete_unused_domains, fold_completed_days, local_day
from backend.collectors.ftl_queries import NetworkAddress
from backend.config import DnsUsageCfg, RetentionCfg
from backend.database import repository as repo
from backend.database.models import SCHEMA_VERSION
from backend.database.repository import Database
from ftl_fake import MAC_A, MAC_B, T0, FakeFtl

IP_A = "192.0.2.10"
IP_B = "192.0.2.11"


def cfg(**kw):
    # model_construct: tests use batch sizes below the production minimum.
    return DnsUsageCfg.model_construct(**{"backfill_days": 91, "batch_rows": 1000, "interval": 0, **kw})


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "nla.sqlite3"))
    d.init_sync()
    yield d
    d.close()


@pytest.fixture
def ftl(tmp_path):
    return FakeFtl(tmp_path / "pihole-FTL.db")


def run(ing, db, now, steps=50, allow_backfill=True):
    """Step until caught up, committing like the core loop does."""
    for _ in range(steps):
        b = ing.step(now, allow_backfill)
        db.write_sync(lambda c: ing.commit(c, b))
        ing.applied(b)
        if not b.more:
            return
    raise AssertionError("did not catch up")


def totals(db):
    return db.read_sync(lambda c: {r["key"]: (r["q"], r["b"], r["d"]) for r in c.execute(
        "SELECT k.key, SUM(h.queries) q, SUM(h.blocked) b, SUM(h.duplicates) d "
        "FROM dns_client_hourly h JOIN dns_clients k ON k.id = h.client GROUP BY k.key")})


def domains(db, key):
    return db.read_sync(lambda c: {r["name"]: r["queries"] for r in c.execute(
        "SELECT n.name, SUM(x.queries) queries FROM dns_domain_daily x JOIN dns_clients k ON k.id = x.client "
        "LEFT JOIN dns_domains n ON n.id = x.domain WHERE k.key = ? GROUP BY x.domain", (key,))})


# --- schema --------------------------------------------------------------------

def test_existing_v3_database_gets_the_dns_tables(tmp_path):
    p = str(tmp_path / "old.sqlite3")
    d = Database(p)
    d.init_sync()
    d.close()
    c = sqlite3.connect(p)
    for t in ("dns_clients", "dns_domains", "dns_client_hourly", "dns_domain_daily", "dns_ip_history"):
        c.execute(f"DROP TABLE {t}")
    c.execute("UPDATE meta SET value='3' WHERE key='schema_version'")
    c.commit()
    c.close()
    d = Database(p)
    d.init_sync()
    names = d.read_sync(lambda c: {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")})
    version = d.read_sync(lambda c: c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0])
    d.close()
    assert {"dns_clients", "dns_domain_daily", "dns_ip_history"} <= names
    assert int(version) == SCHEMA_VERSION == 4


# --- ingestion -----------------------------------------------------------------

def test_queries_are_counted_per_device_hour_and_domain(ftl, db):
    ftl.device(MAC_A, [IP_A]).device(MAC_B, [IP_B])
    log = ftl.add([(T0, IP_A, "a.example", 2), (T0 + 1, IP_A, "a.example", 1),
                   (T0 + 3600, IP_A, "b.example", 3), (T0 + 5, IP_B, "c.example", 2)]).log()
    ing = DnsIngestor(log, cfg())
    run(ing, db, T0 + 7200)
    assert totals(db) == {f"mac:{MAC_A}": (3, 1, 0), f"mac:{MAC_B}": (1, 0, 0)}
    assert domains(db, f"mac:{MAC_A}") == {"a.example": 2, "b.example": 1}
    hours = db.read_sync(lambda c: [tuple(r) for r in c.execute(
        "SELECT ts, queries FROM dns_client_hourly h JOIN dns_clients k ON k.id=h.client "
        "WHERE k.key=? ORDER BY ts", (f"mac:{MAC_A}",))])
    assert hours == [(int(T0) // 3600 * 3600, 2), (int(T0 + 3600) // 3600 * 3600, 1)]


def test_duplicates_are_kept_apart_and_not_in_domain_counts(ftl, db):
    log = ftl.device(MAC_A, [IP_A]).add([(T0, IP_A, "a.example", 2), (T0, IP_A, "a.example", 14)]).log()
    ing = DnsIngestor(log, cfg())
    run(ing, db, T0 + 60)
    assert totals(db) == {f"mac:{MAC_A}": (1, 0, 1)}
    assert domains(db, f"mac:{MAC_A}") == {"a.example": 1}


def test_restart_continues_where_it_stopped_without_counting_twice(ftl, db):
    ftl.device(MAC_A, [IP_A]).add([(T0 + i, IP_A, "a.example", 2) for i in range(5)])
    ing = DnsIngestor(ftl.log(), cfg())
    run(ing, db, T0 + 60)
    ftl.add([(T0 + 100 + i, IP_A, "b.example", 2) for i in range(3)])
    again = DnsIngestor(ftl.log(), cfg())
    db.read_sync(again.load)
    run(again, db, T0 + 200)
    assert totals(db) == {f"mac:{MAC_A}": (8, 0, 0)}


def test_failed_write_does_not_move_the_position(ftl, db):
    log = ftl.device(MAC_A, [IP_A]).add([(T0 + i, IP_A, "a.example", 2) for i in range(5)]).log()
    ing = DnsIngestor(log, cfg())
    b = ing.step(T0 + 60)

    def broken(c):
        ing.commit(c, b)
        raise sqlite3.OperationalError("disk I/O error")
    with pytest.raises(sqlite3.OperationalError):
        db.write_sync(broken)
    assert totals(db) == {}
    run(ing, db, T0 + 60)
    assert totals(db) == {f"mac:{MAC_A}": (5, 0, 0)}


def test_first_start_reads_back_only_the_configured_days(ftl, db):
    now = T0 + 10 * 86400
    log = ftl.device(MAC_A, [IP_A]).add([(T0, IP_A, "old.example", 2),
                                         (now - 3600, IP_A, "new.example", 2)]).log()
    ing = DnsIngestor(log, cfg(backfill_days=1))
    run(ing, db, now)
    assert domains(db, f"mac:{MAC_A}") == {"new.example": 1}


def test_without_backfill_only_new_queries_are_read(ftl, db):
    log = ftl.device(MAC_A, [IP_A]).add([(T0, IP_A, "old.example", 2)]).log()
    ing = DnsIngestor(log, cfg(backfill_days=0))
    run(ing, db, T0 + 60)
    ftl.add([(T0 + 61, IP_A, "new.example", 2)])
    run(ing, db, T0 + 120)
    assert domains(db, f"mac:{MAC_A}") == {"new.example": 1}


def test_backfill_runs_in_steps_and_slows_down_under_load(ftl, db):
    log = ftl.device(MAC_A, [IP_A]).add([(T0 + i, IP_A, "a.example", 2) for i in range(2500)]).log()
    ing = DnsIngestor(log, cfg(batch_rows=1000))
    b = ing.step(T0 + 9000)
    assert b.rows == 1000 and b.more
    assert ing.status["backlog"] == 1500
    small = DnsIngestor(log, cfg(batch_rows=20_000)).step(T0 + 9000, allow_backfill=False)
    assert small.rows == 2000 and small.more


def test_replaced_ftl_database_resumes_after_the_last_counted_second(tmp_path, db):
    first = FakeFtl(tmp_path / "ftl1.db").device(MAC_A, [IP_A])
    log = first.add([(T0 + i, IP_A, "a.example", 2) for i in range(10)]).log()
    ing = DnsIngestor(log, cfg())
    run(ing, db, T0 + 60)
    first.close()
    # Restored from an older backup: ids start again, the old rows are there again.
    os.remove(log.db_path)
    again = FakeFtl(log.db_path).device(MAC_A, [IP_A])
    again.add([(T0 + i, IP_A, "a.example", 2) for i in range(5)] + [(T0 + 100, IP_A, "b.example", 2)])
    run(ing, db, T0 + 200)
    assert domains(db, f"mac:{MAC_A}") == {"a.example": 10, "b.example": 1}


def test_device_name_and_latest_ip_are_kept(ftl, db):
    log = ftl.device(MAC_A, [IP_A], name="laptop.lan").add([(T0, IP_A, "a.example", 2)]).log()
    run(DnsIngestor(log, cfg()), db, T0 + 60)
    row = db.read_sync(lambda c: dict(c.execute("SELECT * FROM dns_clients").fetchone()))
    assert (row["key"], row["basis"], row["mac"], row["ip"], row["name"]) == \
        (f"mac:{MAC_A}", "mac", MAC_A, IP_A, "laptop.lan")


# --- IP history ----------------------------------------------------------------

def test_ip_handover_between_known_devices_is_attributed_by_history(ftl, db):
    # Both devices are long known to Pi-hole - FTL alone would give every query
    # of the IP to whoever holds it now.
    ftl.device(MAC_A, [IP_A], last_seen=T0).device(MAC_B, [IP_B], last_seen=T0)
    ftl.add([(T0, IP_A, "a.example", 2)])
    ing = DnsIngestor(ftl.log(), cfg())
    run(ing, db, T0 + 300)
    ftl.move_ip(IP_A, MAC_B, last_seen=T0 + 4000)
    # A late row from device A (FTL writes with delay) arrives after the handover.
    ftl.add([(T0 + 10, IP_A, "late-a.example", 2), (T0 + 4000, IP_A, "b.example", 2)])
    run(ing, db, T0 + 4300)
    assert domains(db, f"mac:{MAC_A}") == {"a.example": 1, "late-a.example": 1}
    assert domains(db, f"mac:{MAC_B}") == {"b.example": 1}
    hist = db.read_sync(lambda c: [tuple(r) for r in c.execute(
        "SELECT ip, mac FROM dns_ip_history WHERE ip=? ORDER BY first_seen", (IP_A,))])
    assert hist == [(IP_A, MAC_A), (IP_A, MAC_B)]


def test_query_in_the_gap_between_two_owners_stays_ip_only():
    h = IpHistory()
    h.observe([NetworkAddress(IP_A, MAC_A, None, None, T0 - 86400, T0)], now=T0)
    h.observe([NetworkAddress(IP_A, MAC_B, None, None, T0 - 86400, T0 + 7200)], now=T0 + 7300)
    assert h.owner(IP_A, T0) == MAC_A
    assert h.owner(IP_A, T0 + 3600) is None            # nobody known to hold it then
    assert h.owner(IP_A, T0 + 7200) == MAC_B
    assert h.owner(IP_A, T0 - 3600) is NOT_COVERED     # before the history started


def test_stale_network_row_is_not_taken_as_a_handover():
    h = IpHistory()
    h.observe([NetworkAddress(IP_A, MAC_A, None, None, None, T0)], now=T0)
    changed = h.observe([NetworkAddress(IP_A, MAC_B, None, None, None, T0 - 600)], now=T0 + 60)
    assert changed == [] and [i[0] for i in h.by_ip[IP_A]] == [MAC_A]


# --- maintenance ---------------------------------------------------------------

def test_folding_keeps_the_busiest_domains_and_the_exact_day_total(ftl, db):
    rows = [(T0 + i, IP_A, f"d{n}.example", 2) for n in range(6) for i in range(n + 1)]
    log = ftl.device(MAC_A, [IP_A]).add(rows).log()
    run(DnsIngestor(log, cfg()), db, T0 + 600)
    n = db.write_sync(lambda c: fold_completed_days(c, 3, local_day(T0) + 2 * 86400))
    assert n == 3
    d = domains(db, f"mac:{MAC_A}")
    assert d == {"d5.example": 6, "d4.example": 5, "d3.example": 4, None: 3 + 2 + 1}
    assert totals(db)[f"mac:{MAC_A}"][0] == sum(d.values())
    assert db.write_sync(delete_unused_domains) == 3
    assert db.write_sync(lambda c: fold_completed_days(c, 3, local_day(T0) + 2 * 86400)) == 0


def test_retention_removes_old_dns_counters(ftl, db):
    log = ftl.device(MAC_A, [IP_A]).add([(T0, IP_A, "a.example", 2)]).log()
    run(DnsIngestor(log, cfg()), db, T0 + 60)
    ret = RetentionCfg(dns_hourly_days=7, dns_domain_days=7)
    out = db.write_sync(lambda c: repo.apply_retention(c, T0 + 8 * 86400, ret))
    assert out["dns_hourly"] == 1 and out["dns_domains"] == 1 and out["dns_ip_history"] == 1
    assert totals(db) == {}


def test_local_day_is_local_midnight():
    t = time.localtime(local_day(T0))
    assert (t.tm_hour, t.tm_min, t.tm_sec) == (0, 0, 0)
    assert 0 <= T0 - local_day(T0) < 25 * 3600
