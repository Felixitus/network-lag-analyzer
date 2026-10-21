"""Incremental ingestion of Pi-hole's query log into compact per-device counters.

Every step reads the queries added since the last step (`id > last_id`, the
primary key - cheap even on a 10-million-row log), attributes them to devices and
adds them to hourly and daily counters in our own database. Single queries are
not copied: Pi-hole keeps them for 91 days and stays the source for details.

Crash safety: the counters and `last_id` are written in ONE transaction. A step
whose write fails leaves `last_id` where it was, so the same rows are read again
- nothing is counted twice and nothing is lost across restarts or power cuts.

First start: reads back `backfill_days` (bounded by what FTL still has), in steps
of `batch_rows`, so that FTL and the per-second pipeline are not starved. Pi-hole
takes precedence - the caller only runs the backfill when the load guard allows.

FTL database replaced (`pihole -f`, restore, new install): ids start again at 1.
Detected by MAX(id) < last_id; reading resumes after the newest timestamp already
counted. Queries in that very second may be lost - counting them twice would be
worse.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..collectors.ftl_queries import DnsQuery, FtlQueryLog
from ..database.repository import get_setting, set_setting
from .dns_clients import Attribution, ClientResolver, IpHistory

log = logging.getLogger(__name__)

STATE_KEY = "dns_usage_state"
# Part of the key the activity minutes are built with: bump it when the way they
# are written changes, and existing installations rebuild them on the next start.
MINUTES_FORMAT = 2


def minutes_key(rules_fingerprint: str) -> str:
    return f"{rules_fingerprint}:m{MINUTES_FORMAT}"


def local_day(ts: float) -> int:
    """Unix time of local midnight of the day containing ts (DST-safe)."""
    t = time.localtime(ts)
    return int(time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1)))


@dataclass
class Batch:
    last_id: int
    last_ts: float | None
    rows: int = 0
    more: bool = False
    clients: dict[str, list] = field(default_factory=dict)              # key → [Attribution, first, last]
    hourly: dict[tuple[str, int], list[int]] = field(default_factory=dict)       # (key, hour) → [q, blocked, dup]
    daily: dict[tuple[str, int, str], list] = field(default_factory=dict)       # (key, day, domain) → [q, b, first, last]
    hourly_domains: dict[tuple[str, int, str], list] = field(default_factory=dict)  # (key, hour, domain) → same
    history: list[tuple] = field(default_factory=list)                   # (ip, first, mac, last)
    history_since: float | None = None
    minutes: dict[tuple[str, int, str], list[int]] = field(default_factory=dict)  # (key, minute, service) → [q, b]
    rebuild: dict | None = None          # rebuild state after this batch
    minutes_fp: str | None = None        # rules fingerprint the activity minutes are built with


UPSERT_CLIENT = """
INSERT INTO dns_clients(key, basis, mac, ip, name, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)
ON CONFLICT(key) DO UPDATE SET
    ip = CASE WHEN excluded.last_seen >= dns_clients.last_seen THEN excluded.ip ELSE dns_clients.ip END,
    name = COALESCE(excluded.name, dns_clients.name),
    first_seen = MIN(dns_clients.first_seen, excluded.first_seen),
    last_seen = MAX(dns_clients.last_seen, excluded.last_seen)
"""
UPSERT_HOURLY = """
INSERT INTO dns_client_hourly(ts, client, queries, blocked, duplicates) VALUES (?,?,?,?,?)
ON CONFLICT(client, ts) DO UPDATE SET
    queries = queries + excluded.queries, blocked = blocked + excluded.blocked,
    duplicates = duplicates + excluded.duplicates
"""
UPSERT_DAILY = """
INSERT INTO dns_domain_daily(day, client, domain, queries, blocked, first_ts, last_ts) VALUES (?,?,?,?,?,?,?)
ON CONFLICT(client, day, domain) DO UPDATE SET
    queries = queries + excluded.queries, blocked = blocked + excluded.blocked,
    first_ts = MIN(first_ts, excluded.first_ts), last_ts = MAX(last_ts, excluded.last_ts)
"""
UPSERT_HOURLY_DOMAIN = """
INSERT INTO dns_domain_hourly(ts, client, domain, queries, blocked, first_ts, last_ts) VALUES (?,?,?,?,?,?,?)
ON CONFLICT(client, ts, domain) DO UPDATE SET
    queries = queries + excluded.queries, blocked = blocked + excluded.blocked,
    first_ts = MIN(first_ts, excluded.first_ts), last_ts = MAX(last_ts, excluded.last_ts)
"""
UPSERT_MINUTE = """
INSERT INTO dns_service_minutes(client, ts, service, queries, blocked) VALUES (?,?,?,?,?)
ON CONFLICT(client, ts, service) DO UPDATE SET
    queries = queries + excluded.queries, blocked = blocked + excluded.blocked
"""
UPSERT_HISTORY = """
INSERT INTO dns_ip_history(ip, first_seen, mac, last_seen) VALUES (?,?,?,?)
ON CONFLICT(ip, first_seen) DO UPDATE SET mac = excluded.mac,
    last_seen = MAX(last_seen, excluded.last_seen)
"""


class DnsIngestor:
    def __init__(self, ftl: FtlQueryLog, cfg, own_ips: Iterable[str] = (), hourly_domain_hours: float = 48,
                 classifier: Callable[[], object] | None = None, minute_days: float = 31):
        self.ftl = ftl
        self.cfg = cfg
        self.hourly_domain_hours = hourly_domain_hours
        # Callable, so that a reloaded classifier (rule change) is picked up.
        self.classifier = classifier
        self.minute_days = minute_days
        self.rebuild: dict | None = None      # {"cursor", "from", "to"}: FTL ids still to re-read for minutes
        self.minutes_fp: str | None = None
        self.own_ips = list(own_ips)
        self.last_id: int | None = None
        self.last_ts: float | None = None
        self.history = IpHistory()
        self._addresses: list = []
        # step() runs in a worker thread while API requests build resolvers from
        # the same history and address list in other threads.
        self._lock = threading.Lock()
        self.status: dict = {"enabled": True, "ok": None, "message": "Starting", "backlog": None,
                             "last_id": None, "last_ts": None, "history_since": None}

    # ------------------------------------------------------------------ state
    def load(self, conn) -> None:
        """Restore position and IP history from our database (writer or reader connection)."""
        st = get_setting(conn, STATE_KEY, None) or {}
        self.last_id = st.get("last_id")
        self.last_ts = st.get("last_ts")
        self.rebuild = st.get("rebuild")
        self.minutes_fp = st.get("minutes_fp")
        self.history = IpHistory(since=st.get("history_since"))
        self.history.load(tuple(r) for r in conn.execute(
            "SELECT ip, first_seen, mac, last_seen FROM dns_ip_history"))

    # ------------------------------------------------------------------- read
    def step(self, now: float | None = None, allow_backfill: bool = True) -> Batch:
        """Read and aggregate the next rows. Does not touch our database."""
        now = time.time() if now is None else now
        last_id = self.last_id
        if last_id is None:
            days = self.cfg.backfill_days
            last_id = self.ftl.id_before(now - days * 86400) if days > 0 else self.ftl.max_id()
            log.info("DNS usage: first start, reading from FTL id %s (%g days back)", last_id, days)
        max_id = self.ftl.max_id()
        if max_id < last_id:
            resume = self.ftl.id_before(self.last_ts + 1) if self.last_ts is not None else 0
            log.warning("DNS usage: FTL query ids restarted (max %s < last %s) - FTL database was "
                        "replaced; continuing after the last counted second", max_id, last_id)
            last_id = resume

        if self.history.refreshed_at is None or now - self.history.refreshed_at >= self.cfg.interval:
            addresses = self.ftl.network()
            with self._lock:
                self._addresses = addresses
                changed = self.history.observe(addresses, now)
        else:
            changed = []
        resolver = self.resolver()

        limit = self.cfg.batch_rows if allow_backfill else max(1000, self.cfg.batch_rows // 10)
        rows = self.ftl.read_since(last_id, limit)
        newest = max((q.ts for q in rows), default=None)
        last_ts = self.last_ts if newest is None else max(newest, self.last_ts or newest)
        b = Batch(last_id=rows[-1].id if rows else last_id, last_ts=last_ts,
                  rows=len(rows), more=len(rows) == limit, history=changed,
                  history_since=self.history.since, rebuild=self.rebuild, minutes_fp=self.minutes_fp)
        clf = self.classifier() if self.classifier else None
        cache: dict[tuple, Attribution] = {}
        day_cache: dict[int, int] = {}
        for q in rows:
            att = self._attribute(b, resolver, cache, q)
            hour = int(q.ts) // 3600 * 3600
            h = b.hourly.setdefault((att.key, hour), [0, 0, 0])
            oc = q.outcome
            if oc == "duplicate":
                h[2] += 1
                continue
            h[0] += 1
            blocked = oc == "blocked"
            if blocked:
                h[1] += 1
            if clf is not None:
                self._add_minute(b, clf, att.key, q, blocked)
            # All real time zone offsets are multiples of 15 minutes, so a quarter
            # hour never spans two local days.
            qh = int(q.ts) // 900
            day = day_cache.get(qh)
            if day is None:
                day = day_cache[qh] = local_day(q.ts)
            for acc, k in ((b.daily, (att.key, day, q.domain)), (b.hourly_domains, (att.key, hour, q.domain))):
                d = acc.get(k)
                if d is None:
                    acc[k] = [1, int(blocked), int(q.ts), int(q.ts)]
                else:
                    d[0] += 1
                    d[1] += blocked
                    if q.ts < d[2]:
                        d[2] = int(q.ts)
                    if q.ts > d[3]:
                        d[3] = int(q.ts)
        # The rebuild only runs once the regular log is caught up: new queries first.
        if self.rebuild and clf is not None and allow_backfill and not b.more:
            self._rebuild_step(b, clf, resolver, limit)
        self.status["backlog"] = max(0, max_id - b.last_id)
        return b

    def _attribute(self, b: Batch, resolver: ClientResolver, cache: dict, q: DnsQuery) -> Attribution:
        ck = resolver.cache_key(q.client, q.ts)
        att = cache.get(ck)
        if att is None:
            att = cache[ck] = resolver.resolve(q.client, q.ts)
        c = b.clients.get(att.key)
        if c is None:
            b.clients[att.key] = [att, q.ts, q.ts]
        else:
            if q.ts < c[1]:
                c[1] = q.ts
            if q.ts >= c[2]:
                c[2] = q.ts
                c[0] = att          # most recent IP/name wins
        return att

    @staticmethod
    def _add_minute(b: Batch, clf, key: str, q: DnsQuery, blocked: bool) -> None:
        c = clf.classify(q.domain)
        # Lookups without a service are only ever summed up, never turned into
        # phases - per hour is enough for them. Per minute they were most of the
        # table on the Pi (CDNs, unknown names, devices polling in a loop).
        if c.service:
            k = (key, int(q.ts) // 60 * 60, c.service)
        else:
            k = (key, int(q.ts) // 3600 * 3600, f"~{c.primary}")
        m = b.minutes.get(k)
        if m is None:
            b.minutes[k] = [1, int(blocked)]
        else:
            m[0] += 1
            m[1] += blocked

    # -------------------------------------------------------------- rebuild
    def plan_rebuild(self, fingerprint: str, now: float) -> dict:
        """Activity minutes depend on the category rules. After a rule change the
        retained range is re-read from the Pi-hole log, in the background."""
        if self.last_id is None:
            # Nothing ingested yet: the first backfill builds the minutes anyway.
            return {"rebuild": None, "minutes_fp": fingerprint}
        start = self.ftl.id_before(now - self.minute_days * 86400)
        rb = {"cursor": start, "from": start, "to": self.last_id} if self.last_id > start else None
        return {"rebuild": rb, "minutes_fp": fingerprint}

    def write_rebuild(self, conn, plan: dict) -> None:
        conn.execute("DELETE FROM dns_service_minutes")
        st = get_setting(conn, STATE_KEY, None) or {}
        st.update(plan)
        set_setting(conn, STATE_KEY, st)

    def applied_rebuild(self, plan: dict) -> None:
        self.rebuild = plan["rebuild"]
        self.minutes_fp = plan["minutes_fp"]
        self._rebuild_status()

    def _rebuild_step(self, b: Batch, clf, resolver: ClientResolver, limit: int) -> None:
        rb = dict(self.rebuild)
        rows = [q for q in self.ftl.read_since(rb["cursor"], limit) if q.id <= rb["to"]]
        cache: dict[tuple, Attribution] = {}
        for q in rows:
            att = self._attribute(b, resolver, cache, q)
            oc = q.outcome
            if oc != "duplicate":
                self._add_minute(b, clf, att.key, q, oc == "blocked")
        rb["cursor"] = rows[-1].id if rows else rb["to"]
        b.rebuild = None if rb["cursor"] >= rb["to"] else rb
        b.more = b.more or b.rebuild is not None

    def _rebuild_status(self) -> None:
        rb = self.rebuild
        self.status["rebuild"] = None if not rb else {
            "done": round((rb["cursor"] - rb["from"]) / max(1, rb["to"] - rb["from"]), 3)}

    def resolver(self) -> ClientResolver:
        with self._lock:
            return ClientResolver(list(self._addresses), self.own_ips, self.history)

    # ------------------------------------------------------------- live reads
    def recent(self, n: int = 30) -> list[tuple[DnsQuery, Attribution]]:
        """The newest queries straight from FTL (already written by FTL, so up to ~60 s old)."""
        max_id = self.ftl.max_id()
        rows = self.ftl.read_since(max(0, max_id - n), n)
        r = self.resolver()
        return [(q, r.resolve(q.client, q.ts)) for q in reversed(rows)]

    # ------------------------------------------------------------------ write
    def commit(self, conn, b: Batch, now: float | None = None) -> None:
        """Write a batch and the new position in the caller's transaction.

        Hourly domain rows older than `hourly_domain_hours` are not written at all:
        during the backfill they would be deleted by the next retention run anyway.
        """
        if b.clients:
            conn.executemany(UPSERT_CLIENT, [
                (k, att.basis, att.mac, att.ip, att.name, int(first), int(last))
                for k, (att, first, last) in b.clients.items()])
            keys = list(b.clients)
            ids: dict[str, int] = {}
            for i in range(0, len(keys), 500):
                part = keys[i:i + 500]
                ids.update((r[1], r[0]) for r in conn.execute(
                    f"SELECT id, key FROM dns_clients WHERE key IN ({','.join('?' * len(part))})", part))
            names = list({dom for (_k, _d, dom) in b.daily})
            conn.executemany("INSERT OR IGNORE INTO dns_domains(name) VALUES (?)", [(n,) for n in names])
            dom_ids: dict[str, int] = {}
            for i in range(0, len(names), 500):
                part = names[i:i + 500]
                dom_ids.update((r[1], r[0]) for r in conn.execute(
                    f"SELECT id, name FROM dns_domains WHERE name IN ({','.join('?' * len(part))})", part))
            conn.executemany(UPSERT_HOURLY, [(hour, ids[k], q, bl, dup)
                                             for (k, hour), (q, bl, dup) in b.hourly.items()])
            conn.executemany(UPSERT_DAILY, [(day, ids[k], dom_ids[dom], q, bl, f, la)
                                            for (k, day, dom), (q, bl, f, la) in b.daily.items()])
            cut = (time.time() if now is None else now) - self.hourly_domain_hours * 3600
            conn.executemany(UPSERT_HOURLY_DOMAIN, [(hour, ids[k], dom_ids[dom], q, bl, f, la)
                                                    for (k, hour, dom), (q, bl, f, la) in b.hourly_domains.items()
                                                    if hour + 3600 > cut])
            if b.minutes:
                skeys = list({s for (_k, _m, s) in b.minutes})
                conn.executemany("INSERT OR IGNORE INTO dns_services(key) VALUES (?)", [(s,) for s in skeys])
                sids = {r[1]: r[0] for r in conn.execute(
                    f"SELECT id, key FROM dns_services WHERE key IN ({','.join('?' * len(skeys))})", skeys)}
                mcut = (time.time() if now is None else now) - self.minute_days * 86400
                conn.executemany(UPSERT_MINUTE, [(ids[k], minute, sids[s], q, bl)
                                                 for (k, minute, s), (q, bl) in b.minutes.items()
                                                 if minute + 60 > mcut])
        if b.history:
            conn.executemany(UPSERT_HISTORY, [(ip, int(first), mac, int(last)) for ip, first, mac, last in b.history])
        set_setting(conn, STATE_KEY, {"last_id": b.last_id, "last_ts": b.last_ts,
                                      "history_since": b.history_since, "rebuild": b.rebuild,
                                      "minutes_fp": b.minutes_fp})

    def applied(self, b: Batch) -> None:
        """Called after commit() went through - only then does the position move on."""
        self.last_id = b.last_id
        self.last_ts = b.last_ts
        self.rebuild = b.rebuild
        self._rebuild_status()
        self.status.update(ok=True, message="Reading Pi-hole query log" if b.more else "Up to date",
                           last_id=b.last_id, last_ts=b.last_ts, history_since=b.history_since)


# ---------------------------------------------------------------- maintenance
def fold_completed_days(conn, top_n: int, until_day: int) -> int:
    """Keep the `top_n` busiest domains per device and completed day; sum up the rest
    into domain 0. Totals per day stay exact. Returns the number of folded rows."""
    since = get_setting(conn, "dns_folded_until", 0)
    if until_day <= since:
        return 0
    conn.execute("DROP TABLE IF EXISTS temp._dns_fold")
    conn.execute("""
        CREATE TEMP TABLE _dns_fold AS
        SELECT client, day, domain FROM (
            SELECT client, day, domain, ROW_NUMBER() OVER (
                PARTITION BY client, day ORDER BY queries DESC, domain) AS rn
            FROM dns_domain_daily WHERE day >= ? AND day < ? AND domain != 0)
        WHERE rn > ?""", (since, until_day, top_n))
    conn.execute("""
        INSERT INTO dns_domain_daily(day, client, domain, queries, blocked, first_ts, last_ts)
        SELECT d.day, d.client, 0, SUM(d.queries), SUM(d.blocked), MIN(d.first_ts), MAX(d.last_ts)
        FROM dns_domain_daily d JOIN _dns_fold f ON f.client = d.client AND f.day = d.day AND f.domain = d.domain
        WHERE true GROUP BY d.day, d.client
        ON CONFLICT(client, day, domain) DO UPDATE SET
            queries = queries + excluded.queries, blocked = blocked + excluded.blocked,
            first_ts = MIN(first_ts, excluded.first_ts), last_ts = MAX(last_ts, excluded.last_ts)""")
    n = conn.execute("""DELETE FROM dns_domain_daily
                        WHERE (client, day, domain) IN (SELECT client, day, domain FROM _dns_fold)""").rowcount
    conn.execute("DROP TABLE _dns_fold")
    set_setting(conn, "dns_folded_until", until_day)
    return n


def delete_unused_domains(conn) -> int:
    return conn.execute("DELETE FROM dns_domains WHERE id NOT IN "
                        "(SELECT DISTINCT domain FROM dns_domain_daily)").rowcount
