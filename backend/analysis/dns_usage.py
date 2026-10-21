"""Read side of the DNS usage module: totals, domain lists and category breakdowns.

Resolution is honest about itself: totals and timelines come from hourly counters.
Domain lists come from hourly domain counters while the range lies within their
short retention (48 h by default), otherwise from daily counters that cover whole
local days. Every result says which one.

Category breakdowns use each domain's primary category, so the parts add up to
the total. Domains folded into "other domains" on completed days cannot be
classified any more and are reported as their own bucket, not as "unknown".
"""
from __future__ import annotations

from .categories import Classifier
from .dns_ingest import local_day

NOT_ITEMIZED = "not_itemized"
NOT_ITEMIZED_LABEL = "Not itemized (less frequent domains of completed days)"


def hour_range(start: float, end: float) -> tuple[int, int]:
    return int(start) // 3600 * 3600, -(-int(end) // 3600) * 3600


def day_range(t0: int, t1: int) -> tuple[int, int]:
    return local_day(t0), local_day(t1 - 1)


def totals(conn, t0: int, t1: int, client: int | None = None) -> dict:
    """Queries, blocked, duplicates and active clients. The Pi itself is left out of network totals."""
    if client is None:
        r = conn.execute("""
            SELECT SUM(h.queries) q, SUM(h.blocked) b, SUM(h.duplicates) d, COUNT(DISTINCT h.client) n
            FROM dns_client_hourly h JOIN dns_clients k ON k.id = h.client
            WHERE h.ts >= ? AND h.ts < ? AND k.basis != 'local'""", (t0, t1)).fetchone()
        local = conn.execute("""
            SELECT SUM(h.queries) FROM dns_client_hourly h JOIN dns_clients k ON k.id = h.client
            WHERE h.ts >= ? AND h.ts < ? AND k.basis = 'local'""", (t0, t1)).fetchone()[0]
    else:
        r = conn.execute("""SELECT SUM(queries) q, SUM(blocked) b, SUM(duplicates) d, COUNT(DISTINCT client) n
                            FROM dns_client_hourly WHERE client = ? AND ts >= ? AND ts < ?""",
                         (client, t0, t1)).fetchone()
        local = None
    return {"queries": r["q"] or 0, "blocked": r["b"] or 0, "duplicates": r["d"] or 0,
            "active_clients": r["n"] or 0, "local_queries": local}


def timeline(conn, t0: int, t1: int, client: int | None = None) -> list[dict]:
    if client is None:
        rows = conn.execute("""
            SELECT h.ts, SUM(h.queries) q, SUM(h.blocked) b FROM dns_client_hourly h
            JOIN dns_clients k ON k.id = h.client
            WHERE h.ts >= ? AND h.ts < ? AND k.basis != 'local' GROUP BY h.ts ORDER BY h.ts""", (t0, t1))
    else:
        rows = conn.execute("""SELECT ts, queries q, blocked b FROM dns_client_hourly
                               WHERE client = ? AND ts >= ? AND ts < ? ORDER BY ts""", (client, t0, t1))
    return [{"ts": r["ts"], "queries": r["q"], "blocked": r["b"]} for r in rows]


def coverage(conn) -> tuple[int | None, int | None]:
    r = conn.execute("SELECT MIN(ts), MAX(ts) FROM dns_client_hourly").fetchone()
    return r[0], (r[1] + 3600) if r[1] is not None else None


def known_clients(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM dns_clients WHERE basis != 'local'").fetchone()[0]


def domain_rows(conn, d0: int, d1: int, client: int | None = None) -> list[dict]:
    """Per-domain sums from the daily counters. Domain 0 = folded 'other domains'."""
    if client is None:
        sql = """SELECT x.domain, n.name, SUM(x.queries) q, SUM(x.blocked) b, MIN(x.first_ts) f, MAX(x.last_ts) l
                 FROM dns_domain_daily x JOIN dns_clients k ON k.id = x.client
                 LEFT JOIN dns_domains n ON n.id = x.domain
                 WHERE x.day >= ? AND x.day <= ? AND k.basis != 'local' GROUP BY x.domain"""
        args: tuple = (d0, d1)
    else:
        sql = """SELECT x.domain, n.name, SUM(x.queries) q, SUM(x.blocked) b, MIN(x.first_ts) f, MAX(x.last_ts) l
                 FROM dns_domain_daily x LEFT JOIN dns_domains n ON n.id = x.domain
                 WHERE x.client = ? AND x.day >= ? AND x.day <= ? GROUP BY x.domain"""
        args = (client, d0, d1)
    return [{"name": r["name"] if r["domain"] else None, "queries": r["q"], "blocked": r["b"],
             "first_seen": r["f"], "last_seen": r["l"]} for r in conn.execute(sql, args)]


def hourly_domains_from(conn) -> int | None:
    return conn.execute("SELECT MIN(ts) FROM dns_domain_hourly").fetchone()[0]


def domain_rows_hourly(conn, t0: int, t1: int, client: int | None = None) -> list[dict]:
    """Per-domain sums from the short-term hourly counters."""
    if client is None:
        sql = """SELECT n.name, SUM(x.queries) q, SUM(x.blocked) b, MIN(x.first_ts) f, MAX(x.last_ts) l
                 FROM dns_domain_hourly x JOIN dns_clients k ON k.id = x.client
                 JOIN dns_domains n ON n.id = x.domain
                 WHERE x.ts >= ? AND x.ts < ? AND k.basis != 'local' GROUP BY x.domain"""
        args: tuple = (t0, t1)
    else:
        sql = """SELECT n.name, SUM(x.queries) q, SUM(x.blocked) b, MIN(x.first_ts) f, MAX(x.last_ts) l
                 FROM dns_domain_hourly x JOIN dns_domains n ON n.id = x.domain
                 WHERE x.client = ? AND x.ts >= ? AND x.ts < ? GROUP BY x.domain"""
        args = (client, t0, t1)
    return [{"name": r["name"], "queries": r["q"], "blocked": r["b"], "first_seen": r["f"], "last_seen": r["l"]}
            for r in conn.execute(sql, args)]


def distinct_domains_per_client(conn, d0: int, d1: int) -> dict[int, int]:
    return {r[0]: r[1] for r in conn.execute(
        """SELECT client, COUNT(DISTINCT domain) FROM dns_domain_daily
           WHERE day >= ? AND day <= ? AND domain != 0 GROUP BY client""", (d0, d1))}


def classify_rows(rows: list[dict], clf: Classifier) -> list[dict]:
    for r in rows:
        if r["name"] is None:
            r["category"] = NOT_ITEMIZED
            r["classification"] = None
        else:
            c = clf.classify(r["name"])
            r["category"] = c.primary
            r["classification"] = c.to_dict()
    return rows


def category_breakdown(rows: list[dict], clf: Classifier) -> list[dict]:
    acc: dict[str, list[int]] = {}
    for r in rows:
        a = acc.setdefault(r["category"], [0, 0, 0])
        a[0] += r["queries"]
        a[1] += r["blocked"]
        a[2] += 1 if r["name"] is not None else 0
    total = sum(a[0] for a in acc.values()) or 1
    out = [{"category": cat, "label": NOT_ITEMIZED_LABEL if cat == NOT_ITEMIZED else clf.labels.get(cat, cat),
            "queries": q, "blocked": b, "domains": n, "share": q / total}
           for cat, (q, b, n) in acc.items()]
    out.sort(key=lambda x: -x["queries"])
    return out


def compare(cur: dict, prev: dict) -> dict:
    """Change against the previous period of the same length. None where there is no base."""
    def delta(a, b):
        return None if not b else (a - b) / b
    return {k: {"current": cur.get(k), "previous": prev.get(k), "change": delta(cur.get(k) or 0, prev.get(k))}
            for k in ("queries", "blocked", "domains")}
