"""Categories per device: how a device's lookups split into categories, in which hours, and
where the activity estimate allows a number - how much estimated activity that was.

Three different things, kept apart on purpose:

* lookups and their share - counted exactly from the Pi-hole log;
* active hours - clock hours with at least one allowed lookup of the category, also exact,
  from the activity minutes (31 days);
* estimated activity - only the sum of the per-service estimates of analysis/activity.py,
  where that estimate gives a number at all. Categories without services (the UT1 ones:
  adult, gambling, dating, ...) never get one: their lookups are only kept per hour, and an
  hour with one lookup is no hour of use.

None of it is usage time.
"""
from __future__ import annotations

from collections import defaultdict

from .activity import BACKGROUND_CATEGORIES

CONFIDENCE_ORDER = ("high", "medium", "low")


def client_domain_rows(conn, t0: int, t1: int, d0: int, d1: int, hourly: bool) -> list[tuple[int, str | None, int, int]]:
    """(client, domain name, queries, blocked) for every client except the Pi itself."""
    if hourly:
        sql = """SELECT x.client, n.name, SUM(x.queries), SUM(x.blocked)
                 FROM dns_domain_hourly x JOIN dns_clients k ON k.id = x.client
                 JOIN dns_domains n ON n.id = x.domain
                 WHERE x.ts >= ? AND x.ts < ? AND k.basis != 'local' GROUP BY x.client, x.domain"""
        args: tuple = (t0, t1)
    else:
        sql = """SELECT x.client, CASE WHEN x.domain = 0 THEN NULL ELSE n.name END, SUM(x.queries), SUM(x.blocked)
                 FROM dns_domain_daily x JOIN dns_clients k ON k.id = x.client
                 LEFT JOIN dns_domains n ON n.id = x.domain
                 WHERE x.day >= ? AND x.day <= ? AND k.basis != 'local' GROUP BY x.client, x.domain"""
        args = (d0, d1)
    return [tuple(r) for r in conn.execute(sql, args)]


def matrix(rows: list[tuple[int, str | None, int, int]], classifier) -> dict[int, dict]:
    """Per client: total lookups and lookups per primary category ("not_itemized" for folded rows)."""
    out: dict[int, dict] = {}
    for client, name, q, b in rows:
        m = out.setdefault(client, {"queries": 0, "blocked": 0, "categories": defaultdict(lambda: [0, 0])})
        cat = classifier.classify(name).primary if name else "not_itemized"
        m["queries"] += q
        m["blocked"] += b
        m["categories"][cat][0] += q
        m["categories"][cat][1] += b
    return out


def category_list(m: dict, labels: dict[str, str]) -> list[dict]:
    total = m["queries"] or 1
    return sorted(({"category": c, "label": labels.get(c, "Not itemized" if c == "not_itemized" else c),
                    "queries": q, "blocked": b, "share": q / total,
                    "background": c in BACKGROUND_CATEGORIES or c == "not_itemized"}
                   for c, (q, b) in m["categories"].items()), key=lambda x: -x["queries"])


def active_hours(minutes: list[tuple[int, str, int, int]], classifier) -> dict[str, int]:
    """Distinct clock hours per category with at least one allowed lookup, from the activity minutes
    (service rows per minute, '~category' rows per hour)."""
    hours: dict[str, set[int]] = defaultdict(set)
    for ts, skey, q, b in minutes:
        if q - b <= 0:
            continue
        if skey.startswith("~"):
            cat = skey[1:]
        else:
            rule = classifier.service_info(skey)
            cat = rule.categories[0] if rule else "unknown"
        hours[cat].add(ts // 3600)
    return {c: len(h) for c, h in hours.items()}


def estimates(services: list[dict]) -> dict[str, dict]:
    """Per category: sum of the service estimates that have a number, and what was left out."""
    out: dict[str, dict] = {}
    for s in services:
        e = out.setdefault(s["category"], {"estimate_seconds": None, "services": [], "without_estimate": [],
                                           "confidence": None})
        if s.get("estimate_seconds"):
            e["estimate_seconds"] = (e["estimate_seconds"] or 0) + s["estimate_seconds"]
            e["services"].append(s["name"])
            conf = s.get("confidence")
            if conf in CONFIDENCE_ORDER and (e["confidence"] is None
                                             or CONFIDENCE_ORDER.index(conf) > CONFIDENCE_ORDER.index(e["confidence"])):
                e["confidence"] = conf          # the weakest service decides
        else:
            e["without_estimate"].append(s["name"])
    return out
