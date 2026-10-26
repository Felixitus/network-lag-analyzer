"""Filling gaps afterwards - only from sources that really hold the data.

* DNS minutes (lag context, table dns_queries): Pi-hole keeps every query for 91 days, so
  minutes the service did not count (while it was down, or while the device loop was
  broken) can be counted later, exactly as live.
* Presence before the tracking started: the hourly DNS counters per device say that a
  device looked up names in an hour - proof that it was in the network then, at hour
  resolution. Hours without lookups prove nothing, so these periods are marked as
  "from DNS lookups" and never mixed up with the minute-exact presence.

Pi health, line values and anything else that was never stored stay missing.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Iterable

from ..collectors.pihole import BLOCKED_STATUS

CHECKED_KEY = "dns_minutes_backfill_checked"   # settings: hour starts already filled
PRESENCE_KEY = "presence_backfill_until"       # settings: DNS-based presence written up to here
PRESENCE_DAYS = 31


def minute_rows(queries: Iterable) -> list[tuple]:
    """DNS queries (objects with ts, client, domain, status) → dns_queries rows, like the live poll."""
    buckets: dict[tuple[int, str], list] = {}
    for q in queries:
        b = buckets.setdefault((int(q.ts) // 60 * 60, q.client), [0, 0, Counter()])
        b[0] += 1
        if q.status in BLOCKED_STATUS:
            b[1] += 1
        b[2][q.domain] += 1
    return [(m, c, n, bl, json.dumps(dom.most_common(8))) for (m, c), (n, bl, dom) in sorted(buckets.items())]


def hours_to_fill(covered_minutes: set[int], checked: set[int], start: int, end: int) -> list[int]:
    """Whole hours in [start, end) not yet checked. An hour the live poll counted in full is skipped;
    one with gaps is read again and only its missing minutes are added."""
    out = []
    for h in range(start // 3600 * 3600, end // 3600 * 3600, 3600):
        if h in checked or h < start:
            continue
        if sum(1 for m in range(h, h + 3600, 60) if m in covered_minutes) >= 60:
            continue
        out.append(h)
    return out


def presence_periods(hours: Iterable[tuple[int, int]]) -> list[tuple[int, int, int]]:
    """(device id, hour start) with lookups → merged periods (dev, start, end) of whole hours."""
    by_dev: dict[int, list[int]] = defaultdict(list)
    for dev, h in hours:
        by_dev[dev].append(h)
    out = []
    for dev, hs in by_dev.items():
        hs.sort()
        s = e = hs[0]
        for h in hs[1:]:
            if h == e + 3600:
                e = h
            else:
                out.append((dev, s, e + 3600))
                s = e = h
        out.append((dev, s, e + 3600))
    return sorted(out)
