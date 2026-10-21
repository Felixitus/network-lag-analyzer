"""Activity phases from DNS lookups - a cautious estimate, never a measurement of usage time.

Heuristic (documented in the UI, kept deliberately simple so it can be checked):

1. Source: the minutes in which a client looked up names of a service
   (`dns_service_minutes`, written during ingestion with the category rules).
   Lookups without a service (shared CDNs, unknown names) cannot be attributed
   and are only counted (stored per hour).
2. Per service, minutes with lookups belong to the same phase while the pause
   between them is at most the gap (default 5 min, per service in the rules).
3. A phase lasts from its first to its last minute. The gap is NOT added and the
   time between two phases is NOT counted - a pause longer than the gap is
   exactly what we cannot see into. Resolution: one minute.
4. The estimate per service is the sum of its phase durations, with a confidence
   that is at most "medium": DNS can show that an app looked up names, never that
   a person looked at it.

Blocked lookups are reported, but do not form phases: a service that Pi-hole
blocks cannot be in use, its lookups are attempts.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable

# Categories where lookups say nothing about a person using something: updates,
# trackers, devices phoning home, shared infrastructure, unknown names.
BACKGROUND_CATEGORIES = {"ads_tracking", "os_updates", "smart_home", "other", "unknown"}
# Messengers and cloud sync keep background connections and look up names
# while the phone is in a pocket.
BACKGROUND_PRONE = {"communication", "cloud"}
MIN_QUERIES = 10            # fewer lookups in the range: not determinable
MIN_ESTIMATE_SECONDS = 120  # sums below this are noise, not activity
NIGHT_HOURS = range(1, 5)   # 01:00-04:59 local time
NIGHT_SHARE = 0.25          # this much of the activity at night → background refresh likely
# Distinct hours with lookups per active day. A smart TV asks for its streaming
# apps around the clock, also in standby - on the Pi that produced "10 h of
# streaming per day" with medium confidence before this rule existed.
AROUND_THE_CLOCK_HOURS = 18     # → not determinable
MANY_HOURS = 12                 # → low confidence

EXPLANATION = [
    "Background services: apps refresh feeds, sync and keep push connections while nobody uses them.",
    "DNS caches: a device asks again only when the cached answer expires (often after 1-5 minutes), "
    "so long sessions can look like several short phases - or like none.",
    "Prefetching: browsers and apps resolve names in advance, without the page ever being opened.",
    "HTTPS: one lookup can serve a connection that stays open for a long time; DNS shows the start, not the end.",
    "Encrypted DNS (DNS over HTTPS/TLS, iCloud Private Relay, VPN) bypasses Pi-hole completely - "
    "such activity is missing here.",
    "Shared infrastructure: many services load from the same CDNs; those lookups are not attributed to any service.",
]


@dataclass
class Phase:
    start: int
    end: int
    queries: int
    minutes: int = 1

    @property
    def seconds(self) -> int:
        return self.end - self.start

    def to_dict(self) -> dict:
        return {"start": self.start, "end": self.end, "seconds": self.seconds, "queries": self.queries,
                "minutes": self.minutes}


@dataclass
class ServiceActivity:
    service: str
    name: str
    category: str
    rule_confidence: str | None
    gap_minutes: float
    queries: int = 0
    blocked: int = 0
    phases: list[Phase] = field(default_factory=list)
    night_minutes: int = 0
    active_minutes: int = 0
    hours: set[tuple[int, int]] = field(default_factory=set)   # (local day, hour) with lookups


def _merge(phases: list[Phase], ts: int, q: int, gap_s: float) -> None:
    cur = phases[-1] if phases else None
    if cur is not None and ts - cur.end <= gap_s:
        cur.end = max(cur.end, ts)
        cur.queries += q
        cur.minutes += 1
    else:
        phases.append(Phase(ts, ts, q))


def assess(sa: ServiceActivity) -> dict:
    """Estimate and confidence for one service. Returns estimate None when it is not determinable."""
    total = sum(p.seconds for p in sa.phases)
    multi = [p for p in sa.phases if p.queries >= 3]
    single_share = (sum(1 for p in sa.phases if p.minutes == 1) / len(sa.phases)) if sa.phases else 1.0
    if sa.category in BACKGROUND_CATEGORIES:
        return {"estimate_seconds": None, "confidence": None,
                "reason": "Background or shared service - its lookups do not indicate that someone used it."}
    if sa.rule_confidence == "low":
        return {"estimate_seconds": None, "confidence": None,
                "reason": "The domains cannot be attributed to this service reliably."}
    days = len({d for d, _h in sa.hours})
    hours_per_day = len(sa.hours) / days if days else 0.0
    if hours_per_day >= AROUND_THE_CLOCK_HOURS:
        return {"estimate_seconds": None, "confidence": None,
                "reason": f"Lookups in {hours_per_day:.0f} hours of an average day - a device polling in the "
                          "background (e.g. a TV in standby), not continuous use."}
    if sa.queries - sa.blocked < MIN_QUERIES or not multi:
        return {"estimate_seconds": None, "confidence": None,
                "reason": f"Too few lookups ({sa.queries - sa.blocked} allowed) for an estimate."}
    if total < MIN_ESTIMATE_SECONDS:
        return {"estimate_seconds": None, "confidence": None,
                "reason": "Only isolated lookups - no continuous activity visible."}
    reasons = []
    if sa.category in BACKGROUND_PRONE:
        reasons.append("this kind of app also looks up names in the background")
    if sa.active_minutes and sa.night_minutes / sa.active_minutes >= NIGHT_SHARE:
        reasons.append(f"{sa.night_minutes / sa.active_minutes:.0%} of its active minutes are between 01:00 and "
                       "05:00, typical for background refresh")
    if hours_per_day >= MANY_HOURS:
        reasons.append(f"lookups in {hours_per_day:.0f} hours of an average day")
    if single_share >= 0.5:
        reasons.append(f"{single_share:.0%} of the phases are single minutes")
    if sa.rule_confidence == "medium":
        reasons.append("some of its domains are also used by other apps")
    if len(multi) < 2:
        reasons.append("only one phase with several lookups")
    return {"estimate_seconds": int(total), "confidence": "low" if reasons else "medium",
            "reason": ("Low: " + "; ".join(reasons) + ".") if reasons else
            "Medium: repeated phases with several lookups each. Still DNS activity, not verified usage."}


def build(minutes: Iterable[tuple[int, str, int, int]], classifier, default_gap_minutes: float,
          gap_override: float | None = None) -> dict:
    """minutes: (minute_ts, service_key, queries, blocked) in time order.

    service_key is a service id, or "~<category>" for lookups without a service.
    `gap_override` (minutes) replaces every gap, including service-specific ones -
    the "adjustable window" in the UI.
    """
    services: dict[str, ServiceActivity] = {}
    unattributed: dict[str, int] = {}
    overall: list[Phase] = []
    overall_gap = (gap_override or default_gap_minutes) * 60
    hour_cache: dict[int, tuple[int, int]] = {}
    for ts, skey, q, b in minutes:
        rule = None if skey.startswith("~") else classifier.service_info(skey)
        if rule is None:
            # "~<category>", or a service that the current rules no longer know
            # (the minutes are rebuilt in the background after a rule change).
            cat = skey[1:] if skey.startswith("~") else "unknown"
            unattributed[cat] = unattributed.get(cat, 0) + q
            continue
        sa = services.get(skey)
        if sa is None:
            sa = services[skey] = ServiceActivity(skey, rule.service_name or skey, rule.categories[0],
                                                  rule.confidence, gap_override or rule.phase_gap or default_gap_minutes)
        sa.queries += q
        sa.blocked += b
        allowed = q - b
        if allowed <= 0:
            continue
        _merge(sa.phases, ts, allowed, sa.gap_minutes * 60)
        sa.active_minutes += 1
        hk = ts // 3600
        dh = hour_cache.get(hk)
        if dh is None:
            lt = time.localtime(ts)
            dh = hour_cache[hk] = (lt.tm_yday + 1000 * lt.tm_year, lt.tm_hour)
        sa.hours.add(dh)
        hour = dh[1]
        if hour in NIGHT_HOURS:
            sa.night_minutes += 1
        if sa.category not in BACKGROUND_CATEGORIES and sa.rule_confidence != "low":
            if overall and overall[-1].end == ts:
                overall[-1].queries += allowed       # same minute, another service
            else:
                _merge(overall, ts, allowed, overall_gap)
    out = []
    for sa in services.values():
        out.append({"service": sa.service, "name": sa.name, "category": sa.category, "queries": sa.queries,
                    "blocked": sa.blocked, "gap_minutes": sa.gap_minutes,
                    "phases": [p.to_dict() for p in sa.phases], "phase_count": len(sa.phases), **assess(sa)})
    # Estimates first (largest first), then the rest by lookups.
    out.sort(key=lambda s: (s["estimate_seconds"] is None, -(s["estimate_seconds"] or 0), -s["queries"]))
    return {"services": out, "overall": [p.to_dict() for p in overall if p.queries >= 3],
            "unattributed": dict(sorted(unattributed.items(), key=lambda kv: -kv[1])),
            "explanation": EXPLANATION, "resolution": "minute"}


def minutes_from_events(events: Iterable[tuple[float, str, bool]], classifier) -> list[tuple[int, str, int, int]]:
    """(ts, domain, blocked) → minute rows as the ingestion writes them. For tests and tools."""
    acc: dict[tuple[int, str], list[int]] = {}
    for ts, domain, blocked in events:
        c = classifier.classify(domain)
        k = (int(ts) // 60 * 60, c.service) if c.service else (int(ts) // 3600 * 3600, f"~{c.primary}")
        a = acc.setdefault(k, [0, 0])
        a[0] += 1
        a[1] += bool(blocked)
    return sorted((ts, s, q, b) for (ts, s), (q, b) in acc.items())
