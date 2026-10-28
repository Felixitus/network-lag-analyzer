"""DNS usage per device (from Pi-hole's query log, aggregated by backend/analysis/dns_ingest.py).

Everything here is a count of DNS queries as Pi-hole logged them - measured, not
estimated. It shows *that* a device looked up a name, not how long or how much it
used the service behind it, and nothing about lookups that bypass Pi-hole
(DNS over HTTPS, iCloud Private Relay, VPNs). Categories are rule based; every
domain carries the rule, the rule layer and the confidence that produced it.
"""
from __future__ import annotations

import asyncio
import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator

from ..analysis import activity, category_usage as cu, client_match, dns_bypass, dns_usage as usage
from ..analysis.categories import normalize_domain, valid_domain
from ..collectors.ftl_queries import STATUS_TEXT, outcome
from ..database import repository as repo

router = APIRouter(prefix="/api/dns")

NOTE = ("Counts of DNS queries logged by Pi-hole. They show that a device looked up a name, "
        "not how long or how much it used the service. Lookups that bypass Pi-hole "
        "(DNS over HTTPS, Private Relay, VPN) are not included.")
MAX_RANGE = 3660 * 86400
OVERRIDES_KEY = "dns_category_overrides"
CACHE_SECONDS = 30
# Domain lists for long ranges classify tens of thousands of names; two at a time
# is plenty on a Pi that also has to answer DNS.
_heavy = asyncio.Semaphore(2)
_cache: dict[tuple, tuple[float, object]] = {}


def core_of(request: Request):
    return request.app.state.core


def _range(start: float | None, end: float | None) -> tuple[float, float]:
    now = time.time()
    end = now if end is None else end
    start = end - 86400 if start is None else start
    if end <= start:
        raise HTTPException(400, "end must be after start")
    if end - start > MAX_RANGE:
        raise HTTPException(400, "Range too long")
    return start, end


async def _cached(key: tuple, fn):
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    async with _heavy:
        val = await fn()
    if len(_cache) > 200:
        _cache.clear()
    _cache[key] = (time.monotonic(), val)
    return val


def _invalidate() -> None:
    _cache.clear()


def _client_row(core, r) -> dict:
    dev = core.devices.by_mac.get(r["mac"]) if r["mac"] else None
    # The device registry is the live source of aliases; the devices table may lag
    # behind it by one persist cycle.
    alias = dev.custom_name if dev else r["custom_name"]
    # Same host name as the devices page: the registry picks it by source priority.
    hostname = (dev.hostname if dev else None) or r["name"]
    return {"id": r["id"], "key": r["key"], "basis": r["basis"], "mac": r["mac"], "ip": r["ip"],
            "hostname": hostname, "alias": alias,
            "name": alias or hostname or r["ip"] or r["mac"],
            "vendor": dev.vendor if dev else None,
            # Online according to FRITZ!Box/ARP/Pi-hole; None = not determinable (no MAC).
            "online": dev.active if dev else None,
            "connection": dev.interface if dev else None,       # as the FRITZ!Box reports it
            "sources": sorted(dev.sources) if dev else [],
            "first_seen": r["first_seen"], "last_seen": r["last_seen"]}


async def _client(core, cid: int) -> dict:
    def q(c):
        return c.execute("SELECT k.*, d.custom_name FROM dns_clients k LEFT JOIN devices d ON d.mac = k.mac "
                         "WHERE k.id = ?", (cid,)).fetchone()
    r = await core.db.read(q)
    if r is None:
        raise HTTPException(404, "Client not found")
    return _client_row(core, r)


async def _domains(core, start: float, end: float, client: dict | None) -> tuple[list[dict], str, dict]:
    """Domain rows for a range: per hour while the hourly domain counters still cover
    it, else per local day."""
    t0, t1 = usage.hour_range(start, end)
    cid = client["id"] if client else None
    hourly_from = await core.db.read(usage.hourly_domains_from)
    # Hourly rows only exist from when they were first recorded (an installation
    # that ran before them starts empty) and only within their retention; one hour
    # of margin because retention deletes whole hours.
    if hourly_from is not None and t0 >= max(hourly_from, time.time() - core.cfg.retention.dns_domain_hourly_hours * 3600 + 3600):
        rows = await core.db.read(lambda c: usage.domain_rows_hourly(c, t0, t1, cid))
        meta = {"resolution": "hour", "from": t0, "to": t1}
    else:
        d0, d1 = usage.day_range(t0, t1)
        rows = await core.db.read(lambda c: usage.domain_rows(c, d0, d1, cid))
        meta = {"resolution": "day", "from": d0, "to": d1 + 86400}
    return usage.classify_rows(rows, core.classifier), meta["resolution"], meta


def filter_domains(rows: list[dict], status: str = "all", category: str | None = None, q: str | None = None,
                   sort: str = "queries") -> list[dict]:
    """The domain filters of the client page - shared with the export so both show the same rows."""
    needle = normalize_domain(q) if q else None
    sel = [r for r in rows
           if (status != "blocked" or r["blocked"] > 0)
           and (status != "allowed" or r["queries"] > r["blocked"])
           and (category is None or r["category"] == category)
           and (needle is None or (r["name"] is not None and needle in r["name"]))]
    key = {"queries": lambda r: (-r["queries"], r["name"] or "~"),
           "last_seen": lambda r: (-(r["last_seen"] or 0), r["name"] or "~"),
           "domain": lambda r: (r["name"] is None, r["name"] or "")}[sort]
    sel.sort(key=key)
    return sel


def _domain_out(r: dict) -> dict:
    return {"domain": r["name"], "other": r["name"] is None, "queries": r["queries"], "blocked": r["blocked"],
            "first_seen": r["first_seen"], "last_seen": r["last_seen"], "category": r["category"],
            "classification": r["classification"]}


def _resolution_note(res: str) -> str:
    return ("Per hour: the domain list covers exactly the hours of the totals." if res == "hour" else
            "Per local day: the domain list covers whole days, also when the selected range is shorter. "
            "Completed days keep the busiest domains per device and sum up the rest.")


SOURCE_TEXT = {
    "builtin": "Shipped rule file of the Network Lag Analyzer (hand-maintained, backend/data/domain_categories.yaml)",
    "local": "Your rule file domain_categories.local.yaml in the data directory",
    "manual": "Your own rule on the Category rules page",
    "ut1": "UT1 list of the Université Toulouse Capitole (CC BY-SA 4.0), imported on this Pi",
    None: "No rule matched this name",
}
CONFIDENCE_TEXT = {
    "high": "The domain is operated by and only used for this service.",
    "medium": "Mostly this service or category, but also embedded elsewhere - or the judgement of a list.",
    "low": "Shared infrastructure: it says who delivered something, not which service was used.",
    None: "No rule, no confidence.",
}


def explain(core, name: str) -> dict:
    """What a domain is according to the rules, where that comes from and how sure it is."""
    c = core.classifier.classify(name)
    cls = c.to_dict()
    return {**cls, "label": core.classifier.labels.get(c.primary, c.primary),
            "description": core.classifier.info.get(c.primary),
            "also": [{"category": x, "label": core.classifier.labels.get(x, x)} for x in c.categories[1:]],
            "source_text": SOURCE_TEXT.get(c.source, c.source),
            "confidence_text": CONFIDENCE_TEXT.get(c.confidence)}


# ===================================================================== status
@router.get("/status")
async def status(request: Request):
    core = core_of(request)
    a, b = await core.db.read(usage.coverage)
    return {**core.dns_usage_status, "data_from": a, "data_to": b, "note": NOTE}


@router.get("/overview")
async def overview(request: Request, start: float | None = Query(None), end: float | None = Query(None)):
    core = core_of(request)
    start, end = _range(start, end)
    t0, t1 = usage.hour_range(start, end)

    async def build():
        def q(c):
            return (usage.totals(c, t0, t1), usage.timeline(c, t0, t1), usage.known_clients(c), usage.coverage(c))
        tot, tl, known, cov = await core.db.read(q)
        rows, res, meta = await _domains(core, start, end, None)
        cats = usage.category_breakdown(rows, core.classifier)
        rows.sort(key=lambda r: -r["queries"])
        top = [_domain_out(r) for r in rows if r["name"] is not None][:20]
        return {"start": t0, "end": t1, "coverage": {"from": cov[0], "to": cov[1]},
                "totals": {**tot, "known_clients": known}, "timeline": tl,
                "top_domains": top, "categories": cats,
                "domains_resolution": res, "domains_range": meta, "domains_note": _resolution_note(res)}
    data = await _cached(("overview", t0, t1, round(start), round(end)), build)
    recent = []
    if core.dns_usage is not None:
        try:
            for q, att in await asyncio.to_thread(core.dns_usage.recent, 25):
                dev = core.devices.by_mac.get(att.mac) if att.mac else None
                recent.append({"ts": q.ts, "domain": q.domain, "outcome": q.outcome, "client_key": att.key,
                               "client": (dev.display_name if dev else None) or att.name or att.ip,
                               "basis": att.basis, "category": core.classifier.classify(q.domain).primary})
        except Exception as e:      # FTL not readable right now - the rest of the page still works
            recent = None
            data = {**data, "recent_error": str(e)}
    return {**data, "recent": recent,
            "sources": {"pihole": core.pihole_status, "fritzbox": core.fritz_status,
                        "dns_usage": core.dns_usage_status},
            "note": NOTE}


# ===================================================================== clients
@router.get("/clients")
async def clients(request: Request, start: float | None = Query(None), end: float | None = Query(None)):
    core = core_of(request)
    start, end = _range(start, end)
    t0, t1 = usage.hour_range(start, end)
    d0, d1 = usage.day_range(t0, t1)

    def q(c):
        rows = c.execute("""
            SELECT k.id, k.key, k.basis, k.mac, k.ip, k.name, k.first_seen, k.last_seen, d.custom_name,
                   SUM(h.queries) AS queries, SUM(h.blocked) AS blocked, SUM(h.duplicates) AS duplicates,
                   MIN(h.ts) AS first_hour, MAX(h.ts) AS last_hour
            FROM dns_client_hourly h JOIN dns_clients k ON k.id = h.client
            LEFT JOIN devices d ON d.mac = k.mac
            WHERE h.ts >= ? AND h.ts < ?
            GROUP BY h.client ORDER BY queries DESC""", (t0, t1)).fetchall()
        return rows, usage.distinct_domains_per_client(c, d0, d1)
    rows, distinct = await core.db.read(q)
    out = []
    for r in rows:
        item = _client_row(core, r)
        item.update(queries=r["queries"], blocked=r["blocked"], duplicates=r["duplicates"],
                    domains=distinct.get(r["id"]), active_from=r["first_hour"], active_to=r["last_hour"] + 3600)
        out.append(item)
    return {"start": t0, "end": t1, "resolution": "hour", "clients": out,
            "domains_note": "Distinct domains are counted per local day (whole days of the range).",
            "note": NOTE}


@router.get("/clients/{cid}/summary")
async def client_summary(request: Request, cid: int, start: float | None = Query(None),
                         end: float | None = Query(None)):
    core = core_of(request)
    client = await _client(core, cid)
    start, end = _range(start, end)
    t0, t1 = usage.hour_range(start, end)
    p0, p1 = t0 - (t1 - t0), t0

    async def build():
        def q(c):
            return usage.totals(c, t0, t1, cid), usage.totals(c, p0, p1, cid), usage.coverage(c)
        cur, prev, cov = await core.db.read(q)
        rows, res, meta = await _domains(core, start, end, client)
        cats = usage.category_breakdown(rows, core.classifier)
        cur["domains"] = sum(1 for r in rows if r["name"] is not None)
        rows.sort(key=lambda r: -r["queries"])
        comparison = None
        # Only compare when the previous period is fully covered - otherwise a
        # "plus 300 %" would just mean "we were not recording yet".
        if cov[0] is not None and cov[0] <= p0:
            prows, _r, _m = await _domains(core, start - (end - start), start, client)
            prev["domains"] = sum(1 for r in prows if r["name"] is not None)
            pcats = {c["category"]: c["queries"] for c in usage.category_breakdown(prows, core.classifier)}
            comparison = {"start": p0, "end": p1, **usage.compare(cur, prev),
                          "categories": {c["category"]: {"current": c["queries"], "previous": pcats.get(c["category"], 0)}
                                         for c in cats}}
        return {"start": t0, "end": t1, "totals": cur, "categories": cats,
                "top_domains": [_domain_out(r) for r in rows if r["name"] is not None][:10],
                "comparison": comparison,
                "comparison_note": None if comparison else
                "Not available: the previous period of the same length is not fully recorded.",
                "domains_resolution": res, "domains_range": meta, "domains_note": _resolution_note(res)}
    data = await _cached(("summary", cid, t0, t1, round(start), round(end)), build)
    return {"client": client, **data, "note": NOTE}


@router.get("/clients/{cid}/hourly")
async def client_hourly(request: Request, cid: int, start: float | None = Query(None),
                        end: float | None = Query(None)):
    core = core_of(request)
    client = await _client(core, cid)
    start, end = _range(start, end)
    t0, t1 = usage.hour_range(start, end)
    hours = await core.db.read(lambda c: usage.timeline(c, t0, t1, cid))
    # Hours without a row are hours without queries in an ingested range, or hours
    # before ingestion started - status.data_from tells which.
    return {"client": client, "start": t0, "end": t1, "hours": hours, "note": NOTE}


@router.get("/clients/{cid}/domains")
async def client_domains(request: Request, cid: int, start: float | None = Query(None),
                         end: float | None = Query(None), limit: int = Query(100, ge=1, le=1000),
                         offset: int = Query(0, ge=0),
                         status: Literal["all", "blocked", "allowed"] = "all",
                         blocked_only: bool = False,
                         category: str | None = Query(None, max_length=32),
                         q: str | None = Query(None, max_length=253),
                         sort: Literal["queries", "last_seen", "domain"] = "queries"):
    core = core_of(request)
    client = await _client(core, cid)
    start, end = _range(start, end)
    if blocked_only:
        status = "blocked"
    rows, res, meta = await _cached(("domains", cid, round(start), round(end)),
                                    lambda: _domains(core, start, end, client))
    sel = filter_domains(rows, status, category, q, sort)
    return {"client": client, "resolution": res, "range": meta, "total": len(sel), "limit": limit,
            "offset": offset, "domains": [_domain_out(r) for r in sel[offset:offset + limit]],
            "resolution_note": _resolution_note(res), "note": NOTE}


@router.get("/clients/{cid}/activity")
async def client_activity(request: Request, cid: int, start: float | None = Query(None),
                          end: float | None = Query(None), gap: float | None = Query(None, ge=1, le=120)):
    """Estimated activity phases per service, built from the activity minutes."""
    core = core_of(request)
    client = await _client(core, cid)
    start, end = _range(start, end)
    max_days = core.cfg.retention.dns_minute_days
    if end - start > max_days * 86400 + 3600:
        raise HTTPException(400, f"Activity phases are limited to {max_days:g} days "
                                 "(activity minutes are kept that long, see retention settings).")

    def q(c):
        rows = [(r[0], r[1], r[2], r[3]) for r in c.execute(
            """SELECT m.ts, s.key, m.queries, m.blocked FROM dns_service_minutes m
               JOIN dns_services s ON s.id = m.service
               WHERE m.client = ? AND m.ts >= ? AND m.ts < ? ORDER BY m.ts""", (cid, int(start), int(end)))]
        first = c.execute("SELECT MIN(ts) FROM dns_service_minutes").fetchone()[0]
        return rows, first

    async def build():
        rows, first = await core.db.read(q)
        return {**activity.build(rows, core.classifier, core.cfg.dns_usage.phase_gap_minutes, gap),
                "minutes_from": first}
    data = await _cached(("activity", cid, round(start), round(end), gap), build)
    rebuild = (core.dns_usage_status or {}).get("rebuild")
    first = data["minutes_from"]
    return {"client": client, "start": start, "end": end, "gap_minutes": gap,
            "default_gap_minutes": core.cfg.dns_usage.phase_gap_minutes, **data,
            "coverage_note": (f"Activity minutes exist from {time.strftime('%Y-%m-%d %H:%M', time.localtime(first))}; "
                              "earlier parts of the range have no data.") if first and first > start + 60 else
                             ("No activity minutes recorded yet." if not first else None),
            "rebuild_note": (f"The category rules changed - activity minutes are being rebuilt from the Pi-hole log "
                             f"({100 * rebuild['done']:.0f} % done). Phases are incomplete until then.") if rebuild else None,
            "note": "Estimated DNS activity - not verified screen or app usage time. "
                    "The estimate is the sum of the phases; pauses between phases are not counted."}


CATEGORY_NOTE = ("Share of lookups and active hours are counted from the Pi-hole log. The estimated activity is "
                 "the sum of the per-service DNS estimates where one is possible - not screen time, not usage time. "
                 "Grey categories (infrastructure, network checks, telemetry, updates, ...) are background, not use.")


def _hourly_ok(core, t0: int, hourly_from: int | None) -> bool:
    return hourly_from is not None and t0 >= max(hourly_from, time.time() - core.cfg.retention.dns_domain_hourly_hours * 3600 + 3600)


@router.get("/categories")
async def categories_by_client(request: Request, start: float | None = Query(None), end: float | None = Query(None)):
    """Every device with how its lookups split into categories - the overview to pick a device from."""
    core = core_of(request)
    start, end = _range(start, end)
    t0, t1 = usage.hour_range(start, end)
    d0, d1 = usage.day_range(t0, t1)

    async def build():
        hourly = _hourly_ok(core, t0, await core.db.read(usage.hourly_domains_from))
        rows = await core.db.read(lambda c: cu.client_domain_rows(c, t0, t1, d0, d1, hourly))
        m = await asyncio.to_thread(cu.matrix, rows, core.classifier)
        out = []
        for cid, data in m.items():
            try:
                cl = await _client(core, cid)
            except HTTPException:
                continue
            cats = cu.category_list(data, core.classifier.labels)
            fg = sum(c["queries"] for c in cats if not c["background"])
            out.append({"client": cl, "queries": data["queries"], "blocked": data["blocked"], "categories": cats,
                        "foreground_queries": fg})
        out.sort(key=lambda x: -x["queries"])
        return {"start": t0, "end": t1, "resolution": "hour" if hourly else "day",
                "range": {"from": t0, "to": t1} if hourly else {"from": d0, "to": d1 + 86400}, "clients": out}
    data = await _cached(("categories", t0, t1, core.classifier.fingerprint), build)
    return {**data, "labels": core.classifier.labels, "info": core.classifier.info, "note": CATEGORY_NOTE}


@router.get("/clients/{cid}/categories")
async def client_categories(request: Request, cid: int, start: float | None = Query(None), end: float | None = Query(None)):
    """One device per category: lookups and share, active hours, and the estimated activity where possible."""
    core = core_of(request)
    client = await _client(core, cid)
    start, end = _range(start, end)
    rows, res, meta = await _cached(("domains", cid, round(start), round(end)), lambda: _domains(core, start, end, client))
    by = {"queries": 0, "blocked": 0, "categories": {}}
    for r in rows:
        a = by["categories"].setdefault(r["category"], [0, 0])
        a[0] += r["queries"]
        a[1] += r["blocked"]
        by["queries"] += r["queries"]
        by["blocked"] += r["blocked"]
    cats = cu.category_list(by, core.classifier.labels)
    max_days = core.cfg.retention.dns_minute_days
    minutes_ok = end - start <= max_days * 86400 + 3600
    hours: dict[str, int] = {}
    est: dict[str, dict] = {}
    if minutes_ok:
        def q(c):
            return [(r[0], r[1], r[2], r[3]) for r in c.execute(
                """SELECT m.ts, s.key, m.queries, m.blocked FROM dns_service_minutes m
                   JOIN dns_services s ON s.id = m.service
                   WHERE m.client = ? AND m.ts >= ? AND m.ts < ? ORDER BY m.ts""", (cid, int(start), int(end)))]
        minutes = await core.db.read(q)
        hours = cu.active_hours(minutes, core.classifier)
        act = await asyncio.to_thread(activity.build, minutes, core.classifier, core.cfg.dns_usage.phase_gap_minutes)
        est = cu.estimates(act["services"])
    for c in cats:
        c["active_hours"] = hours.get(c["category"]) if minutes_ok else None
        e = est.get(c["category"]) or {}
        c["estimate_seconds"] = None if c["background"] else e.get("estimate_seconds")
        c["estimate_confidence"] = None if c["background"] else e.get("confidence")
        c["estimated_services"] = e.get("services", [])
        c["services_without_estimate"] = e.get("without_estimate", [])
        c["description"] = core.classifier.info.get(c["category"])
    return {"client": client, "start": start, "end": end, "resolution": res, "range": meta,
            "queries": by["queries"], "blocked": by["blocked"], "categories": cats,
            "minutes_note": None if minutes_ok else f"Active hours and estimates only for ranges up to {max_days:g} days.",
            "note": CATEGORY_NOTE}


@router.get("/domain")
async def domain_detail(request: Request, name: str = Query(..., max_length=253), start: float | None = Query(None),
                        end: float | None = Query(None)):
    """One domain: what it is, where the classification comes from, which devices looked it up,
    and how Pi-hole answered it in the last 24 hours."""
    core = core_of(request)
    d = _checked_domain(name)
    start, end = _range(start, end)
    t0, t1 = usage.hour_range(start, end)
    hourly_from = await core.db.read(usage.hourly_domains_from)
    if hourly_from is not None and t0 >= max(hourly_from, time.time() - core.cfg.retention.dns_domain_hourly_hours * 3600 + 3600):
        rows, res = await core.db.read(lambda c: usage.domain_by_client_hourly(c, d, t0, t1)), "hour"
    else:
        d0, d1 = usage.day_range(t0, t1)
        rows, res = await core.db.read(lambda c: usage.domain_by_client(c, d, d0, d1)), "day"
    clients = []
    for r in rows:
        try:
            cl = await _client(core, r["client"])
        except HTTPException:
            continue
        clients.append({**r, "name": cl["name"], "basis": cl["basis"], "ip": cl["ip"], "mac": cl["mac"]})
    clients.sort(key=lambda x: -x["queries"])
    pihole: dict = {"window_hours": 24, "statuses": [], "error": None}
    ing = core.dns_usage
    if ing is None:
        pihole["error"] = "Not available: Pi-hole log not connected"
    else:
        try:
            async with _heavy:
                counts = await asyncio.to_thread(ing.ftl.status_counts, d, time.time() - 86400)
            pihole["statuses"] = sorted(({"code": k, "count": v, "text": STATUS_TEXT.get(k, f"status {k}"),
                                          "kind": outcome(k)}
                                         for k, v in counts.items()), key=lambda s: -s["count"])
        except Exception as e:  # noqa: BLE001 - the counters above are still worth showing
            pihole["error"] = f"Not available: {type(e).__name__}"
    overrides = await core.db.read(lambda c: repo.get_setting(c, OVERRIDES_KEY, {}))
    return {"domain": d, "classification": explain(core, d), "manual_rule": overrides.get(d),
            "clients": clients, "queries": sum(r["queries"] for r in rows), "blocked": sum(r["blocked"] for r in rows),
            "resolution": res, "start": start, "end": end, "pihole": pihole,
            "note": "Counts of lookups as Pi-hole logged them. A lookup says a device asked for the name - "
                    "not that a person opened anything, nor for how long."}


@router.get("/uncategorized")
async def uncategorized_domains(request: Request, start: float | None = Query(None), end: float | None = Query(None),
                                limit: int = Query(30, ge=1, le=200)):
    """Names no rule knows yet, bundled per owner, busiest first - the list to classify by hand."""
    core = core_of(request)
    start, end = _range(start, end)

    async def build():
        rows, res, meta = await _domains(core, start, end, None)
        groups, total_groups = usage.uncategorized(rows, limit)
        total = sum(r["queries"] for r in rows) or 0
        unknown = sum(g["queries"] for g in usage.uncategorized(rows, 10 ** 6)[0])
        return {"groups": groups, "group_count": total_groups, "queries": total, "unknown_queries": unknown,
                "resolution": res, "range": meta}
    return await _cached(("uncategorized", start // 60, end // 60, limit, core.classifier.fingerprint), build)


@router.get("/identification")
async def identification(request: Request):
    """Do FRITZ!Box and Pi-hole identify the same clients? (see analysis/client_match.py)"""
    core = core_of(request)
    ing = core.dns_usage
    fritz_ok = bool(core.fritz_status.get("enabled")) and core.fritz_hosts_at is not None
    pihole = await asyncio.to_thread(ing.ftl.network) if ing is not None else []
    since = int(time.time()) - 86400

    def q(c):
        return {r[0]: r[1] for r in c.execute(
            """SELECT k.ip, SUM(h.queries) FROM dns_client_hourly h JOIN dns_clients k ON k.id = h.client
               WHERE h.ts >= ? AND k.basis != 'local' AND k.ip IS NOT NULL GROUP BY k.ip""", (since,))}
    by_ip = await core.db.read(q)
    res = client_match.compare(core.fritz_hosts if fritz_ok else [], pihole, core.gateway, by_ip)
    if not fritz_ok:
        res["rows"] = []
        res["consistent_share"] = None
    return {**res, "fritz_available": fritz_ok, "fritz_hosts_at": core.fritz_hosts_at,
            "pihole_available": ing is not None,
            "fritz_note": None if fritz_ok else
            ("Not available: FRITZ!Box integration is off - only Pi-hole's own view is checked."
             if not core.fritz_status.get("enabled") else
             f"Not available yet: {core.fritz_status.get('error') or 'waiting for the first host list'}"),
            "note": "A comparison of two independent views of the network. Nothing is merged or guessed from it."}


@router.get("/bypass")
async def bypass(request: Request, start: float | None = Query(None), end: float | None = Query(None)):
    """Devices whose DNS numbers are probably incomplete because they resolve names past Pi-hole."""
    core = core_of(request)
    end = time.time() if end is None else end
    start = end - 7 * 86400 if start is None else start
    start, end = _range(start, end)
    data = await bypass_report(core, start, end)
    return {**data, "note": "Signs, not proof: lookups of VPN/DoH services, FRITZ!Box activity without any Pi-hole query, "
                            "and hours in the network without lookups. What these devices resolved elsewhere is not visible."}


async def bypass_report(core, start: float, end: float) -> dict:
    """Bypass signs per device, plus lookups of known malware/phishing domains (also for the weekly report)."""
    t0, t1 = usage.hour_range(start, end)
    d0, d1 = usage.day_range(t0, t1)

    async def build():
        hourly = _hourly_ok(core, t0, await core.db.read(usage.hourly_domains_from))
        rows = await core.db.read(lambda c: cu.client_domain_rows(c, t0, t1, d0, d1, hourly))

        def q(c):
            first = c.execute("SELECT MIN(ts_start) FROM device_presence WHERE source IS NULL").fetchone()[0]
            # compare presence and lookups only where presence was recorded at all
            w0 = max(t0, -(-int(first) // 3600) * 3600) if first else t1
            dns_hours = {r[0]: r[1] for r in c.execute(
                "SELECT client, COUNT(DISTINCT ts) FROM dns_client_hourly WHERE queries > 0 AND ts >= ? AND ts < ? "
                "GROUP BY client", (w0, t1))}
            periods = c.execute("SELECT dev, ts_start, ts_end FROM device_presence WHERE source IS NULL "
                                "AND ts_end >= ? AND ts_start < ?", (w0, t1)).fetchall()
            return dns_hours, periods, first, w0
        dns_hours, periods, presence_from, w0 = await core.db.read(q)
        present: dict[int, set[int]] = {}
        for dev, s, e in periods:
            for h in range(max(s, w0) // 3600, (min(e, t1) - 1) // 3600 + 1):
                present.setdefault(dev, set()).add(h)
        vpn: dict[int, dict] = {}
        threat: dict[int, dict] = {}
        canary: dict[int, int] = {}
        for cid, name, q_, b in rows:
            if not name:
                continue
            if name == dns_bypass.CANARY or name.endswith("." + dns_bypass.CANARY):
                canary[cid] = canary.get(cid, 0) + q_
                continue
            primary = core.classifier.classify(name).primary
            if primary in ("vpn", "threat"):
                v = (vpn if primary == "vpn" else threat).setdefault(cid, {"n": 0, "names": []})
                v["n"] += q_
                v["names"].append((q_, name))
        clients = {}
        for cid in set(dns_hours) | set(vpn) | {r[0] for r in rows}:
            try:
                clients[cid] = await _client(core, cid)
            except HTTPException:
                pass
        out = []
        for cid, cl in clients.items():
            if cl["basis"] == "local":
                continue
            dev_id = core.devices.id_for(cl["mac"]) if cl["mac"] and cl["mac"] in core.devices.by_mac else None
            ph = len(present.get(dev_id, ())) if dev_id is not None and presence_from else None
            v = vpn.get(cid, {"n": 0, "names": []})
            a = dns_bypass.assess(vpn_lookups=v["n"], vpn_names=[nm for _q, nm in sorted(v["names"], reverse=True)],
                                  present_hours=ph, dns_hours=dns_hours.get(cid, 0), canary=canary.get(cid, 0))
            out.append({"client": cl, "present_hours": ph, "dns_hours": dns_hours.get(cid, 0), **a,
                        "text": dns_bypass.LEVEL_TEXT[a["level"]]})
        # devices the FRITZ!Box sees, but Pi-hole never did
        if core.fritz_status.get("enabled") and core.fritz_hosts_at is not None and core.dns_usage is not None:
            pihole = await asyncio.to_thread(core.dns_usage.ftl.network)
            for r in client_match.compare(core.fritz_hosts, pihole, core.gateway)["rows"]:
                if r["status"] == "not_using_pihole":
                    dev = core.devices.by_mac.get(r["mac"])
                    a = dns_bypass.assess(not_using_pihole=True)
                    out.append({"client": {"id": None, "mac": r["mac"], "ip": r["fritz_ip"], "basis": "mac",
                                           "name": dev.display_name if dev else (r["fritz_name"] or r["mac"])},
                                "present_hours": None, "dns_hours": 0, **a, "text": dns_bypass.LEVEL_TEXT[a["level"]]})
        order = {"bypassing": 0, "partial": 1, "complete": 2}
        out.sort(key=lambda x: (order[x["level"]], x["client"]["name"] or ""))
        threats = [{"client": clients[cid], "lookups": v["n"], "names": [nm for _q, nm in sorted(v["names"], reverse=True)[:5]]}
                   for cid, v in sorted(threat.items(), key=lambda kv: -kv[1]["n"]) if cid in clients]
        return {"start": t0, "end": t1, "devices": out, "threats": threats,
                "counts": {k: sum(1 for x in out if x["level"] == k) for k in order},
                "presence_note": None if presence_from and presence_from <= t0 else
                ("The 'in the network but quiet' check covers the time since presence is recorded "
                 f"({time.strftime('%Y-%m-%d %H:%M', time.localtime(w0))})." if presence_from else
                 "Presence is not recorded yet - the 'in the network but quiet' check is not possible.")}
    return await _cached(("bypass", t0, t1, core.classifier.fingerprint), build)


# ===================================================================== categories
class RuleBody(BaseModel):
    categories: list[str] = Field(min_length=1, max_length=4)
    exact: bool = False
    service_name: str | None = Field(None, max_length=64)

    @field_validator("service_name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        v = (v or "").strip()
        return v or None


def _checked_domain(domain: str) -> str:
    d = normalize_domain(domain)
    if not valid_domain(d):
        raise HTTPException(400, "Not a valid domain name")
    return d


@router.get("/rules")
async def rules(request: Request):
    core = core_of(request)
    overrides, refresh = await core.db.read(lambda c: (repo.get_setting(c, OVERRIDES_KEY, {}),
                                                        repo.get_setting(c, "ut1_refresh", None)))
    return {**core.classifier.summary(), "overrides": overrides, "ut1_refresh": refresh,
            "ut1_auto_update": core.cfg.dns_usage.ut1_auto_update, "ut1_update_days": core.cfg.dns_usage.ut1_update_days}


@router.get("/classify")
async def classify(request: Request, domain: str = Query(..., max_length=253)):
    core = core_of(request)
    d = _checked_domain(domain)
    return {"domain": d, **core.classifier.classify(d).to_dict()}


@router.put("/rules/{domain}")
async def put_rule(request: Request, domain: str, body: RuleBody):
    core = core_of(request)
    d = _checked_domain(domain)
    bad = [c for c in body.categories if c not in core.classifier.labels]
    if bad:
        raise HTTPException(400, f"Unknown categories: {', '.join(bad)}")

    def w(c):
        o = repo.get_setting(c, OVERRIDES_KEY, {})
        o[d] = {"categories": body.categories, "exact": body.exact, "service_name": body.service_name}
        repo.set_setting(c, OVERRIDES_KEY, o)
        return o
    overrides = await core.db.write(w)
    core.reload_classifier(overrides)
    _invalidate()
    return {"domain": d, **core.classifier.classify(d).to_dict()}


@router.delete("/rules/{domain}")
async def delete_rule(request: Request, domain: str):
    core = core_of(request)
    d = _checked_domain(domain)

    def w(c):
        o = repo.get_setting(c, OVERRIDES_KEY, {})
        if d not in o:
            return None
        del o[d]
        repo.set_setting(c, OVERRIDES_KEY, o)
        return o
    overrides = await core.db.write(w)
    if overrides is None:
        raise HTTPException(404, "No manual rule for this domain")
    core.reload_classifier(overrides)
    _invalidate()
    return {"domain": d, **core.classifier.classify(d).to_dict()}
