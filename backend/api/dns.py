"""DNS usage per device (from Pi-hole's query log, aggregated by backend/analysis/dns_ingest.py).

Everything here is a count of DNS queries as Pi-hole logged them - measured, not
estimated. It shows *that* a device looked up a name, not how long or how much it
used the service behind it, and nothing about lookups that bypass Pi-hole
(DNS over HTTPS, iCloud Private Relay, VPNs).
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Query, Request

from ..analysis.dns_ingest import local_day

router = APIRouter(prefix="/api/dns")

NOTE = ("Counts of DNS queries logged by Pi-hole. They show that a device looked up a name, "
        "not how long or how much it used the service. Lookups that bypass Pi-hole "
        "(DNS over HTTPS, Private Relay, VPN) are not included.")
MAX_RANGE = 3660 * 86400


def core_of(request: Request):
    return request.app.state.core


def _range(start: float | None, end: float | None) -> tuple[int, int]:
    now = time.time()
    end = now if end is None else end
    start = end - 86400 if start is None else start
    if end <= start:
        raise HTTPException(400, "end must be after start")
    if end - start > MAX_RANGE:
        raise HTTPException(400, "Range too long")
    # Hour resolution: a partial hour at either end is included as a whole.
    return int(start) // 3600 * 3600, -(-int(end) // 3600) * 3600


def _client_row(r) -> dict:
    return {"id": r["id"], "key": r["key"], "basis": r["basis"], "mac": r["mac"], "ip": r["ip"],
            "hostname": r["name"], "alias": r["custom_name"],
            "name": r["custom_name"] or r["name"] or r["ip"] or r["mac"],
            "first_seen": r["first_seen"], "last_seen": r["last_seen"]}


@router.get("/status")
async def status(request: Request):
    core = core_of(request)

    def q(c):
        return c.execute("SELECT MIN(ts) AS a, MAX(ts) AS b FROM dns_client_hourly").fetchone()
    r = await core.db.read(q)
    return {**core.dns_usage_status, "data_from": r["a"], "data_to": (r["b"] + 3600) if r["b"] else None,
            "note": NOTE}


@router.get("/clients")
async def clients(request: Request, start: float | None = Query(None), end: float | None = Query(None)):
    core = core_of(request)
    t0, t1 = _range(start, end)

    def q(c):
        return c.execute("""
            SELECT k.id, k.key, k.basis, k.mac, k.ip, k.name, k.first_seen, k.last_seen, d.custom_name,
                   SUM(h.queries) AS queries, SUM(h.blocked) AS blocked, SUM(h.duplicates) AS duplicates,
                   MIN(h.ts) AS first_hour, MAX(h.ts) AS last_hour
            FROM dns_client_hourly h JOIN dns_clients k ON k.id = h.client
            LEFT JOIN devices d ON d.mac = k.mac
            WHERE h.ts >= ? AND h.ts < ?
            GROUP BY h.client ORDER BY queries DESC""", (t0, t1)).fetchall()
    rows = await core.db.read(q)
    out = []
    for r in rows:
        item = _client_row(r)
        item.update(queries=r["queries"], blocked=r["blocked"], duplicates=r["duplicates"],
                    active_from=r["first_hour"], active_to=r["last_hour"] + 3600)
        out.append(item)
    return {"start": t0, "end": t1, "resolution": "hour", "clients": out, "note": NOTE}


async def _client(core, cid: int) -> dict:
    def q(c):
        return c.execute("SELECT k.*, d.custom_name FROM dns_clients k LEFT JOIN devices d ON d.mac = k.mac "
                         "WHERE k.id = ?", (cid,)).fetchone()
    r = await core.db.read(q)
    if r is None:
        raise HTTPException(404, "Client not found")
    return _client_row(r)


@router.get("/clients/{cid}/hourly")
async def client_hourly(request: Request, cid: int, start: float | None = Query(None),
                        end: float | None = Query(None)):
    core = core_of(request)
    client = await _client(core, cid)
    t0, t1 = _range(start, end)

    def q(c):
        return [dict(r) for r in c.execute(
            "SELECT ts, queries, blocked, duplicates FROM dns_client_hourly WHERE client=? AND ts>=? AND ts<? "
            "ORDER BY ts", (cid, t0, t1))]
    # Hours without a row are hours without queries in an ingested range, or hours
    # before ingestion started - status.data_from tells which.
    return {"client": client, "start": t0, "end": t1, "hours": await core.db.read(q), "note": NOTE}


@router.get("/clients/{cid}/domains")
async def client_domains(request: Request, cid: int, start: float | None = Query(None),
                         end: float | None = Query(None), limit: int = Query(100, ge=1, le=1000),
                         offset: int = Query(0, ge=0), blocked_only: bool = False):
    core = core_of(request)
    client = await _client(core, cid)
    t0, t1 = _range(start, end)
    d0, d1 = local_day(t0), local_day(t1 - 1)

    def q(c):
        having = "HAVING SUM(x.blocked) > 0" if blocked_only else ""
        rows = c.execute(f"""
            SELECT x.domain, n.name, SUM(x.queries) AS queries, SUM(x.blocked) AS blocked,
                   MIN(x.first_ts) AS first_ts, MAX(x.last_ts) AS last_ts
            FROM dns_domain_daily x LEFT JOIN dns_domains n ON n.id = x.domain
            WHERE x.client = ? AND x.day >= ? AND x.day <= ?
            GROUP BY x.domain {having} ORDER BY queries DESC, n.name LIMIT ? OFFSET ?""",
            (cid, d0, d1, limit, offset)).fetchall()
        total = c.execute(f"""SELECT COUNT(*) FROM (SELECT 1 FROM dns_domain_daily x
            WHERE x.client = ? AND x.day >= ? AND x.day <= ? GROUP BY x.domain {having})""",
            (cid, d0, d1)).fetchone()[0]
        return rows, total
    rows, total = await core.db.read(q)
    domains = [{"domain": r["name"] if r["domain"] else None, "other": r["domain"] == 0,
                "queries": r["queries"], "blocked": r["blocked"],
                "first_seen": r["first_ts"], "last_seen": r["last_ts"]} for r in rows]
    return {"client": client, "resolution": "day", "day_from": d0, "day_to": d1, "total": total,
            "limit": limit, "offset": offset, "domains": domains,
            "note": NOTE + " Domains are counted per local day; days completed keep the busiest "
                           "domains and sum up the rest as 'other domains'."}
