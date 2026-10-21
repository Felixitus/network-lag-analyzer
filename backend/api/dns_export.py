"""Exports of the DNS usage pages as CSV (one table) or XLSX (several sheets).

The export reuses the very functions behind the pages, with the same filters, so
a file never shows other numbers than the screen did. Every file starts with the
export time, the range, the filters and the method - in CSV as key/value rows
above the table, in XLSX as the first sheet.
"""
from __future__ import annotations

import asyncio
import re
import tempfile
import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from .. import __version__
from ..analysis import activity, dns_usage as usage
from ..util.tabular import CsvFormat, csv_stream, write_xlsx
from . import dns

router = APIRouter(prefix="/api/dns")

Kind = Literal["network", "client", "clients", "domains", "categories", "blocked", "timeseries", "phases"]
CSV_KINDS = {"clients", "domains", "categories", "blocked", "timeseries", "phases"}
CLIENT_KINDS = {"client", "phases"}
NETWORK_ONLY = {"network", "clients"}
TITLES = {"network": "Whole network", "client": "Single client", "clients": "Clients", "domains": "Domain list",
          "categories": "Category statistics", "blocked": "Blocked domains", "timeseries": "Time series",
          "phases": "Activity phases"}


def _t(ts) -> str | None:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else None


def _minutes(seconds) -> float | None:
    return None if seconds is None else round(seconds / 60, 1)


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-")[:40] or "client"


# --------------------------------------------------------------------- tables
def clients_table(data: dict) -> list[list]:
    rows = [["Client", "Alias", "Host name", "IP", "MAC", "Vendor", "Attribution", "Online", "DNS queries",
             "Blocked", "Blocked %", "Retries (not counted)", "Distinct domains", "First active hour",
             "Last active hour"]]
    for c in data["clients"]:
        rows.append([c["name"], c["alias"], c["hostname"], c["ip"], c["mac"], c["vendor"],
                     {"mac": "MAC address", "ip": "IP only", "local": "This Pi"}.get(c["basis"], c["basis"]),
                     None if c["online"] is None else c["online"], c["queries"], c["blocked"],
                     round(100 * c["blocked"] / c["queries"], 2) if c["queries"] else None, c["duplicates"],
                     c["domains"], _t(c["active_from"]), _t(c["active_to"] - 3600)])
    return rows


def domains_table(rows: list[dict], labels: dict) -> list[list]:
    out = [["Domain", "Category", "Further categories", "Service", "Rule", "Rule source", "Rule confidence",
            "DNS queries", "Blocked", "First seen", "Last seen"]]
    for r in rows:
        c = r["classification"] or {}
        cats = c.get("categories") or []
        out.append([r["name"] if r["name"] is not None else "(other domains, folded)",
                    usage.NOT_ITEMIZED_LABEL if r["category"] == usage.NOT_ITEMIZED else labels.get(r["category"], r["category"]),
                    ", ".join(labels.get(x, x) for x in cats[1:]) or None, c.get("service_name"), c.get("rule"),
                    c.get("source"), c.get("confidence"), r["queries"], r["blocked"],
                    _t(r["first_seen"]), _t(r["last_seen"])])
    return out


def categories_table(cats: list[dict]) -> list[list]:
    return [["Category", "DNS queries", "Blocked", "Distinct domains", "Share of queries %"]] + [
        [c["label"], c["queries"], c["blocked"], c["domains"], round(100 * c["share"], 2)] for c in cats]


def timeseries_table(hours: list[dict]) -> list[list]:
    return [["Hour (start)", "DNS queries", "Blocked"]] + [[_t(h["ts"]), h["queries"], h["blocked"]] for h in hours]


def services_table(act: dict, labels: dict) -> list[list]:
    out = [["Service", "Category", "DNS queries", "Blocked", "Phases", "Gap (min)", "Estimated activity (min)",
            "Confidence", "Reason"]]
    for s in act["services"]:
        out.append([s["name"], labels.get(s["category"], s["category"]), s["queries"], s["blocked"],
                    s["phase_count"], s["gap_minutes"],
                    _minutes(s["estimate_seconds"]) if s["estimate_seconds"] is not None else "Not reliably determinable",
                    s["confidence"], s["reason"]])
    return out


def phases_table(act: dict, labels: dict) -> list[list]:
    out = [["Service", "Category", "Phase start", "Phase end (last minute)", "Duration (min)", "Lookups",
            "Service estimate (min)", "Service confidence"]]
    for s in act["services"]:
        est = _minutes(s["estimate_seconds"]) if s["estimate_seconds"] is not None else "Not reliably determinable"
        for p in s["phases"]:
            out.append([s["name"], labels.get(s["category"], s["category"]), _t(p["start"]), _t(p["end"]),
                        _minutes(p["seconds"]), p["queries"], est, s["confidence"]])
    return out


def about_rows(kind: str, start: float, end: float, client: dict | None, filters: dict, notes: list[str]) -> list[list]:
    rows = [["Network Lag Analyzer - DNS usage export", None],
            ["Export", TITLES[kind]],
            ["Exported at", _t(time.time())],
            ["Range from", _t(start)],
            ["Range to", _t(end)]]
    if client:
        rows += [["Client", client["name"]], ["IP", client["ip"]], ["MAC", client["mac"]],
                 ["Attribution", {"mac": "MAC address", "ip": "IP only", "local": "This Pi"}.get(client["basis"])]]
    for k, v in filters.items():
        if v not in (None, "", "all"):
            rows.append([f"Filter: {k}", v])
    rows += [["Data source", "Pi-hole query log, read-only; counted per device by Network Lag Analyzer "
                             f"{__version__}"],
             ["Method", dns.NOTE]]
    rows += [["Note", n] for n in notes if n]
    return rows


# --------------------------------------------------------------------- route
@router.get("/export")
async def export(request: Request, kind: Kind, format: Literal["csv", "xlsx"] = "csv",
                 locale: Literal["de", "en"] = "de", start: float | None = Query(None),
                 end: float | None = Query(None), client: int | None = Query(None),
                 status: Literal["all", "blocked", "allowed"] = "all",
                 category: str | None = Query(None, max_length=32), q: str | None = Query(None, max_length=253),
                 sort: Literal["queries", "last_seen", "domain"] = "queries",
                 gap: float | None = Query(None, ge=1, le=120)):
    core = dns.core_of(request)
    start, end = dns._range(start, end)
    if format == "csv" and kind not in CSV_KINDS:
        raise HTTPException(400, f"'{kind}' has several tables - export it as XLSX")
    if kind in CLIENT_KINDS and client is None:
        raise HTTPException(400, "This export needs a client")
    if kind in NETWORK_ONLY and client is not None:
        raise HTTPException(400, "This export covers the whole network - leave out 'client'")
    c = await dns._client(core, client) if client is not None else None
    labels = core.classifier.labels
    filters = {"status": status, "category": labels.get(category, category) if category else None, "search": q,
               "activity gap (min)": gap}
    t0, t1 = usage.hour_range(start, end)
    sheets: list[tuple[str, list[list], int]] = []
    notes: list[str] = []

    memo: dict = {}

    async def domain_rows():
        if "rows" not in memo:
            rows, res, _meta = await dns._domains(core, start, end, c)
            notes.append(dns._resolution_note(res))
            memo["rows"] = rows
        return memo["rows"]

    async def activity_data():
        a = await dns.client_activity(request, client, start, end, gap)
        notes.extend([a["note"], a.get("coverage_note"), a.get("rebuild_note"), *activity.EXPLANATION])
        return a

    if kind in ("network", "clients"):
        sheets.append(("Clients", clients_table(await dns.clients(request, start, end)), 1))
        notes.append("Hour resolution: a partial hour at either end of the range is counted as a whole.")
    if kind in ("network", "client", "categories"):
        rows = await domain_rows()
        sheets.append(("Categories", categories_table(usage.category_breakdown(rows, core.classifier)), 1))
        notes.append("Categories: each domain counts for its primary category, so the shares add up to 100 %.")
    if kind in ("network", "client", "domains"):
        rows = await domain_rows()
        sheets.append(("Domains", domains_table(dns.filter_domains(rows, status, category, q, sort), labels), 1))
    if kind in ("network", "client", "blocked"):
        rows = await domain_rows()
        sheets.append(("Blocked", domains_table(dns.filter_domains(rows, "blocked", category, q, sort), labels), 1))
    if kind in ("network", "client", "timeseries"):
        hours = await core.db.read(lambda conn: usage.timeline(conn, t0, t1, client))
        sheets.append(("Time series", timeseries_table(hours), 1))
        notes.append("Time series: hours without a row had no queries - or lie before recording started "
                     "(see 'Range from' and the coverage on the page).")
    if kind in ("client", "phases"):
        try:
            a = await activity_data()
            if kind == "client":
                sheets.append(("Activity (estimated)", services_table(a, labels), 1))
            sheets.append(("Activity phases", phases_table(a, labels), 1))
        except HTTPException as e:
            if kind == "phases":
                raise
            notes.append(f"Activity phases not included: {e.detail}")
    if kind == "client":
        s = await dns.client_summary(request, client, start, end)
        cmp = s["comparison"]
        summary = [["Value", "This range", "Previous period", "Change %"]]
        for k, label in (("queries", "DNS queries"), ("blocked", "Blocked"), ("domains", "Distinct domains")):
            prev = cmp[k]["previous"] if cmp else None
            ch = cmp[k]["change"] if cmp else None
            summary.append([label, s["totals"].get(k), prev, round(100 * ch, 1) if ch is not None else None])
        summary.append(["Retries (not counted)", s["totals"]["duplicates"], None, None])
        sheets.insert(0, ("Summary", summary, 1))
        if not cmp:
            notes.append(s["comparison_note"])

    about = about_rows(kind, start, end, c, filters, list(dict.fromkeys(notes)))
    stamp = time.strftime("%Y%m%d-%H%M")
    base = f"dns-{kind}" + (f"-{_slug(c['name'])}" if c else "") + f"-{stamp}"
    if format == "csv":
        rows = about + [[]] + sheets[0][1]          # CSV kinds have exactly one table
        return StreamingResponse(csv_stream(rows, CsvFormat(locale)), media_type="text/csv; charset=utf-8",
                                 headers=_disposition(f"{base}.csv"))

    spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
    await asyncio.to_thread(write_xlsx, spool, [("About", about, 1)] + sheets)
    spool.seek(0)

    def chunks():
        try:
            while data := spool.read(64 * 1024):
                yield data
        finally:
            spool.close()
    return StreamingResponse(chunks(), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                             headers=_disposition(f"{base}.xlsx"))


def _disposition(filename: str) -> dict:
    return {"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"}
