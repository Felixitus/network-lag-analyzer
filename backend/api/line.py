"""Internet line API: DSL values, FRITZ!Box events, outages, and the outage report as CSV."""
from __future__ import annotations

import time
from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

from .. import __version__
from ..analysis import line
from ..database import repository as repo
from ..util.tabular import CsvFormat, csv_stream

router = APIRouter(prefix="/api/line")

SPANS = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
Span = Literal["24h", "7d", "30d"]


def _events(c, start: int, end: int, all_kinds: bool) -> list[dict]:
    rows = [dict(r) for r in c.execute(
        "SELECT ts, kind, grp, msg FROM fritz_events WHERE ts>=? AND ts<? ORDER BY ts DESC", (start, end))]
    if not all_kinds:
        rows = [r for r in rows if r["kind"] in line.LINE_KINDS]
    for r in rows:
        r["label"] = line.KIND_LABELS.get(r["kind"], r["kind"])
    return rows


@router.get("")
async def line_page(request: Request, range: Span = Query("24h"), all_events: bool = False):
    core = request.app.state.core
    end = int(time.time()) + 1
    start = end - SPANS[range]

    def q(c):
        stats = [repo.decode_line(r) for r in c.execute("SELECT * FROM line_stats WHERE ts>=? AND ts<? ORDER BY ts", (start, end))]
        events = _events(c, start, end, all_events)
        outs = line.outages(c, start, end)
        return stats, events, outs

    stats, events, outs = await core.db.read(q)
    for o in outs:
        o["events"] = line.match_events(o, events)
    deltas = line.error_deltas(stats)
    return {
        "status": core.line_status,
        "series": {
            "ts": [r["ts"] for r in stats],
            "down_kbit": [r["down_kbit"] for r in stats], "up_kbit": [r["up_kbit"] for r in stats],
            "down_max_kbit": [r["down_max_kbit"] for r in stats], "up_max_kbit": [r["up_max_kbit"] for r in stats],
            "down_snr_db": [r["down_snr_db"] for r in stats], "up_snr_db": [r["up_snr_db"] for r in stats],
            "crc": [d["crc"] for d in deltas], "errored_secs": [d["errored_secs"] for d in deltas],
            "retrains": [d["retrains"] for d in deltas],
        },
        "events": events,
        "outages": outs,
        "outage_minutes": sum(o["minutes"] for o in outs),
        "note": "Line values and events come from the FRITZ!Box; outages are minutes in which none of the "
                "internet targets answered a single ping from the Pi (per-minute values, kept "
                f"{core.cfg.retention.aggregate_days:g} days).",
    }


def _t(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


@router.get("/outages.csv")
async def outage_report(request: Request, days: int = Query(30, ge=1, le=730), locale: Literal["de", "en"] = "de"):
    """Outage report for the provider: our own measured outages plus the FRITZ!Box events around them."""
    core = request.app.state.core
    end = int(time.time()) + 1
    start = end - days * 86400

    def q(c):
        return line.outages(c, start, end), _events(c, start, end, False)

    outs, events = await core.db.read(q)
    rows: list[list] = [
        ["Outage report", f"Network Lag Analyzer {__version__}"],
        ["Created", _t(time.time())],
        ["Period", f"{_t(start)} - {_t(end)}"],
        ["Method", "Minutes in which none of the internet targets answered a ping from inside the home network; "
                   "events from the FRITZ!Box event log within 5 minutes of the outage"],
        [],
        ["Start", "End", "Minutes", "FRITZ!Box events"],
    ]
    for o in outs:
        evs = line.match_events(o, events)
        rows.append([_t(o["start"]), _t(o["end"]), o["minutes"],
                     " | ".join(f"{_t(e['ts'])} {e['label']}: {e['msg']}" for e in sorted(evs, key=lambda e: e["ts"]))])
    rows += [[], ["Total", "", sum(o["minutes"] for o in outs), f"{len(outs)} outages"]]
    fn = f"outages-{time.strftime('%Y%m%d')}.csv"
    return StreamingResponse(csv_stream(rows, CsvFormat(locale)), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{fn}"', "Cache-Control": "no-store"})
