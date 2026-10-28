"""Incidents, events, lag report and PCAP download."""
from __future__ import annotations

import json
import os
import zipfile
from io import BytesIO
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from ..analysis.events import EVENT_LABELS
from ..analysis.root_cause import CATEGORY_LABELS
from ..database import repository as repo
from . import dns, paths

router = APIRouter(prefix="/api")


def core_of(request: Request):
    return request.app.state.core


class LagReport(BaseModel):
    window: Literal[10, 30, 60, 300] = 30


@router.post("/lag-report")
async def lag_report(request: Request, body: LagReport | None = None):
    core = core_of(request)
    return await core.report_lag((body or LagReport()).window)


@router.get("/incidents")
async def incidents(request: Request, limit: int = Query(50, ge=1, le=500), before: int | None = None,
                    source: Literal["auto", "user"] | None = None, session_id: int | None = None):
    core = core_of(request)

    def q(c):
        sql = ("SELECT id, source, ts_start, ts_end, reported_at, title, cause, category, confidence, session_id, "
               "analysis FROM incidents WHERE 1=1")
        args: list = []
        if before:
            sql += " AND id < ?"
            args.append(before)
        if source:
            sql += " AND source = ?"
            args.append(source)
        if session_id:
            sql += " AND session_id = ?"
            args.append(session_id)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in c.execute(sql, args)]
    await core.db.flush()
    rows = await core.db.read(q)
    for r in rows:
        a = repo.dec_analysis(r.pop("analysis"))       # compressed: json_extract cannot look inside
        r["metrics"] = a.get("metrics")
        r["device"] = a.get("device")
        r["category_label"] = CATEGORY_LABELS.get(r["category"] or "", r["category"])
    return {"incidents": rows}


@router.get("/incidents/{incident_id}")
async def incident(request: Request, incident_id: int):
    core = core_of(request)
    await core.db.flush()

    def q(c):
        r = c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if r is None:
            return None
        d = dict(r)
        d["analysis"] = repo.dec_analysis(d["analysis"])
        d["events"] = [dict(e) | {"details": json.loads(e["details"] or "{}"), "label": EVENT_LABELS.get(e["type"])}
                       for e in c.execute("SELECT * FROM events WHERE incident_id=? ORDER BY ts_start", (incident_id,))]
        t0 = (d["ts_start"] or 0) - 30
        t1 = (d["ts_end"] or d["ts_start"]) + 5
        d["flows"] = [dict(f) for f in c.execute(
            "SELECT * FROM network_flows WHERE ts_start <= ? AND ts_end >= ? ORDER BY bytes_up + bytes_down DESC LIMIT 25",
            (t1, t0))]
        d["pcap_files"] = [dict(p) for p in c.execute(
            "SELECT id, ts_start, ts_end, size, protected FROM pcap_files WHERE ts_start <= ? AND COALESCE(ts_end, ts_start) >= ?",
            (t1, t0))]
        # Started during the incident or a little after a lag report (the measurement starts when it is reported)
        d["traceroutes"] = repo.load_traces(c, d["ts_start"] - 5, (d["ts_end"] or d["ts_start"]) + 30, limit=6)
        return d
    d = await core.db.read(q)
    if d is None:
        raise HTTPException(404, "Incident not found")
    d["category_label"] = CATEGORY_LABELS.get(d.get("category") or "", d.get("category"))
    # Flows running at that time (from the 5 s snapshots), if still in memory
    t0, t1 = d["ts_start"] - 10, (d["ts_end"] or d["ts_start"]) + 5
    snaps = [f for ts, fl in core.active_flows if t0 <= ts <= t1 for f in fl]
    agg: dict[tuple, dict] = {}
    for f in snaps:
        k = (f["proto"], f["local_ip"], f["local_port"], f["remote_ip"], f["remote_port"])
        a = agg.setdefault(k, {**f, "recent_bytes": 0})
        a["recent_bytes"] += f["recent_bytes"]
    d["active_flows"] = sorted(({**f, "device": core.devices.label(f["mac"])["name"],
                                 "dns_name": core.devices.ip_names.get(f["remote_ip"])} for f in agg.values()),
                               key=lambda f: -f["recent_bytes"])[:20]
    for f in d["flows"]:
        f["device"] = core.devices.label(f["mac"])["name"] if f["mac"] else None
    d["traceroutes"] = paths.with_assessment(d["traceroutes"], paths.target_names(core))
    d["dns_upstreams"] = await dns.upstream_report(core, d["ts_start"] - 60, (d["ts_end"] or d["ts_start"]) + 60)
    d["deep_capture_enabled"] = core.cfg.deep_capture.enabled
    return d


@router.get("/incidents/{incident_id}/pcap")
async def incident_pcap(request: Request, incident_id: int):
    core = core_of(request)
    if not core.cfg.deep_capture.enabled:
        raise HTTPException(404, "Deep Capture is disabled")
    await core.db.flush()
    inc = await core.db.read(lambda c: c.execute("SELECT ts_start, ts_end FROM incidents WHERE id=?",
                                                 (incident_id,)).fetchone())
    if inc is None:
        raise HTTPException(404, "Incident not found")
    t0, t1 = inc["ts_start"] - 30, (inc["ts_end"] or inc["ts_start"]) + 5
    files = await core.db.read(lambda c: [r["path"] for r in c.execute(
        "SELECT path FROM pcap_files WHERE ts_start <= ? AND COALESCE(ts_end, ts_start) >= ? ORDER BY ts_start",
        (t1, t0))])
    pcap_dir = os.path.realpath(os.path.join(core.cfg.data_dir, "pcap"))
    files = [f for f in files if os.path.realpath(f).startswith(pcap_dir + os.sep) and os.path.exists(f)]
    if not files:
        raise HTTPException(404, "No PCAP files (left) for this time span")
    if len(files) == 1:
        return FileResponse(files[0], media_type="application/vnd.tcpdump.pcap",
                            filename=f"incident-{incident_id}.pcap")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            z.write(f, arcname=os.path.basename(f))
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/zip",
                             headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}-pcap.zip"'})


@router.get("/events")
async def events(request: Request, start: float | None = None, end: float | None = None,
                 limit: int = Query(200, ge=1, le=2000), type: str | None = None):
    core = core_of(request)

    def q(c):
        sql = "SELECT * FROM events WHERE 1=1"
        args: list = []
        if start is not None:
            sql += " AND COALESCE(ts_end, ts_start) >= ?"
            args.append(start)
        if end is not None:
            sql += " AND ts_start <= ?"
            args.append(end)
        if type:
            sql += " AND type = ?"
            args.append(type)
        sql += " ORDER BY ts_start DESC LIMIT ?"
        args.append(limit)
        return [dict(r) | {"details": json.loads(r["details"] or "{}"), "label": EVENT_LABELS.get(r["type"])}
                for r in c.execute(sql, args)]
    await core.db.flush()
    rows = await core.db.read(q)
    for r in rows:
        if r.get("mac"):
            r["device"] = core.devices.label(r["mac"])
    return {"events": rows, "open": [e.to_dict() for e in core.events.open_events()]}
