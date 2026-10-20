"""Gaming Sessions."""
from __future__ import annotations

import ipaddress
import json

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, field_validator

router = APIRouter(prefix="/api/gaming")


def core_of(request: Request):
    return request.app.state.core


class StartBody(BaseModel):
    device_ip: str | None = None

    @field_validator("device_ip")
    @classmethod
    def _ip(cls, v):
        return str(ipaddress.IPv4Address(v)) if v else None


@router.post("/start")
async def start(request: Request, body: StartBody | None = None):
    core = core_of(request)
    ip = (body.device_ip if body else None) or core.cfg.gaming_pc.ip
    return await core.start_gaming(auto=False, device_ip=ip)


@router.post("/stop")
async def stop(request: Request):
    core = core_of(request)
    res = await core.stop_gaming()
    if res is None:
        raise HTTPException(409, "Keine Gaming Session aktiv")
    return res


@router.get("/current")
async def current(request: Request):
    core = core_of(request)
    return {"session": core.gaming.to_dict() if core.gaming else None,
            "candidates": [c | {"device": core.devices.label(c["mac"])["name"]} for c in core.udp_candidates]}


@router.get("/sessions")
async def sessions(request: Request, limit: int = Query(30, ge=1, le=500)):
    core = core_of(request)
    await core.db.flush()
    rows = await core.db.read(lambda c: [dict(r) for r in c.execute(
        "SELECT * FROM gaming_sessions ORDER BY id DESC LIMIT ?", (limit,))])
    for r in rows:
        r["summary"] = json.loads(r["summary"]) if r["summary"] else None
    return {"sessions": rows, "active": core.gaming.to_dict() if core.gaming else None}


@router.get("/sessions/{sid}")
async def session(request: Request, sid: int):
    core = core_of(request)
    await core.db.flush()
    r = await core.db.read(lambda c: c.execute("SELECT * FROM gaming_sessions WHERE id=?", (sid,)).fetchone())
    if r is None:
        raise HTTPException(404, "Session nicht gefunden")
    d = dict(r)
    d["summary"] = json.loads(d["summary"]) if d["summary"] else None
    d["incidents"] = await core.db.read(lambda c: [dict(x) for x in c.execute(
        "SELECT id, source, ts_start, ts_end, title, cause, category, confidence FROM incidents "
        "WHERE session_id=? ORDER BY ts_start", (sid,))])
    return d
