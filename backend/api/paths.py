"""Path measurements (traceroute): the stored ones, and one measured on request."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from ..analysis import path
from ..database import repository as repo

router = APIRouter(prefix="/api/traceroutes")


def with_assessment(traces: list[dict], names: dict[int, str]) -> list[dict]:
    out = []
    for t in traces:
        a = path.assess(t)
        out.append({**t, "name": names.get(t.get("target_id")), "hops": a.get("hops", t.get("hops")),
                    "verdict": a["verdict"], "findings": a["findings"]})
    return out


def target_names(core) -> dict[int, str]:
    return {t["target_id"]: t.get("name") or t["address"] for t in core.trace_targets()}


@router.get("")
async def traceroutes(request: Request, limit: int = Query(10, ge=1, le=100)):
    core = request.app.state.core
    await core.db.flush()
    rows = await core.db.read(lambda c: repo.load_traces(c, limit=limit))
    return {"traceroutes": with_assessment(rows, target_names(core)),
            "targets": [{"target_id": t["target_id"], "name": t.get("name") or t["address"], "kind": t["kind"]}
                        for t in core.trace_targets() if t["kind"] in ("internet", "game")],
            "busy": core.tracer.busy, "enabled": core.cfg.traceroute.enabled}


class RunBody(BaseModel):
    target_id: int


@router.post("")
async def run_traceroute(request: Request, body: RunBody):
    core = request.app.state.core
    if core.cfg.dev_mode:
        raise HTTPException(400, "Not available in demo mode - a path measurement needs the real network.")
    t = next((t for t in core.trace_targets() if t["target_id"] == body.target_id), None)
    if t is None:
        raise HTTPException(404, "Target not found")
    if core.tracer.busy:
        raise HTTPException(409, "A path measurement is already running - try again in a few seconds.")
    res = await core.run_traces([t], "manual")
    return {"traceroutes": with_assessment(res, target_names(core))}
