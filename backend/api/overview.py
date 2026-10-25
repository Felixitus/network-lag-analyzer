"""Overview API: status lights, timeline of the last hours, restarts and incidents in it."""
from __future__ import annotations

import time
from typing import Literal

from fastapi import APIRouter, Query, Request

from ..analysis import line, overview as ov, presence
from ..database import repository as repo

router = APIRouter(prefix="/api")

# range → (seconds, bucket seconds): 144 cells for a day, 168 for a week
SPANS = {"24h": (86400, 600), "7d": (604800, 3600)}


@router.get("/overview")
async def overview(request: Request, range: Literal["24h", "7d"] = Query("24h")):
    core = request.app.state.core
    secs, bucket = SPANS[range]
    end = (int(time.time()) // bucket + 1) * bucket
    start = end - secs
    th, gateway = core.cfg.thresholds, core.gateway

    def q(c):
        tl = ov.timeline(c, th, gateway, start, end, bucket)
        incidents = [dict(r) for r in c.execute(
            """SELECT id, source, ts_start, ts_end, title, cause, category, confidence FROM incidents
               WHERE ts_start < ? AND COALESCE(ts_end, ts_start) >= ? ORDER BY ts_start""", (end, start))]
        log = repo.get_setting(c, ov.RESTART_LOG_KEY, [])
        events = [{"ts": r[0], "kind": r[1], "label": line.KIND_LABELS.get(r[1], r[1])} for r in c.execute(
            f"SELECT ts, kind FROM fritz_events WHERE ts>=? AND ts<? AND kind IN ({','.join('?' * len(line.LINE_KINDS))})",
            (start, end, *line.LINE_KINDS))]
        return tl, incidents, log, events, repo.get_setting(c, presence.ACK_KEY, {})

    tl, incidents, log, line_events, acked = await core.db.read(q)
    devs = core.devices.all()
    new = presence.new_devices(devs, acked, start)
    lights = ov.lights(core) + [ov.devices_light(core, new, presence.unknown_devices(devs, acked))]
    return {"now": time.time(), "lights": lights, "timeline": tl, "incidents": incidents,
            "restarts": ov.restarts(log, start, end), "line_events": line_events,
            "new_devices": [{"ts": d["first_seen"], "name": d["name"], "mac": d["mac"]} for d in new],
            "note": "Each cell sums the stored per-minute measurements. Hatched: nothing was measured."}
