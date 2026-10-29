"""Raspberry Pi API: its own health, its network port, and where losses inside the home network lie."""
from __future__ import annotations

import time
from typing import Literal

from fastapi import APIRouter, Query, Request

from ..analysis import pi_health
from ..database import repository as repo

router = APIRouter(prefix="/api")

SPANS = {"24h": 86400, "7d": 7 * 86400}


def _capture(core) -> dict | None:
    """The capture process as it reports itself every 2 s; None when it is not running."""
    st = core.capture_status or {}
    if core.capture_proc is None or not st:
        return None
    keys = ("state", "source", "pps", "stream_kbps", "lag_s", "busy_pct", "level", "sni", "ring", "ts")
    return {**{k: st.get(k) for k in keys}, "guard_level": core.loadguard.level,
            "buffer": core.cfg.deep_capture.buffer if core.cfg.deep_capture.enabled else None}


def _names(c, start: float) -> dict:
    """HTTPS connections (port 443) with a measured server name, TCP and QUIC apart."""
    out = {}
    for proto, n, named in c.execute(
            "SELECT proto, COUNT(*), COUNT(sni) FROM network_flows WHERE ts_end>=? AND remote_port=443 "
            "AND proto IN ('tcp','udp') GROUP BY proto", (start,)):
        out["quic" if proto == "udp" else "tcp"] = {"flows": n, "named": named}
    return out


@router.get("/pi")
async def pi_page(request: Request, range: Literal["24h", "7d"] = Query("24h")):
    core = request.app.state.core
    end = int(time.time()) + 1
    start = end - SPANS[range]
    rows = await core.db.read(lambda c: [repo.decode_pi_health(r) for r in c.execute(
        "SELECT * FROM pi_health WHERE ts>=? AND ts<? ORDER BY ts", (start, end))])
    names = await core.db.read(lambda c: _names(c, start))
    d = pi_health.deltas(rows)
    th = core.hub.target_health()
    refs = [t for t in th if t["kind"] in ("gateway", "lan")]
    return {
        "health": core.pi_health,
        "service": {"version": core.version, "uptime_s": time.time() - core.started_at},
        "verdict": core.link_verdict(),
        "lan_reference": core.cfg.lan_reference,
        "link_targets": refs,
        "capture": _capture(core),
        "names": names,
        "series": {
            "ts": [r["ts"] for r in rows],
            "temp_c": [r["temp_c"] for r in rows], "cpu_pct": [r["cpu_pct"] for r in rows],
            "mem_avail_mb": [r["mem_avail_mb"] for r in rows],
            "carrier_changes": [x["carrier_changes"] for x in d], "rx_errors": [x["rx_errors"] for x in d],
        },
        "note": "Values from the kernel (sysfs/procfs) once a minute. Port counters per minute; after a reboot "
                "they start again from zero.",
    }
