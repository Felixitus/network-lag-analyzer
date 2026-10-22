"""Device list, renaming, DNS activity per device (Pi-hole)."""
from __future__ import annotations

import json
import re
import time

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator

from ..util.netinfo import normalize_mac

router = APIRouter(prefix="/api")


def core_of(request: Request):
    return request.app.state.core


class DevicePatch(BaseModel):
    custom_name: str | None = Field(None, max_length=64)
    gaming_pc: bool | None = None

    @field_validator("custom_name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if v and not re.fullmatch(r"[\w\-\.\s()äöüÄÖÜß'+#&/]{1,64}", v):
            raise ValueError("Name contains invalid characters")
        return v or None


@router.get("/devices")
async def devices(request: Request):
    core = core_of(request)
    items = core.devices.all()
    now = core.hub.last_finalized
    # attach current rates (last 10 s)
    rates: dict[str, list[float]] = {}
    rows = core.hub.window(10, now) if now else []
    for r in rows:
        for mac, v in (r.get("devices") or {}).items():
            a = rates.setdefault(mac, [0.0, 0.0])
            a[0] += v[0] * 8
            a[1] += v[1] * 8
    n = max(1, len(rows))
    gaming_ip = core.cfg.gaming_pc.ip
    for d in items:
        a = rates.get(d["mac"])
        d["down_bps"] = a[0] / n if a else (0.0 if core.hub.capture_active() else None)
        d["up_bps"] = a[1] / n if a else (0.0 if core.hub.capture_active() else None)
        d["gaming_pc"] = bool(gaming_ip and d["ip"] == gaming_ip)
    return {"devices": items, "traffic_available": core.hub.capture_active()}


@router.post("/devices/refresh-names")
async def refresh_names(request: Request):
    """Forget learned host names and IPs and ask Pi-hole, its DHCP leases and the
    FRITZ!Box again right away. User aliases are kept."""
    core = core_of(request)
    res = await core.refresh_device_names()
    for ch in res["changed"]:
        dev = core.devices.by_mac.get(ch["mac"])
        ch["alias"] = dev.custom_name if dev else None
    return res


@router.patch("/devices/{mac}")
async def patch_device(request: Request, mac: str, body: DevicePatch):
    core = core_of(request)
    m = normalize_mac(mac)
    if not m or m not in core.devices.by_mac:
        raise HTTPException(404, "Device not found")
    dev = core.devices.by_mac[m]
    if "custom_name" in body.model_fields_set:
        core.devices.rename(m, body.custom_name)
        await core.db.write(lambda c: c.execute("UPDATE devices SET custom_name=? WHERE mac=?", (body.custom_name, m)))
    if body.gaming_pc is not None:
        if body.gaming_pc and not dev.ip:
            raise HTTPException(400, "Device has no known IPv4 address")
        await core.update_settings({"gaming_pc": {"ip": dev.ip if body.gaming_pc else None,
                                                  "name": dev.display_name}})
    return dev.to_dict()


@router.get("/devices/{mac}/dns")
async def device_dns(request: Request, mac: str, minutes: int = Query(60, ge=1, le=1440)):
    """DNS activity according to Pi-hole. Note: NOT a measure of bandwidth."""
    core = core_of(request)
    m = normalize_mac(mac)
    dev = core.devices.by_mac.get(m or "")
    if dev is None or not dev.ip:
        raise HTTPException(404, "Device not found or has no IP")
    since = int(time.time()) - minutes * 60

    def q(c):
        return [dict(r) for r in c.execute(
            "SELECT ts, queries, blocked, top_domains FROM dns_queries WHERE client_ip=? AND ts>=? ORDER BY ts",
            (dev.ip, since))]
    rows = await core.db.read(q)
    top: dict[str, int] = {}
    for r in rows:
        for dom, n in json.loads(r["top_domains"] or "[]"):
            top[dom] = top.get(dom, 0) + n
        r.pop("top_domains")
    return {"ip": dev.ip, "available": bool(core.pihole_status.get("ok")), "minutes": rows,
            "top_domains": sorted(top.items(), key=lambda kv: -kv[1])[:20],
            "note": "DNS queries show activity, but not the bandwidth used."}
