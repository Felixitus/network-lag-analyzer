"""Pi-hole actions from the web UI: pause blocking, allow or block a domain, restart DNS, update
the blocklists. Off unless enabled in the settings, every action needs `confirm: true`, and
every action is logged with the user and kept in a list."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from ..analysis.categories import normalize_domain, valid_domain
from ..collectors.pihole_api import PiholeApi, PiholeApiError
from ..database import repository as repo

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/pihole")
ACTIONS_KEY = "pihole_actions"


def _api(core) -> PiholeApi:
    p = core.cfg.pihole
    if not p.api_enabled:
        raise HTTPException(403, "Pi-hole actions are off - switch them on under Setup → Pi-hole actions.")
    return PiholeApi(p.api_url, p.api_password)


PUBLIC_ERRORS = {
    "no_password": "No Pi-hole app password configured",
    "rejected": "Pi-hole rejected the app password",
    "no_session": "Pi-hole gave no session",
    "http": "Pi-hole refused the request - details in the log",
}


def _error_text(e: Exception) -> str:
    """What the browser may see of a failure: a fixed text per kind of error, nothing of the exception.

    Exception texts can carry internal details (paths, addresses, library internals, an error
    message from Pi-hole); they go to the log only."""
    log.warning("Pi-hole API call failed: %s", e, exc_info=not isinstance(e, PiholeApiError))
    if isinstance(e, PiholeApiError):
        for kind, text in PUBLIC_ERRORS.items():
            if e.kind == kind:
                return text
    return "Pi-hole not reachable - details in the log"


async def _do(request: Request, action: str, fn, **detail):
    core = request.app.state.core
    api = _api(core)
    user = getattr(request.state, "username", None) or "?"
    entry = {"ts": time.time(), "user": user, "action": action, **detail}
    try:
        res = await asyncio.to_thread(fn, api)
        entry["ok"] = True
    except (PiholeApiError, OSError, Exception) as e:  # noqa: BLE001 - reported, logged, kept in the list
        entry.update(ok=False, error=_error_text(e))
        res = None
    log.warning("Pi-hole action by %s: %s %s -> %s", user, action, detail, "ok" if entry["ok"] else entry["error"])

    def w(c):
        lst = repo.get_setting(c, ACTIONS_KEY, [])
        lst.insert(0, entry)
        repo.set_setting(c, ACTIONS_KEY, lst[:100])
    await core.db.write(w)
    if not entry["ok"]:
        raise HTTPException(502, entry["error"])
    return {"ok": True, "result": res}


class Confirmed(BaseModel):
    confirm: bool = False

    def check(self) -> None:
        if self.confirm is not True:
            raise HTTPException(400, "Confirmation missing")


class BlockingBody(Confirmed):
    enabled: bool
    minutes: int | None = Field(None, ge=1, le=1440)     # pause length; None = until switched on again


class DomainBody(Confirmed):
    domain: str
    list: Literal["allow", "deny"]
    action: Literal["add", "remove"]

    @field_validator("domain")
    @classmethod
    def _d(cls, v: str) -> str:
        v = normalize_domain(v)
        if not valid_domain(v) or "." not in v:
            raise ValueError("Not a valid domain name")
        return v


@router.get("/state")
async def state(request: Request):
    core = request.app.state.core
    p = core.cfg.pihole
    actions = await core.db.read(lambda c: repo.get_setting(c, ACTIONS_KEY, []))
    out = {"enabled": p.api_enabled, "url": p.api_url, "password_set": bool(p.api_password), "actions": actions[:20],
           "blocking": None, "timer": None, "error": None}
    if p.api_enabled:
        try:
            out.update(await asyncio.to_thread(PiholeApi(p.api_url, p.api_password).blocking))
        except Exception as e:  # noqa: BLE001
            out["error"] = _error_text(e)
    return out


@router.get("/domain")
async def domain_state(request: Request, name: str):
    core = request.app.state.core
    d = normalize_domain(name)
    if not valid_domain(d):
        raise HTTPException(400, "Not a valid domain name")
    try:
        return await asyncio.to_thread(_api(core).domain_state, d)
    except PiholeApiError as e:
        raise HTTPException(502, _error_text(e)) from None


@router.post("/blocking")
async def blocking(request: Request, body: BlockingBody):
    body.check()
    secs = body.minutes * 60 if body.minutes and not body.enabled else None
    return await _do(request, "blocking on" if body.enabled else f"blocking paused {body.minutes or '∞'} min",
                     lambda a: a.set_blocking(body.enabled, secs))


@router.post("/domain")
async def domain(request: Request, body: DomainBody):
    body.check()
    comment = "added from the Network Lag Analyzer"
    fn = (lambda a: a.add_domain(body.list, body.domain, comment)) if body.action == "add" \
        else (lambda a: a.remove_domain(body.list, body.domain))
    return await _do(request, f"{body.action} {body.list}", fn, domain=body.domain)


@router.post("/restartdns")
async def restart_dns(request: Request, body: Confirmed):
    body.check()
    return await _do(request, "restart DNS", lambda a: a.restart_dns())


@router.post("/gravity")
async def gravity(request: Request, body: Confirmed):
    body.check()
    return await _do(request, "update blocklists", lambda a: a.update_gravity())
