"""Settings, setup wizard, login, system state."""
from __future__ import annotations

import asyncio
import shutil
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, ValidationError, field_validator

from .. import setup_wizard
from ..analysis import daily
from ..config import EDITABLE_SECTIONS
from ..database import repository as repo
from .security import SESSION_COOKIE, hash_password, verify_password

router = APIRouter(prefix="/api")


def core_of(request: Request):
    return request.app.state.core


@router.get("/settings")
async def get_settings(request: Request):
    core = core_of(request)
    return {"config": core.cfg.public_dict(), "yaml_path": core.yaml_path,
            "editable": sorted(EDITABLE_SECTIONS)}


@router.put("/settings")
async def put_settings(request: Request, patch: dict):
    core = core_of(request)
    try:
        res = await core.update_settings(patch)
    except ValidationError as e:
        raise HTTPException(422, [{"loc": err["loc"], "msg": err["msg"]} for err in e.errors()]) from None
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    return {"ok": True, **res, "config": core.cfg.public_dict()}


@router.post("/settings/reset")
async def reset_settings(request: Request):
    """Resets all values changed via the web UI (config.yaml applies again)."""
    core = core_of(request)
    await core.db.write(lambda c: repo.set_setting(c, "config_overrides", {}))
    await core.update_settings({})
    return {"ok": True}


@router.get("/setup/check")
async def setup_check(request: Request, deep: bool = True):
    return await setup_wizard.run_checks(core_of(request), deep=deep)


class FritzTest(BaseModel):
    host: str = "auto"
    username: str = Field("", max_length=64)
    password: str = Field("", max_length=128)
    capture_interface: str = Field("1-lan", pattern=r"^[A-Za-z0-9_\-\.]{1,32}$")
    snaplen: int = Field(128, ge=64, le=256)


@router.post("/setup/fritzbox-test")
async def fritz_test(request: Request, body: FritzTest):
    core = core_of(request)
    pw = body.password
    if not pw or pw == "********":
        # Stored password only goes to the stored address - see Core.update_settings.
        if core.cfg.fritzbox.password and body.host.strip().lower() != core.cfg.fritzbox.host.strip().lower():
            raise HTTPException(400, "For a different address please enter the FRITZ!Box password")
        pw = core.cfg.fritzbox.password
    return await setup_wizard.test_fritz(core, body.host, body.username, pw, body.capture_interface, body.snaplen)


@router.post("/setup/complete")
async def setup_complete(request: Request):
    core = core_of(request)
    await core.db.write(lambda c: repo.set_setting(c, "setup_done", True))
    core.setup_done = True
    return {"ok": True}


@router.get("/system")
async def system(request: Request):
    core = core_of(request)
    return {"system": core.loadguard.last, "capture": core.capture_status, "db": core.db.stats,
            "late_traffic_bins": core.hub.late_traffic, "clock_jumps": core.clock_jumps,
            "migration": core.db.migration}


# ------------------------------------------------------------------ database
@router.get("/database")
async def database(request: Request):
    """Space used per table, oldest data point, state of the size limit."""
    core = core_of(request)
    size, tables, oldest = await core.db.read(
        lambda c: (repo.db_size(c), repo.table_sizes(c), repo.oldest_data(c)))
    return {
        "path": core.db.path, "size": size, "tables": tables, "oldest": oldest,
        "limit_mb": core.cfg.retention.max_db_mb, "guard": core.db_guard,
        "retention": core.cfg.retention.model_dump(),
        "protected": list(repo.PROTECTED_TABLES),
        "free_disk": _free_disk(core.db.path),
        # PCAP files live NEXT TO the database and do not count towards its size -
        # they were the real space hog and therefore belong here.
        "pcap": await asyncio.to_thread(core.pcap_usage),
        "deep_capture": core.cfg.deep_capture.model_dump(),
    }


@router.post("/database/pcap-cleanup")
async def pcap_cleanup(request: Request):
    """Bring captures down to the configured budget right away."""
    core = core_of(request)
    before = await asyncio.to_thread(core.pcap_usage)
    await core._cleanup_pcaps()
    await core.db.flush()
    after = await asyncio.to_thread(core.pcap_usage)
    return {"before": before, "after": after, "freed_bytes": before["bytes"] - after["bytes"],
            "note": None if core.capture_proc is None or not core.cfg.deep_capture.enabled else
            "The running capture keeps its current files - they are removed at the next "
            "rotation."}


def _free_disk(path: str) -> int | None:
    try:
        return shutil.disk_usage(Path(path).parent).free
    except OSError:                                    # pragma: no cover
        return None


class DeleteRange(BaseModel):
    """Range to delete. Omitting `start` means "everything before"."""
    start: float | None = None
    end: float
    tables: list[str] | None = None
    confirm: str = Field("", description="Safety confirmation for deleting: must be 'DELETE'")

    @field_validator("tables")
    @classmethod
    def _known(cls, v):
        for t in v or []:
            if t not in repo.TIME_TABLES:
                raise ValueError(f"Unbekannte Tabelle: {t}")
        return v


@router.post("/database/preview")
async def database_preview(request: Request, body: DeleteRange):
    """How many rows would be affected? Shown before deleting."""
    core = core_of(request)
    names = body.tables or list(repo.TIME_TABLES)
    counts = await core.db.read(lambda c: repo.count_range(c, body.start, body.end, names))
    return {"start": body.start, "end": body.end, "counts": counts, "total": sum(counts.values())}


@router.post("/database/delete")
async def database_delete(request: Request, body: DeleteRange):
    core = core_of(request)
    if body.confirm != "DELETE":
        raise HTTPException(400, "Safety confirmation not given")
    # An end date in the future means "until now" - it is clamped to the current
    # time so that data being measured during the request is not deleted.
    end = min(body.end, time.time())
    if body.start is not None and body.start >= end:
        raise HTTPException(400, "The start date is not before the end date")
    deleted = await core.db.write(lambda c: repo.delete_range(c, body.start, end, body.tables))
    freed = await core.db.maintenance(repo.vacuum)
    size = await core.db.read(repo.db_size)
    core.hub.drop_range(body.start, end)               # Ringpuffer nachziehen
    return {"deleted": deleted, "total": sum(deleted.values()), "freed_bytes": freed["freed"],
            "size": size, "end": end}


@router.post("/database/vacuum")
async def database_vacuum(request: Request):
    """Shrink the file. After lowering retention it does not shrink otherwise."""
    core = core_of(request)
    return await core.db.maintenance(repo.vacuum)


@router.get("/daily")
async def daily_stats(request: Request, days: int = Query(90, ge=1, le=3650)):
    """Daily summary for long-term comparison."""
    core = core_of(request)
    return {"days": await core.db.read(lambda c: daily.read(c, days))}


# ------------------------------------------------------------------ Login
class LoginBody(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)


class AuthSetup(BaseModel):
    enabled: bool
    password: str | None = Field(None, min_length=8, max_length=256)
    current_password: str | None = None


@router.get("/auth/state")
async def auth_state(request: Request):
    core = core_of(request)
    sec = core.cfg.security
    signer = request.app.state.signer
    return {"login_enabled": bool(sec.login_enabled and sec.password_hash),
            "logged_in": signer.valid(request.cookies.get(SESSION_COOKIE))}


LOGIN_MAX_FAILS = 5
LOGIN_WINDOW = 15 * 60
_login_fails: dict[str, list[float]] = {}


def _recent_fails(ip: str, now: float) -> list[float]:
    fails = [t for t in _login_fails.get(ip, []) if now - t < LOGIN_WINDOW]
    if fails:
        _login_fails[ip] = fails
    else:
        _login_fails.pop(ip, None)                     # otherwise the dict grows with every IP
    return fails


@router.post("/auth/login")
async def login(request: Request, body: LoginBody, response: Response):
    core = core_of(request)
    sec = core.cfg.security
    if not (sec.login_enabled and sec.password_hash):
        return {"ok": True}
    # Brake against guessing from the LAN: after 5 failed attempts per address
    # a 15-minute pause. In memory is enough - a restart takes longer than an attempt.
    ip = request.client.host if request.client else "?"
    now = time.time()
    if len(_recent_fails(ip, now)) >= LOGIN_MAX_FAILS:
        raise HTTPException(429, "Too many failed attempts - please try again later")
    if not verify_password(body.password, sec.password_hash):
        _login_fails.setdefault(ip, []).append(now)
        raise HTTPException(401, "Wrong password")
    _login_fails.pop(ip, None)
    token = request.app.state.signer.sign(sec.session_hours)
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict", max_age=sec.session_hours * 3600)
    return {"ok": True}


@router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@router.post("/auth/setup")
async def auth_setup(request: Request, body: AuthSetup, response: Response):
    """Enable/disable login or change the password."""
    core = core_of(request)
    sec = core.cfg.security
    if sec.password_hash and not verify_password(body.current_password or "", sec.password_hash):
        raise HTTPException(403, "Current password is wrong")
    new_hash = hash_password(body.password) if body.password else sec.password_hash
    if body.enabled and not new_hash:
        raise HTTPException(400, "Password (at least 8 characters) required")

    def _save(c):
        o = repo.get_setting(c, "config_overrides", {})
        o["security"] = {"login_enabled": body.enabled, "password_hash": new_hash if body.enabled else ""}
        repo.set_setting(c, "config_overrides", o)
    await core.db.write(_save)
    from ..config import build_config
    overrides = await core.db.read(lambda c: repo.get_setting(c, "config_overrides", {}))
    core.cfg = build_config(core.yaml_data, overrides)
    if body.enabled:
        token = request.app.state.signer.sign(core.cfg.security.session_hours)
        response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict",
                            max_age=core.cfg.security.session_hours * 3600)
    return {"ok": True, "login_enabled": body.enabled}
