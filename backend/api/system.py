"""Settings, setup wizard, login, system state."""
from __future__ import annotations

import asyncio
import shutil
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, ValidationError, field_validator

from .. import setup_wizard
from ..analysis import daily
from ..config import EDITABLE_SECTIONS
from ..database import repository as repo

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
    snaplen: int = Field(600, ge=64, le=1024)


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


@router.get("/backups")
async def backups(request: Request):
    from ..database import backup as bk
    core = core_of(request)
    last = await core.db.read(lambda c: repo.get_setting(c, "last_backup", None))
    return {"dir": str(core.backup_dir), "backups": await asyncio.to_thread(bk.list_backups, core.backup_dir),
            "last": last, "settings": core.cfg.backup.model_dump()}


@router.post("/backups/run")
async def backup_now(request: Request):
    core = core_of(request)
    res = await core._auto_backup(force=True)
    if not res or not res.get("ok"):
        raise HTTPException(500, (res or {}).get("error") or "Backup failed")
    return res


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
                raise ValueError(f"Unknown table: {t}")
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
    core.hub.drop_range(body.start, end)               # update the ring buffer too
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
