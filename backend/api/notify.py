"""Notifications: state, the last messages, and a test message to every configured channel."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ..analysis.alerts import Message
from ..collectors import notify as nt

router = APIRouter(prefix="/api/notify")


@router.get("")
async def notify_state(request: Request):
    core = request.app.state.core
    n = core.cfg.notify
    return {"enabled": n.enabled, "channels": nt.channels(n), "active": core.alerts.active(),
            "log": list(core.notify_log)}


@router.post("/test")
async def notify_test(request: Request):
    core = request.app.state.core
    if not nt.channels(core.cfg.notify):
        raise HTTPException(400, "No channel configured - enter an ntfy address, a Telegram bot or an SMTP server first.")
    res = await core._send(Message("test", "Test message",
                                   "If you can read this, notifications from the Network Lag Analyzer arrive.", "default", "test"))
    return {"result": res}
