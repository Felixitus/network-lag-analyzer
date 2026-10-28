"""Login, logout, password change, health check."""
from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import security as s

router = APIRouter(prefix="/api")

# Brake against guessing from the LAN: per address 5 failed attempts per 15 minutes,
# and for all addresses together 30 - so that changing the IP (or MAC) does not
# buy unlimited attempts. In memory is enough: a restart takes longer than a guess.
LOGIN_MAX_FAILS = 5
LOGIN_MAX_FAILS_TOTAL = 30
LOGIN_WINDOW = 15 * 60
FAIL_DELAY = 0.5
_login_fails: dict[str, list[float]] = {}


def core_of(request: Request):
    return request.app.state.core


def _recent(now: float) -> dict[str, list[float]]:
    for ip in list(_login_fails):
        fails = [t for t in _login_fails[ip] if now - t < LOGIN_WINDOW]
        if fails:
            _login_fails[ip] = fails
        else:
            del _login_fails[ip]                       # otherwise the dict grows with every IP
    return _login_fails


def _set_cookie(response: Response, token: str, hours: float) -> None:
    response.set_cookie(s.SESSION_COOKIE, token, httponly=True, samesite="strict", max_age=int(hours * 3600),
                        path="/")


class LoginBody(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class PasswordBody(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)
    new_username: str | None = Field(None, max_length=64)


class LogoutBody(BaseModel):
    everywhere: bool = False


@router.get("/health")
async def health(request: Request):
    """For monitoring and systemd checks. Deliberately reveals nothing but up/down."""
    core = core_of(request)
    try:
        await core.db.read(lambda c: c.execute("SELECT 1").fetchone())
        db_ok = True
    except Exception:          # noqa: BLE001 - any database error means "degraded"
        db_ok = False
    return {"status": "ok" if db_ok else "degraded"}


@router.get("/auth/state")
async def auth_state(request: Request):
    core = core_of(request)
    token = request.cookies.get(s.SESSION_COOKIE)

    def q(c):
        acc = s.get_account(c)
        sess = s.check_session(c, token, core.cfg.security.idle_hours) if acc else None
        return acc is not None, sess
    exists, sess = await core.db.read(q)
    return {"login_required": core.login_required, "account_exists": exists,
            "logged_in": sess is not None, "username": sess["username"] if sess else None}


@router.post("/auth/login")
async def login(request: Request, body: LoginBody, response: Response):
    core = core_of(request)
    ip = s.client_ip(request)
    now = time.time()
    fails = _recent(now)
    if len(fails.get(ip, ())) >= LOGIN_MAX_FAILS or sum(map(len, fails.values())) >= LOGIN_MAX_FAILS_TOTAL:
        raise HTTPException(429, "Too many failed attempts - please try again in 15 minutes",
                            headers={"Retry-After": str(LOGIN_WINDOW)})
    account = await core.db.read(s.get_account)
    if account is None:
        raise HTTPException(403, "No account set up yet - create it on the Raspberry Pi (see README)")
    # Counted before the check: attempts sent in parallel would otherwise all pass the limit
    # while the first ones are still being verified.
    _login_fails.setdefault(ip, []).append(now)
    ok = await asyncio.to_thread(s.verify_login, account, body.username, body.password)
    if not ok:
        await asyncio.sleep(FAIL_DELAY)
        # Same message for wrong username and wrong password.
        raise HTTPException(401, "Wrong username or password")
    _login_fails.pop(ip, None)
    hours = core.cfg.security.session_hours
    token = await core.db.write(lambda c: s.create_session(c, account["username"], hours, ip))
    _set_cookie(response, token, hours)
    return {"ok": True, "username": account["username"]}


@router.post("/auth/logout")
async def logout(request: Request, response: Response, body: LogoutBody | None = None):
    core = core_of(request)
    token = request.cookies.get(s.SESSION_COOKIE)
    if body and body.everywhere:
        n = await core.db.write(lambda c: s.revoke_all(c))
    else:
        await core.db.write(lambda c: s.revoke(c, token))
        n = 1
    response.delete_cookie(s.SESSION_COOKIE, path="/")
    return {"ok": True, "ended": n}


@router.post("/auth/password")
async def change_password(request: Request, body: PasswordBody):
    """Change password (and optionally username). Ends all other sessions."""
    core = core_of(request)
    account = await core.db.read(s.get_account)
    if account is None:
        raise HTTPException(403, "No account set up yet")
    if not await asyncio.to_thread(s.verify_password, body.current_password, account["password_hash"]):
        await asyncio.sleep(FAIL_DELAY)
        raise HTTPException(403, "Current password is wrong")
    username = (body.new_username or "").strip() or account["username"]
    err = s.account_input_problem(username, body.new_password)
    if err:
        raise HTTPException(400, err)
    token = request.cookies.get(s.SESSION_COOKIE)
    await core.db.write(lambda c: s.set_account(c, username, body.new_password, keep_session=token))
    return {"ok": True, "username": username}
