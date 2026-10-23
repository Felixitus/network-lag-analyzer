"""Security: mandatory login, server-side sessions, CSRF protection, security headers.

* Account: one user (username + scrypt hash) in the settings table. It is created
  on the Pi with `python -m backend.account set` - never through the web UI, so that
  nobody on the LAN can claim a fresh installation before its owner does. Until an
  account exists the API answers only /api/health and /api/auth/state.
* Sessions: random 256-bit tokens in an HttpOnly, SameSite=Strict cookie. The
  database stores only their SHA-256, so a copy of the database (backup!) does not
  contain usable sessions. Logout deletes the session; a password change deletes
  all others. Absolute lifetime `session_hours`, plus `idle_hours` without requests.
  The cookie cannot be `Secure`: the UI is plain HTTP inside the LAN (use a VPN for
  remote access, never a port forwarding).
* CSRF: loading the page sets a cookie `nla_csrf` (SameSite=Strict). Every writing
  API request must send the same value in the `X-CSRF-Token` header, and a sent
  Origin must match the host. Foreign websites can neither read the cookie nor
  pass the Origin check.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ..database.repository import get_setting, set_setting

CSRF_COOKIE = "nla_csrf"
CSRF_HEADER = "x-csrf-token"
SESSION_COOKIE = "nla_session"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
OPEN_API = {"/api/auth/state", "/api/auth/login", "/api/health"}
ACCOUNT_KEY = "auth_account"
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
MIN_PASSWORD = 10
TOUCH_SECONDS = 300          # last_seen is written at most this often per session


# ------------------------------------------------------------------ passwords
def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        h = hashlib.scrypt(pw.encode("utf-8"), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(h.hex(), digest)
    except (ValueError, TypeError):
        return False


# A hash to verify against when the username is wrong, so that a wrong username
# takes as long as a wrong password and does not reveal the account name.
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def account_input_problem(username: str, password: str) -> str | None:
    """Error message, or None if acceptable."""
    if not USERNAME_RE.match(username or ""):
        return "Username: 1-64 characters, letters, digits and . _ @ - only"
    if len(password or "") < MIN_PASSWORD:
        return f"Password: at least {MIN_PASSWORD} characters"
    if len(password) > 256:
        return "Password: at most 256 characters"
    if password.lower() == username.lower():
        return "Password must not be the username"
    return None


# ------------------------------------------------------------------ account
def get_account(conn) -> dict | None:
    a = get_setting(conn, ACCOUNT_KEY, None)
    return a if a and a.get("username") and a.get("password_hash") else None


def set_account(conn, username: str, password: str, keep_session: str | None = None) -> None:
    """Create or replace the account. Ends every session except `keep_session` (a token)."""
    err = account_input_problem(username, password)
    if err:
        raise ValueError(err)
    set_setting(conn, ACCOUNT_KEY, {"username": username, "password_hash": hash_password(password),
                                    "changed_at": time.time()})
    revoke_all(conn, except_token=keep_session)


def migrate_legacy(conn, legacy_hash: str) -> bool:
    """Before mandatory login there was an optional password without username.
    Keep it working as user "admin" instead of locking the owner out."""
    if get_account(conn) or not legacy_hash:
        return False
    set_setting(conn, ACCOUNT_KEY, {"username": "admin", "password_hash": legacy_hash,
                                    "changed_at": time.time(), "migrated": True})
    return True


def verify_login(account: dict | None, username: str, password: str) -> bool:
    if account is None:
        verify_password(password, _DUMMY_HASH)
        return False
    name_ok = hmac.compare_digest(username.encode(), account["username"].encode())
    pw_ok = verify_password(password, account["password_hash"] if name_ok else _DUMMY_HASH)
    return name_ok and pw_ok


# ------------------------------------------------------------------ sessions
def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(conn, username: str, hours: float, ip: str | None, now: float | None = None) -> str:
    now = time.time() if now is None else now
    token = secrets.token_urlsafe(32)
    conn.execute("DELETE FROM auth_sessions WHERE expires < ?", (now,))
    conn.execute("INSERT INTO auth_sessions(id, username, created, expires, last_seen, ip) VALUES (?,?,?,?,?,?)",
                 (_digest(token), username, now, now + hours * 3600, now, ip))
    return token


def check_session(conn, token: str | None, idle_hours: float, now: float | None = None) -> dict | None:
    if not token or len(token) > 100:
        return None
    now = time.time() if now is None else now
    r = conn.execute("SELECT id, username, expires, last_seen FROM auth_sessions WHERE id = ?",
                     (_digest(token),)).fetchone()
    if r is None or r["expires"] < now or now - r["last_seen"] > idle_hours * 3600:
        return None
    return dict(r)


def revoke(conn, token: str | None) -> None:
    if token:
        conn.execute("DELETE FROM auth_sessions WHERE id = ?", (_digest(token),))


def revoke_all(conn, except_token: str | None = None) -> int:
    if except_token:
        return conn.execute("DELETE FROM auth_sessions WHERE id != ?", (_digest(except_token),)).rowcount
    return conn.execute("DELETE FROM auth_sessions").rowcount


def client_ip(request: Request) -> str:
    # proxy_headers is off in uvicorn: X-Forwarded-For cannot fake the address.
    return request.client.host if request.client else "?"


# ------------------------------------------------------------------ middleware
class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, core):
        super().__init__(app)
        self.core = core

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/"):
            if request.method in UNSAFE:
                cookie = request.cookies.get(CSRF_COOKIE)
                header = request.headers.get(CSRF_HEADER)
                if not cookie or not header or not hmac.compare_digest(cookie, header):
                    return JSONResponse({"detail": "CSRF token missing or invalid"}, status_code=403)
                origin = request.headers.get("origin")
                host = request.headers.get("host")
                if origin and host and origin.split("://", 1)[-1] != host:
                    return JSONResponse({"detail": "Cross-origin request rejected"}, status_code=403)
            if self.core.login_required and path not in OPEN_API:
                denied = await self._check_login(request)
                if denied is not None:
                    return denied
        response = await call_next(request)
        if CSRF_COOKIE not in request.cookies and not path.startswith("/api/stream"):
            response.set_cookie(CSRF_COOKIE, secrets.token_urlsafe(24), samesite="strict", httponly=False,
                                max_age=365 * 86400)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        if path.startswith("/api/"):
            # Device names, domains and settings must not end up in a browser or proxy cache.
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    async def _check_login(self, request: Request):
        core = self.core
        token = request.cookies.get(SESSION_COOKIE)
        sec = core.cfg.security

        def q(c):
            if get_account(c) is None:
                return "no-account", None
            return "ok", check_session(c, token, sec.idle_hours)
        state, sess = await core.db.read(q)
        if state == "no-account":
            return JSONResponse({"detail": "No account set up yet - create it on the Raspberry Pi with "
                                           "'python -m backend.account set' (see README).",
                                 "setup_required": True}, status_code=403)
        if sess is None:
            return JSONResponse({"detail": "Login required"}, status_code=401)
        now = time.time()
        if now - sess["last_seen"] > TOUCH_SECONDS:
            core.db.enqueue("UPDATE auth_sessions SET last_seen = ? WHERE id = ?", (now, sess["id"]))
        request.state.username = sess["username"]
        return None
