"""Sicherheit: optionaler Login, CSRF-Schutz (Double-Submit-Token), Security-Header.

* CSRF: Beim Laden der Seite wird ein Cookie `nla_csrf` gesetzt (SameSite=Strict).
  Jeder schreibende API-Request muss denselben Wert im Header `X-CSRF-Token` senden.
  Fremde Webseiten können den Cookie nicht lesen und damit keinen gültigen Request bauen.
* Login (optional): scrypt-Passworthash, signiertes Session-Cookie (HMAC-SHA256).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

CSRF_COOKIE = "nla_csrf"
CSRF_HEADER = "x-csrf-token"
SESSION_COOKIE = "nla_session"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
OPEN_API = {"/api/auth/state", "/api/auth/login"}


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


class SessionSigner:
    def __init__(self, data_dir: str):
        p = Path(data_dir) / "session.key"
        if p.exists():
            self.key = p.read_bytes()
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            self.key = secrets.token_bytes(32)
            p.write_bytes(self.key)
            os.chmod(p, 0o600)

    def sign(self, hours: int) -> str:
        exp = str(int(time.time() + hours * 3600))
        sig = hmac.new(self.key, exp.encode(), hashlib.sha256).hexdigest()
        return f"{exp}.{sig}"

    def valid(self, token: str | None) -> bool:
        if not token or "." not in token:
            return False
        exp, sig = token.split(".", 1)
        good = hmac.new(self.key, exp.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, good) and exp.isdigit() and int(exp) > time.time()


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, core, signer: SessionSigner):
        super().__init__(app)
        self.core = core
        self.signer = signer

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/"):
            sec = self.core.cfg.security
            if sec.login_enabled and sec.password_hash and path not in OPEN_API:
                if not self.signer.valid(request.cookies.get(SESSION_COOKIE)):
                    return JSONResponse({"detail": "Login erforderlich"}, status_code=401)
            if request.method in UNSAFE:
                cookie = request.cookies.get(CSRF_COOKIE)
                header = request.headers.get(CSRF_HEADER)
                if not cookie or not header or not hmac.compare_digest(cookie, header):
                    return JSONResponse({"detail": "CSRF-Token fehlt oder ungültig"}, status_code=403)
                origin = request.headers.get("origin")
                host = request.headers.get("host")
                if origin and host and origin.split("://", 1)[-1] != host:
                    return JSONResponse({"detail": "Fremde Herkunft abgelehnt"}, status_code=403)
        response = await call_next(request)
        if CSRF_COOKIE not in request.cookies and not path.startswith("/api/stream"):
            response.set_cookie(CSRF_COOKIE, secrets.token_urlsafe(24), samesite="strict", httponly=False,
                                max_age=365 * 86400)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'")
        return response
