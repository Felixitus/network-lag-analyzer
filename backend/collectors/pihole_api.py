"""Pi-hole v6 API - the only way this program changes Pi-hole, and only on a click.

Everything else reads FTL's database read-only. Each action logs in with an app password,
does one thing and logs out again: Pi-hole allows only a few sessions, and a session left
open would count against the web interface's own logins. Blocking.
"""
from __future__ import annotations

from urllib.parse import quote

import httpx


class PiholeApiError(RuntimeError):
    pass


class PiholeApi:
    def __init__(self, base_url: str, app_password: str, timeout: float = 10.0, transport=None):
        self.base = base_url.rstrip("/") + "/api"
        self.password = app_password
        self.timeout = timeout
        self._transport = transport

    def _client(self) -> httpx.Client:
        # The local web server of Pi-hole uses a self-signed certificate for https.
        return httpx.Client(timeout=self.timeout, verify=False, transport=self._transport)

    def _session(self, c: httpx.Client) -> str:
        if not self.password:
            raise PiholeApiError("No Pi-hole app password configured")
        r = c.post(f"{self.base}/auth", json={"password": self.password})
        if r.status_code == 401:
            raise PiholeApiError("Pi-hole rejected the app password")
        r.raise_for_status()
        sid = ((r.json() or {}).get("session") or {}).get("sid")
        if not sid:
            raise PiholeApiError("Pi-hole gave no session")
        return sid

    def call(self, method: str, path: str, json: dict | None = None, timeout: float | None = None) -> dict:
        with self._client() as c:
            sid = self._session(c)
            try:
                r = c.request(method, f"{self.base}{path}", json=json, headers={"X-FTL-SID": sid},
                              timeout=timeout or self.timeout)
                if r.status_code >= 400:
                    msg = ""
                    try:
                        msg = (r.json().get("error") or {}).get("message") or ""
                    except ValueError:
                        pass
                    raise PiholeApiError(f"Pi-hole answered HTTP {r.status_code} {msg}".strip())
                try:
                    return r.json() if r.content else {}
                except ValueError:
                    return {"text": r.text[-2000:]}
            finally:
                try:
                    c.delete(f"{self.base}/auth", headers={"X-FTL-SID": sid})
                except httpx.HTTPError:
                    pass

    # ------------------------------------------------------------------ actions
    def blocking(self) -> dict:
        d = self.call("GET", "/dns/blocking")
        return {"blocking": d.get("blocking"), "timer": d.get("timer")}

    def set_blocking(self, enabled: bool, seconds: int | None = None) -> dict:
        d = self.call("POST", "/dns/blocking", {"blocking": enabled, "timer": seconds})
        return {"blocking": d.get("blocking"), "timer": d.get("timer")}

    def domain_state(self, domain: str) -> dict:
        out = {}
        for lst in ("allow", "deny"):
            d = self.call("GET", f"/domains/{lst}/exact/{quote(domain, safe='')}")
            out[lst] = bool(d.get("domains"))
        return out

    def add_domain(self, lst: str, domain: str, comment: str) -> None:
        self.call("POST", f"/domains/{lst}/exact", {"domain": domain, "comment": comment, "enabled": True})

    def remove_domain(self, lst: str, domain: str) -> None:
        self.call("DELETE", f"/domains/{lst}/exact/{quote(domain, safe='')}")

    def restart_dns(self) -> None:
        self.call("POST", "/action/restartdns")

    def update_gravity(self) -> str:
        """Downloads the blocklists again; takes a minute or two. Returns the end of Pi-hole's output."""
        d = self.call("POST", "/action/gravity", timeout=600)
        return (d.get("text") or "")[-500:]
