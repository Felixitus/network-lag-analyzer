"""Pi-hole actions: only through its API, one session per action, only when on, only confirmed."""
import json
import os
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.collectors.pihole_api import PiholeApi, PiholeApiError
from backend.config import PiholeCfg


class FakePihole:
    def __init__(self, password="app-pw"):
        self.password = password
        self.calls = []
        self.sessions = 0
        self.allow, self.deny = set(), set()
        self.blocking = "enabled"

    def handler(self, req: httpx.Request):
        path, m = req.url.path, req.method
        self.calls.append((m, path))
        if path == "/api/auth" and m == "POST":
            if json.loads(req.content)["password"] != self.password:
                return httpx.Response(401, json={"session": {"valid": False}})
            self.sessions += 1
            return httpx.Response(200, json={"session": {"valid": True, "sid": "S1"}})
        if path == "/api/auth" and m == "DELETE":
            self.sessions -= 1
            return httpx.Response(204)
        assert req.headers.get("X-FTL-SID") == "S1"
        if path == "/api/dns/blocking":
            if m == "POST":
                body = json.loads(req.content)
                self.blocking = "enabled" if body["blocking"] else "disabled"
                return httpx.Response(200, json={"blocking": self.blocking, "timer": body["timer"]})
            return httpx.Response(200, json={"blocking": self.blocking, "timer": None})
        if path.startswith("/api/domains/"):
            parts = path.split("/")
            lst = parts[3]
            store = self.allow if lst == "allow" else self.deny
            if m == "POST":
                store.add(json.loads(req.content)["domain"])
                return httpx.Response(201, json={})
            if m == "DELETE":
                store.discard(parts[5])
                return httpx.Response(204)
            return httpx.Response(200, json={"domains": [{"domain": parts[5]}] if parts[5] in store else []})
        if path == "/api/action/restartdns":
            return httpx.Response(200, json={})
        return httpx.Response(404, json={"error": {"message": "Not found"}})


def api(fake, pw="app-pw"):
    return PiholeApi("http://127.0.0.1", pw, transport=httpx.MockTransport(fake.handler))


def test_each_action_logs_in_and_out_again():
    fake = FakePihole()
    a = api(fake)
    assert a.set_blocking(False, 300) == {"blocking": "disabled", "timer": 300}
    a.add_domain("deny", "ads.example", "test")
    assert a.domain_state("ads.example") == {"allow": False, "deny": True}
    a.remove_domain("deny", "ads.example")
    assert fake.deny == set() and fake.sessions == 0           # no session left open


def test_wrong_app_password_is_reported():
    with pytest.raises(PiholeApiError, match="rejected"):
        api(FakePihole(), pw="wrong").blocking()
    with pytest.raises(PiholeApiError, match="No Pi-hole app password"):
        api(FakePihole(), pw="").blocking()


def test_the_app_password_only_goes_to_the_local_pihole():
    assert PiholeCfg(api_url="http://127.0.0.1/").api_url == "http://127.0.0.1"
    for bad in ("http://192.0.2.10", "http://evil.example", "ftp://127.0.0.1"):
        with pytest.raises(ValueError):
            PiholeCfg(api_url=bad)


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-pihole")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "missing.yaml")
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core())) as c:
        c.get("/")
        time.sleep(0.5)
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


def test_actions_are_off_by_default_and_need_a_confirmation(client, monkeypatch):
    hdr = {"X-CSRF-Token": client.cookies.get("nla_csrf")}
    assert client.post("/api/pihole/blocking", json={"enabled": False, "minutes": 5, "confirm": True}, headers=hdr).status_code == 403
    fake = FakePihole()
    import backend.api.pihole as mod
    monkeypatch.setattr(mod, "PiholeApi", lambda url, pw: PiholeApi(url, pw, transport=httpx.MockTransport(fake.handler)))
    r = client.put("/api/settings", json={"pihole": {"api_enabled": True, "api_password": "app-pw"}}, headers=hdr)
    assert r.status_code == 200 and r.json()["config"]["pihole"]["api_password"] == "********"
    assert client.post("/api/pihole/blocking", json={"enabled": False, "minutes": 5}, headers=hdr).status_code == 400
    assert client.post("/api/pihole/blocking", json={"enabled": False, "minutes": 5, "confirm": True}).status_code == 403  # CSRF
    r = client.post("/api/pihole/blocking", json={"enabled": False, "minutes": 5, "confirm": True}, headers=hdr)
    assert r.status_code == 200 and fake.blocking == "disabled"
    r = client.post("/api/pihole/domain", json={"domain": "Ads.Example", "list": "deny", "action": "add", "confirm": True}, headers=hdr)
    assert r.status_code == 200 and fake.deny == {"ads.example"}
    assert client.post("/api/pihole/domain", json={"domain": "x; rm", "list": "deny", "action": "add", "confirm": True},
                       headers=hdr).status_code == 422
    st = client.get("/api/pihole/state").json()
    assert st["blocking"] == "disabled" and [a["action"] for a in st["actions"]][:2] == ["add deny", "blocking paused 5 min"]
    assert st["actions"][0]["domain"] == "ads.example" and st["actions"][0]["user"]
    # the saved password survives a save of the masked form
    client.put("/api/settings", json={"pihole": {"api_password": "********", "api_enabled": True}}, headers=hdr)
    assert client.app.state.core.cfg.pihole.api_password == "app-pw"
