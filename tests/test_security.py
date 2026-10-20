"""Login, password throttling and protection of the stored FRITZ!Box password."""
import os
import stat
import sys
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-sec")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "missing.yaml")
    from backend.api import create_app
    from backend.core import Core
    core = Core()
    with TestClient(create_app(core)) as c:
        c.get("/")   # CSRF cookie
        time.sleep(0.5)
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


@pytest.fixture(autouse=True)
def _no_failed_attempts():
    from backend.api import system
    system._login_fails.clear()
    yield
    system._login_fails.clear()


def csrf(c):
    return {"X-CSRF-Token": c.cookies.get("nla_csrf")}


PW = "a-properly-long-password"


def _enable_login(c):
    r = c.post("/api/auth/setup", json={"enabled": True, "password": PW}, headers=csrf(c))
    assert r.status_code == 200
    c.cookies.pop("nla_session", None)                 # like a foreign browser


def _disable_login(c):
    c.post("/api/auth/login", json={"password": PW}, headers=csrf(c))
    r = c.post("/api/auth/setup", json={"enabled": False, "current_password": PW}, headers=csrf(c))
    assert r.status_code == 200


def test_with_login_the_api_is_only_reachable_after_signing_in(client):
    _enable_login(client)
    try:
        assert client.get("/api/status").status_code == 401
        assert client.get("/api/auth/state").json() == {"login_enabled": True, "logged_in": False}
        assert client.post("/api/auth/login", json={"password": "wrong"}, headers=csrf(client)).status_code == 401
        assert client.post("/api/auth/login", json={"password": PW}, headers=csrf(client)).status_code == 200
        assert client.get("/api/status").status_code == 200
    finally:
        _disable_login(client)


def test_after_five_failed_attempts_even_the_right_password_is_rejected(client):
    _enable_login(client)
    try:
        for _ in range(5):
            assert client.post("/api/auth/login", json={"password": "guessed"},
                               headers=csrf(client)).status_code == 401
        r = client.post("/api/auth/login", json={"password": PW}, headers=csrf(client))
        assert r.status_code == 429
    finally:
        from backend.api import system
        system._login_fails.clear()
        _disable_login(client)


def test_stored_fritzbox_password_is_not_sent_to_a_new_address(client):
    r = client.put("/api/settings", json={"fritzbox": {"host": "auto", "password": "fritz-secret"}},
                   headers=csrf(client))
    assert r.status_code == 200
    assert r.json()["config"]["fritzbox"]["password"] == "********"

    # Change the address, password only sent masked → rejected
    r = client.put("/api/settings", json={"fritzbox": {"host": "203.0.113.66", "password": "********"}},
                   headers=csrf(client))
    assert r.status_code == 422
    # With "auto" a different gateway would move the target just the same
    r = client.put("/api/settings", json={"gateway": "203.0.113.66"}, headers=csrf(client))
    assert r.status_code == 422
    # Connection test against a foreign address without a password → rejected before anything is sent
    r = client.post("/api/setup/fritzbox-test", json={"host": "203.0.113.66", "password": "********"},
                    headers=csrf(client))
    assert r.status_code == 400

    # With a newly entered password the change is fine
    r = client.put("/api/settings", json={"fritzbox": {"host": "203.0.113.66", "password": "new"}},
                   headers=csrf(client))
    assert r.status_code == 200
    assert client.app.state.core.cfg.fritzbox.password == "new"


@pytest.mark.skipif(sys.platform == "win32", reason="Unix file permissions")
def test_session_key_is_readable_only_by_the_service(client):
    p = os.path.join(client.app.state.core.cfg.data_dir, "session.key")
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
