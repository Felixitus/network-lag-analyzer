"""Mandatory login, server-side sessions, throttling, bind address, FRITZ!Box password."""
import io
import os
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

USER = "owner"
PW = "a-properly-long-password"


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    """Dev mode (demo data) but with the login enforced like in production."""
    d = tmp_path_factory.mktemp("nla-sec")
    (d / "config.yaml").write_text("security:\n  require_login_in_dev: true\n  idle_hours: 1\n", encoding="utf-8")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "config.yaml")
    yield d
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


@pytest.fixture(scope="module")
def client(env):
    from backend.api import create_app
    from backend.core import Core
    core = Core()
    with TestClient(create_app(core)) as c:
        c.get("/")   # CSRF cookie
        yield c


@pytest.fixture(autouse=True)
def _no_failed_attempts():
    from backend.api import auth
    auth._login_fails.clear()
    yield
    auth._login_fails.clear()


def csrf(c):
    return {"X-CSRF-Token": c.cookies.get("nla_csrf")}


def account_cli(*args, stdin=None, monkeypatch=None):
    from backend import account
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return account.main(list(args))


def login(c, user=USER, pw=PW):
    return c.post("/api/auth/login", json={"username": user, "password": pw}, headers=csrf(c))


def logout(c):
    c.post("/api/auth/logout", json={}, headers=csrf(c))
    c.cookies.pop("nla_session", None)


# --- order matters in this block: it starts without an account ----------------

def test_without_account_everything_but_health_and_state_is_locked(client):
    assert client.get("/api/health").json() == {"status": "ok"}
    st = client.get("/api/auth/state").json()
    assert st == {"login_required": True, "account_exists": False, "logged_in": False, "username": None}
    r = client.get("/api/status")
    assert r.status_code == 403 and r.json()["setup_required"] is True
    assert client.get("/api/dns/clients").status_code == 403
    assert login(client).status_code == 403              # there is nothing to log in to


def test_account_can_only_be_created_on_the_pi_not_through_the_api(client):
    # No endpoint creates an account; the old setup endpoint is gone.
    assert client.post("/api/auth/setup", json={"enabled": True, "password": PW}, headers=csrf(client)).status_code in (403, 404)
    assert client.post("/api/auth/password", json={"current_password": "", "new_password": PW},
                       headers=csrf(client)).status_code == 403


def test_account_cli_rejects_weak_credentials(client, monkeypatch, capsys):
    assert account_cli("set", "--username", USER, "--password-stdin", stdin="short\n", monkeypatch=monkeypatch) == 2
    assert account_cli("set", "--username", "bad name", "--password-stdin", stdin=PW + "\n", monkeypatch=monkeypatch) == 2
    assert account_cli("set", "--username", USER, "--password-stdin", stdin=USER + "\n", monkeypatch=monkeypatch) == 2
    assert "nothing changed" in capsys.readouterr().err


def test_account_cli_creates_the_account_and_the_api_requires_login(client, monkeypatch):
    assert account_cli("set", "--username", USER, "--password-stdin", stdin=PW + "\n", monkeypatch=monkeypatch) == 0
    assert client.get("/api/status").status_code == 401
    assert client.get("/api/stream").status_code == 401
    assert client.get("/api/dns/export?kind=clients&format=csv").status_code == 401
    assert client.get("/api/health").status_code == 200   # still open, says nothing
    assert client.get("/").status_code == 200            # the page itself (login form) loads


def test_login_with_username_and_password_opens_the_api(client):
    assert login(client, USER, "wrong-password").status_code == 401
    assert login(client, "someone", PW).status_code == 401
    r = login(client)
    assert r.status_code == 200 and r.json()["username"] == USER
    cookie = next(c for c in client.cookies.jar if c.name == "nla_session")
    assert cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie._rest).lower()
    assert client.get("/api/status").status_code == 200
    assert client.get("/api/auth/state").json()["username"] == USER
    logout(client)


def test_wrong_username_and_wrong_password_get_the_same_answer(client):
    a, b = login(client, "nobody", PW), login(client, USER, "nope-nope-nope")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_logout_ends_the_session_on_the_server(client):
    login(client)
    token = client.cookies.get("nla_session")
    client.post("/api/auth/logout", json={}, headers=csrf(client))
    client.cookies.set("nla_session", token)             # a copied cookie must not work any more
    assert client.get("/api/status").status_code == 401
    client.cookies.pop("nla_session", None)


def test_only_a_hash_of_the_session_token_is_stored(client):
    login(client)
    token = client.cookies.get("nla_session")
    db = client.app.state.core.db.path
    rows = sqlite3.connect(db).execute("SELECT id FROM auth_sessions").fetchall()
    assert rows and all(token not in r[0] for r in rows)
    logout(client)


def test_after_five_failed_attempts_even_the_right_password_is_rejected(client):
    for _ in range(5):
        assert login(client, USER, "guessed-guessed").status_code == 401
    r = login(client)
    assert r.status_code == 429 and "Retry-After" in r.headers


def test_many_addresses_together_are_throttled_too(client):
    from backend.api import auth
    now = time.time()
    for i in range(auth.LOGIN_MAX_FAILS_TOTAL):
        auth._login_fails.setdefault(f"198.51.100.{i}", []).append(now)   # other addresses
    assert login(client).status_code == 429


def test_session_expires_after_the_idle_time(client):
    login(client)
    core = client.app.state.core
    core.db.write_sync(lambda c: c.execute("UPDATE auth_sessions SET last_seen = last_seen - 7200"))
    assert client.get("/api/status").status_code == 401   # idle_hours: 1 in this test config
    client.cookies.pop("nla_session", None)


def test_password_change_needs_the_current_password_and_ends_other_sessions(client):
    from fastapi.testclient import TestClient as TC
    other = TC(client.app)
    other.get("/")
    assert login(other).status_code == 200
    login(client)
    assert client.post("/api/auth/password", json={"current_password": "wrong", "new_password": "x" * 12},
                       headers=csrf(client)).status_code == 403
    assert client.post("/api/auth/password", json={"current_password": PW, "new_password": "short"},
                       headers=csrf(client)).status_code == 400
    new = "another-long-password"
    r = client.post("/api/auth/password", json={"current_password": PW, "new_password": new}, headers=csrf(client))
    assert r.status_code == 200
    assert client.get("/api/status").status_code == 200   # this session stays
    assert other.get("/api/status").status_code == 401    # the other one is gone
    assert login(other, USER, PW).status_code == 401 and login(other, USER, new).status_code == 200
    # back to the original password for the following tests
    client.post("/api/auth/password", json={"current_password": new, "new_password": PW}, headers=csrf(client))
    logout(client)


def test_logout_everywhere_and_cli_logout_all(client, monkeypatch, capsys):
    login(client)
    client.post("/api/auth/logout", json={"everywhere": True}, headers=csrf(client))
    login(client)
    assert account_cli("logout-all") == 0 and "Ended 1" in capsys.readouterr().out
    assert client.get("/api/status").status_code == 401
    client.cookies.pop("nla_session", None)


def test_login_and_writes_need_the_csrf_token(client):
    assert client.post("/api/auth/login", json={"username": USER, "password": PW}).status_code == 403
    login(client)
    assert client.put("/api/settings", json={"thresholds": {"ping_warning": 60}}).status_code == 403
    assert client.put("/api/settings", json={"thresholds": {"ping_warning": 60}}, headers={
        **csrf(client), "Origin": "http://evil.example"}).status_code == 403
    logout(client)


def test_api_responses_are_not_cached_and_carry_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_stored_fritzbox_password_is_not_sent_to_a_new_address(client):
    login(client)
    try:
        r = client.put("/api/settings", json={"fritzbox": {"host": "auto", "password": "fritz-secret"}},
                       headers=csrf(client))
        assert r.status_code == 200
        assert r.json()["config"]["fritzbox"]["password"] == "********"
        r = client.put("/api/settings", json={"fritzbox": {"host": "203.0.113.66", "password": "********"}},
                       headers=csrf(client))
        assert r.status_code == 422
        r = client.put("/api/settings", json={"gateway": "203.0.113.66"}, headers=csrf(client))
        assert r.status_code == 422
        r = client.post("/api/setup/fritzbox-test", json={"host": "203.0.113.66", "password": "********"},
                        headers=csrf(client))
        assert r.status_code == 400
        r = client.put("/api/settings", json={"fritzbox": {"host": "203.0.113.66", "password": "new"}},
                       headers=csrf(client))
        assert r.status_code == 200
        assert client.app.state.core.cfg.fritzbox.password == "new"
    finally:
        logout(client)


def test_settings_never_contain_password_hashes(client):
    login(client)
    s = client.get("/api/settings").json()["config"]["security"]
    assert "password_hash" not in s
    logout(client)


# --- independent of the app ----------------------------------------------------

def test_legacy_password_becomes_user_admin(tmp_path):
    from backend.api import security as s
    from backend.database.repository import Database
    db = Database(str(tmp_path / "x.sqlite3"))
    db.init_sync()
    legacy = s.hash_password(PW)
    assert db.write_sync(lambda c: s.migrate_legacy(c, legacy)) is True
    acc = db.read_sync(s.get_account)
    assert acc["username"] == "admin" and s.verify_login(acc, "admin", PW)
    assert db.write_sync(lambda c: s.migrate_legacy(c, legacy)) is False   # only once
    db.close()


def test_bind_address_auto_never_means_every_interface(monkeypatch):
    from backend import main
    from backend.util import netinfo
    assert main.bind_address("auto", dev_mode=True) == "127.0.0.1"
    monkeypatch.setattr(netinfo, "default_route", lambda: netinfo.DefaultRoute("eth0", "192.0.2.1"))
    monkeypatch.setattr(netinfo, "primary_ipv4", lambda iface=None: "192.0.2.55")
    assert main.bind_address("auto", dev_mode=False) == "192.0.2.55"
    monkeypatch.setattr(netinfo, "default_route", lambda: None)
    monkeypatch.setattr(netinfo, "primary_ipv4", lambda iface=None: None)
    with pytest.raises(SystemExit):
        main.bind_address("auto", dev_mode=False)
    assert main.bind_address("0.0.0.0", dev_mode=False) == "0.0.0.0"   # only if explicitly configured
