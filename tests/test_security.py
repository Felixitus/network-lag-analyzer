"""Login, Passwort-Bremse und Schutz des gespeicherten FRITZ!Box-Passworts."""
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
        c.get("/")   # CSRF-Cookie
        time.sleep(0.5)
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


@pytest.fixture(autouse=True)
def _ohne_fehlversuche():
    from backend.api import system
    system._login_fails.clear()
    yield
    system._login_fails.clear()


def csrf(c):
    return {"X-CSRF-Token": c.cookies.get("nla_csrf")}


PW = "richtig-langes-passwort"


def _login_aktivieren(c):
    r = c.post("/api/auth/setup", json={"enabled": True, "password": PW}, headers=csrf(c))
    assert r.status_code == 200
    c.cookies.pop("nla_session", None)                 # wie ein fremder Browser


def _login_deaktivieren(c):
    c.post("/api/auth/login", json={"password": PW}, headers=csrf(c))
    r = c.post("/api/auth/setup", json={"enabled": False, "current_password": PW}, headers=csrf(c))
    assert r.status_code == 200


def test_mit_login_ist_die_api_nur_nach_anmeldung_erreichbar(client):
    _login_aktivieren(client)
    try:
        assert client.get("/api/status").status_code == 401
        assert client.get("/api/auth/state").json() == {"login_enabled": True, "logged_in": False}
        assert client.post("/api/auth/login", json={"password": "falsch"}, headers=csrf(client)).status_code == 401
        assert client.post("/api/auth/login", json={"password": PW}, headers=csrf(client)).status_code == 200
        assert client.get("/api/status").status_code == 200
    finally:
        _login_deaktivieren(client)


def test_nach_fuenf_fehlversuchen_wird_auch_das_richtige_passwort_abgewiesen(client):
    _login_aktivieren(client)
    try:
        for _ in range(5):
            assert client.post("/api/auth/login", json={"password": "geraten"},
                               headers=csrf(client)).status_code == 401
        r = client.post("/api/auth/login", json={"password": PW}, headers=csrf(client))
        assert r.status_code == 429
    finally:
        from backend.api import system
        system._login_fails.clear()
        _login_deaktivieren(client)


def test_gespeichertes_fritzbox_passwort_geht_nicht_an_eine_neue_adresse(client):
    r = client.put("/api/settings", json={"fritzbox": {"host": "auto", "password": "fritz-geheim"}},
                   headers=csrf(client))
    assert r.status_code == 200
    assert r.json()["config"]["fritzbox"]["password"] == "********"

    # Adresse ändern, Passwort nur maskiert mitgeschickt → abgelehnt
    r = client.put("/api/settings", json={"fritzbox": {"host": "203.0.113.66", "password": "********"}},
                   headers=csrf(client))
    assert r.status_code == 422
    # Bei "auto" würde ein anderes Gateway das Ziel ebenso verschieben
    r = client.put("/api/settings", json={"gateway": "203.0.113.66"}, headers=csrf(client))
    assert r.status_code == 422
    # Verbindungstest gegen fremde Adresse ohne Passwort → abgelehnt, bevor etwas gesendet wird
    r = client.post("/api/setup/fritzbox-test", json={"host": "203.0.113.66", "password": "********"},
                    headers=csrf(client))
    assert r.status_code == 400

    # Mit neu eingegebenem Passwort ist die Änderung in Ordnung
    r = client.put("/api/settings", json={"fritzbox": {"host": "203.0.113.66", "password": "neu"}},
                   headers=csrf(client))
    assert r.status_code == 200
    assert client.app.state.core.cfg.fritzbox.password == "neu"


@pytest.mark.skipif(sys.platform == "win32", reason="Unix-Dateirechte")
def test_sitzungsschluessel_ist_nur_fuer_den_dienst_lesbar(client):
    p = os.path.join(client.app.state.core.cfg.data_dir, "session.key")
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
