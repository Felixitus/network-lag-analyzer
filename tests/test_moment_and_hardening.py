"""Looking up a past moment, and what the API accepts or hands out."""
import pytest
from fastapi.testclient import TestClient

from backend.api.incidents import moment_peaks
from backend.collectors import notify
from backend.config import Config


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    import os
    d = tmp_path_factory.mktemp("nla")
    os.environ.update(NLA_DEV_MODE="1", NLA_DATA_DIR=str(d), NLA_CONFIG=str(d / "none.yaml"))
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core(str(d / "none.yaml")))) as c:
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


def csrf(c):
    c.get("/")
    return {"x-csrf-token": c.cookies.get("nla_csrf")}


def test_what_was_not_measured_stays_none_in_a_moment():
    peaks = moment_peaks([{"rtt_max": 20.0, "loss_pct": None}, {"rtt_max": 90.0, "loss_pct": None}])
    assert peaks["rtt_max"] == 90.0
    assert peaks["loss_pct"] is None
    assert peaks["down_bps"] is None


def test_a_moment_without_measurements_says_so(client):
    r = client.get("/api/moment", params={"ts": 1000})
    assert r.status_code == 200
    d = r.json()
    assert d["seconds_measured"] == 0 and d["res"] is None
    assert d["peaks"]["rtt_avg"] is None


def test_a_moment_rejects_a_time_that_is_no_time(client):
    assert client.get("/api/moment", params={"ts": -1}).status_code == 422
    assert client.get("/api/moment", params={"ts": "x"}).status_code == 422


def test_the_api_describes_itself_to_nobody(client):
    assert client.get("/api/docs").status_code == 404
    assert client.get("/api/openapi.json").status_code == 404


def test_pages_allow_no_inline_styles_or_scripts(client):
    csp = client.get("/").headers["content-security-policy"]
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp


def test_a_settings_section_of_the_wrong_shape_is_refused_not_a_crash(client):
    r = client.put("/api/settings", json={"fritzbox": "x"}, headers=csrf(client))
    assert r.status_code == 422


def test_an_interface_name_cannot_smuggle_url_parameters(client):
    r = client.put("/api/settings", json={"fritzbox": {"capture_interface": "1-lan&snaplen=0"}}, headers=csrf(client))
    assert r.status_code == 422


def test_default_interface_names_pass():
    cfg = Config()
    assert cfg.fritzbox.capture_interface == "1-lan"


class Cfg:
    ntfy_token = ""
    ntfy_url = "http://192.0.2.5/topic"
    smtp_host = "192.0.2.6"
    smtp_port = 25
    smtp_tls = False
    smtp_starttls = False
    smtp_username = ""
    mail_from = "a@example.test"
    mail_to = "b@example.test"
    telegram_bot_token = "1:secret"
    telegram_chat_id = "1"


def test_a_device_name_with_a_line_break_does_not_stop_its_alert(monkeypatch):
    sent = {}

    class Resp:
        def raise_for_status(self):
            pass

    def post(url, content, headers, timeout):
        sent.update(headers)
        return Resp()
    monkeypatch.setattr(notify.httpx, "post", post)
    notify.send_ntfy(Cfg, "New device\r\nX-Evil: 1", "body", "default")
    assert "\n" not in sent["Title"] and "\r" not in sent["Title"]

    class Smtp:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def send_message(self, msg):
            sent["subject"] = msg["Subject"]
    monkeypatch.setattr(notify.smtplib, "SMTP", Smtp)
    notify.send_mail(Cfg, "New device\nBcc: x@example.test", "body", "default")
    assert "Bcc: x@example.test" in sent["subject"] and "\n" not in sent["subject"]


def test_a_malformed_telegram_token_stays_out_of_the_error(monkeypatch):
    import httpx

    def post(*a, **k):
        raise httpx.InvalidURL("Invalid non-printable ASCII character in URL 1:secret")
    monkeypatch.setattr(notify.httpx, "post", post)
    with pytest.raises(RuntimeError) as e:
        notify.send_telegram(Cfg, "t", "b", "default")
    assert "secret" not in str(e.value)


def test_a_stream_ends_with_its_session():
    import asyncio

    import backend.api.security as sec

    class Db:
        def __init__(self, session):
            self.session = session

        async def read(self, fn):
            return self.session

    class C:
        login_required = True
        cfg = Config()
    C.db = Db(None)
    assert asyncio.run(sec.session_alive(C, "gone")) is False
    C.db = Db({"id": "x"})
    assert asyncio.run(sec.session_alive(C, "here")) is True
    C.login_required = False
    C.db = Db(None)
    assert asyncio.run(sec.session_alive(C, None)) is True
