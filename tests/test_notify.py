"""Notifications: minimum duration, cooldown, all clear; channels fail on their own; secrets stay masked."""
import asyncio
import os
import time

import pytest
from fastapi.testclient import TestClient

from backend.analysis.alerts import Alerts
from backend.collectors import notify as nt
from backend.config import NotifyCfg


def kinds(msgs):
    return [m.kind for m in msgs]


def test_an_alert_needs_its_minimum_duration_and_ends_with_an_all_clear():
    a = Alerts(cooldown_s=600)
    assert a.condition("x", 0, True, "Internet down", "no answer", min_s=60) == []
    assert a.condition("x", 30, True, "Internet down", "no answer", min_s=60) == []
    assert kinds(a.condition("x", 61, True, "Internet down", "no answer", min_s=60)) == ["alert"]
    assert a.condition("x", 300, True, "Internet down", "no answer", min_s=60) == []        # within cooldown
    assert kinds(a.condition("x", 700, True, "Internet down", "no answer", min_s=60)) == ["repeat"]
    m = a.condition("x", 800, False, "Internet down", "", min_s=60)
    assert kinds(m) == ["resolved"] and "13 min" in m[0].body
    assert a.active() == []


def test_a_short_blip_sends_nothing_at_all():
    a = Alerts()
    a.condition("x", 0, True, "t", "b", min_s=60)
    assert a.condition("x", 20, False, "t", "b", min_s=60) == []          # never alerted, so no all clear


def cfg(**kw):
    return NotifyCfg(enabled=True, **kw)


def test_only_configured_channels_are_used():
    assert nt.channels(cfg()) == []
    assert nt.channels(cfg(ntfy_url="https://ntfy.example/topic", telegram_bot_token="t", telegram_chat_id="1",
                           smtp_host="smtp.example", mail_to="me@example.org")) == ["ntfy", "telegram", "email"]
    assert nt.channels(cfg(telegram_bot_token="t")) == []                  # a bot without chat is no channel


def test_one_failing_channel_does_not_stop_the_others():
    sent = []

    def ok(c, t, b, p):
        sent.append(t)

    def broken(c, t, b, p):
        raise ConnectionError("down")
    res = nt.deliver(cfg(ntfy_url="https://ntfy.example/t", telegram_bot_token="t", telegram_chat_id="1"), "T", "B",
                     senders={"ntfy": broken, "telegram": ok})
    assert res == {"ntfy": "ConnectionError: down", "telegram": None} and sent == ["T"]


def test_telegram_errors_never_show_the_token(monkeypatch):
    import httpx

    def fail(*a, **k):
        raise httpx.ConnectError("https://api.telegram.org/botSECRET123/sendMessage")
    monkeypatch.setattr(httpx, "post", fail)
    res = nt.deliver(cfg(telegram_bot_token="SECRET123", telegram_chat_id="1"), "T", "B")
    assert "SECRET123" not in res["telegram"]


def test_ntfy_url_must_be_http():
    with pytest.raises(ValueError):
        NotifyCfg(ntfy_url="ftp://x")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-notify")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "missing.yaml")
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core())) as c:
        c.get("/")
        time.sleep(1)
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


def test_secrets_are_masked_and_kept_when_saved_unchanged(client):
    hdr = {"X-CSRF-Token": client.cookies.get("nla_csrf")}
    r = client.put("/api/settings", json={"notify": {"enabled": True, "telegram_bot_token": "123:ABC", "telegram_chat_id": "42"}},
                   headers=hdr)
    assert r.status_code == 200 and r.json()["config"]["notify"]["telegram_bot_token"] == "********"
    # the UI sends the mask back untouched together with another change
    client.put("/api/settings", json={"notify": {"telegram_bot_token": "********", "cooldown_minutes": 60}}, headers=hdr)
    core = client.app.state.core
    assert core.cfg.notify.telegram_bot_token == "123:ABC" and core.cfg.notify.cooldown_minutes == 60


def test_a_kept_smtp_password_or_ntfy_token_never_goes_to_a_new_server(client):
    hdr = {"X-CSRF-Token": client.cookies.get("nla_csrf")}
    r = client.put("/api/settings", json={"notify": {"smtp_host": "smtp.example", "smtp_username": "me",
                                                     "smtp_password": "pw-1", "ntfy_url": "https://ntfy.example/t",
                                                     "ntfy_token": "tk-1"}}, headers=hdr)
    assert r.status_code == 200
    for change in ({"smtp_host": "smtp.attacker.example"}, {"smtp_port": 2525}, {"smtp_username": "other"},
                   {"ntfy_url": "https://ntfy.attacker.example/t"}):
        r = client.put("/api/settings", json={"notify": {**change, "smtp_password": "********", "ntfy_token": "********"}},
                       headers=hdr)
        assert r.status_code == 422 and "re-enter" in r.json()["detail"], change
    core = client.app.state.core
    assert core.cfg.notify.smtp_host == "smtp.example" and core.cfg.notify.ntfy_url == "https://ntfy.example/t"
    # entering the secret again with the new server is fine
    r = client.put("/api/settings", json={"notify": {"smtp_host": "smtp2.example", "smtp_password": "pw-2"}}, headers=hdr)
    assert r.status_code == 200 and core.cfg.notify.smtp_password == "pw-2"
    r = client.put("/api/settings", json={"notify": {"smtp_host": "", "ntfy_url": ""}}, headers=hdr)
    assert r.status_code == 200                   # switching a channel off needs no secret


def test_internet_down_round_sends_once_then_all_clear(client, monkeypatch):
    core = client.app.state.core
    sent = []

    async def fake_send(m):
        sent.append(m)
        return {}
    monkeypatch.setattr(core, "_send", fake_send)
    core.cfg.notify.enabled, core.cfg.notify.internet_down_seconds = True, 10
    for k in ("router_loss", "pihole_down", "pi_health", "line", "new_device"):
        setattr(core.cfg.notify, k, False)
    monkeypatch.setattr(core.hub, "internet_online", lambda: False)
    run = lambda t: asyncio.run_coroutine_threadsafe(core._notify_round(t, t), core.loop).result(5)   # noqa: E731
    run(1000)
    run(1015)
    run(1030)
    monkeypatch.setattr(core.hub, "internet_online", lambda: True)
    run(1045)
    assert [(m.key, m.kind) for m in sent] == [("internet_down", "alert"), ("internet_down", "resolved")]


def test_test_message_needs_a_channel(client):
    hdr = {"X-CSRF-Token": client.cookies.get("nla_csrf")}
    core = client.app.state.core
    core.cfg.notify.telegram_bot_token = core.cfg.notify.telegram_chat_id = ""
    assert client.post("/api/notify/test", json={}, headers=hdr).status_code == 400
    assert client.get("/api/notify").json()["channels"] == []


def test_mails_carry_a_compact_html_part_with_sections_and_a_link():
    body = ("Measured 100 % of the week.\n\nINTERNET OUTAGES: none measured.\n\nNEW DEVICES: 2\n"
            "- Laptop <Demo> (02:00:00:00:00:33)\n- Phone (02:00:00:00:00:44)\n\nFRITZ!Box: 1× DSL sync lost.")
    out = nt.mail_html("Weekly report", body, "report", "http://192.0.2.55:8088/#/", when=0)
    assert "INTERNET OUTAGES</div><div" in out and "none measured." in out
    assert "NEW DEVICES · 2" in out and out.count("<li") == 2
    assert "Laptop &lt;Demo&gt;" in out and "<Demo>" not in out           # text is escaped
    assert "FRITZ!Box: 1× DSL sync lost." in out                          # mixed case is no heading
    assert 'href="http://192.0.2.55:8088/#/"' in out and "<style" not in out


def test_the_mail_subject_starts_with_the_message_and_has_a_text_part_too(monkeypatch):
    sent = []

    class FakeSmtp:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def send_message(self, m): sent.append(m)
    monkeypatch.setattr(nt.smtplib, "SMTP", FakeSmtp)
    c = cfg(smtp_host="smtp.example", mail_to="me@example.org", smtp_starttls=False)
    res = nt.deliver(c, "Internet down", "No internet target answers pings.", "high", kind="alert",
                     link="http://192.0.2.55:8088/#/line")
    assert res == {"email": None}
    m = sent[0]
    assert m["Subject"] == "⚠ Internet down · Network Lag Analyzer"
    assert m.get_body("plain").get_content().strip().endswith("http://192.0.2.55:8088/#/line")
    assert "border-top:4px solid #d14343" in m.get_body("html").get_content()
