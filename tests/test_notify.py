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
