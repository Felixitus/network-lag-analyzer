"""The note about a newer release: once a day, never installs, no internet is no problem."""
import asyncio
import os
import time

import pytest
from fastapi.testclient import TestClient

from backend.core import _version_tuple


def test_versions_compare_as_numbers():
    assert _version_tuple("1.10.0") > _version_tuple("1.9.2") > _version_tuple("1.9")
    assert _version_tuple("nonsense") < _version_tuple("0.0.1")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-update")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "missing.yaml")
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core())) as c:
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


def run(core, coro):
    return asyncio.run_coroutine_threadsafe(coro, core.loop).result(10)


def test_newer_release_is_reported_and_an_older_one_not(client, monkeypatch):
    import httpx
    core = client.app.state.core

    class R:
        def __init__(self, tag):
            self.tag = tag

        def raise_for_status(self):
            pass

        def json(self):
            return {"tag_name": self.tag, "html_url": "https://github.com/Felixitus/network-lag-analyzer/releases/x"}
    monkeypatch.setattr(httpx, "get", lambda *a, **k: R("v99.0.0"))
    info = run(core, core._check_update(force=True))
    assert info["newer"] and info["latest"] == "99.0.0"
    assert client.get("/api/status").json()["update"]["newer"] is True
    monkeypatch.setattr(httpx, "get", lambda *a, **k: R(f"v{core.version}"))
    assert run(core, core._check_update(force=True))["newer"] is False


def test_no_internet_is_no_error(client, monkeypatch):
    import httpx
    core = client.app.state.core

    def fail(*a, **k):
        raise httpx.ConnectError("offline")
    monkeypatch.setattr(httpx, "get", fail)
    info = run(core, core._check_update(force=True))
    assert info["newer"] is False and info["error"] == "ConnectError"


def test_dev_mode_does_not_ask_github_on_its_own(client, monkeypatch):
    import httpx
    core = client.app.state.core
    monkeypatch.setattr(httpx, "get", lambda *a, **k: pytest.fail("no request expected"))
    core.update_info = None
    assert run(core, core._check_update()) is None
