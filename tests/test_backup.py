"""Automatic backups: consistent, checked, rotated - and manual copies are never touched."""
import os
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from backend.database import backup as bk


def db(tmp_path, rows=100):
    p = tmp_path / "nla.sqlite3"
    c = sqlite3.connect(p)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE t (x INTEGER)")
    c.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(rows)])
    c.commit()
    return p, c


def test_backup_is_a_checked_self_contained_copy(tmp_path):
    p, c = db(tmp_path)
    c.execute("INSERT INTO t VALUES (999)")         # still in the WAL, not checkpointed
    c.commit()
    cfg = tmp_path / "config.yaml"
    cfg.write_text("gateway: auto\n")
    res = bk.make_backup(str(p), tmp_path / "backups", str(cfg), now=1_792_000_000)
    copy = sqlite3.connect(res["path"])
    assert copy.execute("SELECT COUNT(*), MAX(x) FROM t").fetchone() == (101, 999)
    assert copy.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    assert [b["config"] for b in bk.list_backups(tmp_path / "backups")] == [True]
    c.close()
    copy.close()


def test_rotation_keeps_the_newest_and_leaves_manual_copies(tmp_path):
    d = tmp_path / "backups"
    d.mkdir()
    for i, stamp in enumerate(["20261001-0300", "20261008-0300", "20261015-0300"]):
        f = d / f"backup-auto-{stamp}.sqlite3"
        f.write_bytes(b"x")
        os.utime(f, (1_792_000_000 + i, 1_792_000_000 + i))
        (d / f"backup-auto-{stamp}.config.yaml").write_text("x")
    (d / "my-own-copy.sqlite3").write_bytes(b"x")
    assert bk.rotate(d, keep=2) == ["backup-auto-20261001-0300.sqlite3"]
    assert sorted(p.name for p in d.iterdir()) == [
        "backup-auto-20261008-0300.config.yaml", "backup-auto-20261008-0300.sqlite3",
        "backup-auto-20261015-0300.config.yaml", "backup-auto-20261015-0300.sqlite3", "my-own-copy.sqlite3"]


def test_backup_refuses_without_space(tmp_path, monkeypatch):
    p, c = db(tmp_path)
    c.close()
    monkeypatch.setattr(bk.shutil, "disk_usage", lambda _p: type("U", (), {"free": 10})())
    with pytest.raises(OSError, match="free space"):
        bk.make_backup(str(p), tmp_path / "backups")
    assert not list((tmp_path / "backups").glob("*.sqlite3"))


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-backup")
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


def test_backup_now_from_the_ui_and_its_listing(client):
    hdr = {"X-CSRF-Token": client.cookies.get("nla_csrf")}
    r = client.post("/api/backups/run", json={}, headers=hdr)
    assert r.status_code == 200 and r.json()["ok"] and r.json()["size"] > 0
    lst = client.get("/api/backups").json()
    assert len(lst["backups"]) == 1 and lst["last"]["ok"] and lst["settings"]["keep"] == 2
    assert client.post("/api/backups/run", json={}).status_code == 403          # CSRF


def test_automatic_backup_waits_for_its_hour_and_interval(client):
    import asyncio
    core = client.app.state.core
    core.cfg.backup.hour = (time.localtime().tm_hour + 1) % 24
    assert asyncio.run_coroutine_threadsafe(core._auto_backup(), core.loop).result(10) is None      # not the hour
    core.cfg.backup.hour = time.localtime().tm_hour
    assert asyncio.run_coroutine_threadsafe(core._auto_backup(), core.loop).result(10) is None      # just backed up
