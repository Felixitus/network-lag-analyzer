"""UT1 lists: import straight from the archive, and the monthly refresh."""
import asyncio
import hashlib
import io
import json
import os
import sys
import tarfile

import pytest
from fastapi.testclient import TestClient

from backend import dns_category_import as imp
from backend.analysis.categories import UT1_META, Classifier


def make_archive(path, lists):
    with tarfile.open(path, "w:gz") as tar:
        for cat, names in lists.items():
            data = "".join(n + "\n" for n in names).encode()
            info = tarfile.TarInfo(f"blacklists/{cat}/domains")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        evil = b"evil.example\n"
        info = tarfile.TarInfo("../../outside/adult/domains")      # never written anywhere
        info.size = len(evil)
        tar.addfile(info, io.BytesIO(evil))
    return path


def test_import_reads_the_archive_without_extracting_it(tmp_path):
    arc = make_archive(tmp_path / "blacklists.tar.gz", {"adult": ["a.example"], "games": ["g.example"], "sect": ["s.example"]})
    out = tmp_path / "data"
    out.mkdir()
    assert imp.main(["--archive", str(arc), "--data-dir", str(out)]) == 0
    meta = json.loads((out / UT1_META).read_text())
    assert meta["sha256"] == hashlib.sha256(arc.read_bytes()).hexdigest()
    clf = Classifier.load(str(out))
    assert clf.classify("a.example").primary == "adult" and clf.classify("g.example").primary == "gaming"
    assert not (tmp_path / "outside").exists() and not list(out.glob("**/domains"))
    clf.close()


def test_import_needs_a_source(tmp_path):
    assert imp.main(["--data-dir", str(tmp_path)]) == 2
    (tmp_path / "broken.tar.gz").write_bytes(b"not a tar")
    assert imp.main(["--archive", str(tmp_path / "broken.tar.gz"), "--data-dir", str(tmp_path)]) == 2


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-ut1")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "missing.yaml")
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core())) as c:
        c.get("/")
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


def run(core, coro):
    return asyncio.run_coroutine_threadsafe(coro, core.loop).result(120)


def test_refresh_does_nothing_where_ut1_was_never_imported(client):
    core = client.app.state.core
    assert run(core, core._ut1_refresh(force=True)) is None


@pytest.fixture(scope="module")
def first_import(client, tmp_path_factory):
    core = client.app.state.core
    first = make_archive(tmp_path_factory.mktemp("arc") / "v1.tar.gz", {"adult": ["a.example"]})
    assert imp.main(["--archive", str(first), "--data-dir", core.cfg.data_dir]) == 0
    core.reload_classifier({})
    return first


def test_refresh_skips_unchanged_lists(client, first_import, monkeypatch):
    core = client.app.state.core

    def same(url, dst, max_bytes):
        data = first_import.read_bytes()
        dst.write_bytes(data)
        return hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(core, "_download", same)
    r = run(core, core._ut1_refresh(force=True))
    assert r["ok"] and not r["changed"] and r["note"] == "unchanged"


@pytest.mark.skipif(sys.platform == "win32", reason="Windows cannot replace a memory-mapped file; the Pi runs Linux")
def test_refresh_imports_changed_lists(client, first_import, tmp_path, monkeypatch):
    core = client.app.state.core
    served = {"file": first_import}

    def fake_download(url, dst, max_bytes):
        data = served["file"].read_bytes()
        dst.write_bytes(data)
        return hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(core, "_download", fake_download)
    served["file"] = make_archive(tmp_path / "v2.tar.gz", {"adult": ["a.example"], "gambling": ["bet.example"]})
    before = core.classifier.fingerprint
    r = run(core, core._ut1_refresh(force=True))
    assert r["ok"] and r["changed"], r
    assert core.classifier.classify("bet.example").primary == "gambling" and core.classifier.fingerprint != before
    assert not any(p.name == "ut1-download.tar.gz" for p in __import__("pathlib").Path(core.cfg.data_dir).iterdir())
    rules = client.get("/api/dns/rules").json()
    assert rules["ut1_refresh"]["changed"] and rules["ut1_auto_update"] is True


def test_a_failed_download_keeps_the_old_index(client, first_import, monkeypatch):
    core = client.app.state.core

    def fail(url, dst, max_bytes):
        raise OSError("network down")
    monkeypatch.setattr(core, "_download", fail)
    r = run(core, core._ut1_refresh(force=True))
    assert not r["ok"] and "network down" in r["error"]
    assert core.classifier.classify("a.example").primary == "adult"
