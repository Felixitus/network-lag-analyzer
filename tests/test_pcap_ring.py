"""PCAP ring buffer: space usage must stay bounded.

Background: in practice the directory grew to 40 GB, although the settings
said "5 files of 50 MB". Three causes, all of which are nailed down
here - they are not obvious and would otherwise
come back.
"""
import os

import pytest

from backend.collectors.traffic import PcapRing

FILE_SIZE = 20_000
MAX_FILES = 3
LIMIT = 200_000


def ring(tmp_path, **kw):
    kw.setdefault("max_total", LIMIT)
    return PcapRing(str(tmp_path), max_files=MAX_FILES, file_size=FILE_SIZE, emit=lambda m: None, **kw)


def write(r, n, t0):
    for i in range(n):
        r.write(t0 + i * 0.001, b"x" * 400, 400, 1)


def size(p):
    return sum(f.stat().st_size for f in p.glob("*.pcap"))


def test_ring_alone_respects_file_count(tmp_path):
    r = ring(tmp_path)
    write(r, 400, 1_700_000_000)
    assert len(list(tmp_path.glob("*.pcap"))) <= MAX_FILES


def test_protected_files_do_not_grow_without_bound(tmp_path):
    """Every incident kept a file - without a budget this grows endlessly."""
    r = ring(tmp_path)
    t = 1_700_000_000
    for k in range(60):
        t += 5
        write(r, 60, t)
        r.protect(t - 1, t, incident_id=k)
    assert size(tmp_path) <= LIMIT, f"{size(tmp_path)} bytes over the budget of {LIMIT}"
    assert len(list(tmp_path.glob("*.pcap"))) < 60


def test_long_run_stays_inside_the_budget(tmp_path):
    r = ring(tmp_path)
    t = 1_700_000_000
    for k in range(500):
        t += 3
        write(r, 40, t)
        if k % 2 == 0:
            r.protect(t - 1, t, incident_id=k)
        assert size(tmp_path) <= LIMIT, f"budget exceeded in iteration {k}"


def test_restart_adopts_existing_files_instead_of_orphaning_them(tmp_path):
    """If the capture process restarts, the old files must not become orphaned.

    Previously the new ring did not know the old files: they were in no ring
    and not protected - so nobody ever deleted them. Every restart
    added up to `max_files × file_size` this way.
    """
    r1 = ring(tmp_path)
    t = 1_700_000_000
    write(r1, 400, t)
    geschuetzt = []
    for k in range(5):
        t += 5
        write(r1, 60, t)
        geschuetzt += r1.protect(t - 1, t, incident_id=k)
    r1.close()
    before_count = len(list(tmp_path.glob("*.pcap")))
    assert before_count > MAX_FILES

    r2 = ring(tmp_path, protected_paths=geschuetzt)
    assert len(r2.files) + len(r2.protected) == before_count, "existing files were not adopted"
    assert {f["path"] for f in r2.protected} <= set(geschuetzt)
    write(r2, 400, t + 100)
    assert size(tmp_path) <= LIMIT
    # The old unprotected files have disappeared through rotation
    assert len(list(tmp_path.glob("*.pcap"))) <= MAX_FILES + len(r2.protected)


def test_protect_twice_without_packets_in_between(tmp_path):
    """Two incidents in quick succession raised a ValueError - which ended the
    capture process, which then restarted and left files behind."""
    r = ring(tmp_path)
    t = 1_700_000_000
    write(r, 100, t)
    r.protect(t, t + 1, 1)
    r.protect(t, t + 1, 2)        # no packet in between
    r.protect(t, t + 1, 3)
    assert r.cur is None


def test_protect_returns_only_files_that_still_exist(tmp_path):
    """If a file is sacrificed immediately because of the budget, it must not be
    reported as protected - otherwise it would sit in the database without a file."""
    r = ring(tmp_path, max_total=60_000)
    t = 1_700_000_000
    for k in range(30):
        t += 5
        write(r, 60, t)
        for p in r.protect(t - 1, t, incident_id=k):
            assert os.path.exists(p), "non-existent file reported as protected"


def test_adoption_reports_each_file_so_the_database_learns_about_it(tmp_path):
    msgs = []
    r1 = PcapRing(str(tmp_path), MAX_FILES, FILE_SIZE, msgs.append, max_total=LIMIT)
    write(r1, 200, 1_700_000_000)
    r1.close()
    existing = {str(p) for p in tmp_path.glob("*.pcap")}

    msgs.clear()
    PcapRing(str(tmp_path), MAX_FILES, FILE_SIZE, msgs.append, max_total=LIMIT)
    reported = {m[1]["path"] for m in msgs if m[1].get("op") == "new"}
    assert existing <= reported, "adopted files were not reported"
    assert any(m[1].get("op") == "adopted" for m in msgs)


def test_budget_smaller_than_ring_still_keeps_writing(tmp_path):
    """Nonsensical configuration must not bring the capture to a standstill."""
    r = PcapRing(str(tmp_path), max_files=5, file_size=FILE_SIZE, emit=lambda m: None, max_total=10_000)
    write(r, 300, 1_700_000_000)
    assert r.cur is not None and os.path.exists(r.cur["path"])
    assert len(list(tmp_path.glob("*.pcap"))) >= 1


def test_without_limit_behaviour_is_unchanged(tmp_path):
    """max_total = 0 disables the total budget (old behavior, deliberately selectable)."""
    r = ring(tmp_path, max_total=0)
    t = 1_700_000_000
    for k in range(10):
        t += 5
        write(r, 60, t)
        r.protect(t - 1, t, incident_id=k)
    assert len(list(tmp_path.glob("*.pcap"))) > MAX_FILES


@pytest.mark.parametrize("protect_auto,expected", [("none", False), ("all", True)])
def test_protect_policy_decides_whether_a_capture_is_frozen(protect_auto, expected):
    """`protect_auto` decides whether any incident freezes 50 MB."""
    from backend.analysis.correlation import Incident
    from backend.config import Config

    class FakeCore:
        cfg = Config(deep_capture={"enabled": True, "protect_auto": protect_auto})
        capture_proc = object()
        commands = []

        def capture_command(self, *a):
            self.commands.append(a)

    from backend.core import Core
    core = FakeCore()
    inc = Incident(id=1, ts_start=100.0, ts_end=110.0, source="auto")
    inc.confidence = "low"
    assert Core._protect_pcap_for(core, inc, []) is expected
    assert bool(core.commands) is expected


def test_critical_policy_keeps_only_the_relevant_incidents():
    from backend.analysis.correlation import Incident
    from backend.analysis.events import Event
    from backend.config import Config
    from backend.core import Core

    class FakeCore:
        cfg = Config(deep_capture={"enabled": True, "protect_auto": "critical"})
        capture_proc = object()

        def __init__(self):
            self.commands = []

        def capture_command(self, *a):
            self.commands.append(a)

    inc = Incident(id=1, ts_start=100.0, ts_end=110.0, source="auto")
    inc.confidence = "low"
    harmlos = FakeCore()
    assert Core._protect_pcap_for(harmlos, inc, [Event(id=1, type="HIGH_JITTER", severity="warning",
                                                       ts_start=100.0)]) is False
    schlimm = FakeCore()
    assert Core._protect_pcap_for(schlimm, inc, [Event(id=2, type="PACKET_LOSS", severity="critical",
                                                       ts_start=100.0)]) is True
    sicher = FakeCore()
    inc.confidence = "high"
    assert Core._protect_pcap_for(sicher, inc, []) is True


# ------------------------------------------------------------------ disabling
def _core_mit_pcaps(tmp_path, protected_flags, enabled):
    """Core in dev mode with existing captures (file + database row)."""
    import os
    import time as _t
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(tmp_path)
    os.environ["NLA_CONFIG"] = "/nonexistent.yaml"
    from backend.core import Core
    core = Core()
    core.db.init_sync()
    d = tmp_path / "pcap"
    d.mkdir(exist_ok=True)
    for i, prot in enumerate(protected_flags):
        p = d / f"nla-2026090{i}-000000-000.pcap"
        p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 100_000)
        core.db.enqueue("INSERT INTO pcap_files(path, ts_start, ts_end, size, protected) VALUES (?,?,?,?,?)",
                        (str(p), _t.time() - 60, _t.time() - 60, 100_004, prot))
    core.db.flush_sync()
    core.cfg.deep_capture.enabled = enabled
    core.capture_proc = None
    return core, d


def test_disabling_deep_capture_removes_the_running_ring_files(tmp_path):
    """After disabling nobody rotates any more - the running files would otherwise stay."""
    import asyncio
    core, d = _core_mit_pcaps(tmp_path, [0, 0, 0, 1, 1], enabled=False)
    try:
        assert len(list(d.glob("*.pcap"))) == 5
        asyncio.run(core._cleanup_pcaps())
        core.db.flush_sync()
        remaining = sorted(p.name for p in d.glob("*.pcap"))
        assert len(remaining) == 2, f"unprotected files not removed: {remaining}"
        # Incident captures stay until protected_days - you want to be able to
        # download them after disabling.
        rows = core.db.read_sync(lambda c: c.execute(
            "SELECT protected, COUNT(*) FROM pcap_files GROUP BY protected").fetchall())
        assert {r[0]: r[1] for r in rows} == {1: 2}
    finally:
        core.db.close()


def test_enabled_deep_capture_keeps_the_running_ring_files(tmp_path):
    """While Deep Capture is running, the unprotected files belong to the ring - hands off."""
    import asyncio
    core, d = _core_mit_pcaps(tmp_path, [0, 0, 1], enabled=True)
    try:
        asyncio.run(core._cleanup_pcaps())
        core.db.flush_sync()
        assert len(list(d.glob("*.pcap"))) == 3
    finally:
        core.db.close()


def test_files_keep_only_the_headers_even_when_the_capture_sends_more(tmp_path):
    """snaplen 600 is for reading server names; on the SD card it would be 4× the writes
    and the start of every packet's content."""
    import struct
    r = ring(tmp_path, keep=128)
    r.write(1_700_000_000.0, bytes(range(256)) * 3, 1514, 1)
    r.close()
    (f,) = tmp_path.glob("*.pcap")
    raw = f.read_bytes()
    assert struct.unpack_from("<I", raw, 16)[0] == 128                   # snaplen in the file header
    incl, orig = struct.unpack_from("<II", raw, 24 + 8)
    assert (incl, orig) == (128, 1514) and len(raw) == 24 + 16 + 128
