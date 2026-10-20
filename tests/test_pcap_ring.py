"""PCAP-Ringpuffer: Platzverbrauch muss begrenzt bleiben.

Hintergrund: In der Praxis wuchs das Verzeichnis auf 40 GB, obwohl in den
Einstellungen „5 Dateien à 50 MB" stand. Drei Ursachen, die hier alle
festgenagelt werden – sie sind nicht offensichtlich und würden sonst
zurückkommen.
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
    """Jeder Incident hielt eine Datei fest – ohne Budget wächst das endlos."""
    r = ring(tmp_path)
    t = 1_700_000_000
    for k in range(60):
        t += 5
        write(r, 60, t)
        r.protect(t - 1, t, incident_id=k)
    assert size(tmp_path) <= LIMIT, f"{size(tmp_path)} Bytes über dem Budget von {LIMIT}"
    assert len(list(tmp_path.glob("*.pcap"))) < 60


def test_long_run_stays_inside_the_budget(tmp_path):
    r = ring(tmp_path)
    t = 1_700_000_000
    for k in range(500):
        t += 3
        write(r, 40, t)
        if k % 2 == 0:
            r.protect(t - 1, t, incident_id=k)
        assert size(tmp_path) <= LIMIT, f"Budget bei Durchlauf {k} gerissen"


def test_restart_adopts_existing_files_instead_of_orphaning_them(tmp_path):
    """Startet der Capture-Prozess neu, darf der alte Bestand nicht herrenlos werden.

    Vorher kannte der neue Ring die alten Dateien nicht: Sie lagen in keinem Ring
    und waren nicht geschützt – also hat sie nie jemand gelöscht. Bei jedem
    Neustart kamen so bis zu `max_files × file_size` dazu.
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
    vorher = len(list(tmp_path.glob("*.pcap")))
    assert vorher > MAX_FILES

    r2 = ring(tmp_path, protected_paths=geschuetzt)
    assert len(r2.files) + len(r2.protected) == vorher, "Bestand wurde nicht übernommen"
    assert {f["path"] for f in r2.protected} <= set(geschuetzt)
    write(r2, 400, t + 100)
    assert size(tmp_path) <= LIMIT
    # Die alten ungeschützten Dateien sind durch die Rotation verschwunden
    assert len(list(tmp_path.glob("*.pcap"))) <= MAX_FILES + len(r2.protected)


def test_protect_twice_without_packets_in_between(tmp_path):
    """Zwei Incidents kurz hintereinander warfen einen ValueError – und der
    beendete den Capture-Prozess, der danach neu startete und Dateien zurückließ."""
    r = ring(tmp_path)
    t = 1_700_000_000
    write(r, 100, t)
    r.protect(t, t + 1, 1)
    r.protect(t, t + 1, 2)        # kein Paket dazwischen
    r.protect(t, t + 1, 3)
    assert r.cur is None


def test_protect_returns_only_files_that_still_exist(tmp_path):
    """Wird eine Datei wegen des Budgets sofort geopfert, darf sie nicht als
    geschützt gemeldet werden – sonst stünde sie ohne Datei in der Datenbank."""
    r = ring(tmp_path, max_total=60_000)
    t = 1_700_000_000
    for k in range(30):
        t += 5
        write(r, 60, t)
        for p in r.protect(t - 1, t, incident_id=k):
            assert os.path.exists(p), "nicht existierende Datei als geschützt gemeldet"


def test_adoption_reports_each_file_so_the_database_learns_about_it(tmp_path):
    msgs = []
    r1 = PcapRing(str(tmp_path), MAX_FILES, FILE_SIZE, msgs.append, max_total=LIMIT)
    write(r1, 200, 1_700_000_000)
    r1.close()
    vorhanden = {str(p) for p in tmp_path.glob("*.pcap")}

    msgs.clear()
    PcapRing(str(tmp_path), MAX_FILES, FILE_SIZE, msgs.append, max_total=LIMIT)
    gemeldet = {m[1]["path"] for m in msgs if m[1].get("op") == "new"}
    assert vorhanden <= gemeldet, "übernommene Dateien wurden nicht gemeldet"
    assert any(m[1].get("op") == "adopted" for m in msgs)


def test_budget_smaller_than_ring_still_keeps_writing(tmp_path):
    """Unsinnige Konfiguration darf den Mitschnitt nicht zum Stillstand bringen."""
    r = PcapRing(str(tmp_path), max_files=5, file_size=FILE_SIZE, emit=lambda m: None, max_total=10_000)
    write(r, 300, 1_700_000_000)
    assert r.cur is not None and os.path.exists(r.cur["path"])
    assert len(list(tmp_path.glob("*.pcap"))) >= 1


def test_without_limit_behaviour_is_unchanged(tmp_path):
    """max_total = 0 schaltet das Gesamtbudget ab (altes Verhalten, bewusst wählbar)."""
    r = ring(tmp_path, max_total=0)
    t = 1_700_000_000
    for k in range(10):
        t += 5
        write(r, 60, t)
        r.protect(t - 1, t, incident_id=k)
    assert len(list(tmp_path.glob("*.pcap"))) > MAX_FILES


@pytest.mark.parametrize("protect_auto,erwartet", [("none", False), ("all", True)])
def test_protect_policy_decides_whether_a_capture_is_frozen(protect_auto, erwartet):
    """`protect_auto` entscheidet, ob ein beliebiger Incident 50 MB festhält."""
    from backend.analysis.correlation import Incident
    from backend.config import Config

    class FakeCore:
        cfg = Config(deep_capture={"enabled": True, "protect_auto": protect_auto})
        capture_proc = object()
        befehle = []

        def capture_command(self, *a):
            self.befehle.append(a)

    from backend.core import Core
    core = FakeCore()
    inc = Incident(id=1, ts_start=100.0, ts_end=110.0, source="auto")
    inc.confidence = "low"
    assert Core._protect_pcap_for(core, inc, []) is erwartet
    assert bool(core.befehle) is erwartet


def test_critical_policy_keeps_only_the_relevant_incidents():
    from backend.analysis.correlation import Incident
    from backend.analysis.events import Event
    from backend.config import Config
    from backend.core import Core

    class FakeCore:
        cfg = Config(deep_capture={"enabled": True, "protect_auto": "critical"})
        capture_proc = object()

        def __init__(self):
            self.befehle = []

        def capture_command(self, *a):
            self.befehle.append(a)

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


# ------------------------------------------------------------------ Abschalten
def _core_mit_pcaps(tmp_path, protected_flags, enabled):
    """Core im Dev-Modus mit vorhandenen Mitschnitten (Datei + Datenbankzeile)."""
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
    """Nach dem Abschalten rotiert niemand mehr – die laufenden Dateien blieben sonst liegen."""
    import asyncio
    core, d = _core_mit_pcaps(tmp_path, [0, 0, 0, 1, 1], enabled=False)
    try:
        assert len(list(d.glob("*.pcap"))) == 5
        asyncio.run(core._cleanup_pcaps())
        core.db.flush_sync()
        uebrig = sorted(p.name for p in d.glob("*.pcap"))
        assert len(uebrig) == 2, f"ungeschützte Dateien nicht entfernt: {uebrig}"
        # Incident-Mitschnitte bleiben bis protected_days – die will man nach dem
        # Abschalten noch herunterladen können.
        zeilen = core.db.read_sync(lambda c: c.execute(
            "SELECT protected, COUNT(*) FROM pcap_files GROUP BY protected").fetchall())
        assert {r[0]: r[1] for r in zeilen} == {1: 2}
    finally:
        core.db.close()


def test_enabled_deep_capture_keeps_the_running_ring_files(tmp_path):
    """Läuft Deep Capture, gehören die ungeschützten Dateien dem Ring – Finger weg."""
    import asyncio
    core, d = _core_mit_pcaps(tmp_path, [0, 0, 1], enabled=True)
    try:
        asyncio.run(core._cleanup_pcaps())
        core.db.flush_sync()
        assert len(list(d.glob("*.pcap"))) == 3
    finally:
        core.db.close()
