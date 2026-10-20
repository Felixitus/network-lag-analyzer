"""Latenz unter Last (Bufferbloat) und die Handlungsempfehlungen je Kategorie."""
import pytest

from backend.analysis import bufferbloat as bb
from backend.analysis.root_cause import RECOMMENDATIONS, Finding, Window, analyze, recommend

CAP_DOWN, CAP_UP = 100e6, 20e6


def rows(specs):
    """specs: [(anzahl, rtt, down_bps, up_bps)] → Sekundenzeilen."""
    out, ts = [], 1_700_000_000
    for n, rtt, down, up in specs:
        for _ in range(n):
            out.append({"ts": ts, "rtt_avg": rtt, "down_bps": down, "up_bps": up})
            ts += 1
    return out


def test_idle_and_download_load_are_compared():
    r = rows([(20, 18.0, 2e6, 0.5e6), (15, 160.0, 95e6, 1e6)])
    m = bb.measure(r, CAP_DOWN, CAP_UP)
    assert m["idle_ms"] == 18.0
    assert m["down"]["delta_ms"] == 142.0
    assert m["down"]["level"] == "critical" and m["down"]["grade"] == "stark"
    assert bb.DOWN_ADVICE in m["down"]["advice"]
    assert m["up"] is None                      # Upload war nie ausgelastet
    assert m["samples"]["down"] == 15


def test_upload_load_is_separate_and_gets_router_advice():
    r = rows([(20, 18.0, 2e6, 0.5e6), (12, 45.0, 3e6, 19e6)])
    m = bb.measure(r, CAP_DOWN, CAP_UP)
    assert m["up"]["delta_ms"] == 27.0 and m["up"]["level"] == "good"
    assert "Priorisierung" in m["up"]["advice"]
    assert m["down"] is None


def test_mixed_load_is_not_attributed_to_either_direction():
    """Sind beide Richtungen voll, lässt sich die Ursache nicht trennen – dann lieber nichts sagen."""
    r = rows([(20, 18.0, 1e6, 0.2e6), (15, 200.0, 95e6, 19e6)])
    m = bb.measure(r, CAP_DOWN, CAP_UP)
    assert m["up"] is None and m["down"] is None
    assert "hoher Auslastung" in m["note"]


def test_no_capacity_means_no_guess():
    m = bb.measure(rows([(20, 18.0, 2e6, 0.5e6)]), None, None)
    assert m["idle_ms"] is None and m["capacity_known"] is False
    assert "Leitungskapazität" in m["note"]


def test_too_few_idle_seconds_yields_nothing():
    m = bb.measure(rows([(3, 18.0, 1e6, 0.1e6), (20, 150.0, 95e6, 1e6)]), CAP_DOWN, CAP_UP)
    assert m["idle_ms"] is None and m["down"] is None


def test_idle_baseline_may_come_from_a_wider_window():
    """Ein 10-Minuten-Fenster kann durchgehend belastet sein – dann liefert die Stunde die Basis."""
    loaded = rows([(30, 150.0, 95e6, 1e6)])
    wider = rows([(30, 20.0, 1e6, 0.1e6)]) + loaded
    m = bb.measure(loaded, CAP_DOWN, CAP_UP, idle_rows=wider)
    assert m["idle_ms"] == 20.0 and m["down"]["delta_ms"] == 130.0


def test_bucket_row_and_aggregate_roundtrip():
    from backend.database import repository as repo
    m = bb.measure(rows([(20, 20.0, 1e6, 0.2e6), (10, 140.0, 95e6, 1e6)]), CAP_DOWN, CAP_UP)
    row = repo.bufferbloat_params(1_700_000_000, m)
    assert row is not None and row[0] == 1_700_000_000
    assert row[1] == 2000, "in der Datenbank stehen 1/100 ms"
    cols = ["ts", "idle_ms", "idle_secs", "up_ms", "up_worst_ms", "up_secs",
            "down_ms", "down_worst_ms", "down_secs"]
    # aggregate() rechnet mit Millisekunden, so wie read_bufferbloat sie liefert
    b1 = dict(zip(cols, row))
    for k in ("idle_ms", "up_ms", "up_worst_ms", "down_ms", "down_worst_ms"):
        if b1[k] is not None:
            b1[k] /= 100
    b2 = {**b1, "ts": b1["ts"] + 600, "down_ms": 100.0, "down_worst_ms": 180.0}
    agg = bb.aggregate([b1, b2])
    assert agg["windows"] == 2 and agg["idle_ms"] == 20.0
    assert agg["down"]["delta_ms"] == 100.0        # Median aus 140 und 100 → 120, minus 20 Basis
    assert agg["down"]["worst_ms"] == 180.0
    assert agg["up"] is None
    assert [x["ts"] for x in bb.trend([b1, b2], "down")] == [b1["ts"], b2["ts"]]


def test_bucket_row_is_skipped_without_load():
    from backend.database import repository as repo
    m = bb.measure(rows([(20, 20.0, 1e6, 0.2e6)]), CAP_DOWN, CAP_UP)
    assert bb.storable(m) is False                 # nichts zu vergleichen → nichts speichern
    assert repo.bufferbloat_params(1, m) is None
    assert bb.aggregate([])["up"] is None


# ------------------------------------------------------------------ Empfehlungen
def _window(**kw):
    kw.setdefault("rows", [])
    kw.setdefault("t0", 0)
    kw.setdefault("t1", 0)
    kw.setdefault("targets", {})
    return Window(**kw)


@pytest.mark.parametrize("category", sorted(RECOMMENDATIONS))
def test_every_category_has_actionable_steps(category):
    w = _window()
    r = recommend(w, Finding("x", category, 50, "c", []))
    assert r["steps"], category
    assert r["scope"] in ("self", "provider", "remote", "none")
    assert "{" not in " ".join(r["steps"]), "Platzhalter wurde nicht ersetzt"


def test_every_rule_category_is_covered():
    """Jede Kategorie, die eine Regel vergeben kann, braucht eine Empfehlung."""
    from backend.analysis.root_cause import CATEGORY_LABELS
    assert set(CATEGORY_LABELS) <= set(RECOMMENDATIONS)


def test_upload_recommendation_names_the_device():
    w = _window(rows=[{"ts": 0, "traffic_src": "capture", "up_bps": 1.0}])
    f = Finding("rule_upload_saturation", "upload", 90, "c", [], device={"name": "PS5", "mac": "aa"})
    r = recommend(w, f)
    assert any("PS5" in s for s in r["steps"])
    assert r["scope"] == "self"
    assert not any("Mitschnitt" in s for s in r["steps"])


def test_download_recommendation_warns_that_prioritisation_does_not_help():
    r = recommend(_window(), Finding("rule_download_saturation", "download", 90, "c", []))
    joined = " ".join(r["steps"])
    assert "Priorisierung" in joined and "nicht" in joined
    # Ohne Traffic pro Gerät wird das ehrlich ergänzt statt ein Gerät zu raten
    assert any("Mitschnitt" in s for s in r["steps"])


def test_isp_recommendation_says_it_is_not_locally_fixable():
    r = recommend(_window(), Finding("rule_wan_isp", "wan", 70, "c", []))
    assert r["scope"] == "provider"


def test_analyze_includes_recommendation_and_load_latency(pipeline):
    """End-to-End: Aus dem Download-Szenario fallen Empfehlung und Latenz unter Last heraus."""
    p = pipeline().run("download_saturation")
    inc = max((i for i in p.incidents if i.category), key=lambda i: (i.ts_end or i.ts_start) - i.ts_start)
    a = inc.analysis
    assert a["recommendation"]["category"] == a["category"] == "download"
    assert a["recommendation"]["scope"] == "self"
    assert a["recommendation"]["steps"]
    lul = a["metrics"]["latency_under_load"]
    assert lul["down"] is not None, lul
    assert lul["down"]["delta_ms"] > 0
    assert lul["up"] is None
