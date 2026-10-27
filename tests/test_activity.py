"""Activity phases: a cautious estimate from DNS lookups, never a usage measurement."""
import time

from backend.analysis import activity
from backend.analysis.categories import Classifier
from backend.analysis.dns_ingest import DnsIngestor
from backend.config import DnsUsageCfg
from backend.database.repository import Database
from ftl_fake import MAC_A, T0, FakeFtl

CLF = Classifier.load(None)
IP_A = "192.0.2.10"
# A minute-aligned afternoon start, so that minute arithmetic in the tests is exact
# and no test accidentally runs into the night rule.
_lt = time.localtime(T0)
DAY = int(time.mktime((_lt.tm_year, _lt.tm_mon, _lt.tm_mday, 14, 0, 0, 0, 0, -1)))


def run(events, gap=5, override=None, clf=CLF):
    return activity.build(activity.minutes_from_events(sorted(events), clf), clf, gap, override)


def burst(start, minutes, domain="www.instagram.com", every=30, blocked=False):
    return [(start + i, domain, blocked) for i in range(0, int(minutes * 60) + 1, every)]


def svc(result, name):
    return next(s for s in result["services"] if s["service"] == name)


def test_phase_runs_from_first_to_last_lookup_and_pauses_are_not_counted():
    s = svc(run(burst(DAY, 10) + burst(DAY + 3600, 5)), "instagram")
    assert s["phase_count"] == 2
    assert [p["seconds"] for p in s["phases"]] == [600, 300]
    assert s["estimate_seconds"] == 900              # not 3600 + 300: the hour in between is unknown


def test_pause_up_to_the_gap_keeps_the_phase_and_longer_pause_splits_it():
    assert svc(run(burst(DAY, 2) + burst(DAY + 120 + 240, 2)), "instagram")["phase_count"] == 1
    assert svc(run(burst(DAY, 2) + burst(DAY + 120 + 420, 2)), "instagram")["phase_count"] == 2


def test_adjustable_gap_overrides_service_specific_gaps():
    ev = burst(DAY, 3, "www.youtube.com") + burst(DAY + 180 + 420, 3, "www.youtube.com")
    assert svc(run(ev), "youtube")["gap_minutes"] == 10          # rule: video buffers ahead
    assert svc(run(ev), "youtube")["phase_count"] == 1
    assert svc(run(ev, override=5), "youtube")["phase_count"] == 2


def test_several_domains_of_one_service_form_one_phase():
    ev = burst(DAY, 4, "www.instagram.com", 60) + burst(DAY + 30, 4, "scontent.cdninstagram.com", 60)
    s = svc(run(ev), "instagram")
    assert s["phase_count"] == 1 and s["queries"] == 10


def test_too_few_lookups_are_not_reliably_determinable():
    s = svc(run([(DAY, "www.instagram.com", False), (DAY + 60, "www.instagram.com", False)]), "instagram")
    assert s["estimate_seconds"] is None and s["confidence"] is None and "Too few" in s["reason"]


def test_background_categories_never_get_an_estimate():
    r = run(burst(DAY, 60, "fe2.update.microsoft.com") + burst(DAY, 60, "app-measurement.com"))
    for s in r["services"]:
        assert s["estimate_seconds"] is None and "Background" in s["reason"]
    assert r["overall"] == []


def test_messengers_get_low_confidence_at_most():
    s = svc(run(burst(DAY, 20, "g.whatsapp.net") + burst(DAY + 7200, 20, "g.whatsapp.net")), "whatsapp")
    assert s["estimate_seconds"] and s["confidence"] == "low" and "background" in s["reason"]


def test_best_case_is_medium_never_high():
    s = svc(run(burst(DAY, 20) + burst(DAY + 7200, 20)), "instagram")
    assert s["confidence"] == "medium"
    assert all(x["confidence"] in (None, "low", "medium") for x in run(burst(DAY, 300))["services"])


def test_activity_at_night_lowers_the_confidence():
    night = int(time.mktime((_lt.tm_year, _lt.tm_mon, _lt.tm_mday, 2, 0, 0, 0, 0, -1)))
    s = svc(run(burst(night, 30) + burst(night + 5400, 30) + burst(DAY, 20)), "instagram")
    assert s["confidence"] == "low" and "01:00 and 05:00" in s["reason"]


def test_mostly_single_minutes_lower_the_confidence():
    singles = [(DAY + 10_000 + i * 900, "www.instagram.com", False) for i in range(8)]
    s = svc(run(burst(DAY, 10) + burst(DAY + 5000, 10) + singles), "instagram")
    assert s["confidence"] == "low" and "single minutes" in s["reason"]


def test_blocked_lookups_are_counted_but_do_not_form_phases():
    s = svc(run(burst(DAY, 30, "www.tiktok.com", blocked=True)), "tiktok")
    assert s["queries"] == s["blocked"] == 61 and s["phase_count"] == 0 and s["estimate_seconds"] is None


def test_cdn_lookups_are_reported_as_unattributed_not_as_a_service():
    r = run(burst(DAY, 10, "d1abc.cloudfront.net") + burst(DAY, 10, "nothing.example"))
    assert r["services"] == [] and r["unattributed"] == {"infrastructure": 21, "unknown": 21}


def test_overall_phases_merge_foreground_services_only():
    r = run(burst(DAY, 5) + burst(DAY + 400, 5, "www.youtube.com") + burst(DAY, 60, "fe2.update.microsoft.com"))
    assert len(r["overall"]) == 1
    assert (r["overall"][0]["start"], r["overall"][0]["end"]) == (DAY, DAY + 660)   # last minute that had lookups


def test_service_unknown_to_current_rules_is_not_invented():
    rows = [(DAY + 60 * i, "removed-service", 3, 0) for i in range(20)]
    r = activity.build(rows, CLF, 5)
    assert r["services"] == [] and r["unattributed"] == {"unknown": 60}


def test_named_manual_rule_becomes_a_service_with_phases():
    clf = Classifier.load(None, {"school.example": {"categories": ["productivity"], "service_name": "School portal"}})
    s = svc(run(burst(DAY, 20, "www.school.example") + burst(DAY + 7200, 20, "www.school.example"), clf=clf),
            "manual:school-portal")
    assert s["name"] == "School portal" and s["estimate_seconds"] == 2400


def test_explanation_names_the_known_sources_of_error():
    text = " ".join(run([])["explanation"])
    for word in ("Background", "caches", "Prefetching", "HTTPS", "Encrypted DNS"):
        assert word in text


# --- activity minutes in the database -----------------------------------------

def _ingest(ing, db, now):
    for _ in range(50):
        b = ing.step(now)
        db.write_sync(lambda c: ing.commit(c, b, now=now))
        ing.applied(b)
        if not b.more:
            return
    raise AssertionError("did not catch up")


def _minutes(db):
    return db.read_sync(lambda c: [tuple(r) for r in c.execute(
        "SELECT m.ts, s.key, m.queries, m.blocked FROM dns_service_minutes m "
        "JOIN dns_services s ON s.id = m.service ORDER BY m.ts, s.key")])


def test_ingestion_writes_minutes_per_service_without_duplicates(tmp_path):
    db = Database(str(tmp_path / "nla.sqlite3"))
    db.init_sync()
    ftl = FakeFtl(tmp_path / "ftl.db").device(MAC_A, [IP_A])
    log = ftl.add([(DAY + 5, IP_A, "www.instagram.com", 2), (DAY + 6, IP_A, "www.instagram.com", 14),
                   (DAY + 30, IP_A, "i.instagram.com", 3), (DAY + 70, IP_A, "ads.example", 1)]).log()
    clf = CLF
    ing = DnsIngestor(log, DnsUsageCfg.model_construct(backfill_days=91, batch_rows=1000, interval=0),
                      classifier=lambda: clf)
    _ingest(ing, db, DAY + 600)
    assert _minutes(db) == [(DAY, "instagram", 2, 0), (DAY, "~unknown", 1, 1)]   # unattributed: per hour
    db.close()


def test_rule_change_rebuilds_the_minutes_from_the_pihole_log(tmp_path):
    db = Database(str(tmp_path / "nla.sqlite3"))
    db.init_sync()
    ftl = FakeFtl(tmp_path / "ftl.db").device(MAC_A, [IP_A])
    log = ftl.add([(DAY + i * 60, IP_A, "www.school.example", 2) for i in range(5)]).log()
    current = {"clf": CLF}
    ing = DnsIngestor(log, DnsUsageCfg.model_construct(backfill_days=91, batch_rows=1000, interval=0),
                      classifier=lambda: current["clf"])
    now = DAY + 3600
    _ingest(ing, db, now)
    assert {k for _t, k, _q, _b in _minutes(db)} == {"~unknown"}
    current["clf"] = Classifier.load(None, {"school.example": {"categories": ["productivity"],
                                                               "service_name": "School portal"}})
    plan = ing.plan_rebuild(current["clf"].fingerprint, now)
    assert plan["rebuild"] is not None
    db.write_sync(lambda c: ing.write_rebuild(c, plan))
    ing.applied_rebuild(plan)
    assert _minutes(db) == []
    _ingest(ing, db, now)
    assert {k for _t, k, _q, _b in _minutes(db)} == {"manual:school-portal"}
    assert sum(q for _t, _k, q, _b in _minutes(db)) == 5          # nothing counted twice
    assert ing.rebuild is None and ing.status["rebuild"] is None
    # survives a restart: fingerprint and finished rebuild are stored
    again = DnsIngestor(log, ing.cfg, classifier=lambda: current["clf"])
    db.read_sync(again.load)
    assert again.minutes_fp == current["clf"].fingerprint and again.rebuild is None
    db.close()


def test_first_start_needs_no_rebuild():
    ing = DnsIngestor(None, DnsUsageCfg())
    assert ing.plan_rebuild("abc", T0) == {"rebuild": None, "minutes_fp": "abc"}


def test_fingerprint_changes_with_any_rule():
    a = Classifier.load(None).fingerprint
    assert Classifier.load(None).fingerprint == a
    assert Classifier.load(None, {"x.example": {"categories": ["gaming"]}}).fingerprint != a


def test_lookups_around_the_clock_are_background_not_usage():
    # A TV in standby: a few lookups every hour, all day long, for days.
    ev = []
    for d in range(3):
        for hr in range(24):
            ev += burst(DAY - 14 * 3600 + d * 86400 + hr * 3600, 6, "www.netflix.com", every=60)
    s = svc(run(ev), "netflix")
    assert s["estimate_seconds"] is None and "hours of an average day" in s["reason"]


def test_many_active_hours_lower_the_confidence():
    ev = []
    for hr in range(13):
        ev += burst(DAY - 6 * 3600 + hr * 3600, 10, "www.netflix.com", every=60)
    s = svc(run(ev), "netflix")
    assert s["confidence"] == "low" and "13 hours" in s["reason"]


def test_unattributed_lookups_are_kept_per_hour_only():
    rows = activity.minutes_from_events([(DAY + 5, "nothing.example", False), (DAY + 1900, "nothing.example", False),
                                         (DAY + 5, "www.instagram.com", False)], CLF)
    assert rows == [(DAY, "instagram", 1, 0), (DAY, "~unknown", 2, 0)]
