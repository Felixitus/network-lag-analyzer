"""Domain classification: rule layers, specificity, shared infrastructure, imports."""
import pytest

from backend import dns_category_import
from backend.analysis.categories import (BUILTIN_PATH, Classifier, RuleError, UT1_FILE, load_yaml_rules,
                                         valid_domain)
from backend.analysis.dns_usage import NOT_ITEMIZED, category_breakdown, classify_rows


@pytest.fixture(scope="module")
def clf():
    return Classifier.load(None)


@pytest.mark.parametrize("domain, category, service", [
    ("www.facebook.com", "social", "facebook"),
    ("scontent-fra5-1.xx.fbcdn.net", "social", "facebook"),
    ("i.instagram.com", "social", "instagram"),
    ("v16m.tiktokcdn.com", "social", "tiktok"),
    ("rr3---sn-4g5e6nsz.googlevideo.com", "streaming", "youtube"),
    ("video-weaver.fra05.hls.ttvnw.net", "streaming", "twitch"),
    ("store.steampowered.com", "gaming", "steam"),
    ("gateway.discord.gg", "communication", "discord"),
    ("www.reddit.com", "social", "reddit"),
    ("outlook.office.com", "communication", "outlook"),
    ("www.office.com", "productivity", "microsoft365"),
    ("fe2.update.microsoft.com", "os_updates", "windows_update"),
    ("securepubads.g.doubleclick.net", "ads_tracking", "google_ads"),
])
def test_known_services_are_recognized_by_documented_rules(clf, domain, category, service):
    c = clf.classify(domain)
    assert (c.primary, c.service, c.source) == (category, service, "builtin")


def test_more_specific_rule_beats_shared_infrastructure(clf):
    assert clf.classify("youtubei.googleapis.com").service == "youtube"
    shared = clf.classify("fonts.googleapis.com")
    assert (shared.primary, shared.service, shared.confidence) == ("other", None, "low")


def test_cdn_is_never_attributed_to_a_service(clf):
    for d in ("d1abc.cloudfront.net", "e1234.dscx.akamaiedge.net", "x.fastly.net", "s3.amazonaws.com"):
        c = clf.classify(d)
        assert c.service is None and c.confidence == "low", d


def test_sdk_domains_of_a_service_are_not_counted_as_using_it(clf):
    # The Facebook SDK sits in countless other apps.
    c = clf.classify("graph.facebook.com")
    assert (c.primary, c.confidence) == ("ads_tracking", "medium")


def test_exact_rule_does_not_cover_other_names_on_the_same_shared_host(clf):
    assert clf.classify("feelinsonice-hrd.appspot.com").service == "snapchat"
    assert clf.classify("someone-else.appspot.com").primary == "unknown"


def test_service_with_several_categories_keeps_all_of_them(clf):
    c = clf.classify("discord.com")
    assert c.categories == ("communication", "gaming") and c.primary == "communication"


def test_unknown_domain_has_no_source_and_no_confidence(clf):
    c = clf.classify("nothing-matches.example")
    assert (c.primary, c.source, c.rule, c.confidence) == ("unknown", None, None, None)


def test_local_names_are_their_own_service(clf):
    assert clf.classify("printer.lan").service == "local_network"
    assert clf.classify("12.68.168.192.in-addr.arpa").service == "local_network"


def test_matching_ignores_case_and_trailing_dot(clf):
    assert clf.classify("WWW.Netflix.COM.").service == "netflix"


def test_manual_rule_wins_over_builtin_for_the_same_name_but_not_over_a_more_specific_one():
    clf = Classifier.load(None, {"youtube.com": {"categories": ["gaming"]},
                                 "googleapis.com": {"categories": ["productivity"]}})
    assert (clf.classify("www.youtube.com").primary, clf.classify("www.youtube.com").source) == ("gaming", "manual")
    assert clf.classify("youtubei.googleapis.com").source == "builtin"
    assert clf.classify("fonts.googleapis.com").primary == "productivity"


def test_manual_exact_rule_only_matches_that_name():
    clf = Classifier.load(None, {"tv.example": {"categories": ["streaming"], "exact": True}})
    assert clf.classify("tv.example").primary == "streaming"
    assert clf.classify("api.tv.example").primary == "unknown"


def test_local_rule_file_overrides_builtin_and_bad_file_is_reported(tmp_path):
    (tmp_path / "domain_categories.local.yaml").write_text(
        "categories: {kids: Kids}\nservices:\n  school:\n    name: School portal\n    categories: [kids]\n"
        "    domains: [school.example, netflix.com]\n", encoding="utf-8")
    clf = Classifier.load(str(tmp_path))
    assert clf.classify("www.school.example").primary == "kids" and clf.labels["kids"] == "Kids"
    assert clf.classify("www.netflix.com").source == "local"
    (tmp_path / "domain_categories.local.yaml").write_text("services:\n  x:\n    categories: [nope]\n    domains: [a.example]\n",
                                                           encoding="utf-8")
    clf = Classifier.load(str(tmp_path))
    assert clf.errors and "unknown categories" in clf.errors[0]
    assert clf.classify("www.netflix.com").source == "builtin"


def test_builtin_rules_are_valid_and_reference_only_known_categories():
    rs, labels = load_yaml_rules(BUILTIN_PATH, "builtin")
    assert len(rs) > 300
    assert {"social", "gaming", "streaming", "communication", "productivity", "shopping", "news", "music",
            "cloud", "ads_tracking", "os_updates", "smart_home", "other", "unknown"} == set(labels)
    with pytest.raises(RuleError):
        from backend.analysis.categories import _rule_set_from_data
        _rule_set_from_data({"categories": {"a": "A"}, "services": {"x": {"categories": ["a"], "domains": ["bad domain"]}}},
                            "t", None)


def test_ut1_import_maps_categories_skips_ips_and_loads_as_lowest_layer(tmp_path):
    ut1 = tmp_path / "blacklists"
    (ut1 / "games").mkdir(parents=True)
    (ut1 / "games" / "domains").write_text("minigames.example\n203.0.113.5\nnetflix.com\n", encoding="utf-8")
    (ut1 / "adult").mkdir()
    (ut1 / "adult" / "domains").write_text("skip.example\n", encoding="utf-8")
    assert dns_category_import.main(["--ut1", str(ut1), "--data-dir", str(tmp_path)]) == 0
    lines = (tmp_path / UT1_FILE).read_text(encoding="utf-8").splitlines()
    assert lines == ["minigames.example\tgaming", "netflix.com\tgaming"]
    clf = Classifier.load(str(tmp_path))
    c = clf.classify("www.minigames.example")
    assert (c.primary, c.source, c.confidence) == ("gaming", "ut1", "medium")
    assert clf.classify("www.netflix.com").source == "builtin"     # same specificity: builtin wins


def test_ut1_import_without_known_categories_keeps_the_previous_file(tmp_path):
    (tmp_path / UT1_FILE).write_text("old.example\tgaming\n", encoding="utf-8")
    (tmp_path / "empty").mkdir()
    assert dns_category_import.main(["--ut1", str(tmp_path / "empty"), "--data-dir", str(tmp_path)]) == 2
    assert (tmp_path / UT1_FILE).read_text(encoding="utf-8") == "old.example\tgaming\n"


def test_domain_validation_rejects_injection_attempts():
    assert valid_domain("a-b_c.example") and valid_domain("lan")
    for bad in ("=cmd|' /C calc'!A0", "a b.example", "a..example", "-a.example", "", "x" * 300):
        assert not valid_domain(bad), bad


def test_category_breakdown_adds_up_and_keeps_folded_domains_apart(clf):
    rows = classify_rows([
        {"name": "www.youtube.com", "queries": 6, "blocked": 0},
        {"name": "steamcommunity.com", "queries": 3, "blocked": 0},
        {"name": None, "queries": 1, "blocked": 0},
    ], clf)
    cats = category_breakdown(rows, clf)
    assert [c["category"] for c in cats] == ["streaming", "gaming", NOT_ITEMIZED]
    assert sum(c["share"] for c in cats) == pytest.approx(1)
    assert cats[2]["domains"] == 0
