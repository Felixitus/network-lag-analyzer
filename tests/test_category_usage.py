"""Categories per device: lookups, active hours and estimated activity, kept apart."""
from backend.analysis import category_usage as cu
from backend.analysis.categories import BUILTIN_PATH, Classifier

CLF = Classifier.load(builtin=BUILTIN_PATH)


def test_matrix_counts_lookups_per_device_and_category():
    m = cu.matrix([(1, "www.youtube.com", 6, 0), (1, "d1.cloudfront.net", 4, 0), (1, None, 2, 0),
                   (2, "www.tiktok.com", 3, 1)], CLF)
    cats = {c["category"]: c for c in cu.category_list(m[1], CLF.labels)}
    assert m[1]["queries"] == 12 and cats["streaming"]["queries"] == 6
    assert cats["infrastructure"]["background"] and cats["not_itemized"]["background"]
    assert not cats["streaming"]["background"]
    assert abs(sum(c["share"] for c in cats.values()) - 1) < 1e-9
    assert m[2]["blocked"] == 1


def test_active_hours_count_distinct_hours_with_allowed_lookups_only():
    minutes = [(3600, "youtube", 2, 0), (3660, "youtube", 1, 0), (7200, "youtube", 1, 1),   # blocked only
               (10800, "~adult", 3, 0), (14400, "~adult", 1, 0)]
    assert cu.active_hours(minutes, CLF) == {"streaming": 1, "adult": 2}


def test_estimates_sum_services_and_keep_the_weakest_confidence():
    est = cu.estimates([
        {"category": "streaming", "name": "YouTube", "estimate_seconds": 600, "confidence": "medium"},
        {"category": "streaming", "name": "Twitch", "estimate_seconds": 300, "confidence": "low"},
        {"category": "streaming", "name": "Netflix", "estimate_seconds": None, "confidence": None}])
    s = est["streaming"]
    assert (s["estimate_seconds"], s["confidence"], s["services"], s["without_estimate"]) == \
        (900, "low", ["YouTube", "Twitch"], ["Netflix"])
