import itertools

import pytest

from guardian import scoring
from guardian.config import FACTORS, load
from guardian.cvss import base_score


def full(**over):
    f = {k: scoring.factor(0.5, "verified", "x") for k in FACTORS}
    f.update(over)
    return f


def test_weights_sum_to_100():
    assert sum(load()["score"]["weights"].values()) == 100


def test_unknown_never_scores_zero():
    unknown = full(reachability=scoring.factor(None, "unknown", "not scanned"))
    zero = full(reachability=scoring.factor(0.0, "verified", "x"))
    r_unknown, r_zero = scoring.score(unknown), scoring.score(zero)
    prior = load()["score"]["priors"]["reachability"]
    assert r_unknown["contributions"]["reachability"] == pytest.approx(20 * prior)
    assert r_unknown["score"] > r_zero["score"]
    assert r_unknown["unknown_factors"] == ["reachability"]


def test_unknown_widens_range_and_lowers_confidence():
    known = scoring.score(full())
    unk = scoring.score(full(exploitability=scoring.factor(None, "unknown", "no EPSS")))
    assert known["range"][0] == known["range"][1]
    assert unk["range"][0] < unk["score"] < unk["range"][1]
    assert unk["confidence"] < known["confidence"]


@pytest.mark.parametrize("name,kind,limit,start", [("KEV_FLOOR", "floor", 90, 0.5), ("NOT_LOADED_CAP", "cap", 39, 0.9)])
def test_guardrails_fire_and_are_reported(name, kind, limit, start):
    f = {k: scoring.factor(start, "verified", "x") for k in FACTORS}
    r = scoring.score(f, [(name, kind, limit, "test")])
    assert r["score"] == limit
    assert r["guardrails"][0]["name"] == name


def test_guardrail_silent_when_not_needed():
    f = {k: scoring.factor(1.0, "verified", "x") for k in FACTORS}
    assert scoring.score(f, [("KEV_FLOOR", "floor", 90, "t")])["guardrails"] == []


def test_monotonic_in_each_factor():
    for k in FACTORS:
        scores = [scoring.score(full(**{k: scoring.factor(v, "verified", "x")}))["raw_score"]
                  for v in (0.1, 0.4, 0.7, 1.0)]
        assert scores == sorted(scores), k


def test_bands():
    assert [scoring.band(s) for s in (90, 70, 50, 20, 5)] == ["critical", "high", "medium", "low", "info"]


def test_explanation_mentions_guardrail_and_range():
    r = scoring.score(full(severity=scoring.factor(None, "unknown", "none")), [("KEV_FLOOR", "floor", 90, "kev")])
    text = scoring.explain(r)
    assert "KEV_FLOOR" in text and "as low as" in text


@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 9.1),   # lodash CVE-2019-10744
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss_base_score(vector, expected):
    assert base_score(vector)[0] == expected


def test_cvss_v4_and_missing_fall_back():
    assert base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert base_score(None) is None


def test_all_grade_combinations_are_valid():
    for g in itertools.islice(itertools.product(scoring.GRADE_Q, repeat=2), 8):
        scoring.score(full(severity=scoring.factor(0.5, g[0], "x"), exposure=scoring.factor(0.5, g[1], "x")))
