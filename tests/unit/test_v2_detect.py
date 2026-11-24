"""v2 detection (M2): merge across tools by alias, not-run never counted as clean, explanation templates."""

from guardian.v2.stages import s04_vulns as sd
from guardian.v2.stages import s06_prioritise as sp

COMPS = [{"id": "pkg:pypi/aiohttp@3.5.3", "ecosystem": "pypi", "name": "aiohttp", "version": "3.5.3",
          "purl": "pkg:pypi/aiohttp@3.5.3", "direct": True, "dev": False}]


def rec(tool, ids, **kw):
    return {"tool": tool, "purl": "pkg:pypi/aiohttp@3.5.3", "name": "aiohttp", "version": "3.5.3", "ecosystem": "pypi",
            "ids": set(ids), "summary": "s", "vectors": [], "label": "HIGH", "score_hint": None, "fixed": ["3.9.2"],
            "file": "requirements.txt", "refs": [], **kw}


def test_three_tools_one_issue_one_row():
    tools = {"osv_scanner": {"status": "ran", "ecosystems": ["pypi"]}, "grype": {"status": "ran", "ecosystems": ["pypi"]},
             "v1_osv": {"status": "not-applicable", "ecosystems": []}}
    rows = sd.merge([rec("osv_scanner", ["PYSEC-1", "CVE-2024-1"]), rec("grype", ["GHSA-x", "CVE-2024-1"])], COMPS, tools)
    assert len(rows) == 1
    r = rows[0]
    assert r["advisory"] == "GHSA-x" and set(r["aliases"]) == {"PYSEC-1", "CVE-2024-1"}
    assert r["reported_by"] == {"osv_scanner": True, "grype": True, "v1_osv": "not-applicable"}
    assert r["disagreement"] is False and r["severity"] == "high"


def test_tool_that_did_not_run_is_not_run_not_false():
    tools = {"osv_scanner": {"status": "ran", "ecosystems": ["pypi"]}, "grype": {"status": "not-run"},
             "v1_osv": {"status": "not-applicable", "ecosystems": []}}
    r = sd.merge([rec("osv_scanner", ["GHSA-y"])], COMPS, tools)[0]
    assert r["reported_by"]["grype"] == "not-run" and r["disagreement"] is False


def test_tool_that_ran_and_missed_it_is_flagged():
    tools = {"osv_scanner": {"status": "ran", "ecosystems": ["pypi"]}, "grype": {"status": "ran", "ecosystems": ["pypi"]},
             "v1_osv": {"status": "not-applicable", "ecosystems": []}}
    r = sd.merge([rec("osv_scanner", ["GHSA-z"])], COMPS, tools)[0]
    assert r["reported_by"]["grype"] is False and r["disagreement"] is True


def _item(rank, score, conf, contribs):
    keys = ["severity", "exploitability", "reachability", "exposure", "fix_availability"]
    w = {"severity": 30, "exploitability": 25, "reachability": 20, "exposure": 15, "fix_availability": 10}
    return {"rank": rank, "score": score, "confidence": conf, "title": f"t{rank}", "band": "high", "guardrails": [],
            "initial_severity": "high",
            "factor_rows": [{"factor": k, "label": sp.FACTOR_LABEL[k], "weight": w[k], "value": c / w[k], "grade": "verified",
                             "evidence": "e", "contribution": c} for k, c in zip(keys, contribs)]}


def test_vs_next_names_the_deciding_factor():
    a, b = _item(1, 80, 76, [22.5, 22.5, 10, 15, 10]), _item(2, 71, 76, [25, 10, 10, 15, 10])
    assert "exploitability adds +12.5" in sp.vs_next_text(a, b)
    assert sp.vs_next_text(a, None) is None


def test_reachability_unknown_for_non_npm_never_zero():
    from guardian.config import load
    row = {"cvss_score": 7.5, "severity_source": "CVSS v3 vector", "severity": "high", "cves": [], "ecosystem": "pypi",
           "dev": False, "version": "3.5.3", "fixed": ["3.9.2"]}
    f, rails = sp._generic_vuln_factors(row, {}, {"status": "not evaluated"}, None, load())
    assert f["reachability"]["value"] is None and f["reachability"]["grade"] == "unknown"


def test_deadline_stops_calls_and_slow_key_rotates(monkeypatch):
    from guardian.agents import llm
    calls = []

    def slow(url, body, key, timeout=None):
        calls.append(key)
        raise TimeoutError("slow")

    monkeypatch.setattr(llm, "_http_post", slow)
    monkeypatch.setattr("guardian.env.gemini_keys", lambda: ["k1", "k2", "k3"])
    g = llm.Gemini("m")
    g.transport = llm._http_post
    llm.set_deadline(60)
    try:
        try:
            g.generate("s", [])
        except llm.AgentUnavailable:
            pass
        assert len(set(calls)) == 3  # rotated through every key on timeouts
        llm.set_deadline(1)  # less than 3 s left: no call at all
        calls.clear()
        try:
            g.generate("s", [])
        except llm.AgentUnavailable as e:
            assert "time budget" in str(e)
        assert calls == []
    finally:
        llm.set_deadline(None)
