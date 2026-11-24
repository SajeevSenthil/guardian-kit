import pytest

from guardian import audit, report

VULN = {"id": "F1", "type": "known_vulnerability", "advisory": "GHSA-aaaa", "aliases": ["CVE-2020-1"],
        "component": "pkg:npm/a@1.0.0"}
OTHER = {"id": "F2", "type": "known_vulnerability", "advisory": "GHSA-bbbb", "aliases": [], "component": "pkg:npm/b@1.0.0"}
FINDINGS = {"F1": VULN, "F2": OTHER, "F3": {"id": "F3", "type": "typosquat", "component": "pkg:npm/x@1"}}


def val(verdict, ids):
    return {"verdict": verdict, "resolved_ids": ids, "branch": "guardian/fix-P-0001", "commit": "abc1234",
            "not_run": ["build", "tests"]}


def test_vex_fixed_only_for_validated_plans():
    v = report.build_vex("r", FINDINGS, {"P-0001": val("partial", ["F1", "F3"]), "P-0002": val("failed", ["F2"])}, {}, "head")
    assert [s["vulnerability"]["name"] for s in v["statements"]] == ["GHSA-aaaa"]      # F3 is not a CVE; F2 failed
    s = v["statements"][0]
    assert s["status"] == "fixed" and "NOT run" in s["status_notes"]
    assert v["@context"] == "https://openvex.dev/ns/v0.2.0"


def test_vex_not_affected_only_when_a_human_confirmed():
    decisions = {"F2": {"decision": "not-affected", "by": "Alice", "at": "t", "reason": "never loaded"},
                 "F1": {"decision": "accepted-risk", "by": "Bob", "at": "t", "reason": "x"}}
    v = report.build_vex("r", FINDINGS, {}, decisions, "head")
    assert [(s["vulnerability"]["name"], s["status"]) for s in v["statements"]] == [("GHSA-bbbb", "not_affected")]
    assert "Alice" in v["statements"][0]["impact_statement"]


def test_refuter_candidate_alone_never_reaches_vex():
    findings = {**FINDINGS, "F2": {**OTHER, "status": "not_affected_candidate"}}
    assert report.build_vex("r", findings, {}, {}, "head")["statements"] == []


def test_accept_requires_a_name_and_reason(tmp_path):
    with pytest.raises(ValueError):
        report.accept(tmp_path, "F1", "not-affected", "", "reason")
    with pytest.raises(ValueError):
        report.accept(tmp_path, "F1", "accepted-risk", "Alice", " ")
    with pytest.raises(ValueError):
        report.accept(tmp_path, "F1", "ignore", "Alice", "r")


def test_accept_records_decision_and_audit(tmp_path):
    rec = report.accept(tmp_path, "F1", "accepted-risk", "Alice", "compensating control")
    assert rec["by"] == "Alice" and (tmp_path / "decisions" / "F1.json").exists()
    ok, msg = audit.verify(tmp_path)
    assert ok and "1 events" in msg


def test_unknown_vulnerabilities_are_never_reported_as_zero():
    assert "NOT evaluated" in report.vuln_clause("not evaluated", None)
    assert "NOT evaluated" in report.vuln_clause("not evaluated", 0)
    assert report.vuln_clause("evaluated", 0).startswith("0 package")


def test_docker_sentence_says_not_implemented():
    assert "not implemented" in report.docker_sentence(True) and "not installed" not in report.docker_sentence(True)
    assert "not installed" in report.docker_sentence(False)


def test_no_fixed_vex_when_the_rescan_did_not_evaluate_vulnerabilities():
    v = {**val("partial", ["F1"]), "osv_evaluated": False}
    assert report.build_vex("r", FINDINGS, {"P-0001": v}, {}, "head")["statements"] == []
