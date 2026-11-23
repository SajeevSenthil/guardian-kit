import hashlib
import json

import pytest

from guardian import audit, policy, remediate


# ---- semver / helpers ---------------------------------------------------------------------
@pytest.mark.parametrize("a,b,d", [("4.17.4", "4.17.21", "patch"), ("4.17.4", "4.18.1", "minor"),
                                   ("1.0.1", "1.0.0", "patch"), ("2.0.0", "3.1.0", "major"), ("1.2.3", "1.2.3", "none")])
def test_semver_distance(a, b, d):
    assert remediate.semver_distance(a, b) == d


def test_unused_require_lines(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "i.js").write_text(
        "var a = require('used');\nvar b = require('unused');\na.go();\n", encoding="utf-8")
    hits = remediate.unused_require_lines(tmp_path, "unused")
    assert [(h[0], h[1]) for h in hits] == [("routes/i.js", 2)]
    assert remediate.unused_require_lines(tmp_path, "used") == []


def test_kind_preference_ranks_pin_back_before_remove():
    pred = {"target_resolved": True, "plan_gate": {"pass": True}, "new_vulnerabilities": [], "resolved": [1, 2],
            "dangling_requires": [], "semver": "patch"}
    pin = {"id": "U1", "kind": "pin_back", "ops": [1, 2, 3], "prediction": pred}
    rem = {"id": "U2", "kind": "remove", "ops": [1], "prediction": {**pred, "semver": "none"}}
    assert min([rem, pin], key=remediate.rank_key)["id"] == "U1"


def test_dangling_require_outranks_everything_but_resolution():
    good = {"target_resolved": True, "plan_gate": {"pass": True}, "new_vulnerabilities": [], "resolved": [1],
            "dangling_requires": [], "semver": "none"}
    c1 = {"id": "C1", "kind": "remove", "ops": [1], "prediction": {**good, "dangling_requires": ["x"], "resolved": [1, 2, 3]}}
    c2 = {"id": "C2", "kind": "remove", "ops": [1, 2, 3], "prediction": good}
    assert min([c1, c2], key=remediate.rank_key)["id"] == "C2"


# ---- policy (Python port of policy/guardian.rego) -----------------------------------------
DOC = {
    "findings": [{"id": "F1", "band": "critical", "scope": "prod", "status": "open", "kev": False, "component": "pkg:npm/a@1"},
                 {"id": "F2", "band": "critical", "scope": "dev", "status": "open", "kev": False, "component": "pkg:npm/b@1"},
                 {"id": "F3", "band": "low", "scope": "dev", "status": "open", "kev": True, "component": "pkg:npm/c@1"}],
    "components": [{"purl": "pkg:npm/n@1", "name": "n", "has_install_script": True, "origin_trusted": False, "new": True},
                   {"purl": "pkg:npm/o@1", "name": "o", "has_install_script": True, "origin_trusted": True, "new": False},
                   {"purl": "pkg:npm/p@1", "name": "p", "has_install_script": False, "origin_trusted": None, "new": False}],
    "images": [{"ref": "node:18", "digest": None, "new": True}, {"ref": "mongo:3", "digest": None, "new": False},
               {"ref": "x@sha256:ab", "digest": "sha256:ab", "new": True}],
    "actions": [{"uses": "o/a@v1", "pinned_sha": False, "first_party": False, "new": True},
                {"uses": "actions/checkout@v3", "pinned_sha": False, "first_party": True, "new": True},
                {"uses": "o/b@" + "a" * 40, "pinned_sha": True, "first_party": False, "new": True}],
    "config": {"allowed_install_scripts": []},
}


def test_policy_rules_match_the_rego_file():
    r = policy.evaluate(DOC)
    d = "\n".join(r["deny"])
    assert not r["pass"]
    assert "critical finding F1" in d and "F2" not in d.split("KEV")[0]            # dev critical: no deny
    assert "F3 is in the CISA KEV" in d                                            # KEV blocks regardless of band
    assert "new component pkg:npm/n@1 runs an install script" in d
    assert "new component pkg:npm/n@1 does not come from a trusted registry" in d
    assert "changed image reference node:18" in d and "mongo:3" not in d and "x@sha256" not in d
    assert "o/a@v1" in d and "actions/checkout" not in d and "o/b@" not in d
    w = "\n".join(r["warn"])
    assert "existing component pkg:npm/o@1" in w and "mongo:3" in w and "origin of pkg:npm/p@1" in w


def test_allow_list_suppresses_install_script_deny():
    doc = {**DOC, "config": {"allowed_install_scripts": ["n"]}}
    assert not any("runs an install script" in x for x in policy.evaluate(doc)["deny"])


def test_plan_gate():
    head = {"deny": ["x on pkg:npm/t@1", "other problem"]}
    assert policy.plan_gate(head, {"deny": ["other problem"]}, ["pkg:npm/t@"])["pass"]
    assert not policy.plan_gate(head, {"deny": ["other problem", "x on pkg:npm/t@2"]}, ["pkg:npm/t@"])["pass"]
    assert not policy.plan_gate(head, {"deny": ["other problem", "brand new"]}, ["pkg:npm/t@"])["pass"]


# ---- approval bound to the plan hash ------------------------------------------------------
def make_run(tmp_path):
    (tmp_path / "plans").mkdir()
    patch = "From abc\n--- a/package.json\n+++ b/package.json\n"
    (tmp_path / "plans" / "P-0001.patch").write_text(patch, encoding="utf-8")
    plan = {"id": "P-0001", "patch_file": "plans/P-0001.patch", "state": "pending_approval",
            "plan_hash": hashlib.sha256(patch.encode()).hexdigest()}
    (tmp_path / "plans" / "P-0001.json").write_text(json.dumps(plan), encoding="utf-8")
    return tmp_path


def test_unapproved_plan_is_refused(tmp_path):
    ok, msg = remediate.check_approval(make_run(tmp_path), "P-0001")
    assert not ok and "not been approved" in msg


def test_approval_then_edit_is_refused(tmp_path):
    run = make_run(tmp_path)
    rec = remediate.approve(run, "P-0001", "Test Approver")
    assert rec["decision"] == "approved" and rec["plan_hash"] == json.loads((run / "plans/P-0001.json").read_text())["plan_hash"]
    assert remediate.check_approval(run, "P-0001")[0]
    p = run / "plans" / "P-0001.patch"
    p.write_text(p.read_text() + "+ sneaky extra line\n", encoding="utf-8")
    ok, msg = remediate.check_approval(run, "P-0001")
    assert not ok and "changed after approval" in msg


def test_rejection_and_missing_name(tmp_path):
    run = make_run(tmp_path)
    with pytest.raises(ValueError):
        remediate.approve(run, "P-0001", "  ")
    remediate.approve(run, "P-0001", "Reviewer", reject=True, comment="no")
    assert not remediate.check_approval(run, "P-0001")[0]


def test_audit_chain_detects_edits(tmp_path):
    run = make_run(tmp_path)
    remediate.approve(run, "P-0001", "Test Approver")
    audit.append(run, "guardian", "validate.started", "P-0001")
    assert audit.verify(run)[0]
    lines = (run / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    e = json.loads(lines[0])
    e["subject"] = "P-9999"
    (run / "audit.jsonl").write_text("\n".join([json.dumps(e)] + lines[1:]) + "\n", encoding="utf-8")
    ok, msg = audit.verify(run)
    assert not ok and "line 1" in msg
