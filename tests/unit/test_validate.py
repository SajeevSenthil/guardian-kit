import json

from guardian import loop, validate


def app(tmp_path, deps, installed=()):
    (tmp_path / "routes").mkdir(parents=True)
    (tmp_path / "routes" / "index.js").write_text("var a = require('kept');\nvar b = require('gone');\nvar fs = require('fs');\n",
                                                  encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {d: "1.0.0" for d in deps}}), encoding="utf-8")
    for p in installed:
        (tmp_path / "node_modules" / p).mkdir(parents=True)
        (tmp_path / "node_modules" / p / "package.json").write_text("{}", encoding="utf-8")
    return tmp_path


def test_require_check_declared(tmp_path):
    ok, missing = validate._require_check(app(tmp_path, ["kept"]), installed=False)
    assert not ok and [m["package"] for m in missing] == ["gone"] and missing[0]["line"] == 2


def test_require_check_installed(tmp_path):
    root = app(tmp_path, ["kept", "gone"], installed=["kept"])
    ok, missing = validate._require_check(root, installed=True)
    assert not ok and missing[0]["error"] == "Cannot find module 'gone'"
    assert validate._require_check(app(tmp_path / "x", ["kept", "gone"], ["kept", "gone"]), installed=True)[0]


def test_check_status_never_reports_not_run_as_passed():
    assert validate._check("build", None, "docker missing")["status"] == "not run"
    assert validate._check("x", False, "")["status"] == "FAILED"


PLAN = {"id": "P-0004", "finding": "F1", "chosen": {"id": "C1", "summary": "manifest-only removal"},
        "alternatives_considered": [
            {"id": "C2", "kind": "remove", "summary": "remove incl. require line",
             "prediction": {"target_resolved": True, "plan_gate": True, "dangling_requires": []}},
            {"id": "C9", "kind": "remove", "summary": "still dangling",
             "prediction": {"target_resolved": True, "plan_gate": True, "dangling_requires": ["gone"]}},
            {"id": "E", "kind": "escalate", "summary": "escalate", "prediction": {"target_resolved": False}}]}


def result(failing):
    checks = [validate._check("approval", True, "ok"), validate._check("build", None, "no docker"),
              validate._check(failing, False, "boom", evidence=[("routes/index.js:2 `var b = require('gone');` -> "
                                                                    "Cannot find module 'gone'")])]
    return {"verdict": "failed", "checks": checks}


def test_diagnosis_picks_alternative_without_the_failure():
    d = loop.deterministic_diagnosis(PLAN, result("static_start"))
    assert d["failing_check"] == "static_start" and d["recommended_candidate"] == "C2"
    assert "Cannot find module 'gone'" in d["root_cause"]


def test_diagnosis_escalates_when_nothing_is_eligible():
    plan = {**PLAN, "alternatives_considered": PLAN["alternatives_considered"][1:]}
    assert loop.deterministic_diagnosis(plan, result("static_start"))["recommended_candidate"] == "E"


def test_agent_recommendation_must_be_eligible():
    allowed = {a["id"] for a in loop._eligible(PLAN, [c for c in result("static_start")["checks"] if c["passed"] is False])}
    assert allowed == {"C2"}      # C9 leaves a dangling require, E escalates


def test_unknown_vulnerabilities_are_never_counted_as_fixed():
    before = [{"id": "F1", "type": "known_vulnerability", "component": "pkg:npm/a@1", "advisory": "GHSA-1"},
              {"id": "F2", "type": "typosquat", "component": "pkg:npm/x@1", "title": "look-alike"}]
    gone, new = validate.compare(before, [], osv_ok=False)        # OSV down: every vuln "disappears"
    assert gone == ["F2"] and new == []
    gone, _ = validate.compare(before, [], osv_ok=True)
    assert gone == ["F1", "F2"]
