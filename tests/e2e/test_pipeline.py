"""End-to-end: scan -> prioritise -> analyse -> plan -> approve -> validate -> loop -> approve -> validate -> report.

Runs in an isolated runs folder (pytest tmp_path); approvals are recorded under a name that says they are an
automated test, never on the team's demo run. The Diagnostician agent is mocked to recommend an ineligible
candidate, to prove that code keeps its own choice. Run with:  python -m pytest -q -m e2e -s
"""

import subprocess
import time

import pytest

from guardian import loop, prioritise, remediate, report, runs, validate
from guardian.agents.runner import analyse

pytestmark = pytest.mark.e2e
TEST_APPROVER = "e2e-test (automated test, not a human review)"


def timed(t, name, fn, *a, **k):
    s = time.time()
    r = fn(*a, **k)
    t[name] = round(time.time() - s, 1)
    return r


def test_closed_loop_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setattr(runs, "RUNS", tmp_path)
    t = {}
    run = timed(t, "scan", runs.scan, "guardian-baseline", "tampered", False)
    pr = timed(t, "prioritise", prioritise.prioritise, run)
    timed(t, "analyse(offline)", analyse, run, mode="offline")
    fid = next(f["id"] for f in pr["findings"] if f["type"] == "typosquat")

    # 1. the "manifest-only dependency bot" plan, chosen explicitly
    p1 = timed(t, "plan C1", remediate.make_plan, run, fid, force_candidate="C1")
    assert p1["prediction"]["dangling_requires"], "the dry run should already predict the dangling require()"
    assert not remediate.check_approval(run, p1["id"])[0]
    remediate.approve(run, p1["id"], TEST_APPROVER)
    r1 = timed(t, "validate P1", validate.validate, run, p1["id"])
    failed = {c["name"] for c in r1["checks"] if c["passed"] is False}
    assert r1["verdict"] == "failed" and "static_start" in failed, r1["checks"]
    assert {"build", "tests", "baseline_tests"} <= set(r1.get("not_run", []))

    # 2. loop: a mocked agent recommends the ineligible C1 again -> code keeps its own choice (C2)
    monkeypatch.setattr(loop, "agent_diagnosis", lambda *a, **k: {"status": "ok", "model": "mock",
                                                                   "recommended_candidate": "C1", "claims": []})
    lp = timed(t, "diagnose + re-plan", loop.close_loop, run, p1["id"], r1, "live")
    assert "not eligible" in lp["diagnosis"]["decision_note"]
    p2 = lp["new_plan"]
    assert p2["chosen"]["id"] == "C2" and p2["supersedes"] == p1["id"] and p2["state"] == "pending_approval"
    assert not remediate.check_approval(run, p2["id"])[0], "a superseding plan must not be approved automatically"

    # 3. second approval, validation
    remediate.approve(run, p2["id"], TEST_APPROVER)
    r2 = timed(t, "validate P2", validate.validate, run, p2["id"])
    assert r2["verdict"] == "partial", r2["checks"]            # container build / smoke test not implemented
    assert r2["target_resolved"] and fid in r2["resolved_ids"]
    assert not [c for c in r2["checks"] if c["passed"] is False]
    assert any("lodahs" in x for x in r2["sbom_diff"]["removed"])

    # 4. report
    rep = timed(t, "report", report.render, run)["report"]
    st = {i["id"]: i["status"] for i in rep["findings"]}
    assert st[fid] == "remediated_partial"
    assert rep["audit"]["chain_ok"] and rep["summary"]["counts"]["remediated_partial"] == 1
    assert subprocess.run(["git", "-C", str(runs.TARGET), "status", "--porcelain"], capture_output=True,
                          check=True).stdout == b""
    print("\nTIMINGS (s):", t)
