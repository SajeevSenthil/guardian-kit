"""v2 fix (M3): human gate, hash binding, verify verdicts, approvals only via the HTTP route."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from guardian.v2 import runner, stages_fix as sf
from guardian.v2.workspace import Workspace


@pytest.fixture()
def ws(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_WORKSPACES_DIR", str(tmp_path / "ws"))
    monkeypatch.setenv("GUARDIAN_OFFLINE", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("pyyaml==3.13\nflask==2.0.1\n", encoding="utf-8")
    w = Workspace.create("path", str(repo), None, "tester")
    assert runner.run_stage(w, "ingest")["status"] == "ok"
    w.write("vulns", {"rows": [{"component_id": "pkg:pypi/pyyaml@3.13", "ecosystem": "pypi", "name": "pyyaml", "version": "3.13",
                                "advisory": "GHSA-a", "aliases": ["CVE-1"], "fixed": ["5.4"], "severity": "critical"}]})
    w.write("prioritise", {"items": [{"kind": "vuln", "component_id": "pkg:pypi/pyyaml@3.13", "rank": 1, "score": 80, "band": "high"}]})
    return w


def test_plan_edits_the_exact_pin_and_waits_for_a_human(ws):
    s = sf.run_remedies(ws, {})
    assert s == {"plans": 1, "actionable": 1, "decided": 0, "approved": 0}
    p = ws.read("remedies")["plans"][0]
    assert p["to_version"] == "5.4" and p["edits"][0]["new"] == "pyyaml==5.4"
    patch = (ws.dir / p["patch"]).read_bytes()
    assert b"-pyyaml==3.13" in patch and b"+pyyaml==5.4" in patch
    assert ws.status("remedies")["status"] == "awaiting_approval"
    assert (ws.src / "requirements.txt").read_text(encoding="utf-8").startswith("pyyaml==3.13")  # source untouched


def test_hash_mismatch_and_empty_approver_refused(ws):
    sf.run_remedies(ws, {})
    with pytest.raises(PermissionError):
        sf.record_decision(ws, "P-0001", "approve", "alice", "0" * 64)
    h = ws.read("remedies")["plans"][0]["plan_hash"]
    with pytest.raises(ValueError):
        sf.record_decision(ws, "P-0001", "approve", " ", h)
    with pytest.raises(ValueError):
        sf.freeze_approved(ws)  # nothing decided yet


def test_verify_offline_is_partial_never_verified(ws):
    sf.run_remedies(ws, {})
    h = ws.read("remedies")["plans"][0]["plan_hash"]
    sf.record_decision(ws, "P-0001", "approve", "alice", h)
    sf.freeze_approved(ws)
    with pytest.raises(PermissionError):
        sf.record_decision(ws, "P-0001", "reject", "alice", h)  # frozen after send
    s = sf.run_verify(ws, {})
    r = ws.read("verify")
    assert s["verdict"] == "PARTIAL"
    st = {c["name"]: c["status"] for c in r["checks"]}
    assert st["approval"] == "pass" and st["apply"] == "pass" and st["tests"] == "not-run"
    # Grype can rescan offline from its local DB; if no scanner ran, nothing may be claimed fixed
    assert st["targets_fixed"] == ("not-run" if st["rescan"] == "not-run" else "pass")
    assert (ws.dir / "work" / "verify" / "requirements.txt").read_text(encoding="utf-8").startswith("pyyaml==5.4")
    assert (ws.src / "requirements.txt").read_text(encoding="utf-8").startswith("pyyaml==3.13")


def test_tampered_plan_after_approval_fails_verify(ws):
    sf.run_remedies(ws, {})
    h = ws.read("remedies")["plans"][0]["plan_hash"]
    sf.record_decision(ws, "P-0001", "approve", "alice", h)
    sf.freeze_approved(ws)
    res = ws.read("remedies")
    res["plans"][0]["to_version"] = "9.9"  # edited after approval
    ws.write("remedies", res)
    sf.run_verify(ws, {})
    assert ws.read("verify")["verdict"] == "FAILED"


def test_only_the_http_route_records_decisions():
    root = Path(__file__).resolve().parents[2] / "guardian"
    callers = [p for p in root.rglob("*.py") if re.search(r"record_decision\(|freeze_approved\(", p.read_text(encoding="utf-8"))]
    assert {p.name for p in callers} == {"stages_fix.py", "routes_fix.py"}
    agents = (root / "agents").rglob("*.py")
    assert not any("stages_fix" in p.read_text(encoding="utf-8") for p in agents)


def test_container_command_is_isolated(tmp_path):
    cmd = sf.docker_cmd("docker", tmp_path, "python:3.12-slim", "pytest", network=False)
    assert "--network" in cmd and cmd[cmd.index("--network") + 1] == "none"
    assert "-e" not in cmd and "--env" not in cmd and "--privileged" not in cmd
    assert cmd.count("-v") == 1 and cmd[cmd.index("-v") + 1].endswith(":/app")
    assert "--network" not in sf.docker_cmd("docker", tmp_path, "x", "install", network=True)


def test_test_plan_detection(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts": {"test": "echo \\"Error: no test specified\\" && exit 1"}}', encoding="utf-8")
    assert sf.test_plan(tmp_path) is None
    (tmp_path / "package.json").write_text('{"scripts": {"test": "mocha"}}', encoding="utf-8")
    assert sf.test_plan(tmp_path)["eco"] == "npm"
