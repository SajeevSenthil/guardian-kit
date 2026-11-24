"""The closed loop (phase 11): failed validation -> diagnosis -> superseding plan -> new human approval.

Diagnosis is made by the Diagnostician agent when a model is available, and always by code as well.
The deterministic diagnosis reads the failed checks' evidence (unresolved require(), install errors,
new findings, policy) and picks the best-ranked alternative from the failed plan that the dry run
predicts resolves the target without the observed failure mode. An agent recommendation is accepted
only if it names such an alternative; otherwise code's choice stands. The new plan is created in
state pending_approval with `supersedes` = the failed plan. Nothing is re-approved automatically.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from . import audit, remediate, runs
from .agents.llm import AgentUnavailable, Gemini, run_agent
from .agents.runner import CLAIM
from .config import load
from .evidence import EvidenceIndex

PROMPT = Path(__file__).parent / "agents" / "prompts" / "diagnostician.md"
SCHEMA = {"type": "object", "properties": {
    "failing_check": {"type": "string"}, "root_cause": {"type": "string"}, "claims": {"type": "array", "items": CLAIM},
    "recommended_candidate": {"type": "string"}, "unknowns": {"type": "array", "items": {"type": "string"}}},
    "required": ["failing_check", "root_cause", "claims", "recommended_candidate", "unknowns"]}


def _eligible(plan: dict, failed: list[dict]) -> list[dict]:
    """Alternatives predicted to resolve the target, pass the plan gate, and avoid the observed failure."""
    unresolved = any(c["name"] == "static_start" for c in failed)
    out = []
    for a in plan["alternatives_considered"]:
        p = a["prediction"]
        if a["kind"] == "escalate" or not p.get("target_resolved") or not p.get("plan_gate"):
            continue
        if unresolved and p.get("dangling_requires"):
            continue
        out.append(a)
    return out


def deterministic_diagnosis(plan: dict, result: dict) -> dict:
    failed = [c for c in result["checks"] if c["passed"] is False and c["affects_verdict"]]
    first = failed[0] if failed else None
    if not first:
        return {"failing_check": None, "root_cause": "no failed check", "recommended_candidate": None}
    if first["name"] == "static_start":
        cause = ("first-party code still requires a package the plan removed: " + "; ".join(first["evidence"]))
    elif first["name"] == "install":
        cause = "the patched lockfile does not install: " + "; ".join(first["evidence"][:3])
    elif first["name"] == "new_findings":
        cause = "the fix introduces new critical/high findings: " + "; ".join(first["evidence"][:3])
    else:
        cause = f"check {first['name']} failed: {first['detail']}"
    el = _eligible(plan, failed)
    return {"failing_check": first["name"], "root_cause": cause,
            "recommended_candidate": el[0]["id"] if el else "E",
            "why": (f"{el[0]['id']} ({el[0]['summary']}) is predicted to resolve the target with no dangling "
                    "require() and a passing plan gate" if el else "no remaining candidate avoids the failure: escalate"),
            "source": "deterministic (code)"}


def agent_diagnosis(run: Path, plan: dict, result: dict, mode: str) -> dict:
    if mode != "live" or os.environ.get("GUARDIAN_OFFLINE") == "1":
        return {"status": "skipped", "reason": f"mode={mode}"}
    models = load().get("agents", {}).get("gemini", {})
    index = EvidenceIndex()
    logs = json.loads((run / "validation" / plan["id"] / "logs.json").read_text(encoding="utf-8"))
    ids = [index.add_tool_output("check", {"name": c["name"]}, json.dumps(c)) for c in result["checks"]]
    lid = index.add_tool_output("logs", {"plan": plan["id"]}, json.dumps(logs)[:6000])
    alts = index.add_tool_output("candidates", {"plan": plan["id"]}, json.dumps(plan["alternatives_considered"])[:6000])
    payload = (f"Validation of plan {plan['id']} ({plan['chosen']['summary']}) for finding {plan['finding']} "
               f"returned {result['verdict']}.\nEvidence ids: checks {ids}, logs {lid}, candidates {alts}.\n<tool_output>\n"
               + "\n".join(f"[{i}] {index.items[i]['excerpt'][:1500]}" for i in ids + [lid, alts]) + "\n</tool_output>")
    try:
        client = Gemini(models.get("diagnostician", models.get("default", "gemini-2.5-flash")))
    except AgentUnavailable as e:
        return {"status": "skipped", "reason": str(e)}
    r = run_agent(name="diagnostician", model_client=client, system=PROMPT.read_text(encoding="utf-8"), payload=payload,
                  tools={}, schema=SCHEMA, index=index, max_turns=2)
    if r["status"] != "ok":
        return {"status": "skipped", "reason": r["reason"]}
    out = r["result"]
    return {"status": "ok", "model": r["model"], **{k: v for k, v in out.items() if k != "claims"},
            "claims": [index.check_claim(c, r["model"]) for c in out.get("claims", [])]}


def close_loop(run: Path, plan_id: str, result: dict, mode: str = "live") -> dict | None:
    """After a failed validation: diagnose, then create the superseding plan (pending approval)."""
    if result["verdict"] != "failed":
        return None
    plan = runs.read_json(run, f"plans/{plan_id}.json")
    det = deterministic_diagnosis(plan, result)
    ai = agent_diagnosis(run, plan, result, mode)
    failed = [c for c in result["checks"] if c["passed"] is False]
    allowed = {a["id"] for a in _eligible(plan, failed)}
    rec = det["recommended_candidate"]
    note = "code's recommendation"
    if ai.get("status") == "ok" and ai.get("recommended_candidate") in allowed:
        rec, note = ai["recommended_candidate"], "agent recommendation, accepted by code (eligible alternative)"
    elif ai.get("status") == "ok":
        note = f"agent recommended {ai.get('recommended_candidate')}, not eligible; code's choice kept"
    diag = {"plan": plan_id, "deterministic": det, "agent": ai, "recommended_candidate": rec, "decision_note": note}
    runs.write_json(run, f"validation/{plan_id}.diagnosis.json", diag)
    audit.append(run, "guardian", "diagnosis", plan_id, {"failing_check": det["failing_check"], "recommended": rec})
    if rec == "E":
        return {"diagnosis": diag, "new_plan": None}
    new = remediate.make_plan(run, plan["finding"], force_candidate=rec, supersedes=plan_id,
                              chosen_by=f"diagnosis of failed {plan_id} ({note})")
    return {"diagnosis": diag, "new_plan": new}
