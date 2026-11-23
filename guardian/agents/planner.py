"""Remediation Planner (rationale for the chosen candidate) and the Refuter's review of a plan.

Both write INFERRED claims only. Neither can change which candidate is chosen, the prediction, the
policy result or the patch: those are code output. If the Planner prefers another candidate, that
preference is recorded for the human approver.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..evidence import EvidenceIndex
from .llm import AgentUnavailable, Gemini, run_agent
from .runner import CLAIM, SCHEMAS

PROMPTS = Path(__file__).parent / "prompts"
PLANNER_SCHEMA = {"type": "object", "properties": {
    "preferred_candidate": {"type": "string"}, "claims": {"type": "array", "items": CLAIM},
    "compatibility_impact": {"type": "string"}, "what_could_go_wrong": {"type": "string"},
    "unknowns": {"type": "array", "items": {"type": "string"}}},
    "required": ["preferred_candidate", "claims", "compatibility_impact", "what_could_go_wrong", "unknowns"]}


def _summary(plan: dict, cands: list[dict], index: EvidenceIndex) -> str:
    rows = []
    for c in cands:
        p = c["prediction"]
        eid = index.add_tool_output("dry_run", {"candidate": c["id"]}, json.dumps({
            "candidate": c["id"], "summary": c["summary"], "applied": p.get("applied"),
            "target_resolved": p.get("target_resolved"), "resolved": len(p.get("resolved", [])),
            "added": p.get("added", [])[:10], "removed": p.get("removed", [])[:10], "semver": p.get("semver"),
            "new_vulnerabilities": [v["advisory"] + " " + v["severity"] for v in p.get("new_vulnerabilities", [])][:10],
            "dangling_requires": p.get("dangling_requires"), "plan_gate": (p.get("plan_gate") or {}).get("reason")}))
        rows.append(f"[{eid}] candidate {c['id']} ({c['kind']}): {c['summary']}")
    return (f"Plan {plan['id']} for finding {plan['finding']} ({plan['finding_type']}) on {plan['component']}.\n"
            f"Code chose {plan['chosen']['id']} by deterministic ranking.\nDry-run results (cite these ids):\n"
            "<tool_output>\n" + "\n".join(rows) + "\n</tool_output>")


def make_planner(mode: str, models: dict, max_turns: int = 4):
    def planner(ctx, plan, cands) -> dict:
        if mode != "live":
            return {"status": "skipped", "reason": f"mode={mode}"}
        try:
            index = EvidenceIndex()
            payload = _summary(plan, cands, index)
            out = {}
            for role, prompt, schema in (("remediation_planner", "remediation_planner.md", PLANNER_SCHEMA),
                                         ("refuter", "refuter.md", SCHEMAS["refuter"])):
                client = Gemini(models.get(role, models.get("default", "gemini-2.5-flash")))
                task = payload if role == "remediation_planner" else (
                    payload + "\n\nArgue against the CHOSEN plan: will it break the app, miss the risk, or add risk?")
                r = run_agent(name=f"plan_{role}", model_client=client, system=(PROMPTS / prompt).read_text(encoding="utf-8"),
                              payload=task, tools={}, schema=schema, index=index, max_turns=max_turns)
                if r["status"] != "ok":
                    out[role] = {"status": "skipped", "reason": r["reason"]}
                    continue
                res = r["result"]
                out[role] = {"status": "ok", "model": r["model"],
                             "claims": [index.check_claim(c, r["model"]) for c in res.get("claims", [])],
                             **{k: v for k, v in res.items() if k != "claims"}}
            pref = out.get("remediation_planner", {}).get("preferred_candidate")
            if pref and pref != plan["chosen"]["id"]:
                out["note_for_approver"] = f"the Planner preferred {pref}; code chose {plan['chosen']['id']}"
            return out
        except AgentUnavailable as e:
            return {"status": "skipped", "reason": str(e)}
    return planner if os.environ.get("GUARDIAN_OFFLINE") != "1" else make_planner_offline()


def make_planner_offline():
    return lambda ctx, plan, cands: {"status": "skipped", "reason": "offline"}
