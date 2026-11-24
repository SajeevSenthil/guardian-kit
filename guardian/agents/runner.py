"""Stage `analyse` (phases 5 and 9): Change Detective, Risk Analyst and Refuter, applied by code.

How agent output is used (LLMs propose; code decides):
- Change Detective -> `ai_assessment` on change findings (INFERRED claims, checked quotes). Its
  suggested risk is shown as a proposal; it never changes the score.
- Risk Analyst -> vulnerable symbols. A symbol counts only if its advisory quote is a literal
  substring of the advisory text (checked here). Code then recomputes the reachability tier from
  the app's own call sites (reachability.tier_with_symbols, grade `inferred`) and re-scores.
- Refuter -> verdict, applied by fixed rules: upheld -> confidence +5; downgraded -> the named
  factor's grade drops one step and the finding is re-scored (confidence drops); refuted -> the
  finding becomes a "not affected CANDIDATE" awaiting a named human (score unchanged);
  inconclusive -> nothing. A downgrade or refutation with no checked quote is treated as inconclusive.
Offline, or when the model is unavailable, every agent step is "skipped" and nothing changes.
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import re
import subprocess
from pathlib import Path

from .. import reachability, runs, scoring
from ..config import load
from ..evidence import EvidenceIndex
from ..prioritise import INFO_TYPES, _osv_text
from .llm import AgentUnavailable, Gemini, run_agent
from .tools import RunTools

PROMPTS = Path(__file__).parent / "prompts"
CLAIM = {"type": "object", "properties": {"text": {"type": "string"},
                                          "evidence_ids": {"type": "array", "items": {"type": "string"}},
                                          "quotes": {"type": "array", "items": {"type": "string"}}},
         "required": ["text", "evidence_ids"]}
LEVELS = ["critical", "high", "medium", "low"]
SCHEMAS = {
    "change_detective": {"type": "object", "properties": {
        "summary": {"type": "string"}, "claims": {"type": "array", "items": CLAIM},
        "resembles": {"type": "object", "properties": {"pattern": {"type": "string"}, "why": {"type": "string"}},
                      "required": ["pattern", "why"]},
        "suggested_risk": {"type": "string", "enum": LEVELS}, "suggested_risk_reason": {"type": "string"},
        "would_lower": {"type": "string"}, "would_raise": {"type": "string"},
        "unknowns": {"type": "array", "items": {"type": "string"}}},
        "required": ["summary", "claims", "suggested_risk", "unknowns"]},
    "risk_analyst": {"type": "object", "properties": {
        "vulnerable_symbols": {"type": "array", "items": {"type": "object", "properties": {
            "symbol": {"type": "string"}, "advisory_quote": {"type": "string"}, "evidence_id": {"type": "string"}},
            "required": ["symbol", "advisory_quote"]}},
        "app_reaches": {"type": "string", "enum": ["yes", "no", "unknown"]},
        "call_site": {"type": "object", "properties": {"file": {"type": "string"}, "line": {"type": "integer"},
                                                       "quote": {"type": "string"}, "evidence_id": {"type": "string"}}},
        "claims": {"type": "array", "items": CLAIM}, "unknowns": {"type": "array", "items": {"type": "string"}}},
        "required": ["vulnerable_symbols", "app_reaches", "claims", "unknowns"]},
    "refuter": {"type": "object", "properties": {
        "verdict": {"type": "string", "enum": ["upheld", "downgraded", "refuted", "inconclusive"]},
        "factor": {"type": "string", "enum": ["severity", "exploitability", "reachability", "exposure",
                                             "fix_availability", "none"]},
        "claims": {"type": "array", "items": CLAIM}, "benign_explanation": {"type": "string"}},
        "required": ["verdict", "factor", "claims"]},
}
TOOLS = {
    "change_detective": ["get_finding", "list_package_files", "read_package_file", "find_imports",
                         "commit_context", "list_incident_patterns"],
    "risk_analyst": ["get_finding", "get_advisory", "find_imports", "find_call_sites", "read_source_excerpt"],
    "refuter": ["get_finding", "get_advisory", "find_imports", "find_call_sites", "read_source_excerpt",
                "list_package_files", "read_package_file"],
}
DEMOTE = {"verified": "heuristic", "heuristic": "inferred", "inferred": "inferred", "unknown": "unknown"}


def _norm(s):
    return re.sub(r"\s+", " ", s or "").strip()


def _payload(f: dict, index: EvidenceIndex, role: str) -> str:
    ev = "\n".join(f"[{i}] {index.items[i]['source']}{', line ' + str(index.items[i]['line']) if index.items[i].get('line') else ''}: "
                   f"{index.items[i]['excerpt'][:300]}" for i in index.ids_for(f["id"]))
    p = f.get("priority", {})
    task = {"change_detective": "Investigate this supply-chain change and write your assessment.",
            "risk_analyst": "Identify the vulnerable symbol from the advisory and whether the app calls it.",
            "refuter": "Argue against this finding and give your verdict."}[role]
    return (f"{task}\n\nFinding {f['id']} ({f['type']}) on {f['component']}\nTitle: {f.get('title')}\n"
            f"Advisory: {f.get('advisory') or '-'}\nCurrent score: {p.get('score')} ({p.get('band')}), "
            f"confidence {p.get('confidence')}\nDependency path: {' -> '.join(f.get('path') or [])}\n"
            f"Introduced by: {(f.get('commit') or {}).get('sha', '-')} {(f.get('commit') or {}).get('subject', '')}\n"
            f"\nEvidence (cite these ids):\n<tool_output>\n{ev}\n</tool_output>")


def _rescore(f: dict, factors: dict, rails: list) -> None:
    f.setdefault("priority_before_agents", {k: f["priority"][k] for k in ("score", "band", "range", "confidence")})
    res = scoring.score(factors, [tuple(r) for r in rails])
    res["explanation"] = scoring.explain(res)
    res["rails"] = rails
    f["priority"] = res


# A package describing itself ("harmless", "demo", "safe", ...) is never evidence. Quotes made of such
# self-description do not count as support for lowering risk, even when they are literal.
SELF_DESCRIPTION = re.compile(r"(?i)\b(harmless|benign|safe|demo|example only|test(ing)? only|for testing|"
                              r"do not worry|don't worry|not malicious|no harm)\b")


def _supports(c: dict) -> bool:
    return bool(c["support_checked"]) and not any(SELF_DESCRIPTION.search(q) for q in c["quotes"])


def apply_refuter(f: dict, rec: dict, out: dict, claims: list[dict]) -> None:
    """Fixed rules for a Refuter verdict. Mutates the finding `f` and the record `rec`."""
    verdict, factor = out.get("verdict"), out.get("factor")
    supported = any(_supports(c) for c in claims)
    if verdict in ("downgraded", "refuted") and not supported:
        why = ("its only checked quotes are the package describing itself"
               if any(c["support_checked"] for c in claims) else "no reason had a checked quote")
        rec["applied"] = f"{verdict} -> inconclusive ({why})"
        verdict = "inconclusive"
    if verdict == "upheld":
        f["priority"]["confidence"] = min(100, f["priority"]["confidence"] + 5)
        rec["applied"] = "confidence +5"
    elif verdict == "downgraded" and factor in f["priority"]["factors"]:
        fac = f["priority"]["factors"][factor]
        factors = {**f["priority"]["factors"], factor: {**fac, "grade": DEMOTE[fac["grade"]]}}
        _rescore(f, factors, f["priority"]["rails"])
        rec["applied"] = f"{factor} grade {fac['grade']} -> {DEMOTE[fac['grade']]}; re-scored"
    elif verdict == "refuted":
        f["status"] = "not_affected_candidate"
        rec["applied"] = "not-affected CANDIDATE: waits for a named human (score unchanged)"
    else:
        rec.setdefault("applied", "no change")
    rec.update(verdict=out.get("verdict"), effective_verdict=verdict, factor=factor,
               benign_explanation=out.get("benign_explanation"))


def _commit_files(sha: str) -> list[str]:
    out = subprocess.run(["git", "-C", str(runs.TARGET), "show", "--name-only", "--format=", sha],
                         capture_output=True, check=False).stdout.decode("utf-8", "replace")
    return [x for x in out.splitlines() if x.strip()]


def analyse(run: Path, mode: str = "live", top_n: int | None = None, fresh: bool = False) -> dict:
    cfg = load()
    acfg = cfg.get("agents", {})
    models = acfg.get("gemini", {})
    pr = runs.read_json(run, "prioritised.json")
    day1 = runs.read_json(run, "findings.json")
    nodes = {n["id"]: n for n in runs.read_json(run, "graph.json")["nodes"]}
    meta = runs.read_json(run, "run.json")
    src = runs.materialise(run, meta["head"])
    pj = json.loads((src / "package.json").read_text(encoding="utf-8"))
    scan = reachability.scan(src, set(pj.get("dependencies", {})) | set(pj.get("devDependencies", {})))
    findings = pr["findings"]
    byid = {f["id"]: f for f in findings}
    index = EvidenceIndex(findings)
    tools = RunTools(run, findings, nodes, scan, src, day1.get("commits", []))
    n = top_n or cfg["run"]["top_n_for_agents"]
    ranked = [byid[i] for i in pr["ranking"]]
    top = ranked[:n]
    change = [f for f in ranked if f["type"] not in INFO_TYPES | {"known_vulnerability"} and f.get("new_in_head")]

    status = {}

    def client(role):
        if mode != "live":
            return None
        try:
            return Gemini(models.get(role, models.get("default", "gemini-2.5-flash")),
                          max_output_tokens=acfg.get("max_output_tokens", 2048))
        except AgentUnavailable as e:
            status[role] = str(e)
            return None

    jobs = [("change_detective", f) for f in change]
    jobs += [("risk_analyst", f) for f in top if f["type"] == "known_vulnerability"]
    jobs += [("refuter", f) for f in top]
    events: list = []

    def work(role, f):
        c = client(role)
        r = run_agent(name=role, model_client=c, system=(PROMPTS / f"{role}.md").read_text(encoding="utf-8"),
                      payload=_payload(f, index, role), tools=tools.as_tools(TOOLS[role]), schema=SCHEMAS[role],
                      index=index, max_turns=cfg["limits"]["agent_max_turns"],
                      token_budget=acfg.get("token_budget_per_agent", 120_000),
                      mode=mode if c else ("unavailable" if mode == "live" else mode), cache=not fresh,
                      events=events)
        if r["status"] == "skipped" and role in status:
            r["reason"] = status[role]
        return role, f["id"], r

    results: dict = {}
    with cf.ThreadPoolExecutor(cfg["run"]["agent_concurrency"]) as ex:
        for role, fid, r in ex.map(lambda j: work(*j), jobs):
            results.setdefault(fid, {})[role] = r

    stats = {"tokens": 0, "turns": 0, "tool_calls": 0, "quotes_kept": 0, "quotes_dropped": 0,
             "by_role": {}}
    for fid, roles in results.items():
        f = byid[fid]
        for role, r in roles.items():
            st = stats["by_role"].setdefault(role, {"ok": 0, "skipped": 0, "reasons": set()})
            if r["status"] != "ok":
                st["skipped"] += 1
                st["reasons"].add(r.get("reason") or "skipped")
                f.setdefault("agents", {})[role] = {"status": "skipped", "reason": r.get("reason")}
                continue
            st["ok"] += 1
            stats["tokens"] += r.get("tokens", 0)
            stats["turns"] += r.get("turns", 0)
            stats["tool_calls"] += len(r.get("tool_calls", []))
            out = r["result"]
            claims = [index.check_claim(c, r["model"]) for c in out.get("claims", [])]
            stats["quotes_kept"] += sum(len(c["quotes"]) for c in claims)
            stats["quotes_dropped"] += sum(len(c["dropped_quotes"]) for c in claims)
            rec = {"status": "ok", "model": r["model"], "turns": r["turns"], "claims": claims,
                   "tool_calls": [{k: t[k] for k in ("tool", "args", "evidence_id")} for t in r.get("tool_calls", [])],
                   "cached": r.get("cached", False)}
            if role == "change_detective":
                rec.update(summary=out.get("summary"), resembles=out.get("resembles"),
                           suggested_risk=out.get("suggested_risk"), suggested_risk_reason=out.get("suggested_risk_reason"),
                           would_lower=out.get("would_lower"), would_raise=out.get("would_raise"),
                           unknowns=out.get("unknowns"), note="proposal only; the score is computed by code")
            elif role == "risk_analyst":
                adv = _norm(_osv_text(f.get("advisory", "")))
                confirmed = [s["symbol"] for s in out.get("vulnerable_symbols", [])
                             if _norm(s.get("advisory_quote")) and _norm(s["advisory_quote"]) in adv
                             and s["symbol"].split(".")[-1] in s["advisory_quote"]]
                confirmed = [s.split(".")[-1] for s in confirmed]
                rec.update(vulnerable_symbols=out.get("vulnerable_symbols"), confirmed_symbols=confirmed,
                           app_reaches=out.get("app_reaches"), call_site=out.get("call_site"), unknowns=out.get("unknowns"))
                node = nodes.get(f.get("nodeId"))
                t = reachability.tier_with_symbols(node, confirmed, scan) if (node and confirmed) else None
                cur = f["priority"]["factors"]["reachability"]
                if t and reachability.TIER_VALUE[t["tier"]] > (cur["value"] or 0):
                    w = t["witness"][0]
                    factors = {**f["priority"]["factors"], "reachability": scoring.factor(
                        reachability.TIER_VALUE[t["tier"]], "inferred",
                        f"{t['tier']}: {t['note']} [{w['file']}:{w['line']} {w['excerpt']}]")}
                    rails = [r_ for r_ in f["priority"]["rails"] if r_[0] != "NOT_LOADED_CAP"]
                    _rescore(f, factors, rails)
                    rec["tier_change"] = f"{f.get('reachability', {}).get('tier')} -> {t['tier']} (inferred)"
                    f["reachability"] = {**t, "source": "risk_analyst"}
            elif role == "refuter":
                apply_refuter(f, rec, out, claims)
            f.setdefault("agents", {})[role] = rec

    # investigation records for non-CVE findings in the top N and every change finding
    inv = {}
    for f in {x["id"]: x for x in change + [t for t in top if t["type"] != "known_vulnerability"]}.values():
        node = nodes.get(f.get("nodeId"), {})
        same = [g for g in findings if g.get("nodeId") == f.get("nodeId") and g["type"] == "suspicious_update"]
        inv[f["id"]] = {
            "finding": f["id"], "component": f["component"], "type": f["type"],
            "timeline": {"commit": f.get("commit"), "commit_files": _commit_files(f["commit"]["sha"]) if f.get("commit") else []},
            "version_comparison": [e for g in same for e in g["evidence"]],
            "provenance": {"resolved": node.get("resolved"), "registry": node.get("registry"),
                           "integrity": node.get("integrity"), "signature": "not evaluated"},
            "verified_facts": [{"id": i, **index.items[i]} for i in index.ids_for(f["id"])],
            "ai_assessment": f.get("agents", {}).get("change_detective"),
            "resembles": (f.get("agents", {}).get("change_detective") or {}).get("resembles"),
        }

    # re-rank after any re-scoring
    best: dict = {}
    for f in findings:
        key = (f["component"], f.get("advisory") or f["id"])
        if key not in best or f["priority"]["score"] > best[key]["priority"]["score"]:
            best[key] = f
    pr["ranking"] = [f["id"] for f in sorted(best.values(), key=lambda f: (-f["priority"]["score"],
                                                                           -f["priority"]["confidence"], f["id"]))]
    for st in stats["by_role"].values():
        st["reasons"] = sorted(st["reasons"])
    pr.setdefault("meta", {})["analysis"] = {"mode": mode, "provider": acfg.get("provider", "gemini"),
                                             "models": models, "jobs": len(jobs), **stats}
    runs.write_json(run, "prioritised.json", pr)
    runs.write_json(run, "investigations.json", inv)
    runs.write_json(run, "evidence_index.json", index.items)
    (run / "agent_trace.jsonl").write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    runs.mark_stage(run, "analyse", "ok" if mode == "live" else f"skipped ({mode})")
    return pr["meta"]["analysis"]
