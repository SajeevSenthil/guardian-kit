"""Stage `report` (phase 12): Guardian report rendered from the run directory only.

Outputs in runs/<id>/report/:
  guardian-report.json   machine-readable, validated against schemas/guardian-report.schema.json
  guardian-report.md     human-readable (follows templates/guardian-report.md)
  guardian-report.html   human-readable, one self-contained file
  vex.openvex.json       OpenVEX: `fixed` for validated remediations, `not_affected` ONLY when a named
                         human confirmed it (`guardian accept --as not-affected`)
  sbom.before.cdx.json, sbom.after.<plan>.cdx.json   CycloneDX before / after each validated fix

The executive summary is a template filled by code; every sentence cites finding, plan or evidence
ids. No model writes report text.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import platform
import shutil
import subprocess
from pathlib import Path

from . import audit, runs

KIT = Path(__file__).resolve().parents[1]
SCHEMA = KIT / "schemas" / "guardian-report.schema.json"
BANDS = ["critical", "high", "medium", "low", "info"]
TYPE_LABEL = {"typosquat": "look-alike name"}


def _t(t: str) -> str:
    return TYPE_LABEL.get(t, t)


def _load(run: Path, name: str, default=None):
    p = run / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default


def _all(run: Path, folder: str, pattern: str) -> dict:
    d = run / folder
    return {p.stem.split(".")[0]: json.loads(p.read_text(encoding="utf-8"))
            for p in sorted(d.glob(pattern))} if d.is_dir() else {}


def _ver(cmd: list[str]) -> str:
    exe = shutil.which(cmd[0])
    if not exe:
        return "not installed"
    try:
        out = subprocess.run([exe, *cmd[1:]], capture_output=True, timeout=30, check=False)
        return (out.stdout or out.stderr).decode("utf-8", "replace").strip().splitlines()[0]
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def vuln_clause(osv_status: str | None, pairs: int | None) -> str:
    """Unknown is never zero: without an evaluated OSV lookup the report must not print a count."""
    if osv_status == "evaluated" and pairs is not None:
        return f"{pairs} package–advisory vulnerability pairs are present; "
    return "known vulnerabilities were NOT evaluated (OSV unavailable: unknown, not zero); "


def docker_sentence(docker_installed: bool) -> str:
    return ("The container build and HTTP smoke test are not implemented in this build"
            + ("" if docker_installed else " (and docker is not installed on this machine)")
            + "; a 'partial' verdict means the fix is confirmed by install, static checks and rescan, not by a build.")


# ---------------------------------------------------------------------------------- decisions
def accept(run: Path, finding_id: str, as_: str, by: str, reason: str) -> dict:
    """Record a human decision: not-affected (feeds VEX) or accepted-risk. Both need a name and a reason."""
    if as_ not in ("not-affected", "accepted-risk"):
        raise ValueError("--as must be not-affected or accepted-risk")
    if not (by or "").strip() or not (reason or "").strip():
        raise ValueError("a named human (--by) and a reason are required")
    pr = _load(run, "prioritised.json")
    if pr and finding_id not in {f["id"] for f in pr["findings"]}:
        raise KeyError(f"no finding {finding_id}")
    rec = {"finding": finding_id, "decision": as_, "by": by.strip(), "reason": reason.strip(),
           "at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds")}
    runs.write_json(run, f"decisions/{finding_id}.json", rec)
    audit.append(run, f"human:{rec['by']}", f"finding.{as_}", finding_id, {"reason": rec["reason"]})
    return rec


# ---------------------------------------------------------------------------------- VEX
def build_vex(run_id: str, findings: dict, validations: dict, decisions: dict, head_commit: str) -> dict:
    stmts = []
    seen = set()
    for pid, v in validations.items():
        if v.get("verdict") not in ("verified", "partial"):
            continue
        for fid in v.get("resolved_ids", []):
            f = findings.get(fid)
            if not f or f["type"] != "known_vulnerability" or (f["advisory"], f["component"]) in seen:
                continue
            seen.add((f["advisory"], f["component"]))
            note = (f"Resolved on branch {v.get('branch')} ({v.get('commit')}) by plan {pid}, approved by a human; "
                    + ("build and tests passed." if v["verdict"] == "verified"
                       else "rescan confirms the fix; build and tests were NOT run (" + ", ".join(v.get("not_run", [])) + ")."))
            stmts.append({"vulnerability": {"name": f["advisory"], "aliases": f.get("aliases", [])},
                          "products": [{"@id": f"git:target@{v.get('commit')}", "subcomponents": [{"@id": f["component"]}]}],
                          "status": "fixed", "status_notes": note})
    for fid, d in decisions.items():
        f = findings.get(fid)
        if d["decision"] != "not-affected" or not f or f["type"] != "known_vulnerability":
            continue
        stmts.append({"vulnerability": {"name": f["advisory"], "aliases": f.get("aliases", [])},
                      "products": [{"@id": f"git:target@{head_commit}", "subcomponents": [{"@id": f["component"]}]}],
                      "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path",
                      "impact_statement": f"Confirmed by {d['by']} on {d['at']}: {d['reason']}"})
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"https://guardian.invalid/vex/{run_id}",
            "author": "Guardian (generated from human-approved decisions)",
            "timestamp": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), "version": 1, "statements": stmts}


# ---------------------------------------------------------------------------------- collect
def collect(run: Path) -> dict:
    meta = _load(run, "run.json")
    day1 = _load(run, "findings.json")
    pr = _load(run, "prioritised.json")
    graph = _load(run, "graph.json")
    plans = _all(run, "plans", "P-*.json")
    approvals = _all(run, "approvals", "P-*.json")
    validations = {k: v for k, v in _all(run, "validation", "P-*.json").items() if "verdict" in v}
    decisions = _all(run, "decisions", "*.json")
    findings = {f["id"]: f for f in pr["findings"]}
    ranking = pr["ranking"]
    chain_ok, chain_msg = audit.verify(run)
    events = [json.loads(x) for x in (run / "audit.jsonl").read_text(encoding="utf-8").splitlines()] \
        if (run / "audit.jsonl").exists() else []

    resolved: dict[str, tuple[str, str]] = {}
    for pid, v in validations.items():
        if v["verdict"] in ("verified", "partial"):
            for fid in v.get("resolved_ids", []):
                resolved.setdefault(fid, (pid, v["verdict"]))
    planned = {}
    for pid, p in plans.items():   # every finding a pending/approved plan is predicted to resolve
        if p["state"] in ("pending_approval", "approved"):
            for fid in [p["finding"], *(p["prediction"].get("resolved") or [])]:
                planned.setdefault(fid, pid)

    def status(fid):
        if fid in decisions:
            return decisions[fid]["decision"].replace("-", "_")
        if fid in resolved:
            return f"remediated_{resolved[fid][1]}"
        if findings[fid].get("status") == "not_affected_candidate":
            return "not_affected_candidate"
        if fid in planned:
            return "fix_planned"
        return "open"

    def claims(f):
        ver = [{"type": "verified" if e.get("kind", "verified") == "verified" else "derived",
                "evidence_id": f"{f['id']}.E{i}", "source": e["source"], "line": e.get("line"), "excerpt": e["excerpt"][:300]}
               for i, e in enumerate(f.get("evidence", []), 1)]
        inf = []
        for role, a in (f.get("agents") or {}).items():
            if a.get("status") == "ok":
                inf += [{"type": "inferred", "agent": role, "model": c["model"], "text": c["text"],
                         "evidence_ids": c["evidence_ids"], "support_checked": c["support_checked"]} for c in a["claims"]]
        return ver, inf

    items = []
    for fid in ranking:
        f = findings[fid]
        p = f["priority"]
        ver, inf = claims(f)
        items.append({"id": fid, "type": f["type"], "title": f.get("title"), "component": f["component"],
                      "advisory": f.get("advisory"), "path": f.get("path"), "new_in_head": f.get("new_in_head"),
                      "commit": f.get("commit"), "score": p["score"], "band": p["band"], "range": p["range"],
                      "confidence": p["confidence"], "factors": {k: {"value": v["value"], "grade": v["grade"],
                                                                     "evidence": v["evidence"]} for k, v in p["factors"].items()},
                      "guardrails": p["guardrails"], "explanation": p["explanation"],
                      "refuter": ((f.get("agents") or {}).get("refuter") or {}).get("effective_verdict"),
                      "status": status(fid), "verified_claims": ver, "inferred_claims": inf,
                      "agent_steps": {r: a.get("status") for r, a in (f.get("agents") or {}).items()}})
    by_band = {b: sum(1 for i in items if i["band"] == b) for b in BANDS}
    need = [i for i in items if i["band"] in ("critical", "high")]
    open_need = [i for i in need if i["status"] in ("open", "fix_planned", "not_affected_candidate")]
    counts = day1["counts"]

    plan_rows = []
    for pid, p in plans.items():
        a = approvals.get(pid)
        v = validations.get(pid)
        plan_rows.append({"id": pid, "finding": p["finding"], "component": p["component"], "state": p["state"],
                          "supersedes": p.get("supersedes"), "action": p["chosen"], "chosen_by": p["chosen_by"],
                          "alternatives": [{"id": x["id"], "summary": x["summary"], "why_not_chosen": x["why_not_chosen"]}
                                           for x in p["alternatives_considered"]],
                          "prediction": {k: p["prediction"].get(k) for k in ("target_resolved", "resolved_by_band", "added",
                                                                             "removed", "version_changes", "semver",
                                                                             "new_vulnerabilities", "dangling_requires", "risk")},
                          "compatibility": {"semver": p["prediction"].get("semver"),
                                            "version_changes": p["prediction"].get("version_changes"),
                                            "dangling_requires": p["prediction"].get("dangling_requires")},
                          "policy": {"head": p["policy_head"]["pass"], "predicted": p["prediction"]["policy"]["pass"],
                                     "plan_gate": p["prediction"]["plan_gate"]},
                          "policy_entries": p.get("policy_entries", []), "rollback": p["rollback"],
                          "plan_hash": p["plan_hash"],
                          "approval": {k: a[k] for k in ("approver", "decision", "at", "plan_hash", "comment")} if a else None,
                          "validation": {"verdict": v["verdict"], "not_run": v.get("not_run", []),
                                         "checks": [{k: c[k] for k in ("name", "status", "detail", "evidence", "seconds",
                                                                       "affects_verdict")} for c in v["checks"]],
                                         "risk": v.get("risk"), "sbom_diff": v.get("sbom_diff"),
                                         "branch": v.get("branch"), "commit": v.get("commit")} if v else None,
                          "ai_rationale": p.get("rationale", {}).get("ai")})

    verified = [pid for pid, v in validations.items() if v["verdict"] == "verified"]
    partial = [pid for pid, v in validations.items() if v["verdict"] == "partial"]
    failed = [pid for pid, v in validations.items() if v["verdict"] == "failed"]
    accepted = [d for d in decisions.values() if d["decision"] == "accepted-risk"]
    not_aff = [d for d in decisions.values() if d["decision"] == "not-affected"]
    candidates = [i["id"] for i in items if i["status"] == "not_affected_candidate"]
    analysis = (pr.get("meta") or {}).get("analysis") or {}
    agents_ran = sum(s["ok"] for s in analysis.get("by_role", {}).values())
    agents_skipped = sum(s["skipped"] for s in analysis.get("by_role", {}).values())

    nodes = graph["nodes"]
    pkgs = [n for n in nodes if n.get("kind") == "pkg"]
    top = items[:3]
    new_sus = [i for i in items if i["new_in_head"]
               and i["type"] not in ("known_vulnerability", "new_dependency", "changed_dependency")]
    summary = [
        {"text": f"Guardian compared {meta['base']} ({meta['base_sha'][:7]}) with {meta['head']} ({meta['head_sha'][:7]}) "
                 f"and inventoried {counts['packages']} packages ({counts['install_paths']} install paths, "
                 f"{counts['direct']} direct).", "cites": ["sbom.head.cdx.json"]},
        {"text": f"{len(new_sus)} supply-chain findings were introduced since the baseline, and "
                 + vuln_clause(day1["meta"]["osv"].get("status"), counts.get("vuln_pairs"))
                 + f"{len(need)} ranked items need attention (critical or high).",
         "cites": [i["id"] for i in new_sus][:12]},
    ] + [{"text": f"Ranked #{n}: {i['title'] or i['advisory']} on {i['component']} scores {i['score']} ({i['band']}), "
                  f"confidence {i['confidence']}.", "cites": [i["id"]]} for n, i in enumerate(top, 1)] + [
        {"text": f"{len(plans)} remediation plan(s) were created, {sum(1 for a in approvals.values() if a['decision'] == 'approved')} "
                 f"approved by a human, {len(validations)} validated "
                 f"({len(verified)} verified, {len(partial)} partial, {len(failed)} failed).", "cites": sorted(plans)},
        {"text": f"{len(open_need)} critical/high item(s) remain open; {len(accepted)} risk(s) were accepted and "
                 f"{len(not_aff)} marked not affected by a named human.", "cites": [i["id"] for i in open_need][:12]},
        {"text": docker_sentence(shutil.which("docker") is not None), "cites": partial or []},
    ]
    not_evaluated = [
        {"item": "container build and smoke test", "why": "not implemented in this build"
         + ("" if shutil.which("docker") else "; docker not installed"), "effect": "validation verdicts at best partial"},
        {"item": f"{sum(1 for n in pkgs if not n.get('resolved'))} bundled install paths", "why": "no download origin in the lockfile; OSV cannot match them", "effect": "vulnerabilities not evaluated (unknown, not clean)"},
        {"item": "install scripts of registry packages", "why": "tarballs are not downloaded", "effect": "reported as 'content not inspected'"},
        {"item": "image digest / action SHA pinning", "why": "no Docker Hub or GitHub lookups", "effect": "fix candidates restore the base tag or delete the workflow instead"},
        {"item": "conftest / OPA", "why": "not installed", "effect": "policy evaluated by guardian/policy.py (Python port of policy/guardian.rego)"},
        {"item": "syft, grype, osv-scanner", "why": "not installed", "effect": "lockfile SBOM + OSV API used; no second scanner to cross-check"},
        {"item": f"AI agent steps ({agents_skipped} skipped, {agents_ran} ran)", "why": analysis.get("by_role") and
         "; ".join(f"{r}: {', '.join(s['reasons'])}" for r, s in analysis["by_role"].items() if s["reasons"]) or "analyse not run",
         "effect": "no AI assessment where skipped; scores are computed by code either way"},
    ]
    osv = day1["meta"]["osv"]
    if osv.get("status") != "evaluated":
        not_evaluated.insert(0, {"item": "known vulnerabilities (OSV)", "why": osv.get("reason") or osv.get("status"),
                                 "effect": "no vulnerability findings: unknown, not zero"})
    if pr["meta"]["kev"].get("status") != "evaluated":
        not_evaluated.append({"item": "CISA KEV", "why": pr["meta"]["kev"].get("error") or "not evaluated",
                              "effect": "KEV membership unknown; KEV_FLOOR cannot fire"})
    missing_epss = pr["meta"]["epss"]["requested"] - pr["meta"]["epss"]["scored"]
    if pr["meta"]["epss"]["status"] != "evaluated":
        not_evaluated.append({"item": "EPSS", "why": "; ".join(pr["meta"]["epss"].get("errors", [])) or "not evaluated",
                              "effect": "exploitability unknown: prior used, range widened"})
    elif missing_epss:
        not_evaluated.append({"item": f"EPSS for {missing_epss} CVE(s)", "why": "no score published",
                              "effect": "exploitability unknown: prior used, range widened"})
    weights = {i["id"]: i["confidence"] for i in need}
    overall_conf = round(sum(weights.values()) / len(weights)) if weights else None
    ev_index = [{"id": c["evidence_id"], "source": c["source"], "line": c["line"], "type": c["type"],
                 "sha256": hashlib.sha256(c["excerpt"].encode("utf-8")).hexdigest()}
                for i in items for c in i["verified_claims"]]
    before_after = {"need_attention_open_before": len(need),
                    "need_attention_open_after": len(open_need),
                    "findings_before": len(pr["findings"]),
                    "validated_plans": {pid: {"verdict": v["verdict"], "risk": v.get("risk"), "sbom_diff": v.get("sbom_diff"),
                                              "prediction": next((c for c in v["checks"] if c["name"] == "prediction"), None)}
                                        for pid, v in validations.items()}}
    commits = []
    for c in day1.get("commits", []):
        fs = [i for i in items if (i.get("commit") or {}).get("sha") == c["sha"]]
        commits.append({"sha": c["sha"], "subject": c["subject"], "findings": [{"id": i["id"], "type": i["type"],
                                                                                 "band": i["band"]} for i in fs]})
    return {
        "schema": "guardian-report/1.0",
        "run": {"run_id": meta["run_id"], "target": meta["target"], "base": meta["base"], "base_sha": meta["base_sha"],
                "head": meta["head"], "head_sha": meta["head_sha"], "mode": meta.get("mode"),
                "generated": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
                "sample_app": {"repository": "https://github.com/snyk-labs/nodejs-goof", "licence": "Apache-2.0",
                               "commit": "add14ba59e98240d9e00a235dd7d42cd61ae9912",
                               "modifications": "scripts/make_demo_target.sh: baseline smoke test + vendored helper; "
                                                "tampered branch with 4 simulated attack commits (local only)"}},
        "tools": {"python": platform.python_version(), "git": _ver(["git", "--version"]), "node": _ver(["node", "--version"]),
                  "npm": _ver(["npm", "--version"]), "docker": _ver(["docker", "--version"])},
        "data_sources": {"osv": day1["meta"]["osv"], "epss": pr["meta"]["epss"], "kev": pr["meta"]["kev"],
                         "models": analysis.get("models"), "agent_mode": analysis.get("mode", "analyse not run")},
        "summary": {"counts": {"packages": counts["packages"], "install_paths": counts["install_paths"],
                               "findings": len(pr["findings"]), "ranked_items": len(items), "by_band": by_band,
                               "need_attention": len(need), "remediated_verified": len(verified),
                               "remediated_partial": len(partial), "remaining_open_need_attention": len(open_need),
                               "accepted_risk": len(accepted), "not_affected": len(not_aff)},
                    "sentences": summary},
        "inventory": {"direct": counts["direct"], "transitive": counts["transitive"], "prod_paths": counts["prod"],
                      "dev_paths": counts["dev"],
                      "origins": {"registry": sum(1 for n in pkgs if n.get("registry")),
                                  "local_file": sum(1 for n in pkgs if (n.get("resolved") or "").startswith("file:")),
                                  "bundled": sum(1 for n in pkgs if not n.get("resolved"))},
                      "sbom_files": ["sbom.before.cdx.json"] + [f"sbom.after.{pid}.cdx.json" for pid in validations
                                                                 if validations[pid]["verdict"] != "failed"],
                      "path_examples": [{"id": i["id"], "path": i["path"]} for i in items[:10]]},
        "changes": commits,
        "findings": items,
        "plans": plan_rows,
        "remaining": {"open_by_band": {b: sum(1 for i in items if i["band"] == b and i["status"] == "open") for b in BANDS},
                      "accepted_risks": accepted, "not_affected": not_aff, "not_affected_candidates": candidates},
        "before_after": before_after,
        "confidence": {"overall": overall_conf, "basis": "mean confidence of critical/high items",
                       "drivers": {"unknown_factors": sum(1 for i in need for f in i["factors"].values() if f["grade"] == "unknown"),
                                   "inferred_factors": sum(1 for i in need for f in i["factors"].values() if f["grade"] == "inferred"),
                                   "agent_steps_skipped": agents_skipped}},
        "audit": {"chain_ok": chain_ok, "result": chain_msg, "events": len(events),
                  "by_actor": {a: sum(1 for e in events if e["actor"] == a) for a in sorted({e["actor"] for e in events})}},
        "not_evaluated": not_evaluated,
        "evidence_index": ev_index,
    }


# ---------------------------------------------------------------------------------- render
def _md(rep: dict) -> str:
    r, s = rep["run"], rep["summary"]["counts"]
    L = [f"# Guardian Report — {r['target']} @ {r['head']} ({r['head_sha'][:7]})", "",
         (f"Run {r['run_id']} · {r['generated']} · scan mode {r['mode']} · agents: {rep['data_sources']['agent_mode']} · "
         f"baseline {r['base']} ({r['base_sha'][:7]})"), "",
         ("> Claim types: **verified** = read from tool output (evidence id shown) · **derived** = computed by Guardian's code "
         "· **inferred (AI)** = model judgement. \"Unknown\" means not established; it never means safe."), "",
         "## 1. Executive summary", ""]
    L += [f"- {x['text']}" + (f" [{', '.join(x['cites'][:8])}{'…' if len(x['cites']) > 8 else ''}]" if x["cites"] else "")
          for x in rep["summary"]["sentences"]]
    L += ["", "| Components | Findings | Need attention | Remediated and verified | Remediated (partial) | Remaining open (crit/high) | Accepted risk |",
          "|---|---|---|---|---|---|---|",
          (f"| {s['packages']} ({s['install_paths']} paths) | {s['findings']} | {s['need_attention']} | {s['remediated_verified']} | "
          f"{s['remediated_partial']} | {s['remaining_open_need_attention']} | {s['accepted_risk']} |"), "",
          "## 2. Scope and method", "",
          (f"Sample application: {r['sample_app']['repository']} ({r['sample_app']['licence']}), commit "
          f"`{r['sample_app']['commit'][:8]}`. Modifications: {r['sample_app']['modifications']}."), "",
          "Tools: " + ", ".join(f"{k} {v}" for k, v in rep["tools"].items()), "",
          (f"Data sources: OSV ({rep['data_sources']['osv'].get('status')}), EPSS ({rep['data_sources']['epss']['status']}), "
          f"CISA KEV ({rep['data_sources']['kev']['status']}, catalog {rep['data_sources']['kev'].get('catalogVersion')}). "
          f"Agents: {rep['data_sources']['agent_mode']}, models {rep['data_sources']['models']}."), "",
          "**Not evaluated:**", ""]
    L += [f"- {n['item']}: {n['why']} → {n['effect']}" for n in rep["not_evaluated"]]
    inv = rep["inventory"]
    L += ["", "## 3. Component inventory and dependency paths", "",
          (f"{s['packages']} packages: {inv['direct']} direct, {inv['transitive']} transitive; install paths {inv['prod_paths']} prod / "
          f"{inv['dev_paths']} dev; origins {inv['origins']}. SBOMs: {', '.join(inv['sbom_files'])}."), ""]
    L += [f"- {p['id']}: {' → '.join(p['path'] or [])}" for p in inv["path_examples"]]
    L += ["", "## 4. What changed (baseline → head)", ""]
    for c in rep["changes"]:
        L.append(f"- **{c['sha']}** {c['subject']}: " + (", ".join(f"{f['id']} {_t(f['type'])} ({f['band']})" for f in c["findings"]) or "no findings"))
    L += ["", f"## 5. Findings and supporting evidence (top 25 of {len(rep['findings'])} ranked)", ""]
    for i in rep["findings"][:25]:
        L += [f"### {i['id']} · {i['score']} {i['band']} · {_t(i['type'])} · {i['component']}", "",
              f"{i['title'] or i['advisory']} — status **{i['status']}**, range {i['range']}, confidence {i['confidence']}"
              + (f", guardrails {', '.join(g['name'] for g in i['guardrails'])}" if i["guardrails"] else "")
              + (f", refuter {i['refuter']}" if i["refuter"] else ""), "",
              f"Path: {' → '.join(i['path'] or [])}", "", "| factor | value | grade | evidence |", "|---|---|---|---|"]
        L += [f"| {k} | {v['value'] if v['value'] is not None else 'unknown'} | {v['grade']} | {v['evidence'][:140]} |"
              for k, v in i["factors"].items()]
        L += [""] + [f"- *{c['type']}* `{c['evidence_id']}` {c['source']}{', line ' + str(c['line']) if c['line'] else ''}: `{c['excerpt'][:160]}`"
                     for c in i["verified_claims"][:4]]
        L += [f"- *inferred (AI, {c['model']})*: {c['text']} (support checked: {c['support_checked']})" for c in i["inferred_claims"][:3]]
        L.append("")
    L += ["## 6. Recommended and approved actions", ""]
    for p in rep["plans"]:
        a = p["approval"]
        L += [f"### {p['id']} — {p['action']['summary']}", "",
              f"Finding {p['finding']} on {p['component']} · state **{p['state']}** · chosen by {p['chosen_by']}"
              + (f" · supersedes {p['supersedes']}" if p["supersedes"] else ""), "",
              (f"Predicted: target resolved {p['prediction']['target_resolved']}, resolved {p['prediction']['resolved_by_band']}, "
              f"semver {p['prediction']['semver']}, new vulnerabilities {len(p['prediction']['new_vulnerabilities'] or [])}, "
              f"dangling require() {p['prediction']['dangling_requires']}. Plan gate: {'PASS' if p['policy']['plan_gate']['pass'] else 'FAIL'} "
              f"({p['policy']['plan_gate']['reason']})."), "",
              "Alternatives: " + "; ".join(f"{x['id']} — {x['why_not_chosen']}" for x in p["alternatives"]), "",
              f"Rollback: {p['rollback']}", "",
              (f"Approval: {a['decision'] + ' by ' + a['approver'] + ' at ' + a['at'] + ' for hash ' + a['plan_hash'][:16] if a else '**not approved**'}"
              f" · plan hash `{p['plan_hash'][:16]}`"), ""]
    L += ["## 7. Validation results", ""]
    vals = [p for p in rep["plans"] if p["validation"]]
    if not vals:
        L += ["No plan has been validated in this run (validation requires a human approval first).", ""]
    for p in vals:
        v = p["validation"]
        L += [f"### {p['id']} — verdict **{v['verdict'].upper()}**", "", "| check | status | detail |", "|---|---|---|"]
        L += [f"| {c['name']} | {c['status']} | {c['detail'][:160]} |" for c in v["checks"]]
        L.append("")
    ba = rep["before_after"]
    L += ["## 8. Before and after", "",
          f"Critical/high items open: {ba['need_attention_open_before']} → {ba['need_attention_open_after']}.", ""]
    L += [f"- {pid}: {x['verdict']}, risk {x['risk']}, SBOM diff {x['sbom_diff']}" for pid, x in ba["validated_plans"].items()]
    rm = rep["remaining"]
    L += ["", "## 9. Remaining and accepted risks", "",
          (f"Open and not covered by any plan, by band: {rm['open_by_band']} (the summary's open critical/high count "
          "also includes findings with a pending plan)."), "",
          (f"Accepted risks: {len(rm['accepted_risks'])} · not affected (human-confirmed): {len(rm['not_affected'])} · "
          f"not-affected candidates awaiting a human: {rm['not_affected_candidates'] or 'none'}."), ""]
    L += [f"- {d['finding']} {d['decision']} by {d['by']} ({d['at']}): {d['reason']}" for d in rm["accepted_risks"] + rm["not_affected"]]
    c, au = rep["confidence"], rep["audit"]
    L += ["", "## 10. Confidence and audit trail", "",
          f"Overall confidence {c['overall']} ({c['basis']}); drivers {c['drivers']}.", "",
          f"Audit chain: **{'OK' if au['chain_ok'] else 'BROKEN'}** — {au['result']}; events by actor {au['by_actor']}.", "",
          "## Appendix A. Evidence index", "", (f"{len(rep['evidence_index'])} evidence items in guardian-report.json "
          "(`evidence_index`: id, source, line, type, sha256 of the excerpt)."), "",
          "## Appendix B. Machine-readable files", "",
          "guardian-report.json (schema: schemas/guardian-report.schema.json) · vex.openvex.json · "
          + " · ".join(inv["sbom_files"]), ""]
    return "\n".join(L)


def _html(rep: dict, md: str) -> str:
    e = html.escape
    r, s = rep["run"], rep["summary"]["counts"]
    def badge(t):
        return f'<span class="b b-{e(str(t))}">{e(str(t))}</span>'
    rows = "".join(
        f"<tr><td>{e(i['id'])}</td><td><b>{i['score']}</b> {badge(i['band'])}</td><td>{e(_t(i['type']))}</td>"
        f"<td class=m>{e(i['component'])}</td><td>{e((i['title'] or i['advisory'] or '')[:90])}</td><td>{badge(i['status'])}</td>"
        f"<td>{i['confidence']}</td></tr>" for i in rep["findings"][:40])
    plans = ""
    for p in rep["plans"]:
        a, v = p["approval"], p["validation"]
        checks = "".join(f"<tr><td>{e(c['name'])}</td><td>{badge(c['status'].replace(' ', '_'))}</td><td>{e(c['detail'][:180])}</td></tr>"
                         for c in (v["checks"] if v else []))
        plans += (f"<section class=card><h3>{e(p['id'])} · {e(p['action']['summary'])}</h3>"
                  f"<p>Finding <b>{e(p['finding'])}</b> on <span class=m>{e(p['component'])}</span> · state {badge(p['state'])}"
                  f"{' · supersedes ' + e(p['supersedes']) if p['supersedes'] else ''}</p>"
                  f"<p>Prediction: target resolved <b>{p['prediction']['target_resolved']}</b>, resolved {e(str(p['prediction']['resolved_by_band']))}, "
                  f"semver {e(str(p['prediction']['semver']))}, dangling require() {e(str(p['prediction']['dangling_requires']))} · plan gate "
                  f"<b>{'PASS' if p['policy']['plan_gate']['pass'] else 'FAIL'}</b></p>"
                  "<p>Alternatives:</p><ul>" + "".join(f"<li><b>{e(x['id'])}</b> {e(x['summary'])} — <i>{e(x['why_not_chosen'])}</i></li>"
                                                      for x in p["alternatives"]) + "</ul>"
                  f"<p>Approval: {e(a['decision'] + ' by ' + a['approver'] + ' at ' + a['at']) if a else '<b>not approved</b>'} · "
                  f"hash <span class=m>{e(p['plan_hash'][:16])}</span></p>"
                  + (f"<p>Validation verdict {badge(v['verdict'])}</p><table>{checks}</table>" if v else "<p>Not validated.</p>")
                  + "</section>")
    summ = "".join(f"<li>{e(x['text'])}" + (f" <span class=c>[{e(', '.join(x['cites'][:8]))}]</span>" if x["cites"] else "")
                   + "</li>" for x in rep["summary"]["sentences"])
    ne = "".join(f"<li><b>{e(n['item'])}</b>: {e(n['why'])} → {e(n['effect'])}</li>" for n in rep["not_evaluated"])
    stat = "".join(f'<div class=s><b>{e(str(v))}</b><span>{e(k)}</span></div>' for k, v in [
        ("packages", s["packages"]), ("findings", s["findings"]), ("need attention", s["need_attention"]),
        ("verified fixes", s["remediated_verified"]), ("partial fixes", s["remediated_partial"]),
        ("open crit/high", s["remaining_open_need_attention"]), ("accepted risk", s["accepted_risk"])])
    au = rep["audit"]
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Guardian Report</title><style>
:root{{--bg:#f6f7f9;--p:#fff;--i:#14181f;--m:#5b6472;--l:#d9dde3;--c:#9b1111;--h:#d62828;--md:#ee8a12;--lo:#6b7684;--ok:#1e8e3e;--a:#1f5fbf}}
@media (prefers-color-scheme:dark){{:root{{--bg:#12151a;--p:#1b1f26;--i:#eef1f5;--m:#a3acb8;--l:#2d333d}}}}
body{{margin:0;background:var(--bg);color:var(--i);font:19px/1.45 system-ui,Segoe UI,Roboto,sans-serif}}
main{{max-width:1200px;margin:auto;padding:16px}} h1{{font-size:30px}} h2{{margin-top:32px;border-bottom:2px solid var(--l)}}
.card{{background:var(--p);border:1px solid var(--l);border-radius:10px;padding:12px 16px;margin:12px 0}}
.st{{display:flex;flex-wrap:wrap;gap:10px}} .s{{background:var(--p);border:1px solid var(--l);border-radius:10px;padding:8px 14px}}
.s b{{display:block;font-size:28px}} .s span{{color:var(--m);font-size:14px;text-transform:uppercase}}
table{{border-collapse:collapse;width:100%;background:var(--p)}} td,th{{border-bottom:1px solid var(--l);padding:5px 8px;text-align:left;vertical-align:top}}
.m{{font-family:ui-monospace,Consolas,monospace;font-size:16px;word-break:break-all}} .c{{color:var(--m);font-size:15px}}
.b{{display:inline-block;padding:0 7px;border-radius:6px;font-size:14px;font-weight:700;color:#fff;background:var(--lo)}}
.b-critical{{background:var(--c)}} .b-high{{background:var(--h)}} .b-medium{{background:var(--md)}} .b-passed,.b-verified,.b-remediated_verified,.b-validated{{background:var(--ok)}}
.b-FAILED,.b-failed,.b-validation_failed{{background:var(--c)}} .b-partial,.b-remediated_partial,.b-validated_partial,.b-not_run,.b-pending_approval,.b-fix_planned{{background:var(--md)}}
.note{{background:var(--p);border-left:6px solid var(--a);padding:8px 12px}}
</style></head><body><main>
<h1>Guardian Report — {e(r['target'])} @ {e(r['head'])} ({e(r['head_sha'][:7])})</h1>
<p class=c>Run {e(r['run_id'])} · {e(r['generated'])} · scan mode {e(str(r['mode']))} · agents: {e(str(rep['data_sources']['agent_mode']))} · baseline {e(r['base'])} ({e(r['base_sha'][:7])}) · rendered by code from the run directory; no model wrote this text</p>
<p class=note><b>verified</b> = read from tool output · <b>derived</b> = computed by code · <b>inferred (AI)</b> = model judgement · "unknown" never means safe</p>
<h2>1. Executive summary</h2><div class=st>{stat}</div><ul>{summ}</ul>
<h2>2. Not evaluated</h2><ul>{ne}</ul>
<h2>3. Ranked findings (top 40 of {len(rep['findings'])})</h2>
<table><tr><th>id</th><th>score</th><th>type</th><th>component</th><th>title / advisory</th><th>status</th><th>conf.</th></tr>{rows}</table>
<h2>4. Recommended and approved actions, validation</h2>{plans or '<p>No plans.</p>'}
<h2>5. Remaining and accepted risks</h2><p>Open and not covered by any plan, by band: {e(str(rep['remaining']['open_by_band']))} (the summary's open critical/high count also includes findings with a pending plan). Accepted: {len(rep['remaining']['accepted_risks'])}. Not affected (human-confirmed): {len(rep['remaining']['not_affected'])}. Not-affected candidates awaiting a human: {e(str(rep['remaining']['not_affected_candidates'] or 'none'))}.</p>
<h2>6. Confidence and audit trail</h2><p>Overall confidence {rep['confidence']['overall']} ({e(rep['confidence']['basis'])}). Audit chain <b>{'OK' if au['chain_ok'] else 'BROKEN'}</b>: {e(au['result'])}. Events by actor: {e(str(au['by_actor']))}.</p>
<h2>Full report (Markdown)</h2><details><summary>show</summary><pre style="white-space:pre-wrap">{e(md)}</pre></details>
</main></body></html>"""


def render(run: Path) -> dict:
    import jsonschema
    rep = collect(run)
    out = run / "report"
    out.mkdir(exist_ok=True)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.validate(rep, schema)
    (out / "guardian-report.json").write_text(json.dumps(rep, indent=1), encoding="utf-8")
    md = _md(rep)
    (out / "guardian-report.md").write_text(md, encoding="utf-8")
    (out / "guardian-report.html").write_text(_html(rep, md), encoding="utf-8")
    pr = _load(run, "prioritised.json")
    vex = build_vex(rep["run"]["run_id"], {f["id"]: f for f in pr["findings"]},
                    {k: v for k, v in _all(run, "validation", "P-*.json").items() if "verdict" in v},
                    _all(run, "decisions", "*.json"), rep["run"]["head_sha"][:12])
    (out / "vex.openvex.json").write_text(json.dumps(vex, indent=1), encoding="utf-8")
    shutil.copy2(run / "sbom.head.cdx.json", out / "sbom.before.cdx.json")
    for pid, v in _all(run, "validation", "P-*.json").items():
        if "verdict" in v and v["verdict"] != "failed" and (run / v.get("sbom_after", "x")).exists():
            shutil.copy2(run / v["sbom_after"], out / f"sbom.after.{pid}.cdx.json")
    runs.mark_stage(run, "report", "ok")
    audit.append(run, "guardian", "report.rendered", run.name, {"findings": len(rep["findings"]), "plans": len(rep["plans"]),
                                                                "vex_statements": len(vex["statements"])})
    return {"dir": out, "report": rep, "vex": vex}
