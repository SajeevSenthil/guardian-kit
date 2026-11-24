"""Stage `validate` (phase 11): prove an approved plan in a throwaway clone, then the closed loop.

Checks, in order. Each is {name, passed: True | False | None, detail, evidence, seconds}; None means
"could not run" and is reported as "not run", never as passed.

  1 approval        plan approved by a named human and its patch hash unchanged
  2 baseline        docker smoke test on unmodified head (needs docker), plus a static baseline:
                    `node --check` on first-party files and every first-party require() declared
  3 apply           clone, branch guardian/fix-<plan>, `git am` the binary patch, commit
  4 build           docker build (needs docker)
  5 install         `npm ci --ignore-scripts` from the patched lockfile (installs, verifies integrity,
                    runs no package script; nothing is executed)
  6 tests           docker smoke test (needs docker), plus a static start check: `node --check` and
                    every first-party require() resolving to an installed package
  7 rescan          the full Day-1 pipeline on the fixed branch vs the base ref
  8 sbom_diff       before vs after components
  9 new_findings    findings present after that were not present before; new critical/high fails
 10 policy          plan gate on the actual result
 11 prediction      phase-10 prediction vs what happened (informational, does not affect the verdict)

Verdict: failed if any verdict check is False; verified if all are True; partial when some could
not run. ./target is never modified; rollback is deleting the clone.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from . import audit, policy, reachability, remediate, runs
from .reachability import NODE_BUILTINS

INSTALL_TIMEOUT = 900


def _check(name, passed, detail, evidence=None, t0=None, verdict=True):
    return {"name": name, "passed": passed, "status": {True: "passed", False: "FAILED", None: "not run"}[passed],
            "detail": detail, "evidence": evidence or [], "seconds": round(time.time() - t0, 1) if t0 else None,
            "affects_verdict": verdict}


def _docker() -> str | None:
    return shutil.which("docker")


def _node_check(root: Path) -> tuple[bool, list[str]]:
    errors = []
    node = shutil.which("node")
    for f in reachability.app_files(root):
        r = subprocess.run([node, "--check", str(f)], capture_output=True, timeout=60, check=False)
        if r.returncode:
            errors.append(f"{f.relative_to(root).as_posix()}: {r.stderr.decode('utf-8', 'replace').strip()[:300]}")
    return not errors, errors


def _require_check(root: Path, installed: bool) -> tuple[bool, list[dict]]:
    """Every package first-party code require()s must be declared (and installed, when installed=True)."""
    pj = json.loads((root / "package.json").read_text(encoding="utf-8"))
    declared = set(pj.get("dependencies", {})) | set(pj.get("devDependencies", {})) | set(pj.get("optionalDependencies", {}))
    missing = []
    for pkg, imp in reachability.scan(root, set())["imports"].items():
        if pkg in NODE_BUILTINS:
            continue
        present = (root / "node_modules" / pkg / "package.json").exists() if installed else pkg in declared
        if not present:
            s = imp["sites"][0] if imp["sites"] else {}
            missing.append({"package": pkg, "file": s.get("file"), "line": s.get("line"), "excerpt": s.get("excerpt"),
                            "error": f"Cannot find module '{pkg}'" if installed else f"'{pkg}' is not declared in package.json"})
    return not missing, missing


def _rescan(ctx: remediate.Ctx, root: Path, out: Path, branch: str) -> dict:
    fp = ctx.fp
    out.mkdir(parents=True, exist_ok=True)
    shutil.copy2(runs.FASTPATH_OUT / "vis-network.min.js", out / "vis-network.min.js")
    saved = (fp.TARGET, fp.OUT)
    try:
        fp.TARGET, fp.OUT = str(root), str(out)
        doc = fp.build(ctx.meta["base"], branch, False)
    finally:
        fp.TARGET, fp.OUT = saved
    return doc


def _key(f: dict) -> tuple:
    return (f["type"], f["component"], f.get("advisory") or f.get("title", "")[:80])


def compare(before: list[dict], after: list[dict], osv_ok: bool) -> tuple[list[str], list[dict]]:
    """(ids of findings resolved, findings that are new). Unknown is never fixed: when the rescan could
    not evaluate vulnerabilities, their absence afterwards proves nothing, so none counts as resolved."""
    ak = {_key(f) for f in after}
    bk = {_key(f) for f in before}
    gone = [f["id"] for f in before if _key(f) not in ak and (osv_ok or f["type"] != "known_vulnerability")]
    new = [f for f in after if _key(f) not in bk and f["type"] not in ("new_dependency", "changed_dependency")]
    return gone, new


def validate(run: Path, plan_id: str) -> dict:
    ctx = remediate.Ctx(run)
    plan = runs.read_json(run, f"plans/{plan_id}.json")
    vdir = run / "validation" / plan_id
    vdir.mkdir(parents=True, exist_ok=True)
    checks, logs = [], {}
    audit.append(run, "guardian", "validate.started", plan_id, {"plan_hash": plan["plan_hash"]})

    def done(verdict, extra=None):
        res = {"plan": plan_id, "finding": plan["finding"], "candidate": plan["chosen"]["id"],
               "verdict": verdict, "checks": checks, "finished": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
               **(extra or {})}
        runs.write_json(run, f"validation/{plan_id}.json", res)
        (vdir / "logs.json").write_text(json.dumps(logs, indent=1), encoding="utf-8")
        plan["state"] = {"verified": "validated", "partial": "validated_partial", "failed": "validation_failed",
                         "refused": plan["state"]}[verdict]
        runs.write_json(run, f"plans/{plan_id}.json", plan)
        audit.append(run, "guardian", f"validate.{verdict}", plan_id,
                     {"checks": {c["name"]: c["status"] for c in checks}})
        return res

    # 1 approval
    t0 = time.time()
    ok, msg = remediate.check_approval(run, plan_id)
    checks.append(_check("approval", ok, msg, t0=t0))
    if not ok:
        return done("refused")

    # 2 baseline (unmodified head)
    t0 = time.time()
    base = remediate.work_clone(ctx, f"{plan_id}-baseline")
    nc_ok, nc_err = _node_check(base)
    rq_ok, rq_missing = _require_check(base, installed=False)
    logs["baseline_static"] = {"node_check_errors": nc_err, "undeclared_requires": rq_missing}
    checks.append(_check("baseline_tests", None,
                         "container smoke test on unmodified head: not implemented in this build"
                         + ("" if _docker() else " (docker is not installed)"), t0=t0))
    checks.append(_check("baseline_static", nc_ok and rq_ok,
                         f"node --check on {len(reachability.app_files(base))} first-party files: "
                         f"{'ok' if nc_ok else 'errors'}; every require() declared: {'yes' if rq_ok else 'no'}",
                         evidence=nc_err + [m["error"] for m in rq_missing], t0=t0))
    if not (nc_ok and rq_ok):
        return done("failed", {"stopped": "baseline does not pass; a later failure could not be attributed to the fix"})

    # 3 apply
    t0 = time.time()
    root = remediate.work_clone(ctx, plan_id)
    branch = f"guardian/fix-{plan_id}"
    subprocess.run(["git", "-C", str(root), "checkout", "-q", "-b", branch], check=True, capture_output=True)
    r = subprocess.run(["git", "-C", str(root), "am", "--quiet", str((run / plan["patch_file"]).resolve())],
                       capture_output=True, check=False)
    logs["apply"] = (r.stdout + r.stderr).decode("utf-8", "replace")[-2000:]
    sha = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"], capture_output=True,
                         check=False).stdout.decode().strip()
    checks.append(_check("apply", r.returncode == 0, f"branch {branch} at {sha} in {root.relative_to(run).as_posix()}"
                         if r.returncode == 0 else "git am failed", evidence=[logs["apply"][-400:]] if r.returncode else [], t0=t0))
    if r.returncode:
        return done("failed")

    # 4 build
    checks.append(_check("build", None, "container build: not implemented in this build"
                         + ("" if _docker() else " (docker is not installed)")))

    # 5 install (no scripts)
    t0 = time.time()
    offline = ["--offline"] if os.environ.get("GUARDIAN_OFFLINE") == "1" else []   # npm cache only
    r = subprocess.run([remediate._npm(), "ci", "--ignore-scripts", "--no-audit", "--no-fund", *offline], cwd=str(root),
                       capture_output=True, timeout=INSTALL_TIMEOUT, check=False)
    out = (r.stdout + r.stderr).decode("utf-8", "replace")
    logs["install"] = out[-4000:]
    checks.append(_check("install", r.returncode == 0, "npm ci --ignore-scripts from the patched lockfile: "
                         + ("ok" if r.returncode == 0 else f"exit {r.returncode}"),
                         evidence=[ln for ln in out.splitlines() if "ERR" in ln][:8], t0=t0))

    # 6 tests
    t0 = time.time()
    checks.append(_check("tests", None, "container smoke test (app start + HTTP routes): not implemented in this build"
                         + ("" if _docker() else " (docker is not installed)"), t0=t0))
    nc_ok, nc_err = _node_check(root)
    rq_ok, rq_missing = _require_check(root, installed=r.returncode == 0)
    logs["static_start"] = {"node_check_errors": nc_err, "unresolved_requires": rq_missing}
    checks.append(_check("static_start", nc_ok and rq_ok,
                         f"node --check: {'ok' if nc_ok else 'errors'}; every first-party require() resolves to an "
                         f"installed package: {'yes' if rq_ok else 'NO'}",
                         evidence=nc_err + [f"{m['file']}:{m['line']} `{m['excerpt']}` -> {m['error']}" for m in rq_missing],
                         t0=t0))
    shutil.rmtree(root / "node_modules", ignore_errors=True)

    # 7 rescan, 8 sbom diff, 9 new findings
    t0 = time.time()
    after = _rescan(ctx, root, vdir / "after", branch)
    before = runs.read_json(run, "findings.json")["findings"]
    osv_ok = (after.get("meta", {}).get("osv") or {}).get("status") == "evaluated"
    checks.append(_check("rescan", True if osv_ok else None,
                         f"Day-1 pipeline on {branch} vs {ctx.meta['base']}: {len(after['findings'])} findings "
                         f"(before: {len(before)})" + ("" if osv_ok else
                         "; known vulnerabilities NOT evaluated (OSV unavailable): none can be counted as fixed"),
                         t0=t0))
    t0 = time.time()
    sb_after = json.loads((vdir / "after" / "sbom.head.cdx.json").read_text(encoding="utf-8"))
    sdiff = ctx.fp.lsd.diff(ctx.head_sbom, sb_after)
    (vdir / "sbom.after.cdx.json").write_text(json.dumps(sb_after), encoding="utf-8")
    checks.append(_check("sbom_diff", True, f"components {sdiff['counts']['old']} -> {sdiff['counts']['new']}: "
                         f"added {len(sdiff['added'])}, removed {len(sdiff['removed'])}",
                         evidence=[f"+ {a['purl']}" for a in sdiff["added"]] + [f"- {x}" for x in sdiff["removed"]], t0=t0))
    gone, new = compare(before, after["findings"], osv_ok)
    bad = [f for f in new if f["risk"] in ("critical", "high")]
    checks.append(_check("new_findings", False if bad else (True if osv_ok else None),
                         f"{len(new)} new finding(s), {len(bad)} critical/high"
                         + ("" if osv_ok else "; new vulnerabilities could not be checked (OSV unavailable)"),
                         evidence=[f"{f['risk']} {f['type']} {f['component']} {f.get('advisory', '')}" for f in new][:10]))
    target = ctx.byid[plan["finding"]]

    # 10 policy on the actual result
    after_nodes = json.loads((vdir / "after" / "graph.json").read_text(encoding="utf-8"))["nodes"]
    after_nodes = {n["id"]: n for n in after_nodes}
    act = [{**f, "band": f["risk"]} for f in after["findings"]]
    head_policy = remediate.policy_state(ctx, ctx.findings, ctx.nodes, ctx.head_src)
    actual_policy = remediate.policy_state(ctx, act, after_nodes, root)
    gate = policy.plan_gate(head_policy, actual_policy, remediate.target_tokens(target))
    checks.append(_check("policy", gate["pass"] if osv_ok else None,
                         gate["reason"] if osv_ok else "not evaluable: the KEV / critical-finding rules need vulnerability "
                         "data, which the rescan could not get", evidence=gate["remaining_on_target"] + gate["introduced"]))

    # 11 prediction vs outcome
    pred = plan["prediction"]
    match = {"target_resolved": (pred.get("target_resolved"), target["id"] in gone),
             "components_removed": (sorted(pred.get("removed", [])), sorted(sdiff["removed"])),
             "components_added": (sorted(pred.get("added", [])), sorted(a["purl"] for a in sdiff["added"])),
             "dangling_requires": (pred.get("dangling_requires"), [m["package"] for m in rq_missing])}
    agree = all(a == b for a, b in match.values())
    checks.append(_check("prediction", agree, "prediction matches the outcome" if agree else "prediction differs: " +
                         ", ".join(k for k, (a, b) in match.items() if a != b),
                         evidence=[f"{k}: predicted {a} / actual {b}" for k, (a, b) in match.items()], verdict=False))

    vc = [c for c in checks if c["affects_verdict"]]
    verdict = "failed" if any(c["passed"] is False for c in vc) else "verified" if all(c["passed"] for c in vc) else "partial"
    return done(verdict, {"branch": branch, "commit": sha, "work_dir": root.relative_to(run).as_posix(),
                          "target_resolved": target["id"] in gone, "findings_resolved": len(gone),
                          "resolved_ids": gone, "osv_evaluated": osv_ok, "sbom_after": f"validation/{plan_id}/sbom.after.cdx.json",
                          "sbom_diff": {"added": [a["purl"] for a in sdiff["added"]], "removed": sdiff["removed"]},
                          "new_findings": [_key(f) for f in new],
                          "risk": {"target_before": target["priority"]["score"],
                                   "target_after": 0 if target["id"] in gone else target["priority"]["score"],
                                   "findings_before": len(before), "findings_after": len(after["findings"])},
                          "not_run": [c["name"] for c in checks if c["passed"] is None]})
