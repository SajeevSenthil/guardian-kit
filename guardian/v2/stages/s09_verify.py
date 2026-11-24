"""Stage 9 - Sandbox verification: apply approved edits to a fresh clone, refresh the lockfile, run tests in
Docker (network none), rescan with the same tools, compare before/after; the verdict is computed by code.

Page: guardian/api/static/pages/s09_verify.js · Output: stages/verify/ (result.json, logs, rescans)
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from ..identity import norm_name
from ..proc import offline
from ..proc import run as _run
from ..tools import find_tool
from ..workspace import Workspace
from .s04_vulns import (
    GRYPE_DB,
    _osv_targets,
    records_from_grype,
    records_from_osv_scanner,
)
from .s08_remedies import _clone, apply_edit, plan_hash

IMAGES = {"npm": "node:20-bookworm-slim", "pypi": "python:3.12-slim", "golang": "golang:1.22"}


LIMITS = ["--memory", "2g", "--cpus", "2", "--pids-limit", "512", "--security-opt", "no-new-privileges"]


def _docker() -> str | None:
    exe = find_tool("docker")
    for cand in ("C:/Program Files/Docker/Docker/resources/bin/docker.exe",):
        if not exe and Path(cand).exists():
            exe = cand
    return exe


def test_plan(clone: Path) -> dict | None:
    """Which ecosystem's tests to run and how: (install step with network, test step without)."""
    pj = clone / "package.json"
    if pj.exists():
        t = (json.loads(pj.read_text(encoding="utf-8")).get("scripts") or {}).get("test", "")
        if t and "no test specified" not in t:
            return {"eco": "npm", "install": "npm ci || npm install", "test": "npm test"}
    if any((clone / f).exists() for f in ("requirements.txt", "pyproject.toml", "setup.py")):
        has_tests = any(clone.glob("test*/**/*.py")) or any(clone.glob("**/test_*.py")) or (clone / "pytest.ini").exists()
        if has_tests:
            req = "pip install -r requirements.txt" if (clone / "requirements.txt").exists() else "pip install ."
            return {"eco": "pypi", "install": f"python -m venv /app/.gv && . /app/.gv/bin/activate && {req} && pip install pytest",
                    "test": ". /app/.gv/bin/activate && python -m pytest -q"}
    if (clone / "go.mod").exists():
        return {"eco": "golang", "install": "GOMODCACHE=/app/.gomod go mod download",
                "test": "GOMODCACHE=/app/.gomod GOFLAGS=-mod=mod go test ./..."}
    return None


def docker_cmd(docker: str, clone: Path, image: str, script: str, network: bool) -> list[str]:
    """No env passthrough, no host mounts except the clone; the test step has no network."""
    return [docker, "run", "--rm", *LIMITS, *([] if network else ["--network", "none"]),
            "-v", f"{clone}:/app", "-w", "/app", image, "sh", "-c", script]


def _counts(text: str) -> str | None:
    pats = [r"(\d+) passed(?:, (\d+) failed)?", r"(\d+) passing(?:[\s\S]*?(\d+) failing)?", r"Tests:\s+(?:(\d+) failed, )?(\d+) passed"]
    for p in pats:
        m = re.search(p, text)
        if m:
            return " ".join(m.group(0).split())[:80]
    return None


def container_tests(clone: Path, approved: list, out: Path, ws: Workspace) -> dict:
    plan = test_plan(clone)
    if not plan:
        return _check("tests", "not-run", "no test suite found in the repository (nothing to run)")
    docker = _docker()
    if not docker:
        return _check("tests", "not-run", "docker is not installed: the repository's tests were NOT run "
                      "(they run only inside an isolated container)")
    if _run([docker, "info"], timeout=30).returncode:
        return _check("tests", "not-run", "docker is installed but the daemon is not running (start Docker Desktop)")
    image = IMAGES[plan["eco"]]
    log = out / "tests.log"
    r1 = _run(docker_cmd(docker, clone, image, plan["install"], network=True), timeout=1200)
    r2 = _run(docker_cmd(docker, clone, image, plan["test"], network=False), timeout=1200) if r1.returncode == 0 else None
    parts = [f"$ {plan['install']}", r1.stdout, r1.stderr]
    if r2:
        parts += [f"$ {plan['test']}  (network: none)", r2.stdout, r2.stderr]
    log.write_text("\n".join(parts), encoding="utf-8")
    if r1.returncode:
        return _check("tests", "fail", f"dependencies did not install in the container (exit {r1.returncode})", ws.rel(log))
    n = _counts(r2.stdout + r2.stderr)
    return _check("tests", "pass" if r2.returncode == 0 else "fail",
                  f"{plan['test']} in {image}, network none: exit {r2.returncode}" + (f" ({n})" if n else ""), ws.rel(log))


def _check(name, status, detail, log=None):
    return {"name": name, "status": status, "detail": detail, "log": log}


def run_verify(ws: Workspace, opts: dict) -> dict:
    res = ws.read("remedies") or {}
    out = ws.stage_dir("verify")
    aset_p = ws.dir / "stages" / "remedies" / "approved_set.json"
    if not res.get("sent") or not aset_p.exists():
        raise RuntimeError("no approved set: approve plans on the Remedies page and press 'Send to sandbox'")
    aset = json.loads(aset_p.read_text(encoding="utf-8"))
    plans = {p["id"]: p for p in res["plans"]}
    checks, approved = [], []
    for a in aset["plans"]:
        p = plans.get(a["id"])
        ok = p and p["decision"]["status"] == "approved" and plan_hash(p) == a["plan_hash"] == p["plan_hash"]
        if not ok:
            checks.append(_check("approval", "fail", f"{a['id']}: plan changed after approval (hash mismatch)"))
        else:
            approved.append(p)
    if approved and not checks:
        checks.append(_check("approval", "pass", f"{len(approved)} plan(s) approved by "
                             f"{', '.join(sorted({p['decision']['by'] for p in approved}))}; hashes match"))
    clone = _clone(ws, "verify")
    # 1. apply
    try:
        for p in approved:
            for e in p["edits"]:
                apply_edit(clone, e)
        diff = _run(["git", "diff", "--stat"], cwd=clone).stdout
        (out / "applied.diff").write_text(_run(["git", "diff"], cwd=clone).stdout, encoding="utf-8")
        checks.append(_check("apply", "pass", f"approved edits applied to a fresh clone: {diff.strip().splitlines()[-1] if diff.strip() else 'no change'}",
                             ws.rel(out / "applied.diff")))
    except Exception as e:  # noqa: BLE001
        checks.append(_check("apply", "fail", str(e)))
    # 2. lockfile
    if any(p["ecosystem"] == "npm" for p in approved) and (clone / "package-lock.json").exists():
        npm = find_tool("npm") or shutil.which("npm.cmd")
        if not npm:
            checks.append(_check("lockfile", "not-run", "npm not installed"))
        else:
            base = [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
            r = _run(base, cwd=clone, timeout=900)
            log = r.stdout + "\n" + r.stderr
            if r.returncode and "ERESOLVE" in log:
                # peer-dependency conflict (typical after a major upgrade): resolve anyway, but say so
                r2 = _run(base + ["--legacy-peer-deps"], cwd=clone, timeout=900)
                log += "\n\n$ retry with --legacy-peer-deps\n" + r2.stdout + "\n" + r2.stderr
                conflict = re.search(r"Conflicting peer dependency: (\S+)", log)
                (out / "npm-lock.log").write_text(log, encoding="utf-8")
                checks.append(_check(
                    "lockfile", "warn" if r2.returncode == 0 else "fail",
                    (f"resolved only by ignoring a peer-dependency conflict ({conflict.group(1) if conflict else 'see log'}): "
                     "the upgrade may be incompatible; only the tests can confirm it") if r2.returncode == 0
                    else f"npm could not resolve the upgraded versions (exit {r2.returncode})", ws.rel(out / "npm-lock.log")))
            else:
                (out / "npm-lock.log").write_text(log, encoding="utf-8")
                checks.append(_check("lockfile", "pass" if r.returncode == 0 else "fail",
                                     "package-lock.json regenerated with --package-lock-only --ignore-scripts (no code run)"
                                     if r.returncode == 0 else f"npm exit {r.returncode}", ws.rel(out / "npm-lock.log")))
    else:
        checks.append(_check("lockfile", "pass", "requirements pins are the lock; nothing to regenerate"))
    # 3. tests: the ONLY place repository code runs, and only inside an isolated container
    checks.append(container_tests(clone, approved, out, ws))
    # 4. rescan with the same tools as stage 4
    after_records, tools = [], {}
    ing = ws.read("ingest") or {}
    targets = _osv_targets(ing)
    exe = find_tool("osv-scanner")
    if exe and targets and not offline():
        cmd = [exe, "scan", "source", "--format", "json"]
        for _, f in targets:
            cmd += ["-L", (f"requirements.txt:{f}" if Path(f).name.startswith("requirements") else f)]
        r = _run(cmd, cwd=clone)
        if r.returncode in (0, 1) and r.stdout.strip():
            (out / "rescan-osv-scanner.json").write_text(r.stdout, encoding="utf-8")
            after_records += records_from_osv_scanner(json.loads(r.stdout))
            tools["osv_scanner"] = "ran"
        else:
            tools["osv_scanner"] = f"failed (exit {r.returncode})"
    else:
        tools["osv_scanner"] = "not-run"
    syft, grype = find_tool("syft"), find_tool("grype")
    if syft and grype:
        sb = out / "rescan-syft.cdx.json"
        _run([syft, "scan", f"dir:{clone}", "-q", "-o", f"cyclonedx-json={sb}", "--exclude", "./**/node_modules/**",
              "--exclude", "./**/.git/**"], env={"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true", "SYFT_CHECK_FOR_APP_UPDATE": "false"})
        r = _run([grype, f"sbom:{sb}", "-o", "json", "-q"], env={"GRYPE_DB_CACHE_DIR": str(GRYPE_DB),
                                                                  "GRYPE_CHECK_FOR_APP_UPDATE": "false", "GRYPE_DB_AUTO_UPDATE": "false"})
        if r.returncode in (0, 1) and r.stdout.strip():
            (out / "rescan-grype.json").write_text(r.stdout, encoding="utf-8")
            after_records += records_from_grype(json.loads(r.stdout))
            tools["grype"] = "ran"
        else:
            tools["grype"] = f"failed (exit {r.returncode})"
    else:
        tools["grype"] = "not-run"
    ran = [k for k, v in tools.items() if v == "ran"]
    checks.append(_check("rescan", "pass" if ran else "not-run", f"tools on the patched clone: {tools}",
                         ws.rel(out / "rescan-osv-scanner.json") if (out / "rescan-osv-scanner.json").exists() else None))
    # 5. compare before / after (by package name + alias overlap)
    before = (ws.read("vulns") or {}).get("rows", [])

    def key(eco, name):
        return (eco, norm_name(eco, name or ""))

    after_by_pkg: dict = {}
    for rec in after_records:
        after_by_pkg.setdefault(key(rec["ecosystem"], rec["name"] or ""), []).append(rec)
    per_plan, new = [], []
    for p in approved:
        recs = after_by_pkg.get(key(p["ecosystem"], p["name"]), [])
        gone, still = [], []
        for adv in p["targets"]:
            brow = next((b for b in before if b["advisory"] == adv and b["component_id"] == p["component_id"]), None)
            ids = {adv, *(brow or {}).get("aliases", [])}
            (still if any(r["ids"] & ids for r in recs) else gone).append(adv)
        before_ids = {i for b in before if key(b["ecosystem"], b["name"]) == key(p["ecosystem"], p["name"])
                      for i in [b["advisory"], *b["aliases"]]}
        for r in recs:
            if not (r["ids"] & before_ids):
                new.append({"package": p["name"], "version": r.get("version"), "ids": sorted(r["ids"]), "tool": r["tool"]})
        per_plan.append({"plan": p["id"], "package": p["name"], "from": p["from_version"], "to": p["to_version"],
                         "targets": len(p["targets"]), "gone": gone, "still_present": still})
    targeted = {(p["component_id"], a) for p in approved for a in p["targets"]}
    remaining = [{"name": b["name"], "version": b["version"], "advisory": b["advisory"], "severity": b["severity"]}
                 for b in before if (b["component_id"], b["advisory"]) not in targeted]
    fixed = sum(len(x["gone"]) for x in per_plan)
    total = sum(x["targets"] for x in per_plan)
    still = sum(len(x["still_present"]) for x in per_plan)
    if ran:
        checks.append(_check("targets_fixed", "pass" if still == 0 and total else "fail",
                             f"{fixed} of {total} targeted advisories are gone after the fix"))
        checks.append(_check("no_new_vulnerabilities", "pass" if not new else "fail",
                             f"{len(new)} advisory(ies) newly reported on the upgraded packages"))
    else:
        checks.append(_check("targets_fixed", "not-run", "no scanner ran on the patched clone: cannot claim anything is fixed"))
    statuses = [c["status"] for c in checks]
    verdict = "FAILED" if "fail" in statuses else "PARTIAL" if ("not-run" in statuses or "warn" in statuses) else "VERIFIED"
    result = {"verdict": verdict, "checks": checks, "per_plan": per_plan, "new_vulnerabilities": new,
              "remaining": remaining, "approved_set": res.get("approved_set"), "tools": tools,
              "headline": (f"Targeted vulnerabilities fixed: {fixed} of {total} · new: {len(new)} · tests: "
                           f"{next(c['status'] for c in checks if c['name'] == 'tests').replace('-', ' ')} · "
                           f"remaining (not covered by an approved plan): {len(remaining)}"),
              "why_verdict": {"VERIFIED": "every check passed, including the tests in a container",
                              "PARTIAL": "nothing failed, but these checks did not run or passed only with a warning: "
                                         + ", ".join(c["name"] for c in checks if c["status"] in ("not-run", "warn")),
                              "FAILED": "at least one check failed: " + ", ".join(c["name"] for c in checks if c["status"] == "fail")}[verdict],
              "clone": ws.rel(clone / ".git" / "HEAD") if (clone / ".git" / "HEAD").exists() else None}
    ws.write("verify", result)
    ws.audit("verify", verdict=verdict, fixed=fixed, total=total, new=len(new))
    return {"verdict": verdict, "fixed": f"{fixed}/{total}", "new": len(new), "remaining": len(remaining)}
