"""Stage `plan` and `approve` (phase 10): fix candidates, dry runs, policy gate, plans, human approval.

Every candidate is tried in a throwaway clone (runs/<id>/work/<plan>-<cand>/, remote removed); ./target
is never modified. Edits are made by code. A dry run re-resolves the lockfile only
(`npm install --package-lock-only --ignore-scripts`): nothing is installed, built or executed. The
prediction therefore sees manifests and source, not whether the application starts; that is what
validation (phase 11) is for.

Candidate rules (generic; no package name appears here):
  known vulnerability, direct    V1 lowest fixed version for this advisory (same major if possible)
                                 V2 highest fixed version among this package's advisories in that major
                                 VM major upgrade when no same-major fix exists
                                 VR remove the dependency when no first-party code imports it
  known vulnerability, transitive VO npm `overrides` to the fixed version
  new suspicious package          C1 remove from manifest + lockfile ("what a dependency bot would do")
                                 C2 C1 + delete the vendored tarball + remove the unused require() line
                                 C3 replace with the package it imitates (only when its binding is used)
  suspicious update               U1 restore the base version (manifest spec, tarball, lockfile) and
                                    block the new version's integrity hash by policy
                                 U2 remove it (as C2)
  untrusted image                 I1 restore the base ref's exact FROM line (digest pin: not evaluated)
  CI component / pattern          A1 delete the workflow introduced by the change
  every finding                   E  escalate to a human security reviewer (no edits)
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from . import audit, enrich, policy, reachability, runs
from .config import load
from .reachability import NODE_BUILTINS
from .scoring import band as score_band

NPM_TIMEOUT = 300
SEMVER_RANK = {"none": 0, "patch": 1, "minor": 2, "major": 3}


# ---------------------------------------------------------------------------------- helpers
def _sv(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", (v or "0").split("-")[0])[:3]) or (0,)


def semver_distance(old: str, new: str) -> str:
    a, b = _sv(old) + (0, 0, 0), _sv(new) + (0, 0, 0)
    return "none" if a[:3] == b[:3] else "major" if a[0] != b[0] else "minor" if a[1] != b[1] else "patch"


def _sh(args: list[str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=str(cwd), capture_output=True, timeout=timeout, check=False,
                          shell=False)


def _npm() -> str:
    return shutil.which("npm.cmd") or shutil.which("npm") or "npm"


def _read_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _write_json(p: Path, d: dict) -> None:
    p.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")


def _normalise_file_paths(lock: Path) -> None:
    """npm on Windows can write `file:` specs with backslashes; patches must stay portable."""
    d = _read_json(lock)

    def fix(o):
        if isinstance(o, dict):
            return {k: fix(v) for k, v in o.items()}
        if isinstance(o, list):
            return [fix(v) for v in o]
        return o.replace("\\", "/") if isinstance(o, str) and o.startswith("file:") else o
    _write_json(lock, fix(d))


# ---------------------------------------------------------------------------------- edit operations
def op_set_dep(root: Path, name: str, spec: str) -> str:
    pj = _read_json(root / "package.json")
    sec = next((s for s in ("dependencies", "devDependencies") if name in pj.get(s, {})), "dependencies")
    old = pj.setdefault(sec, {}).get(name)
    pj[sec][name] = spec
    _write_json(root / "package.json", pj)
    return f"package.json {sec}.{name}: {old} -> {spec}"


def op_remove_dep(root: Path, name: str) -> str:
    pj = _read_json(root / "package.json")
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        if name in pj.get(sec, {}):
            old = pj[sec].pop(name)
            _write_json(root / "package.json", pj)
            return f"package.json: removed {sec}.{name} ({old})"
    return f"package.json: {name} not declared"


def op_override(root: Path, name: str, version: str) -> str:
    pj = _read_json(root / "package.json")
    pj.setdefault("overrides", {})[name] = version
    _write_json(root / "package.json", pj)
    return f"package.json overrides.{name} = {version}"


def op_delete(root: Path, rel: str) -> str:
    p = root / rel
    if p.exists():
        p.unlink()
        return f"deleted {rel}"
    return f"{rel} already absent"


def op_restore(root: Path, rel: str, ref: str) -> str:
    data = subprocess.run(["git", "-C", str(root), "show", f"{ref}:{rel}"], capture_output=True, check=True).stdout
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_bytes(data)
    return f"restored {rel} from {ref}"


def unused_require_lines(root: Path, pkg: str) -> list[tuple[str, int, str]]:
    """(file, line, text) of `var x = require('<pkg>')` lines whose binding is never used again."""
    out = []
    for f in reachability.app_files(root):
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*(?:var|let|const)\s+(\w+)\s*=\s*require\(\s*['\"]" + re.escape(pkg) + r"['\"]\s*\)\s*;?\s*$", ln)
            if m and not any(re.search(r"\b" + re.escape(m.group(1)) + r"\b", x) for j, x in enumerate(lines, 1) if j != i):
                out.append((f.relative_to(root).as_posix(), i, ln))
    return out


def op_remove_lines(root: Path, items: list[tuple[str, int, str]]) -> str:
    for rel, _, text in items:
        p = root / rel
        lines = p.read_text(encoding="utf-8").split("\n")
        lines.remove(text) if text in lines else None
        p.write_text("\n".join(lines), encoding="utf-8")
    return "removed " + ", ".join(f"{r}:{n} `{t.strip()}`" for r, n, t in items)


def op_replace_require(root: Path, old: str, new: str) -> str:
    n = 0
    for f in reachability.app_files(root):
        t = f.read_text(encoding="utf-8")
        t2 = re.sub(r"(require\(\s*['\"])" + re.escape(old) + r"(['\"]\s*\))", r"\g<1>" + new + r"\g<2>", t)
        if t2 != t:
            f.write_text(t2, encoding="utf-8")
            n += 1
    return f"require('{old}') -> require('{new}') in {n} file(s)"


def op_replace_line(root: Path, rel: str, old: str, new: str) -> str:
    p = root / rel
    t = p.read_text(encoding="utf-8")
    if old not in t:
        return f"{rel}: line not found"
    p.write_text(t.replace(old, new, 1), encoding="utf-8")
    return f"{rel}: `{old.strip()}` -> `{new.strip()}`"


# ---------------------------------------------------------------------------------- candidates
class Ctx:
    """Everything a stage needs about one run, loaded once."""

    def __init__(self, run: Path):
        self.run = run
        self.cfg = load()
        self.meta = runs.read_json(run, "run.json")
        self.pr = runs.read_json(run, "prioritised.json")
        self.findings = self.pr["findings"]
        self.byid = {f["id"]: f for f in self.findings}
        self.nodes = {n["id"]: n for n in runs.read_json(run, "graph.json")["nodes"]}
        self.head_src = runs.materialise(run, self.meta["head"])
        self.base_src = runs.materialise(run, self.meta["base"])
        self.fp = runs.fastpath()
        self.base_nodes = self.fp.inventory(str(self.base_src))["nodes"]
        self.head_sbom = runs.read_json(run, "sbom.head.cdx.json")

    def node(self, f: dict) -> dict | None:
        return self.nodes.get(f.get("nodeId"))


def _same_component_vulns(ctx: Ctx, purl: str) -> list[dict]:
    return [g for g in ctx.findings if g["type"] == "known_vulnerability" and g["component"] == purl]


def candidates(ctx: Ctx, f: dict) -> list[dict]:
    n = ctx.node(f) or {}
    name, ver = n.get("name"), n.get("version")
    out = []
    t = f["type"]
    if t == "known_vulnerability" and n.get("kind") == "pkg":
        inst = _sv(ver)
        fixed = sorted({v for v in f.get("fixed") or [] if _sv(v) > inst}, key=_sv)
        same = [v for v in fixed if _sv(v)[0] == inst[0]]
        if n.get("direct"):
            if same:
                out.append({"id": "V1", "kind": "upgrade", "summary": f"upgrade {name} {ver} -> {same[0]} "
                            f"(lowest fixed version for {f['advisory']})", "ops": [("set_dep", name, same[0])]})
                allfix = sorted({v for g in _same_component_vulns(ctx, f["component"]) for v in g.get("fixed") or []
                                 if _sv(v) > inst and _sv(v)[0] == inst[0]}, key=_sv)
                if allfix and allfix[-1] != same[0]:
                    out.append({"id": "V2", "kind": "upgrade", "summary": f"upgrade {name} {ver} -> {allfix[-1]} "
                                f"(highest fixed version among this package's advisories, same major)",
                                "ops": [("set_dep", name, allfix[-1])]})
            elif fixed:
                out.append({"id": "VM", "kind": "upgrade", "summary": f"major upgrade {name} {ver} -> {fixed[0]}",
                            "ops": [("set_dep", name, fixed[0])]})
            if (f.get("reachability") or {}).get("tier") == "R0":
                out.append({"id": "VR", "kind": "remove", "summary": f"remove {name}: no first-party code imports it",
                            "ops": [("remove_dep", name)]})
        elif fixed:
            out.append({"id": "VO", "kind": "override", "summary": f"npm override {name} -> {(same or fixed)[0]} "
                        "(transitive)", "ops": [("override", name, (same or fixed)[0])]})
    elif t in ("typosquat", "unexpected_dependency", "non_registry_origin", "unsafe_install_script", "suspicious_update") \
            and n.get("kind") == "pkg" and n.get("direct"):
        tarball = (n.get("resolved") or "")[5:] if (n.get("resolved") or "").startswith("file:") else None
        dead = unused_require_lines(ctx.head_src, name)
        base_node = next((b for b in ctx.base_nodes.values() if b.get("kind") == "pkg" and b["name"] == name
                          and b["id"] == n["id"]), None)
        if base_node and base_node["version"] != ver:   # changed since base -> restore base version
            base_pj = _read_json(ctx.base_src / "package.json")
            spec = {**base_pj.get("devDependencies", {}), **base_pj.get("dependencies", {})}.get(name)
            ops = [("set_dep", name, spec)]
            if (base_node.get("resolved") or "").startswith("file:"):
                ops.append(("restore", base_node["resolved"][5:], ctx.meta["base"]))
            if tarball and tarball != (base_node.get("resolved") or "")[5:]:
                ops.append(("delete", tarball))
            out.append({"id": "U1", "kind": "pin_back", "summary": f"restore {name} {ver} -> {base_node['version']} "
                        f"(the version at {ctx.meta['base']}) and block {ver}'s integrity hash",
                        "ops": ops, "policy_entries": [{"block": f["component"], "integrity": n.get("integrity")}]})
        if not base_node:
            out.append({"id": "C1", "kind": "remove", "summary": f"remove {name} from package.json and the lockfile "
                        "(manifest-only removal, what a dependency bot would do)", "ops": [("remove_dep", name)]})
        ops = [("remove_dep", name)] + ([("delete", tarball)] if tarball else []) + ([("remove_lines", dead)] if dead else [])
        imp = ctx.head_src and reachability.scan(ctx.head_src, {name})["imports"].get(name)
        if dead or not imp:
            out.append({"id": "C2" if not base_node else "U2", "kind": "remove",
                        "summary": f"remove {name}: manifest, lockfile" + (", vendored tarball" if tarball else "")
                                   + (", and its unused require() line" if dead else ""), "ops": ops})
        m = re.search(r"resembles '([^']+)'", f.get("title", ""))
        if t == "typosquat" and m and imp and not dead:
            out.append({"id": "C3", "kind": "replace", "summary": f"replace {name} with {m.group(1)}",
                        "ops": [("remove_dep", name), ("replace_require", name, m.group(1))]
                               + ([("delete", tarball)] if tarball else [])})
    elif t == "untrusted_image":
        df_h = (ctx.head_src / "Dockerfile").read_text(encoding="utf-8")
        df_b = (ctx.base_src / "Dockerfile").read_text(encoding="utf-8") if (ctx.base_src / "Dockerfile").exists() else ""
        h = re.findall(r"^\s*FROM\s+\S+.*$", df_h, re.MULTILINE)
        b = re.findall(r"^\s*FROM\s+\S+.*$", df_b, re.MULTILINE)
        if h and b and h[0] != b[0]:
            out.append({"id": "I1", "kind": "pin", "summary": f"restore the base image line `{b[0].strip()}` "
                        "(exact tag; digest pin not evaluated: no registry lookup)", "ops": [("replace_line", "Dockerfile", h[0], b[0])]})
    elif t in ("unpinned_ci_component", "unsafe_ci_pattern") and f.get("new_in_head"):
        rel = f["component"] if f["component"].startswith(".github/") else None
        if rel and not (ctx.base_src / rel).exists():
            out.append({"id": "A1", "kind": "remove", "summary": f"delete {rel} (introduced by this change; "
                        "pinning to a commit SHA needs a GitHub lookup: not evaluated)", "ops": [("delete", rel)]})
    out.append({"id": "E", "kind": "escalate", "summary": "escalate to a human security reviewer (no code change)",
                "ops": []})
    return out


def _apply(root: Path, ops: list) -> tuple[list[str], bool]:
    log, npm = [], False
    for op in ops:
        k = op[0]
        if k == "set_dep":
            log.append(op_set_dep(root, op[1], op[2]))
            npm = True
        elif k == "remove_dep":
            log.append(op_remove_dep(root, op[1]))
            npm = True
        elif k == "override":
            log.append(op_override(root, op[1], op[2]))
            npm = True
        elif k == "delete":
            log.append(op_delete(root, op[1]))
        elif k == "restore":
            log.append(op_restore(root, op[1], op[2]))
        elif k == "remove_lines":
            log.append(op_remove_lines(root, op[1]))
        elif k == "replace_require":
            log.append(op_replace_require(root, op[1], op[2]))
        elif k == "replace_line":
            log.append(op_replace_line(root, op[1], op[2], op[3]))
    return log, npm


# ---------------------------------------------------------------------------------- clone + dry run
def work_clone(ctx: Ctx, name: str) -> Path:
    w = ctx.run / "work" / name
    if w.exists():
        shutil.rmtree(w, ignore_errors=True)
    w.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "-q", "--local", str(runs.TARGET), str(w)], check=True, capture_output=True)
    for args in (["checkout", "-q", ctx.meta["head"]], ["remote", "remove", "origin"],
                 ["config", "user.name", "Guardian"], ["config", "user.email", "guardian@example.invalid"],
                 ["config", "commit.gpgsign", "false"], ["config", "core.autocrlf", "false"]):
        subprocess.run(["git", "-C", str(w), *args], check=True, capture_output=True)
    return w


def dangling_requires(root: Path) -> list[str]:
    """Packages first-party code require()s that the manifest no longer declares."""
    pj = _read_json(root / "package.json")
    declared = set(pj.get("dependencies", {})) | set(pj.get("devDependencies", {})) | set(pj.get("optionalDependencies", {}))
    imported = reachability.scan(root, set())["imports"]
    return sorted(p for p in imported if p not in declared and p not in NODE_BUILTINS)


def _resolved(ctx: Ctx, f: dict, pred_purls: set, root: Path) -> bool:
    if f["component"].startswith("pkg:npm/"):
        return f["component"] not in pred_purls
    for e in f.get("evidence", []):
        rel = e["source"].split(" @ ")[0]
        p = root / rel
        if e.get("line") and p.exists() and e["excerpt"].strip() in p.read_text(encoding="utf-8", errors="replace"):
            return False
    return True


def policy_state(ctx: Ctx, findings: list[dict], nodes: dict, root: Path) -> dict:
    df, wfs = policy.read_tree(root)
    dfb, wfb = policy.read_tree(ctx.base_src)
    kev_any = lambda f: any("is in CISA KEV" in fac["evidence"] for fac in f["priority"]["factors"].values()) \
        if "priority" in f else bool(f.get("kev"))
    def scope(f):
        n = ctx.nodes.get(f.get("nodeId")) or nodes.get(f.get("nodeId")) or {}
        return "ci" if f["component"].startswith(".github/") else ("dev" if n.get("dev") else "prod")
    doc = {"findings": [{"id": f["id"], "type": f["type"], "band": f["priority"]["band"] if "priority" in f else f["band"],
                         "kev": kev_any(f), "scope": scope(f), "status": "open", "component": f["component"]}
                        for f in findings if f["type"] not in ("new_dependency", "changed_dependency")],
           "components": policy.components(nodes, ctx.base_nodes),
           "images": policy.images(df, dfb), "actions": policy.actions(wfs, wfb),
           "config": {"allowed_install_scripts": ctx.cfg["trust"].get("allowed_install_scripts", [])}}
    return {"input": doc, **policy.evaluate(doc)}


def dry_run(ctx: Ctx, plan_id: str, cand: dict, target: dict, head_policy: dict) -> dict:
    if cand["kind"] == "escalate":
        return {"applied": [], "npm": None, "target_resolved": False, "resolved": [], "added": [], "removed": [],
                "version_changes": [], "new_vulnerabilities": [], "dangling_requires": [], "semver": "none",
                "policy": head_policy | {"input": None}, "plan_gate": {"pass": False, "reason": "no change"}}
    root = work_clone(ctx, f"{plan_id}-{cand['id']}")
    log, need_npm = _apply(root, cand["ops"])
    npm = None
    if need_npm:
        offline = ["--offline"] if os.environ.get("GUARDIAN_OFFLINE") == "1" else []   # npm cache only
        r = _sh([_npm(), "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", *offline],
                root, NPM_TIMEOUT)
        npm = {"exit": r.returncode, "tail": r.stdout.decode("utf-8", "replace")[-400:] + r.stderr.decode("utf-8", "replace")[-600:]}
        if r.returncode == 0:
            _normalise_file_paths(root / "package-lock.json")
    if npm and npm["exit"] != 0:
        return {"applied": log, "npm": npm, "error": "npm could not resolve the lockfile", "target_resolved": False,
                "plan_gate": {"pass": False, "reason": "dry run failed"}, "policy": {"pass": False, "deny": [], "warn": []}}
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", f"guardian {plan_id}: {cand['summary']}"],
                   check=False, capture_output=True)
    patch = subprocess.run(["git", "-C", str(root), "format-patch", "--binary", "-1", "--stdout"],
                           capture_output=True, check=True).stdout
    # ---- prediction
    pred_sbom = ctx.fp.lsd.sbom(str(root))
    hp = {c["purl"] for c in ctx.head_sbom["components"]}
    pp = {c["purl"] for c in pred_sbom["components"]}
    added, removed = sorted(pp - hp), sorted(hp - pp)
    def by_name(s):
        d: dict = {}
        for x in s:
            d.setdefault(x.rsplit("@", 1)[0], []).append(x.rsplit("@", 1)[1])
        return {k: sorted(v, key=_sv) for k, v in d.items()}
    hn, pn = by_name(hp - pp), by_name(pp - hp)
    changes = [{"package": k.split("/", 1)[1], "from": ", ".join(hn[k]), "to": ", ".join(pn[k]),
                "semver": max((semver_distance(a, b) for a in hn[k] for b in pn[k]), key=SEMVER_RANK.get)}
               for k in sorted(set(hn) & set(pn))]
    pred_inv = ctx.fp.inventory(str(root))
    pred_nodes = pred_inv["nodes"]
    add_nodes = {k: v for k, v in pred_nodes.items() if v.get("kind") == "pkg" and v["purl"] in set(added)}
    osv_status, osv_hits = ctx.fp.osv_scan(add_nodes)
    kev, _ = enrich.kev()
    new_v = []
    for nid, vs in osv_hits.items():
        nd = pred_nodes[nid]
        for v in vs:
            sev = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 50, "LOW": 20}.get(v["severity"], 50)
            new_v.append({"id": f"N-{v['id']}@{nd['name']}", "type": "known_vulnerability", "component": nd["purl"],
                          "advisory": v["id"], "severity": v["severity"], "fixed": v["fixed"], "nodeId": nid,
                          "band": score_band(sev - (20 if nd.get("dev") else 0)),
                          "kev": bool(kev and any(a in kev for a in v["aliases"])), "band_source": "OSV severity (not re-scored)"})
    seen, uniq_new = set(), []
    for v in new_v:
        if (v["component"], v["advisory"]) not in seen:
            seen.add((v["component"], v["advisory"]))
            uniq_new.append(v)
    resolved = [f["id"] for f in ctx.findings if _resolved(ctx, f, pp, root)]
    remaining = [f for f in ctx.findings if f["id"] not in set(resolved)]
    pred_policy = policy_state(ctx, remaining + uniq_new, pred_nodes, root)
    gate = policy.plan_gate(head_policy, pred_policy, target_tokens(target))
    dang = [d for d in dangling_requires(root) if d not in dangling_requires(ctx.head_src)]
    worst = max((SEMVER_RANK[c["semver"]] for c in changes), default=0)
    return {"applied": log, "npm": npm, "work_dir": str(root.relative_to(ctx.run)), "patch": patch.decode("utf-8", "replace"),
            "target_resolved": target["id"] in resolved, "resolved": resolved,
            "resolved_by_band": _bands(ctx, resolved), "added": added, "removed": removed, "version_changes": changes,
            "semver": next(k for k, v in SEMVER_RANK.items() if v == worst),
            "new_vulnerabilities": uniq_new, "new_vulnerability_lookup": osv_status.get("status"),
            "dangling_requires": dang, "policy": {k: pred_policy[k] for k in ("engine", "pass", "deny", "warn")},
            "plan_gate": gate,
            "risk": {"target_before": target["priority"]["score"], "target_after": 0 if target["id"] in resolved
                     else target["priority"]["score"], "max_new_vulnerability_band": max(
                         (v["band"] for v in uniq_new), key=lambda b: ["info", "low", "medium", "high", "critical"].index(b),
                         default=None)}}


def target_tokens(target: dict) -> list[str]:
    """Strings that identify the plan's target inside policy messages: its component, the same package
    at any version (`pkg:npm/name@`), and image refs / action refs quoted in its evidence."""
    c = target["component"]
    toks = [c] + ([c.rsplit("@", 1)[0] + "@"] if c.startswith("pkg:npm/") else [])
    for e in target.get("evidence", []):
        toks += re.findall(r"FROM\s+(\S+)", e.get("excerpt", "")) + re.findall(r"uses:\s*(\S+)", e.get("excerpt", ""))
    return sorted(set(toks))


def _bands(ctx: Ctx, ids: list[str]) -> dict:
    out = {}
    for i in ids:
        b = ctx.byid[i]["priority"]["band"]
        out[b] = out.get(b, 0) + 1
    return out


# all else equal, prefer fixes that keep the dependency working over removing or replacing it
KIND_PREFERENCE = {"upgrade": 0, "pin_back": 0, "override": 1, "pin": 1, "replace": 2, "remove": 3, "escalate": 9}


def rank_key(c: dict) -> tuple:
    p = c["prediction"]
    return (not p.get("target_resolved"), bool(p.get("dangling_requires")), not p.get("plan_gate", {}).get("pass"),
            len(p.get("new_vulnerabilities", [])), KIND_PREFERENCE.get(c["kind"], 5), -len(p.get("resolved", [])),
            SEMVER_RANK.get(p.get("semver", "none"), 0), len(c.get("ops", [])))


def why_not(chosen: dict, other: dict) -> str:
    a, b = chosen["prediction"], other["prediction"]
    if other["kind"] == "escalate":
        return "no code change; kept as the fallback if every candidate is rejected"
    if not b.get("target_resolved"):
        return "does not resolve the target finding"
    if b.get("dangling_requires") and not a.get("dangling_requires"):
        return f"leaves first-party code requiring a removed package: {', '.join(b['dangling_requires'])}"
    if not b.get("plan_gate", {}).get("pass") and a.get("plan_gate", {}).get("pass"):
        return "fails the plan gate: " + b["plan_gate"]["reason"]
    if len(b.get("new_vulnerabilities", [])) > len(a.get("new_vulnerabilities", [])):
        return f"leaves {len(b['new_vulnerabilities'])} known vulnerabilities on the new version vs {len(a['new_vulnerabilities'])}"
    if KIND_PREFERENCE.get(other["kind"], 5) > KIND_PREFERENCE.get(chosen["kind"], 5):
        return f"a {other['kind']} is more disruptive than a {chosen['kind']} that resolves the finding as well"
    if len(b.get("resolved", [])) < len(a.get("resolved", [])):
        return f"resolves {len(b['resolved'])} findings vs {len(a['resolved'])}"
    return "ranked lower on semver distance or size of change"


# ---------------------------------------------------------------------------------- plans
def _next_plan_id(run: Path) -> str:
    d = run / "plans"
    d.mkdir(exist_ok=True)
    n = len(list(d.glob("P-*.json"))) + 1
    return f"P-{n:04d}"


def make_plan(run: Path, finding_id: str, force_candidate: str | None = None, supersedes: str | None = None,
              planner=None, chosen_by: str | None = None) -> dict:
    ctx = Ctx(run)
    f = ctx.byid.get(finding_id)
    if not f:
        raise KeyError(f"no finding {finding_id}")
    head_policy = policy_state(ctx, ctx.findings, ctx.nodes, ctx.head_src)
    pid = _next_plan_id(run)
    cands = candidates(ctx, f)
    for c in cands:
        c["prediction"] = dry_run(ctx, pid, c, f, head_policy)
    # one follow-up: if an upgrade's new version still carries an advisory with a same-major fix, try that fix too
    for c in [c for c in cands if c["kind"] == "upgrade"]:
        tgt = c["ops"][0][2]
        later = sorted({v for nv in c["prediction"].get("new_vulnerabilities", [])
                        if nv["component"].rsplit("@", 1)[0] == f["component"].rsplit("@", 1)[0]
                        for v in nv.get("fixed") or [] if _sv(v) > _sv(tgt) and _sv(v)[0] == _sv(tgt)[0]}, key=_sv)
        if later and not any(x["ops"] and x["ops"][0][:2] == ("set_dep", c["ops"][0][1]) and x["ops"][0][2] == later[-1]
                             for x in cands):
            nc = {"id": "V3", "kind": "upgrade", "summary": f"upgrade {c['ops'][0][1]} -> {later[-1]} (fixes an advisory "
                  f"that still affects {tgt})", "ops": [("set_dep", c["ops"][0][1], later[-1])]}
            nc["prediction"] = dry_run(ctx, pid, nc, f, head_policy)
            cands.insert(-1, nc)
            break
    ranked = sorted(cands, key=rank_key)
    chosen = next((c for c in cands if c["id"] == force_candidate), None) if force_candidate else ranked[0]
    if chosen is None:
        raise KeyError(f"no candidate {force_candidate}; have {[c['id'] for c in cands]}")
    patch = chosen["prediction"].get("patch", "")
    (run / "plans" / f"{pid}.patch").write_text(patch, encoding="utf-8")
    plan = {
        "id": pid, "finding": f["id"], "finding_type": f["type"], "component": f["component"],
        "title": f.get("title"), "advisory": f.get("advisory"), "state": "pending_approval",
        "created": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), "supersedes": supersedes,
        "chosen": {k: chosen[k] for k in ("id", "kind", "summary")},
        "chosen_by": chosen_by or ("explicit --candidate (human/operator choice)" if force_candidate
                                   else "deterministic ranking"),
        "deterministic_best": ranked[0]["id"],
        "prediction": {k: v for k, v in chosen["prediction"].items() if k != "patch"},
        "alternatives_considered": [{"id": c["id"], "kind": c["kind"], "summary": c["summary"],
                                     "prediction": _short(c["prediction"]),
                                     "why_not_chosen": ("ranked best by code; not used because this plan was created "
                                                        f"for an explicitly chosen candidate ({chosen['id']})"
                                                        if rank_key(c) < rank_key(chosen) else why_not(chosen, c))}
                                    for c in cands if c is not chosen],
        "policy_entries": chosen.get("policy_entries", []),
        "policy_head": {k: head_policy[k] for k in ("engine", "pass", "deny", "warn")},
        "patch_file": f"plans/{pid}.patch", "plan_hash": hashlib.sha256(patch.encode("utf-8")).hexdigest(),
        "rollback": "Nothing to roll back in ./target (never modified). Discard the plan by deleting "
                    f"{chosen['prediction'].get('work_dir', 'its work clone')}. If the patch is later merged by a "
                    "human: `git revert <commit>` and `npm ci --ignore-scripts` from the restored lockfile.",
        "rationale": {"deterministic": f"{chosen['id']} ranked first: resolves the target="
                                       f"{chosen['prediction'].get('target_resolved')}, plan gate="
                                       f"{chosen['prediction'].get('plan_gate', {}).get('pass')}, "
                                       f"new vulnerabilities={len(chosen['prediction'].get('new_vulnerabilities', []))}, "
                                       f"findings resolved={len(chosen['prediction'].get('resolved', []))}, "
                                       f"semver={chosen['prediction'].get('semver')}"},
    }
    if planner:
        plan["rationale"]["ai"] = planner(ctx, plan, cands)
    runs.write_json(run, f"plans/{pid}.json", plan)
    audit.append(run, "guardian", "plan.created", pid, {"finding": f["id"], "candidate": chosen["id"],
                                                         "plan_hash": plan["plan_hash"], "supersedes": supersedes})
    runs.mark_stage(run, "plan", "ok")
    return plan


def _short(p: dict) -> dict:
    return {"target_resolved": p.get("target_resolved"), "resolved": len(p.get("resolved", [])),
            "added": len(p.get("added", [])), "removed": len(p.get("removed", [])), "semver": p.get("semver"),
            "new_vulnerabilities": len(p.get("new_vulnerabilities", [])), "dangling_requires": p.get("dangling_requires"),
            "plan_gate": (p.get("plan_gate") or {}).get("pass"), "error": p.get("error")}


# ---------------------------------------------------------------------------------- approval
def approve(run: Path, plan_id: str, approver: str, reject: bool = False, comment: str = "") -> dict:
    if not approver or not approver.strip():
        raise ValueError("an approver name is required")
    plan = runs.read_json(run, f"plans/{plan_id}.json")
    current = hashlib.sha256((run / plan["patch_file"]).read_text(encoding="utf-8").encode("utf-8")).hexdigest()
    if current != plan["plan_hash"]:
        raise ValueError("the plan's patch changed after it was created; re-plan instead of approving")
    rec = {"plan": plan_id, "plan_hash": plan["plan_hash"], "approver": approver.strip(),
           "decision": "rejected" if reject else "approved", "comment": comment,
           "at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds")}
    runs.write_json(run, f"approvals/{plan_id}.json", rec)
    plan["state"] = rec["decision"]
    runs.write_json(run, f"plans/{plan_id}.json", plan)
    audit.append(run, f"human:{rec['approver']}", f"plan.{rec['decision']}", plan_id,
                 {"plan_hash": plan["plan_hash"], "comment": comment})
    return rec


def check_approval(run: Path, plan_id: str) -> tuple[bool, str]:
    """Validation refuses a plan that is not approved, or whose current patch differs from the approved one."""
    pp = run / "plans" / f"{plan_id}.json"
    ap = run / "approvals" / f"{plan_id}.json"
    if not pp.exists():
        return False, f"no plan {plan_id}"
    plan = _read_json(pp)
    if not ap.exists():
        return False, f"{plan_id} has not been approved by a human"
    a = _read_json(ap)
    if a["decision"] != "approved":
        return False, f"{plan_id} was {a['decision']} by {a['approver']}"
    current = hashlib.sha256((run / plan["patch_file"]).read_text(encoding="utf-8").encode("utf-8")).hexdigest()
    if current != a["plan_hash"] or plan["plan_hash"] != a["plan_hash"]:
        return False, (f"{plan_id} changed after approval (approved hash {a['plan_hash'][:12]}, current "
                       f"{current[:12]}): a new approval is required")
    return True, f"{plan_id} approved by {a['approver']} at {a['at']} for hash {a['plan_hash'][:12]}"
