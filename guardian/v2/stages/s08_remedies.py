"""Stage 8 - Remedies: one hash-bound upgrade plan per package; waits for a human decision in the UI.

Decisions are recorded ONLY through guardian/api/routes_approval.py (a human click).
Page: guardian/api/static/pages/s08_remedies.js · Output: stages/remedies/ (result.json, P-*.patch, approved_set.json)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path

from ..identity import norm_name, vkey
from ..proc import now
from ..proc import run as _run
from ..workspace import Workspace

HASHED = ("id", "component_id", "ecosystem", "name", "from_version", "to_version", "targets", "edits", "kind")


def plan_hash(plan: dict) -> str:
    body = {k: plan.get(k) for k in HASHED} | {"patch_sha256": plan.get("patch_sha256")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _clone(ws: Workspace, name: str) -> Path:
    d = ws.dir / "work" / name
    if d.exists():
        shutil.rmtree(d, onerror=lambda f, p, e: (os.chmod(p, 0o700), f(p)))
    d.parent.mkdir(parents=True, exist_ok=True)
    r = _run(["git", "-c", "core.autocrlf=false", "clone", "-q", "--no-hardlinks", "--no-recurse-submodules",
              "-c", f"core.hooksPath={ws.dir / '.nohooks'}", str(ws.src), str(d)])
    if r.returncode:
        raise RuntimeError(f"clone failed: {r.stderr.strip()[-200:]}")
    _run(["git", "config", "core.autocrlf", "false"], cwd=d)
    return d


def apply_edit(root: Path, e: dict) -> None:
    p = root / e["file"]
    if e["kind"] == "replace_line":
        raw = p.read_bytes().decode("utf-8")
        lines = raw.splitlines(keepends=True)
        i = e["line"] - 1
        if i >= len(lines) or lines[i].rstrip("\r\n") != e["old"]:
            raise RuntimeError(f"{e['file']}:{e['line']} no longer reads {e['old']!r}")
        end = lines[i][len(lines[i].rstrip("\r\n")):]
        lines[i] = e["new"] + end
        p.write_bytes("".join(lines).encode("utf-8"))
    elif e["kind"] == "json_set":
        raw = p.read_bytes().decode("utf-8")
        j = json.loads(raw)
        cur = j
        for k in e["path"][:-1]:
            cur = cur.setdefault(k, {})
        cur[e["path"][-1]] = e["value"]
        indent = 2 if '\n  "' in raw else 4 if '\n    "' in raw else 2
        nl = "\r\n" if "\r\n" in raw else "\n"
        p.write_bytes((json.dumps(j, indent=indent, ensure_ascii=False) + "\n").replace("\n", nl).encode("utf-8"))
    else:
        raise RuntimeError(f"unknown edit kind {e['kind']}")


def _req_edit(src: Path, ing: dict, name: str, old: str, new: str) -> dict | None:
    for f in (ing.get("ecosystems", {}).get("pypi", {}) or {}).get("manifests", []):
        if not Path(f).name.startswith("requirements"):
            continue
        for i, ln in enumerate((src / f).read_bytes().decode("utf-8", "replace").splitlines(), 1):
            m = re.match(r"^(\s*)([A-Za-z0-9_.\-\[\]]+)(\s*==\s*)([^\s;#]+)(.*)$", ln)
            if m and norm_name("pypi", re.sub(r"\[.*\]", "", m.group(2))) == norm_name("pypi", name) and m.group(4) == old:
                return {"file": f, "kind": "replace_line", "line": i, "old": ln,
                        "new": f"{m.group(1)}{m.group(2)}{m.group(3)}{new}{m.group(5)}"}
    return None


def _npm_edit(src: Path, name: str, new: str) -> dict | None:
    p = src / "package.json"
    if not p.exists():
        return None
    j = json.loads(p.read_text(encoding="utf-8"))
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        if name in (j.get(sec) or {}):
            return {"file": "package.json", "kind": "json_set", "path": [sec, name], "value": new,
                    "note": f"direct dependency: set {sec}.{name} to {new}"}
    return {"file": "package.json", "kind": "json_set", "path": ["overrides", name], "value": new,
            "note": f"transitive dependency: npm overrides forces {name}@{new} wherever it is required"}


def _major(v: str) -> tuple:
    """Semver 'major' part: the first number, or the first two for 0.x versions (0.2 -> 0.3 is breaking)."""
    nums = [x[1] for x in vkey(v or "0") if x[0] == 1] or [0]
    return tuple(nums[:2]) if nums[0] == 0 else (nums[0],)


def _pick_version(installed: str | None, rows: list[dict]) -> tuple[str | None, list[str]]:
    """Lowest version that is >= a fix of every advisory with a fix; advisories without a fix are listed."""
    need, nofix = None, []
    iv = vkey(installed or "0")
    for r in rows:
        later = sorted((f for f in r["fixed"] if vkey(f) > iv), key=vkey)
        if not later:
            nofix.append(r["advisory"])
            continue
        if need is None or vkey(later[0]) > vkey(need):
            need = later[0]
    return need, nofix


def run_remedies(ws: Workspace, opts: dict) -> dict:
    pri, vul, ing = ws.read("prioritise") or {"items": []}, ws.read("vulns") or {"rows": []}, ws.read("ingest") or {}
    top = int(opts.get("top") or 10)
    by_comp: dict[str, list] = {}
    for r in vul["rows"]:
        by_comp.setdefault(r["component_id"], []).append(r)
    chosen, seen = [], set()
    for it in pri["items"]:
        r0 = (by_comp.get(it.get("component_id")) or [None])[0]
        name_key = (r0["ecosystem"], norm_name(r0["ecosystem"], r0["name"])) if r0 else None
        if it["kind"] == "vuln" and r0 and name_key not in seen:  # one plan per package (all installed versions)
            seen.add(name_key)
            chosen.append(it)
        if len(chosen) >= top:
            break
    out = ws.stage_dir("remedies")
    for old in out.glob("P-*.patch"):
        old.unlink()
    clone = _clone(ws, "plan") if chosen else None
    plans = []
    for n, it in enumerate(chosen, 1):
        rows = by_comp[it["component_id"]]
        r0 = rows[0]
        eco, name, ver = r0["ecosystem"], r0["name"], r0["version"]
        to, nofix = _pick_version(ver, rows)
        pid = f"P-{n:04d}"
        plan = {"id": pid, "component_id": it["component_id"], "ecosystem": eco, "name": name, "from_version": ver,
                "to_version": to, "targets": sorted(r["advisory"] for r in rows if r["advisory"] not in nofix),
                "unfixable": nofix, "priority": {"rank": it["rank"], "score": it["score"], "band": it["band"]},
                "edits": [], "kind": "upgrade", "decision": {"status": "pending"}, "patch": None, "patch_sha256": None}
        edit = None
        if to and eco == "pypi":
            edit = _req_edit(ws.src, ing, name, ver, to)
        elif to and eco == "npm":
            edit = _npm_edit(ws.src, name, to)
        if not to:
            plan.update(kind="manual", reason="no fixed version is published for these advisories")
        elif not edit:
            plan.update(kind="manual", reason=(f"no exact pin for {name} found in a manifest Guardian can edit "
                                               f"({eco}); upgrade it by hand or through its parent package"))
        else:
            plan["edits"] = [edit]
            try:
                apply_edit(clone, edit)
                diff = _run(["git", "diff", "--no-color"], cwd=clone).stdout
                _run(["git", "checkout", "--", "."], cwd=clone)
                pb = diff.encode("utf-8")
                (out / f"{pid}.patch").write_bytes(pb)
                plan["patch"], plan["patch_sha256"] = ws.rel(out / f"{pid}.patch"), hashlib.sha256(pb).hexdigest()
            except Exception as e:  # noqa: BLE001 - recorded on the plan, shown to the human
                plan.update(kind="manual", reason=f"edit could not be prepared: {e}", edits=[])
        plan["lockfile_note"] = ("npm: the lockfile is regenerated in the sandbox with --package-lock-only --ignore-scripts"
                                 if eco == "npm" else "requirements pins are the lock: no regeneration needed"
                                 if eco == "pypi" else None)
        plan["why"] = (f"Ranked #{it['rank']} ({it['band']}, {it['score']}). Moving {name} {ver} → {to} fixes "
                       f"{len(plan['targets'])} advisory(ies): {', '.join(plan['targets'][:6])}"
                       + (f"; no fix exists yet for {', '.join(nofix)}" if nofix else "") + "." if to else
                       f"Ranked #{it['rank']}; no fixed version published.")
        plan["rollback"] = "revert the patch (git revert) or restore the previous version pin"
        plan["major_upgrade"] = bool(to and ver and _major(to) != _major(ver))
        if plan["major_upgrade"]:
            plan["breaking_risk"] = (f"major version change {ver} → {to}: APIs may have changed; expect code changes "
                                     "and rely on the sandbox tests")
        plan["plan_hash"] = plan_hash(plan)
        plans.append(plan)
    result = {"plans": plans, "sent": False, "approved_set": None,
              "note": "Plans are computed by code from the advisories' fixed versions. Approve, reject or defer each "
                      "one; only approved plans go to the sandbox. The approval is bound to plan_hash."}
    ws.write("remedies", result)
    summary = _summary(result)
    ws.set_status("remedies", "awaiting_approval", summary=summary)
    return summary


def _summary(res: dict) -> dict:
    ps = res["plans"]
    actionable = [p for p in ps if p["kind"] != "manual"]
    return {"plans": len(ps), "actionable": len(actionable),
            "decided": sum(1 for p in actionable if p["decision"]["status"] != "pending"),
            "approved": sum(1 for p in actionable if p["decision"]["status"] == "approved")}


# decisions are made ONLY through guardian/api/routes_approval.py (a human click); kept here as pure helpers
def record_decision(ws: Workspace, plan_id: str, decision: str, approver: str, hash_shown: str, note: str = "") -> dict:
    res = ws.read("remedies")
    if not res:
        raise LookupError("no remedies yet")
    if res.get("sent"):
        raise PermissionError("the approved set was already sent to the sandbox; re-run remedies to change it")
    plan = next((p for p in res["plans"] if p["id"] == plan_id), None)
    if not plan:
        raise LookupError(f"no plan {plan_id}")
    if decision not in ("approve", "reject", "defer"):
        raise ValueError("decision must be approve, reject or defer")
    if not (approver or "").strip():
        raise ValueError("approver name is required")
    if plan["kind"] == "manual" and decision == "approve":
        raise ValueError("a manual plan cannot be approved: it has no edit to apply")
    if hash_shown != plan["plan_hash"] or plan_hash(plan) != plan["plan_hash"]:
        raise PermissionError("plan_hash mismatch: the plan changed since it was shown; reload and review it again")
    plan["decision"] = {"status": {"approve": "approved", "reject": "rejected", "defer": "deferred"}[decision],
                        "by": approver.strip(), "at": now(), "note": note, "plan_hash": plan["plan_hash"]}
    ws.write("remedies", res)
    ws.set_status("remedies", "awaiting_approval", summary=_summary(res))
    ws.audit(f"plan_{decision}", actor=approver.strip(), plan=plan_id, plan_hash=plan["plan_hash"], note=note)
    return plan


def freeze_approved(ws: Workspace) -> dict:
    res = ws.read("remedies")
    act = [p for p in res["plans"] if p["kind"] != "manual"]
    if any(p["decision"]["status"] == "pending" for p in act):
        raise ValueError("decide every plan first (approve, reject or defer)")
    appr = [p for p in act if p["decision"]["status"] == "approved"]
    if not appr:
        raise ValueError("approve at least one plan to send to the sandbox")
    aset = {"at": now(), "plans": [{"id": p["id"], "plan_hash": p["plan_hash"], "by": p["decision"]["by"]} for p in appr]}
    (ws.stage_dir("remedies") / "approved_set.json").write_text(json.dumps(aset, indent=2), encoding="utf-8")
    res["sent"], res["approved_set"] = True, ws.rel(ws.stage_dir("remedies") / "approved_set.json")
    ws.write("remedies", res)
    ws.set_status("remedies", "ok", summary=_summary(res))
    ws.audit("send_to_sandbox", actor=appr[0]["decision"]["by"], plans=[p["id"] for p in appr])
    return aset
