"""Policy gate: the rules of policy/guardian.rego, evaluated in Python (conftest is not installed).

Input document shape: policy/README.md. `new` = introduced since the base ref. `deny` fails the gate,
`warn` does not. Rules (same as the Rego file):
  deny  open critical finding on a production component
  deny  open finding whose CVE is in the CISA KEV catalogue
  deny  new component with an install script not on the reviewed allow-list   (warn if existing)
  deny  new component from an untrusted origin                                (warn if origin unknown)
  deny  changed image reference without a digest                              (warn if existing)
  deny  new third-party action not pinned to a commit SHA                      (warn if existing)

Plan gate (our addition, see implementations.md phase 10): a plan passes when its predicted state
has no deny on the plan's target component and introduces no deny that head did not already have.
"""

from __future__ import annotations

import re
from pathlib import Path

ENGINE = "guardian/policy.py (Python port of policy/guardian.rego; conftest not installed)"


def images(text: str, base_text: str) -> list[dict]:
    out = []
    base = set(re.findall(r"^\s*FROM\s+(\S+)", base_text or "", re.MULTILINE | re.IGNORECASE))
    for ref in re.findall(r"^\s*FROM\s+(\S+)", text or "", re.MULTILINE | re.IGNORECASE):
        digest = ref.split("@", 1)[1] if "@sha256:" in ref else None
        out.append({"ref": ref, "digest": digest, "tag": ref.split("@")[0].split(":")[1] if ":" in ref.split("@")[0] else "latest",
                    "new": ref not in base})
    return out


def actions(workflows: dict[str, str], base_workflows: dict[str, str]) -> list[dict]:
    out = []
    base_uses = {u for t in base_workflows.values() for u in re.findall(r"uses:\s*(\S+)", t)}
    for path, t in workflows.items():
        for uses in re.findall(r"uses:\s*(\S+)", t):
            if "@" not in uses:
                continue
            owner = uses.split("/")[0]
            out.append({"uses": uses, "file": path, "pinned_sha": bool(re.fullmatch(r"[0-9a-f]{40}", uses.split("@")[1])),
                        "first_party": owner in ("actions", "github"), "new": uses not in base_uses})
    return out


def read_tree(root: Path) -> tuple[str, dict]:
    df = root / "Dockerfile"
    wf = root / ".github" / "workflows"
    return (df.read_text(encoding="utf-8", errors="replace") if df.exists() else "",
            {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8", errors="replace")
             for p in sorted(wf.glob("*.y*ml"))} if wf.is_dir() else {})


def components(nodes: dict, base_nodes: dict) -> list[dict]:
    base = {n.get("purl") for n in base_nodes.values() if n.get("kind") == "pkg"}
    out, seen = [], set()
    for n in nodes.values():
        if n.get("kind") != "pkg" or n["purl"] in seen:
            continue
        seen.add(n["purl"])
        origin = True if n.get("registry") else (None if not n.get("resolved") else False)
        out.append({"purl": n["purl"], "name": n["name"], "has_install_script": bool(n.get("install")),
                    "origin_trusted": origin, "new": n["purl"] not in base})
    return out


def evaluate(doc: dict) -> dict:
    deny, warn = [], []
    allowed = set(doc.get("config", {}).get("allowed_install_scripts", []))
    for f in doc.get("findings", []):
        if f.get("status") == "open" and f.get("band") == "critical" and f.get("scope") == "prod":
            deny.append(f"critical finding {f['id']} open on production component {f['component']}")
        if f.get("status") == "open" and f.get("kev") is True:
            deny.append(f"finding {f['id']} is in the CISA KEV catalogue ({f['component']})")
    for c in doc.get("components", []):
        if c["has_install_script"] and c["name"] not in allowed:
            (deny if c["new"] else warn).append(
                f"{'new' if c['new'] else 'existing'} component {c['purl']} runs an install script that is not on the reviewed allow-list")
        if c["new"] and c["origin_trusted"] is False:
            deny.append(f"new component {c['purl']} does not come from a trusted registry")
        if c["origin_trusted"] is None:
            warn.append(f"origin of {c['purl']} could not be determined (unknown is not trusted)")
    for i in doc.get("images", []):
        if i["digest"] is None:
            (deny if i["new"] else warn).append(
                f"{'changed' if i['new'] else 'existing'} image reference {i['ref']} is not pinned by digest")
    for a in doc.get("actions", []):
        if not a["first_party"] and not a["pinned_sha"]:
            (deny if a["new"] else warn).append(
                f"{'new' if a['new'] else 'existing'} third-party action {a['uses']} is not pinned to a commit SHA")
    return {"engine": ENGINE, "pass": not deny, "deny": sorted(set(deny)), "warn": sorted(set(warn))}


def plan_gate(head: dict, predicted: dict, target_tokens: list[str]) -> dict:
    """Pass if no predicted deny names the target and no deny is new compared with head."""
    on_target = [d for d in predicted["deny"] if any(t and t in d for t in target_tokens)]
    introduced = [d for d in predicted["deny"] if d not in head["deny"]]
    ok = not on_target and not introduced
    reason = ("no remaining violation on the target and none introduced" if ok else
              "; ".join(filter(None, [f"{len(on_target)} violation(s) remain on the target" if on_target else "",
                                      f"{len(introduced)} new violation(s) introduced" if introduced else ""])))
    return {"pass": ok, "reason": reason, "remaining_on_target": on_target, "introduced": introduced,
            "resolved": [d for d in head["deny"] if d not in predicted["deny"]]}
