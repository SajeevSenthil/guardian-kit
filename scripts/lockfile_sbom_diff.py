#!/usr/bin/env python3
"""Offline fallback: npm lockfile (v2/v3) -> minimal CycloneDX 1.5 JSON, and SBOM diff.

Stdlib only, no network. Written because syft / cyclonedx-npm could not be installed in the
verification sandbox (see docs/research/02-tool-verification.md). The diff half works on any
CycloneDX JSON (syft, cyclonedx-npm, cdxgen or this script), keyed on purl.

  lockfile_sbom_diff.py sbom <project-dir> > sbom.cdx.json
  lockfile_sbom_diff.py diff <old.cdx.json> <new.cdx.json> > diff.json
"""

import json
import os
import sys

REGISTRY = "https://registry.npmjs.org/"


def _name(path, entry):
    return entry.get("name") or path.split("node_modules/")[-1]


def _ref(path, entry):
    return "pkg:npm/%s@%s" % (_name(path, entry).replace("@", "%40", 1), entry.get("version", "0"))


def _resolve(packages, from_path, dep):
    """Node resolution: nearest node_modules/<dep> walking up from from_path."""
    base = from_path
    while True:
        cand = (base + "/" if base else "") + "node_modules/" + dep
        if cand in packages:
            return cand
        if not base:
            return None
        cut = base.rfind("/node_modules/")
        base = base[:cut] if cut >= 0 else ""


def sbom(project):
    lock = json.load(open(os.path.join(project, "package-lock.json")))
    pk = lock["packages"]
    root = pk[""]
    root_ref = "pkg:npm/%s@%s" % (lock.get("name", "root"), lock.get("version", "0"))
    comps, deps = {}, {}
    for path, e in pk.items():
        if not path or e.get("link"):
            continue
        ref = _ref(path, e)
        resolved = e.get("resolved", "")
        props = [
            {"name": "guardian:lockPath", "value": path},
            {"name": "guardian:resolved", "value": resolved},
            {"name": "guardian:registrySource", "value": str(resolved.startswith(REGISTRY)).lower()},
            {"name": "guardian:hasInstallScript", "value": str(bool(e.get("hasInstallScript"))).lower()},
            {"name": "guardian:integrity", "value": e.get("integrity", "")},
            {"name": "guardian:dev", "value": str(bool(e.get("dev"))).lower()},
        ]
        c = comps.setdefault(
            ref,
            {
                "type": "library",
                "bom-ref": ref,
                "name": _name(path, e),
                "version": e.get("version", ""),
                "purl": ref,
                "scope": "optional" if e.get("dev") else "required",
                "properties": props,
            },
        )
        if resolved and not resolved.startswith("file:"):
            c["externalReferences"] = [{"type": "distribution", "url": resolved}]
    for path, e in pk.items():
        if e.get("link"):
            continue
        names = dict(e.get("dependencies", {}))
        names.update(e.get("optionalDependencies", {}))
        if not path:
            names.update(e.get("devDependencies", {}))
        me = root_ref if not path else _ref(path, e)
        out = deps.setdefault(me, set())
        for d in names:
            t = _resolve(pk, path, d)
            if t:
                out.add(_ref(t, pk[t]))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{"name": "guardian-lockfile-sbom", "version": "0.1"}],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": lock.get("name", "root"),
                "version": lock.get("version", ""),
            },
        },
        "components": [comps[k] for k in sorted(comps)],
        "dependencies": [{"ref": k, "dependsOn": sorted(v)} for k, v in sorted(deps.items())],
    }


def _near(a, b):
    """True if a != b and they differ by one edit or one adjacent swap (typosquat shapes)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return (
            len(diff) == 2
            and diff[1] == diff[0] + 1
            and a[diff[0]] == b[diff[1]]
            and a[diff[1]] == b[diff[0]]
        )
    s, l = (a, b) if len(a) < len(b) else (b, a)
    return any(l[:i] + l[i + 1 :] == s for i in range(len(l)))


def _props(c):
    return {p["name"]: p["value"] for p in c.get("properties", [])}


def diff(old, new):
    o = {c.get("purl") or c["bom-ref"]: c for c in old.get("components", [])}
    n = {c.get("purl") or c["bom-ref"]: c for c in new.get("components", [])}
    names_old = {c["name"] for c in o.values()}
    parents = {}
    for d in new.get("dependencies", []):
        for t in d.get("dependsOn", []):
            parents.setdefault(t, []).append(d["ref"])
    added = []
    for k in sorted(set(n) - set(o)):
        c, p = n[k], _props(n[k])
        flags = []
        if p.get("guardian:registrySource") == "false":
            flags.append("non-registry-source")
        if p.get("guardian:hasInstallScript") == "true":
            flags.append("install-script")
        look = sorted(x for x in names_old if _near(c["name"], x))
        if look:
            flags.append("name-resembles:" + ",".join(look))
        added.append(
            {
                "purl": k,
                "name": c["name"],
                "version": c.get("version"),
                "resolved": p.get("guardian:resolved"),
                "introducedBy": parents.get(k, []),
                "flags": flags,
            }
        )
    changed = []
    for k in sorted(set(n) & set(o)):
        po, pn = _props(o[k]), _props(n[k])
        for f in ("guardian:integrity", "guardian:resolved", "guardian:hasInstallScript"):
            if f in po and po.get(f) != pn.get(f):
                changed.append({"purl": k, "field": f, "old": po.get(f), "new": pn.get(f)})
    return {
        "counts": {"old": len(o), "new": len(n)},
        "added": added,
        "removed": sorted(set(o) - set(n)),
        "changedSamePurl": changed,
    }


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "sbom":
        json.dump(sbom(sys.argv[2]), sys.stdout, indent=1)
    elif len(sys.argv) == 4 and sys.argv[1] == "diff":
        json.dump(diff(json.load(open(sys.argv[2])), json.load(open(sys.argv[3]))), sys.stdout, indent=1)
    else:
        sys.exit(__doc__)
