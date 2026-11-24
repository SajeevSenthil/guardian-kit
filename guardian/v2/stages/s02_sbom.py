"""Stage 2 - Inventory & SBOM: Syft for every ecosystem, manifest parsing for direct/dev, v1 npm cross-check.

Page: guardian/api/static/pages/s02_sbom.js · Output: stages/sbom/ (result.json, syft.json, syft.cdx.json, syft.spdx.json)
"""

from __future__ import annotations

import collections
import json
import os
import re
import shutil
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import tomllib

from ...config import load as load_cfg
from .. import bridge
from ..identity import EXACT, norm_name, norm_purl, purl_type
from ..proc import run as _run
from ..tools import find_tool, tool_version
from ..workspace import Workspace
from .s01_ingest import _req_lines

SYFT_EXCLUDES = ["./**/node_modules/**", "./**/.git/**", "./**/.venv/**", "./**/venv/**", "./**/__pycache__/**"]


def _line_of(text: str, needle: str) -> int | None:
    pat = re.compile(r"(^|[\s\"'\[{(,])" + re.escape(needle) + r"($|[\s\"'=<>~!;:@\[,)\]}])", re.I)
    for i, ln in enumerate(text.splitlines(), 1):
        if pat.search(ln):
            return i
    return None


def direct_deps(src: Path, found: dict) -> dict:
    """{(eco, normalised name): {"dev": bool, "file": rel, "line": n, "spec": str}} from ROOT-level manifests
    (and any requirements*.txt). Best effort per ecosystem; anything not parsed is simply not marked direct."""
    out: dict[tuple, dict] = {}

    def add(eco, name, rel, dev=False, spec=""):
        key = (eco, norm_name(eco, name))
        if not name or key in out and not out[key]["dev"]:
            return
        text = (src / rel).read_text(encoding="utf-8", errors="replace")
        out[key] = {"dev": dev, "file": rel, "line": _line_of(text, name), "spec": spec}

    for eco, d in found.get("ecosystems", {}).items():
        for rel in d["manifests"]:
            p = src / rel
            base = p.name
            top = "/" not in rel
            try:
                if eco == "npm" and base == "package.json" and top:
                    j = json.loads(p.read_text(encoding="utf-8"))
                    for sec, dev in (("dependencies", False), ("optionalDependencies", False),
                                     ("peerDependencies", False), ("devDependencies", True)):
                        for n, v in (j.get(sec) or {}).items():
                            add(eco, n, rel, dev, str(v))
                elif eco == "pypi" and base.startswith("requirements") and base.endswith(".txt"):
                    dev = bool(re.search(r"dev|test|lint|doc", base))
                    for _, s in _req_lines(p):
                        n = re.split(r"[\s\[<>=!~;@]", s, 1)[0]
                        add(eco, n, rel, dev, s[len(n):].strip())
                elif eco == "pypi" and base in ("pyproject.toml", "Pipfile") and top:
                    t = tomllib.loads(p.read_text(encoding="utf-8"))
                    for s in (t.get("project", {}).get("dependencies") or []):
                        n = re.split(r"[\s\[<>=!~;@]", s, 1)[0]
                        add(eco, n, rel, False, s[len(n):].strip())
                    for grp in (t.get("project", {}).get("optional-dependencies") or {}).values():
                        for s in grp:
                            add(eco, re.split(r"[\s\[<>=!~;@]", s, 1)[0], rel, True)
                    poetry = t.get("tool", {}).get("poetry", {})
                    for n, v in (poetry.get("dependencies") or {}).items():
                        if n.lower() != "python":
                            add(eco, n, rel, False, str(v))
                    for g in (poetry.get("group") or {}).values():
                        for n in (g.get("dependencies") or {}):
                            add(eco, n, rel, True)
                    for sec, dev in (("packages", False), ("dev-packages", True)):
                        for n, v in (t.get(sec) or {}).items():
                            add(eco, n, rel, dev, str(v))
                elif eco == "golang" and base == "go.mod":
                    for ln in p.read_text(encoding="utf-8").splitlines():
                        m = re.match(r"^\s*(?:require\s+)?([\w.\-]+\.[\w.\-/]+)\s+(v\S+)(.*)$", ln)
                        if m and "// indirect" not in m.group(3):
                            add(eco, m.group(1), rel, False, m.group(2))
                elif eco == "cargo" and base == "Cargo.toml" and top:
                    t = tomllib.loads(p.read_text(encoding="utf-8"))
                    for sec, dev in (("dependencies", False), ("dev-dependencies", True), ("build-dependencies", True)):
                        for n in (t.get(sec) or {}):
                            add(eco, n, rel, dev)
                elif eco == "composer" and base == "composer.json" and top:
                    j = json.loads(p.read_text(encoding="utf-8"))
                    for sec, dev in (("require", False), ("require-dev", True)):
                        for n, v in (j.get(sec) or {}).items():
                            if "/" in n:
                                add(eco, n, rel, dev, str(v))
                elif eco == "gem" and base == "Gemfile" and top:
                    for m in re.finditer(r"""^\s*gem\s+['"]([^'"]+)['"]""", p.read_text(encoding="utf-8"), re.M):
                        add(eco, m.group(1), rel)
                elif eco == "maven" and base == "pom.xml" and top:
                    xml = p.read_text(encoding="utf-8", errors="replace")
                    for m in re.finditer(r"<dependency>(.*?)</dependency>", xml, re.S):
                        g = re.search(r"<groupId>\s*([^<\s]+)", m.group(1))
                        a = re.search(r"<artifactId>\s*([^<\s]+)", m.group(1))
                        sc = re.search(r"<scope>\s*([^<\s]+)", m.group(1))
                        if g and a:
                            add(eco, f"{g.group(1)}/{a.group(1)}", rel, bool(sc and sc.group(1) == "test"))
            except (OSError, ValueError, tomllib.TOMLDecodeError):
                continue
    return out


def _comp_name(eco: str, a: dict) -> str:
    if eco == "maven":
        m = re.match(r"pkg:maven/([^@?]+)", urllib.parse.unquote(a.get("purl") or ""))
        if m:
            return m.group(1)
    if eco == "golang":
        return a.get("name", "")
    return a.get("name", "")


def run_syft(ws: Workspace, out_dir: Path) -> dict:
    exe = find_tool("syft")
    if not exe:
        raise RuntimeError("Syft is not installed: run `python scripts/setup_tools.py` (or scripts/setup_tools.ps1)")
    cmd = [exe, "scan", f"dir:{ws.src}", "-q", "-o", f"syft-json={out_dir / 'syft.json'}",
           "-o", f"cyclonedx-json={out_dir / 'syft.cdx.json'}", "-o", f"spdx-json={out_dir / 'syft.spdx.json'}"]
    for x in SYFT_EXCLUDES:
        cmd += ["--exclude", x]
    # dev dependencies are part of the supply chain (build/test tools): include them, and mark them dev later
    r = _run(cmd, timeout=int(load_cfg()["limits"].get("tool_timeout_s", 180)) + 120,
             extra_env={"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true", "SYFT_CHECK_FOR_APP_UPDATE": "false"})
    if r.returncode or not (out_dir / "syft.json").exists():
        raise RuntimeError(f"syft failed (exit {r.returncode}): {(r.stderr or '').strip()[-300:]}")
    shown = " ".join(Path(c).name if i == 0 else c for i, c in enumerate(cmd))
    return {"command": shown.replace(str(out_dir), "<stage dir>").replace(str(ws.src), "<src>"),
            "version": tool_version("syft")}


def components_from_syft(syft: dict, src: Path, directs: dict) -> tuple[list[dict], list[dict]]:
    """(components, relationships as (dependent_purl, dependency_purl, lockfile)) from syft-json."""
    srcs = str(src.resolve()).replace("\\", "/").lower()
    by_id, comps = {}, {}
    for a in syft.get("artifacts", []):
        eco = purl_type(a.get("purl", "")) if a.get("purl") else (a.get("type") or "unknown")
        name = _comp_name(eco, a)
        ver = a.get("version") or ""
        unpinned = not EXACT.match(ver)
        locs = []
        for loc in a.get("locations", []):
            p = (loc.get("path") or "").replace("\\", "/")
            p = p[len(srcs):].lstrip("/") if p.lower().startswith(srcs) else p.lstrip("/")
            if p not in locs:
                locs.append(p)
        key = norm_purl(a["purl"]) if a.get("purl") and not unpinned else f"{eco}:{norm_name(eco, name)}@{ver or '?'}"
        d = directs.get((eco, norm_name(eco, name)))
        c = comps.get(key) or {
            "id": key, "ecosystem": eco, "name": name, "version": None if unpinned else ver,
            "declared": ver if unpinned and ver else None, "unpinned": unpinned, "purl": a.get("purl"),
            "direct": None, "dev": None, "locations": [], "licenses": [], "source_tool": ["syft"],
            "found_by": a.get("foundBy"), "introduced_via": None}
        c["locations"] = sorted(set(c["locations"]) | set(locs))
        for lic in a.get("licenses", []) or []:
            v = lic.get("spdxExpression") or lic.get("value")
            if v and v not in c["licenses"]:
                c["licenses"].append(v)
        if d:
            c["direct"], c["dev"] = True, d["dev"]
            c["manifest"] = {"file": d["file"], "line": d["line"], "spec": d["spec"]}
        comps[key] = c
        by_id[a["id"]] = key
    rels = []
    for r in syft.get("artifactRelationships", []):
        if r.get("type") != "dependency-of":
            continue
        dep, dependent = by_id.get(r.get("parent")), by_id.get(r.get("child"))
        if dep and dependent and dep != dependent:
            rels.append({"from": dependent, "to": dep, "source": "syft",
                         "file": (comps[dependent]["locations"] or [None])[0]})
    known_direct = {(c["ecosystem"], norm_name(c["ecosystem"], c["name"])) for c in comps.values()}
    for (eco, n), d in directs.items():  # declared in a manifest but not reported by Syft (e.g. unpinned)
        if (eco, n) not in known_direct:
            key = f"{eco}:{n}@?"
            comps[key] = {"id": key, "ecosystem": eco, "name": n, "version": None, "declared": d["spec"] or None,
                          "unpinned": True, "purl": None, "direct": True, "dev": d["dev"], "locations": [d["file"]],
                          "licenses": [], "source_tool": ["manifest"], "found_by": "guardian-manifest-parser",
                          "manifest": {"file": d["file"], "line": d["line"], "spec": d["spec"]}, "introduced_via": None}
    for c in comps.values():
        if c["direct"] is None and directs:
            eco_has = any(k[0] == c["ecosystem"] for k in directs)
            if eco_has:
                c["direct"] = False  # its ecosystem's root manifest was parsed and it is not listed there
    return sorted(comps.values(), key=lambda c: (c["ecosystem"], c["name"].lower(), c["version"] or "")), rels


def _project_ids(src: Path) -> set:
    out = set()
    try:
        j = json.loads((src / "package.json").read_text(encoding="utf-8"))
        out.add(("npm", norm_name("npm", j.get("name", "")), j.get("version")))
    except (OSError, ValueError):
        pass
    try:
        t = tomllib.loads((src / "pyproject.toml").read_text(encoding="utf-8"))
        for name, ver in ((t.get("project", {}).get("name"), t.get("project", {}).get("version")),
                          (t.get("tool", {}).get("poetry", {}).get("name"), t.get("tool", {}).get("poetry", {}).get("version"))):
            if name:
                out.add(("pypi", norm_name("pypi", name), ver))
    except (OSError, ValueError):
        pass
    return out


def _v1_components(run: Path) -> dict:
    g = json.loads((run / "graph.json").read_text(encoding="utf-8"))
    out = {}
    for n in g["nodes"]:
        if n.get("kind") == "pkg" and n.get("purl"):
            k = norm_purl(n["purl"])
            prev = out.get(k)
            if not prev or (n.get("direct") and not prev.get("direct")):
                out[k] = n
    return out


def run_sbom(ws: Workspace, opts: dict) -> dict:
    out = ws.stage_dir("sbom")
    ing = ws.read("ingest") or {}
    syft_meta = run_syft(ws, out)
    syft = json.loads((out / "syft.json").read_text(encoding="utf-8"))
    directs = direct_deps(ws.src, ing)
    comps, rels = components_from_syft(syft, ws.src, directs)
    selfs = _project_ids(ws.src)
    if selfs:  # the analysed project itself is not one of its dependencies
        drop = {c["id"] for c in comps if (c["ecosystem"], norm_name(c["ecosystem"], c["name"]), c["version"]) in selfs}
        comps = [c for c in comps if c["id"] not in drop]
        rels = [r for r in rels if r["from"] not in drop and r["to"] not in drop]
    (out / "relationships.json").write_text(json.dumps(rels), encoding="utf-8")

    v1 = {"status": "not-applicable", "reason": "no package-lock.json at the repo root"}
    cross = None
    if bridge.has_npm_lock(ws):
        offline = os.environ.get("GUARDIAN_OFFLINE") == "1" or bool(opts.get("offline"))
        run = bridge.scan(ws, offline=offline)
        shutil.copy2(run / "sbom.head.cdx.json", out / "v1.cdx.json")
        v1c = _v1_components(run)
        syft_npm = {c["id"] for c in comps if c["ecosystem"] == "npm" and c["version"]}
        for c in comps:
            n = v1c.get(c["id"])
            if n:
                c["direct"], c["dev"] = bool(n.get("direct")), bool(n.get("dev"))
                c["source_tool"] = sorted(set(c["source_tool"]) | {"v1"})
                c["lock"] = {"file": "package-lock.json", "line": n.get("lockLine"), "key": n.get("id")}
        only_v1 = sorted(set(v1c) - syft_npm)
        only_syft = sorted(syft_npm - set(v1c))
        cross = {"syft_npm": len(syft_npm), "v1_npm_unique": len(v1c),
                 "v1_npm_installs": sum(1 for n in json.loads((run / "graph.json").read_text(encoding="utf-8"))["nodes"]
                                        if n.get("kind") == "pkg"),
                 "agree": len(syft_npm & set(v1c)), "only_v1": only_v1[:200], "only_syft": only_syft[:200],
                 "only_v1_count": len(only_v1), "only_syft_count": len(only_syft),
                 "explanation": "v1 counts every installed copy in package-lock.json (npm nests the same "
                                "name@version in several node_modules folders); Syft lists each name@version once. "
                                "Packages only one side reports are listed so a human can check them."}
        v1 = {"status": "ran", "run": ws.rel(run), "components": len(v1c)}

    eco_counts = collections.Counter(c["ecosystem"] for c in comps)
    lic = collections.Counter(x for c in comps for x in (c["licenses"] or ["(none declared)"]))
    totals = {"components": len(comps), "ecosystems": dict(eco_counts),
              "direct": sum(1 for c in comps if c["direct"] is True),
              "transitive": sum(1 for c in comps if c["direct"] is False),
              "direct_unknown": sum(1 for c in comps if c["direct"] is None),
              "dev": sum(1 for c in comps if c["dev"] is True), "unpinned": sum(1 for c in comps if c["unpinned"]),
              "licenses": len([k for k in lic if k != "(none declared)"])}
    result = {"components": comps, "totals": totals, "licenses": lic.most_common(30),
              "tools": {"syft": {"status": "ran", **syft_meta}, "v1_npm": v1}, "crosscheck": cross,
              "files": {"syft_json": ws.rel(out / "syft.json"), "syft_cdx": ws.rel(out / "syft.cdx.json"),
                        "syft_spdx": ws.rel(out / "syft.spdx.json"),
                        "v1_cdx": ws.rel(out / "v1.cdx.json") if (out / "v1.cdx.json").exists() else None,
                        "relationships": ws.rel(out / "relationships.json")}}
    ws.write("sbom", result)
    return {k: totals[k] for k in ("components", "direct", "transitive", "unpinned")} | {
        "ecosystems": len(eco_counts), "syft": syft_meta["version"], "v1_npm": v1["status"]}
