"""Reachability from the application's own source code (never node_modules), deterministic.

Tiers (docs/research/04 section 2.1):
  R0  no first-party file imports the package                         value 0.1
  R1  the package is imported (or, for a transitive package, the      value 0.5
      direct dependency that brings it in is imported)
  R2  a member the app uses on the package is named in the advisory   value 0.8
  R3  that member is used on a line that also reads request data      value 1.0
      (req.body / req.query / req.params / req.cookies / req.headers / req.files)
  unknown  the package is not imported, but its name appears as a string literal in app code
           (libraries such as ORMs load drivers by name), or there is no path from the app.

Every tier above R0 carries a witness (file:line excerpt). All tiers are graded `heuristic`:
dynamic require(variable) and indirect calls defeat a text scan, and transitive tiers do not
analyse what the parent library does with its dependency (capped at R1).
"""

from __future__ import annotations

import re
from pathlib import Path

TIER_VALUE = {"R0": 0.1, "R1": 0.5, "R2": 0.8, "R3": 1.0}
_EXCLUDE = re.compile(r"(^|/)(node_modules|public|vendor|tests?|__tests__|\.github|guardian|coverage)/|\.(spec|test)\.[cm]?js$")
_REQ = re.compile(r"\breq\.(body|query|params|cookies|headers|files)\b")
_REQUIRE_BIND = re.compile(r"(?:var|let|const)\s+(\w+)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)(?:\s*\.\s*(\w+))?")
_REQUIRE_DESTR = re.compile(r"(?:var|let|const)\s*\{([^}]*)\}\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)")
_REQUIRE_ANY = re.compile(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)")
_IMPORT = re.compile(r"import\s+(?:(\w+)|\*\s+as\s+(\w+)|\{([^}]*)\})\s+from\s+['\"]([^'\"]+)['\"]")
_GENERIC = {"then", "call", "apply", "bind", "length", "prototype", "toString", "default", "constructor"}
NODE_BUILTINS = {
    "assert", "buffer", "child_process", "cluster", "crypto", "dgram", "dns", "events", "fs", "http", "http2",
    "https", "net", "os", "path", "process", "querystring", "readline", "stream", "string_decoder", "timers",
    "tls", "tty", "url", "util", "v8", "vm", "worker_threads", "zlib", "module", "perf_hooks", "async_hooks",
}


def package_of(spec: str) -> str | None:
    """'pkg/sub' -> 'pkg'; '@scope/a/b' -> '@scope/a'; relative paths and builtins -> None."""
    if spec.startswith((".", "/", "node:")):
        return None
    parts = spec.split("/")
    name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
    return None if name in NODE_BUILTINS else name


def app_files(src: Path) -> list[Path]:
    out = []
    for p in sorted(src.rglob("*")):
        rel = p.relative_to(src).as_posix()
        if p.is_file() and p.suffix in (".js", ".mjs", ".cjs", ".ts") and not _EXCLUDE.search(rel):
            out.append(p)
    return out


def _site(src: Path, f: Path, i: int, line: str) -> dict:
    return {"file": f.relative_to(src).as_posix(), "line": i, "excerpt": line.strip()[:200],
            "request_data": bool(_REQ.search(line))}


def scan(src: Path, candidate_names: set[str] | None = None) -> dict:
    """Import scan of first-party code.

    Returns {"files": [...], "imports": {pkg: {"sites": [...], "members": {m: [sites]}}},
             "strings": {pkg: [sites]}, "scripts": {pkg: "script text"}}
    """
    files = app_files(src)
    imports: dict[str, dict] = {}
    texts = {f: f.read_text(encoding="utf-8", errors="replace").splitlines() for f in files}

    def entry(pkg):
        return imports.setdefault(pkg, {"sites": [], "members": {}})

    for f, lines in texts.items():
        bindings: dict[str, str] = {}   # identifier -> package (namespace binding)
        named: dict[str, str] = {}      # identifier -> package (a specific member)
        for i, line in enumerate(lines, 1):
            for m in _REQUIRE_ANY.finditer(line):
                pkg = package_of(m.group(1))
                if pkg:
                    entry(pkg)["sites"].append(_site(src, f, i, line))
            for m in _REQUIRE_BIND.finditer(line):
                pkg = package_of(m.group(2))
                if not pkg:
                    continue
                if m.group(3):  # var exec = require('x').exec
                    named[m.group(1)] = pkg
                    entry(pkg)["members"].setdefault(m.group(3), []).append(_site(src, f, i, line))
                else:
                    bindings[m.group(1)] = pkg
            for m in _REQUIRE_DESTR.finditer(line):
                pkg = package_of(m.group(2))
                for name in filter(None, (s.split(":")[0].strip() for s in m.group(1).split(","))):
                    if pkg:
                        named[name] = pkg
            for m in _IMPORT.finditer(line):
                pkg = package_of(m.group(4))
                if not pkg:
                    continue
                entry(pkg)["sites"].append(_site(src, f, i, line))
                if m.group(1) or m.group(2):
                    bindings[m.group(1) or m.group(2)] = pkg
                for name in filter(None, (s.split(" as ")[-1].strip() for s in (m.group(3) or "").split(","))):
                    named[name] = pkg
        # member uses: binding.member  /  named member called
        for i, line in enumerate(lines, 1):
            if _REQUIRE_ANY.search(line) or line.lstrip().startswith("import "):
                continue
            for b, pkg in bindings.items():
                for m in re.finditer(r"(?<![\w$.])" + re.escape(b) + r"\s*\.\s*([A-Za-z_$][\w$]*)", line):
                    entry(pkg)["members"].setdefault(m.group(1), []).append(_site(src, f, i, line))
            for n, pkg in named.items():
                if re.search(r"(?<![\w$.])" + re.escape(n) + r"\s*\(", line):
                    entry(pkg)["members"].setdefault(n, []).append(_site(src, f, i, line))

    strings: dict[str, list] = {}
    for name in candidate_names or ():
        if name in imports:
            continue
        pat = re.compile(r"['\"]" + re.escape(name) + r"['\"]")
        for f, lines in texts.items():
            for i, line in enumerate(lines, 1):
                if pat.search(line) and not _REQUIRE_ANY.search(line):
                    strings.setdefault(name, []).append(_site(src, f, i, line))

    scripts = {}
    pj = src / "package.json"
    if pj.exists():
        import json
        s = json.loads(pj.read_text(encoding="utf-8")).get("scripts", {})
        for name in candidate_names or ():
            hits = [f"{k}: {v}" for k, v in s.items() if re.search(r"(^|[\s;&|(])" + re.escape(name) + r"(\s|$)", v)]
            if hits:
                scripts[name] = hits[0]
    return {"files": [f.relative_to(src).as_posix() for f in files], "imports": imports,
            "strings": strings, "scripts": scripts}


def _words(text: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_$][\w$]{3,}", text or ""))


def _quote(text: str, word: str) -> str:
    for sent in re.split(r"(?<=[.!?])\s+|\n+", text or ""):
        if re.search(r"\b" + re.escape(word) + r"\b", sent):
            return sent.strip()[:240]
    return word


def package_tier(name: str, scan_result: dict) -> dict:
    """Tier for a package imported (or not) directly by the app, ignoring advisories."""
    imp = scan_result["imports"].get(name)
    if imp and imp["sites"]:
        return {"tier": "R1", "grade": "heuristic", "witness": imp["sites"][:3],
                "note": f"imported by first-party code ({len(imp['sites'])} site(s))"}
    if name in scan_result["scripts"]:
        return {"tier": "R1", "grade": "heuristic", "witness": [{"file": "package.json", "line": None,
                "excerpt": scan_result["scripts"][name], "request_data": False}],
                "note": "invoked by an npm script (runs as a tool, not imported)"}
    if name in scan_result["strings"]:
        return {"tier": "unknown", "grade": "unknown", "witness": scan_result["strings"][name][:3],
                "note": "not imported, but named as a string in app code: may be loaded by another library"}
    return {"tier": "R0", "grade": "heuristic", "witness": [],
            "note": f"no import found in {len(scan_result['files'])} first-party file(s)"}


def tier_for_vulnerability(node: dict, nodes: dict, advisory_text: str, scan_result: dict) -> dict:
    """Reachability tier of one vulnerable install path."""
    path = node.get("path")
    if not path:
        return {"tier": "unknown", "grade": "unknown", "witness": [], "note": "no dependency path from the app"}
    if not node.get("direct"):
        parent = nodes[path[1]]
        pt = package_tier(parent["name"], scan_result)
        if pt["tier"] in ("R1", "R2", "R3"):
            return {"tier": "R1", "grade": "heuristic", "witness": pt["witness"][:1],
                    "note": f"transitive: brought in by {parent['name']}@{parent['version']}, which the app uses; "
                            "whether that library calls the vulnerable code is not analysed (capped at R1)"}
        return {**pt, "note": f"transitive via {parent['name']}@{parent['version']}: " + pt["note"]}
    base = package_tier(node["name"], scan_result)
    if base["tier"] != "R1" or node["name"] not in scan_result["imports"]:
        return base
    words = _words(advisory_text)
    members = scan_result["imports"][node["name"]]["members"]
    hits = {m: sites for m, sites in members.items() if m in words and m not in _GENERIC}
    if not hits:
        used = ", ".join(sorted(members)[:8]) or "none"
        return {**base, "note": base["note"] + f"; members used ({used}) are not named in the advisory"}
    sites = [s for m in sorted(hits) for s in hits[m]]
    req = [s for s in sites if s["request_data"]]
    tier = "R3" if req else "R2"
    m0 = min(hits)
    return {"tier": tier, "grade": "heuristic", "witness": (req or sites)[:3], "symbols": sorted(hits),
            "advisory_quote": _quote(advisory_text, m0),
            "note": f"advisory names `{', '.join(sorted(hits))}`, which the app calls"
                    + (" on a line that reads request data" if req else "")}
