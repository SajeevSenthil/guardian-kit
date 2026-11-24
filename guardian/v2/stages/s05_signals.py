"""Stage 5 - Supply-chain signals: risks without a CVE (manifests, Dockerfiles, CI; v1 rules for npm).

Page: guardian/api/static/pages/s05_signals.js · Output: stages/signals/result.json
"""

from __future__ import annotations

import collections
import json
import re
from pathlib import Path

from ..identity import norm_purl
from ..workspace import Workspace

WHY = {
    "unpinned_version": "Without an exact version, every install can pull a different (possibly hijacked) release; "
                        "the scanners cannot match it against advisories either.",
    "non_registry_source": "Code fetched from a git URL, tarball URL or local path bypasses the registry's integrity "
                           "and audit trail.",
    "custom_index": "An extra or custom package index allows dependency confusion: a public package with your "
                    "internal name can win the resolution.",
    "no_lockfile": "Without a lockfile, transitive versions float: the build you test is not the build you ship.",
    "docker_latest": "A floating base image tag changes underneath you; pin a version and digest.",
    "docker_curl_pipe": "Piping a downloaded script into a shell runs unreviewed remote code during the build.",
    "ci_unpinned_action": "A tag can be moved to malicious code (tj-actions, 2025); pin third-party actions to a commit SHA.",
    "ci_write_all": "Every step (and every action) gets a token that can push code and releases.",
    "ci_curl_pipe": "Remote script executed in CI with the job's credentials.",
    "ci_pull_request_target": "pull_request_target runs with secrets; checking out the PR's code lets a fork run it.",
}


def _lines(p: Path):
    try:
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def repo_signals(src: Path, ing: dict) -> list[dict]:
    out = []

    def add(rule, title, file, line, excerpt, risk, category, grade="verified", component=None):
        out.append({"rule": rule, "title": title, "category": category, "risk": risk, "grade": grade,
                    "component": component or file, "component_id": None,
                    "evidence": [{"file": file, "line": line, "excerpt": excerpt.strip()[:200]}], "why": WHY[rule], "source": "v2-rules"})

    for f in ing.get("dockerfiles") or []:
        for i, ln in enumerate(_lines(src / f), 1):
            m = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", ln, re.I)
            if m and "@sha256:" not in m.group(1) and m.group(1).lower() != "scratch":
                img = m.group(1)
                tag = img.rsplit(":", 1)[1] if ":" in img.split("/")[-1] else None
                if tag in (None, "latest"):
                    add("docker_latest", f"base image {img} is floating ({'no tag' if not tag else ':latest'})", f, i, ln, "medium", "container")
            if re.search(r"(curl|wget)[^|\n]*\|\s*(ba|z)?sh\b", ln):
                add("docker_curl_pipe", "Dockerfile pipes a downloaded script into a shell", f, i, ln, "high", "container")
    for f in ing.get("workflows") or []:
        lines = _lines(src / f)
        text = "\n".join(lines)
        for i, ln in enumerate(lines, 1):
            m = re.search(r"uses:\s*([\w.\-]+/[\w.\-/]+)@([\w.\-/]+)", ln)
            if m and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)) and not m.group(1).startswith(("actions/", "github/")):
                add("ci_unpinned_action", f"third-party action {m.group(1)}@{m.group(2)} is not pinned to a commit", f, i, ln,
                    "medium", "ci", component=f"{m.group(1)}@{m.group(2)}")
            if re.search(r"permissions:\s*write-all", ln):
                add("ci_write_all", "workflow token has write-all permissions", f, i, ln, "high", "ci")
            if re.search(r"(curl|wget)[^|\n]*\|\s*(ba|z)?sh\b", ln):
                add("ci_curl_pipe", "workflow pipes a remote script into a shell", f, i, ln, "high", "ci")
        if "pull_request_target" in text and re.search(r"actions/checkout", text) and re.search(r"github\.event\.pull_request\.head", text):
            i = next(k for k, ln in enumerate(lines, 1) if "pull_request_target" in ln)
            add("ci_pull_request_target", "pull_request_target workflow checks out the pull request's code", f, i,
                lines[i - 1], "high", "ci")
    return out


def manifest_signals(src: Path, ing: dict, comps: list[dict]) -> list[dict]:
    out = []

    def add(rule, title, file, line, excerpt, risk, grade="verified", component=None, component_id=None):
        out.append({"rule": rule, "title": title, "category": "manifest", "risk": risk, "grade": grade,
                    "component": component or file, "component_id": component_id,
                    "evidence": [{"file": file, "line": line, "excerpt": (excerpt or "").strip()[:200]}],
                    "why": WHY[rule], "source": "v2-rules"})

    for c in comps:
        if not c.get("version") and c["ecosystem"] not in ("github", "github-action"):
            m = c.get("manifest") or {}
            add("unpinned_version", f"{c['name']} has no exact version ({c.get('declared') or 'any'})",
                m.get("file") or (c["locations"] or [""])[0], m.get("line"), f"{c['name']} {c.get('declared') or ''}",
                "low", component=c["name"], component_id=c["id"])
    for eco, d in (ing.get("ecosystems") or {}).items():
        for f in d["manifests"]:
            p = src / f
            lines = _lines(p)
            if Path(f).name.startswith("requirements") or Path(f).name in ("pip.conf", "pip.ini"):
                for i, ln in enumerate(lines, 1):
                    s = ln.strip()
                    if re.match(r"^(-i|--index-url|--extra-index-url)\b", s):
                        add("custom_index", "pip is told to use another package index", f, i, s, "medium")
                    elif re.match(r"^(-e\s+)?(git\+|hg\+|svn\+|https?://|file:)", s) or " @ " in s and "://" in s:
                        add("non_registry_source", "dependency installed from a URL or VCS, not the registry", f, i, s, "medium")
            if Path(f).name == "package.json":
                try:
                    j = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    j = {}
                for sec in ("dependencies", "devDependencies", "optionalDependencies"):
                    for n, v in (j.get(sec) or {}).items():
                        if re.match(r"^(git\+|git:|github:|https?://|file:|link:)|^[\w-]+/[\w.-]+(#.*)?$", str(v)):
                            ln = next((k for k, x in enumerate(lines, 1) if f'"{n}"' in x), None)
                            add("non_registry_source", f"{n} is installed from {v}", f, ln, f'"{n}": "{v}"', "medium", component=n)
        if d.get("pinned") in ("no lockfile", "partly or not pinned") and eco not in ("golang",):
            add("no_lockfile", f"{eco}: no lockfile ({d.get('pinned')})", (d["manifests"] or ["?"])[0], None,
                ", ".join(d["manifests"][:3]), "low", grade="verified", component=eco)
    for f in (".npmrc", "pip.conf", ".pypirc"):
        for i, ln in enumerate(_lines(src / f), 1):
            if re.match(r"^\s*(registry|index-url|extra-index-url)\s*=", ln):
                add("custom_index", f"{f} points at a custom registry", f, i, ln, "medium")
    return out


def run_signals(ws: Workspace, opts: dict) -> dict:
    ing, sb = ws.read("ingest") or {}, ws.read("sbom") or {}
    sigs = []
    v1_types = set()
    if ws.v1_run and (ws.v1_run / "findings.json").exists():
        fj = json.loads((ws.v1_run / "findings.json").read_text(encoding="utf-8"))
        for f in (fj["findings"] if isinstance(fj, dict) else fj):
            if f["type"] == "known_vulnerability":
                continue
            v1_types.add(f["type"])
            sigs.append({"rule": f["type"], "title": f.get("title"), "category": f.get("category"), "risk": f.get("risk"),
                         "grade": f.get("claim", "verified"), "component": f.get("component"),
                         "component_id": norm_purl(f["component"]) if str(f.get("component", "")).startswith("pkg:") else None,
                         "evidence": [{"file": (e.get("source") or "").split(" @")[0], "line": e.get("line"),
                                       "excerpt": e.get("excerpt")} for e in f.get("evidence", [])],
                         "why": f.get("rule"), "source": "v1", "v1_id": f["id"]})
    # generic repo rules: v1 already checks Dockerfiles and workflows for npm repos, so run ours only otherwise
    if not ws.v1_run:
        sigs += repo_signals(ws.src, ing)
    sigs += manifest_signals(ws.src, ing, sb.get("components") or [])
    for i, s in enumerate(sigs, 1):
        s["id"] = f"S{i:03d}"
    cats = collections.Counter(s["category"] for s in sigs)
    risk = collections.Counter(s["risk"] for s in sigs)
    result = {"signals": sigs, "rows": sigs, "counts": {"total": len(sigs), "by_category": dict(cats), "by_risk": dict(risk)},
              "sources": {"v1_npm_rules": "ran" if ws.v1_run else "not-applicable", "v2_repo_rules": "not-needed (v1 ran)" if ws.v1_run else "ran",
                          "v2_manifest_rules": "ran", "deps.dev_scorecard": "not-run (not built yet)"},
              "note": "Signals are risks without a CVE, found by fixed rules on files (verified facts) or heuristics "
                      "(labelled). A package describing itself as harmless is not evidence."}
    ws.write("signals", result)
    return {"signals": len(sigs), "high": risk.get("high", 0) + risk.get("critical", 0), "categories": len(cats)}
