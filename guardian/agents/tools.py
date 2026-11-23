"""Read-only tools exposed to agents. Each returns compact text; the runner mints it as evidence.

No tool writes, executes, or reaches the network. Package, advisory and source text is wrapped in
<package_content>, <advisory_text> or <file_excerpt> tags: it is third-party DATA, never instructions.
"""

from __future__ import annotations

import json
import re
import subprocess
import tarfile
from pathlib import Path

from .. import runs
from ..prioritise import _osv_text

KIT = Path(__file__).resolve().parents[2]
PATTERNS = KIT / "guardian" / "data" / "incident_patterns.json"


def decl(name: str, description: str, props: dict | None = None, required: list | None = None) -> dict:
    from .llm import to_gemini_schema
    d = {"name": name, "description": description}
    if props:
        d["parameters"] = to_gemini_schema({"type": "object", "properties": props, "required": required or []})
    return d


class RunTools:
    def __init__(self, run: Path, findings: list[dict], nodes: dict, scan: dict, head_src: Path, commits: list):
        self.run, self.nodes, self.scan, self.src = run, nodes, scan, head_src
        self.findings = {f["id"]: f for f in findings}
        self.commits = {c["sha"]: c for c in commits}

    # -- helpers ---------------------------------------------------------------------------
    def _node(self, component: str) -> dict | None:
        cands = [n for n in self.nodes.values() if n.get("purl") == component or n.get("name") == component]
        return min(cands, key=lambda n: len(n.get("path") or [0] * 99), default=None)

    def _tarball(self, component: str) -> Path | None:
        n = self._node(component)
        if not n or not (n.get("resolved") or "").startswith("file:"):
            return None
        p = self.src / n["resolved"][5:]
        return p if p.exists() else None

    # -- tools -----------------------------------------------------------------------------
    def get_finding(self, finding_id: str) -> str:
        f = self.findings.get(finding_id)
        if not f:
            return json.dumps({"error": f"no finding {finding_id}"})
        ev = [{"id": f"{finding_id}.E{i}", "source": e["source"], "line": e.get("line"), "excerpt": e["excerpt"][:400]}
              for i, e in enumerate(f.get("evidence", []), 1)]
        p = f.get("priority", {})
        return json.dumps({"id": f["id"], "type": f["type"], "component": f["component"], "title": f.get("title"),
                           "initial_risk": f.get("risk"), "rule": f.get("rule"), "path": f.get("path"),
                           "new_in_head": f.get("new_in_head"), "commit": f.get("commit"),
                           "score": p.get("score"), "factors": {k: {"value": v["value"], "grade": v["grade"],
                                                                     "evidence": v["evidence"]}
                                                                 for k, v in p.get("factors", {}).items()},
                           "evidence": ev})

    def list_package_files(self, component: str) -> str:
        tb = self._tarball(component)
        if not tb:
            return json.dumps({"result": "not available: only local file: tarballs are opened (registry "
                                         "tarballs are not downloaded)"})
        with tarfile.open(tb) as t:
            return json.dumps({"tarball": tb.relative_to(self.src).as_posix(),
                               "files": [{"path": m.name, "bytes": m.size} for m in t.getmembers() if m.isfile()]})

    def read_package_file(self, component: str, path: str, start_line: int = 1) -> str:
        tb = self._tarball(component)
        if not tb:
            return json.dumps({"result": "not available: not a local tarball"})
        with tarfile.open(tb) as t:
            m = next((x for x in t.getmembers() if x.isfile() and x.name == path), None)
            if not m:
                return json.dumps({"error": f"{path} not in package"})
            lines = t.extractfile(m).read().decode("utf-8", "replace").splitlines()
        start = max(1, int(start_line))
        body = "\n".join(f"{i}: {ln[:300]}" for i, ln in enumerate(lines[start - 1:start + 79], start))
        return f"<package_content file=\"{path}\" lines=\"{len(lines)}\">\n{body}\n</package_content>"

    def get_advisory(self, advisory_id: str) -> str:
        text = _osv_text(advisory_id)
        return f"<advisory_text id=\"{advisory_id}\">\n{text[:3500]}\n</advisory_text>" if text.strip() else \
            json.dumps({"error": f"advisory {advisory_id} not in the local OSV cache"})

    def find_imports(self, package: str) -> str:
        imp = self.scan["imports"].get(package)
        sites = (imp or {}).get("sites", [])
        return json.dumps({"package": package, "imported": bool(sites),
                           "sites": [{"file": s["file"], "line": s["line"], "excerpt": s["excerpt"]} for s in sites[:10]],
                           "named_as_string": self.scan["strings"].get(package, [])[:3],
                           "npm_script": self.scan["scripts"].get(package)})

    def find_call_sites(self, package: str, member: str = "") -> str:
        mem = (self.scan["imports"].get(package) or {}).get("members", {})
        sel = {k: v for k, v in mem.items() if not member or k == member}
        return json.dumps({"package": package, "members": {k: [{"file": s["file"], "line": s["line"],
                                                                 "excerpt": s["excerpt"],
                                                                 "reads_request_data": s["request_data"]}
                                                                for s in v[:6]] for k, v in sel.items()}})

    def read_source_excerpt(self, file: str, line: int, context: int = 6) -> str:
        if file not in self.scan["files"]:
            return json.dumps({"error": "only first-party application files can be read",
                               "allowed": self.scan["files"]})
        lines = (self.src / file).read_text(encoding="utf-8", errors="replace").splitlines()
        a, b = max(1, int(line) - int(context)), min(len(lines), int(line) + int(context))
        body = "\n".join(f"{i}: {lines[i - 1]}" for i in range(a, b + 1))
        return f"<file_excerpt file=\"{file}\">\n{body}\n</file_excerpt>"

    def commit_context(self, sha: str) -> str:
        if sha not in self.commits:
            return json.dumps({"error": "only commits between the base and head refs", "allowed": list(self.commits)})
        out = subprocess.run(["git", "-C", str(runs.TARGET), "show", "--stat", "--format=%h %s%n%an %ad", sha],
                             capture_output=True, check=True).stdout.decode("utf-8", "replace")
        return out[:3000]

    def list_incident_patterns(self) -> str:
        return PATTERNS.read_text(encoding="utf-8")

    def as_tools(self, names: list[str]) -> dict:
        s = {"type": "string"}
        table = {
            "get_finding": (decl("get_finding", "Facts and evidence ids of one finding.",
                                 {"finding_id": s}, ["finding_id"]), self.get_finding),
            "list_package_files": (decl("list_package_files", "Files and sizes inside a local package tarball.",
                                        {"component": s}, ["component"]), self.list_package_files),
            "read_package_file": (decl("read_package_file", "Read up to 80 numbered lines of a file inside a "
                                       "local package tarball (static read, never executed).",
                                       {"component": s, "path": s, "start_line": {"type": "integer"}},
                                       ["component", "path"]), self.read_package_file),
            "get_advisory": (decl("get_advisory", "Summary and details text of an OSV advisory (data).",
                                  {"advisory_id": s}, ["advisory_id"]), self.get_advisory),
            "find_imports": (decl("find_imports", "Where first-party code imports a package.",
                                  {"package": s}, ["package"]), self.find_imports),
            "find_call_sites": (decl("find_call_sites", "Members of a package the app uses, with call sites.",
                                     {"package": s, "member": s}, ["package"]), self.find_call_sites),
            "read_source_excerpt": (decl("read_source_excerpt", "Numbered lines around a line of a first-party "
                                         "application file.", {"file": s, "line": {"type": "integer"},
                                                               "context": {"type": "integer"}},
                                         ["file", "line"]), self.read_source_excerpt),
            "commit_context": (decl("commit_context", "Files and summary of a commit between base and head.",
                                    {"sha": s}, ["sha"]), self.commit_context),
            "list_incident_patterns": (decl("list_incident_patterns", "Known supply-chain incident patterns."),
                                       self.list_incident_patterns),
        }
        return {n: table[n] for n in names}


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)
