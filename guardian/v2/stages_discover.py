"""Stages 1-3 (M1): ingest, sbom, graph. Any ecosystem; tools first (Syft, deps.dev), v1 npm layer on top.

Nothing here runs code from the analysed repo: git clone with hooks disabled, Syft (reads files),
deps.dev (HTTP API), the v1 fast path (reads the lockfile via git archive).
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..config import load as load_cfg
from . import bridge
from .tools import find_tool, tool_version
from .workspace import KIT, Workspace

SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "env", ".tox", "__pycache__", "vendor", "dist", "build",
             "target", ".mypy_cache", ".pytest_cache", "site-packages", ".next", "bower_components"}
MANIFESTS = {  # ecosystem -> (manifest patterns, lockfile patterns)
    "npm": (["package.json"], ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]),
    "pypi": (["requirements*.txt", "pyproject.toml", "Pipfile", "setup.cfg", "setup.py"],
             ["poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock"]),
    "golang": (["go.mod"], ["go.sum"]),
    "maven": (["pom.xml", "build.gradle", "build.gradle.kts"], ["gradle.lockfile"]),
    "cargo": (["Cargo.toml"], ["Cargo.lock"]),
    "gem": (["Gemfile", "*.gemspec"], ["Gemfile.lock"]),
    "composer": (["composer.json"], ["composer.lock"]),
    "nuget": (["*.csproj", "packages.config"], ["packages.lock.json"]),
}
DEPSDEV_SYSTEM = {"npm": "npm", "pypi": "pypi", "golang": "go", "maven": "maven", "cargo": "cargo", "nuget": "nuget"}
SYFT_EXCLUDES = ["./**/node_modules/**", "./**/.git/**", "./**/.venv/**", "./**/venv/**", "./**/__pycache__/**"]


def _cfg_sources() -> dict:
    return load_cfg().get("sources", {})


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 600, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "GCM_INTERACTIVE": "never", **(extra_env or {})}
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env,
                          encoding="utf-8", errors="replace")


def _git(*args: str, cwd: Path | None = None, timeout: int = 600) -> str:
    r = _run(["git", *args], cwd=cwd, timeout=timeout)
    if r.returncode:
        raise RuntimeError(f"git {args[0]} failed: {(r.stderr or r.stdout).strip().splitlines()[-1:]}")
    return r.stdout


# ---------------------------------------------------------------- ingest
def check_git_url(url: str) -> tuple[str, str]:
    """Allow-list check. Returns (host, path). Raises ValueError with the setting to change."""
    u = urllib.parse.urlsplit(url.strip())
    if u.scheme != "https":
        raise ValueError("only https:// git URLs are accepted")
    if u.username or u.password or "@" in u.netloc:
        raise ValueError("credentials in the URL are not accepted")
    host = (u.hostname or "").lower()
    parts = [p for p in u.path.split("/") if p]
    if not host or len(parts) < 2:
        raise ValueError("expected https://<host>/<owner>/<repo>")
    owner, repo = parts[0].lower(), parts[1].lower().removesuffix(".git")
    allow = [a.lower().strip("/") for a in _cfg_sources().get("allow", [])]
    if not any(a in (host, f"{host}/{owner}", f"{host}/{owner}/{repo}") for a in allow):
        raise ValueError(f"{host}/{owner} is not in guardian.toml [sources] allow "
                         f"(currently: {', '.join(allow) or 'empty'}). Only repositories you are authorised "
                         "to analyse may be added there.")
    return host, f"{owner}/{repo}"


def _dir_mb(p: Path) -> float:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) / 1e6


def _safe_unzip(zpath: Path, dest: Path, max_mb: float) -> None:
    dest = dest.resolve()
    with zipfile.ZipFile(zpath) as z:
        total = 0
        for info in z.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in name.split("/"):
                raise ValueError(f"unsafe path in zip: {info.filename}")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f"symlink in zip refused: {info.filename}")
            total += info.file_size
            if total > max_mb * 1e6:
                raise ValueError(f"zip expands beyond {max_mb} MB")
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if dest not in target.parents and target != dest:
                raise ValueError(f"unsafe path in zip: {info.filename}")
        z.extractall(dest)
    kids = [k for k in dest.iterdir()]
    if len(kids) == 1 and kids[0].is_dir():  # "repo-main/..." wrapper folder
        inner = kids[0]
        for k in inner.iterdir():
            shutil.move(str(k), str(dest / k.name))
        inner.rmdir()


def _snapshot_commit(src: Path) -> None:
    _git("init", "-q", cwd=src)
    _git("config", "core.autocrlf", "false", cwd=src)
    _git("add", "-A", cwd=src)
    _git("-c", "user.name=guardian", "-c", "user.email=guardian@localhost", "commit", "-q", "--allow-empty",
         "-m", "guardian snapshot", cwd=src)


def _fetch_source(ws: Workspace) -> None:
    m = ws.meta
    kind, value, ref = m["source"]["kind"], m["source"]["value"], m.get("ref")
    max_mb = float(_cfg_sources().get("max_mb", 200))
    if ws.src.exists():
        shutil.rmtree(ws.src, onerror=lambda f, p, e: (os.chmod(p, 0o700), f(p)))
    nohooks = ws.dir / ".nohooks"
    nohooks.mkdir(exist_ok=True)
    safe = ["-c", f"core.hooksPath={nohooks}", "-c", "core.autocrlf=false", "-c", "protocol.allow=never",
            "-c", "protocol.https.allow=always", "-c", "protocol.file.allow=always"]
    if kind == "git":
        check_git_url(value)
        _git(*safe, "clone", "-q", "--depth", "50", "--no-recurse-submodules", value, str(ws.src), timeout=900)
        if ref:
            try:
                _git("checkout", "-q", ref, cwd=ws.src)
            except RuntimeError:
                _git(*safe, "fetch", "-q", "--depth", "50", "origin", ref, cwd=ws.src, timeout=900)
                _git("checkout", "-q", "FETCH_HEAD", cwd=ws.src)
    elif kind == "zip":
        ws.src.mkdir(parents=True)
        _safe_unzip(Path(value), ws.src, max_mb)
        _snapshot_commit(ws.src)
    else:
        p = Path(value).expanduser().resolve()
        if not p.is_dir():
            raise ValueError(f"not a directory: {p}")
        if (p / ".git").exists():
            _git(*safe, "clone", "-q", "--no-hardlinks", "--no-recurse-submodules", str(p), str(ws.src), timeout=900)
            if ref:
                _git("checkout", "-q", ref, cwd=ws.src)
        else:
            shutil.copytree(p, ws.src, ignore=shutil.ignore_patterns(*SKIP_DIRS))
            _snapshot_commit(ws.src)
    mb = _dir_mb(ws.src)
    if mb > max_mb:
        raise ValueError(f"checkout is {mb:.0f} MB, above [sources] max_mb = {max_mb:.0f}")


def _walk(src: Path, limit: int = 60000):
    n = 0
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".") or d == ".github"]
        for f in filenames:
            n += 1
            if n > limit:
                return
            yield Path(dirpath) / f


def detect(src: Path) -> dict:
    eco: dict[str, dict] = {}
    dockerfiles, workflows = [], []
    for f in _walk(src):
        rel = f.relative_to(src).as_posix()
        name = f.name
        if name == "Dockerfile" or name.endswith(".Dockerfile") or name.startswith("Dockerfile."):
            dockerfiles.append(rel)
        if rel.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
            workflows.append(rel)
        for e, (mans, locks) in MANIFESTS.items():
            for kind, pats in (("manifests", mans), ("lockfiles", locks)):
                if any(Path(name).match(p) for p in pats):
                    eco.setdefault(e, {"manifests": [], "lockfiles": []})[kind].append(rel)
    for e, d in eco.items():
        d["pinned"] = _pinned(src, e, d)
    return {"ecosystems": eco, "dockerfiles": sorted(dockerfiles), "workflows": sorted(workflows)}


def _pinned(src: Path, eco: str, d: dict) -> str:
    if d["lockfiles"]:
        return "lockfile"
    if eco == "pypi":
        reqs = [m for m in d["manifests"] if m.split("/")[-1].startswith("requirements")]
        if reqs:
            lines = [ln for r in reqs for ln in _req_lines(src / r)]
            if lines and all("==" in ln for _, ln in lines):
                return "all pinned (==)"
            return "partly or not pinned"
    if eco == "golang":
        return "go.mod (minimal version selection)"
    return "no lockfile"


def run_ingest(ws: Workspace, opts: dict) -> dict:
    _fetch_source(ws)
    sha = _git("rev-parse", "HEAD", cwd=ws.src).strip()
    ref = ws.meta.get("ref") or _git("rev-parse", "--abbrev-ref", "HEAD", cwd=ws.src).strip()
    found = detect(ws.src)
    deep = bridge.has_npm_lock(ws)
    size = round(_dir_mb(ws.src), 1)
    ws.update(sha=sha, v1_run=None)
    eco = found["ecosystems"]
    notes = []
    if not eco:
        notes.append("No package manifests found: later stages will have nothing to analyse.")
    if "npm" in eco and not deep:
        notes.append("npm without a root package-lock.json: Syft lists what the manifests declare; the deep npm "
                     "layer (lockfile evidence, reachability) does not run.")
    result = {"source": ws.meta["source"], "ref": ref, "sha": sha, "size_mb": size, **found, "deep_npm": deep,
              "notes": notes, "consent": ws.meta.get("consent")}
    ws.write("ingest", result)
    ws.audit("ingest", source=ws.meta["source"]["value"], sha=sha)
    return {"ecosystems": sorted(eco), "sha": sha[:12], "size_mb": size, "deep_npm": deep,
            "manifests": sum(len(v["manifests"]) + len(v["lockfiles"]) for v in eco.values())}


# ---------------------------------------------------------------- manifests (direct dependencies)
def norm_name(eco: str, name: str) -> str:
    n = (name or "").strip().lower()
    return re.sub(r"[-_.]+", "-", n) if eco == "pypi" else n


def _req_lines(p: Path):
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for i, ln in enumerate(text.splitlines(), 1):
        s = ln.split("#", 1)[0].strip()
        if not s or s.startswith(("-", "git+", "http")) or "://" in s:
            continue
        yield i, s


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


def norm_version(eco: str, v: str | None) -> str | None:
    """Compare-only normalisation: PEP 440 treats 3.20 and 3.20.0 as the same release."""
    if not v:
        return v
    v = v.strip().lower().removeprefix("v") if eco != "golang" else v.strip()
    if eco == "pypi":
        v = re.sub(r"(\.0+)+$", "", v)
    return v


# ---------------------------------------------------------------- sbom
def purl_type(purl: str) -> str:
    m = re.match(r"pkg:([^/]+)/", purl or "")
    return m.group(1) if m else "unknown"


def norm_purl(purl: str) -> str:
    p = urllib.parse.unquote((purl or "").split("?")[0].split("#")[0]).lower()
    if p.startswith("pkg:pypi/"):
        body, _, ver = p[9:].partition("@")
        p = "pkg:pypi/" + re.sub(r"[-_.]+", "-", body) + ("@" + ver if ver else "")
    return p


def _comp_name(eco: str, a: dict) -> str:
    if eco == "maven":
        m = re.match(r"pkg:maven/([^@?]+)", urllib.parse.unquote(a.get("purl") or ""))
        if m:
            return m.group(1)
    if eco == "golang":
        return a.get("name", "")
    return a.get("name", "")


EXACT = re.compile(r"^v?\d+(\.\d+)*([.\-+][0-9A-Za-z.\-+]+)?$")


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


# ---------------------------------------------------------------- graph
def _cache_dir() -> Path:
    d = KIT / ".cache" / "depsdev"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _depsdev(url: str) -> dict | None:
    p = _cache_dir() / (hashlib.sha256(url.encode()).hexdigest()[:24] + ".json")
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))["data"]
    if os.environ.get("GUARDIAN_OFFLINE") == "1":
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "guardian"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None
    import datetime as dt
    p.write_text(json.dumps({"fetched": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), "url": url,
                             "data": data}), encoding="utf-8")
    return data


def depsdev_resolve(eco: str, name: str, version: str | None) -> dict | None:
    system = DEPSDEV_SYSTEM.get(eco)
    if not system:
        return None
    qn = urllib.parse.quote(name.replace("/", ":") if eco == "maven" else name, safe="")
    assumed = False
    if not version:
        pkg = _depsdev(f"https://api.deps.dev/v3/systems/{system}/packages/{qn}")
        vs = [v for v in (pkg or {}).get("versions", []) if v.get("isDefault")]
        if not vs:
            return None
        version, assumed = vs[0]["versionKey"]["version"], True
    data = _depsdev(f"https://api.deps.dev/v3/systems/{system}/packages/{qn}/versions/"
                    f"{urllib.parse.quote(version, safe='')}:dependencies")
    if not data or not data.get("nodes"):
        return None
    return {"version": version, "assumed": assumed, "nodes": data["nodes"], "edges": data.get("edges", []),
            "error": data.get("error")}


def _paths(adj: dict, root: str, k: int = 3, cap: int = 200000):
    """BFS depth + up to k shortest paths per node (over the shortest-path parent DAG)."""
    depth, parents = {root: 0}, collections.defaultdict(list)
    q = collections.deque([root])
    while q:
        u = q.popleft()
        for v in adj.get(u, ()):
            if v not in depth:
                depth[v] = depth[u] + 1
                parents[v].append(u)
                q.append(v)
            elif depth[v] == depth[u] + 1 and len(parents[v]) < k:
                parents[v].append(u)
    paths = {root: [[root]]}
    budget = cap
    for v in sorted(depth, key=depth.get):
        if v == root:
            continue
        acc = []
        for p in parents[v]:
            for pp in paths.get(p, []):
                acc.append(pp + [v])
                budget -= 1
                if len(acc) >= k or budget <= 0:
                    break
            if len(acc) >= k:
                break
        paths[v] = acc
    return depth, paths


def run_graph(ws: Workspace, opts: dict) -> dict:
    sb = ws.read("sbom")
    if not sb:
        raise RuntimeError("run the sbom stage first")
    ing = ws.read("ingest") or {}
    root = "root"
    nodes = {root: {"id": root, "name": Path(str(ing.get("source", {}).get("value", "project"))).name.removesuffix(".git")
                    or "project", "version": (ing.get("sha") or "")[:12], "ecosystem": "project", "kind": "root",
                    "direct": None, "dev": None}}
    for c in sb["components"]:
        nodes[c["id"]] = {"id": c["id"], "name": c["name"], "version": c["version"], "ecosystem": c["ecosystem"],
                          "kind": "pkg", "direct": c["direct"], "dev": c["dev"], "unpinned": c["unpinned"],
                          "licenses": c["licenses"], "purl": c["purl"], "in_sbom": True}
    edges: dict[tuple, dict] = {}

    def add_edge(a, b, source, kind="dependency", evidence=None):
        if a == b or a not in nodes or b not in nodes:
            return
        e = edges.setdefault((a, b), {"from": a, "to": b, "kind": kind, "sources": [], "evidence": []})
        if source not in e["sources"]:
            e["sources"].append(source)
        if evidence and evidence not in e["evidence"]:
            e["evidence"].append(evidence)

    # 1. root -> direct (manifest evidence)
    for c in sb["components"]:
        if c["direct"]:
            m = c.get("manifest") or {}
            ev = {"file": m.get("file") or (c["locations"] or [None])[0], "line": m.get("line"),
                  "excerpt": (f"{c['name']} {m.get('spec') or ''}").strip()}
            add_edge(root, c["id"], "manifest", "dev" if c["dev"] else "direct", ev)
    # 2. Syft relationships
    rel_path = ws.dir / sb["files"]["relationships"]
    rels = json.loads(rel_path.read_text(encoding="utf-8")) if rel_path.exists() else []
    for r in rels:
        add_edge(r["from"], r["to"], "syft", evidence={"file": r.get("file"), "line": None,
                                                       "excerpt": "Syft dependency-of relationship"})
    # 3. v1 npm edges with lockfile line evidence
    v1_status = "not-applicable"
    if ws.v1_run and (ws.v1_run / "graph.json").exists():
        g = json.loads((ws.v1_run / "graph.json").read_text(encoding="utf-8"))
        lock2id = {n["id"]: norm_purl(n["purl"]) for n in g["nodes"] if n.get("purl")}
        lock2id[""] = root
        lines = {n["id"]: n.get("lockLine") for n in g["nodes"]}
        for a, b in g["edges"]:
            ia, ib = lock2id.get(a), lock2id.get(b)
            if ia and ib:
                add_edge(ia, ib, "v1-lockfile", evidence={"file": "package-lock.json", "line": lines.get(b),
                                                          "excerpt": f'"{b}" (required by {"the project" if not a else a})'})
        v1_status = "ran"
    # 4. deps.dev for ecosystems whose transitive dependencies the files do not give
    has_out = collections.Counter(nodes[a]["ecosystem"] for (a, b) in edges if a != root)
    depsdev = {"status": "not-needed", "resolved": 0, "failed": 0, "assumed_versions": 0, "ecosystems": []}
    todo = [c for c in sb["components"] if c["direct"] and not has_out.get(c["ecosystem"])
            and c["ecosystem"] in DEPSDEV_SYSTEM]
    limit = int(_cfg_sources().get("max_depsdev_lookups", 150))
    if todo and not opts.get("no_depsdev"):
        depsdev["status"] = "ran" if os.environ.get("GUARDIAN_OFFLINE") != "1" else "cache-only (offline)"
        depsdev["ecosystems"] = sorted({c["ecosystem"] for c in todo})
        with ThreadPoolExecutor(8) as ex:
            res = list(ex.map(lambda c: (c, depsdev_resolve(c["ecosystem"], c["name"], c["version"])), todo[:limit]))
        depsdev["skipped_over_limit"] = max(0, len(todo) - limit)
        for c, r in res:
            if not r:
                depsdev["failed"] += 1
                nodes[c["id"]]["resolution"] = "not resolved"
                continue
            depsdev["resolved"] += 1
            depsdev["assumed_versions"] += r["assumed"]
            if r["assumed"]:
                nodes[c["id"]]["assumed_version"] = r["version"]
            idx = []
            for n in r["nodes"]:
                vk = n["versionKey"]
                if n.get("relation") == "SELF":
                    idx.append(c["id"])
                    continue
                nid = f"{c['ecosystem']}:{norm_name(c['ecosystem'], vk['name'])}@{vk['version']}"
                match = next((k for k, v in nodes.items() if v.get("ecosystem") == c["ecosystem"]
                              and norm_name(c["ecosystem"], v.get("name", "")) == norm_name(c["ecosystem"], vk["name"])
                              and norm_version(c["ecosystem"], v.get("version")) == norm_version(c["ecosystem"], vk["version"])),
                             None)
                if not match:
                    nodes[nid] = {"id": nid, "name": vk["name"], "version": vk["version"], "ecosystem": c["ecosystem"],
                                  "kind": "pkg", "direct": False, "dev": c["dev"], "unpinned": False, "licenses": [],
                                  "purl": None, "in_sbom": False, "resolved_by": "deps.dev"}
                idx.append(match or nid)
            for e in r["edges"]:
                a, b = idx[e["fromNode"]], idx[e["toNode"]]
                add_edge(a, b, "deps.dev", evidence={"file": None, "line": None,
                                                     "excerpt": f"deps.dev: requires {e.get('requirement', '')}".strip()})
    # 4b. packages no other package depends on are declared by the project in the file they were found in
    #     (e.g. GitHub Actions in a workflow, an extraneous lockfile entry): attach them to the root, labelled.
    comp_by_id = {c["id"]: c for c in sb["components"]}
    has_parent = {b for (_, b) in edges}
    for nid, n in nodes.items():
        if n["kind"] == "pkg" and nid not in has_parent:
            loc = ((comp_by_id.get(nid) or {}).get("locations") or [None])[0]
            add_edge(root, nid, "declared-in-file", "declared",
                     {"file": loc, "line": None, "excerpt": "listed in this file; no other package depends on it"})
            if n["direct"] is None:
                n["direct"] = True
    # 5. paths, depth, fan-in
    adj = collections.defaultdict(list)
    for (a, b) in edges:
        adj[a].append(b)
    depth, paths = _paths(adj, root)
    fan_in = collections.Counter(b for (_, b) in edges)
    for nid, n in nodes.items():
        n["depth"] = depth.get(nid)
        n["fan_in"] = fan_in.get(nid, 0)
        n["paths"] = paths.get(nid, [])
        n["cluster"] = n["paths"][0][1] if n["paths"] and len(n["paths"][0]) > 1 else nid
        if n["kind"] == "pkg" and n["direct"] is None and n["depth"] == 1:
            n["direct"] = True
        if n["kind"] == "pkg" and n["depth"] and n["depth"] > 1 and n["direct"] is None:
            n["direct"] = False
    unreachable = [nid for nid in nodes if nid not in depth]
    names = collections.defaultdict(set)
    for n in nodes.values():
        if n["kind"] == "pkg" and n["version"]:
            names[(n["ecosystem"], n["name"])].add(n["version"])
    eco_info = {}
    for eco in sorted({n["ecosystem"] for n in nodes.values() if n["kind"] == "pkg"}):
        srcs = collections.Counter(s for (a, b), e in edges.items() if nodes[b]["ecosystem"] == eco for s in e["sources"])
        eco_info[eco] = {"nodes": sum(1 for n in nodes.values() if n["ecosystem"] == eco),
                         "edge_sources": dict(srcs),
                         "transitives_resolved": bool(srcs.get("syft") or srcs.get("v1-lockfile") or srcs.get("deps.dev"))
                         or eco not in DEPSDEV_SYSTEM,  # actions, images...: nothing transitive to resolve
                         "not_resolved": sum(1 for n in nodes.values() if n["ecosystem"] == eco
                                             and n.get("resolution") == "not resolved")}
    stats = {"nodes": len(nodes) - 1, "edges": len(edges),
             "direct": sum(1 for n in nodes.values() if n["kind"] == "pkg" and n["direct"]),
             "transitive": sum(1 for n in nodes.values() if n["kind"] == "pkg" and n["direct"] is False),
             "max_depth": max(depth.values()) if depth else 0,
             "not_connected": len([u for u in unreachable if u != root]),
             "top_depended_on": [{"id": k, "name": nodes[k]["name"], "version": nodes[k]["version"], "fan_in": v}
                                 for k, v in fan_in.most_common(20) if k != root],
             "duplicate_versions": sorted([{"ecosystem": e, "name": n, "versions": sorted(v)}
                                           for (e, n), v in names.items() if len(v) > 1],
                                          key=lambda x: -len(x["versions"]))[:50],
             "cycles": "not computed"}
    result = {"root": root, "nodes": list(nodes.values()), "edges": list(edges.values()), "stats": stats,
              "ecosystems": eco_info, "sources": {"syft": len(rels), "v1_npm": v1_status, "deps.dev": depsdev},
              "note": "Edges come from tools: Syft relationships, the v1 package-lock parser (with line evidence) "
                      "and the deps.dev resolver (labelled; a real install can differ). Nothing was installed."}
    ws.write("graph", result)
    return {"nodes": stats["nodes"], "edges": stats["edges"], "direct": stats["direct"],
            "transitive": stats["transitive"], "max_depth": stats["max_depth"],
            "depsdev": depsdev["status"], "v1_npm": v1_status}
