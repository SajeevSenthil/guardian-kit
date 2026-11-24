"""Stage 1 - Start & intake: fetch the repo safely (git / zip / local folder) and detect every ecosystem.

Page: guardian/api/static/pages/s01_ingest.js · Output: stages/ingest/result.json
"""

from __future__ import annotations

import os
import re
import shutil
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from ...config import load as load_cfg
from .. import bridge
from ..proc import run as _run
from ..workspace import Workspace

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


def _cfg_sources() -> dict:
    return load_cfg().get("sources", {})


def _git(*args: str, cwd: Path | None = None, timeout: int = 600) -> str:
    r = _run(["git", *args], cwd=cwd, timeout=timeout)
    if r.returncode:
        raise RuntimeError(f"git {args[0]} failed: {(r.stderr or r.stdout).strip().splitlines()[-1:]}")
    return r.stdout


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
    if "*" in allow:  # any https repository (consent is still required and audited)
        return host, f"{owner}/{repo}"
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
