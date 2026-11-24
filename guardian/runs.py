"""Run directories (runs/<run_id>/) and read-only materialisation of git refs.

A run is created by `guardian scan`: it runs the Day-1 fast path and copies its outputs into the
run directory, so every later stage (prioritise, plan, approve, validate, report) reads and writes
one self-contained folder. ./target is only ever read through `git archive`.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import io
import json
import os
import secrets
import shutil
import subprocess
import tarfile
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
TARGET = KIT / "target"
RUNS = Path(os.environ["GUARDIAN_RUNS_DIR"]) if os.environ.get("GUARDIAN_RUNS_DIR") else KIT / "runs"
FASTPATH_OUT = KIT / "fastpath" / "out"
DAY1_FILES = ("findings.json", "graph.json", "sbom.base.cdx.json", "sbom.head.cdx.json", "sbom.diff.json")


def git(*args: str, cwd: Path = TARGET) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, check=True).stdout.decode(
        "utf-8", "replace"
    )


def new_run_id() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(2)


def resolve(run: str | None = None) -> Path:
    """A run id, a run directory, or None for the latest run."""
    if run:
        p = Path(run)
        if p.is_dir():
            return p.resolve()
        if (RUNS / run).is_dir():
            return RUNS / run
        raise FileNotFoundError(f"no run '{run}' under {RUNS}")
    runs = sorted(d for d in RUNS.glob("*") if d.is_dir() and (d / "run.json").exists())
    if not runs:
        raise FileNotFoundError("no runs yet: run `python -m guardian scan` first")
    return runs[-1]


def read_json(run: Path, name: str):
    return json.loads((run / name).read_text(encoding="utf-8"))


def write_json(run: Path, name: str, data) -> Path:
    p = run / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=1), encoding="utf-8")
    return p


def materialise(run: Path, ref: str) -> Path:
    """Extract <ref> of ./target into runs/<id>/src/<ref>/ (read-only, no checkout)."""
    dest = run / "src" / ref.replace("/", "_")
    if dest.exists():
        return dest
    data = subprocess.run(["git", "-C", str(TARGET), "archive", ref], capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        t.extractall(dest, filter="data")
    return dest


_FP = None


def fastpath():
    """The Day-1 fast path module (inventory, SBOM, OSV helpers), loaded once."""
    global _FP
    if _FP is None:
        spec = importlib.util.spec_from_file_location("fastpath_build", KIT / "fastpath" / "build.py")
        _FP = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_FP)
    return _FP


def scan(base: str, head: str, offline: bool) -> Path:
    """Run the Day-1 fast path and start a run directory from its outputs."""
    fastpath().build(base, head, offline)
    run = RUNS / new_run_id()
    run.mkdir(parents=True)
    for f in DAY1_FILES:
        shutil.copy2(FASTPATH_OUT / f, run / f)
    write_json(run, "run.json", {
        "run_id": run.name, "target": "./target", "base": base, "head": head,
        "base_sha": git("rev-parse", base).strip(), "head_sha": git("rev-parse", head).strip(),
        "created": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "mode": "offline" if offline else "live", "stages": {"scan": "ok"},
    })
    return run


def mark_stage(run: Path, stage: str, status: str, **extra) -> None:
    meta = read_json(run, "run.json")
    meta.setdefault("stages", {})[stage] = status
    meta.update(extra)
    write_json(run, "run.json", meta)
