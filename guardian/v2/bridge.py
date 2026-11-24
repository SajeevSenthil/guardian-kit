"""Bridge to the v1 pipeline (contract §4).

v1 reads the analysed repo from module variables (guardian.runs.TARGET, fastpath build.TARGET)
and writes runs under guardian.runs.RUNS. `use_target(ws)` points all of them at the workspace
while inside the block (global lock: v1 also shares fastpath/out), and restores them after.

    from guardian.v2 import bridge
    if bridge.has_npm_lock(ws):
        bridge.scan(ws)                 # v1 fast path on ws.src, sets ws.v1_run
    with bridge.use_target(ws):
        ... any v1 call that touches the repo (prioritise, analyse, remediate, validate) ...
"""

from __future__ import annotations

import contextlib
import json
import shutil
import threading
from pathlib import Path

from .. import runs
from .workspace import Workspace

_LOCK = threading.RLock()


def has_npm_lock(ws: Workspace) -> bool:
    return (ws.src / "package-lock.json").is_file()


@contextlib.contextmanager
def use_target(ws: Workspace):
    with _LOCK:
        fp = runs.fastpath()
        saved = (runs.TARGET, runs.RUNS, fp.TARGET)
        runs.TARGET = Path(ws.src)
        runs.RUNS = ws.dir / "v1runs"
        fp.TARGET = str(ws.src)
        try:
            yield
        finally:
            runs.TARGET, runs.RUNS, fp.TARGET = saved


def scan(ws: Workspace, offline: bool = False) -> Path:
    """v1 Day-1 fast path on the workspace snapshot (base = head = HEAD). npm only."""
    if not has_npm_lock(ws):
        raise RuntimeError("the v1 npm layer needs package-lock.json at the repo root")
    with use_target(ws):
        (ws.dir / "v1runs").mkdir(exist_ok=True)
        # v1 writes its outputs to fastpath/out (committed demo files): redirect them into the workspace
        fp = runs.fastpath()
        out = ws.dir / "v1out"
        out.mkdir(exist_ok=True)
        vis = Path(fp.HERE) / "out" / "vis-network.min.js"
        if vis.exists() and not (out / vis.name).exists():
            shutil.copy2(vis, out / vis.name)
        saved = (fp.OUT, runs.FASTPATH_OUT)
        fp.OUT, runs.FASTPATH_OUT = str(out), out
        try:
            run = runs.scan("HEAD", "HEAD", offline)
        finally:
            fp.OUT, runs.FASTPATH_OUT = saved
        meta = json.loads((run / "run.json").read_text(encoding="utf-8"))
        meta.update(target=str(ws.src), workspace=ws.id, snapshot=True)
        (run / "run.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    ws.v1_run = run
    return run
