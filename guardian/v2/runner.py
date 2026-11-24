"""Stage runner: fixed registry, upstream checks, status/timing, stale marking (contract §5).

Stage functions live in other members' modules and are imported lazily, so a stage that is not
written yet reports "not built yet" instead of breaking the app.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import time
import traceback

from .workspace import Workspace

ORDER = ["ingest", "sbom", "graph", "vulns", "signals", "prioritise", "investigate", "remedies", "verify", "report"]
REGISTRY = {
    "ingest": "guardian.v2.stages.s01_ingest:run_ingest",
    "sbom": "guardian.v2.stages.s02_sbom:run_sbom",
    "graph": "guardian.v2.stages.s03_graph:run_graph",
    "vulns": "guardian.v2.stages.s04_vulns:run_vulns",
    "signals": "guardian.v2.stages.s05_signals:run_signals",
    "prioritise": "guardian.v2.stages.s06_prioritise:run_prioritise",
    "investigate": "guardian.v2.stages.s07_investigate:run_investigate",
    "remedies": "guardian.v2.stages.s08_remedies:run_remedies",
    "verify": "guardian.v2.stages.s09_verify:run_verify",
    "report": "guardian.v2.stages.s10_report:run_report",
}
TITLES = {"ingest": "Start & intake", "sbom": "Inventory & SBOM", "graph": "Dependency graph",
          "vulns": "Vulnerabilities", "signals": "Supply-chain signals", "prioritise": "Prioritised risk",
          "investigate": "Agent investigation", "remedies": "Remedies (approval)", "verify": "Sandbox verification",
          "report": "Report"}
NEEDS = {"ingest": [], "sbom": ["ingest"], "graph": ["sbom"], "vulns": ["sbom"], "signals": ["sbom"],
         "prioritise": ["vulns", "signals", "graph"], "investigate": ["prioritise"], "remedies": ["prioritise"],
         "verify": ["remedies"], "report": []}
OK_STATES = ("ok",)


class NotBuilt(RuntimeError):
    pass


class StageError(RuntimeError):
    pass


def resolve(stage: str):
    if stage not in REGISTRY:
        raise StageError(f"unknown stage {stage!r}; stages are {', '.join(ORDER)}")
    mod, fn = REGISTRY[stage].split(":")
    try:
        m = importlib.import_module(mod)
    except ModuleNotFoundError as e:
        if e.name == mod:
            raise NotBuilt(f"stage '{stage}' is not built yet ({mod} missing)") from None
        raise
    f = getattr(m, fn, None)
    if f is None:
        raise NotBuilt(f"stage '{stage}' is not built yet ({REGISTRY[stage]} missing)")
    return f


def downstream(stage: str) -> list[str]:
    out, todo = [], [stage]
    while todo:
        s = todo.pop()
        for k, v in NEEDS.items():
            if s in v and k not in out:
                out.append(k)
                todo.append(k)
    return [s for s in ORDER if s in out]


def _input_hash(ws: Workspace, stage: str) -> str:
    h = hashlib.sha256()
    for up in NEEDS[stage]:
        p = ws.dir / "stages" / up / "result.json"
        h.update(up.encode() + (p.read_bytes() if p.exists() else b"-"))
    return h.hexdigest()[:16]


def missing_upstream(ws: Workspace, stage: str) -> list[str]:
    return [u for u in NEEDS[stage] if ws.status(u).get("status") not in OK_STATES]


def run_stage(ws: Workspace, stage: str, opts: dict | None = None, force: bool = False) -> dict:
    """Run one stage. Returns its workspace status entry. Never raises for a stage failure."""
    opts = dict(opts or {})
    fn = resolve(stage)  # NotBuilt / StageError propagate: the caller shows them
    miss = missing_upstream(ws, stage)
    if miss:
        raise StageError(f"run {', '.join(miss)} first ('{stage}' needs {', '.join(NEEDS[stage])})")
    with ws.lock:
        if ws.status(stage).get("status") == "running" and not force:
            raise StageError(f"'{stage}' is already running")
        ws.set_status(stage, "running")
    before = (ws.dir / "stages" / stage / "result.json")
    old = before.read_bytes() if before.exists() else None
    t0 = time.time()
    try:
        summary = fn(ws, opts) or {}
        cur = ws.status(stage).get("status")
        final = "awaiting_approval" if cur == "awaiting_approval" else "ok"
        ws.set_status(stage, final, summary=summary if final == "ok" else ws.status(stage).get("summary", summary),
                      seconds=round(time.time() - t0, 1), input_hash=_input_hash(ws, stage))
    except Exception as e:  # a stage failure is data for the UI, not a crash
        msg = f"{type(e).__name__}: {e}".splitlines()[0][:500]
        extra = {"traceback": traceback.format_exc()[-4000:]} if os.environ.get("GUARDIAN_DEBUG") == "1" else {}
        ws.set_status(stage, "failed", error=msg, seconds=round(time.time() - t0, 1), **extra)
        return ws.status(stage)
    new = before.read_bytes() if before.exists() else None
    if new != old:
        for d in downstream(stage):
            if ws.status(d).get("status") in ("ok", "awaiting_approval", "failed"):
                ws.set_status(d, "stale")
    ws.audit("stage", stage=stage, status=ws.status(stage).get("status"))
    return ws.status(stage)


def run_until(ws: Workspace, stage: str, opts: dict | None = None) -> dict:
    """Run every stage needed for `stage` (in order) that is not already ok, then `stage` itself."""
    want, todo = [], [stage]
    while todo:
        s = todo.pop()
        if s not in want:
            want.append(s)
            todo.extend(NEEDS[s])
    results = {}
    for s in [x for x in ORDER if x in want]:
        if s != stage and ws.status(s).get("status") == "ok":
            continue
        try:
            results[s] = run_stage(ws, s, opts)
        except (NotBuilt, StageError) as e:
            results[s] = {"status": "failed", "error": str(e)}
        if results[s].get("status") not in ("ok", "awaiting_approval"):
            break
    return results
