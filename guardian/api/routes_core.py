"""Core endpoints (M1): workspaces, stage runs, status, files, upload (contract §6)."""

from __future__ import annotations

import mimetypes
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ..v2 import runner
from ..v2.tools import find_tool, tool_version
from ..v2.workspace import Workspace

router = APIRouter(prefix="/api")
EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="stage")
_BUSY: set[str] = set()
_BUSY_LOCK = threading.Lock()


class WsIn(BaseModel):
    kind: str
    value: str
    ref: str | None = None
    consent_by: str
    consent: bool = False


def _ws(ws_id: str) -> Workspace:
    try:
        return Workspace.load(ws_id)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e)) from None


def submit(ws: Workspace, fn, *args) -> None:
    """Run a job for a workspace in the background; one job per workspace at a time."""
    with _BUSY_LOCK:
        if ws.id in _BUSY:
            raise HTTPException(409, "a stage is already running for this workspace")
        _BUSY.add(ws.id)

    def job():
        try:
            fn(*args)
        except Exception as e:  # NotBuilt / StageError: record it on the stage so the UI shows it
            stage = args[1] if len(args) > 1 else None
            if stage:
                ws.set_status(stage, "failed", error=str(e))
        finally:
            with _BUSY_LOCK:
                _BUSY.discard(ws.id)

    EXECUTOR.submit(job)


@router.get("/meta")
def meta():
    return {"stages": [{"id": s, "title": runner.TITLES[s], "needs": runner.NEEDS[s]} for s in runner.ORDER],
            "tools": {t: {"path": bool(find_tool(t)), "version": tool_version(t)}
                      for t in ("syft", "osv-scanner", "grype", "docker", "git", "npm")}}


@router.get("/ws")
def list_ws():
    return Workspace.list()


@router.post("/ws")
def create_ws(body: WsIn):
    try:
        ws = Workspace.create(body.kind, body.value, body.ref, body.consent_by, body.consent)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    return {"id": ws.id}


@router.post("/ws/upload")
async def upload_ws(file: UploadFile = File(...), consent_by: str = Form(...), consent: bool = Form(False),
                    ref: str | None = Form(None)):
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "upload a .zip of the repository")
    data = await file.read()
    if len(data) > 300e6:
        raise HTTPException(400, "zip larger than 300 MB")
    try:
        ws = Workspace.create("zip", "(upload pending)", ref, consent_by, consent)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    zp = ws.dir / "upload.zip"
    zp.write_bytes(data)
    m = ws.meta
    m["source"] = {"kind": "zip", "value": str(zp), "filename": file.filename}
    ws.update(source=m["source"])
    return {"id": ws.id}


@router.get("/ws/{ws_id}")
def get_ws(ws_id: str):
    ws = _ws(ws_id)
    m = ws.meta
    for s in runner.ORDER:
        m["stages"].setdefault(s, {"status": "not_run"})
        try:
            runner.resolve(s)
            m["stages"][s]["built"] = True
        except runner.NotBuilt:
            m["stages"][s]["built"] = False
    m["busy"] = ws.id in _BUSY
    return m


@router.post("/ws/{ws_id}/stages/{stage}/run")
def run_stage(ws_id: str, stage: str, body: dict | None = None):
    ws = _ws(ws_id)
    try:
        runner.resolve(stage)
    except (runner.NotBuilt, runner.StageError) as e:
        raise HTTPException(400, str(e)) from None
    miss = runner.missing_upstream(ws, stage)
    if miss:
        raise HTTPException(400, f"run {', '.join(miss)} first")
    submit(ws, runner.run_stage, ws, stage, body or {})
    return {"started": stage}


@router.post("/ws/{ws_id}/run-until/{stage}")
def run_until(ws_id: str, stage: str, body: dict | None = None):
    ws = _ws(ws_id)
    if stage not in runner.REGISTRY:
        raise HTTPException(400, f"unknown stage {stage}")
    submit(ws, runner.run_until, ws, stage, body or {})
    return {"started": stage}


@router.get("/ws/{ws_id}/stages/{stage}")
def get_stage(ws_id: str, stage: str):
    ws = _ws(ws_id)
    if stage not in runner.REGISTRY:
        raise HTTPException(404, f"unknown stage {stage}")
    st = ws.status(stage)
    return {"stage": stage, "title": runner.TITLES[stage], "status": st.get("status", "not_run"),
            "summary": st.get("summary"), "error": st.get("error"), "started": st.get("started"),
            "finished": st.get("finished"), "seconds": st.get("seconds"), "result": ws.read(stage)}


@router.get("/ws/{ws_id}/file")
def get_file(ws_id: str, path: str):
    ws = _ws(ws_id)
    try:
        p = ws.safe_path(path)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e)) from None
    mt = mimetypes.guess_type(p.name)[0] or "text/plain"
    if p.suffix in (".json", ".jsonl", ".patch", ".diff", ".log", ".md", ".txt", ".lock", ".toml", ".yaml", ".yml"):
        mt = "application/json" if p.suffix == ".json" else "text/plain"
    return FileResponse(p, media_type=mt, headers={"X-Content-Type-Options": "nosniff"},
                        content_disposition_type="inline", filename=p.name)
