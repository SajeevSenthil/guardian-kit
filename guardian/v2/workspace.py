"""Workspace: one analysed repo snapshot and every stage output (contract §4).

workspaces/<id>/
  workspace.json      source, ref, sha, consent, v1_run, per-stage status
  src/                the repo (always a git repo after ingest)
  stages/<stage>/result.json
  audit.jsonl         hash-chained (guardian.audit)
"""

from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import threading
from pathlib import Path

from .. import audit as _audit

KIT = Path(__file__).resolve().parents[2]
_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()
SOURCE_KINDS = ("git", "zip", "path")


def root() -> Path:
    return Path(os.environ["GUARDIAN_WORKSPACES_DIR"]) if os.environ.get("GUARDIAN_WORKSPACES_DIR") else KIT / "workspaces"


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def _lock(ws_id: str) -> threading.RLock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(ws_id, threading.RLock())


def _atomic_write(p: Path, data) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + f".tmp{secrets.token_hex(3)}")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    os.replace(tmp, p)


class Workspace:
    def __init__(self, ws_dir: Path):
        self.dir = Path(ws_dir)
        self.id = self.dir.name
        self.src = self.dir / "src"
        self.lock = _lock(self.id)

    # ---------- lifecycle ----------
    @classmethod
    def create(cls, kind: str, value: str, ref: str | None = None, consent_by: str | None = None,
               consent: bool = True) -> "Workspace":
        if kind not in SOURCE_KINDS:
            raise ValueError(f"source kind must be one of {SOURCE_KINDS}")
        if not value or not str(value).strip():
            raise ValueError("source value is required")
        if not consent or not (consent_by or "").strip():
            raise ValueError("consent is required: your name and 'I am authorised to analyse this repository'")
        if kind == "git":
            from .stages_discover import check_git_url
            check_git_url(value)  # refuse early, before anything is written
        ws_id = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(2)
        ws = cls(root() / ws_id)
        ws.dir.mkdir(parents=True)
        _atomic_write(ws.dir / "workspace.json", {
            "id": ws_id, "source": {"kind": kind, "value": str(value).strip()}, "ref": (ref or "").strip() or None,
            "sha": None, "created": now(), "consent": {"by": consent_by.strip(), "at": now()},
            "v1_run": None, "stages": {}})
        ws.audit("consent", actor=consent_by.strip(), source_kind=kind, source=str(value).strip(), ref=ref)
        return ws

    @classmethod
    def load(cls, ws_id: str) -> "Workspace":
        if not ws_id or "/" in ws_id or "\\" in ws_id or ws_id.startswith("."):
            raise FileNotFoundError(f"no workspace {ws_id!r}")
        d = root() / ws_id
        if not (d / "workspace.json").exists():
            raise FileNotFoundError(f"no workspace {ws_id!r}")
        return cls(d)

    @classmethod
    def list(cls) -> list[dict]:
        out = []
        if root().exists():
            for d in sorted(root().iterdir(), reverse=True):
                if (d / "workspace.json").exists():
                    m = json.loads((d / "workspace.json").read_text(encoding="utf-8"))
                    out.append({"id": m["id"], "source": m["source"], "created": m["created"], "sha": m.get("sha")})
        return out

    # ---------- metadata ----------
    @property
    def meta(self) -> dict:
        return json.loads((self.dir / "workspace.json").read_text(encoding="utf-8"))

    def update(self, **fields) -> dict:
        with self.lock:
            m = self.meta
            m.update(fields)
            _atomic_write(self.dir / "workspace.json", m)
            return m

    @property
    def v1_run(self) -> Path | None:
        v = self.meta.get("v1_run")
        return Path(v) if v else None

    @v1_run.setter
    def v1_run(self, p: Path | None) -> None:
        self.update(v1_run=str(p) if p else None)

    # ---------- stages ----------
    def stage_dir(self, stage: str) -> Path:
        d = self.dir / "stages" / stage
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write(self, stage: str, data: dict) -> Path:
        p = self.stage_dir(stage) / "result.json"
        _atomic_write(p, data)
        return p

    def read(self, stage: str) -> dict | None:
        p = self.dir / "stages" / stage / "result.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def status(self, stage: str) -> dict:
        return self.meta.get("stages", {}).get(stage, {"status": "not_run"})

    def set_status(self, stage: str, status: str, summary: dict | None = None, error: str | None = None,
                   **extra) -> None:
        with self.lock:
            m = self.meta
            st = m.setdefault("stages", {}).setdefault(stage, {})
            st["status"] = status
            if status == "running":
                st.update(started=now(), finished=None, error=None)
            elif status in ("ok", "failed", "awaiting_approval"):
                st["finished"] = now()
            if summary is not None:
                st["summary"] = summary
            if error is not None or status == "ok":
                st["error"] = error
            st.update(extra)
            _atomic_write(self.dir / "workspace.json", m)

    def audit(self, event: str, actor: str = "guardian", **fields) -> dict:
        return _audit.append(self.dir, actor, event, self.id, fields)

    # ---------- files ----------
    def safe_path(self, rel: str) -> Path:
        """Resolve a user-supplied path inside the workspace or its v1 run; refuse anything else."""
        rel = (rel or "").replace("\\", "/").lstrip("/")
        if rel.startswith("v1/") and self.v1_run:  # "v1/<file>" = a file of the v1 run behind this workspace
            base, rest = self.v1_run.resolve(), rel[3:]
        else:
            base, rest = self.dir.resolve(), rel
        p = (base / rest).resolve()
        if base not in p.parents or not p.is_file():
            raise FileNotFoundError(f"not a file in this workspace: {rel}")
        return p

    def rel(self, p: Path) -> str:
        """The path to pass to safe_path / the file endpoint for an absolute path we wrote."""
        p = Path(p).resolve()
        if self.v1_run and self.v1_run.resolve() in p.parents:
            return "v1/" + p.relative_to(self.v1_run.resolve()).as_posix()
        return p.relative_to(self.dir.resolve()).as_posix()
