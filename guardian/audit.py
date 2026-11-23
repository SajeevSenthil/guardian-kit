"""Append-only, hash-chained audit log: runs/<id>/audit.jsonl.

Each event: seq (from 1), at, actor, action, subject, detail, prev_hash, hash, where
hash = sha256 of the event's canonical JSON (sorted keys, compact separators, UTF-8) without `hash`,
and prev_hash = the previous event's hash (64 zeros for the first). verify() recomputes the chain.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

ZERO = "0" * 64


def _canon(e: dict) -> bytes:
    return json.dumps({k: v for k, v in e.items() if k != "hash"}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _events(run: Path) -> list[dict]:
    p = run / "audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def append(run: Path, actor: str, action: str, subject: str, detail: dict | None = None) -> dict:
    ev = _events(run)
    e = {"seq": len(ev) + 1, "at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), "actor": actor,
         "action": action, "subject": subject, "detail": detail or {}, "prev_hash": ev[-1]["hash"] if ev else ZERO}
    e["hash"] = hashlib.sha256(_canon(e)).hexdigest()
    with (run / "audit.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    return e


def verify(run: Path) -> tuple[bool, str]:
    prev = ZERO
    for i, e in enumerate(_events(run), 1):
        if e.get("seq") != i:
            return False, f"line {i}: sequence is {e.get('seq')}, expected {i}"
        if e.get("prev_hash") != prev:
            return False, f"line {i}: prev_hash does not match line {i - 1}"
        if hashlib.sha256(_canon(e)).hexdigest() != e.get("hash"):
            return False, f"line {i}: content does not match its hash (edited)"
        prev = e["hash"]
    return True, f"OK ({len(_events(run))} events, final hash {prev[:12]})"
