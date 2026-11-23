"""Evidence index, redaction and the claim checker (product rules 1 and 2).

- Evidence is minted only by code: from a finding's own evidence lines (ids `<finding>.E<n>`) or
  from the output of a read-only agent tool (ids `T<n>`). A model never creates evidence.
- `check_claim` is the only door for model output: status is forced to INFERRED, unknown evidence
  ids are dropped, and every quote must be a literal substring (whitespace-normalised, >= 8
  characters) of a cited evidence excerpt, otherwise it is dropped. A model can never raise its
  own claim to "verified".
"""

from __future__ import annotations

import os
import re
import threading

from .env import SECRET_NAMES

_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}"), re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"), re.compile(r"\bAQ\.[A-Za-z0-9_-]{30,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{30,}"), re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]{12,}"),
]


def redact(text: str) -> str:
    """Mask configured secret values and well-known token shapes. Narrow patterns only."""
    if not text:
        return text
    for name in SECRET_NAMES:
        v = os.environ.get(name)
        if v and len(v) >= 8:
            text = text.replace(v, f"[REDACTED:{name}]")
    for p in _PATTERNS:
        text = p.sub(lambda m: (m.group(1) if m.groups() else "") + "[REDACTED]", text)
    return text


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


class EvidenceIndex:
    def __init__(self, findings: list[dict] | None = None):
        self._lock = threading.Lock()
        self.items: dict[str, dict] = {}
        self._n = 0
        for f in findings or []:
            for i, e in enumerate(f.get("evidence", []), 1):
                self.items[f"{f['id']}.E{i}"] = {**e, "finding": f["id"], "kind": e.get("kind", "verified")}

    def ids_for(self, finding_id: str) -> list[str]:
        return [k for k in self.items if k.startswith(finding_id + ".E")]

    def add_tool_output(self, tool: str, args: dict, excerpt: str) -> str:
        with self._lock:
            self._n += 1
            eid = f"T{self._n}"
            self.items[eid] = {"source": f"tool:{tool}({', '.join(f'{k}={v}' for k, v in args.items())})",
                               "line": None, "excerpt": redact(excerpt)[:6000], "kind": "tool"}
            return eid

    def check_claim(self, claim: dict, model: str) -> dict:
        """Coerce one model claim to INFERRED and verify its cited support."""
        ids = [i for i in claim.get("evidence_ids") or [] if i in self.items]
        dropped_ids = [i for i in claim.get("evidence_ids") or [] if i not in self.items]
        corpus = " \n ".join(_norm(self.items[i]["excerpt"]) for i in ids)
        kept, dropped = [], []
        for q in claim.get("quotes") or []:
            nq = _norm(q)
            (kept if len(nq) >= 8 and nq in corpus else dropped).append(q)
        support = None if not (claim.get("quotes") or []) else (not dropped and bool(kept))
        return {"text": redact(str(claim.get("text", ""))), "status": "INFERRED", "model": model,
                "evidence_ids": ids, "quotes": kept, "support_checked": support,
                "dropped_quotes": dropped, "dropped_evidence_ids": dropped_ids}
