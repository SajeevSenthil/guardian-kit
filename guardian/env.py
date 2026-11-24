"""Minimal .env loader (stdlib). Values are put into os.environ and never printed or logged."""

from __future__ import annotations

import os
import re
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
SECRET_NAMES = ("GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY")
_SECRET_RE = re.compile(r"^(GEMINI|GOOGLE|ANTHROPIC)_API_KEY(_\d+)?$")


def secret_env_items():
    """(name, value) of every model key in the environment, including numbered ones (GEMINI_API_KEY_2)."""
    return [(k, v) for k, v in os.environ.items() if _SECRET_RE.match(k) and v]


def gemini_keys() -> list[str]:
    """All configured Gemini keys in a stable order: GEMINI_API_KEY, GEMINI_API_KEY_1 .. _9, GOOGLE_API_KEY."""
    names = ["GEMINI_API_KEY"] + [f"GEMINI_API_KEY_{i}" for i in range(1, 10)] + ["GOOGLE_API_KEY"]
    out = []
    for n in names:
        v = os.environ.get(n)
        if v and v not in out:
            out.append(v)
    return out


def load_dotenv(path: Path | None = None) -> None:
    p = path or KIT / ".env"
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


def key_present(name: str) -> bool:
    return bool(os.environ.get(name))
