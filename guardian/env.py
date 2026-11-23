"""Minimal .env loader (stdlib). Values are put into os.environ and never printed or logged."""

from __future__ import annotations

import os
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
SECRET_NAMES = ("GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY")


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
