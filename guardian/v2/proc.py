"""Process and environment helpers shared by all stages (one place for subprocess settings)."""

from __future__ import annotations

import datetime as dt
import os
import subprocess


def run(cmd: list[str], cwd=None, timeout: int = 600, env: dict | None = None,
        extra_env: dict | None = None) -> subprocess.CompletedProcess:
    """Run a command, capture text output (UTF-8). Git never prompts for credentials."""
    full = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "GCM_INTERACTIVE": "never",
            **(env or {}), **(extra_env or {})}
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, env=full)


def offline() -> bool:
    """GUARDIAN_OFFLINE=1: no outbound lookups; results come from cache or are 'not evaluated'."""
    return os.environ.get("GUARDIAN_OFFLINE") == "1"


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
