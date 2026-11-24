"""Locate external tools (tools/bin first, then PATH) and report their versions."""

from __future__ import annotations

import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

KIT = Path(__file__).resolve().parents[2]
BIN = KIT / "tools" / "bin"
_VERSION_ARGS = {"syft": ["version"], "grype": ["version"], "osv-scanner": ["--version"], "docker": ["--version"],
                 "git": ["--version"], "npm": ["--version"], "node": ["--version"]}


def find_tool(name: str) -> str | None:
    for cand in (BIN / f"{name}.exe", BIN / name):
        if cand.is_file():
            return str(cand)
    return shutil.which(name)


@lru_cache(maxsize=32)
def tool_version(name: str) -> str | None:
    exe = find_tool(name)
    if not exe:
        return None
    try:
        out = subprocess.run([exe, *_VERSION_ARGS.get(name, ["--version"])], capture_output=True, text=True,
                             timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"(?im)^\s*version:\s*v?(\S+)", out) or re.search(r"v?(\d+\.\d+\.\d+\S*)", out)
    return m.group(1) if m else (out.strip().splitlines() or [None])[0]
