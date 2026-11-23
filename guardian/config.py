"""Typed access to guardian.toml (stdlib tomllib). Validates the scoring settings on load."""

from __future__ import annotations

import tomllib
from functools import lru_cache
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
FACTORS = ("severity", "exploitability", "reachability", "exposure", "fix_availability")


class ConfigError(ValueError):
    pass


@lru_cache(maxsize=1)
def load(path: str | None = None) -> dict:
    p = Path(path) if path else KIT / "guardian.toml"
    cfg = tomllib.loads(p.read_text(encoding="utf-8"))
    w = cfg["score"]["weights"]
    if set(w) != set(FACTORS):
        raise ConfigError(f"score.weights must name exactly {FACTORS}, got {sorted(w)}")
    if sum(w.values()) != 100:
        raise ConfigError(f"score.weights must sum to 100, got {sum(w.values())}")
    for k, v in cfg["score"]["priors"].items():
        if not 0 < v <= 1:
            raise ConfigError(f"score.priors.{k} must be in (0, 1], got {v}")
    return cfg
