"""CVSS v3.0 / v3.1 base score from a vector string (FIRST specification, section 7)."""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """CVSS 3.1 Roundup: smallest number with one decimal >= x (float-safe)."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def base_score(vector: str | None) -> tuple[float, str] | None:
    """Return (score, version) for a CVSS:3.x vector, or None if absent / not v3."""
    if not vector or not vector.startswith("CVSS:3."):
        return None
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope_changed = parts["S"] == "C"
        av, ac, ui = _AV[parts["AV"]], _AC[parts["AC"]], _UI[parts["UI"]]
        pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0, vector.split("/")[0][5:]
    raw = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(raw, 10)), vector.split("/")[0][5:]
