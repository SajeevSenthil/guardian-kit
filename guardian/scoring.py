"""Deterministic risk score (0-100) with a separate confidence and a best/worst-case range.

Design: docs/ARCHITECTURE.md section 6 and docs/research/04 section 1.5. Pure functions.

- Five factors, each a value in 0..1 with an evidence grade: verified | heuristic | inferred | unknown.
- Unknown never scores zero: it takes the configured prior, lowers confidence and widens the range.
- Guardrails (floors/caps) are applied after the weighted sum and reported by name.
"""

from __future__ import annotations

from .config import FACTORS, load

GRADE_Q = {"verified": 1.0, "heuristic": 0.7, "inferred": 0.4, "unknown": 0.0}
BOUNDS = {"severity": (0.25, 1.0), "exploitability": (0.15, 1.0), "reachability": (0.1, 1.0),
          "exposure": (0.3, 1.0), "fix_availability": (0.5, 1.0)}


def factor(value: float | None, grade: str, evidence: str) -> dict:
    if value is None:
        grade = "unknown"
    if grade not in GRADE_Q:
        raise ValueError(f"bad grade {grade}")
    return {"value": value, "grade": grade, "evidence": evidence}


def band(score: int, bands: dict | None = None) -> str:
    b = bands or load()["score"]["bands"]
    for name in ("critical", "high", "medium", "low"):
        if score >= b[name]:
            return name
    return "info"


def score(factors: dict, guardrails: list[tuple[str, str, int, str]] = (), cfg: dict | None = None) -> dict:
    """factors: {name: factor(...)}; guardrails: [(name, "floor"|"cap", limit, reason)] that apply.

    Returns score, band, range, confidence, contributions, unknown factors, guardrails fired.
    """
    cfg = cfg or load()
    w, prior = cfg["score"]["weights"], cfg["score"]["priors"]
    missing = set(FACTORS) - set(factors)
    if missing:
        raise ValueError(f"missing factors {sorted(missing)}")

    def val(k):
        return prior[k] if factors[k]["value"] is None else factors[k]["value"]

    def soft(k):
        return factors[k]["grade"] in ("unknown", "inferred")

    def total(pick):
        return sum(w[k] * pick(k) for k in FACTORS)

    raw = total(val)
    lo = total(lambda k: BOUNDS[k][0] if soft(k) else val(k))
    hi = total(lambda k: BOUNDS[k][1] if soft(k) else val(k))
    fired = []
    s, lo_s, hi_s = raw, lo, hi
    for name, kind, limit, reason in guardrails:
        if kind == "floor" and s < limit:
            s, lo_s, hi_s = limit, max(lo_s, limit), max(hi_s, limit)
            fired.append({"name": name, "effect": f"raised to {limit}", "reason": reason})
        elif kind == "cap" and s > limit:
            s, lo_s, hi_s = limit, min(lo_s, limit), min(hi_s, limit)
            fired.append({"name": name, "effect": f"capped at {limit}", "reason": reason})
    s = round(s)
    return {
        "score": s, "band": band(s, cfg["score"]["bands"]),
        "range": [round(lo_s), round(hi_s)],
        "confidence": round(sum(w[k] * GRADE_Q[factors[k]["grade"]] for k in FACTORS)),
        "raw_score": round(raw, 1),
        "contributions": {k: round(w[k] * val(k), 1) for k in FACTORS},
        "factors": factors,
        "unknown_factors": [k for k in FACTORS if factors[k]["value"] is None],
        "guardrails": fired,
    }


def explain(result: dict) -> str:
    """Plain-language explanation generated from the numbers (no model involved)."""
    f, c = result["factors"], result["contributions"]
    top = sorted(c, key=lambda k: -c[k])[:2]
    parts = [f"{k.replace('_', ' ')} {f[k]['value'] if f[k]['value'] is not None else 'unknown'} "
             f"({f[k]['grade']}: {f[k]['evidence']})" for k in top]
    s = f"Ranked {result['band']} ({result['score']}/100) mainly because of " + "; ".join(parts) + "."
    for g in result["guardrails"]:
        s += f" Guardrail {g['name']} {g['effect']}: {g['reason']}."
    lo, hi = result["range"]
    soft = [k for k in f if f[k]["grade"] in ("unknown", "inferred")]
    if soft:
        s += (f" It could be as low as {lo} or as high as {hi} depending on "
              + ", ".join(k.replace("_", " ") for k in soft) + ", which " + ("is" if len(soft) == 1 else "are")
              + " not established by evidence.")
    else:
        s += " Every factor is backed by verified or heuristic evidence, so the range is narrow."
    s += f" Confidence {result['confidence']}/100."
    return s
