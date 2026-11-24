"""Scorecard: compare a run's findings with demo/ground_truth.yaml (the planted scenario).

Matching rule (from the ground-truth file): an entry counts as detected when a finding has the same
`type` and its component, title or evidence names the entry's `component` (purl name@version, file
path, image or action ref). `changes` entries must be new since the baseline; `preexisting` entries
must not be. `negative_controls` must NOT have the listed finding types. Computed by code only.
"""

from __future__ import annotations

from pathlib import Path

import yaml

KIT = Path(__file__).resolve().parents[1]


def _names(f: dict) -> str:
    return " ".join([f.get("component", ""), f.get("title") or ""] + [e.get("excerpt", "") for e in f.get("evidence", [])])


def _match(entry: dict, findings: list[dict], new: bool | None) -> list[dict]:
    comp = str(entry.get("component", ""))
    key = comp.split(" ")[-1] if comp.startswith("Dockerfile FROM") else comp
    out = []
    for f in findings:
        if f["type"] != entry["type"]:
            continue
        if new is not None and bool(f.get("new_in_head")) != new:
            continue
        hay = _names(f)
        if key and (key in hay or (comp.startswith("Dockerfile FROM") and f["component"].startswith("Dockerfile")
                                   and f"FROM {key}" in hay)):
            out.append(f)
    return out


def score(findings: list[dict], ground_truth: Path | None = None) -> dict:
    gt = yaml.safe_load((ground_truth or KIT / "demo" / "ground_truth.yaml").read_text(encoding="utf-8"))
    rows = []
    for section, new in (("changes", True), ("preexisting", False)):
        for e in gt.get(section, []):
            hits = _match(e, findings, new)
            rows.append({"id": e["id"], "section": section, "type": e["type"], "component": e["component"],
                         "commit_subject": e.get("commit_subject"), "detected": bool(hits),
                         "findings": [{"id": h["id"], "score": (h.get("priority") or {}).get("score"),
                                       "band": (h.get("priority") or {}).get("band") or h.get("risk"),
                                       "commit": (h.get("commit") or {}).get("sha")} for h in hits]})
    controls = []
    for e in gt.get("negative_controls", []):
        bad_types = e["must_not_have"] if isinstance(e["must_not_have"], list) else [e["must_not_have"]]
        comp = e["component"]
        wrong = [f for f in findings if f["type"] in bad_types and comp in _names(f)
                 and not (comp.startswith("pkg:") and f.get("component") != comp)]
        controls.append({"id": e["id"], "component": comp, "must_not_have": bad_types, "respected": not wrong,
                         "violations": [f["id"] for f in wrong]})
    ch = [r for r in rows if r["section"] == "changes"]
    pe = [r for r in rows if r["section"] == "preexisting"]
    return {"changes": {"detected": sum(r["detected"] for r in ch), "total": len(ch)},
            "preexisting": {"detected": sum(r["detected"] for r in pe), "total": len(pe)},
            "negative_controls": {"respected": sum(c["respected"] for c in controls), "total": len(controls)},
            "rows": rows, "controls": controls,
            "missed": [r["id"] for r in rows if not r["detected"]],
            "note": "The detectors were developed with these seeds known; hold-out seeds and a second "
                    "application have not been run, so this measures the demo, not generality."}
