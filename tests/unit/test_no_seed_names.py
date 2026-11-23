"""Detector, scoring and planning code must be generic: no seeded package name, file name or
ground-truth id may appear in guardian/ or fastpath/build.py. Forbidden strings are read from
demo/ground_truth.yaml, not hard-coded here."""

import re
from pathlib import Path

import yaml

KIT = Path(__file__).resolve().parents[2]


def forbidden() -> set[str]:
    gt = yaml.safe_load((KIT / "demo" / "ground_truth.yaml").read_text(encoding="utf-8"))
    out = set()
    for section in ("changes", "optional_changes"):
        for e in gt.get(section, []):
            out.add(e["id"])
            m = re.match(r"pkg:npm/([^@]+)@", str(e.get("component", "")))
            if m and e.get("status") == "seeded":
                out.add(m.group(1))
            for f in str(e.get("file", "")).replace("->", ",").split(","):
                f = f.strip()
                if f.startswith(("vendor/", "package/")):
                    out.add(f)
    # names a real attacker would choose and the seeds use; detectors must find them, not name them
    out |= {e["id"] for e in gt.get("preexisting", [])} | {e["id"] for e in gt.get("negative_controls", [])}
    return {s for s in out if s}


def code_files():
    yield KIT / "fastpath" / "build.py"
    for p in (KIT / "guardian").rglob("*.py"):
        if "data" not in p.parts:
            yield p


def test_forbidden_list_is_not_empty():
    assert {"lodahs"} <= forbidden() or len(forbidden()) > 5


def test_no_seed_names_in_code():
    bad = []
    words = forbidden()
    for p in code_files():
        text = p.read_text(encoding="utf-8")
        for w in words:
            if re.search(r"(?<![\w-])" + re.escape(w) + r"(?![\w-])", text):
                bad.append(f"{p.relative_to(KIT)}: {w}")
    assert not bad, "seeded names found in generic code:\n" + "\n".join(bad)
