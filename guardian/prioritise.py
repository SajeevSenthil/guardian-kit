"""Stage `prioritise`: turn Day-1 findings into one ranked list with explainable scores.

Inputs (run directory): findings.json and graph.json from the scan, the head ref's source
(materialised read-only), OSV advisory texts from the Day-1 cache, EPSS and KEV (enrich.py).
Output: prioritised.json = every finding with a `priority` block, plus the ranking.
All values are computed by code; nothing here is model output.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import enrich, reachability, runs, scoring
from .config import load
from .cvss import base_score

OSV_CACHE = runs.KIT / "fastpath" / ".cache" / "osv"
INFO_TYPES = {"new_dependency", "changed_dependency"}
GHSA_BUCKET = {"CRITICAL": 0.95, "HIGH": 0.8, "MEDIUM": 0.55, "MODERATE": 0.55, "LOW": 0.25}

# Non-CVE anomaly rubric (docs/research/04 section 1.7; rows marked * are our extensions, documented in
# docs/ARCHITECTURE.md section 6). Severity = worst plausible impact of the class.
ANOMALY_SEVERITY = {
    "typosquat": 0.85, "unsafe_install_script": 0.7, "suspicious_update": 0.7,
    "non_registry_origin": 0.6,   # *
    "unexpected_dependency": 0.5,  # *
    "unsafe_ci_pattern": 0.7,      # *
    "unpinned_ci_component": 0.5, "untrusted_image": 0.4, "lockfile_drift": 0.35,
    "new_dependency": 0.2, "changed_dependency": 0.2,  # * informational
}


def _osv_text(advisory_id: str) -> str:
    p = OSV_CACHE / (hashlib.sha256(("vuln:" + advisory_id).encode()).hexdigest()[:24] + ".json")
    if not p.exists():
        return ""
    d = json.loads(p.read_text(encoding="utf-8"))["data"]
    return (d.get("summary") or "") + "\n" + (d.get("details") or "")


def _semver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v.split("-")[0])[:3]) or (0,)


def _fix_factor(f: dict) -> dict:
    inst = _semver(f.get("installed_version") or "0")
    later = sorted((v for v in f.get("fixed") or [] if _semver(v) > inst), key=_semver)
    if not later:
        return scoring.factor(0.5, "verified", "no fixed version published for this range (OSV)")
    same = [v for v in later if _semver(v)[0] == inst[0]]
    if same:
        return scoring.factor(1.0, "verified", f"fixed in {same[0]}, same major as {f['installed_version']} (OSV)")
    return scoring.factor(0.7, "verified", f"fix needs a major upgrade to {later[0]} (OSV)")


def _cves(f: dict) -> list[str]:
    ids = list(f.get("aliases") or [])
    for e in f.get("evidence", []):
        ids += re.findall(r"CVE-\d{4}-\d{4,}", e.get("excerpt", ""))
    return sorted({i for i in ids if i.startswith("CVE-")})


def _exploit_vuln(cves, epss, epss_status, kev) -> tuple[dict, bool]:
    if kev is not None and any(c in kev for c in cves):
        c = next(c for c in cves if c in kev)
        return scoring.factor(1.0, "verified", f"{c} is in CISA KEV (added {kev[c]['dateAdded']})"), True
    scored = [(epss[c]["epss"], c) for c in cves if c in epss]
    if not scored:
        why = "no CVE alias" if not cves else ("EPSS not evaluated" if epss_status["status"] == "not evaluated"
                                                 else "no EPSS score published")
        return scoring.factor(None, "unknown", why + ("" if kev is not None else "; KEV not evaluated")), False
    p, c = max(scored)
    v = 0.9 if p >= 0.5 else 0.7 if p >= 0.1 else 0.4 if p >= 0.01 else 0.15
    kev_note = "not in KEV" if kev is not None else "KEV not evaluated"
    return scoring.factor(v, "verified", f"EPSS {p:.3f} for {c} (percentile {epss[c]['percentile']:.2f}), {kev_note}"), False


def _exposure_pkg(node: dict, cfg: dict) -> dict:
    if node.get("dev"):
        return scoring.factor(0.3, "verified", "dev-only dependency (lockfile `dev` flag): runs in CI and on laptops")
    if cfg["context"].get("internet_facing"):
        return scoring.factor(1.0, "heuristic", "production dependency of an internet-facing service "
                                                "(internet_facing = true is a stated assumption in guardian.toml)")
    return scoring.factor(0.6, "heuristic", "production dependency, internal service (guardian.toml)")


def _workflow_text(src: Path, rel: str) -> str:
    p = src / rel
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


def _anomaly_factors(f, node, scan, src, kev, cfg) -> tuple[dict, bool]:
    t, title = f["type"], f.get("title", "")
    sev = scoring.factor(ANOMALY_SEVERITY.get(t, 0.3), "heuristic", f"rubric value for class `{t}`")
    is_kev = False
    # exploitability = strength of the hostile signal
    if t == "typosquat":
        m = re.search(r"edit distance (\d+)", title)
        d = int(m.group(1)) if m else 2
        ex = scoring.factor(0.8 if d == 1 and f.get("new_in_head") else 0.5, "heuristic",
                            f"edit distance {d} from an existing or popular name" + (", new package" if f.get("new_in_head") else ""))
    elif t == "unsafe_install_script":
        sig = " ".join(f.get("signals") or []).lower()
        v = 0.8 if ("url" in sig or "network" in sig) else 0.6 if sig else 0.5
        ex = scoring.factor(v, "heuristic", "install script signals: " + (", ".join(f.get("signals") or []) or "none read"))
    elif t == "suspicious_update":
        added = any("install hook added: yes" in e.get("excerpt", "") for e in f["evidence"])
        ex = scoring.factor(0.8 if added else 0.6, "heuristic", "update adds an install hook" if added else "large size jump")
    elif t == "unpinned_ci_component":
        cves = _cves(f)
        if kev is not None and any(c in kev for c in cves):
            c = next(c for c in cves if c in kev)
            ex = scoring.factor(1.0, "verified", f"action advisory {c} is in CISA KEV")
            is_kev = True
        elif cves:
            ex = scoring.factor(0.8, "heuristic", "OSV lists advisories for this action: " + ", ".join(cves))
        else:
            ex = scoring.factor(0.3, "heuristic", "mutable ref with no hostile signal (hygiene)")
    elif t == "unsafe_ci_pattern":
        pipe = "pipes a remote script" in title
        ex = scoring.factor(0.6 if pipe else 0.3, "heuristic",
                            "remote script piped to a shell" if pipe else "over-broad token permissions")
    else:
        ex = scoring.factor(0.3 if t not in INFO_TYPES else 0.15, "heuristic", "hygiene issue, no hostile signal")
    # reachability = does it execute?
    if node and node.get("kind") == "pkg":
        if node.get("install"):
            reach = scoring.factor(1.0, "verified", "has an install script: runs at `npm install`, no import needed")
        elif scan["imports"].get(node["name"], {}).get("sites"):
            s = scan["imports"][node["name"]]["sites"][0]
            reach = scoring.factor(0.8, "heuristic", f"imported by the app ({s['file']}:{s['line']})")
        else:
            reach = scoring.factor(0.4, "heuristic", "present in the lockfile only")
        expo = (scoring.factor(1.0, "verified", "runs where it is installed: CI and production builds (install script)")
                if node.get("install") else _exposure_pkg(node, cfg))
    elif node and node["name"] == "Dockerfile":
        reach = scoring.factor(1.0, "verified", "the base image is the runtime of the deployed app")
        expo = _exposure_pkg({"dev": False}, cfg)
    else:
        txt = _workflow_text(src, node["name"]) if node else ""
        hot = bool(re.search(r"write-all|contents:\s*write|pull_request_target|\$\{\{\s*secrets\.", txt))
        reach = scoring.factor(1.0 if hot else 0.5, "heuristic",
                               "workflow runs with write permissions or secrets" if hot else "read-only workflow")
        expo = scoring.factor(1.0, "heuristic", "CI runner holds repository credentials")
    fix = scoring.factor(1.0, "verified", "remove, replace or pin is available")
    return {"severity": sev, "exploitability": ex, "reachability": reach, "exposure": expo,
            "fix_availability": fix}, is_kev


def prioritise(run: Path) -> dict:
    cfg = load()
    data, graph = runs.read_json(run, "findings.json"), runs.read_json(run, "graph.json")
    meta = runs.read_json(run, "run.json")
    nodes = {n["id"]: n for n in graph["nodes"]}
    src = runs.materialise(run, meta["head"])
    pj = json.loads((src / "package.json").read_text(encoding="utf-8"))
    names = set(pj.get("dependencies", {})) | set(pj.get("devDependencies", {}))
    scan = reachability.scan(src, names)

    [f for f in data["findings"] if f["type"] == "known_vulnerability"]
    all_cves = sorted({c for f in data["findings"] for c in _cves(f)})
    epss, epss_status = enrich.epss(all_cves)
    kev, kev_status = enrich.kev()

    # MALICIOUS_FLOOR components: new, non-registry, install script with >= 2 distinct red flags
    malicious = {f["nodeId"] for f in data["findings"] if f["type"] == "unsafe_install_script"
                 and f.get("new_in_head") and len(set(f.get("signals") or [])) >= 2
                 and not nodes.get(f["nodeId"], {}).get("registry", True)}

    out = []
    for f in data["findings"]:
        node = nodes.get(f.get("nodeId"))
        rails = []
        if f["type"] == "known_vulnerability":
            sv = base_score(f.get("cvss"))
            sev = (scoring.factor(round(sv[0] / 10, 2), "verified", f"CVSS {sv[1]} base {sv[0]} from the OSV vector")
                   if sv else scoring.factor(GHSA_BUCKET.get((f.get("severity") or "").upper()), "verified",
                                             f"GitHub severity {f.get('severity')} (no CVSS v3 vector)"))
            r = reachability.tier_for_vulnerability(node, nodes, _osv_text(f["advisory"]), scan)
            w = r["witness"][0] if r["witness"] else None
            reach = scoring.factor(reachability.TIER_VALUE.get(r["tier"]), r["grade"], f"{r['tier']}: {r['note']}"
                                   + (f" [{w['file']}:{w['line']} {w['excerpt']}]" if w else ""))
            ex, is_kev = _exploit_vuln(_cves(f), epss, epss_status, kev)
            factors = {"severity": sev, "exploitability": ex, "reachability": reach,
                       "exposure": _exposure_pkg(node, cfg), "fix_availability": _fix_factor(f)}
            if is_kev and r["tier"] != "R0":
                rails.append(("KEV_FLOOR", "floor", 90, "listed in CISA KEV and reachable or unknown"))
            if r["tier"] == "R0" and r["grade"] in ("verified", "heuristic") and not is_kev:
                rails.append(("NOT_LOADED_CAP", "cap", 39, "no first-party code loads this package"))
            f = {**f, "reachability": r}
        else:
            factors, is_kev = _anomaly_factors(f, node, scan, src, kev, cfg)
            if is_kev:
                rails.append(("KEV_FLOOR", "floor", 90, "the component's advisory is listed in CISA KEV"))
            if f.get("nodeId") in malicious and f["type"] not in INFO_TYPES:
                rails.append(("MALICIOUS_FLOOR", "floor", 90, ("new component from an untrusted origin whose "
                                                             "install script shows two or more red-flag capabilities")))
        res = scoring.score(factors, rails, cfg)
        res["explanation"] = scoring.explain(res)
        res["rails"] = [list(r) for r in rails]   # applicable guardrails, kept for re-scoring after agents
        out.append({**f, "priority": res})

    # ranking: one entry per unique (component, advisory) for vulnerabilities, per finding otherwise
    best: dict = {}
    for f in out:
        key = (f["component"], f.get("advisory") or f["id"])
        if key not in best or f["priority"]["score"] > best[key]["priority"]["score"]:
            best[key] = f
    ranked = sorted(best.values(), key=lambda f: (-f["priority"]["score"], -f["priority"]["confidence"], f["id"]))
    bands = {}
    for f in ranked:
        bands[f["priority"]["band"]] = bands.get(f["priority"]["band"], 0) + 1
    result = {
        "meta": {"run_id": run.name, "weights": cfg["score"]["weights"], "priors": cfg["score"]["priors"],
                 "bands": cfg["score"]["bands"], "epss": epss_status, "kev": kev_status,
                 "reachability_scan": {"files": scan["files"], "packages_imported": sorted(scan["imports"])},
                 "assumptions": {"internet_facing": cfg["context"].get("internet_facing")}},
        "funnel": {"packages": data["counts"]["packages"], "install_paths": data["counts"]["install_paths"],
                   "findings": len(out), "ranked_items": len(ranked), "by_band": bands,
                   "need_attention": bands.get("critical", 0) + bands.get("high", 0)},
        "ranking": [f["id"] for f in ranked],
        "findings": out,
    }
    runs.write_json(run, "prioritised.json", result)
    runs.mark_stage(run, "prioritise", "ok")
    return result
