"""Stage 6 - Prioritised risk: the scoring formula for every ecosystem, with code-written reasons.

Page: guardian/api/static/pages/s06_prioritise.js · Output: stages/prioritise/result.json
"""

from __future__ import annotations

import collections

from ... import enrich, scoring
from ...config import load as load_cfg
from .. import bridge
from ..identity import norm_purl, purl_type
from ..workspace import Workspace
from .s04_vulns import GHSA_BUCKET, _sev_label

FACTOR_LABEL = {"severity": "severity", "exploitability": "exploitability", "reachability": "reachability",
                "exposure": "exposure", "fix_availability": "fix availability"}


SIGNAL_SEVERITY = {"docker_curl_pipe": 0.7, "ci_curl_pipe": 0.7, "ci_write_all": 0.7, "ci_pull_request_target": 0.8,
                   "ci_unpinned_action": 0.5, "docker_latest": 0.4, "custom_index": 0.6, "non_registry_source": 0.6,
                   "unpinned_version": 0.3, "no_lockfile": 0.35}


def _generic_vuln_factors(r: dict, epss, epss_status, kev, cfg) -> tuple[dict, list]:
    from ...prioritise import _exploit_vuln, _fix_factor
    if r["cvss_score"] is not None:
        sev = scoring.factor(round(r["cvss_score"] / 10, 2), "verified", f"CVSS {r['cvss_score']} ({r['severity_source']})")
    else:
        sev = scoring.factor(GHSA_BUCKET.get(r["severity"]), "verified", f"database severity {r['severity']}")
    ex, is_kev = _exploit_vuln(r["cves"], epss, epss_status, kev)
    reach = scoring.factor(None, "unknown", f"static reachability is implemented for npm only; {r['ecosystem']} not analysed")
    if r.get("dev") is True:
        expo = scoring.factor(0.3, "verified", "dev/test dependency (from the manifest)")
    elif r.get("dev") is False:
        expo = (scoring.factor(1.0, "heuristic", "production dependency of an internet-facing service (guardian.toml)")
                if cfg["context"].get("internet_facing") else
                scoring.factor(0.6, "heuristic", "production dependency, internal service (guardian.toml)"))
    else:
        expo = scoring.factor(None, "unknown", "cannot tell from the files whether it ships to production")
    fix = _fix_factor({"installed_version": r["version"] or "0", "fixed": r["fixed"]})
    rails = [("KEV_FLOOR", "floor", 90, "listed in CISA KEV and reachability unknown")] if is_kev else []
    return {"severity": sev, "exploitability": ex, "reachability": reach, "exposure": expo, "fix_availability": fix}, rails


def _generic_signal_factors(s: dict, cfg) -> dict:
    rule = s["rule"]
    sev = scoring.factor(SIGNAL_SEVERITY.get(rule, 0.3), "heuristic", f"rubric value for rule `{rule}`")
    hostile = rule in ("docker_curl_pipe", "ci_curl_pipe", "ci_pull_request_target", "custom_index")
    ex = scoring.factor(0.6 if hostile else 0.3, "heuristic", "pattern abused in real attacks" if hostile else "hygiene issue, no hostile signal")
    if s["category"] == "ci":
        reach = scoring.factor(1.0, "verified", "runs on every workflow trigger")
        expo = scoring.factor(1.0, "heuristic", "CI runner holds repository credentials")
    elif s["category"] == "container":
        reach = scoring.factor(1.0, "verified", "the image is the runtime of the deployed app")
        expo = scoring.factor(0.6, "heuristic", "deployed container")
    else:
        reach = scoring.factor(0.5, "heuristic", "affects what gets installed")
        expo = scoring.factor(0.6, "heuristic", "build and install environment")
    return {"severity": sev, "exploitability": ex, "reachability": reach, "exposure": expo,
            "fix_availability": scoring.factor(1.0, "verified", "pin, remove or restrict is available")}


def _factor_rows(p: dict, weights: dict) -> list[dict]:
    rows = []
    for k in scoring.FACTORS if hasattr(scoring, "FACTORS") else ("severity", "exploitability", "reachability", "exposure", "fix_availability"):
        f = p["factors"][k]
        rows.append({"factor": k, "label": FACTOR_LABEL[k], "weight": weights[k], "value": f["value"], "grade": f["grade"],
                     "evidence": f["evidence"], "contribution": p["contributions"][k]})
    return rows


def why_text(item: dict) -> str:
    fr = sorted(item["factor_rows"], key=lambda r: -r["contribution"])[:2]
    parts = [f"{r['label']} ({r['value'] if r['value'] is not None else 'unknown, prior used'}: {r['evidence']})" for r in fr]
    s = f"Scored {item['score']}/100 ({item['band']}) mainly because of " + " and ".join(parts) + "."
    for g in item["guardrails"]:
        s += f" Guardrail {g['name']} {g['effect']}: {g['reason']}."
    return s


def vs_next_text(a: dict, b: dict | None) -> str | None:
    if not b:
        return None
    if a["score"] == b["score"]:
        if a["confidence"] != b["confidence"]:
            return (f"Same score as #{b['rank']} {b['title']}; listed first because its evidence is stronger "
                    f"(confidence {a['confidence']} vs {b['confidence']}).")
        return f"Tied with #{b['rank']} {b['title']} (same score and confidence); order between them is alphabetical."
    ca = {r["factor"]: r["contribution"] for r in a["factor_rows"]}
    cb = {r["factor"]: r["contribution"] for r in b["factor_rows"]}
    k = max(ca, key=lambda x: ca[x] - cb[x])
    d = round(ca[k] - cb[k], 1)
    rail = next((g for g in a["guardrails"] if g["name"] not in {x["name"] for x in b["guardrails"]}), None)
    s = (f"Ranks above #{b['rank']} ({b['score']}) mainly because its {FACTOR_LABEL[k]} adds {d:+} points "
         f"({ca[k]} vs {cb[k]}).")
    if rail:
        s += f" It also has guardrail {rail['name']} ({rail['effect']})."
    return s


def initial_vs_final(item: dict) -> str:
    ini = item.get("initial_severity") or "unknown"
    if ini == "unknown":
        return f"No published severity; Guardian ranks it {item['band']}."
    order = ["low", "medium", "high", "critical"]
    fb = item["band"] if item["band"] in order else "low"
    if ini not in order or order.index(fb) == order.index(ini):
        return f"Published as {ini}; Guardian agrees ({item['band']})."
    low = min(item["factor_rows"][1:], key=lambda r: r["contribution"] / max(r["weight"], 1))
    if order.index(fb) < order.index(ini):
        return (f"Published as {ini}, ranked {item['band']} here: {low['label']} pulls it down "
                f"({low['value'] if low['value'] is not None else 'unknown'}: {low['evidence']}).")
    top = max(item["factor_rows"][1:], key=lambda r: r["contribution"] / max(r["weight"], 1))
    return f"Published as {ini}, ranked {item['band']} here: {top['label']} raises it ({top['evidence']})."


def run_prioritise(ws: Workspace, opts: dict) -> dict:
    cfg = load_cfg()
    weights = cfg["score"]["weights"]
    vul, sig = ws.read("vulns") or {"rows": []}, ws.read("signals") or {"signals": []}
    items, v1_meta = [], None
    covered_v1 = set()
    if ws.v1_run:
        from ... import prioritise as v1p
        with bridge.use_target(ws):
            pr = v1p.prioritise(ws.v1_run)
        v1_meta = {"file": ws.rel(ws.v1_run / "prioritised.json"), "funnel": pr["funnel"], "epss": pr["meta"]["epss"],
                   "kev": pr["meta"]["kev"], "reachability_scan": pr["meta"]["reachability_scan"]}
        byid = {f["id"]: f for f in pr["findings"]}
        row_by_v1 = {v: r for r in vul["rows"] for v in r.get("v1_ids", [])}
        sig_by_v1 = {s.get("v1_id"): s for s in sig["signals"] if s.get("v1_id")}
        for fid in pr["ranking"]:
            f = byid[fid]
            p = f["priority"]
            row = row_by_v1.get(fid)
            is_v = f["type"] == "known_vulnerability"
            if row:
                covered_v1.add(row["id"])
            items.append({"kind": "vuln" if is_v else "signal", "ref": (row or {}).get("id") or (sig_by_v1.get(fid) or {}).get("id"),
                          "v1_id": fid, "title": (f"{f.get('advisory')} in {(row or {}).get('name') or f['component']}" if is_v else f.get("title")),
                          "component": f["component"], "component_id": norm_purl(f["component"]) if f["component"].startswith("pkg:") else None,
                          "ecosystem": purl_type(f["component"]) if f["component"].startswith("pkg:") else "repo",
                          "advisory": f.get("advisory"), "initial_severity": _sev_label(None, f.get("severity") or f.get("risk")),
                          "summary": (row or {}).get("summary") or f.get("title"), "priority": p,
                          "reachability": (f.get("reachability") or {}).get("tier"), "source": "v1 (npm deep layer)",
                          "agents": f.get("agents")})
    epss = kev = None
    cves = sorted({c for r in vul["rows"] for c in r["cves"]})
    epss, epss_status = enrich.epss(cves) if cves else ({}, {"status": "not needed"})
    kev, kev_status = enrich.kev()
    for r in vul["rows"]:
        if r["id"] in covered_v1 or any(v is True for k, v in r["reported_by"].items() if k == "v1_osv"):
            continue
        factors, rails = _generic_vuln_factors(r, epss, epss_status, kev, cfg)
        p = scoring.score(factors, rails, cfg)
        items.append({"kind": "vuln", "ref": r["id"], "title": f"{r['advisory']} in {r['name']} {r['version'] or ''}".strip(),
                      "component": r["purl"] or r["component_id"], "component_id": r["component_id"], "ecosystem": r["ecosystem"],
                      "advisory": r["advisory"], "initial_severity": r["severity"], "summary": r["summary"], "priority": p,
                      "reachability": None, "source": "generic (tools + formula)"})
    for s in sig["signals"]:
        if s.get("source") == "v1":
            continue  # already ranked by v1
        p = scoring.score(_generic_signal_factors(s, cfg), [], cfg)
        items.append({"kind": "signal", "ref": s["id"], "title": s["title"], "component": s["component"],
                      "component_id": s.get("component_id"), "ecosystem": "repo", "advisory": None,
                      "initial_severity": None, "summary": s["why"], "priority": p, "reachability": None,
                      "source": "generic (rules + formula)"})
    for it in items:
        p = it.pop("priority")
        it.update({"score": p["score"], "band": p["band"], "range": p["range"], "confidence": p["confidence"],
                   "guardrails": p["guardrails"], "unknown_factors": p["unknown_factors"],
                   "factor_rows": _factor_rows(p, weights)})
    items.sort(key=lambda x: (-x["score"], -x["confidence"], x["title"] or ""))
    for i, it in enumerate(items, 1):
        it["rank"] = i
    for i, it in enumerate(items):
        it["why"] = why_text(it)
        it["vs_next"] = vs_next_text(it, items[i + 1] if i + 1 < len(items) else None)
        it["initial_vs_final"] = initial_vs_final(it)
    demoted = [{"rank": it["rank"], "title": it["title"], "initial_severity": it["initial_severity"], "score": it["score"],
                "band": it["band"], "reason": it["initial_vs_final"]}
               for it in items if it["initial_severity"] in ("critical", "high") and it["score"] < 65][:50]
    bands = collections.Counter(it["band"] for it in items)
    ini = collections.Counter(it["initial_severity"] for it in items)
    result = {"items": items, "rows": [{"component_id": it["component_id"], "id": it["title"], "band": it["band"]} for it in items if it["component_id"]],
              "demoted": demoted, "weights": weights, "bands": cfg["score"]["bands"], "priors": cfg["score"]["priors"],
              "counts": {"items": len(items), "by_band": dict(bands), "initial": dict(ini),
                         "need_attention": bands.get("critical", 0) + bands.get("high", 0)},
              "enrichment": {"epss": epss_status, "kev": kev_status}, "v1": v1_meta,
              "formula": "score = 30·severity + 25·exploitability + 20·reachability + 15·exposure + 10·fix availability; "
                         "unknown factors use a prior, lower confidence and widen the range; guardrails apply after."}
    ws.write("prioritise", result)
    return {"ranked": len(items), "critical": bands.get("critical", 0), "high": bands.get("high", 0),
            "demoted": len(demoted), "deep_npm": bool(ws.v1_run)}
