"""Stage 10 - Report: everything the workspace produced, stage coverage, audit-chain check, downloads.

Page: guardian/api/static/pages/s10_report.js · Output: stages/report/ (result.json, report.json, report.md)
"""

from __future__ import annotations

import json

from ..proc import now
from ..tools import tool_version
from ..workspace import Workspace


def run_report(ws: Workspace, opts: dict) -> dict:
    from .. import runner
    m = ws.meta
    stages = []
    for s in runner.ORDER[:-1]:
        st = m.get("stages", {}).get(s, {})
        stages.append({"stage": s, "title": runner.TITLES[s], "status": st.get("status", "not_run"),
                       "summary": st.get("summary"), "finished": st.get("finished"),
                       "file": f"stages/{s}/result.json" if (ws.dir / "stages" / s / "result.json").exists() else None})
    sb, vu, pr, rm, vf = (ws.read(x) or {} for x in ("sbom", "vulns", "prioritise", "remedies", "verify"))
    rep = {"generated": now(), "workspace": ws.id, "source": m["source"], "sha": m.get("sha"), "consent": m.get("consent"),
           "stages": stages,
           "sbom": (sb.get("totals") or {}), "vulnerabilities": (vu.get("counts") or {}),
           "tools": {k: {"status": v.get("status"), "version": v.get("version")} for k, v in (vu.get("tools") or {}).items()},
           "top_risks": [{k: it[k] for k in ("rank", "title", "score", "band", "why")} for it in (pr.get("items") or [])[:10]],
           "plans": [{"id": p["id"], "package": p["name"], "from": p["from_version"], "to": p["to_version"],
                      "decision": p["decision"]} for p in (rm.get("plans") or [])],
           "verification": {k: vf.get(k) for k in ("verdict", "headline", "why_verdict")} if vf else {"verdict": "not run"},
           "tool_versions": {t: tool_version(t) for t in ("syft", "osv-scanner", "grype")}}
    from ...audit import verify as audit_verify
    ok, msg = audit_verify(ws.dir) if (ws.dir / "audit.jsonl").exists() else (False, "no audit log")
    rep["audit"] = {"ok": ok, "detail": msg}
    out = ws.stage_dir("report")
    (out / "report.json").write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
    md = [f"# Guardian report: {m['source'].get('value')}", "", f"Commit `{m.get('sha')}` · generated {rep['generated']}", "",
          "## Stages", *[f"- **{s['title']}**: {s['status']}" for s in stages], "",
          "## SBOM", f"{rep['sbom'].get('components', 'not run')} components", "",
          "## Vulnerabilities", json.dumps(rep["vulnerabilities"].get("by_severity", "not run")), "",
          "## Top risks", *[f"{t['rank']}. {t['title']} ({t['band']} {t['score']}): {t['why']}" for t in rep["top_risks"]], "",
          "## Remedies", *[f"- {p['id']} {p['package']} {p['from']} → {p['to']}: {p['decision']['status']}" for p in rep["plans"]], "",
          "## Sandbox verification", f"**{rep['verification'].get('verdict')}**: {rep['verification'].get('headline', '')}", "",
          f"Audit chain: {'OK' if ok else 'NOT OK'} ({msg})"]
    (out / "report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    rep["files"] = {"json": ws.rel(out / "report.json"), "md": ws.rel(out / "report.md"), "audit": "audit.jsonl",
                    "sbom_cdx": (sb.get("files") or {}).get("syft_cdx"), "sbom_spdx": (sb.get("files") or {}).get("syft_spdx")}
    ws.write("report", rep)
    return {"stages_ok": sum(1 for s in stages if s["status"] in ("ok", "awaiting_approval")), "verdict": rep["verification"].get("verdict"),
            "audit": "ok" if ok else "not ok"}
