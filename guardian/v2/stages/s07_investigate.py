"""Stage 7 - Agent investigation: AI agents on the top items, 2-minute budget; code checks every claim.

Page: guardian/api/static/pages/s07_investigate.js · Output: stages/investigate/result.json
"""

from __future__ import annotations

import json

from .. import bridge
from ..proc import offline
from ..workspace import Workspace


def run_investigate(ws: Workspace, opts: dict) -> dict:
    from ...env import gemini_keys
    from ...report import AGENT_INFO, agents_view
    mode = "offline" if offline() or opts.get("mode") == "offline" else "live"
    if mode == "live" and not gemini_keys():
        mode = "offline"
    top = int(opts.get("top") or 3)
    pri = ws.read("prioritise") or {"items": []}
    out = {"mode": mode, "top": top, "agents": [], "items": [], "provider": "gemini", "keys_configured": len(gemini_keys())}
    if ws.v1_run and (ws.v1_run / "prioritised.json").exists():
        from ...agents import llm
        from ...agents.runner import analyse
        budget = float(opts.get("budget_s") or 115)  # results on screen within 2 minutes
        llm.set_deadline(budget if mode == "live" else None)
        try:
            with bridge.use_target(ws):
                stats = analyse(ws.v1_run, mode=mode, top_n=top)
        finally:
            llm.set_deadline(None)
        out["time_budget_s"] = budget if mode == "live" else None
        pr = json.loads((ws.v1_run / "prioritised.json").read_text(encoding="utf-8"))
        view = agents_view(pr, {}, ws.v1_run)
        out.update({"analysis": stats, "agents": view["agents"], "flow": view["flow"], "models": view["models"],
                    "tokens": view["tokens"], "quotes_kept": view["quotes_kept"], "quotes_dropped": view["quotes_dropped"],
                    "investigations": ws.rel(ws.v1_run / "investigations.json") if (ws.v1_run / "investigations.json").exists() else None,
                    "v1_prioritised": ws.rel(ws.v1_run / "prioritised.json")})
        # re-scored items may differ after the agents: keep the prioritise page honest by flagging it stale
    else:
        out["agents"] = [{"key": k, "name": n, "when": w, "method": m, "output": o, "how_code_uses_it": a, "tools": [],
                          "runs": {"ok": 0, "skipped": min(top, len(pri["items"]))},
                          "outputs": [{"finding": it["ref"], "component": it["component"], "status": "skipped",
                                       "reason": f"agents for {it['ecosystem']} are not built yet (npm deep layer only)"}
                                      for it in pri["items"][:top]] if k in ("risk_analyst", "refuter") else []}
                         for k, n, w, m, o, a in AGENT_INFO]
        out["flow"] = ["Agents run on the npm deep layer today. For this repo every agent step is shown as skipped; "
                       "the scores above do not depend on any AI."]
    ok = sum(a["runs"]["ok"] for a in out["agents"])
    skipped = sum(a["runs"]["skipped"] for a in out["agents"])
    ws.write("investigate", out)
    return {"mode": mode, "agent_runs_ok": ok, "skipped": skipped, "top": top}
