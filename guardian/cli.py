"""Guardian command line (stdlib argparse; `python -m guardian <command>`)."""

from __future__ import annotations

import argparse
import os
import sys


def _p(*a):
    print(*a, flush=True)


def cmd_scan(a):
    from . import runs
    run = runs.scan(a.base, a.head, a.offline)
    _p(f"run created: {run}")


def cmd_prioritise(a):
    from . import prioritise, runs
    run = runs.resolve(a.run)
    res = prioritise.prioritise(run)
    m, fn = res["meta"], res["funnel"]
    _p(f"run {run.name}")
    _p(f"EPSS: {m['epss']['status']} ({m['epss']['scored']}/{m['epss']['requested']} CVEs scored)   "
       f"KEV: {m['kev']['status']}" + (f" (catalog {m['kev'].get('catalogVersion')})" if m['kev'].get('catalogVersion') else ""))
    _p(f"funnel: {fn['packages']} packages ({fn['install_paths']} install paths) -> {fn['findings']} findings -> "
       f"{fn['ranked_items']} ranked items -> {fn['need_attention']} need attention (critical+high)  bands={fn['by_band']}")
    byid = {f["id"]: f for f in res["findings"]}
    _p(f"\n{'#':>3} {'score':>5} {'range':>9} {'conf':>4} {'band':8} {'type':24} component / detail")
    for i, fid in enumerate(res["ranking"][: a.top], 1):
        f = byid[fid]
        p = f["priority"]
        detail = f.get("advisory") or f.get("title", "")[:60]
        reach = f.get("reachability", {}).get("tier", "")
        rails = ",".join(g["name"] for g in p["guardrails"])
        _p(f"{i:>3} {p['score']:>5} {p['range']!s:>9} {p['confidence']:>4} {p['band']:8} {f['type'][:24]:24} "
           f"{f['component'][:44]}  {detail} {reach} {rails}")


def cmd_explain(a):
    from . import runs
    run = runs.resolve(a.run)
    res = runs.read_json(run, "prioritised.json")
    f = next((x for x in res["findings"] if x["id"] == a.finding), None)
    if not f:
        sys.exit(f"no finding {a.finding} in {run.name}")
    p = f["priority"]
    _p(f"{f['id']}  {f['type']}  {f['component']}  {f.get('advisory', '')}")
    _p(f"{f.get('title', '')}")
    _p(f"\nscore {p['score']} ({p['band']})  range {p['range']}  confidence {p['confidence']}  raw {p['raw_score']}")
    w = res["meta"]["weights"]
    _p(f"\n{'factor':18} {'weight':>6} {'value':>6} {'points':>6}  grade      evidence")
    for k, fac in p["factors"].items():
        v = "unknown" if fac["value"] is None else fac["value"]
        _p(f"{k:18} {w[k]:>6} {v!s:>6} {p['contributions'][k]:>6}  {fac['grade']:10} {fac['evidence']}")
    for g in p["guardrails"]:
        _p(f"guardrail {g['name']}: {g['effect']} ({g['reason']})")
    _p("\n" + p["explanation"])


def cmd_analyse(a):
    from . import runs
    from .agents.runner import analyse
    run = runs.resolve(a.run)
    st = analyse(run, mode=a.mode, top_n=a.top, fresh=a.fresh)
    _p(f"run {run.name}  mode={st['mode']}  provider={st['provider']}  jobs={st['jobs']}")
    for role, s in st["by_role"].items():
        _p(f"  {role:18} ok={s['ok']:>3} skipped={s['skipped']:>3}" + (f"  reasons: {'; '.join(s['reasons'])[:160]}" if s['reasons'] else ""))
    _p(f"  tokens={st['tokens']} turns={st['turns']} tool_calls={st['tool_calls']} "
       f"quotes kept={st['quotes_kept']} dropped={st['quotes_dropped']}  (cost not estimated)")
    res = runs.read_json(run, "prioritised.json")
    shown = next((f for f in res["findings"] if f.get("agents", {}).get("change_detective", {}).get("status") == "ok"), None)
    if shown:
        cd = shown["agents"]["change_detective"]
        _p(f"\nexample: {shown['id']} {shown['type']} {shown['component']}\n  AI summary ({cd['model']}): {cd['summary']}")
        for c in cd["claims"][:4]:
            _p(f"  - [INFERRED, support_checked={c['support_checked']}] {c['text']}  cites {c['evidence_ids']}")
        _p(f"  resembles: {cd.get('resembles')}\n  suggested risk (proposal): {cd.get('suggested_risk')}")


def cmd_doctor(a):
    import json
    import shutil
    import urllib.error
    import urllib.request

    from .config import load
    cfg = load()
    from .env import gemini_keys
    keys = gemini_keys()
    _p(f"GEMINI_API_KEY present: {'yes' if keys else 'no'} ({len(keys)} key(s) configured; values never shown)")
    for t in ("git", "node", "npm", "docker", "conftest", "syft", "grype", "osv-scanner"):
        _p(f"  {t:12} {'found' if shutil.which(t) else 'MISSING'}")
    if not keys:
        return 1
    if os.environ.get("GUARDIAN_OFFLINE") == "1":
        _p("offline: Gemini model check skipped")
        return 0
    req = urllib.request.Request("https://generativelanguage.googleapis.com/v1beta/models?pageSize=200",
                                 headers={"x-goog-api-key": keys[0]})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            names = {m["name"].split("/")[-1] for m in json.load(r).get("models", [])
                     if "generateContent" in m.get("supportedGenerationMethods", [])}
    except urllib.error.HTTPError as e:
        _p(f"Gemini API: HTTP {e.code} (key rejected or no access)")
        return 1
    except OSError as e:
        _p(f"Gemini API unreachable: {type(e).__name__}")
        return 1
    _p(f"Gemini API: OK, {len(names)} models support generateContent")
    for role, m in cfg.get("agents", {}).get("gemini", {}).items():
        _p(f"  {role:20} {m:28} {'available' if m in names else 'NOT AVAILABLE'}")
    flash = sorted(n for n in names if "flash" in n)[:8]
    _p(f"  some available models: {', '.join(flash)}")
    return 0


def cmd_plan(a):
    from . import remediate, runs
    from .agents.planner import make_planner
    from .config import load
    run = runs.resolve(a.run)
    mode = "offline" if os.environ.get("GUARDIAN_OFFLINE") == "1" else a.mode
    plan = remediate.make_plan(run, a.finding, force_candidate=a.candidate,
                               planner=make_planner(mode, load().get("agents", {}).get("gemini", {})))
    p = plan["prediction"]
    _p(f"{plan['id']}  [{plan['state']}]  finding {plan['finding']} ({plan['finding_type']}) on {plan['component']}")
    _p(f"chosen {plan['chosen']['id']} ({plan['chosen_by']}): {plan['chosen']['summary']}")
    _p("  edits: " + " | ".join(p.get("applied", [])))
    if p.get("npm"):
        _p(f"  npm --package-lock-only --ignore-scripts: exit {p['npm']['exit']}")
    _p(f"  prediction: target resolved={p.get('target_resolved')}  findings resolved={len(p.get('resolved', []))} "
       f"{p.get('resolved_by_band', {})}  components +{len(p.get('added', []))}/-{len(p.get('removed', []))}  "
       f"semver={p.get('semver')}  new vulnerabilities={len(p.get('new_vulnerabilities', []))}  "
       f"dangling require()={p.get('dangling_requires')}")
    for c in p.get("version_changes", [])[:6]:
        _p(f"    {c['package']}: {c['from']} -> {c['to']} ({c['semver']})")
    _p(f"  risk: target {p.get('risk', {}).get('target_before')} -> {p.get('risk', {}).get('target_after')}")
    _p(f"  policy on head: {'PASS' if plan['policy_head']['pass'] else 'FAIL'} ({len(plan['policy_head']['deny'])} deny)   "
       f"predicted: {'PASS' if p['policy']['pass'] else 'FAIL'} ({len(p['policy']['deny'])} deny)   "
       f"plan gate: {'PASS' if p['plan_gate']['pass'] else 'FAIL'} - {p['plan_gate']['reason']}")
    for d in p["plan_gate"].get("resolved", [])[:6]:
        _p(f"    resolved deny: {d}")
    _p("  alternatives considered:")
    for alt in plan["alternatives_considered"]:
        _p(f"    {alt['id']} ({alt['kind']}): {alt['summary']}\n       -> not chosen: {alt['why_not_chosen']}")
    if plan.get("policy_entries"):
        _p(f"  policy entries: {plan['policy_entries']}")
    _p(f"  rollback: {plan['rollback']}")
    _p(f"  plan_hash {plan['plan_hash']}  patch {plan['patch_file']}")
    ai = plan["rationale"].get("ai") or {}
    _p(f"  AI rationale: {ai.get('status', 'ok') if 'status' in ai else 'ok'} {ai.get('reason', '')}")
    _p(f"\nnext: python -m guardian approve {plan['id']} --approver \"Your Name\"")


def cmd_approve(a):
    from . import remediate, runs
    run = runs.resolve(a.run)
    rec = remediate.approve(run, a.plan, a.approver, reject=a.reject, comment=a.comment or "")
    _p(f"{rec['plan']} {rec['decision']} by {rec['approver']} at {rec['at']} (plan_hash {rec['plan_hash'][:16]}...)")


def cmd_withdraw(a):
    from . import remediate, runs
    plan = remediate.withdraw(runs.resolve(a.run), a.plan, a.reason)
    _p(f"{plan['id']} withdrawn: {plan['withdrawn_reason']}")


def cmd_validate(a):
    from . import remediate, runs
    run = runs.resolve(a.run)
    from .loop import close_loop
    from .validate import validate
    ok, msg = remediate.check_approval(run, a.plan)
    if not ok:
        _p("REFUSED: " + msg)
        return 3
    res = validate(run, a.plan)
    _p(f"validation of {a.plan} (candidate {res['candidate']}, finding {res['finding']})")
    for c in res["checks"]:
        flag = "" if c["affects_verdict"] else "  (informational)"
        _p(f"  {c['status']:8} {c['name']:16} {c['detail']}{flag}" + (f"  [{c['seconds']}s]" if c.get("seconds") else ""))
        for e in c["evidence"][:4]:
            _p(f"           - {e}")
    _p(f"VERDICT: {res['verdict'].upper()}" + (f"  (not run: {', '.join(res.get('not_run', []))})" if res.get("not_run") else ""))
    if "risk" in res:
        r = res["risk"]
        _p(f"  target score {r['target_before']} -> {r['target_after']}; findings {r['findings_before']} -> "
           f"{r['findings_after']}; target resolved: {res['target_resolved']}")
    if res["verdict"] == "failed" and not a.no_loop:
        mode = "offline" if os.environ.get("GUARDIAN_OFFLINE") == "1" else a.mode
        loop = close_loop(run, a.plan, res, mode)
        d = loop["diagnosis"]
        _p(f"\nDIAGNOSIS ({d['deterministic']['source']}): {d['deterministic']['root_cause']}")
        ag = d["agent"]
        _p(f"  Diagnostician agent: {ag.get('status')} {ag.get('reason') or ag.get('root_cause') or ''}")
        _p(f"  recommended: {d['recommended_candidate']} ({d['decision_note']}) - {d['deterministic'].get('why', '')}")
        if loop["new_plan"]:
            np = loop["new_plan"]
            _p(f"\nNEW PLAN {np['id']} supersedes {a.plan}: {np['chosen']['summary']}")
            _p(f"  state {np['state']}, plan_hash {np['plan_hash'][:16]}...  A human must approve it:")
            _p(f"  python -m guardian approve {np['id']} --approver \"Your Name\"")
    return 0 if res["verdict"] in ("verified", "partial") else 5


def cmd_policy(a):
    from . import remediate, runs
    run = runs.resolve(a.run)
    ctx = remediate.Ctx(run)
    st = remediate.policy_state(ctx, ctx.findings, ctx.nodes, ctx.head_src)
    runs.write_json(run, "policy-input.json", st["input"])
    _p(f"policy gate on {ctx.meta['head']}: {'PASS' if st['pass'] else 'FAIL'}  ({st['engine']})")
    for d in st["deny"]:
        _p(f"  deny: {d}")
    _p(f"  warn: {len(st['warn'])}")


def cmd_audit(a):
    from . import audit, runs
    ok, msg = audit.verify(runs.resolve(a.run))
    _p(msg)
    return 0 if ok else 4


def cmd_report(a):
    from . import report, runs
    run = runs.resolve(a.run)
    res = report.render(run)
    rep, s = res["report"], res["report"]["summary"]["counts"]
    _p(f"report written to {res['dir']}")
    for f in sorted(res["dir"].iterdir()):
        _p(f"  {f.name:32} {f.stat().st_size:>9} bytes")
    _p(f"JSON schema: valid ({report.SCHEMA.relative_to(report.KIT).as_posix()})")
    _p(f"VEX statements: {len(res['vex']['statements'])} "
       f"(fixed: {sum(1 for x in res['vex']['statements'] if x['status'] == 'fixed')}, "
       f"not_affected: {sum(1 for x in res['vex']['statements'] if x['status'] == 'not_affected')})")
    _p(f"summary: {s}")
    for x in rep["summary"]["sentences"]:
        _p(f"  - {x['text']}")
    _p(f"audit chain: {rep['audit']['result']}")


def cmd_review(a):
    from . import review, runs
    out = review.render(runs.resolve(a.run))
    _p(f"review page: {out}")


def cmd_accept(a):
    from . import report, runs
    rec = report.accept(runs.resolve(a.run), a.finding, a.as_, a.by, a.reason)
    _p(f"{rec['finding']} recorded as {rec['decision']} by {rec['by']} at {rec['at']}")


def _not_built(name):
    def f(a):
        _p(f"`{name}` is not built yet (see implementations.md)")
        return 2
    return f


def cmd_ui(a):
    import uvicorn
    _p(f"Guardian UI on http://127.0.0.1:{a.port}  (Ctrl+C to stop)")
    uvicorn.run("guardian.api.app:app", host="127.0.0.1", port=a.port, log_level="warning")


def cmd_ws(a):
    from .v2.workspace import Workspace
    if a.action == "list":
        for w in Workspace.list():
            _p(f"{w['id']}  {w['source']['kind']}  {w['source']['value']}")
        return
    if a.action == "create":
        ws = Workspace.create(a.kind, a.value, a.ref, a.by, consent=bool(a.by))
        _p(ws.id)
        return
    ws = Workspace.load(a.id)
    for k, v in ws.meta.get("stages", {}).items():
        _p(f"{k:12} {v.get('status'):18} {v.get('error') or v.get('summary') or ''}")


def cmd_stage(a):
    from .v2 import runner
    from .v2.workspace import Workspace
    ws = Workspace.load(a.ws)
    res = runner.run_until(ws, a.name) if a.until else {a.name: runner.run_stage(ws, a.name, force=a.force)}
    bad = 0
    for k, v in res.items():
        _p(f"{k:12} {v.get('status'):18} {v.get('error') or v.get('summary') or ''}")
        bad |= v.get("status") not in ("ok", "awaiting_approval")
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guardian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="Day-1 scan (fast path) into a new run directory")
    s.add_argument("--base", default="guardian-baseline")
    s.add_argument("--head", default="tampered")
    s.add_argument("--offline", action="store_true")
    s.set_defaults(fn=cmd_scan)
    s = sub.add_parser("prioritise", help="score and rank every finding")
    s.add_argument("--run")
    s.add_argument("--top", type=int, default=25)
    s.add_argument("--offline", action="store_true")
    s.set_defaults(fn=cmd_prioritise)
    s = sub.add_parser("explain", help="factor table for one finding")
    s.add_argument("finding")
    s.add_argument("--run")
    s.set_defaults(fn=cmd_explain)
    s = sub.add_parser("analyse", help="agents: Change Detective, Risk Analyst, Refuter (phase 9)")
    s.add_argument("--run")
    s.add_argument("--mode", choices=["live", "offline"], default="live")
    s.add_argument("--top", type=int)
    s.add_argument("--fresh", action="store_true", help="ignore the agent result cache")
    s.set_defaults(fn=cmd_analyse)
    sub.add_parser("doctor", help="keys (presence only), tools, Gemini model availability").set_defaults(fn=cmd_doctor)
    s = sub.add_parser("plan", help="fix candidates, dry runs, policy gate -> a plan awaiting approval")
    s.add_argument("--finding", required=True)
    s.add_argument("--candidate", help="choose this candidate explicitly instead of the ranked best")
    s.add_argument("--run")
    s.add_argument("--mode", choices=["live", "offline"], default="live")
    s.set_defaults(fn=cmd_plan)
    s = sub.add_parser("approve", help="record a human approval (or rejection) bound to the plan hash")
    s.add_argument("plan")
    s.add_argument("--approver", required=True)
    s.add_argument("--reject", action="store_true")
    s.add_argument("--comment")
    s.add_argument("--run")
    s.set_defaults(fn=cmd_approve)
    s = sub.add_parser("withdraw", help="withdraw a pending plan (e.g. a defective patch) so it cannot be approved")
    s.add_argument("plan")
    s.add_argument("--reason", required=True)
    s.add_argument("--run")
    s.set_defaults(fn=cmd_withdraw)
    s = sub.add_parser("validate", help="validate an approved plan; on failure diagnose and re-plan")
    s.add_argument("plan")
    s.add_argument("--run")
    s.add_argument("--mode", choices=["live", "offline"], default="live")
    s.add_argument("--no-loop", action="store_true", help="do not diagnose / re-plan after a failure")
    s.set_defaults(fn=cmd_validate)
    s = sub.add_parser("policy", help="policy gate on the head ref")
    s.add_argument("--run")
    s.set_defaults(fn=cmd_policy)
    s = sub.add_parser("audit-verify", help="verify the hash-chained audit log")
    s.add_argument("--run")
    s.set_defaults(fn=cmd_audit)
    s = sub.add_parser("report", help="render the Guardian report (HTML, Markdown, JSON, VEX, SBOMs)")
    s.add_argument("--run")
    s.set_defaults(fn=cmd_report)
    s = sub.add_parser("review", help="render the jury review page (runs/<id>/report/review.html)")
    s.add_argument("--run")
    s.set_defaults(fn=cmd_review)
    s = sub.add_parser("accept", help="record a human decision on a finding: not-affected or accepted-risk")
    s.add_argument("finding")
    s.add_argument("--as", dest="as_", required=True, choices=["not-affected", "accepted-risk"])
    s.add_argument("--by", required=True, help="name of the human taking the decision")
    s.add_argument("--reason", required=True)
    s.add_argument("--run")
    s.set_defaults(fn=cmd_accept)
    # ---- v2 (any repo, stage by stage) ----
    s = sub.add_parser("ui", help="v2 web UI on http://127.0.0.1:8080")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(fn=cmd_ui)
    s = sub.add_parser("ws", help="v2 workspaces: create | status | list")
    s.add_argument("action", choices=["create", "status", "list"])
    s.add_argument("--kind", choices=["git", "zip", "path"], default="path")
    s.add_argument("--value", help="git URL, zip file or local folder")
    s.add_argument("--ref")
    s.add_argument("--by", help="your name (recorded as consent)")
    s.add_argument("--id")
    s.set_defaults(fn=cmd_ws)
    s = sub.add_parser("stage", help="v2: run one stage of a workspace (or --until to run the chain)")
    s.add_argument("name")
    s.add_argument("--ws", required=True)
    s.add_argument("--until", action="store_true")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_stage)
    from .env import load_dotenv
    load_dotenv()
    a = ap.parse_args(argv)
    if getattr(a, "offline", False):
        os.environ["GUARDIAN_OFFLINE"] = "1"
    try:
        return a.fn(a) or 0
    except (FileNotFoundError, KeyError, ValueError, OSError, RuntimeError) as e:
        if os.environ.get("GUARDIAN_DEBUG") == "1":
            raise
        msg = e.args[0] if isinstance(e, KeyError) and e.args else e
        print(f"error: {msg}  (set GUARDIAN_DEBUG=1 for the traceback)", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
