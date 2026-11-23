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


def _not_built(name):
    def f(a):
        _p(f"`{name}` is not built yet (see implementations.md)")
        return 2
    return f


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
    for name in ("plan", "approve", "validate", "report"):
        sub.add_parser(name).set_defaults(fn=_not_built(name))
    a = ap.parse_args(argv)
    if getattr(a, "offline", False):
        os.environ["GUARDIAN_OFFLINE"] = "1"
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())
