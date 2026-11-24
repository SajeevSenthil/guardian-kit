"""Review page for the jury: one self-contained HTML file rendered from the run directory by code.

Sections: the scenario + test report, 1 initial vulnerabilities (what the advisory databases say),
2 prioritised vulnerabilities (what matters for this app, and why), 3 suspicious changes investigated,
4 recommended remedies, 5 AI agents and orchestration, 6 what was not evaluated.
Output: runs/<id>/report/review.html. No model writes any text on this page; agent output is shown
inside labelled "AI" boxes exactly as stored.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from . import report

E = html.escape
BAND_ORDER = ["critical", "high", "medium", "low", "info"]
TYPE_LABEL = {"typosquat": "look-alike name", "unsafe_install_script": "unsafe install script",
              "suspicious_update": "suspicious update", "non_registry_origin": "untrusted origin",
              "unexpected_dependency": "unexpected dependency", "untrusted_image": "untrusted base image",
              "unpinned_ci_component": "unpinned CI action", "unsafe_ci_pattern": "unsafe CI pattern",
              "lockfile_drift": "lockfile drift", "known_vulnerability": "known vulnerability"}


def links(items):
    """Row of links to the real files behind a section (paths relative to runs/<id>/report/)."""
    return ("<p class=links><b>Source files:</b> "
            + " · ".join(f'<a href="{E(href)}" target=_blank>{E(label)}</a>' for label, href in items) + "</p>")


def t(x):
    return TYPE_LABEL.get(x, x)


def badge(text, kind):
    return f'<span class="b b-{E(str(kind))}">{E(str(text))}</span>'


def short(path):
    p = [x.split("node_modules/")[-1] for x in (path or [])]
    return " → ".join(p)


def cves(i):
    return ", ".join(a for a in i.get("aliases", []) if a.startswith("CVE")) or "—"


def bar(v):
    w = 0 if v is None else int(v * 100)
    return f'<span class="bar"><span style="width:{w}%"></span></span>'


def claim_list(claims, limit=4):
    out = []
    for c in (claims or [])[:limit]:
        st = {True: ("quote checked", "ok"), False: ("quote dropped", "bad"), None: ("no quote", "warn")}[c.get("support_checked")]
        out.append(f"<li>{badge('AI · ' + st[0], st[1])} {E(c['text'])}</li>")
    return "<ul class=claims>" + "".join(out) + "</ul>" if out else ""


# ------------------------------------------------------------------------------------------- sections
def sec_scenario(rep):
    sc, r = rep["scorecard"], rep["run"]
    rows = []
    for x in sc["rows"]:
        res = badge("detected", "ok") if x["detected"] else badge("MISSED", "bad")
        hit = "; ".join(f"{h['id']} · {h['score']} {h['band']}" for h in x["findings"])
        where = x["commit_subject"] or ("already in the upstream app" if x["section"] == "preexisting" else "")
        rows.append(f"<tr><td>{E(x['id'])}</td><td>{E(where)}</td><td>{E(t(x['type']))}</td>"
                    f"<td class=m>{E(x['component'])}</td><td>{res}</td><td>{E(hit)}</td></tr>")
    for c in sc["controls"]:
        res = badge("respected", "ok") if c["respected"] else badge("VIOLATED", "bad")
        rows.append(f"<tr><td>{E(c['id'])}</td><td>must NOT be flagged</td><td>{E(', '.join(t(x) for x in c['must_not_have']))}</td>"
                    f"<td class=m>{E(c['component'])}</td><td>{res}</td><td></td></tr>")
    commits = "".join(f"<li><b class=m>{E(c['sha'])}</b> “{E(c['subject'])}” → "
                      + (", ".join(f"{f['id']} {t(f['type'])}" for f in c["findings"] if f["type"] not in
                                   ("new_dependency", "changed_dependency")) or "—") + "</li>" for c in rep["changes"])
    return f"""<section id=scenario><h2>0 · The scenario and the test result</h2>
<p>Sample app: <b>{E(r['sample_app']['repository'])}</b> ({E(r['sample_app']['licence'])}), pinned commit
<span class=m>{E(r['sample_app']['commit'][:8])}</span>. Two versions of one repository:
<b>{E(r['base'])}</b> (trusted, <span class=m>{E(r['base_sha'][:7])}</span>) and <b>{E(r['head'])}</b>
(<span class=m>{E(r['head_sha'][:7])}</span>) with 4 innocent-looking commits that plant harmless, local-only
replicas of real supply-chain attacks:</p><ul>{commits}</ul>
{links([("scorecard (JSON)", "data/0_scorecard.json"), ("ground truth", "../../../demo/ground_truth.yaml"),
        ("Day-1 findings", "../findings.json"), ("Day-1 dashboard", "../../../fastpath/out/guardian.html")])}
<div class=tiles><div class=tile><b>{sc['changes']['detected']}/{sc['changes']['total']}</b><span>planted changes detected</span></div>
<div class=tile><b>{sc['preexisting']['detected']}/{sc['preexisting']['total']}</b><span>pre-existing risks</span></div>
<div class=tile><b>{sc['negative_controls']['respected']}/{sc['negative_controls']['total']}</b><span>negative controls respected</span></div></div>
<details><summary>Test report: expected (demo/ground_truth.yaml) vs detected, computed by code</summary>
<table><tr><th>id</th><th>planted in commit</th><th>expected</th><th>component</th><th>result</th><th>finding</th></tr>{''.join(rows)}</table>
<p class=muted>{E(sc['note'])}</p></details></section>"""


def sec_initial(rep, vulns):
    by = {b: 0 for b in BAND_ORDER}
    pairs = {}
    for i in vulns:
        pairs.setdefault((i["component"], i["advisory"]), i)
    for i in pairs.values():
        by[i["initial_risk"] or "info"] = by.get(i["initial_risk"] or "info", 0) + 1
    top = sorted(pairs.values(), key=lambda i: (BAND_ORDER.index(i["initial_risk"] or "info"),
                                                -float((i.get("cvss") and 1) or 0), i["component"]))[:15]
    rows = "".join(
        f"<tr><td>{badge(i['initial_risk'], i['initial_risk'])}</td><td class=m>{E(i['component'])}</td>"
        f"<td class=m>{E(i['advisory'])}</td><td>{E(cves(i))}</td><td>{E(str(i['github_severity']))}</td>"
        f"<td>{E(', '.join(i['fixed']) or 'none')}</td><td>{'direct' if i['direct'] else 'transitive'}{' · dev' if i['dev'] else ''}</td>"
        f"<td class=small>{E(short(i['path']))}</td></tr>" for i in top)
    ds = rep["data_sources"]
    return f"""<section id=initial><h2>1 · Initial vulnerabilities — what the advisory databases say</h2>
<p>Every installed <b>name@version</b> from the lockfile is sent to <b>OSV.dev</b> ({E(str(ds['osv'].get('status')))});
all advisories returned are <b>GitHub Security Advisories</b> (reviewed). The initial level is GitHub's severity
(from the CVSS score: ≥9 critical, 7–8.9 high, 4–6.9 moderate, &lt;4 low), one level lower for dev-only packages.
This is <i>how bad the bug is in general</i> — not yet whether it matters for this app.</p>
{links([("initial vulnerabilities (JSON)", "data/1_initial_vulnerabilities.json"), ("SBOM head (CycloneDX)", "../sbom.head.cdx.json"),
        ("SBOM base", "../sbom.base.cdx.json"), ("SBOM diff", "../sbom.diff.json"), ("dependency graph", "../graph.json"),
        ("Day-1 findings", "../findings.json")])}
<div class=tiles>{''.join(f'<div class="tile t-{b}"><b>{by.get(b, 0)}</b><span>{b}</span></div>' for b in BAND_ORDER[:4])}
<div class=tile><b>{len(pairs)}</b><span>package–advisory pairs</span></div></div>
<h3>Highest by initial severity (15 of {len(pairs)})</h3>
<table><tr><th>initial</th><th>package</th><th>advisory</th><th>CVE</th><th>GitHub</th><th>fixed in</th><th>relation</th><th>dependency path</th></tr>{rows}</table></section>"""


def sec_prioritised(rep, vulns):
    pairs = {}
    for i in vulns:
        k = (i["component"], i["advisory"])
        if k not in pairs or i["score"] > pairs[k]["score"]:
            pairs[k] = i
    ranked = sorted(pairs.values(), key=lambda i: (-i["score"], -i["confidence"]))
    rows = []
    for n, i in enumerate(ranked[:20], 1):
        f = i["factors"]
        g = ", ".join(x["name"] for x in i["guardrails"])
        moved = f"{i['initial_risk']} → {i['band']}"
        rows.append(f"<tr><td>{n}</td><td><b>{i['score']}</b> {badge(i['band'], i['band'])}<div class=small>range {i['range']} · conf {i['confidence']}</div></td>"
                    f"<td class=m>{E(i['component'])}<div class=small>{E(i['advisory'])} · {E(cves(i))}</div></td>"
                    f"<td>{bar(f['severity']['value'])}{bar(f['exploitability']['value'])}{bar(f['reachability']['value'])}{bar(f['exposure']['value'])}{bar(f['fix_availability']['value'])}</td>"
                    f"<td><b>{E(str(i['reach_tier']))}</b></td><td>{E(g) or '—'}</td><td class=small>{E(moved)}</td></tr>")
    down = [i for i in ranked if i["initial_risk"] == "critical" and i["band"] in ("low", "medium")][:4]
    downs = "".join(f"<li><b>{E(i['component'])}</b> {E(i['advisory'])}: GitHub critical → <b>{i['score']} {i['band']}</b> — "
                    f"{E(i['factors']['reachability']['evidence'][:160])}</li>" for i in down)
    ex = next((i for i in ranked if i["reach_tier"] == "R3"), None)
    ex2 = next((i for i in ranked if ex and i["component"] == ex["component"] and i["advisory"] != ex["advisory"]
                and i["initial_risk"] == "critical"), None)
    def table(i):
        return "".join(f"<tr><td>{E(k.replace('_', ' '))}</td><td>{'unknown' if v['value'] is None else v['value']}</td>"
                       f"<td>{badge(v['grade'], v['grade'])}</td><td class=small>{E(v['evidence'])}</td></tr>" for k, v in i["factors"].items())
    worked = ""
    if ex:
        worked = (f"<div class=grid2><div class=card><h4>{E(ex['advisory'])} · GitHub {E(str(ex['github_severity']))} → "
                  f"<b>{ex['score']}</b> {badge(ex['band'], ex['band'])}</h4><table>{table(ex)}</table></div>")
        if ex2:
            worked += (f"<div class=card><h4>{E(ex2['advisory'])} · GitHub {E(str(ex2['github_severity']))} → "
                       f"<b>{ex2['score']}</b> {badge(ex2['band'], ex2['band'])}</h4><table>{table(ex2)}</table></div>")
        worked += "</div>"
    w = rep["data_sources"]
    return f"""<section id=prioritised><h2>2 · Prioritised vulnerabilities — what matters for this app</h2>
<p>Computed by code: <b>score = 30·severity + 25·exploitability + 20·reachability + 15·exposure + 10·fix</b>
(each 0–1). Severity = CVSS/10 (else GitHub bucket); exploitability = CISA KEV ({E(str(w['kev'].get('status')))}) or
EPSS ({E(str(w['epss'].get('status')))}); reachability R0–R3 from the app's own code; exposure prod/dev; fix availability.
Bands: critical ≥85 · high ≥65 · medium ≥40 · low ≥15. Guardrails: KEV_FLOOR ≥90, NOT_LOADED_CAP ≤39, MALICIOUS_FLOOR ≥90.
Unknown never scores zero: it uses a stated prior, widens the range and lowers confidence. AI never sets a number.</p>
{links([("prioritised vulnerabilities (JSON)", "data/2_prioritised_vulnerabilities.json"), ("all scores + factors", "../prioritised.json"),
        ("weights / priors / bands", "../../../guardian.toml")])}
<h3>Same package, two advisories — reachability decides</h3>{worked}
<h3>Top 20 vulnerabilities after prioritisation</h3><p class=small>bars: severity · exploitability · reachability · exposure · fix</p>
<table><tr><th>#</th><th>score</th><th>package · advisory</th><th>factors</th><th>reach</th><th>guardrail</th><th>initial → final</th></tr>{''.join(rows)}</table>
<h3>Demoted: “critical” on paper, low in this app</h3><ul>{downs or '<li>none</li>'}</ul></section>"""


def sec_changes(rep, inv):
    sus = [i for i in rep["findings"] if i["new_in_head"] and i["type"] not in
           ("known_vulnerability", "new_dependency", "changed_dependency")]
    cards = []
    for i in sus:
        ev = "".join(f"<li><span class=small>{E(c['type'])} · {E(c['source'])}{', line ' + str(c['line']) if c['line'] else ''}</span>"
                     f"<code>{E(c['excerpt'])}</code></li>" for c in i["verified_claims"][:4])
        rec = inv.get(i["id"]) or {}
        prov = rec.get("provenance") or {}
        files = ", ".join((rec.get("timeline") or {}).get("commit_files", [])[:6])
        ag = (rep_agents_for(i))
        cd = ag.get("change_detective") or {}
        rf = ag.get("refuter") or {}
        if cd.get("status") == "ok":
            ai = (f"<div class=ai><b>AI · Change Detective ({E(str(cd.get('model')))})</b><p>{E(str(cd.get('summary')))}</p>"
                  f"<p class=small>resembles: {E(str((cd.get('resembles') or {}).get('pattern')))} — {E(str((cd.get('resembles') or {}).get('why')))}"
                  f" · suggested risk (proposal only): {E(str(cd.get('suggested_risk')))}</p>{claim_list(cd.get('claims'))}</div>")
        else:
            ai = f"<div class=ai-skip>AI · Change Detective: {E(str(cd.get('status') or 'not run'))} {E(str(cd.get('reason') or ''))}</div>"
        if rf:
            ai += (f"<div class=ai><b>AI · Refuter</b> verdict <b>{E(str(rf.get('verdict') or rf.get('status')))}</b> → applied by code: "
                   f"{E(str(rf.get('applied') or rf.get('reason') or ''))}{claim_list(rf.get('claims'), 2)}</div>")
        cards.append(f"""<div class=card><h4>{badge(i['band'], i['band'])} {i['score']} · {E(t(i['type']))} · <span class=m>{E(i['component'])}</span></h4>
<p>{E(i['title'] or '')}</p><p class=small>commit <b class=m>{E((i.get('commit') or {}).get('sha', '-'))}</b> “{E((i.get('commit') or {}).get('subject', ''))}”
· rule: {E(str(i.get('rule') or ''))}</p>
<div class=grid2><div><b>Verified evidence (code)</b><ul class=ev>{ev}</ul>
{('<p class=small>signals: ' + E(', '.join(i['signals'])) + '</p>') if i['signals'] else ''}
<p class=small>provenance: {E(str(prov.get('resolved') or '—'))} · registry {E(str(prov.get('registry')))} · signature {E(str(prov.get('signature') or '—'))}<br>
commit touched: {E(files or '—')}</p></div><div>{ai}</div></div></div>""")
    return f"""<section id=changes><h2>3 · Suspicious changes investigated (no CVE exists for any of them)</h2>
<p>Code compares the trusted baseline with the new version and applies generic rules: look-alike names (edit distance),
install scripts <b>read as text, never run</b> (env-var reads, URLs, network/process calls, temp writes, payload size),
untrusted origins, suspicious updates (new hook, size jump), unused new imports, floating base images, unpinned CI actions,
<span class=m>write-all</span>, <span class=m>curl | sh</span>. Each finding is linked to the commit that introduced it.
The <b>Change Detective</b> agent then investigates with read-only tools and explains what the change appears to do.</p>
{links([("suspicious changes (JSON)", "data/3_suspicious_changes.json"), ("investigation records", "../investigations.json"),
        ("evidence index", "../evidence_index.json"), ("agent trace", "../agent_trace.jsonl")])}
{''.join(cards)}</section>"""


_AGENTS = {}


def rep_agents_for(i):
    return _AGENTS.get(i["id"], {})


def sec_remedies(rep):
    cards = []
    for p in rep["plans"]:
        pr = p["prediction"]
        alts = "".join(f"<li><b>{E(a['id'])}</b> {E(a['summary'])}<br><span class=small>not chosen: {E(a['why_not_chosen'])}</span></li>"
                       for a in p["alternatives"])
        vc = ", ".join(f"{c['package']} {c['from']} → {c['to']} ({c['semver']})" for c in (pr.get("version_changes") or []))
        ap = p["approval"]
        appr = (badge(f"{ap['decision']} by {ap['approver']}", "ok" if ap["decision"] == "approved" else "bad") if ap
                else badge("waiting for a human approval", "warn"))
        ai = p.get("ai_rationale") or {}
        planner = ai.get("remediation_planner") if isinstance(ai, dict) else None
        ref = ai.get("refuter") if isinstance(ai, dict) else None
        aiblock = ""
        if planner and planner.get("status") == "ok":
            aiblock += (f"<div class=ai><b>AI · Remediation Planner ({E(str(planner.get('model')))})</b> prefers "
                        f"<b>{E(str(planner.get('preferred_candidate')))}</b><p class=small>compatibility: {E(str(planner.get('compatibility_impact')))}"
                        f"<br>what could go wrong: {E(str(planner.get('what_could_go_wrong')))}</p>{claim_list(planner.get('claims'), 3)}</div>")
        if ref and ref.get("status") == "ok":
            aiblock += (f"<div class=ai><b>AI · Refuter reviews the plan</b> verdict <b>{E(str(ref.get('verdict')))}</b>"
                        f"{claim_list(ref.get('claims'), 2)}</div>")
        if not aiblock:
            reason = (ai.get("reason") if isinstance(ai, dict) else None) or (planner or {}).get("reason") or "not run"
            aiblock = f"<div class=ai-skip>AI rationale: {E(str(reason))}</div>"
        if isinstance(ai, dict) and ai.get("note_for_approver"):
            aiblock += f"<p class=small><b>note for approver:</b> {E(ai['note_for_approver'])}</p>"
        cards.append(f"""<div class=card><h4>{E(p['id'])} · finding <b>{E(p['finding'])}</b> on <span class=m>{E(p['component'])}</span> {appr}</h4>
<p><b>Recommended:</b> {E(p['action']['summary'])} <span class=small>({E(p['chosen_by'])})</span></p>
{links([("plan JSON", f"../plans/{p['id']}.json"), ("patch", f"../plans/{p['id']}.patch")]
       + ([("approval", f"../approvals/{p['id']}.json")] if p['approval'] else [])
       + ([("validation", f"../validation/{p['id']}.json")] if p['validation'] else []))}
<div class=grid2><div><b>What code tested (dry run in a throwaway clone, scripts disabled)</b><ul class=ev>
<li>edits: {E(' | '.join(p.get('edits') or []))}</li>
<li>target resolved: <b>{E(str(pr.get('target_resolved')))}</b> · findings resolved {E(str(pr.get('resolved_by_band')))}</li>
<li>version change: {E(vc or 'none')} · new vulnerabilities on the fix: {len(pr.get('new_vulnerabilities') or [])}
· require() left dangling: {E(str(pr.get('dangling_requires')))}</li>
<li>policy plan gate: <b>{'PASS' if p['policy']['plan_gate']['pass'] else 'FAIL'}</b> — {E(p['policy']['plan_gate']['reason'])}</li>
<li>rollback: {E(p['rollback'])}</li>
<li class=small>patch sha256 <span class=m>{E(str(p.get('patch_sha256'))[:16])}…</span> · plan hash (what a human approves) <span class=m>{E(p['plan_hash'][:16])}…</span></li></ul>
<b>Alternatives considered</b><ul>{alts}</ul></div><div>{aiblock}</div></div></div>""")
    return f"""<section id=remedies><h2>4 · Recommended remedies</h2>
<p>For each finding code generates candidate fixes by generic rules (upgrade to the lowest / highest fixed version, npm
override, remove, replace, restore the baseline version, pin, delete an introduced workflow, escalate), applies each one in a
<b>throwaway clone</b> (./target is never modified), re-resolves only the lockfile with scripts disabled, and predicts the
result: findings resolved, components added/removed, known vulnerabilities <i>on the fix version</i>, require() calls a
removal would break, and the policy result. Ranking is deterministic; every rejected alternative carries a computed reason.
The <b>Remediation Planner</b> and the <b>Refuter</b> comment; they cannot change the choice. A named human must approve the
exact plan hash before anything is validated; nothing is ever pushed or merged.</p>
{links([("remedies (JSON)", "data/4_remedies.json"), ("policy input", "../policy-input.json"), ("audit log", "../audit.jsonl")])}
{''.join(cards) or '<p>No plans yet.</p>'}</section>"""


def sec_agents(rep):
    ag = rep["agents"]
    steps = [("code", "scan", "SBOM, graph, OSV, sabotage rules"), ("code", "prioritise", "score · range · confidence"),
             ("ai", "analyse", "Change Detective · Risk Analyst · Refuter"), ("code", "apply rules", "check quotes · re-score"),
             ("code", "plan", "candidates · dry runs · policy"), ("ai", "advise", "Remediation Planner · Refuter"),
             ("human", "approve", "name + plan hash"), ("code", "validate", "install · static start · rescan"),
             ("ai", "diagnose", "Diagnostician (on failure)"), ("code", "report", "this page")]
    flow = "".join(f'<div class="step s-{k}"><b>{E(n)}</b><span>{E(d)}</span></div>' for k, n, d in steps)
    cards = []
    for a in ag["agents"]:
        ok = [o for o in a["outputs"] if o.get("status") == "ok"]
        sample = ""
        if ok:
            o = ok[0]
            facts = " · ".join(f"<b>{E(k)}</b>: {E(str(o[k]))}" for k in ("summary", "verdict", "effective_verdict", "applied",
                                                                       "confirmed_symbols", "tier_change", "preferred_candidate",
                                                                       "recommended") if o.get(k))
            tools = "".join(f"<li class=m>{E(x)}</li>" for x in o.get("tool_calls", [])[:5])
            sample = (f"<div class=ai><b>example output — {E(str(o.get('finding') or o.get('plan')))}</b> <span class=small>{E(str(o.get('model') or ''))}</span>"
                      f"<p>{facts}</p>{claim_list(o.get('claims'), 3)}"
                      + (f"<details><summary>tool calls it made</summary><ul>{tools}</ul></details>" if tools else "") + "</div>")
        cards.append(f"""<div class=card><h4>{E(a['name'])} <span class=small>{E(a['when'])}</span></h4>
<p><b>Method:</b> {E(a['method'])}</p><p><b>May call only:</b> <span class=m>{E(', '.join(a['tools']))}</span></p>
<p><b>Produces:</b> {E(a['output'])}</p><p><b>How code uses it:</b> {E(a['how_code_uses_it'])}</p>
<p><b>This run:</b> {a['runs']['ok']} ran · {a['runs']['skipped']} skipped</p>{sample}</div>""")
    loop = ["code builds the task from the run's evidence (ids such as F361.E1)",
            "the agent may call only its allow-listed read-only tools; every tool result is stored by code as evidence T&lt;n&gt; before the model sees it",
            "the final answer is a separate request with no tools that must match a JSON schema (validated, one retry)",
            "code forces every claim to INFERRED, drops unknown evidence ids and any quote that is not word-for-word in the cited evidence",
            "code applies fixed rules — the model never sets a score, chooses a fix, approves or applies anything"]
    return f"""<section id=agents><h2>5 · AI agents and orchestration</h2>
<p><b>Agents never message each other.</b> Guardian's deterministic code is the orchestrator: it runs the stages in a fixed
order, builds each agent's task from the shared run state, checks the agent's answer, applies fixed rules and writes the
result back for the next stage to read. Provider {E(str(ag['provider']))} · mode {E(str(ag['mode']))} · tokens {ag['tokens']}
· quotes kept {ag['quotes_kept']} / dropped {ag['quotes_dropped']}.</p>
{links([("agents (JSON)", "data/5_agents.json"), ("agent trace", "../agent_trace.jsonl"), ("prompts", "../../../guardian/agents/prompts/"),
        ("agent outputs per finding", "../prioritised.json")])}
<div class=flow>{flow}</div>
<h3>One agent run, step by step (same for all five)</h3><ol>{''.join(f'<li>{x}</li>' for x in loop)}</ol>
<div class=grid2>{''.join(cards)}</div></section>"""


ARTEFACTS = [
    ("run.json", "../run.json", "run metadata: target, refs, commit hashes, stage status"),
    ("findings.json", "../findings.json", "Day-1 findings with evidence (scan)"),
    ("sbom.base.cdx.json / sbom.head.cdx.json", "../sbom.head.cdx.json", "CycloneDX SBOMs of both versions"),
    ("sbom.diff.json", "../sbom.diff.json", "packages added / removed / changed"),
    ("graph.json", "../graph.json", "dependency graph: nodes, edges, paths"),
    ("prioritised.json", "../prioritised.json", "every finding with score, factors, guardrails, agent outputs"),
    ("investigations.json", "../investigations.json", "investigation records of suspicious changes"),
    ("evidence_index.json", "../evidence_index.json", "every evidence item incl. agent tool outputs (T<n>)"),
    ("agent_trace.jsonl", "../agent_trace.jsonl", "each agent tool call, in order"),
    ("plans/", "../plans/", "remediation plans (JSON) and patches"),
    ("policy-input.json", "../policy-input.json", "the policy gate's input document"),
    ("audit.jsonl", "../audit.jsonl", "hash-chained audit log"),
    ("guardian-report.html / .md / .json", "guardian-report.html", "full report (human + machine readable)"),
    ("vex.openvex.json", "vex.openvex.json", "OpenVEX statements (only human-approved / validated)"),
    ("data/", "data/", "the intermediate results behind each section of this page"),
]


def sec_artefacts():
    rows = "".join(f'<tr><td><a href="{E(h)}" target=_blank>{E(n)}</a></td><td>{E(d)}</td></tr>' for n, h, d in ARTEFACTS)
    return f"<section id=files><h2>7 · All generated files</h2><table>{rows}</table></section>"


def sec_limits(rep):
    return ("<section id=limits><h2>6 · Not evaluated — said plainly</h2><ul>"
            + "".join(f"<li><b>{E(n['item'])}</b>: {E(n['why'])} → {E(n['effect'])}</li>" for n in rep["not_evaluated"])
            + f"</ul><p class=small>Audit chain: <b>{'OK' if rep['audit']['chain_ok'] else 'BROKEN'}</b> — {E(rep['audit']['result'])}</p></section>")


CSS = """
:root{--bg:#f5f6f8;--p:#fff;--i:#14181f;--m:#5b6472;--l:#d9dde3;--crit:#9b1111;--high:#d62828;--med:#e07b00;--low:#6b7684;
--ok:#1e8e3e;--warn:#b26a00;--bad:#c5221f;--ai:#f3e8fd;--aib:#8430ce;--a:#1f5fbf}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--p:#1a1e25;--i:#eef1f5;--m:#a3acb8;--l:#2d333d;--ai:#2a1f3a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--i);font:19px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
header{background:var(--p);border-bottom:1px solid var(--l);padding:14px 24px;position:sticky;top:0;z-index:5}
header h1{margin:0;font-size:28px}header p{margin:2px 0 8px;color:var(--m);font-size:15px}
nav a{display:inline-block;margin:2px 6px 2px 0;padding:4px 12px;border-radius:16px;background:var(--bg);color:var(--i);
text-decoration:none;font-weight:600;font-size:16px;border:1px solid var(--l)}nav a:hover{border-color:var(--a)}
main{max-width:1280px;margin:auto;padding:8px 24px 60px}section{margin-top:28px}h2{font-size:26px;border-bottom:3px solid var(--l);padding-bottom:4px}
h3{margin-top:22px}h4{margin:0 0 6px;font-size:19px}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:10px 0}.tile{background:var(--p);border:1px solid var(--l);border-radius:12px;padding:8px 16px;min-width:130px}
.tile b{display:block;font-size:30px}.tile span{color:var(--m);font-size:14px;text-transform:uppercase}
.t-critical b{color:var(--crit)}.t-high b{color:var(--high)}.t-medium b{color:var(--med)}
table{border-collapse:collapse;width:100%;background:var(--p);margin:8px 0;font-size:16px}th,td{border-bottom:1px solid var(--l);padding:6px 8px;text-align:left;vertical-align:top}
.m{font-family:ui-monospace,Consolas,monospace;word-break:break-all}.small{font-size:14px;color:var(--m)}.muted{color:var(--m)}
.card{background:var(--p);border:1px solid var(--l);border-radius:12px;padding:12px 16px;margin:12px 0}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:900px){.grid2{grid-template-columns:1fr}}
.b{display:inline-block;padding:0 8px;border-radius:6px;font-size:13px;font-weight:700;color:#fff;background:var(--low);vertical-align:2px}
.b-critical{background:var(--crit)}.b-high{background:var(--high)}.b-medium{background:var(--med)}.b-ok{background:var(--ok)}
.b-warn{background:var(--warn)}.b-bad{background:var(--bad)}.b-verified{background:var(--ok)}.b-heuristic{background:var(--a)}
.b-inferred{background:var(--aib)}.b-unknown{background:var(--low)}
.bar{display:inline-block;width:34px;height:12px;background:var(--l);border-radius:3px;margin-right:3px}.bar span{display:block;height:100%;background:var(--a);border-radius:3px}
.ev{padding-left:18px}.ev code{display:block;font-size:14px;background:var(--bg);padding:3px 6px;border-radius:4px;white-space:pre-wrap;word-break:break-all}
.ai{background:var(--ai);border:2px dashed var(--aib);border-radius:10px;padding:8px 12px;margin:6px 0}.ai-skip{border:2px dashed var(--l);border-radius:10px;padding:8px 12px;color:var(--m)}
.claims{padding-left:18px;font-size:16px}.flow{display:flex;flex-wrap:wrap;gap:8px;align-items:stretch;margin:12px 0}
.step{border-radius:10px;padding:8px 12px;min-width:120px;border:2px solid var(--l);background:var(--p)}.step b{display:block}.step span{font-size:13px;color:var(--m)}
.s-ai{border:2px dashed var(--aib);background:var(--ai)}.s-human{border:3px solid #e8710a}.s-code{border-color:var(--ok)}
.legend{font-size:14px;color:var(--m)}.links{font-size:15px;background:var(--p);border:1px solid var(--l);border-radius:8px;padding:6px 10px}
.links a{color:var(--a);font-weight:600}a{color:var(--a)}
"""


def write_data(run: Path, rep: dict, vulns: list, inv: dict) -> None:
    """The intermediate result behind each section, as JSON files next to the page."""
    d = run / "report" / "data"
    d.mkdir(parents=True, exist_ok=True)
    pairs = {}
    for i in vulns:
        k = (i["component"], i["advisory"])
        if k not in pairs or i["score"] > pairs[k]["score"]:
            pairs[k] = i
    initial = [{"component": i["component"], "advisory": i["advisory"], "cves": [a for a in i["aliases"] if a.startswith("CVE")],
                "initial_risk": i["initial_risk"], "github_severity": i["github_severity"], "cvss_vector": i["cvss"],
                "fixed": i["fixed"], "direct": i["direct"], "dev": i["dev"], "path": i["path"]} for i in pairs.values()]
    ranked = sorted(pairs.values(), key=lambda i: (-i["score"], -i["confidence"]))
    prio = [{"rank": n, "finding": i["id"], "component": i["component"], "advisory": i["advisory"], "score": i["score"],
             "band": i["band"], "range": i["range"], "confidence": i["confidence"], "initial_risk": i["initial_risk"],
             "reachability_tier": i["reach_tier"], "factors": i["factors"], "guardrails": i["guardrails"],
             "explanation": i["explanation"]} for n, i in enumerate(ranked, 1)]
    sus = [{**{k: i[k] for k in ("id", "type", "component", "title", "score", "band", "commit", "rule", "signals",
                                 "verified_claims", "inferred_claims", "status")},
            "investigation": inv.get(i["id"]), "agents": _AGENTS.get(i["id"])}
           for i in rep["findings"] if i["new_in_head"] and i["type"] not in ("known_vulnerability", "new_dependency", "changed_dependency")]
    files = {"0_scorecard.json": rep["scorecard"], "1_initial_vulnerabilities.json": initial,
             "2_prioritised_vulnerabilities.json": prio, "3_suspicious_changes.json": sus, "4_remedies.json": rep["plans"],
             "5_agents.json": rep["agents"], "6_not_evaluated.json": rep["not_evaluated"]}
    for name, data in files.items():
        (d / name).write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")


def render(run: Path) -> Path:
    rep = report.collect(run)
    pr = json.loads((run / "prioritised.json").read_text(encoding="utf-8"))
    _AGENTS.clear()
    for f in pr["findings"]:
        if f.get("agents"):
            _AGENTS[f["id"]] = f["agents"]
    invp = run / "investigations.json"
    inv = json.loads(invp.read_text(encoding="utf-8")) if invp.exists() else {}
    vulns = [i for i in rep["findings"] if i["type"] == "known_vulnerability"]
    r, s = rep["run"], rep["summary"]["counts"]
    tiles = "".join(f"<div class=tile><b>{E(str(v))}</b><span>{E(k)}</span></div>" for k, v in [
        ("packages", s["packages"]), ("findings", s["findings"]), ("need attention", s["need_attention"]),
        ("plans", len(rep["plans"])), ("approved", sum(1 for p in rep["plans"] if p["approval"])),
        ("validated", s["remediated_verified"] + s["remediated_partial"])])
    page = f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Report</title><style>{CSS}</style></head><body>
<header><h1>Report — Supply Chain Guardian</h1>
<p>run {E(r['run_id'])} · {E(r['base'])} ({E(r['base_sha'][:7])}) → {E(r['head'])} ({E(r['head_sha'][:7])}) · generated {E(r['generated'])} by code from the run directory ·
<b>verified</b> = from tool output · <b>heuristic</b> = computed by code · <span class="b b-inferred">AI</span> boxes = model inference with checked quotes</p>
<nav><a href=#scenario>0 Scenario & test</a><a href=#initial>1 Initial vulnerabilities</a><a href=#prioritised>2 Prioritised</a>
<a href=#changes>3 Suspicious changes</a><a href=#remedies>4 Remedies</a><a href=#agents>5 Agents & orchestration</a><a href=#limits>6 Not evaluated</a><a href=#files>7 All files</a></nav></header>
<main><div class=tiles>{tiles}</div>
{sec_scenario(rep)}{sec_initial(rep, vulns)}{sec_prioritised(rep, vulns)}{sec_changes(rep, inv)}{sec_remedies(rep)}{sec_agents(rep)}{sec_limits(rep)}{sec_artefacts()}
</main></body></html>"""
    out = run / "report" / "review.html"
    out.parent.mkdir(exist_ok=True)
    write_data(run, rep, vulns, inv)
    out.write_text(page, encoding="utf-8")
    return out
