# Prompt — Member 2 (M2): vulnerabilities, signals, prioritised risk, agent investigation

Setup (in a terminal, before opening Claude Code):
```
git fetch origin && git checkout v2-any-repo && git pull
```
Then start Claude Code in the repo, run `/clear` and paste the block below.

```text
I am M2 on a 3-person team with a 2-hour deadline. Read docs/V2_TEAM_CONTRACT.md completely
first. It is binding: the file ownership, stage ids, function signatures, page module API, CSS
tokens and classes, and the honesty rules are fixed. Then skim new_plan.md §3 (pages 4–7) for
the intent. We wrap the existing v1 pipeline; we do not rebuild it. Work on branch v2-any-repo
only. Edit only the files the contract gives to M2:
- guardian/v2/stages_detect.py
- guardian/api/routes_detect.py
- guardian/api/static/pages/{vulns,signals,prioritise,investigate}.js
- tests/unit/test_v2_detect.py
Read the v1 code first: guardian/prioritise.py, guardian/scoring.py, guardian/cli.py
(cmd_prioritise, cmd_explain, cmd_analyse), guardian/agents/runner.py (analyse),
guardian/report.py (agents_view, AGENT_INFO) and guardian/review.py (sec_initial,
sec_prioritised, sec_changes, sec_agents). Reuse their logic and wording.

Until M1's skeleton lands (about T+30), develop against the fake workspace in contract §7,
using runs/20261124T053859Z-8e1c. Put pure logic in helpers that take dicts, so tests need no
network.

1. run_vulns(ws, opts), writing stages/vulns/result.json:
   - from ws.v1_run/findings.json, every finding with a vulnerability type (OSV / GitHub
     advisories): package, version, purl, advisory ids + aliases, severity (CVSS score/vector,
     GitHub severity), fixed versions, summary, direct/transitive, dev/prod, introduced_via;
   - extra tools, only if the binary exists in tools/bin (M1's setup script downloads them):
     - osv-scanner: `osv-scanner scan source --lockfile=<src>/package-lock.json --format json`
       (osv-scanner v2 syntax; check `osv-scanner --version` and adjust, then write the exact
       command to docs/tool-notes/osv-scanner.md);
     - grype: `grype sbom:<stages/sbom/syft.cdx.json or the v1 SBOM> -o json`;
     - exit code 1 with results means "found", not "failed";
     - save the raw outputs under stages/vulns/;
   - merge rows by (purl, alias set). reported_by = {osv_api: true/false, osv_scanner:
     true/false/"not-run", grype: true/false/"not-run"}; disagreement = a tool that ran did not
     report it;
   - summary: counts by severity, unique advisories, affected packages, tools {name: ran|not-run,
     version}, agreement {all, some, one}.
   pages/vulns.js:
   - G.header;
   - severity tiles;
   - a tools card: each tool with ran / not-run and its version, and the agreement counts;
   - a table with severity badge, package@version, advisory (linked to osv.dev), CVSS, fixed-in,
     reported-by chips, direct/transitive, dev/prod;
   - row click shows the detail: summary (rendered as untrusted text, escaped), path from the
     root, raw tool links;
   - G.sources: findings.json, the raw tool outputs, result.json.

2. run_signals(ws, opts): every finding that is not a vulnerability (supply-chain signals: install
   scripts, name confusion, integrity/provenance, Dockerfile, CI workflow, curl|sh,
   permissions…). Per signal: rule, title, component, grade (verified/heuristic), evidence lines
   (file:line + excerpt), why_it_matters (reuse the v1 wording in review.py sec_changes).
   pages/signals.js:
   - G.header;
   - tiles by category;
   - cards grouped by rule, each with an evidence block (.mono), a grade chip and why it
     matters;
   - G.sources.

3. run_prioritise(ws, opts):
   - with bridge.use_target(ws): call the same v1 prioritise function cmd_prioritise calls,
     on ws.v1_run;
   - then build result.json for the page: per item the rank, score, band, the 5 factors (value,
     weight, contribution, grade, source), guardrails fired, confidence + range;
   - add code-generated (template, no LLM) text:
     - why: the two biggest contributing factors in words;
     - vs_next: the factor whose difference most explains the gap to the next item;
     - initial vs final: GitHub severity vs band, and why it moved;
   - also the demoted list (critical or high on paper, below 40 now).
   pages/prioritise.js, the "Prioritised risk report" (a long page is fine):
   - a formula card (30·severity + 25·exploitability + 20·reachability + 15·exposure +
     10·fix; the bands; the guardrails);
   - tiles: initial critical/high vs prioritised critical/high;
   - a top-20 table with factor bars;
   - per item, an expandable report: why, vs next, factor table with grade chips and source
     links, guardrails, confidence range;
   - a "Demoted: what we deliberately pushed down and why" section;
   - G.sources.

4. run_investigate(ws, opts):
   - with bridge.use_target(ws): call guardian.agents.runner.analyse(ws.v1_run,
     mode=opts.get("mode", "live"), top_n=opts.get("top", 5));
   - honour GUARDIAN_OFFLINE=1 → offline mode;
   - result.json: per agent (Change Detective, Risk Analyst, Refuter) and per item: status,
     model, claims (text, quotes kept/dropped, support_checked, evidence ids), tool calls,
     verdict/summary fields, and what code did with it. Reuse report.agents_view and
     AGENT_INFO;
   - summary: ran/skipped per agent, tokens, quotes kept/dropped, provider, models;
   - never include API keys (key count only).
   pages/investigate.js:
   - a flow strip: Code finds → Agent investigates (read-only tools) → Code checks quotes and
     schema → Refuter challenges → Code applies fixed rules → saved to file;
   - per agent a card: method, tools it may call, what it produces, how code uses it;
   - then per item, its outputs, with ALL AI text inside .ai-box, quote kept/dropped chips, a
     collapsible list of tool calls, and "skipped — reason" shown plainly;
   - an optional "Re-run agents" button = the G.header run button with opts {top: n} (add
     POST /api/ws/{id}/investigate/run in routes_detect.py only if you need extra parameters);
   - G.sources.

5. tests/unit/test_v2_detect.py:
   - merge-by-alias (three tool rows for one issue give one row);
   - disagreement flag;
   - not-run tool never counted as 0;
   - the why / vs_next templates on fixture factor dicts;
   - signals grouping;
   - investigate result building from a fixture prioritised.json with skipped and ok agents.

Acceptance (T+75, integration 1):
- On M1's workspace from a small npm repo, run stages 4–7 from the UI.
- Vulns: rows with reported-by chips; tools that aren't installed show "not run".
- Prioritised: the formula, the top 20 with why / vs next, the demoted list.
- Investigation: offline shows every card as "skipped (offline)"; live with a Gemini key shows
  at least one agent's AI box with quote chips.
- Every Source files link opens a real file. `python -m pytest -q` passes.
- Commit "[M2] stages 4-7 and pages", pull --rebase, push.
After T+75: fix integration bugs in your files; at T+100 freeze; write a 10-line section per
page in docs/V2_DEMO.md, by sending your text to M3, who owns that file.
```
