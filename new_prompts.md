# Guardian v2 — phase prompts (paste one per session)

How to use:
- One phase per Claude Code session. Start with `/clear`, then paste the block.
- Read `new_plan.md` first; the prompts refer to its sections.
- Every phase ends with its acceptance checks passing, an entry in `implementations.md`, updated
  `docs/KNOWN_LIMITATIONS.md` and one commit (you push).
- Keep v1 working: v1 modules, `./target` and v1 tests must keep passing (`python -m pytest -q`).
- Rules from `CLAUDE.md` still apply. In particular:
  - never run code from the analysed repo or its packages;
  - `npm` always runs with `--ignore-scripts`;
  - never send secrets to a model;
  - unknown is never zero;
  - only code writes facts, and agents produce INFERRED claims only.

---

## Phase 1 — Foundation: workspaces, stage runner, API, UI shell, ingest (5–7 h)

```text
Read CLAUDE.md, new_plan.md (all of it) and docs/HACKATHON_BRIEF.md "Out of scope".
We are building Guardian v2: a web app that analyses any authorised npm repo stage by stage.
This phase builds the skeleton every later phase plugs into.

0. Scope first. Stop and show me the exact text changes before editing:
   (a) the CLAUDE.md scope rule, from "./target" to "./target and workspaces/*/src (cloned only
       from guardian.toml [sources] allow, with recorded consent)";
   (b) the matching change to .claude/hooks/block_out_of_scope.py.
   Apply them only after I say yes.

1. Tools. Write scripts/setup_tools.ps1 and scripts/setup_tools.sh:
   - download pinned Windows/Linux release binaries of syft, grype and osv-scanner from their
     GitHub releases into tools/bin/;
   - verify each against the release checksums file;
   - record versions in tools.lock.
   Then use the tool-probe subagent once per tool against ./target:
   - syft dir: -> CycloneDX and SPDX JSON;
   - grype sbom:<file> -o json;
   - osv-scanner --lockfile / scan source --format json.
   Save trimmed fixtures to tests/fixtures/<tool>/ and docs/tool-notes/<tool>.md (exact command,
   version, JSON key paths, exit codes; note that grype and osv-scanner exit non-zero when they
   find vulnerabilities). Add guardian/tools/bin.py: find_tool(name) -> path or None (tools/bin
   first, then PATH). `guardian doctor` lists each tool and its version, or "missing".

2. Workspaces (guardian/workspace.py):
   - create(source, ref, compare_ref, consent) -> workspace id;
   - the layout from new_plan.md §2;
   - workspace.json holds the source, refs, resolved shas, consent (who and when), and per-stage
     {status, started, finished, input_hash, output_files, tool_versions, error}.
   Sources:
   - a git URL. Allowed only if the host/org matches guardian.toml [sources] allow (default
     empty). Clone into workspaces/<id>/src with:
     - `git -c core.hooksPath=/dev/null -c core.autocrlf=false clone --depth 50 --no-recurse-submodules`;
     - a size limit, [sources] max_mb;
     - then a checkout of the ref. Compare mode also checks out workspaces/<id>/base.
   - an uploaded .zip: safe extraction (reject absolute paths, `..`, symlinks; size limit).
   - a local path: copied, not linked.
   A refused URL gives a clear error naming the allow-list setting. Write consent to audit.jsonl.

3. Stage runner (guardian/pipeline/):
   - a registry of Stage(name, needs=[...], run(ws) -> list of output files);
   - stages: ingest, sbom, graph, vulns, signals, prioritise, investigate, remedies, verify,
     report. Only ingest is real now; the others are stubs that raise NotBuilt;
   - support a stage status "awaiting_approval": a stage that is blocked on a human gate. The
     runner never passes it automatically;
   - run_stage(ws, name, force=False):
     - checks that upstream stages are ok, otherwise reports which are missing;
     - computes input_hash from the upstream output files;
     - marks downstream stages stale when its own outputs change;
     - writes events.jsonl;
   - run_until(ws, name) runs the chain;
   - CLI: `python -m guardian ws create ...`, `python -m guardian stage <name> --ws <id>`,
     `python -m guardian ws status <id>`.

4. Ingest stage (stages/1_ingest.json):
   - every package.json and lockfile in the tree (skip node_modules);
   - for each: package manager, lockfile format/version, workspaces (monorepo);
   - Dockerfiles, CI workflow files;
   - repo size, commit sha, ref.
   If there are several lockfiles, pick the root one by default and record the choice; the
   others are listed for the UI.

5. API (guardian/api/app.py, FastAPI, run with `python -m guardian ui` on 127.0.0.1:8080):
   - POST /api/workspaces, GET /api/workspaces, GET /api/workspaces/{id};
   - POST /api/workspaces/{id}/stages/{name}/run?force=, and /run-until/{name};
   - GET /api/workspaces/{id}/events, Server-Sent Events from events.jsonl;
   - GET /api/workspaces/{id}/files/{path}, read-only, constrained to the workspace dir.
   Jobs run in a thread pool; one stage per workspace at a time. Bind to localhost only.

6. Frontend (guardian/api/static/, plain HTML+CSS+JS, no build step; vis-network from cdnjs,
   pinned):
   - left nav with the 10 stages and status chips (including "awaiting approval");
   - Start page: URL / zip / path, ref, compare-with ref, consent checkbox, Run all, Run up to;
   - every stage page: header with Run / Re-run, status, times, tool versions, Source files
     links, and a body that renders that stage's JSON (generic JSON tree for now);
   - live progress from SSE;
   - light/dark theme; works at 1280px and 390px wide.

Tests: workspace create (path and zip, including a zip-slip rejection), allow-list refusal, stage
dependency and stale marking, API smoke test with FastAPI TestClient, find_tool.

Acceptance:
- `python -m guardian doctor` shows syft, grype and osv-scanner with versions.
- In the browser: enter a local path to a small npm repo, tick consent, run "ingest". The
  Ingest page shows the lockfile(s); Source files open stages/1_ingest.json.
- A URL not on the allow-list is refused with a clear message.
- `python -m pytest -q` passes (v1 tests included).
- Commit "v2 phase 1: workspaces, stage runner, API, UI shell, ingest".
```

---

## Phase 2 — SBOM and dependency graph with evidence (6–8 h)

```text
Read new_plan.md §3 (pages 2 and 3) and §4, and docs/tool-notes/syft.md. Reuse what is generic
in fastpath/build.py (the lockfile inventory, Node.js resolution and BFS paths), moved into
guardian/ecosystems/npm.py, with no demo-specific names.

1. SBOM stage (stages/2_sbom/):
   a) Syft. `syft dir:<src> -o cyclonedx-json=syft.cdx.json -o spdx-json=syft.spdx.json`. Use the
      exact flags from the tool note and a timeout. Exclude node_modules if present.
   b) Lockfile parser. Our own CycloneDX 1.5 from the chosen lockfile (v1, v2 and v3
      package-lock formats). Each component carries name, version, purl, integrity, resolved,
      dev, optional, licence (from the lockfile when present), and its lockfile key and line.
      No lockfile: run `npm install --package-lock-only --ignore-scripts` in a copy and label
      every component "lockfile generated by Guardian".
   c) crosscheck.json: compare by purl. Lists only_syft, only_parser and version mismatches,
      each with a reason code where it can be explained (e.g. bundled deps, workspace links,
      optional platform packages). Counts on both sides.
   The SBOM written for download is Syft's (if it ran) enriched with our dependency
   relationships. Record which one it is.

2. Graph stage (stages/3_graph.json), built by code from the lockfile with Node.js resolution:
   - nodes: id (purl), name, version, direct, dev, optional, depth (shortest), fan_in,
     licence;
   - edges: from, to, range requested, resolved version, kind (prod/dev/optional/peer), and
     evidence: the lockfile key + line of the parent's dependency entry, plus the manifest line
     for root edges;
   - paths: up to K shortest paths from the root per node (K in guardian.toml);
   - stats: total, direct, transitive, max depth, top-20 most depended-on, duplicate versions
     of the same package, cycles;
   - unresolved edges (a range no installed version satisfies) are listed, not dropped.
   Large graphs: also write clusters (group transitive nodes under their top-level dependency),
   so the UI can draw clusters first and expand on click.

3. UI:
   Inventory and SBOM page:
   - totals;
   - a server-paginated, searchable table: name, version, purl, licence, direct/transitive,
     dev/prod, "introduced via" (first path);
   - the cross-check panel (counts and the difference table with reasons);
   - downloads of CycloneDX and SPDX.
   Dependency Graph page:
   - vis-network graph, clustered when there are more than 800 nodes;
   - filters: direct, transitive, dev, prod, depth ≤ k, search box;
   - node side panel: all paths from the root, edge evidence (file:line, excerpt), licence, and
     placeholders for the vulns and signals filled by later phases;
   - tabs: Direct, Transitive, Statistics (with the duplicate-versions and cycles lists).

Tests:
- parser on v1, v2 and v3 lockfile fixtures (tests/fixtures/lockfiles/);
- crosscheck against the Syft fixture;
- the graph on a tiny hand-made lockfile, checking paths, depth, an unresolved edge and evidence
  lines;
- a 5,000-node synthetic lockfile builds in under 10 s.

Acceptance:
- On ./target's head commit (via a local-path workspace) and on one more real npm repo:
  - the SBOM page shows Syft and parser counts and their differences;
  - the graph opens in under 3 s;
  - clicking a transitive package shows its full path from the root with lockfile line evidence.
- Re-running sbom marks graph and every later stage stale.
- Commit "v2 phase 2: SBOM with Syft + parser cross-check, dependency graph with evidence".
```

---

## Phase 3 — Vulnerability detection and supply-chain signals (6–8 h)

```text
Read new_plan.md §3 (pages 4 and 5) and §4, and docs/tool-notes/grype.md and osv-scanner.md.
Reuse guardian/enrich.py (EPSS, KEV) and the OSV client and generic sabotage rules from v1.

1. Vulns stage (stages/4_vulns/):
   - grype.json: `grype sbom:<2_sbom/syft.cdx.json> -o json` (from the tool note);
   - osv-scanner.json: OSV-Scanner on the chosen lockfile;
   - osv-api.json: the v1 OSV querybatch on the parser SBOM, plus advisory details;
   - each tool records ran / not run / failed, its version, duration and exit code. A non-zero
     exit that means "found vulns" is not a failure.
   merged.json:
   - one row per (purl, advisory). Advisory identity is the union of the alias sets
     (GHSA/CVE/OSV ids), so the same issue from three tools is one row;
   - per row: severity (CVSS vector and score if any, GitHub severity), affected range, fixed
     versions, summary, references;
   - reported_by: {grype: yes/no/not run, osv_scanner: ..., osv_api: ...};
   - disagreement: true when a tool that ran did not report it;
   - EPSS and KEV enrichment, with fetch time, or "unknown";
   - graph links: is it direct, the shortest paths, dev or prod.
   Never treat "no tool ran" as "no vulnerabilities".

2. Signals stage (stages/5_signals.json): generic rules only, never name a specific package.
   Package level (from the lockfile and registry metadata, cached):
   - hasInstallScript;
   - resolved from git/http/file instead of the registry;
   - missing integrity;
   - deprecated version;
   - name confusion with popular packages: edit distance and scope tricks against a bundled
     top-packages list, labelled heuristic;
   - very new version (published < N days ago);
   - maintainer count;
   - a version published long after the previous one with a new maintainer.
   Install-script packages: on request (a button, or [signals] inspect_tarballs = true),
   download the tarball into the workspace cache and read package.json scripts and the files
   they reference as text (the v1 static rules: secrets read, network calls, eval/child_process,
   obfuscation). Never extract with npm or run anything.
   Repo level: the v1 rules for Dockerfile (:latest, no digest, curl|sh), CI workflows (actions
   not pinned to a sha, permissions write-all, pull_request_target with checkout), and .npmrc.
   Compare mode: the same rules on base and head, plus a diff (added, removed and version
   changes, new install scripts, new signals), with the commit that introduced each change.
   Every signal has a rule id, a grade (verified fact vs heuristic), evidence (file:line,
   excerpt) and a plain-English "why this matters".

3. UI:
   Vulnerabilities page:
   - tiles by severity;
   - a "tool agreement" summary (all agree / some / one only);
   - a table with severity, package, advisory, fixed-in, EPSS, KEV, reported-by chips (✓ / ✗ /
     not run), direct/transitive and dev/prod;
   - row detail with the advisory text (shown as untrusted text), the paths from the root, and
     links to each tool's raw output.
   Signals page:
   - grouped by rule;
   - each card has evidence lines, the grade and the rule explanation;
   - compare mode adds a "Changed since <base>" section first.
   Graph page: colour vulnerable and signalled nodes, add the "Vulnerable only" filter, and fill
   the side-panel placeholders.

Tests:
- alias merging (three tools, one issue, one row);
- disagreement flag;
- not-run handling;
- each signal rule on a positive and a negative fixture;
- zip and tarball path traversal rejected;
- no package names from demo/ground_truth.yaml appear in detector code (the existing test
  extended to the new modules).

Acceptance:
- On two real repos the Vulnerabilities page shows rows from at least two tools with agreement
  chips. Disable one tool (rename it in tools/bin) and its column shows "not run" everywhere,
  never "0 found".
- Compare mode on ./target (guardian-baseline vs tampered) still finds the planted changes; run
  the scorecard as a regression check and report the numbers.
- Commit "v2 phase 3: vulnerability detection (Grype, OSV-Scanner, OSV) and supply-chain signals".
```

---

## Phase 4 — Prioritised risk report and agent investigation (6–8 h)

```text
Read new_plan.md §3 (pages 6 and 7), guardian/scoring.py, guardian/prioritise.py,
guardian/reachability.py and guardian/agents/. Do not change the formula, weights, bands or
guardrails; adapt their inputs.

1. Prioritise stage (stages/6_prioritised.json):
   Inputs are merged vulns, signals, graph and the source tree, for reachability. Rework the v1
   adapters so the factors come from the v2 files:
   - severity from merged CVSS / GitHub severity;
   - exploitability from KEV / EPSS;
   - reachability tiers R0–R3 from the graph (loaded at all?) and static import/call search in
     the repo's own source;
   - exposure from dev/prod plus repo hints (a Dockerfile EXPOSE, a server framework in direct
     deps), labelled heuristic;
   - fix availability from fixed versions.
   Per item: score, band, factor table (value, grade, source file and line), guardrails fired,
   and confidence plus its range.
   Code-written explanations (templates, no LLM):
   - "why": one sentence naming the two biggest factors;
   - "vs neighbour": why it ranks above the next item and below the previous one, naming the
     factor that makes the difference;
   - "what would change it": e.g. "if the app called defaultsDeep this would be R3 → 87".
   Also write the demoted list (high CVSS but low priority, and why).

2. Investigate stage (stages/7_investigation.json):
   - run the Change Detective (signals and changes), Risk Analyst (vulns) and Refuter (both) on
     the top N (guardian.toml), with the v1 runner, tools and check_claim;
   - agent tools point at the workspace (src, stages/*, tarball cache), not ./target;
   - record per agent output: inputs given, tool calls and minted evidence ids, claims with
     quote check results, model, tokens, and **what code did with it** (e.g. "Refuter verdict
     weakened → confidence −0.1, rule R-2", "Risk Analyst tier change R1→R2 rejected: no call
     site evidence");
   - offline mode and API errors give "skipped" with the reason, per item;
   - re-running a single agent on a single item is possible
     (POST .../stages/investigate/run?agent=&item=).

3. UI:
   Prioritised Risk page, a long report:
   - a formula box;
   - the top-N table with factor bars;
   - per item, an expandable report: why, vs neighbour, what would change it, factor table with
     grade chips and source links, guardrails, confidence range;
   - a demoted section;
   - an "Explain any item" search.
   Agent Investigation page:
   - a flow diagram (code → agent → code check → file);
   - per item, three agent cards: Change Detective, Risk Analyst, Refuter;
   - each card shows its claims (AI · inferred, quote kept / dropped), its tool calls and what
     code did with it;
   - a re-run button per card;
   - a header with provider, models, tokens and key status (count only, never the key).

Tests:
- factor adapters on fixture stage files;
- explanation templates (deterministic text);
- the investigate stage with a fake LLM client (scripted responses) covering success, a dropped
  quote, schema failure and a 503 skip;
- agents never write to stages other than 7.

Acceptance:
- On a real repo the Prioritised page explains the top 10 with "why" and "vs neighbour", and
  every factor links to its file.
- With a Gemini key: at least the Refuter and one other agent produce outputs, shown with quote
  check results.
- With GUARDIAN_OFFLINE=1 every card says skipped and the scores are identical.
- Commit "v2 phase 4: prioritised risk report and agent investigation".
```

---

## Phase 5 — Per-remedy approval, sandbox verification, report, hardening (9–12 h)

```text
Read new_plan.md §3 (pages 8, 9 and 10) and §6, guardian/remediate.py, guardian/validate.py,
guardian/report.py and guardian/review.py. Prerequisite: Docker Desktop installed. If it is not,
build everything anyway and the container check reports "not run".

1. Remedies stage (stages/8_remedies/), the human gate:
   - point remediate.py at the workspace: candidates are generated and predicted in a throwaway
     clone under workspaces/<id>/work/, with `npm install --package-lock-only --ignore-scripts`;
   - the Remediation Planner explains and chooses among gate-passing candidates only;
   - plan files, patches, patch_sha256 and plan_hash as in v1;
   - also check that the plans don't conflict when applied together (two plans changing the same
     package to different versions). Conflicting plans are flagged and cannot both be approved.
   Per-remedy decisions, made in the UI only:
   - POST .../plans/{id}/decision {decision: approve|reject|defer, approver, plan_hash, note};
   - the server re-computes plan_hash and refuses a mismatch;
   - every decision goes to audit.jsonl;
   - approvals are accepted only through the HTTP API from the UI, never from the agent layer
     or a stage; a test enforces that no code path under guardian/agents or guardian/pipeline
     can call it;
   - a decision can be changed until the batch is sent.
   After the plans are generated the stage status is "awaiting_approval (k of n decided)".
   POST .../remedies/send-to-sandbox (enabled when every plan is decided and at least one is
   approved):
   - freezes the approved set as approved_set.json (plan ids + hashes + approvers);
   - marks remedies ok;
   - starts the verify stage automatically.

2. Verify stage (stages/9_verify/), the proof:
   - fresh clone of the workspace source into work/verify-<n>/ (the uploaded src is never
     modified);
   - apply every plan in approved_set.json in order, checking each patch_sha256 again.
   Checks, each recorded as pass / fail / not run with log file, duration and evidence:
     1. apply: patches apply cleanly;
     2. install: `npm ci --ignore-scripts`; the lockfile matches the predicted versions;
     3. tests and build, the only step that runs repo code, so container only:
        - `docker run --rm --network none --memory 2g --cpus 2 --pids-limit 512 --read-only
          --tmpfs /tmp -v <clone>:/app -w /app node:<engines.node or LTS>@sha256:<pinned digest>`;
        - inside it: `npm rebuild` (scripts allowed only here), `npm test`, then `npm run build`
          if a build script exists;
        - dependencies are installed in a networked step before the test step, still in a
          container, still with no secrets;
        - a time limit;
        - "no test script" is reported as "not run (repo has no tests)", not as passed;
        - Docker missing gives "not run";
        - parse the pass/fail counts from the output when the format is recognisable (mocha,
          jest, tap), otherwise use the exit code;
     4. rescan: the stage 2–5 tools (Syft, Grype, OSV-Scanner, OSV API, signals) on the patched
        tree, written under 9_verify/rescan/;
     5. compare, before vs after:
        - per approved plan, its targeted advisories: gone / still present;
        - new advisories introduced (must be 0);
        - new signals;
        - SBOM diff (added, removed, changed);
        - remaining advisories not covered by any approved plan, listed and never hidden;
     6. policy gate on the patched tree.
   Verdict, computed by code:
   - VERIFIED only if checks 1–6 all passed, the tests ran and passed, every targeted
     advisory is gone, nothing new appeared, and each tool that ran in stage 4 also ran in the
     rescan;
   - PARTIAL if any check is "not run";
   - FAILED if any check failed. On FAILED:
     - run the Diagnostician on the failing check's log;
     - mark the responsible plan(s) "needs revision" and send the pipeline back to Remedies,
       where a new plan needs a new approval;
     - verify never retries on its own.
   Write verify.json with all of the above, plus the headline numbers.

3. Report stage (stages/10_report/):
   - report.json built from whatever stages are present, each missing stage listed as "not run",
     and validated against the schema (extend schemas/guardian-report.schema.json with the v2
     sections);
   - report.html, the printable long page with the sections of the UI pages and source links;
   - report.md;
   - vex.json (fixed only for validated plans with OSV evaluated; not_affected only by a human
     accept);
   - an audit chain check result.

4. UI:
   Remedies page:
   - per plan: candidates tried, prediction, gate, choice and why, rejected alternatives, diff
     viewer, rollback, plan_hash;
   - Approve / Reject / Defer buttons; Approve opens a form with the approver name and shows
     the hash being approved;
   - conflict warnings;
   - a progress bar "k of n decided";
   - the "Send approved remedies to sandbox" button, after which the UI jumps to the Sandbox tab.
   Sandbox Verification tab:
   - the approved set (who approved what, which hash);
   - a live check list with spinners, then pass / fail / not run, each opening its log;
   - the test results (counts and failing test names);
   - a before/after table per plan: targeted advisories gone / present;
   - the "new vulnerabilities" box (must read 0);
   - the SBOM diff;
   - a remaining-advisories list;
   - a big verdict banner: VERIFIED / PARTIAL (with what didn't run) / FAILED (with the
     Diagnostician card and a "back to Remedies" link);
   - every number links to its file in 9_verify/.
   Report page:
   - a stage coverage list;
   - downloads (HTML, MD, JSON, VEX, audit log);
   - "open printable report".

Tests:
- decision API: hash mismatch refused, unknown plan refused, decision after send refused;
- approvals cannot be made from agents or pipeline code;
- the approved-set freeze;
- plan conflict detection;
- the verify verdict table:
  - all pass → VERIFIED;
  - tests not run → PARTIAL;
  - a targeted advisory still present → FAILED;
  - a new advisory → FAILED;
  - a tool missing in the rescan → PARTIAL;
- the docker command builder includes --network none and no env passthrough;
- the uploaded src is unchanged after verify (hash the tree before and after).

5. Hardening:
   - run the whole flow from the UI on three different allow-listed npm repos: one small, one
     with more than 1,000 packages, and one monorepo or without a lockfile. Fix what breaks.
     Record timings per stage in docs/KNOWN_LIMITATIONS.md;
   - limits: clone size, packages, tool timeouts, a concurrent-workspace cap. Each one has a
     clear UI message;
   - security pass:
     - the file endpoint can't leave the workspace;
     - a zip can't escape;
     - the URL allow-list can't be bypassed (credentials in the URL, `file://`, `ssh`, redirects,
       IP literals);
     - no secrets appear in events, reports or LLM prompts (a test greps outputs for key shapes);
   - one e2e test on a tiny fixture repo under tests/fixtures/repos/ (create → all stages offline
     → report validates).

6. Docs:
   - README: what v2 is, how to install the tools, run the UI, analyse a repo, and run a stage
     alone;
   - docs/ARCHITECTURE.md: the v2 section with the stage diagram;
   - docs/KNOWN_LIMITATIONS.md: npm only, reachability is static, scale limits, the not-run
     checks;
   - demo script: URL → graph → vulns → prioritised → agents → remedy → approve → validate →
     report, in 6 minutes.

Acceptance:
- On a fresh workspace from the UI, every stage runs individually and via Run all.
- On a real repo:
  - two remedies are approved and one rejected in the UI;
  - "Send to sandbox" starts verify automatically;
  - the Sandbox tab shows the patches applied, a clean install, `npm test` passing in the
    container, a rescan with every targeted advisory gone and 0 new, and the verdict VERIFIED;
  - the rejected remedy's advisories appear under "remaining".
- Force a failure (approve a plan whose version breaks the tests). The verdict is FAILED, the
  Diagnostician explains it, and the plan is back in Remedies needing a new approval.
- The report downloads, and report.json validates.
- Three repos have been processed; their timings are recorded.
- `python -m pytest -q` passes, plus `python -m pytest -q -m e2e` on the fixture repo.
- Commit "v2 phase 5: per-remedy UI approval, sandbox verification, report, hardening".
```

---

## Unstick prompt (use when a phase stalls twice on the same problem)

```text
We are stuck on: <one line>. Stop changing code. List (1) what you tried, (2) the exact error
output, (3) three hypotheses ranked by likelihood with the one command that would confirm or
refute each. Run only those commands, then propose the smallest change. Do not widen scope.
```
