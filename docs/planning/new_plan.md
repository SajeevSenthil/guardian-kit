# Guardian v2 — any-repo web app: plan

Status: **plan only, nothing built yet.** This file says what we build, why, in what order and how
long it should take. The paste-in prompts for each phase are in `new_prompts.md`.

---

## 1. What changes and why

| Today (v1) | v2 |
|---|---|
| Scans only `./target`, a prepared copy of one app with 4 planted commits | The user pastes a **git URL** (or uploads a `.zip`, or gives a local path); Guardian works on any npm project |
| Detection needs two refs (`guardian-baseline` vs `tampered`) | **Snapshot mode is the default:** one commit is analysed on its own. **Compare mode is optional:** pick two refs of the same repo to see what changed |
| SBOM and vulnerabilities from our own stdlib code (lockfile parser + OSV API) | **Real SBOM tools:** Syft makes the SBOM, Grype and OSV-Scanner match vulnerabilities. Our parser stays, as a cross-check and to add graph evidence |
| A CLI plus a static HTML page made after the run | A **web app** with one section per stage. Each stage can be run, re-run and inspected separately, and the report is built from whatever stages have run |
| Demo scorecard against `demo/ground_truth.yaml` | Dropped from the main flow. Kept as a regression test only |

What stays (it is generic and already tested):
- the scoring formula and its guardrails;
- the 5 agents, with their evidence check, schema validation and the rule that code decides;
- remediation in throwaway clones, the human approval bound to the plan hash, and validation;
- the hash-chained audit log.

### Scope rule: must be settled before Phase 1

The organiser's brief (`docs/HACKATHON_BRIEF.md`, "Out of scope") forbids *"accessing repositories,
registries or infrastructure outside the team's authorized sandbox"*. `CLAUDE.md` says to scan only
`./target`, and a project hook enforces this. An "analyse any URL" box conflicts with both.

v2 keeps to the rule by design, not by trust:
- **Allow-list.** `guardian.toml [sources] allow = [...]` lists the hosts or organisations that may be
  cloned. The default is empty, so local paths and uploaded zips only. Any other URL is refused,
  and the refusal is shown in the UI.
- **Consent.** The user must tick "I am authorised to analyse this repository". The tick is written
  to the audit log with the URL and the commit sha.
- **Sandbox workspace.** Clones go to `workspaces/<id>/src`, never into `./target`. They use
  `--depth`, `--no-recurse-submodules`, git hooks disabled and a size limit.
- **Static only.** Code from the repo or its packages is never run. `npm` only ever runs with
  `--ignore-scripts`, and only in a clone.
- **Docs and hook.** `CLAUDE.md` and the hook are updated to "`./target` **and** `workspaces/*/src`",
  with the human's sign-off, never silently.

**Decision needed from you:** ask the organisers whether public repos you choose count as your
"authorized sandbox". If not, the demo uses local paths and zips only. The design doesn't change.

---

## 2. Target architecture

```
 Browser (single page, one section per stage)
   │  REST + Server-Sent Events (progress)
 FastAPI server  guardian/api/        ← thin: validates input, starts jobs, serves files
   │
 Stage runner    guardian/pipeline/   ← stage registry; each stage declares its inputs and outputs
   │
 Stages (one module each, each also runnable from the CLI):
   1 ingest → 2 sbom → 3 graph → 4 vulns → 5 signals → 6 prioritise → 7 investigate → 8 remedies
     → [HUMAN APPROVES EACH REMEDY IN THE UI] → 9 sandbox verify → 10 report
   │
 Tool adapters   guardian/tools/      ← syft, grype, osv-scanner, npm, git, OSV/EPSS/KEV/deps.dev APIs
   │
 Workspace store workspaces/<id>/     ← every stage writes JSON here; the UI only reads these files
```

**Why this shape:**
- **Each stage is a pure function:** files in, files out. That is what makes "run any section
  separately" possible. The UI's *Run* button and `python -m guardian stage <name> --ws <id>` call
  the same function.
- **The stage registry knows the dependency graph.** If you run *vulns* before *sbom*, it offers to
  run *sbom* first. Each stage records a hash of its inputs, so if an upstream stage is re-run its
  downstream sections show **stale**.
- **FastAPI instead of NiceGUI.** FastAPI is already installed (0.162.4); NiceGUI is not. A plain
  REST API also lets the CLI, tests and the UI share one code path. The frontend is static
  HTML + JS (no build step), with vis-network for graphs as in v1. `CLAUDE.md` gets the change
  noted.
- **The UI reads only files that stages wrote.** Every number on screen has a "source file" link,
  as on today's review page. This is the honesty rule from v1, kept.

### Workspace layout
```
workspaces/<id>/
  workspace.json          url or path, ref(s), sha(s), consent, created, stage status + input hashes
  src/  [base/]           checked-out code (base only in compare mode)
  stages/
    1_ingest.json         repo facts: manifests found, lockfile version, package manager, size
    2_sbom/               syft.cdx.json, syft.spdx.json, parser.cdx.json, crosscheck.json
    3_graph.json          nodes, edges with evidence, paths, stats
    4_vulns/              grype.json, osv-scanner.json, osv-api.json, merged.json (with agreement)
    5_signals.json        supply-chain risk signals with evidence
    6_prioritised.json    scores, factors, reasons, confidence
    7_investigation.json  agent outputs, checked claims, tool calls
    8_remedies/           plans, patches, predictions, approvals (one file per plan, bound to plan_hash)
    9_verify/             sandbox clone results: per-check logs, test output, before/after rescans, verdict
    10_report/            report.json, report.md, report.html, vex.json
  events.jsonl  audit.jsonl
```

---

## 3. The UI: pages and what each must show

A left navigation lists the stages, each with a status chip: not run / running / ok / stale / failed.
Each page has the same header: **Run this stage**, **Re-run**, the last run time, the tool versions
used, and "Source files". Long scrollable pages are fine.

1. **Start**
   - git URL / zip upload / local path;
   - an optional ref, and an optional "compare with" ref;
   - the consent tick;
   - **Run all**, or **Run up to…** a chosen stage.
2. **Inventory and SBOM**
   - totals: packages, direct, transitive, dev, licences;
   - a searchable table: name, version, purl, licence, direct/transitive, dev/prod, introduced via;
   - a **tool cross-check** panel: Syft found N, the lockfile parser found M, the differences listed
     with the reason for each;
   - downloads of CycloneDX and SPDX.
3. **Dependency graph**
   - an interactive graph with filters: direct only, transitive only, dev/prod, vulnerable only,
     depth ≤ k, search;
   - clicking a node opens a side panel:
     - why it is installed: every path from the root, e.g. `app → express → body-parser → qs`;
     - its **evidence**: the lockfile entry and line, and the manifest line for direct dependencies;
     - its licence, its vulnerabilities and its signals;
   - large graphs cluster by top-level dependency, so the page stays fast with more than 5,000 nodes;
   - tabs: Direct, Transitive, Vulnerable, Graph statistics (depth, fan-in, most depended-on).
4. **Vulnerabilities**
   - one row per (package, advisory), merged across Grype, OSV-Scanner and the OSV API by alias
     (GHSA/CVE);
   - columns: severity, CVSS, fixed-in, and **which tools reported it** (a tools-disagree flag
     when they differ);
   - "unknown" rows when a tool didn't run;
   - each row links to its graph paths.
5. **Supply-chain signals** (risks with no CVE)
   - install scripts (from the lockfile's `hasInstallScript`; the tarball is read statically on
     request);
   - name-confusion with popular packages;
   - deprecated or yanked versions;
   - packages that aren't pinned or are resolved from git or http;
   - missing integrity hashes;
   - registry metadata: maintainer count, age of the version, publish time vs release history;
   - in the repo itself: Dockerfile `:latest`, unpinned CI actions, `permissions: write-all`,
     `curl | sh`;
   - in compare mode, what changed between the two refs.
6. **Prioritised risk** (the detailed report)
   - the formula, with every factor's value, grade (verified / heuristic / inferred / unknown) and
     source;
   - a sentence in plain English for **why this rank**, generated by code from the factors;
   - **why it is above or below its neighbour**;
   - guardrails that fired;
   - confidence, with the range across the factors it wasn't sure about;
   - a demoted list.
7. **Agent investigation**
   - for each top-N item:
     - Change Detective, Risk Analyst and Refuter cards;
     - claims marked AI · inferred, with quote check results;
     - the tool calls each agent made and the evidence ids they minted;
     - what code did with each output (applied, ignored, and why);
   - a "re-run this agent" button;
   - in offline mode, each card shows "skipped" with the reason.
8. **Remedies** (the human gate)
   - per plan: the candidates tried, the predicted result, the policy gate, the chosen fix and why,
     rejected alternatives, the patch diff, the rollback and the plan hash;
   - **each remedy is approved or rejected individually in the UI**, by a typed name and bound to
     the plan hash that is shown on screen. Every decision goes to the audit log;
   - the pipeline **waits** here: the stage shows *awaiting approval (2 of 5 decided)*;
   - once every plan is approved, rejected or deferred and the human clicks **Send approved
     remedies to sandbox**, the next stage starts automatically;
   - nothing unapproved ever reaches the sandbox.
9. **Sandbox verification** (its own tab: the proof)
   - takes **all approved remedies together** and applies them in a fresh throwaway clone of the
     uploaded repo, `workspaces/<id>/work/verify-<n>/`. The uploaded source is never touched;
   - runs the checks in order, each shown live as pass / fail / not run, with its log:
     1. patches apply cleanly (`git apply`, patch hashes match the approved ones);
     2. clean install: `npm ci --ignore-scripts`;
     3. the lockfile matches the predicted versions;
     4. **the repo's own tests (`npm test`) and build (`npm run build` if present)**;
     5. **full rescan with the same tools as stage 4** (Grype, OSV-Scanner, OSV API) and
        signals, on the patched tree;
     6. before/after comparison: the vulnerabilities each remedy targeted, now gone or still
        present; new vulnerabilities introduced (must be 0); SBOM diff;
     7. policy gate re-checked;
   - running the repo's tests **executes the repo's code**, so check 4 runs only inside an
     isolated container (Docker): no network after install, no host mounts except the clone, no
     environment secrets, CPU, memory and time limits. **If Docker is not available, check 4
     shows "not run", never "passed".** That is the one place code from the repo is allowed to
     run, which keeps the `CLAUDE.md` rule ("`--ignore-scripts` unless inside the validation
     container");
   - verdict, computed by code:
     - **Verified** only when every check passed, including tests in the container, and the
       rescan shows every targeted vulnerability gone with nothing new;
     - **Partial** if any check is "not run";
     - **Failed** if any check failed. Then the Diagnostician explains the failure, the plan
       goes back to Remedies, and it needs a new approval;
   - a big honest headline: *"Targeted vulnerabilities fixed: 12 of 12 · new: 0 · tests: 148
     passed · remaining (not addressed by an approved remedy): 31"*. "No vulnerabilities" is
     shown only if the rescan really returns zero from tools that ran.
10. **Report**
   - built from whatever stages are present (missing stages say "not run");
   - downloads: HTML, Markdown, JSON (validated against the schema), CycloneDX VEX, and the audit
     log with its chain check.

---

## 4. Real tools: what each one does in v2

| Tool | Role | If it's missing |
|---|---|---|
| **Syft** | SBOM of the source tree (`dir:` scan), CycloneDX and SPDX JSON | Our lockfile parser's SBOM is used, and the page says "Syft not run" |
| **Grype** | Vulnerability matching on the Syft SBOM (`sbom:` input) | That column shows "not run" |
| **OSV-Scanner** | Vulnerability matching on the lockfile | That column shows "not run" |
| OSV API (current code) | Third source, plus advisory details (affected functions, ranges) | Cached, or "unknown" |
| `npm` (`--package-lock-only --ignore-scripts`) | Creates a lockfile when the repo has only `package.json`; also used for remediation predictions | No lockfile means the graph is marked partial |
| EPSS, CISA KEV | Exploitability factor | "unknown"; confidence drops |
| deps.dev / npm registry metadata | Maintainers, version age, deprecations, provenance | Those signals show "unknown" |
| Optional: Trivy, Hadolint, zizmor, OpenSSF Scorecard | Extra evidence on the Signals page | Hidden when not installed |

Rules carried over from `CLAUDE.md`:
- every tool is **probed once on this machine** first, with its exact version, command and JSON
  paths written to `docs/tool-notes/<tool>.md` and a fixture saved;
- versions are recorded in `tools.lock`;
- wrappers return small typed summaries plus evidence ids, never raw JSON to a model.

On this machine Syft, Grype, OSV-Scanner, Trivy and Docker are currently **missing**. Phase 1
downloads the Windows release binaries into `tools/bin/` and checks their checksums.

**Why tools and our own code together:** the tools give industry-standard SBOMs and matching. Our
code gives what the tools don't, such as edge-level evidence (which lockfile line creates each
edge), paths from the root, reachability, and signals. When the two disagree, the UI shows it
instead of hiding it.

---

## 5. The five phases

Estimates assume one person working with Claude Code in focused sessions, including tests and fixing
what breaks. Ranges cover the usual surprises (tool flags on Windows, large repos).

| # | Phase | Delivers | Estimate |
|---|---|---|---|
| 1 | **Foundation: workspaces, stage runner, API, UI shell, ingest** | Paste a URL, zip or path; repo checked out safely; the pages exist with Run buttons; stage status and SSE progress; tools installed and probed | **5–7 h** |
| 2 | **SBOM and dependency graph** | Syft SBOM + parser cross-check; graph with per-edge evidence, paths, filters, clustering; Inventory and Graph pages complete | **6–8 h** |
| 3 | **Vulnerabilities and supply-chain signals** | Grype + OSV-Scanner + OSV merged with agreement; EPSS/KEV; generic signals in snapshot and compare modes; Vulnerabilities and Signals pages | **6–8 h** |
| 4 | **Prioritised risk and agent investigation** | v1 scoring moved onto the new stage outputs; reasons and neighbour comparison; the 3 investigation agents on top-N from the UI; Prioritised and Investigation pages | **6–8 h** |
| 5 | **Remedies with per-remedy UI approval, sandbox verification, report, hardening** | Approve each remedy in the UI, which advances the pipeline; a Sandbox tab that applies the approved remedies in a clone, installs, runs tests in a container, rescans and proves before/after; Report page with all exports; tested on 3 repos; docs | **9–12 h** |
| | **Total** | | **32–43 h** (about 4–5 focused days; 3–4 if Phase 5 hardening is cut) |

**Prerequisite for Phase 5:** Docker Desktop must be installed. It is missing on this machine now.
Without it, sandbox verification still applies the fixes, installs, rescans and proves before and
after, but the "tests pass" check honestly shows "not run".

**Cut lines** (if time runs out, stop here and still have something that works end to end):
- after Phase 2: SBOM and graph for any repo;
- after Phase 3: the whole of "yesterday's part" for any repo;
- after Phase 4: prioritisation and investigation;
- if Phase 5 is short, keep the per-remedy approval and Sandbox tab (the proof) and cut the
  hardening on extra repos.

### Main risks and how each is handled
| Risk | Mitigation |
|---|---|
| Huge repos or monorepos (several lockfiles, more than 10k packages) | Ingest lists every lockfile and the user picks one (default: the root); the graph clusters; tables page on the server; size and time limits |
| Repos without a lockfile | Generate one with `npm install --package-lock-only --ignore-scripts` in the workspace, labelled **generated, not the repo's own** |
| Tools behave differently on Windows | Probe first (Phase 1); pass absolute paths; fixtures in tests |
| Rate limits on OSV, EPSS or deps.dev | Batch, cache under `.cache/` with the fetch time, show "unknown" rather than 0 |
| Gemini overload (seen yesterday: 503s and timeouts) | Key rotation is already in place; per-agent re-run buttons; "skipped" is shown, never hidden; nothing depends on the AI |
| Scope rule | Section 1: allow-list, consent, sandbox, static only |
| Losing v1 | v1 code and `./target` stay; v2 lives in new modules; v1 tests keep passing |

---

## 6. Definition of done (v2)
- Three different public npm repos on the allow-list, including one with more than 1,000 packages,
  go from URL to report entirely in the UI.
- Each stage can be re-run alone, and its downstream sections show stale.
- Each remedy is approved in the UI, and only approved remedies reach the sandbox. The Sandbox tab
  shows, for at least one repo:
  - every approved fix applied;
  - a clean install;
  - the repo's tests passing in the container;
  - a rescan with 0 new vulnerabilities and every targeted vulnerability gone;
  - the verdict **Verified**.
- Every number in the UI links to the file it came from. Unknown is never shown as zero.
- Each tool's column on the Vulnerabilities page shows whether that tool actually ran, plus its
  version.
- Unit tests pass, plus one e2e test on a small fixture repo committed under `tests/fixtures/repos/`.
- `README.md`, `docs/ARCHITECTURE.md` and `docs/KNOWN_LIMITATIONS.md` are updated, and
  `implementations.md` gets one entry per phase.
