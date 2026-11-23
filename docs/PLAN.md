# Two-day plan

Assumes roughly nine working hours per day and one person driving Claude Code. Times are
budgets, not promises. Every phase has a prompt in `docs/PROMPTS.md` with the same number.

## Scope

**Will build (core, maps one-to-one to the brief):**
discover → SBOM → dependency graph → CVE detection → change/anomaly detection → evidence view
(Day 1); prioritisation with explainable score and confidence → non-CVE investigation →
remediation plan → human approval → build/test/rescan validation → report (Day 2).

**Will build (differentiators):** evidence ledger with typed claims; scorecard against planted
ground truth with hold-out seeds; refuter agent; package capability diff; reachability with a
file:line witness; and the centrepiece, a **closed agent loop shown live**: plan → human
approval → validation fails → agent diagnoses → new plan → second approval → verified.

**Five runtime agents, no more:** Change Detective, Risk Analyst, Refuter, Remediation
Planner, Diagnostician. Discovery, vulnerability matching, scoring, policy and validation
checks are deterministic code. (A sixth, the Reporter, is optional in phase 13.)

**Three required external tools:** syft, grype, osv-scanner (plus docker). Everything else
(hadolint, zizmor, guarddog, conftest, cosign, semgrep, trivy) is optional extra evidence: use
it if it installs in five minutes, otherwise our own rules cover the requirement.

**Stretch, in this order, only when the core is green:** policy-as-code gate (small; built in
phase 10 if conftest installed) → VEX export of not-affected candidates → remediation patch +
PR text as local files → continuous-monitoring replay → provenance check with cosign →
advanced package risk on a synthetic fixture.

**Will not build:** multi-language support, opening pull requests anywhere, dynamic package
sandboxing, deployment, auth, multi-user, SARIF, a long-running monitor daemon. These go in
Known Limitations.

**Cannot do (rules):** scan anything but the target, publish packages, use real credentials,
auto-merge. Design choices already respect these; see `CLAUDE.md`.

## Day 1 — "Guardian's Eyes" (visibility and detection)

| # | Phase | Budget | Done when |
|---|---|---|---|
| 0 | Setup, preflight, prove the target builds, verify the three required tools | 75 min | `guardian doctor` truthful; both target branches build and pass the smoke test; `docs/tool-notes/*.md` written from real runs |
| 1 | Skeleton: package, config, ledger, audit, events, CLI | 50 min | unit tests green; an offline scan run writes evidence, events and a verifiable audit chain |
| 2 | Discover: inventory, SBOM, graph, origins, Dockerfile + workflows | 60 min | `guardian discover` writes SBOM + inventory for both refs; paths for any component |
| 3 | Vulnerabilities: scan, merge, fixes, paths, EPSS/KEV | 45 min | findings with CVE, severity, fix, path; counts reconcile with the raw scanner |
| 4 | Changes: diff + detectors + capability diff + scorecard | 90 min | all seven `GT-C*` entries detected; negative controls clean; base == head gives no change findings |
| 5 | First agent: Change Detective | 45 min | each change finding carries an AI assessment with checked support; offline mode still works |
| 6 | UI v1: Overview, Inventory, Changes, Findings + evidence drawer, live trace | 90 min | the Day-1 story can be clicked through without the terminal |
| 7 | Hold-out seeds, second app, Day-1 report, replay recording, checkpoint rehearsal | 40 min | `/checkpoint day1` passes; 3-minute checkpoint rehearsed twice |

Total 495 of 540 minutes: 45 minutes of slack. Use it; do not plan it away.

**Day-1 cut lines (if behind at the listed moment):**
- After phase 3 and more than 30 min behind: in phase 4 build only the detectors for look-alike
  name, install script, image tag and unpinned action; leave capability diff for Day 2 morning.
- Phase 6 not showing real data 75 minutes in: switch UI to Streamlit (logic is UI-free).
- Never cut: evidence ledger, the Changes view, the scorecard. They are the Day-1 story.

**Day-1 checkpoint answer** ("what is in the application, what changed, what appears risky"):
Inventory page → Changes page → Findings page, in that order, three minutes. Script in
`docs/DEMO.md`.

## Day 2 — "Guardian's Brain & Shield" (reasoning, action, proof)

| # | Phase | Budget | Done when |
|---|---|---|---|
| 8 | Prioritise: reachability tiers, scorer, confidence, bands | 75 min | ranked list; the reachable lodash finding outranks an unreachable higher-CVSS one; unknowns shown |
| 9 | Risk Analyst + Refuter + investigation record | 60 min | top findings carry an inferred reachability judgement and a refuter verdict |
| 10 | Remediation: candidates, dry-run prediction, policy gate, approval | 75 min | a plan with alternatives, prediction, rollback, policy result; approval recorded with plan hash |
| 11 | Validate + the closed loop (fail → diagnose → re-plan → verify) | 100 min | the hero finding goes through the whole loop live; nothing touches the target repo |
| 12 | Report + exports + remaining UI pages | 60 min | HTML/MD + JSON report, VEX; Remediation, Validation, Report pages work |
| 13 | Stretch pack (optional; take in order, stop at the time box) | 30 min | each finished item demoable in under 30 s |
| 14 | Docs: README, architecture diagram, Responsible AI note, limitations | 30 min | a stranger can set up and run from the README |
| 15 | Freeze: e2e test, UI test, replay recording, three timed rehearsals | 60 min | `/checkpoint final` passes; demo rehearsed three times, under time |

Total 490 of 540 minutes. Phase 15 **is** the freeze: no new features once it starts.
Documentation is written as you go (every phase adds its row to the README feature table and
its limitations), so phase 14 is assembly, not authorship.

**Day-2 cut lines:**
- Phase 11 is the heart of Day 2. If docker builds are flaky, validate with `npm ci
  --ignore-scripts` + `node --check` + a `node -e "require('./app')"`-style start check + rescan
  inside the clone and label the container build "not run". Do not fake a pass.
- If behind after phase 10: skip phase 13 entirely.
- If behind after phase 11: phase 12 produces Markdown + JSON only, no VEX, no HTML polish.

## Parallel work (optional, if a second Claude Code session is available)

From phase 6 onward, run UI work in a second git worktree
(`git worktree add ../guardian-ui -b ui && cd ../guardian-ui && claude`). The UI reads only
`runs/<run_id>/` files and the event stream, so it does not collide with pipeline work. Merge
at the end of each phase. One session at a time edits `guardian/contracts.py`.

## Rhythm for every phase

1. Fresh session (`/clear`), then paste the phase prompt (or type `/phase N`).
2. Let Claude plan first for multi-file phases (Shift+Tab to plan mode), approve the plan.
3. Claude builds, runs the acceptance commands, fixes until green.
4. Ask for the `skeptic-reviewer` subagent on the diff when the phase touched findings or claims.
5. Commit. Tick the phase in `docs/PROGRESS.md`. Push is your job, not Claude's.

## Risks and what to do

| Risk | Mitigation |
|---|---|
| Venue network is bad | Phase 0 warms caches and pre-pulls images; replay mode; all JS/CSS local |
| Anthropic API slow or down during demo | `--mode replay` with a "REPLAY" badge; offline mode proves the deterministic core |
| A scanner cannot be installed | `scripts/lockfile_sbom_diff.py` is a stdlib SBOM + diff fallback; the OSV API can replace grype; record the gap as not evaluated |
| Docker unavailable on the laptop | degrade validation as described above; say so |
| goof does not build today (old deps, `npm update` in its Dockerfile) | phase 0 builds and smoke-tests **both** branches first and fixes the baseline (documented) before anything depends on it |
| Scorecard looks rigged (detectors tuned on the seeds) | hold-out seeds added after detectors are frozen; a second application; a test that fails if detector code names seeded packages |
| Claude Code drifts or overbuilds | one phase per session, acceptance commands, `/checkpoint` audits against `docs/requirements.yaml` |
| Overclaiming in the pitch | `docs/DEMO.md` wording; scorecard shows misses on purpose |
