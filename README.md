# Supply Chain Guardian

**Know what you build. Trust what you ship.**

Guardian compares a trusted version of an application with its current version. It does four
things:

- lists everything the application is built from;
- finds known vulnerabilities;
- spots suspicious changes such as look-alike packages, hijacked updates, loosened Docker and
  CI settings, and install scripts that touch secrets;
- backs every warning with proof: the file, the line and the commit.

Built for the Bosch "Software Supply Chain Guardian" hackathon.

| | Status |
|---|---|
| **Day 1: the Guardian's eyes.** SBOM, dependency graph, vulnerabilities, suspicious changes, evidence dashboard | **Implemented:** [`fastpath/`](fastpath/README.md) |
| **Day 2: brain and shield.** AI agents, prioritisation, fix plan, human approval, validated remediation, report | **Designed, not built yet:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |

---

## Quick start

From this folder, using Git Bash on Windows or any shell on macOS or Linux:

```bash
bash scripts/make_demo_target.sh     # once: builds ./target, the sample app with planted risks
python fastpath/build.py             # ~20 s: writes fastpath/out/
start fastpath/out/guardian.html     # Windows  (macOS: open, Linux: xdg-open)
```

You need Python ≥ 3.11.4, git, and Node/npm (npm is only used to build the demo target).
Internet access is optional: `python fastpath/build.py --offline` uses cached vulnerability
data, and any lookup it can't answer shows "not evaluated".

**On Windows, building the target needs three workarounds:**
- `python3` opens the Microsoft Store instead of Python;
- git's automatic line-ending conversion breaks the target's shell scripts;
- VS Code locks the new folder, so the final rename fails.

Each fix is in [`fastpath/README.md`](fastpath/README.md#windows-notes-building-the-demo-target).

---

## 1. The problem

A modern application is mostly other people's code. Our sample app declares **37**
dependencies, but installing it pulls in **982 unique packages**, installed in **1,276** places.
Developers review the 37 they chose. Attackers target the rest:

| Attack | Real-world example |
|---|---|
| A package with a look-alike name (`lodahs` instead of `lodash`) | npm typosquatting campaigns |
| A "patch" release that quietly adds an install script | 2025–26 npm worm droppers |
| A CI action referenced by a movable tag | tj-actions/changed-files compromise, March 2025 |
| A Docker base image switched to a floating tag | silent base-image swaps |
| Old packages with published vulnerabilities (CVEs) | most real applications |

Existing scanners answer "which CVEs exist?". Teams still lack answers to three questions:

- **What changed** between the version we trusted and this one?
- **Does the change look like an attack?**
- **Can I check the evidence myself?**

## 2. The idea

Guardian works from **two git refs**, a trusted baseline and the version under review, and
answers the three questions in the organisers' Day 1 checkpoint:

1. **What is in the application?** An SBOM and a dependency graph.
2. **What changed?** A package-by-package and file-by-file diff, with each change linked to
   the commit that introduced it.
3. **What appears risky?** Known vulnerabilities plus generic sabotage-detection rules, each
   finding backed by evidence.

**Product rules** (from `CLAUDE.md`, enforced in code):

- **Evidence is minted only by tools.** Every fact on screen was read from a file or an API
  response by code. A model never creates evidence.
- **Claims are typed.**
  - *verified* = read directly from a file or from OSV.
  - *computed* = derived by code (edit distance, size ratio).
  - *AI inference*, from Day 2, will always be labelled as such, separately.
- **Unknown is never zero.** If a lookup fails or a package can't be checked, Guardian says
  "not evaluated". It never says "clean".
- **LLMs propose; code decides.** Scores, verdicts and pass/fail are computed by deterministic
  code.

## 3. Technical approach

```
              ┌──────────── Day 1: implemented (fastpath/build.py) ─────────────┐
 git refs ──► │ 1 Inventory ─► 2 SBOM + graph ─► 3 Vulnerabilities ─► 4 Change │
 baseline +   │   (lockfile)     (CycloneDX)        (OSV API)          detectors│
 tampered     │                                                    ─► 5 Evidence│──► guardian.html
              └──────────────────────────────────────────────────────────────────┘    findings.json
                                                                                      SBOMs
              ┌──────────── Day 2: designed (docs/ARCHITECTURE.md) ─────────────┐
              │ prioritise ─► refute ─► plan ─► HUMAN APPROVAL ─► validate ─► report
              │   (agents add judgement; code computes scores and pass/fail)    │
              └──────────────────────────────────────────────────────────────────┘
```

### Day 1: deterministic detection (built)

All the code is in `fastpath/build.py`, using only the Python standard library.

1. **Read both refs safely.**
   - `git archive <ref>` is extracted into a temp folder with Python's `tarfile`
     (`filter="data"`).
   - The target repo is never checked out, modified or executed.
2. **Inventory and SBOM.**
   - `package-lock.json` lists every installed package: version, `resolved` origin,
     `integrity` hash, install-script flag and dev/prod scope.
   - `scripts/lockfile_sbom_diff.py` writes a **CycloneDX 1.5** SBOM for each ref, plus their
     diff.
3. **Dependency graph.**
   - There is one node per install path.
   - Edges follow **Node.js module resolution**: a package's dependency is the nearest
     `node_modules/<name>`, walking up the folders. So the edges are what the app actually
     loads.
   - A breadth-first search from the app gives every package its shortest dependency path.
   - *Direct* means the package is listed in the root `package.json` and installed at the top
     level.
   - The Dockerfile and the GitHub workflow files are added as file nodes.
4. **Vulnerabilities.**
   - Registry packages are sent in batches to OSV (`POST /v1/querybatch`), and each advisory
     is fetched from `GET /v1/vulns/{id}`.
   - Guardian keeps the advisory ID, CVE aliases, severity and fixed versions.
   - Responses are cached on disk with their fetch time.
   - Dev-only packages are rated one level lower.
5. **Diff between the refs.**
   - A package is *new* if its install path is missing in the baseline.
   - It is *changed* if its version, integrity hash or origin differs.
   - A risky Dockerfile or workflow line is *new* if that exact line is absent from the
     baseline file.
   - The introducing commit comes from `git log -S "<exact text>" baseline..head -- <file>`.
6. **Sabotage rules.** All rules are generic; no package name is hard-coded.

   | Rule | Trigger | Risk |
   |---|---|---|
   | Look-alike name | New name within edit distance 2 (1 if under 6 letters) of another dependency or of a list of popular npm names | high |
   | Non-registry origin | `resolved` is not the npm registry | medium |
   | Unsafe install script | Install hook present. The script is **read as text, never run**, and checked for env-var reads (secret-like names), hard-coded URLs, network/process APIs, temp-dir writes and large code files | 2+ signals → critical, else high |
   | Suspicious update | The new version adds an install hook, or its tarball grows 2× or more | high |
   | Unexpected dependency | A new `require()` whose variable is never used | medium |
   | Untrusted image | `FROM` without `@sha256:` digest; floating tag; changed since baseline | high / medium / low |
   | Unpinned CI component | `uses:` not pinned to a 40-char commit SHA (OSV is also checked for the action) | high / medium / low |
   | Unsafe CI pattern | `permissions: write-all`; `curl … \| sh` | high |
   | Lockfile drift | Image built with `npm install`/`npm update` instead of `npm ci` | low |

7. **Findings.** Each finding records:
   - component, type, and risk level, plus **the rule that set it**;
   - the dependency path;
   - whether it is new or already present, and its commit;
   - its **evidence**: file, line and exact excerpt, or the OSV API URL and fetch time.

   Duplicate findings (same file + same type) are merged.
8. **Dashboard.** `guardian.html` is a single offline file with an interactive graph
   (vis-network) and three tabs: *What is in it*, *What changed*, *What is risky*.
   - Colours: red = suspicious change, orange = known vulnerability, grey = clean, dashed
     outline = new since baseline.
   - Clicking a node shows its version, origin, path, findings and evidence.

Full details, outputs and options: [`fastpath/README.md`](fastpath/README.md).

### Day 2: agentic analysis and remediation (designed)

A deterministic **conductor** runs the stages in a fixed order. **Five agents** built on the
Claude Agent SDK add judgement where it's needed:

| Agent | Job | It cannot |
|---|---|---|
| Change Detective | Investigates each suspicious change (opens the archive, reads the script, checks the commit) and explains what it does and which real incident it resembles | execute package code or follow instructions found in packages |
| Risk Analyst | Checks whether the app actually calls the vulnerable function (reachability) | set the score; code recomputes it |
| Refuter | Argues against top findings and fix plans to cut false alarms. Uses a different model from the analyst | close a finding; "refuted" only creates a candidate for a human to confirm |
| Remediation Planner | Ranks the fix options that code has enumerated and dry-run; writes rationale and rollback | apply anything |
| Diagnostician | When a validated fix fails, reads the build and test logs and proposes the next option | approve or apply anything |

The loop:

1. A plan is proposed.
2. **A human approves it.** The approval is bound to the plan's hash, so any edit to the plan
   voids it.
3. The fix is applied in a **throwaway clone**, then the image is built, smoke-tested,
   rescanned and SBOM-diffed.
4. If a check fails, the Diagnostician writes a new plan, which needs a fresh approval.

Nothing is ever pushed, merged or deployed.

**AI guardrails:**
- Each agent runs with no built-in tools: no shell, no files, no web. It gets only its own
  read-only tools.
- Agents must answer in a JSON schema.
- Each agent has a turn limit and a budget limit.
- If an agent fails, a deterministic fallback runs and the step is marked "skipped".
- Secrets are redacted before any model call.
- Package and advisory text is treated as data, never as instructions.

**Risk score.** The score is computed by code:

| Factor | Weight |
|---|---|
| severity | 30 |
| exploitability (EPSS, KEV) | 25 |
| reachability | 20 |
| exposure | 15 |
| fix availability | 10 |

Guardrails apply on top. Confidence drops for every unknown factor and moves with the
Refuter's verdict.

## 4. Sample application and planted risks

**Sample app:** [snyk-labs/nodejs-goof](https://github.com/snyk-labs/nodejs-goof) (Apache-2.0),
pinned to commit `add14ba5`. It is an Express + MongoDB to-do app, deliberately vulnerable,
with a real dependency tree, a Dockerfile, a compose file and CI workflows.

`scripts/make_demo_target.sh` builds `./target` with two refs:

- **`guardian-baseline`:** the app as published, plus one vendored helper package.
- **`tampered`:** four commits with innocent-looking messages, each planting a harmless,
  local-only replica of a real attack pattern:

| Commit | Planted risk |
|---|---|
| `431ac1d` feat: add string helper utility | `lodahs`: look-alike of lodash, from a local file, with a postinstall script that reads secret-like env vars |
| `a8de0f9` chore: use node 18 base image | Dockerfile `node:18.13.0` → `node:18` (floating tag, no digest) |
| `52e2fa6` ci: list changed files on pull requests | `tj-actions/changed-files@v45`, `permissions: write-all`, `curl … \| bash` |
| `05b9d85` chore: bump guardian-demo-strfmt to 1.0.1 | Patch release adds a preinstall script and a 99 KB one-line payload; tarball grows 5× |

Nothing is published to any registry. The ground truth is in
[`demo/ground_truth.yaml`](demo/ground_truth.yaml).

**Not limited to this app.** The rules work on any npm project with a `package-lock.json` (v2/v3)
in git, and the Docker and CI rules work on any repo. Other package ecosystems (pip, Maven, Go)
each need their own lockfile parser.

## 5. Results (Day 1, on the demo target)

| Measure | Value |
|---|---|
| Packages | 982 unique (1,276 install paths): 37 direct, 945 transitive |
| Vulnerabilities (OSV) | 217 advisories across 165 packages |
| Suspicious findings | 10 new since baseline, 5 already present |
| Planted changes detected | **7 / 7** (GT-C1…C7), each linked to the correct commit |
| Preexisting risks | GT-P1 and GT-P2 detected and marked "already present" |
| Negative controls | 3 / 3 respected (lodash not called a look-alike; strfmt 1.0.0 and `actions/checkout` not flagged as malicious) |

**Caveat:** the detectors were written with the planted risks known. The honest test of how
well they generalise is the hold-out seeds plus a run on a second application. Neither has
been done yet.

## 6. Why this stack

| Choice | Reason |
|---|---|
| Python standard library only | Runs anywhere in ~20 s with nothing to install. The tool's own supply chain is minimal |
| `git archive` instead of checkout | The target is only read, never modified or executed |
| The lockfile, not just `package.json` | The lockfile records what is actually installed, with origin and integrity hash for every transitive package |
| CycloneDX 1.5 | OWASP standard; other tools (Dependency-Track, grype) can consume the output |
| OSV.dev | Free, no API key, aggregates GitHub advisories and others, has a batch API, also covers GitHub Actions |
| vis-network | Renders 1,000+ nodes on canvas, works offline from one file |
| One self-contained HTML file | The demo cannot fail on a server, a port or Wi-Fi |
| Claude Agent SDK (Day 2) | Agents with in-process, read-only tools, structured output, and turn and budget limits |

## 7. Safety and responsible AI

- **Only `./target` is touched, and only by reading it.** No checkout, no install, no execution
  of package code. Install scripts are read as text.
- **One external service.** The only network calls go to `api.osv.dev`. Nothing is published,
  pushed or deployed by Guardian.
- **No credentials.** OSV needs no key. On Day 2, `ANTHROPIC_API_KEY` is read from the
  environment and secrets are redacted before any model call.
- **Human approval** is required for every remediation (Day 2). Fixes run only in a throwaway
  clone.
- **Enforcement for Claude Code.** A Claude Code `PreToolUse` hook
  (`.claude/hooks/block_out_of_scope.py`) blocks out-of-scope commands while building: push,
  publish, PR, merge and network scanners.

Draft note: [`docs/RESPONSIBLE_AI.md`](docs/RESPONSIBLE_AI.md).

## 8. Known limitations

- **npm only** for package analysis. The script reads a fixed `./target` path.
- **Registry install scripts are not opened.** Reading them would mean downloading the
  tarball, so they are reported as "content not inspected" at medium risk.
- **Bundled packages** (no `resolved` field) are not matched against OSV; they show "not
  evaluated".
- **Vulnerability counts** are advisory × package pairs.
- **No reachability, EPSS or KEV yet** (Day 2).
- **Text rules can be evaded** by obfuscation. Size-growth and large-file rules are the
  backstop.
- **The Docker image is not built or scanned yet.** Only the Dockerfile is read.

More: [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md) and
[`fastpath/README.md`](fastpath/README.md#known-limitations).

## 9. Repository layout

| Path | What it is |
|---|---|
| `fastpath/` | **Implemented Day 1 pipeline:** `build.py`, dashboard template, outputs in `out/` |
| `scripts/make_demo_target.sh` | Builds `./target` (sample app + planted risks) |
| `scripts/lockfile_sbom_diff.py` | Lockfile → CycloneDX SBOM, and SBOM diff (stdlib) |
| `demo/ground_truth.yaml` | What is planted, used to check results |
| `demo/packages/` | The harmless local packages used as planted risks |
| `guardian/contracts.py` | Data models and the product rules (starter for the full app) |
| `guardian/data/popular_npm_names.txt` | Popular names for the look-alike detector |
| `guardian.toml` | Configuration for the full app: models, score weights, trust lists |
| `policy/` | Policy-as-code rules (OPA/conftest), for Day 2 |
| `templates/` | Report and pull-request body templates |
| `docs/ARCHITECTURE.md` | Full system design: pipeline, agents, risk score, controls |
| `docs/HACKATHON_BRIEF.md` | The organisers' problem statement and rules |
| `docs/PLAN.md`, `docs/PROMPTS.md` | Build plan by phase, with prompts and acceptance checks |
| `docs/DEMO.md` | Demo script and judge Q&A |
| `docs/research/` | Research notes: prior art, tools, threats, Day 2, Agent SDK, UX |
| `CLAUDE.md`, `.claude/` | Rules, safety hook, subagents and skills for building with Claude Code |

## 10. Building the rest with Claude Code

The Day 2 work is planned phase by phase in `docs/PROMPTS.md`:

- Run a phase with `/phase N`, then check its acceptance commands and commit.
- Run `/checkpoint final` to audit the result against every requirement on the organisers'
  slides.
- `docs/PLAN.md` has cut lines if time runs short.

**Rules you must not break** (from the organisers):

- do not scan or attack real systems;
- stay inside your sandbox;
- never publish packages;
- never use real credentials;
- never merge or deploy without human approval;
- do not affect other teams.
