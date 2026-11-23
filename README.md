# Supply Chain Guardian — hackathon build kit

> **Implemented so far (Day 1): the fast path.** SBOM, dependency graph, OSV vulnerabilities,
> suspicious-change detection and an evidence dashboard, in one stdlib Python script.
> Full instructions: [`fastpath/README.md`](fastpath/README.md).
>
> ```bash
> bash scripts/make_demo_target.sh     # once: builds ./target (Windows: see fastpath/README.md)
> python fastpath/build.py             # ~20 s, writes fastpath/out/
> start fastpath/out/guardian.html     # Windows (macOS: open, Linux: xdg-open)
> ```
>
> The AI agents, remediation and validation described below are the Day 2 plan and are not
> built yet.

Everything needed to build the Bosch "Software Supply Chain Guardian" in two days with Claude
Code: the plan, the system design, step-by-step prompts, Claude Code configuration (rules,
subagents, skills, safety hook), a ready-made demo target with planted risks, research notes,
and the demo script.

This kit is a plan and a scaffold. It is **not** the finished application: Claude Code builds
that, phase by phase, from `docs/PROMPTS.md`. Replace this README with the project README in
phase 14.

## What you are building, in one paragraph

Guardian compares a trusted baseline of an application with its current state, inventories
everything it is built from (SBOM, dependency graph, container, CI), finds known vulnerabilities
and suspicious changes, ranks them by what matters for this app, proposes a fix, waits for a
human to approve it, proves the fix in an isolated build, and writes a report where every
statement is backed by tool evidence or labelled as AI inference.

## How we intend to win (short version)

Most teams will ship "scanner + LLM summary + dashboard". Four things set this design apart, and
each maps to a sentence in the brief:

1. **A closed agent loop, live** — plan, human approval, real build and test, the fix fails,
   an agent diagnoses it from the logs, new plan, second approval, verified ("agentic",
   "test before you trust", "human approval").
2. **Evidence ledger** — facts are written only by code from tool output; everything the AI
   says sits in a separate, labelled column with its cited support checked ("clearly separate
   verified evidence from AI-generated inference").
3. **Scorecard against planted ground truth, with hold-outs** — we show what Guardian caught
   *and missed*, including risks its detectors never saw during development.
4. **A refuter agent** that argues against findings and fixes ("confidence level").

Details: `docs/research/01-prior-art-and-winning-strategy.md` and `docs/DEMO.md`.

## Before you start (15 minutes)

You need: macOS or Linux, git, Docker (running), Node 18+ and npm, Python 3.11+, Claude Code,
and an Anthropic API key for the app's own agents (Claude Code itself can use your normal login).

```bash
unzip guardian-kit.zip && cd guardian-kit
cp .env.example .env            # put ANTHROPIC_API_KEY in it; never commit it
git init && git add -A && git commit -m "kit"
claude                          # start Claude Code in this folder
```

When Claude Code asks whether to trust the folder and its hook, say yes: the hook only blocks
out-of-scope commands (git push, package publishing, opening or merging pull requests, network
scanners).

## The two days

1. Read `docs/HACKATHON_BRIEF.md` (the organiser's slides, transcribed), then `docs/PLAN.md`.
2. In Claude Code, run the phases in order. Either type `/phase 0`, `/phase 1`, … or paste the
   matching block from `docs/PROMPTS.md`. One phase per session; `/clear` between phases.
3. After each phase, check its acceptance list, then commit. Tick `docs/PROGRESS.md`.
4. End of Day 1: `/checkpoint day1`. End of Day 2: `/checkpoint final`.
5. Rehearse from `docs/DEMO.md`. Stop building 90 minutes before the final demo.

| Day | Phases | Result |
|---|---|---|
| 1 | 0–7 | inventory, SBOM, graph, CVEs, change detection, evidence UI, scorecard |
| 2 | 8–15 | ranking, investigation, fix plan, approval, validation, report, docs, rehearsal |

Both days are planned with about 45 minutes of slack. If you fall behind, `docs/PLAN.md` has
explicit cut lines and `docs/PROMPTS.md` has a "Behind schedule" prompt. A smaller system that works end to
end beats a larger one that half works.

## What is in the kit

| Path | What it is |
|---|---|
| `CLAUDE.md` | project rules Claude Code loads automatically (scope limits, product rules, commands) |
| `docs/HACKATHON_BRIEF.md` | the problem statement, both days, guidelines, stretch goals, deliverables |
| `docs/PLAN.md` | scope, schedule, time boxes, cut lines, risks |
| `docs/PROMPTS.md` | the prompts for phases 0–15 plus utility prompts |
| `docs/ARCHITECTURE.md` | system design: pipeline, agents, risk score, data layout, UI, controls |
| `docs/requirements.yaml` | every bullet on the slides with how we prove it |
| `docs/DEMO.md` | Day-1 checkpoint script, final demo script, slides, judge Q&A, failure plan |
| `docs/RESPONSIBLE_AI.md` | draft of the required Responsible AI & security note |
| `docs/KNOWN_LIMITATIONS.md` | what is unverified or limited, to be kept current |
| `docs/research/01…06` | research: prior art, tool verification, threats, Day 2 + stretch, Claude Code + Agent SDK, UX + judging |
| `guardian/contracts.py` | starter code: the data models and the three product rules |
| `guardian.toml` | starter configuration (models, score weights, trust lists) |
| `demo/packages/` | harmless local packages used as planted risks |
| `demo/ground_truth.yaml` | the list of planted and pre-existing risks the scorecard checks |
| `scripts/make_demo_target.sh` | builds `./target`: the sample app with `baseline` and `tampered` branches |
| `scripts/setup_tools.sh` | installs the scanners and records versions |
| `scripts/lockfile_sbom_diff.py` | no-dependency SBOM + diff fallback |
| `guardian/data/popular_npm_names.txt` | starter list for the look-alike-name detector |
| `policy/` | starter policy-as-code rules and tests |
| `templates/` | report and pull-request body templates |
| `samples/` | small real outputs captured while writing the kit |
| `.claude/settings.json`, `.claude/hooks/` | permissions and the out-of-scope command blocker |
| `.claude/agents/` | build-time helpers: `tool-probe`, `skeptic-reviewer`, `requirements-auditor`, `ui-tester`, `demo-director` |
| `.claude/skills/` | `/phase`, `/checkpoint`, and reference skills for contracts, tools and the Agent SDK |

## The sample application

[snyk-labs/nodejs-goof](https://github.com/snyk-labs/nodejs-goof) (Apache-2.0), pinned to commit
`add14ba5`: an Express + MongoDB to-do app with 32 direct dependencies and about 980 packages in
its lockfile, a Dockerfile, a compose file and CI workflows. It satisfies the organiser's sample
application guidelines. `scripts/make_demo_target.sh` clones it locally, removes the git remote,
adds a credential-free smoke test (bound to 127.0.0.1; the app is deliberately vulnerable, so
keep it off the network), and creates a `tampered` branch with four commits that introduce
harmless, local-only replicas of real supply-chain incident patterns. Nothing is published
anywhere. See `demo/ground_truth.yaml`.

## What has and has not been verified

Checked while writing the kit: the target builder runs and produces the branches (rebuilt
several times); the planted packages install from the lockfile in an isolated project and
their scripts only write a marker file (an independent review also unpacked and read them);
the lockfile SBOM/diff fallback works; the safety hook gives the intended result on 25 test
commands run outside Claude Code; the data contracts reject model-authored "verified" claims;
the lodash call site used for the reachability example exists in the app. The phase 1 prompt
was dry-run once by a separate agent and the ambiguities it hit were fixed.

**Not verified** (the kit was written in a sandbox without network access or Docker): every
third-party scanner command, every public API shape, the app's Docker build and smoke test, a
full `npm ci` of the app, the setup script, the starter policies, and which lodash advisory
matches the call site. Phase 0 settles all of these on your machine first, on purpose.
Research notes mark each unverified item.

## Tips for working with Claude Code

- Use plan mode (Shift+Tab) for phases that touch many files; approve the plan, then let it build.
- Give it a check it can run. Every phase prompt ends with acceptance commands for this reason.
- If it fails twice on the same thing, `/clear` and use the "Unstick" prompt in `docs/PROMPTS.md`.
- Ask for the `skeptic-reviewer` subagent before committing anything that touches findings,
  scoring or documentation. It looks for overclaims and demo-specific shortcuts.
- Commit before risky changes. Pushing is always your job; the hook stops Claude from doing it.
- A second Claude Code session in a git worktree can build the UI in parallel from phase 6.
- Optional: a browser MCP server (Playwright) helps with UI testing. The install line in
  `docs/research/05-claude-code-and-agent-sdk.md` §6.2 is unverified; check the project's README.

## Rules you must not break

From the organiser's slide: do not scan or attack real systems, do not go outside your own
sandbox, do not publish packages to public registries, do not use real credentials, do not
merge or deploy without human approval, do not affect other teams. The design and the hook
respect these; keep it that way when improvising.
