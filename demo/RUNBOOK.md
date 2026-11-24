# Demo runbook

Exact commands, what to click, what to say, and what to do when something breaks. Everything
here matches what is built (see `implementations.md`); do not say more than this page says.

## Lines that are TRUE (use them)

1. "Facts on screen are written by code from tool output: file, line, commit or API response.
   Anything an AI says is labelled as inference, and its quotes are checked against the evidence."
2. *(Only after the approval run has actually happened.)* "The first fix was what a dependency bot would do: delete the package from the manifest. Guardian
   caught that the code still requires it, worked out why, proposed a better fix, and a human had
   to approve again. Nothing was pushed or merged; the target repository was never modified."
3. "Unknown is never zero. When a lookup cannot run, the report says *not evaluated*."

## Lines to AVOID (not true of this build)

- "We built and ran the container" — the container build and HTTP smoke test are **not implemented**;
  validation is install + static checks + rescan ("partial").
- "The scorecard / hold-out seeds" — not built; ground truth was checked by hand (7/7, 3/3).
- "The AI agents found …" — unless you have done a live run with a Gemini key (`python -m guardian
  doctor`), agents were **skipped**; say "the agents are built and tested with a mocked model".

---

## The night before (30–40 min)

```bash
bash scripts/make_demo_target.sh              # only if ./target is missing (Windows: see fastpath/README.md)
python -m guardian scan                       # warms the OSV cache; writes fastpath/out/guardian.html
python -m guardian prioritise                 # warms EPSS + KEV caches
python -m guardian analyse                    # live only if GEMINI_API_KEY is in .env; else "skipped"
python -m guardian prioritise --top 5         # note the look-alike finding id (type typosquat)
python -m guardian plan --finding <ID> --candidate C1     # the "dependency bot" plan; note its id, call it P-a
#   check the patch is small before approving:  grep "files changed" runs/<run_id>/plans/P-a.patch   (expect 2)
python -m guardian approve P-a --approver "<your name>"
python -m guardian validate P-a               # FAILED at static_start -> diagnosis -> new plan P-b (printed)
python -m guardian approve P-b --approver "<your name>"
python -m guardian validate P-b               # PARTIAL (container build / smoke test not implemented)
python -m guardian report
python -m guardian audit-verify
bash scripts/record_demo.sh                   # freezes this run into demo/recorded/final/<run_id>/
```

Optional, also validates the end-to-end machinery with a labelled test approver in an isolated
folder (~10 min, real `npm ci` twice): `python -m pytest -q -m e2e -s`.

Open in the browser and keep the tabs: `fastpath/out/guardian.html`,
`runs/<run_id>/report/guardian-report.html`.

## The demo (about 6 minutes)

| Time | Screen / command | Say |
|---|---|---|
| 0:00 | dashboard, top bar | "goof, an open-source Node app at a pinned commit. Trusted baseline vs the branch under review: 982 packages, 37 direct, 945 transitive." |
| 0:30 | **Transitive** tab → type `ansi-regex` → click it | "The app never asked for this package. It arrives six levels down via typeorm, with a known vulnerability — the blue path shows how." |
| 1:00 | **Vulnerabilities** tab → filter critical, transitive | "Known CVEs from OSV, each with the fix and the direct dependency that brings it in." |
| 1:20 | **What changed** tab | "Four innocent-looking commits. 10 suspicious findings, each linked to its commit." Click `lodahs`: "look-alike of lodash, local tarball, install script that reads secret-like environment variables — read as text, never run." |
| 2:00 | `python -m guardian explain <F-id of lodash GHSA-4xc9>` (F162 in the current run) | "Prioritised by code: the app calls `_.merge` on request data (`routes/index.js:362`), so this advisory is R3 and scores 79 — above lodash's CRITICAL advisory GHSA-jf85 (72), which is about `defaultsDeep`, a function the app never calls. Every factor shows its evidence." (Another lodash `merge` advisory also scores 79; do not call it unique.) |
| 2:40 | report → section 6 (Markdown) / "Recommended and approved actions" (HTML), plans P-a and P-b | **Only after the approval run.** "Plan 1 was the dependency-bot fix. A human approved its exact patch hash. Validation installed it in a throwaway clone and the static start check failed: `routes/index.js:21` still requires the package. Code diagnosed it and proposed plan 2, which also removes the unused import. It needed a new approval." |
| 3:40 | report → section 7, validation table of P-b (only after the approval run) | "Install with scripts disabled, every require resolves, rescan shows the look-alike gone and nothing new, SBOM diff shows exactly one component removed. Verdict partial: we say plainly the container build is not implemented." |
| 4:30 | report → not-evaluated list, audit line | "Everything we could not check is listed. The audit log is hash-chained and verifies." |
| 5:00 | questions | |

## When something breaks

| Problem | Do this | Say |
|---|---|---|
| **Network down** | add `--offline` to `scan`/`prioritise`, `--mode offline` to `analyse`/`plan`/`validate`, or `GUARDIAN_OFFLINE=1`; caches are used; npm uses `--offline` | "Offline mode: cached data, and anything not cached shows as not evaluated." |
| **Gemini API down / no key** | nothing; agent steps are recorded as skipped | "The agents are an add-on; scores, plans and verdicts are computed by code." |
| **Docker** | not used by this build | — |
| **A command fails** | the CLI prints one line `error: …`; `GUARDIAN_DEBUG=1` shows the traceback | — |
| **Browser / dashboard will not open** | open the frozen copies in `demo/recorded/final/<run_id>/` (HTML, Markdown, JSON) | "This is the recorded run from last night; same files." |
| **Validation too slow live (~3 min)** | show the recorded validation table instead of re-running | — |

There is no replay mode; the recorded folder is the fallback (record it with `scripts/record_demo.sh`
after the approval run; until then it does not exist).

**Before the approval run** (no plan validated yet): skip 2:40 and 3:40. Instead show section 6: the
C1 plan predicts `dangling require() ['lodahs']`, and the ranked plan lists C1 under alternatives as
"leaves first-party code requiring a removed package"; open `target/routes/index.js:21`
(`var strutil = require('lodahs');`) and say "a human must approve; nothing has been validated yet".
That cut brings the demo to about 3 minutes.
