# Known limitations

Frank list, kept current. Status as of 2026-11-24. Details and measurements: `implementations.md`.

## Not run or not built

- **No end-to-end validation yet.** Every plan needs a human approval before validation; none
  has been given on the demo run. The validation machinery was probed on an unmodified clone
  (`npm ci --ignore-scripts` 141 s, rescan reproduces the same 370 findings) and the logic is
  unit-tested, but the closed loop (fail → diagnose → new plan → approve → validate) has not been
  run end to end.
- **The container build and the HTTP smoke test are not implemented** (docker was not installed on
  the build machine, so they were never built); validation reports them "not run" and the best
  possible verdict is "partial". Installing docker alone does not change this.
- **No live AI run.** No model key was configured; every agent step is "skipped". Agent behaviour
  is tested only with a fake model. Model ids in `guardian.toml` (`gemini-2.5-flash`,
  `gemini-2.5-pro`) are unverified until `python -m guardian doctor` lists them. Agent cost is not
  estimated (tokens are counted).
- **Hold-out seeds, a second application, an automatic scorecard: not built.** The 7/7 detection
  result is measured against seeds the rules were developed with; it says little about
  generality.
- **No NiceGUI UI, replay mode, event stream, or Playwright UI test.** The UI is two HTML files.
- **conftest, syft, grype, osv-scanner, cosign, trivy are not installed.** Policy runs on a Python
  port of `policy/guardian.rego` (the Rego file itself is still untested); there is no second
  scanner to cross-check OSV.
- **No self-SBOM / `tools.lock`** for Guardian itself; tool versions are listed in the README.
- **VEX** follows the OpenVEX v0.2.0 structure but is not validated with official tooling.

- **The end-to-end test (`tests/e2e/`) has not been run** by the assistant (it records test approvals);
  run `python -m pytest -q -m e2e -s`.
- **Plan P-0004 in the demo run has a defective patch** (line-ending churn, fixed in code since; see
  implementations.md phase 15): withdraw it and use P-0005.

## Detection limits

- **npm only** (lockfile v2/v3). The Docker and CI rules are generic.
- **326 bundled install paths** (packages shipped inside another package, no `resolved` field)
  are not matched against OSV; they show "not evaluated".
- **Install scripts of registry packages are not opened** (tarballs are not downloaded); they are
  reported as "content not inspected" at medium risk.
- **Static text rules can be evaded** by obfuscated code; size-growth and large-file rules are
  the backstop.
- **The unused-import rule** matches `var|let|const x = require('pkg')` in first-party JS files only
  (destructuring and ES `import` are not covered by this rule).
- **Image digest and action SHA pinning are not evaluated** (no Docker Hub / GitHub lookups); fix
  candidates restore the base image tag or delete the introduced workflow instead.
- **The dependency path shown is the shortest one**; longer routes exist.

## Scoring limits

- **Reachability is a heuristic.** R2 matches members the app uses against words in the advisory
  text (can over-match generic names such as mongoose `Schema`); R3 requires the call and request
  data on the same line (no data-flow tracking); transitive packages are capped at R1.
- **Anomaly rubric values** are our choices (documented in `docs/ARCHITECTURE.md` §6); several
  rows extend the research rubric and are marked as such.
- **Exploit/PoC references in advisories do not raise exploitability** yet.
- **Predicted findings after a fix are not re-scored**; their band comes from OSV severity.

## Process limits

- **One validation takes ~3 minutes** (mostly `npm ci`), above the 2-minute target.
- **The policy "plan gate"** is our addition: the full gate (rules of the Rego file) fails on both
  head and every fixed state while unrelated pre-existing violations (e.g. KEV-listed jquery)
  remain; plans are judged on their target and on what they introduce.
- **Work clones can be hard to delete on Windows** while VS Code's Git extension watches them.
- **On Windows, `scripts/make_demo_target.sh` needs three workarounds** (python3 alias, autocrlf,
  folder lock) documented in `fastpath/README.md`.
- **Self-description filter is a keyword list.** A refutation whose only checked quotes contain words
  such as "harmless", "demo", "safe" or "do not worry" is treated as inconclusive
  (`guardian/agents/runner.py::SELF_DESCRIPTION`); other phrasings of a self-description are not caught.
- **Agent result cache.** With a cache hit (`.cache/agents/`), tool outputs are re-minted as evidence
  from the cached file without re-running the tool; the cache is local and git-ignored, but an edited
  or stale cache file would become evidence. Use `analyse --fresh` to bypass it.
- **A checked quote is not a checked conclusion.** Code confirms that cited text exists, not that
  the agent's reasoning follows from it; that is why AI claims are never shown as facts.

## Known before the build (kit notes), with their status

| Kit note | Status |
|---|---|
| Tool commands not verified when the kit was written | OSV, EPSS, KEV and npm were probed before wrapping (`docs/tool-notes/epss-kev.md`); scanners were never installed |
| Container build not tested | still not tested (no docker); `npm ci --ignore-scripts` of the full tree works (141 s) |
| Seeded packages say they are harmless | detectors ignore it; one adversarial unit test covers agents |
| Starter Rego untested | still untested (Python port used) |
| Popular-package list from general knowledge | unchanged |
| goof ships no unit tests | unchanged; our checks are static start + rescan, smoke test needs docker |
