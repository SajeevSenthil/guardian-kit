# Implementations log (Day 2)

What has been built for each Day-2 phase of `docs/PROMPTS.md`, how to run it, what was verified,
and what differs from the plan. Newest phase at the bottom.

## Ground rules for this log

- Every statement here was checked by running the code on this machine on the date given.
  Anything not run says "not run".
- Numbers come from the demo target (`./target`, `guardian-baseline` → `tampered`); advisory
  data (OSV, EPSS, KEV) changes over time, so vulnerability counts may drift on a re-run.

## How Day 2 is wired to Day 1 (decision, 2026-11-23)

The phase plan assumes Day 1 was built inside the `guardian/` package (phases 1–7). Day 1 was
built instead as the stdlib fast path (`fastpath/build.py`, see `fastpath/README.md`). Day 2
builds **on top of the fast path's outputs** rather than rebuilding Day 1:

```
python -m guardian scan          # runs fastpath/build.py, then creates runs/<run_id>/ from its outputs
python -m guardian prioritise    # phase 8
python -m guardian explain F162  # phase 8
```

A run directory `runs/<run_id>/` holds `run.json`, the Day-1 files (`findings.json`,
`graph.json`, the SBOMs), `src/<ref>/` (the ref extracted read-only with `git archive`) and each
later stage's output. `runs/` is git-ignored.

Not built from phases 1–7, and what replaces it for now:

| Planned (phases 1–7) | Status | Stand-in |
|---|---|---|
| Evidence ledger + hash-chained audit log | not built | evidence is embedded in each finding (file, line, excerpt / API URL + fetch time) |
| Event stream, replay mode | not built | — |
| syft / grype / osv-scanner wrappers | not built (tools not installed) | lockfile SBOM + OSV API (fast path) |
| NiceGUI dashboard | not built | `fastpath/out/guardian.html` |

Machine state that limits Day 2 (checked 2026-11-23):

- **Docker: not installed.** Phase 11 build and smoke-test checks will report "not run".
- **`ANTHROPIC_API_KEY`: not set; `claude-agent-sdk`: not installed.** Agents (phases 9–11) can
  only run their deterministic fallback ("agent step skipped") until both exist.
- **conftest, syft, grype, osv-scanner: not installed.**

---

## Phase 8 — Prioritise (2026-11-23) — done

**Brief items:** Day 2 item 1 (combine severity with exploitability, reachability and exposure;
production vs dev; urgent vs lower priority; explainable score and confidence). Stretch S-1
(reachability).

### What was built

| File | Purpose |
|---|---|
| `guardian/config.py` | loads `guardian.toml`; refuses weights that do not sum to 100 or priors outside (0, 1] |
| `guardian/runs.py` | run directories; `scan` (runs the fast path, copies its outputs); read-only `materialise(ref)` via `git archive` + `tarfile(filter="data")` |
| `guardian/cvss.py` | CVSS v3.0/v3.1 base score from the vector (FIRST spec incl. Roundup) |
| `guardian/enrich.py` | EPSS (FIRST.org, 100 CVEs per call) and CISA KEV, cached in `.cache/enrich/` with fetch time; offline/failure → `None` (unknown) |
| `guardian/reachability.py` | import scan of first-party code; tiers R0–R3 / unknown with file:line witnesses |
| `guardian/scoring.py` | pure scoring: 5 weighted factors, evidence grades, priors, range, confidence, guardrails, bands, generated explanation |
| `guardian/prioritise.py` | builds the factors for every finding (CVE and non-CVE), applies guardrails, writes `prioritised.json` |
| `guardian/cli.py`, `__main__.py` | `python -m guardian scan / prioritise / explain` |
| `fastpath/build.py` | now also writes `graph.json` and keeps `cvss` + `installed_version` on vulnerability findings |
| `docs/tool-notes/epss-kev.md`, `tests/fixtures/epss/`, `tests/fixtures/kev/` | API probes done before wrapping (shapes, limits, observed values) |

### How the score is computed

`score = Σ weight × value` over five factors (weights from `guardian.toml`: severity 30,
exploitability 25, reachability 20, exposure 15, fix availability 10), then guardrails. Each
factor carries a value in 0..1, an evidence grade and a one-line evidence string.

**Known vulnerabilities**

| Factor | Rule | Grade |
|---|---|---|
| severity | CVSS v3 base score / 10 computed from the OSV vector; else GitHub bucket (critical .95, high .8, moderate .55, low .25) | verified |
| exploitability | CVE in CISA KEV → 1.0; else EPSS ≥ .5 → .9, ≥ .1 → .7, ≥ .01 → .4, < .01 → .15; no CVE / no EPSS → unknown (prior .4) | verified |
| reachability | R0 .1 · R1 .5 · R2 .8 · R3 1.0 · unknown → prior .5 | heuristic |
| exposure | dev-only (lockfile flag) .3; prod + `internet_facing = true` (stated assumption) 1.0; prod internal .6 | verified / heuristic |
| fix availability | fixed version in same major 1.0; only via major bump .7; none published .5 | verified |

**Reachability tiers** (`guardian/reachability.py`, first-party `.js/.mjs/.cjs/.ts` files, excluding
`node_modules/ public/ vendor/ test(s)/ .github/ guardian/` and `*.spec.js`):

- **R0** — no first-party file imports the package.
- **R1** — imported (`require`, `import`), or invoked by an npm script; for a transitive package,
  the direct dependency that brings it in is used (capped at R1: what the library does with its
  dependency is not analysed).
- **R2** — a member the app uses on the package (`_.merge`, destructured names,
  `require('x').y`) is named as a whole word in the advisory's summary or details.
- **R3** — R2, and that member is used on a line reading `req.body/query/params/cookies/headers/files`.
- **unknown** — not imported, but the package name appears as a string literal in app code
  (libraries load drivers and engines by name), or no dependency path exists.

**Non-CVE anomalies** use the same factor names (rubric in `docs/ARCHITECTURE.md` §6, "implemented
rubric"): severity by class, exploitability = strength of the hostile signal, reachability =
does it execute (install script → runs at install, 1.0), exposure, fix (remove/pin available).

**Guardrails** (each reported on the finding when it fires):

- `KEV_FLOOR` → at least 90: CVE in KEV and tier not R0; or a CI action whose advisory is in KEV.
- `NOT_LOADED_CAP` → at most 39: tier R0 (heuristic) and not in KEV.
- `MALICIOUS_FLOOR` → at least 90: new component, not from the registry, whose install script
  shows two or more distinct red-flag signals.

**Confidence** = Σ weight × grade quality (verified 1.0, heuristic 0.7, inferred 0.4, unknown 0).
**Range** = the score recomputed with every unknown/inferred factor at its minimum and maximum.
**Bands** (`guardian.toml`): critical ≥ 85, high ≥ 65, medium ≥ 40, low ≥ 15, info < 15.

### Results on the demo target (run 2026-11-23)

```
EPSS: evaluated (204/205 CVEs scored)   KEV: evaluated (catalog 2026.11.23)
funnel: 982 packages (1276 install paths) -> 370 findings -> 288 ranked items -> 80 need attention
bands: critical 9, high 71, medium 182, low 26
```

Ranked items = one per unique (package, advisory) for vulnerabilities, one per finding otherwise.

| Check (phase 8 acceptance) | Result |
|---|---|
| The `_.merge` lodash advisory outranks a higher-CVSS one the app does not reach | **met.** GHSA-4xc9-xhrj-v574 (CVE-2018-16487, names `merge`): **R3**, witness `routes/index.js:362 _.merge(message, req.body.message, {`, score **79**. GHSA-jf85-cpcp-j695 (CVE-2019-10744, CVSS 9.1, about `defaultsDeep`): R1, score **72**. The `merge` call site is not paired with the `defaultsDeep` advisory. |
| A package no app file imports ranks low | **met.** json-schema 0.2.3 and minimist (CVSS 9.8, via `tap`): R0 → `NOT_LOADED_CAP` → **39 (low)**. |
| Dev-only shows reduced exposure | **met.** e.g. cipher-base (via browserify, dev): exposure 0.3 "dev-only dependency (lockfile `dev` flag)". |
| Unknown EPSS shown as unknown with prior and wider range | **met.** mongoose GHSA-h8hf-x3f4-xwgp: exploitability unknown ("no EPSS score published"), range [71, 92], confidence 64. |
| Look-alike package with install script at or near the top | **met.** `lodahs` findings: 90 (critical), `MALICIOUS_FLOOR`; `guardian-demo-strfmt@1.0.1`: 90. |
| Real KEV data used | `tj-actions/changed-files@v45`: advisory CVE-2025-30066 is **in CISA KEV** → `KEV_FLOOR` 90. jquery 2.2.4 GHSA-jpcq-cgw6-v4j6 (KEV-listed CVE) → 90. |

Reachability tiers across vulnerability findings: R0 23 · R1 314 · R2 8 · R3 3 · unknown 5.
R2/R3 symbols found: lodash `merge` (R3), mongoose `Schema`/`model`, moment `locale`,
validator `rtrim` (R2). `ejs@1.0.0` is **unknown**: not imported, but `'ejs'` is named in
`app.js` (view engine loaded by name).

### Tests

`python -m pytest -q tests/unit` → **22 passed**:

- `test_scoring.py`: weights sum to 100; unknown never scores zero; unknown widens range and
  lowers confidence; each guardrail fires and is reported; monotonic in every factor; bands;
  CVSS calculator against five vectors (incl. 9.1 for CVE-2019-10744).
- `test_reachability.py`: package-name parsing; tests/ and public/ excluded; R3/R2/R1/R0/unknown
  on a fixture app; npm-script invocation; transitive capped at R1.
- `test_no_seed_names.py`: no seeded package name, vendored file or ground-truth id (read from
  `demo/ground_truth.yaml`) appears in `guardian/` or `fastpath/build.py`. It caught one
  docstring example during the phase; the example was made generic.

`uvx ruff check guardian tests/unit --line-length 110` → clean.

### Not done in this phase / limitations

- **UI:** scores are in `prioritised.json` and the CLI, not yet in `guardian.html`
  (planned with the report in phase 12).
- **R2 symbol matching is a whole-word text match** between members the app uses and the
  advisory prose. It can over-match generic names (mongoose `Schema`) and miss a symbol the
  advisory does not spell out. The witness and the advisory quote are shown so a reviewer can
  judge; the Risk Analyst agent (phase 9) is meant to refine it.
- **R3 is a line-level heuristic** (the member call and request data on the same line); data
  flowing through variables is not tracked.
- Exploit/PoC references in advisories do not yet raise exploitability (research 04 §1.5).
- Bundled packages (326 install paths) still have no OSV data, so they are not scored.
