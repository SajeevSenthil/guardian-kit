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

---

## Phase 9 — Agents: Change Detective, Risk Analyst, Refuter, investigation record (2026-11-23) — built, live run pending

**Brief items:** Day 2 item 2 (investigate suspicious changes; clearly separate verified evidence
from AI-generated inference) and the "AI" half of item 1 (prioritise with AI). This phase also
covers the Change Detective planned for phase 5.

### Provider change (user decision)

The design specified the Claude Agent SDK. The team has a **Gemini** API key, not an Anthropic one,
so the agent layer was built provider-neutral with a **Gemini backend over the REST API using the
Python standard library** (no SDK installed). The safety design is unchanged:

| Control | Implementation |
|---|---|
| Least privilege | the model can call only the read-only tools in an allow-list built by our code; an unknown tool name is refused, never executed; no shell, file-system or web tool exists |
| Evidence minted by code | every tool result is stored as evidence `T<n>` before the model sees it |
| Structured output | final answer is a separate request with no tools and a JSON `responseSchema`; validated by code; one retry; then "skipped" |
| Claims are INFERRED | `EvidenceIndex.check_claim` forces INFERRED, drops unknown evidence ids, drops quotes that are not literal (≥ 8 chars) substrings of a cited excerpt |
| Limits | `agent_max_turns` (12), `max_output_tokens` (2048) per call, `token_budget_per_agent` (120k), HTTP timeouts, retry with backoff on 429/5xx |
| Secrets | `.env` loaded at runtime, never printed; `redact()` masks the configured key values and token shapes in every payload and tool output; the key travels in the `x-goog-api-key` header, never in a URL |
| Prompt injection | package, advisory, source and tool text is wrapped as `<package_content>` / `<advisory_text>` / `<file_excerpt>` / `<tool_output>` data; prompts forbid following it and forbid using a package's self-description as evidence |
| Fallback | offline, no key, model error or invalid output → status "skipped" with the reason; nothing changes |
| Cache | results cached in `.cache/agents/` by hash of (agent, model, prompt, payload, schema); `--fresh` bypasses |

### What was built

| File | Purpose |
|---|---|
| `guardian/env.py` | minimal `.env` loader (values never printed) |
| `guardian/evidence.py` | evidence index (finding evidence `F…E<n>`, tool evidence `T<n>`), `redact()`, `check_claim()` |
| `guardian/agents/llm.py` | Gemini client (retry, token count), tool loop, structured final answer, schema validator, cache |
| `guardian/agents/tools.py` | read-only tools: `get_finding`, `list_package_files`, `read_package_file` (local tarballs only, read as text), `get_advisory` (OSV cache), `find_imports`, `find_call_sites`, `read_source_excerpt` (first-party files only), `commit_context` (base..head only), `list_incident_patterns` |
| `guardian/agents/prompts/*.md` | `change_detective.md`, `risk_analyst.md`, `refuter.md` |
| `guardian/agents/runner.py` | `analyse` stage: selects findings, runs agents concurrently, applies results by fixed rules, writes investigation records |
| `guardian/data/incident_patterns.json` | pattern library; only the tj-actions entry is marked verified (CISA KEV); the rest are labelled unverified |
| `guardian.toml` `[agents]` | provider, models per role, token limits |
| CLI | `python -m guardian analyse [--mode live|offline] [--top N] [--fresh]`, `python -m guardian doctor` |

### How agent output changes results (code decides)

- **Change Detective** (all change findings new since baseline): writes `agents.change_detective`
  on the finding: summary, checked claims, "resembles", suggested risk (shown as a proposal only;
  the score is not changed).
- **Risk Analyst** (vulnerabilities in the top N): a vulnerable symbol counts only if its
  `advisory_quote` is a literal substring of the advisory text. Code then recomputes the tier
  from the app's own call sites (`reachability.tier_with_symbols`, grade `inferred`) and
  re-scores; `NOT_LOADED_CAP` is dropped if the tier is no longer R0.
- **Refuter** (top N), `apply_refuter`: upheld → confidence +5; downgraded → named factor's grade
  drops one step and the finding is re-scored; refuted → `status: not_affected_candidate`
  (waits for a named human; score unchanged); inconclusive → nothing. **A downgrade or refutation
  with no checked quote is treated as inconclusive.**
- **Investigation record** (`investigations.json`) for every change finding and non-CVE top-N
  finding: timeline (commit + files it touched), version comparison, provenance (origin,
  integrity, signature = not evaluated), verified facts with ids, AI assessment, resembles.
- The score before agents is kept as `priority_before_agents`.

### Verified

- `python -m pytest -q tests/unit` → **36 passed** (14 new in `test_agents.py`, model replaced
  by a fake transport): claim coercion to INFERRED; unknown ids and non-literal quotes dropped;
  redaction; tool loop mints `T1` evidence; the final call has no tools and a schema; an unknown
  tool (`shell`) is refused; invalid output twice → skipped; offline → skipped; refuter rules.
- **Adversarial fixture:** an install script whose comment says it is harmless, and a model that
  "refutes" using a paraphrase that is not a literal quote → treated as **inconclusive**, score and
  status unchanged.
- `python -m guardian analyse --mode offline` on the demo run: 22 jobs (10 Change Detective,
  2 Risk Analyst, 10 Refuter), all **skipped with the reason**, no score changed; 10 investigation
  records written (e.g. strfmt 1.0.1: commit `05b9d85` touching `package-lock.json`,
  `package.json` and both vendored tarballs; provenance `file:` origin, integrity, signature not
  evaluated).
- `uvx ruff check guardian tests/unit --line-length 110` → clean.

### Not done / pending

- **No live Gemini run yet.** `python -m guardian doctor` reports `GEMINI_API_KEY present: no`.
  Once the key is in `.env`: run `doctor` (checks the key and which configured models exist),
  then `python -m guardian analyse --mode live`. Phase 9's live acceptance items (agent results
  on the top findings, the Refuter upholding the look-alike finding and proposing not-affected
  for an unimported package, time and token totals) are **not yet checked**.
- Model ids in `guardian.toml` (`gemini-2.5-flash`, `gemini-2.5-pro` for the Refuter) are
  unverified until `doctor` lists the models the key can use. Cost is not estimated (tokens are
  counted).
- Not built: `registry_metadata` and `capability_diff` tools (no registry calls; the
  suspicious-update evidence already carries the size and file diff), agent results in the UI.
