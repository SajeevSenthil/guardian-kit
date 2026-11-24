# Responsible AI & security note

Every statement below describes the system as built on 2026-11-24 and points to the code or test
that implements it. Things that were designed but not built are listed as such.

## 1. Where AI is used — and where it is not

| Agent | Purpose | Input it sees | Output | Can it change anything? |
|---|---|---|---|---|
| Change Detective | explain each suspicious change new since the baseline | the finding's evidence excerpts; tool outputs it requests | AI assessment (INFERRED claims), "resembles", suggested risk (shown as a proposal) | **no** — the score is not changed |
| Risk Analyst | name the vulnerable symbol from the advisory and find the app's call site | advisory text, call-site excerpts | symbols with an advisory quote | only through code: the symbol counts if its quote is a literal substring of the advisory; code then recomputes reachability from the app's own call sites (grade `inferred`) |
| Refuter | argue against top findings and the chosen plan | the finding and read-only tools | verdict upheld / downgraded / refuted / inconclusive | only through fixed rules: upheld → confidence +5; downgraded → one factor's grade drops; **refuted → only a "not affected CANDIDATE" for a human**; a downgrade or refutation without a checked quote is treated as inconclusive |
| Remediation Planner | rationale, compatibility impact, what could go wrong | candidates and their dry-run results | INFERRED rationale and a preferred candidate | **no** — code chooses the candidate; a disagreement is shown to the approver |
| Diagnostician | explain a failed validation | check results and logs | root cause and a recommended candidate | only if it names an alternative that code already found eligible; the new plan needs a **new human approval** |

Implementation: `guardian/agents/runner.py` (`apply_refuter`, analyst handling), `guardian/agents/planner.py`,
`guardian/loop.py`. Prompts: `guardian/agents/prompts/*.md`.

AI is **not** used for: inventory, SBOM, dependency graph, vulnerability matching, the change
diff, the sabotage rules, risk scores, policy decisions, fix candidates and their edits, dry
runs, validation pass/fail, approvals, VEX, or report text. All of these are deterministic code
(`fastpath/build.py`, `guardian/prioritise.py`, `scoring.py`, `remediate.py`, `policy.py`,
`validate.py`, `report.py`).

**Status:** the agents are built and unit-tested with a fake model. No live model run has been
done yet (no key on the build machine); without a key every agent step is recorded as
"skipped" and nothing changes.

## 2. How hallucinations are controlled

- **Facts come only from code.** Evidence is either a finding's own lines (file, line, excerpt or
  API URL + fetch time) or the output of a read-only tool, minted by code as `T<n>` before the
  model sees it (`guardian/evidence.py`, `EvidenceIndex`). On an agent cache hit the cached tool
  outputs are re-minted without re-running the tools (see Known limitations; `--fresh` bypasses).
- **Every model claim is INFERRED.** `check_claim` forces the status to INFERRED, drops evidence
  ids that do not exist, and drops any quote that is not a literal (≥ 8 characters) substring of a
  cited excerpt; `support_checked` records the result
  (`tests/unit/test_agents.py::test_check_claim_forces_inferred_and_checks_quotes`,
  `test_quote_must_come_from_a_cited_id`).
- **Structured output only.** The final answer is a separate request with no tools and a JSON
  schema; it is validated by code, retried once, then "skipped" (`test_invalid_output_twice_is_skipped`).
- **A second agent argues the other side** (Refuter; configured to a different model than the
  analyst in `guardian.toml`), and its verdict is applied by fixed rules (`test_upheld_and_downgraded_rules`).
- **The report is written by code.** The executive summary is a template filled with computed
  values; sentences cite the finding / plan ids or the file they are based on (`guardian/report.py`).
- **Unknown is never zero.** Missing EPSS, KEV, OSV or reachability uses a stated prior, lowers
  confidence and widens the range (`tests/unit/test_scoring.py::test_unknown_never_scores_zero`);
  an OSV outage is reported as "not evaluated", never "0 vulnerabilities" (found and fixed in the
  phase-14 fresh-clone test; `tests/unit/test_report.py::test_unknown_vulnerabilities_are_never_reported_as_zero`).
- **Ground truth.** Detection was checked against `demo/ground_truth.yaml` (7/7 planted
  findings, 3/3 negative controls) — by hand; an automatic scorecard and hold-out seeds were
  **not built**.

## 3. Actions that require human approval

- **Applying any remediation.** `python -m guardian approve P-xxxx --approver "Name"` records the
  name, time and the plan's patch hash (`guardian/remediate.py::approve`). Validation refuses a plan
  that is not approved, was rejected, or whose patch changed after approval
  (`tests/unit/test_remediate.py::test_approval_then_edit_is_refused`).
- **A superseding plan** after a failed validation is created in `pending_approval`; approvals
  never carry over (`guardian/loop.py::close_loop`).
- **Accepting a risk or marking a finding not affected** needs a named person and a reason
  (`python -m guardian accept`, `tests/unit/test_report.py::test_accept_requires_a_name_and_reason`).
  Only those human decisions can produce a `not_affected` VEX statement; a Refuter candidate alone
  never does (`test_refuter_candidate_alone_never_reaches_vex`).
- **No push, merge, publish, deploy or pull request.** No code path does any of these. The demo
  target has no git remote and is only read (`git archive`); fixes are applied in throwaway clones
  under `runs/<id>/work/`. During development a Claude Code hook (`.claude/hooks/block_out_of_scope.py`)
  blocked such commands, and the assistant was also blocked from recording an approval itself.

## 4. Protecting source code, credentials and secrets

- **One secret:** the model key `GEMINI_API_KEY`, loaded from `.env` at runtime
  (`guardian/env.py`), never printed (`python -m guardian doctor` shows presence only), sent only
  in the `x-goog-api-key` header, never in a URL or a file under `runs/`.
- **Redaction** runs on every payload sent to a model and on every tool output: configured key
  values, Google / Anthropic / OpenAI-style keys, GitHub tokens, AWS key ids, private-key blocks,
  bearer tokens (`guardian/evidence.py::redact`, `tests/unit/test_agents.py::test_redaction`).
- **Only excerpts leave the machine**, never whole files or the repository: tool outputs are capped
  at 6,000 characters, package files at 80 lines, source excerpts at a few lines around a call site,
  advisory text at 3,500 characters (`guardian/agents/tools.py`, `llm.py`).
- **Hosts contacted and what is sent:**

  | Host | Sent |
  |---|---|
  | `api.osv.dev` | npm package names and versions; advisory ids; GitHub Action names |
  | `api.first.org` | CVE ids |
  | `www.cisa.gov` | nothing (downloads the KEV catalogue) |
  | `registry.npmjs.org` | package names / versions that `npm` resolves in dry runs and validation |
  | `generativelanguage.googleapis.com` | only when a key is set: redacted finding evidence excerpts and requested tool outputs |

- **Scanned packages are never executed.** Install scripts are read as text from the tarball
  (`fastpath/build.py::inspect_tarball`); `npm` always runs with `--ignore-scripts`; `node --check`
  only parses first-party files. (The design's container build and smoke test were not built.)
- **Agents** have no shell, file-system or network tool; an unknown tool name is refused
  (`test_unknown_tool_is_refused_not_executed`); turns, output tokens and a token budget are capped.

## 5. Untrusted content and prompt injection

Package files, advisory text, source excerpts and tool outputs reach models inside
`<package_content>`, `<advisory_text>`, `<file_excerpt>` and `<tool_output>` blocks; every prompt
says they are data, never instructions, and that a package describing itself as harmless is not
evidence (`guardian/agents/prompts/*.md`). Code adds two checks on top of the prompt: a refutation that
paraphrases the package's own "harmless" comment has no literal quote and is treated as
inconclusive (`tests/unit/test_agents.py::test_refutation_based_on_self_description_is_not_applied`);
a refutation whose only literal quotes are self-describing language ("harmless", "demo", "safe",
"do not worry", …) is also treated as inconclusive
(`test_verbatim_self_description_quote_does_not_support_a_refutation`). The second check is a keyword
list, so other phrasings are not caught. A live adversarial test against a real model has **not** been run.

## 6. Known failure modes and limits

See `docs/KNOWN_LIMITATIONS.md`. The ones that matter most for AI: no live model run yet; a
checked quote proves the cited text exists, not that the conclusion follows; reachability is a
text heuristic; agent cost is not estimated (tokens are counted).

## 7. Auditability

`runs/<id>/audit.jsonl` is append-only and hash-chained: plan creation, approvals and rejections
(actor `human:<name>`), validation start and verdict, diagnosis, human decisions, report
rendering (`guardian/audit.py`). `python -m guardian audit-verify` recomputes the chain and names
the first broken line (`tests/unit/test_remediate.py::test_audit_chain_detects_edits`); the
report prints the verification result. Agent tool calls are recorded per run in
`agent_trace.jsonl` and per finding; they are not yet in the hash chain.
