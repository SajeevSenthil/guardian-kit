---
name: guardian-contracts
description: The evidence ledger and typed-claim rules, data contracts, run directory layout and honesty rules for Guardian. Use when creating or changing findings, claims, evidence, scoring, plans, validation results, the report, or any UI that shows them.
---

# Guardian contracts

Authoritative code: `guardian/contracts.py`. Design: `docs/ARCHITECTURE.md` sections 4, 6, 7, 10.

## The three rules

1. **Evidence is minted only by tools.** `ledger.add_evidence(kind, source, excerpt, raw, *,
   source_version, command, locator, synthetic)` is called inside tool wrappers, one record per
   fact (one finding object, one lockfile entry, a few source lines), so every fact has a small
   excerpt. Agents receive evidence ids; they cannot create them.
2. **Every claim is typed, and only code writes facts.**

   | Status | Written by | Must have | Rendered as |
   |---|---|---|---|
   | `verified` | code only: `ledger.verified(text, evidence_ids, derived_by)`, a sentence rendered from the fields of the cited evidence | evidence ids, `derived_by`; never `model`/`agent` | "Verified facts" column, solid chip, link to evidence |
   | `derived` | code: a computation over verified facts (distance, diff, score) | `derived_by` + input evidence ids | outlined chip, "computed" |
   | `inferred` | agents, always | `model`, `agent`; optional evidence ids + literal `quotes` as support | "AI assessment" column, dashed chip, "AI" tag |

   Every agent claim goes through `ledger.check_claim`: status is forced to `inferred`; unknown
   evidence ids are dropped; quotes that do not literally occur in the cited evidence (minimum
   8 characters, whitespace-normalised) are dropped; `support_checked` records the outcome;
   each drop is an audit event. A model can therefore never promote its own claim to a fact.
   A checked quote shows that the cited text exists, not that the conclusion follows: the UI
   says "support checked", never "verified", for agent claims.
3. **Unknown is never zero.** Missing signal → `None` + grade `unknown` → prior from
   `guardian.toml`, lower confidence, wider range, grey "unknown" in the UI. A check that did not
   run has `passed=None` and is reported as "not run". Anything that could not be evaluated is a
   `NotEvaluated` record and appears in the UI and the report.

## Who decides what

| Decision | Made by |
|---|---|
| Which tools to run, what to look at next, how to explain, what could be wrong | agents |
| Whether a fact is true | tools (evidence) |
| Score, band, confidence, guardrails | `scoring.py` |
| Whether a plan passes policy | conftest |
| Whether a fix worked | `validate.py` checks |
| Whether a fix is applied | a human approval record bound to `plan_hash` |
| Whether a finding is "not affected" or an accepted risk | a named human; agents only propose |

## Writing a new tool wrapper (checklist)

- Probe the real tool first (`tool-probe` subagent) → `docs/tool-notes/<tool>.md` + fixture.
- Run through `tools/proc.run([...])` (argument list, timeout, no shell).
- Store the raw output as evidence; build excerpts small enough to quote (one finding, one line,
  one JSON object).
- Return pydantic models from `contracts.py`, with `evidence_ids` set.
- Missing tool / timeout / non-zero exit → return a result that says "not run" with the reason;
  do not raise through the conductor, do not return an empty list that looks like "clean".
- Unit test from the fixture; no network in unit tests.

## Writing a detector

- Input: inventory, changes, capability profiles. Output: raw signals → `Finding`.
- Generic only. No package names, file names or ids from the demo target in any code under
  `guardian/`. A test reads the forbidden strings from `demo/ground_truth.yaml` and greps.
- Detectors write facts (`verified`, `derived`); they do not write interpretations of intent.
- A package's own comments or description ("harmless", "demo", "safe") are recorded as a fact
  about its contents and never lower a finding's risk.
- Each finding: `type`, `component_purl`, `dependency_paths`, `claims` (at least one verified),
  `initial_severity` from the rule table, `detector`, `new_in_head`, and `introduced_by_commit`
  when it is a change.
- A detector that cannot evaluate (no network, tool missing) emits a `not_evaluated` note for
  the report's "what was not evaluated" section.

## Run directory

See `docs/ARCHITECTURE.md` section 7. The UI and the report read only from `runs/<run_id>/`.
Anything shown on screen must be reproducible from those files, which is also what makes replay
mode possible.

## Audit log

`audit.append(actor, action, subject, detail)` for: every tool run, agent run, finding raised,
claim downgraded, score computed, plan proposed, policy result, approval, each validation check,
report generated. Actors are `human:<name>`, `agent:<name>` or `code:<module>`. The chain is
verified by `guardian audit verify` and the result appears in the report.

## Honesty rules for text (UI strings, report, README)

- Label fixtures `SYNTHETIC`; label replay `REPLAY`; label model text `AI`.
- No "all", "guarantees", "real-time", "production-ready".
- Numbers come from a measurement in this repo or they are not written.
- Limitations go to `docs/KNOWN_LIMITATIONS.md` the moment they are discovered.
