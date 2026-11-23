# Responsible AI & security note (draft — complete in phase 14)

This is a required deliverable. It is written as a draft of the *intended* controls. In phase
14, keep only statements that are true of the built system and add a pointer (file, test or
screenshot) to each. Delete anything that was not built.

## 1. Where AI is used

| Agent | Purpose | Input it sees | Output | Can it change anything? |
|---|---|---|---|---|
| Change Detective | investigate each suspicious change | verified facts, diffs, capability profiles, short package excerpts | AI assessment (inferred claims) | no |
| Risk Analyst | connect advisories to our call sites | advisory text, call-site excerpts | reachability judgement (inferred) | no |
| Refuter | try to disprove findings and plans | the finding, same read-only tools | verdict with reasons | no |
| Remediation Planner | rank fix candidates, write rationale | candidates and dry-run results | plan text | no |
| Diagnostician | explain a failed validation | build/test log excerpts | diagnosis, recommended next candidate | no (the new plan needs a new human approval) |

AI is **not** used for: inventory, vulnerability matching, diffs, scores, policy decisions,
pass/fail of validation, approval, or applying changes. _(pointer: …)_

## 2. How hallucinations are controlled

- Facts come only from tools. Each is stored as evidence with the command and a hash. _(…)_
- Only code writes facts ("verified", "derived"), by rendering fields of tool output. Agent
  output is always labelled inference; the evidence ids and quotes it cites are checked and
  unsupported ones are dropped and counted. _(test: …)_
- Agent outputs are schema-validated; invalid output falls back to a deterministic result. _(…)_
- A second agent with a different prompt (and model) tries to refute important findings. _(…)_
- The report's summary is filled by template from computed values. _(…)_
- Missing data is shown as unknown and lowers confidence; it never counts as "safe". _(…)_
- A scorecard against planted ground truth reports misses and false alarms. _(…)_

## 3. Actions that require human approval

- Applying any remediation: requires an approval record (named person, time, plan hash).
- A plan that replaces a failed one needs its own approval; approvals never carry over.
- Accepting a risk or marking a finding not affected: requires a named person and a reason.
  The refuter agent can only propose it.
- Guardian has no capability to push, merge, publish, deploy or open a pull request. The demo
  target has no git remote and is never written to; fixes live in throwaway clones. A project
  hook blocks such commands during development. _(…)_

## 4. Protecting source code, credentials and secrets

- The only secret is the model API key, read from the environment, never logged. _(…)_
- A redaction pass runs on every string sent to a model or written to the ledger. _(test: …)_
- Only short excerpts are sent to the model, never whole files or the whole repository.
- Data that leaves the machine: _(list hosts and what is sent to each: model API; OSV; EPSS;
  CISA; npm registry; deps.dev)_.
- Scanned packages are never executed; install scripts run only inside the disposable validation
  container, which has no credentials mounted.
- Agents have read-only tools, no shell, no file writes, no general network access, turn and
  budget limits, and do not load this repository's settings.

### Update 2026-11-23: model provider is Gemini

The runtime agents call Google's Gemini API (`generativelanguage.googleapis.com`) instead of
Anthropic's, because that is the key the team has. What leaves the machine, per agent call: the
finding's evidence excerpts (file, line, short excerpt), and the outputs of the read-only tools the
agent requests: short excerpts of first-party source files, of local package files, of OSV advisory
text, and commit file lists. Whole repositories are never sent. Every payload passes `redact()`
first (configured key values, cloud/GitHub token shapes, private-key blocks, bearer tokens). The
key is read from `.env` at runtime, sent only in the `x-goog-api-key` header and never printed or
written to the run directory. Implementation: `guardian/agents/llm.py`, `guardian/evidence.py`.

## 5. Untrusted content and prompt injection

Package files, READMEs, changelogs and advisory text are treated as data in delimited blocks.
An instruction found inside them is reported as a suspicious signal, and a package describing
itself as harmless is not treated as evidence. _(tests: injected README; self-described
"harmless" install script)_

## 6. Known failure modes and limits

_(fill from docs/KNOWN_LIMITATIONS.md: heuristic reachability, npm only, model availability,
scanner database freshness, synthetic fixtures, cost estimates, …)_

## 7. Auditability

Hash-chained audit log of every tool run, agent run, decision, approval and validation check;
`guardian audit verify`; the verification result is printed in the report. _(…)_
