# Guardian Report — {{ target }} @ {{ head_ref }} ({{ head_commit_short }})

Run {{ run_id }} · {{ generated_at }} · mode {{ mode }} · baseline {{ base_ref }} ({{ base_commit_short }})

> Claim types: **verified** = read from tool output (evidence id shown) · **derived** = computed
> by Guardian's code · **inferred (AI)** = model judgement. "Unknown" means not established; it
> never means safe.

## 1. Executive summary
{{ summary }}   <!-- every sentence cites finding/evidence ids -->

| Components | Findings | Need attention | Remediated and verified | Remaining open | Accepted risk |
|---|---|---|---|---|---|

## 2. Scope and method
Sample application, repository, commit, licence, how it was modified. Tools and versions.
Data sources and cache age. Models used per agent. What was **not** evaluated and why.

## 3. Component inventory and dependency paths
Counts (direct / transitive, prod / dev, by origin). SBOM files. Container images. CI components.
Dependency-path examples for each finding below.

## 4. What changed (baseline → head)
Per commit: components added / removed / changed, files, resulting findings.

## 5. Findings and supporting evidence (ranked)
For each: id, title, component, dependency path, type, claims by type with evidence ids, score
with factor table, range, confidence, guardrails, refuter verdict, status.

## 6. Recommended and approved actions
For each plan: action, alternatives considered, predicted effect, compatibility impact, rollback,
policy result, approval (who, when, plan hash).

## 7. Validation results
For each plan: checks (baseline tests, apply, build, tests, rescan, SBOM diff, new findings,
policy) with pass / fail / not run, durations, evidence ids. Rejected candidates and why.

## 8. Before and after
Risk score, finding counts, component counts, SBOM diff, prediction vs outcome.

## 9. Remaining and accepted risks
Open findings by band; accepted risks with approver and reason; not-affected (VEX) with
justification.

## 10. Confidence and audit trail
Overall confidence and its drivers. Audit chain verification result. Event counts by actor.

## Appendix A. Evidence index
id · source · command · sha256 · file

## Appendix B. Machine-readable files
guardian-report.json · sbom.*.cdx.json · vex.openvex.json · scorecard.json
