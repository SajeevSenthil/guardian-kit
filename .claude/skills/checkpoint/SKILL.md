---
name: checkpoint
description: Audit the project against every requirement on the organiser's slides and report what is met, partial or missing, plus the best next steps. Argument - day1, final, or empty for everything.
argument-hint: [day1|final]
---

Run a checkpoint for scope: **$ARGUMENTS** (empty means everything).

1. Use the `requirements-auditor` subagent with that scope and wait for its table.
2. Use the `skeptic-reviewer` subagent on the current state of findings, scoring, report
   templates and docs (not just the last diff) and wait for its list.
3. Merge the two into one report for the human:
   - requirements: met / partial / missing counts, and the table rows that are not MET;
   - trust problems from the sceptic, most serious first;
   - the scorecard result for the latest run;
   - test, lint and audit-chain status;
   - "If you have 30 minutes / 2 hours": the best use of each, naming the phase prompt.
4. If scope is `day1`: say plainly whether the three checkpoint questions (what is in the
   application, what changed, what appears risky) can each be answered from one screen.
   If scope is `final`: say plainly whether the chain Prioritized Risk → Recommended Fix → Human
   Approval → Build & Test → Rescan → Verified Remediation runs end to end today.
5. Change nothing unless the human asks.
