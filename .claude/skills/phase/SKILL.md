---
name: phase
description: Run one build phase of the Guardian two-day plan by number (0-15). Reads the phase prompt from docs/PROMPTS.md and executes it with its acceptance checks.
argument-hint: [phase-number]
disable-model-invocation: true
---

Run build phase **$ARGUMENTS** of this project.

1. Read `docs/PROGRESS.md` (create it from the phase table in `docs/PLAN.md` if missing) and
   confirm the previous phases are ticked. If an earlier phase is unfinished, say so and ask
   whether to continue anyway.
2. Open `docs/PROMPTS.md`, find the section "Phase $ARGUMENTS", and treat the text inside its
   code block as the instructions for this session. Read every file it tells you to read first.
3. For a phase that touches more than three files, write a short plan (files, order, tests) and
   show it before editing.
4. Build it. Work in small steps; run the unit tests after each step.
5. Run every acceptance check listed in the phase. Report each as pass / fail with the command
   output that proves it. Fix failures; if a check cannot pass inside the time box in
   `docs/PLAN.md`, stop and present the cut line from that file instead of pushing on.
6. Update `docs/requirements.yaml` (`status`, `evidence`) for any requirement ids the phase
   names (some phases name none), `docs/PROGRESS.md`, the README feature table, and
   `docs/KNOWN_LIMITATIONS.md` for anything discovered.
7. Commit with message `phase $ARGUMENTS: <summary>`. Do not push.
8. Finish with: what works now (three lines), what was cut or is fragile, and the exact next
   command for the human. Do not start the next phase.
