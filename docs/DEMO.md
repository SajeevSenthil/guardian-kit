# Demo, pitch and judge Q&A

Depth and sources: `docs/research/06-ux-demo-and-judging.md` (UX, regulation, judging) and
`docs/research/01-prior-art-and-winning-strategy.md` (what other teams will show).

No official scoring sheet was found. **Ask the organisers on Day 1 morning** whether a rubric
exists and how long each demo slot is; adjust the timings below.

## The story (one persona, one incident pattern)

"Priya is the security engineer for a product team. Monday morning: her scanner shows hundreds
of findings, and a pull request has changed the lockfile. Her CVE scanner says nothing new,
because the dangerous changes have no CVE yet. She has one hour."

The seeded changes in our target are harmless replicas of real incident patterns (look-alike
package, install-time script, a patch release that gains a dropper-shaped script, a mutable CI
action that was really compromised in 2025, a floating base image tag). Say "harmless replica" out
loud; never imply we handled live malware. Confirm incident dates and details in
`docs/research/03-threats-and-detection-signals.md` before quoting any.

## Three lines to remember

1. "The first fix failed. Guardian found out by building it, an agent worked out why, and a
   human approved the second one. Nothing was merged."
2. "Facts on this screen are written by code from tool output. Everything the AI says is in
   the other column, labelled, with its evidence checked."
3. "We planted risks in the app before the demo, including some the detectors had never seen.
   Here is the scorecard, misses included."

## Day-1 checkpoint (3 minutes)

The organiser's sentence: **"Show us what is in the application, what changed, and what appears
risky."** Answer it in exactly that order, one screen each. The scan has already run; keep a
live re-run for questions.

| Time | Screen | Say |
|---|---|---|
| 0:00 | Overview | "This is goof, an open-source Node app, containerised, at a pinned commit. Guardian compared a trusted baseline with the current branch. *N* components, *M* findings, *K* need attention." |
| 0:20 | Inventory | **What is in it.** "Every component with version, direct or transitive, production or dev, and where it came from. The SBOM is CycloneDX. Pick any transitive package: here is the path back to the dependency we chose." Show one path. Two seconds each on the container and CI tabs. |
| 0:55 | Findings → one transitive CVE | "Known vulnerabilities, each traced to the direct dependency that brings it in, with the fix version. That is the part every scanner does." (15 seconds, then move on.) |
| 1:10 | Changes | **What changed.** "Four commits since baseline. One added a dependency. One bumped a helper by a patch version. One changed the base image. One added a CI workflow. None of them has a CVE." |
| 1:40 | Findings → the look-alike package | **What appears risky.** "A package one letter-swap from lodash, installed from a tarball instead of the registry, with an install script that lists secret-looking environment variables. Left column: facts, written by code, each with the tool output behind it." Open one evidence drawer. "Right column: the AI's assessment, labelled." |
| 2:20 | Findings → the patch bump | "The patch release gained an install script and a 99 KB encoded file. Guardian compared the two versions without running either." |
| 2:40 | Overview scorecard | "We planted these, harmlessly. Guardian found *x* of *y* seeded and *a* of *b* hold-out risks it had never seen; this is what it missed. Tomorrow: which ones matter, a fix, a human approval and proof." |

Do not show: the terminal, raw JSON, long CVE tables.

## Final demo (6 minutes)

The organiser's sentence: **"Show us how the Guardian takes a finding from detection to verified
remediation."** One finding, the top-ranked one, goes through their whole arrow: Prioritized
Risk → Recommended Fix → Human Approval → Build & Test → Rescan → Verified Remediation.
Discover and detect ran before going on stage. Planning, approval and validation happen live.
Start the first validation as early as the script allows, because it is the slow part.

| Time | Screen | Say / do |
|---|---|---|
| 0:00 | Slide 1 | Persona and problem in two sentences. One regulation sentence (below). |
| 0:25 | Overview | Funnel: "*N* components → *M* findings → *K* that matter. Scorecard: *x* of *y*, hold-outs included. Yesterday: how Guardian sees. Today: how it decides and acts." |
| 0:45 | Findings (ranked) | **Prioritized risk.** "Top of the list is not a CVE: the look-alike package. Below it, two vulnerabilities: this one has the higher CVSS, but no application file imports the package, so it ranks low. This one is called with request data at this line, so it ranks high. Each factor shows its evidence grade; unknowns are shown as unknown and widen the range. The score is computed by code; the model never sets it." |
| 1:30 | Finding #1 → Investigation | "Verified facts on the left, AI assessment on the right. A second agent argued the other side: upheld." |
| 1:55 | Remediation | **Recommended fix.** "Candidates, each dry-run against the manifests. The first is what a dependency bot would do: drop it from the manifest. Policy gate passes." |
| 2:15 | Approve | **Human approval.** Type a real name, click Approve. "The approval is bound to the hash of this exact patch." Validation starts. |
| 2:25 | Validation + Agent trace | **Build & test.** Live stepper. While it builds: "This runs in a throwaway clone and a container. The repository itself is never touched, and Guardian cannot push or open a pull request." |
| 3:05 | Validation: failed | "The build passed and the app failed to start. The fix was wrong, and Guardian knows only because it tested it." Show the trace: "The diagnostician agent read the log, found the missing-module error and the line that still imports the package, and recommends the candidate that removes the import too." |
| 3:35 | Remediation (new plan) → Approve | "A new plan, a new hash, so a new approval. The earlier approval does not carry over." Approve. |
| 3:45 | Validation, second run | **Rescan.** Stepper again; narrate the checks: baseline test, apply, build, smoke test, rescan, SBOM diff, new findings, policy, prediction. (If the build is slow, switch to the Report screen and come back.) |
| 4:40 | Validation result | **Verified remediation.** "Finding gone, no new findings, exactly one component removed, risk from *a* to *b*, prediction matched." |
| 4:55 | Report | "Human-readable and machine-readable: inventory, evidence, ranking, both approvals, both validations, remaining risk, what was not evaluated, and an audit trail that verifies." |
| 5:20 | Slide: architecture | "Five agents where judgement is needed, code where correctness is needed, one human gate." |
| 5:40 | Slide: limits + stretch | What is real, what is synthetic, what is next. Close with line 1. |

If two live validations do not fit the slot (measure in phase 15), run the first one before
going on stage and show its recorded result with the REPLAY badge, then run only the second
live. Say that this is what you are doing.

## Slides (six at most)

1. Title, persona, problem ("the dangerous change had no CVE").
2. What Guardian does: the five verbs, one line each.
3. Architecture diagram (`docs/architecture.png`).
4. The loop: plan → approve → fail → diagnose → re-plan → approve → verified, with one real
   screenshot of a finding's "Verified facts / AI assessment" columns.
5. Results: scorecard numbers (seeded and hold-out), timings, estimated agent cost. Measured
   values only.
6. Limits, Responsible AI in four bullets, next steps.

## The regulation sentence (checked dates are in research 06 §1; do not go beyond them)

"The EU Cyber Resilience Act's reporting duty for actively exploited vulnerabilities started on
11 September 2026, with the full requirements applying from December 2027; automotive and
industrial rules ask the same question: do you know what is in your product, and can you show
how you handled a problem? Guardian is a prototype of that engineering workflow."

Never say "CRA-compliant" or "meets ISO/SAE 21434". Bosch already runs an ORT-based compliance
pipeline that inventories components and looks up CVEs, so do not present "SBOM + CVE list" as
the novelty. Present the change view, the non-CVE investigation, the evidence/inference split
and the approve → build → test → rescan loop.

## Responsible AI, in four sentences

"The AI never writes facts: code does, from tool output, and everything the AI says is
labelled inference with its cited support checked. The AI never decides: scores, policy and
pass/fail are code. The AI never acts: a named human approves a specific patch, and fixes run
only in a throwaway clone. Package contents are treated as hostile data, analysed statically,
and only short excerpts leave the machine."

## Likely questions and honest answers

| Question | Answer (adapt to what was actually built) |
|---|---|
| Does it only work on your demo app? | "Detectors are generic; a test fails if our code names a seeded package. The scorecard separates hold-out seeds the detectors never saw, and we ran detection on *second app* (README, 'also tested on'). Remediation is npm-only today." |
| How do you know the AI is not making things up? | "It cannot state a fact. Facts are rendered by code from tool output. The AI column is labelled, and the evidence it cites is checked; *n* quotes were dropped in this run." Show the count. |
| What does the AI actually add over the scanners? | "Scanners list. The agents investigate what a change does, connect an advisory to our call sites, argue against each other, rank fix options, and when a fix fails they diagnose it and re-plan. Without them (offline mode) you keep the verified layer and lose the investigation and the recovery loop." |
| Is that failed fix staged? | "It is a real candidate, the manifest-only change a dependency bot produces, and it really fails the start-up test. The planner's dry run sees manifests, not runtime; that is why validation exists." (If the planner now ranks the better candidate first, say that, and say you chose the naive one to show the loop.) |
| False positives? | "The scorecard has negative controls. For typosquats we compare against popular names and the project's own dependencies with thresholds; here is one it rejected." Give the measured number. |
| What if a scanner is wrong or missing? | "Two vulnerability sources are merged and both are shown. A tool that did not run is 'not run', never 'clean'." |
| Prompt injection from a malicious README? | "Package text is passed as delimited data, agents have read-only tools and no shell, and facts need tool evidence. We have a test with an injected README." |
| How is reachability done, how accurate? | "Import graph plus symbol references with a file:line witness. It is a heuristic tier, labelled as such; it is not a full call graph, and dynamic loading is reported as unknown." |
| Why not let the agent open the PR and merge? | "The rules forbid it and so does good practice. Guardian writes the patch and the PR text to disk; a human decides what happens to them." |
| How does this fit an existing SBOM pipeline? | "It reads and writes CycloneDX and writes OpenVEX, so it can sit after an existing analyzer step and before evaluation." (Only claim formats that were built.) |
| Cost and latency? | Give measured per-run agent cost estimate and timings from the README. |
| What data leaves the laptop? | "Short excerpts of package and advisory text and our own call-site lines go to the model API; package names and versions go to public advisory APIs. No secrets, no whole files. Listed in the Responsible AI note." |

## Failure plan

| If | Then |
|---|---|
| Wifi or API fails | `guardian ui --replay demo/recorded/final`; say "this is a recording of this morning's run" (badge is visible) |
| Docker build hangs | Show the recorded validation; offer to run it afterwards |
| UI crashes | CLI commands in `demo/RUNBOOK.md` produce the same story; the HTML report opens from disk |
| A judge asks for something not built | "Not built. Here is how the design would take it." Point at the limitations slide. |

Before going on: laptop on power, notifications off, font size up, caches warm, images
pre-pulled, replay tested, a second browser tab with the HTML report already open.
