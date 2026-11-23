# 01 — Prior art and winning strategy

Research date: 2026-11-23. Scope: the Bosch "Software Supply Chain Guardian" brief (`docs/HACKATHON_BRIEF.md`).

**How to read this.** Everything in sections 1 and 2 comes from pages actually fetched in this research pass (listed in Sources), read through a page-summarising fetch tool, so wording is paraphrased and details should be spot-checked before being quoted on a slide. Items marked **[unverified]** come from background knowledge or search-result titles only and were not read. Section 3 is our own analysis, not sourced fact.

---

## TL;DR

1. **The whole pipeline in the brief is already commodity.** GitHub (Dependabot alerts assignable to agents), GitLab (dependency auto-remediation), FOSSA (fossabot) and several small open-source repos already do scan → bump → test → rescan → PR with a human merge. A team that only reproduces that loop is showing judges something they can already buy.
2. **What nobody in the open-source set does well** is the part the brief asks for in its own words: "clearly separate verified evidence from AI-generated inference", "confidence level", "detect newly introduced problems", "audit trail". These are trust features, and they are cheap to build.
3. **Security hackathon judges reward restraint.** The CrowdStrike and GitLab winner write-ups both single out agents that check AI output, say "inconclusive", try to break their own answer, and require named human approval.
4. **Recommended identity for our entry:** a guardian that *proves* things. Every claim carries an evidence tag, a second agent tries to refute it, the fix is validated by a real build/test/rescan with an SBOM diff, and the system is scored against seeded ground truth on stage.

---

## 1. Prior art

### 1.1 Open-source projects (READMEs read)

| Project | Shape | Stages / agents | Fix validation | Human approval | UI | Idea worth borrowing |
|---|---|---|---|---|---|---|
| **Hitesh564/agentic-vulnerability-remediator** | Python CLI, closed loop, Python-only | OSV discovery → CVSS/fix ranking → per-run venv → **baseline pytest** → upgrade → failure **diagnosis classifier** → LLM repair of calling code → deterministic gate (APPLY / REGENERATE / REJECT) → independent OSV re-query | Baseline tests must pass first; post-upgrade and post-repair pytest; fresh OSV query decides success, not the agent | None described | CLI plus artifacts (`report.md`, logs, decision JSON, per-attempt diffs) | **Baseline-first and fail-closed.** Refuse to remediate if tests were already red; classify failures so only "dependency compatibility" failures trigger LLM repair; generator and gate are separate components |
| **tonywangs/code-canary** ("Dependency Canary") | Next.js web + API + RAG agent package; Modal services | Upload repo/ZIP/image → SBOM → enrich from NVD/OSV/GHSA → index into vector store → Q&A and patch plans → PDF/Markdown report | None described | None described | KPI dashboard, interactive severity-coloured dependency graph, natural-language Q&A with sample questions | **It won** (README states 1st Place Overall at an AI Agent & Infra hackathon hosted by Lux Capital, Modal, Cognition, AWS, Ramp) with no validation loop at all. Lesson: a clean graph, a question like "what single upgrade removes the most critical CVEs?", and a **zero-config mock mode that always demos** beat depth that fails live |
| **ericrihm/depfence** | Static-only Python CLI, 14 ecosystems | Lockfile detection → async metadata fetch → 53 package scanners + 32 project scanners (workflows, Dockerfiles) → enrichment (EPSS, CISA KEV, OpenSSF Scorecard, reachability) → A–F grades → suppressions/baselines | `depfence fix --apply` exists; validation not described | Not described | table, JSON, SARIF, HTML, CycloneDX 1.5, SPDX 2.3; `watch` mode; MCP server; pre-commit; GitHub Action | **Non-CVE detector catalogue**: composite typosquat/slopsquat score (Levenshtein + character confusion + keyboard adjacency + affix tricks), install-hook checks, **verifying that pinned SHAs and versions actually exist**, prompt-injection strings aimed at AI security agents inside packages. Also the invariant "never executes package code", and network failures degrade to INFO rather than CRITICAL |
| **msaad00/agent-bom** | CLI + control plane + MCP server (86 tools) | Read-only collection → normalise to shared Finding / graph contracts → correlate reachable risk → owner + SLA → remediation → rescan → export / runtime policy | Rescan confirms the fix held | Explicit operator opt-in for anything that writes; no approval workflow described | Investigation path view; architecture graph with **Current / Proposed / Difference** views; SARIF, JSON, PR summaries | **"Missing evidence is never converted into a factual zero"**: unknown is reported as partial/unavailable. And the exposure path framing (exposed service → workload → image digest → package → identity → data) as the unit of a finding. VEX is not mentioned in its README |
| **aenealabs/aura** | AWS-heavy platform (Neptune + OpenSearch GraphRAG, ECS Fargate sandbox), React 19 UI | Orchestrator, Coder (read-only tools), Reviewer (OWASP/policy), Validator (5 layers), Monitor; failed patches loop back up to 3 times | Sandbox with no inbound, no public IP, egress limited to DNS/HTTPS. README's own status notes say the sandbox step reports SKIPPED unless enabled and does not yet receive patched code | Every patch needs approval; four autonomy levels and industry presets defined but not applied | Many dashboards (HITL approvals, "Mission Control" reasoning view, Trust Center); screenshots use sample data | **Autonomy levels as explicit policy** and a network-restricted sandbox spec. Also a cautionary tale: a large surface of dashboards and ADRs with the core loop not wired. Judges who click will notice |
| **farhadabbasiamiri/python-sbom-agent** | Python scanner + local LLM agent | Parse deps → OSV → dedupe → weighted score (severity 65 / count 25 / fix availability 10) → extract fixed versions → **check the target version is itself clean and really exists on PyPI** → Python-version compatibility filter → local agent summary | Recommendation-level only (target version checked against OSV and PyPI) | None | JSON report; Gradio planned | **Validate the recommendation before proposing it** (does the fixed version exist, is it itself vulnerable, is it compatible with the runtime). And "no data leaves the machine" as a responsible-AI line |
| **kamali1-ux/Autonomous-Software-Supply-Chain-Security** | React + Spring Boot + FastAPI/Gemini + MySQL, Docker Compose | Discover → SBOM (CycloneDX 1.5) → Scan (OSV, NVD, KEV) → Analyze → Explain → Recommend → Heal → Verify → Report | Snapshot manifest → minimal bump → tests → regenerate SBOM → rescan → VERIFIED, one-click rollback. The README's demo labels the test run "simulated" | State machine PENDING_APPROVAL → APPROVED → APPLIED → VERIFIED / ROLLED_BACK with role-based sign-off and reviewer remarks | SBOM explorer, **What-If Fix Simulator**, Approval Center, live sandbox log, PDF + CycloneDX export, audit log | **This is almost exactly the brief, already built.** It is the clearest picture of the median strong entry. Borrow the approval state machine and formula-based score with AI limited to narrative. Note its stated weights do not reconcile with its own demo arithmetic, and its tests are simulated: both are openings for us |

Pattern across all seven: only one (Hitesh564) runs a real test suite against a real upgrade, and it has no approval step; the two that have approval workflows (aura, kamali1-ux) do not demonstrably run real validation. **No project read here combines real validation, real approval and an evidence/inference split.**

### 1.2 Commercial and platform products

| Product | What was read | Mechanism | Idea worth borrowing |
|---|---|---|---|
| **GitHub: Dependabot alerts assignable to AI agents** (changelog, 2026-04-07) | Read | From an alert, "Assign to Agent" (Copilot, Claude, Codex). Agent uses the advisory plus how the repo uses the dependency, opens a **draft PR**, investigates build/test failures and proposes code changes; can **downgrade to last known safe version** when a package is compromised and no patch exists. Multiple agents can each open a draft PR for comparison. GitHub warns fixes are not always correct and must be reviewed | **Downgrade/rollback as a first-class remediation** for malware (maps to the brief's "pin a trusted version"); competing candidate fixes compared side by side |
| **GitLab dependency scanning auto-remediation** (blog, 2026-07-16, beta) | Read | Stage 1 deterministic bump to nearest fixed version in an MR. Stage 2, only if the pipeline fails, an agent reads pipeline errors, the changelog and code usage, and commits fixes; if it cannot get green it posts findings and stops. "Never merges on its own." Cooldowns, closed MRs not re-created, severity threshold, cap at patch/minor/major | **Deterministic first, agent only on failure**, plus bump-size caps as policy and "stop and hand over with findings" as a valid outcome |
| **FOSSA fossabot** (blog) | Read | Loading code → change detection → impact detection → adapt. Reads release notes and migration guides, uses static/type analysis to find where the app uses changed APIs; PR carries a merge recommendation and what was analysed. Self-scores on an Accuracy/Consistency/Correctness dataset, weighting "called a breaking change safe" as the worse error | **Upgrade impact analysis** (which of our files touch the changed API) and **publishing an eval with asymmetric error costs** |
| **Google DeepMind CodeMender** (blog, 2025-10-06) | Read | Agents with static/dynamic analysis, differential testing, fuzzing, SMT solvers; an **LLM critique tool compares original and modified code** for regressions and the agent self-corrects. Only patches that fix root cause, are functionally correct, cause no regressions and follow style go to humans; all patches human-reviewed before upstreaming. 72 fixes upstreamed in about six months | **A separate critic that diffs before/after**, and an explicit four-part acceptance bar for a fix |
| **Trail of Bits Buttercup** (AIxCC, 2nd place, open source) | Product page read | Multi-agent; static analysis plus AI-guided fuzzing; every candidate bug **reproduced before it is reported**; every patch verified to close the bug without breaking the build. Page reports 28 vulnerabilities, 19 patches, 90% patch accuracy, non-reasoning LLMs only | **"Proven before reported"**: a finding is not a finding until something reproduced it. For dependencies the analogue is a reachability witness (file:line import/call chain) or a rescan |
| **Endor Labs** (third-party review read, not vendor docs) | Read | Function-level reachability via call graphs with EPSS; minimum safe version bump PRs for direct and transitive; backported patches where no upgrade exists. The review flags the "up to 97% fewer findings" figure as a vendor best case | **Reachability as the noise filter** and "minimum safe bump" rather than "latest" |
| **Socket** (alert-type docs read) | Read | Behavioural/capability alerts rather than CVEs: install scripts, typosquat, network / shell / filesystem / env-var access, obfuscated code, high-entropy strings, eval, new author, unstable ownership, recently published, chronological version anomaly, manifest confusion, git/HTTP dependencies; GitHub Actions data-flow-to-sink alerts; four explicitly "AI-detected" alert types | **Capability diff between two versions of a package** ("this update newly gained network + env access + a postinstall") is the best single non-CVE signal for the brief's "suspicious package update" |
| **Aikido** (search result only) | **[unverified]** | Product pages titled "Patch CVEs without upgrades" suggest backport-style patched libraries | — |
| **Snyk agent fix, Renovate merge confidence, Seal Security, Chainguard** | **[unverified]**, not read in this pass | From background knowledge: Renovate surfaces crowd-sourced adoption/passing-rate signals per update; Seal ships backported patched versions of old releases; Chainguard ships minimal, signed, low-CVE base images with SBOMs and provenance | Worth a 10-minute check if we cite them. Chainguard-style **base image swap** is a strong, visual "update the container base image" remediation with a large before/after CVE delta |
| **Other AIxCC finalists (Team Atlanta's Atlantis, etc.)** | **[unverified]**, search titles only | — | A GitLab hackathon winner list mentions a "DELTA Cyber Reasoning System" fuzzing project, so CRS-style entries do appear at hackathons |

### 1.3 What the prior art tells us

- **Table stakes (do not present as innovation):** SBOM via Syft/CycloneDX, OSV lookup, EPSS + KEV enrichment, weighted 0–100 score, LLM narrative, dependency graph, PDF report, approval button.
- **Emerging norm in real products:** deterministic bump first, agent only when the build breaks; draft PR; never auto-merge; stop-and-hand-over is acceptable.
- **Rare, and requested by the brief:** evidence vs inference separation, confidence that means something, "newly introduced problems" detection via SBOM diff, capability diffing of package versions, self-evaluation against ground truth, VEX output.

---

## 2. How judges score, and what winners did

### 2.1 Criteria actually published

- **GitLab AI Hackathon 2026:** technical work, design, potential impact, idea quality.
- **Microsoft AI Agents Hackathon 2025** (as reported by a third-party guide): innovation, impact, usability, solution quality, category alignment.
- **Agentic AI Innovation Challenge 2026** (same guide): innovation and creativity, technical implementation, real-world impact, UX and design, presentation and demo.
- **Bosch's own brief** gives the rubric away without weights: "Core capabilities demonstrate completeness. Stretch goals demonstrate innovation." Deliverables are tagged "Show. Explain. Enable. Inspire.", and a Responsible AI & security note is mandatory. Bosch's actual scoring sheet was not found; treat the mapping below as inference.

Likely Bosch buckets and where the evidence is: completeness (five stages, both checkpoints), innovation (stretch goals), technical depth (architecture diagram, real validation), demo quality (the exact Day-2 sentence: "detection to verified remediation"), responsible AI (hallucination control, approval points, secret handling), and industrial relevance. That last one is our inference: Bosch ships regulated embedded and automotive software, so SBOM/VEX and audit-trail language is likely to resonate (**[unverified]** as a judging factor).

### 2.2 What winning security-agent projects did

**CrowdStrike AgentWorks hackathon** (vendor write-up of winners):
- *Exclusion Adversary* drafts the narrowest safe detection exclusion, **then tries to bypass its own draft**; in testing it caught a wildcard flaw and tightened the rule.
- *Help Desk Takeover Defender*: investigation in about 70 seconds versus 20–30 minutes manually; **deterministic scoring; every containment step needs named human approval**.
- *Agent Smith* inventories MCP servers on endpoints against an approved list and opens a governance case.
- Judges praised an agent's ability to **disclose missing evidence, avoid unsupported conclusions and preserve human control** as much as speed, and praised a runner-up for reproducible tests and for returning "inconclusive".
- Stated lessons: solve a real problem; use the model only for judgment and deterministic tools for everything else; guardrails (caps on tool calls, retries, spend); measurable outcomes against datasets; creativity.

**GitLab AI Hackathon 2026** (security-relevant winners):
- *RedAgent* ("Most Impactful") **checks AI-generated security reports** so findings are verified before developers act.
- *SecurityMonkey* (honourable mention) **injects known vulnerabilities into a test branch and scores how well scanners catch them**.
- *Gitdefender* (Grand Prize, Google Cloud track) finds the bug, writes the fix and opens the review.
- *Compliance Sentinel* blocks merges on critical violations; *MR Compliance Auditor* maps evidence to SOC 2 controls on a live dashboard.

**Dependency Canary** (code-canary): first place overall with a graph, Q&A, a report and a mock mode. Demo reliability and one memorable question carried it.

**Generic guide (tensorhack.com):** winners act on real systems and change state; pick one narrow workflow and finish it; show logs, tool calls, retries, permissions and the point where a human can stop the agent.

### 2.3 Translating that into a demo

- One scenario, end to end, in under five minutes, with a recorded fallback.
- Put a **number with a baseline** on screen (for example: 212 raw scanner findings → 9 need attention → 1 fix removes 6; 7/8 seeded risks caught, 0 false "verified").
- Show the agent **declining** to do something (fix rejected because tests fail or because the bump introduces a new CVE), then recovering with an alternative. A refusal is more persuasive than a clean run.
- Make the approval a real gate: nothing is written to the branch until a named human clicks, and the click is in the audit log.

---

## 3. The obvious solution, and how to beat it

### 3.1 What roughly 70 of 100 teams will ship (our estimate)

Claude Code, given this brief, tends to produce:

- Syft or cdxgen → CycloneDX; Grype / Trivy / OSV-Scanner → findings JSON.
- LangGraph or CrewAI with five agents named after the five brief stages, each a thin prompt around one tool.
- LLM-written "risk summary" and an invented weighted score (CVSS + EPSS + KEV), with "confidence: 0.87" generated by the model.
- Typosquat check by Levenshtein distance against a top-packages list; a regex for `postinstall`.
- Streamlit or Next.js dashboard with a pyvis/D3 dependency graph, severity pie chart, chat box.
- "Approve" button → version bump → `docker build` → rescan → green tick.
- Juice Shop, WebGoat or a Log4Shell demo app as the target.

Typical weaknesses a judge can find in two questions: reachability is the LLM's opinion; confidence numbers are made up; evidence and inference are mixed in one paragraph; tests are not really run, or the app has none; no detection of *new* problems the fix introduces; nothing measures whether the guardian is right; the guardian itself runs unpinned tools and would execute a malicious install script while scanning it.

### 3.2 Differentiators, ranked by judge impact versus build cost

Impact and cost are our estimates on a 1–5 scale for a small team with AI coding agents. Brief references are to `HACKATHON_BRIEF.md`.

| # | Differentiator | What it is, concretely | Brief hook | Impact | Cost | Verdict |
|---|---|---|---|---|---|---|
| 1 | **Evidence ledger: VERIFIED / DERIVED / INFERRED** | Every claim in UI and report is a record with a type, the tool command and output hash that produced it, or `INFERRED` with model and prompt id. The LLM may only cite ledger ids; any sentence without a citation is rendered as inference. Unknown is shown as unknown, never as zero | "clearly separate verified evidence from AI-generated inference"; Responsible AI note; audit trail | 5 | 2 | **Build first.** It is a schema and a rendering rule, and it becomes the answer to "how do you control hallucinations" |
| 2 | **Seeded-ground-truth scorecard** | Fork the sample app, plant about 8–10 known risks (typosquat, malicious postinstall in a local-registry package, lockfile integrity mismatch, unpinned GitHub Action, `latest` base image, reachable vs unreachable CVE pair, a dev-only CVE). Run the guardian, show precision/recall and the misses, live | "Drive measurable outcomes"; Day-1 "at least one supply-chain anomaly" becomes eight | 5 | 2 | **Build early**; it doubles as the regression suite and the demo script. Mirrors GitLab's SecurityMonkey |
| 3 | **Real validation with SBOM diff and a rejected fix** | In a throwaway container/branch: baseline tests → apply → build → tests → rescan → before/after SBOM diff listing removed, added and changed components and any **new** CVEs. Demo includes one candidate that fails (breaks tests or pulls in a new vulnerable transitive) and the fallback that passes | Day-2 step 4 almost verbatim; "detect newly introduced vulnerabilities or dependencies" | 5 | 3 | **Core.** Most teams will fake or skip the failure path. Baseline-first rule borrowed from Hitesh564 |
| 4 | **Adversarial verifier ("refuter") agent** | A second agent with a different prompt, and ideally a different model, whose only job is to disprove each high-priority finding and each proposed fix: wrong version range, not in the production dependency closure, vulnerable symbol never imported, fix version itself affected. Outcome per finding: upheld / downgraded / inconclusive, with reasons, in the ledger | "confidence level"; hallucination control; "request further review" | 4 | 2 | **Build.** Confidence becomes a function of evidence count and refuter outcome, not an LLM number. Mirrors Exclusion Adversary, RedAgent and CodeMender's critic |
| 5 | **Reachability with a witness, emitted as VEX** | For the app's language, compute import/call evidence from our code to the vulnerable package or symbol (AST import graph plus grep for advisory-listed symbols is enough). Reachable findings show the file:line chain; unreachable ones are exported as OpenVEX `not_affected` with a justification, and the rescan consumes the VEX file | Stretch goal 1; "remaining or accepted risk"; machine-readable report | 4 | 3 | **Build a narrow version** (one language, import-level, symbol-level for 2–3 showcased CVEs). State limits openly (dynamic imports). VEX formats and scanner flags are **[unverified]** here; confirm against Trivy/Grype docs |
| 6 | **Capability diff for suspicious updates** | Diff two versions of a package tarball without executing it: new install scripts, new network/process/env/fs API use, new obfuscation or high-entropy blobs, new maintainers, publish-time anomalies. Output: "version X→Y newly gained: postinstall, outbound HTTP, reads env" | Day-2 step 2 ("compare package versions… suspicious scripts"); stretch goal 4 | 4 | 3 | **Build for one ecosystem.** Socket's alert list is the checklist. Static-only, as depfence insists |
| 7 | **Scenario replay of a real attack** | Recreate a well-known incident in the sandbox with a harmless stand-in package on a local registry (a lockfile change that introduces a new transitive with an install script, in the style of the 2018 event-stream compromise, or a CI action moved off a pinned SHA). The guardian catches it at the PR | Day-1 checkpoint "what changed"; "Inspire" | 4 | 2 | **Use as the demo narrative**, reusing #2 and #6. Never publish anything publicly (hard rule). Incident details are from background knowledge, **[unverified]** in this pass |
| 8 | **Counterfactual fix planner** | Before touching anything, enumerate candidate actions (minimum safe bump, major bump, parent upgrade for a transitive, override/pin, remove, base image swap, block by policy) and resolve each in dry-run to predict CVEs removed, components added, semver distance and files using changed APIs. Rank; human approves one; prediction is then compared with the actual result | Day-2 step 3 ("expected risk reduction, compatibility impact and rollback option") | 4 | 3 | **Build if time on day 2.** kamali1-ux has a "What-If Simulator", so the differentiator is that ours resolves for real and is checked against the outcome |
| 9 | **Guardian guards itself** | The guardian's own SBOM, pinned tool versions and digests, a scan of itself in the report, no package code execution, network-restricted sandbox, secret redaction before any LLM call, and prompt-injection handling for text read from packages (READMEs, changelogs, advisories treated as data) | Responsible AI & security note; "how source code, credentials and secrets are protected" | 3 | 1 | **Cheap, do it.** One slide and one command. depfence shows packages now carry strings aimed at AI reviewers, so the injection point is real |
| 10 | **Policy-as-code gate with approval state machine** | A few Rego/Conftest rules (no unpinned actions, no `latest` images, no install scripts from packages younger than N days, no KEV in the production closure) evaluated on the SBOM and plan; approval record with approver, timestamp, plan hash; autonomy levels as policy | Stretch goals 3 and 5; "Human Approval"; hard rule on auto-merge | 3 | 2 | **Build minimal.** Many teams will have an approve button; few will bind the approval to a hash of the exact plan that was validated. Add one Cosign verification of the base image if time allows |
| 11 | **Continuous monitoring / time travel** | Re-evaluate a stored SBOM against today's advisories without rebuilding; demo by replaying the advisory feed from a past date to "today" | Stretch goal 6; the word "continuously" in the problem statement | 3 | 2 | Optional. Good 20-second moment, low risk |

**Suggested build order:** Day 1: 1, 2, the discovery/detection core, 6 (one ecosystem), 9. Day 2: 3, 4, 5, 10, then 8 or 11 if green. Use 7 as the storyline throughout.

### 3.3 Positioning lines for the pitch (ours, to test)

- "Other guardians tell you what they think. Ours shows what it can prove, marks what it guesses, and lets a second agent try to prove it wrong."
- "We planted eight attacks in the app before the demo. Here is the scorecard, including the one we missed."
- "The first fix the agent proposed was rejected by its own validation. Here is why, and here is the one that passed."

### 3.4 Risks to this strategy

- Over-building trust machinery and under-delivering the basic five stages. Completeness is named explicitly in the brief, so the plain pipeline must work by the Day-1 checkpoint.
- Reachability claims that do not survive questions. Keep it narrow and label the method.
- Live demo dependence on network (OSV, registries, LLM). Borrow code-canary's mock/offline mode and cache advisory data.
- The ranking above is judgment, not data: no Bosch scoring sheet or past Bosch winners were found.

---

## Sources

Read in this pass (via a summarising fetch tool):

- Brief: `/home/claude/guardian-kit/docs/HACKATHON_BRIEF.md`
- https://raw.githubusercontent.com/Hitesh564/agentic-vulnerability-remediator/main/README.md
- https://raw.githubusercontent.com/tonywangs/code-canary/main/README.md
- https://raw.githubusercontent.com/ericrihm/depfence/main/README.md
- https://raw.githubusercontent.com/msaad00/agent-bom/main/README.md
- https://raw.githubusercontent.com/aenealabs/aura/main/README.md
- https://raw.githubusercontent.com/farhadabbasiamiri/python-sbom-agent/main/README.md
- https://raw.githubusercontent.com/kamali1-ux/Autonomous-Software-Supply-Chain-Security/main/README.md
- https://www.trailofbits.com/buttercup/
- https://deepmind.google/blog/introducing-codemender-an-ai-agent-for-code-security/
- https://github.blog/changelog/2026-04-07-dependabot-alerts-are-now-assignable-to-ai-agents-for-remediation
- https://about.gitlab.com/blog/dependency-scanning-auto-remediation/
- https://fossa.com/blog/fossabot-dependency-upgrade-ai-agent/
- https://appsecsanta.com/endor-labs (third-party review of Endor Labs, not vendor documentation)
- https://docs.socket.dev/docs/issues-list
- https://about.gitlab.com/blog/gitlab-ai-hackathon-2026-meet-the-winners/
- https://www.crowdstrike.com/en-us/blog/five-lessons-from-agentworks-hackathon/
- https://tensorhack.com/guides/ai-agent-hackathons (third-party guide; its claims about Microsoft and other hackathon rubrics were not checked against the organisers' pages)

Seen in search results but not read (leads, unverified):

- https://www.darpa.mil/news/2025/aixcc-results
- https://blog.trailofbits.com/2025/08/07/aixcc-finals-tale-of-the-tape/
- https://microsoft.github.io/AI_Agents_Hackathon/winners/
- https://devblogs.microsoft.com/devops/introducing-agentic-autofix-for-code-and-dependencies/
- https://snyk.io/jp/blog/remediation-agents-demystified/
- https://www.aikido.dev/code/aikido-libraries
- https://docs.github.com/en/code-security/concepts/code-scanning/autofix-for-code-scanning
- https://socket.dev/glossary/vex
- https://findevil.devpost.com/

Not covered, or covered only from background knowledge: Renovate merge confidence, Snyk agent fix, Seal Security, Chainguard, Aikido, other AIxCC finalists, OpenVEX/scanner VEX flags, details of historical attacks for the replay scenario, Devpost entries specifically on supply-chain guardians, and Bosch's actual judging sheet.
