# 06 — UX, demo, pitch and judging

Research date: 2026-11-23. Markers used throughout:

- **[V]** verified in a source read this session (see Sources).
- **[S]** seen only in a search-result title/snippet, page not read.
- **[U]** unverified: from the author's background knowledge, not checked this session. Check before putting it on a slide.

---

## 1. Company perspective: why Bosch cares

Bosch ships products with digital elements in every regulated category at once: vehicle ECUs and software (Mobility), PLCs/drives/IoT gateways (Rexroth, Building Technologies), power tools and home appliances (consumer). Each one is built on open-source dependencies, so "what is in it, what changed, what is risky, can we prove we fixed it" is a legal obligation, not a nice-to-have.

### 1.1 Regulation table (dates checked)

| Regime | What it demands that our prototype touches | Timeline as of Nov 2026 | Status |
|---|---|---|---|
| **EU Cyber Resilience Act**, Reg. (EU) 2024/2847 | Reporting of actively exploited vulnerabilities and severe incidents: early warning 24 h, notification 72 h, final report 14 days after a fix is available (vulnerabilities) / 1 month (incidents), via ENISA's Single Reporting Platform to the CSIRT of main establishment and ENISA. Applies to products already on the market. | **Reporting obligations applied from 11 Sep 2026 (already live).** Conformity-assessment-body provisions from 11 Jun 2026. **Full application 11 Dec 2027** (essential requirements, vulnerability-handling during the support period, supplier notification duty). | [V] EC implementation page, Skadden, cyberresilienceact.eu |
| CRA SBOM duty (Annex I, Part II (1)) | Manufacturer must identify and document components and vulnerabilities, including an SBOM in a commonly used, machine-readable format covering at least top-level dependencies; SBOM goes into technical documentation and is given to market-surveillance authorities on request; no duty to publish it. | Applies with the main body on 11 Dec 2027. | [U] wording from memory; the article fetched for it failed. Read the regulation text before quoting. |
| CRA standards | Harmonised standards are late: drafting deadlines for vulnerability-handling standards moved from 30 Aug to 31 Oct 2026 and product standards from 30 Oct to 31 Dec 2026 (draft amendment); a further one-month extension is reported for 10 Nov 2026. **Legal application dates did not move.** | No CRA harmonised standard cited in the Official Journal as of the source's date (Jul-Sep 2026). | [V] for the two-month shift; the 10 Nov extension is [S] |
| CRA delay / "Digital Omnibus" | None of the sources read mention any proposal that delays the CRA application dates. | Treat 11 Dec 2027 as firm. | [V] by absence in three sources; not an exhaustive check |
| **UNECE R155** (CSMS) / **R156** (SUMS) | OEM needs a certified cybersecurity management system covering development, production and post-production, including managing supplier-related risk; R156 requires controlled, traceable software updates. Tier-1 suppliers such as Bosch must supply the evidence. | In the EU: new vehicle types from July 2022; **all newly produced vehicles from July 2024**. Extension to all category-L vehicles (motorcycles) proposed, with July 2029 mentioned. | July 2024 [V] (Upstream); July 2022 [S] (NXP snippet: "July 6, 2022"); supplier-risk wording [U] |
| **ISO/SAE 21434** | The engineering standard used to demonstrate R155: TARA, vulnerability management and continuous monitoring across the lifecycle, cybersecurity interface agreements with suppliers. | Published 2021 [U]. | Lifecycle vulnerability-management point [V]; clause detail [U] |
| **IEC 62443** (industrial) | 62443-4-1 secure development lifecycle: security management of third-party components, defect/vulnerability handling, security update management. 62443-4-2 component requirements. | In force; commonly used as the basis for CRA industrial product standards. | [U] entirely |
| **NIS2** (Directive (EU) 2022/2555) | Art. 21 risk-management measures include supply-chain security and vulnerability handling for essential/important entities, which covers many Bosch customers and Bosch entities. | EU transposition deadline 17 Oct 2024 [U]. **German implementation act in force 6 Dec 2025, no transition period; >29,500 companies in scope per BSI; registration within 3 months.** | Germany facts [V] (DLA Piper); Art. 21 detail [U] |

### 1.2 Bosch's own open-source and security engineering

- Bosch runs an internal **Open Source Compliance as a Service (OCaaS)** platform with an Analyzer → Scanner → Advisor → Evaluator → Reporter pipeline; the Advisor step looks up known CVEs for discovered components (e.g. via VulnerableCode); over 20 plugins. [V] (OpenChain post, whose title is "ORT Server at Bosch")
- That pipeline is the **OSS Review Toolkit (ORT)** stage model; ORT Server lives at Eclipse as **Eclipse Apoapsis**. Bosch engineers are long-standing ORT contributors. [S]/[U]
- Bosch people present on SBOM exchange in the automotive supply chain (OpenChain Automotive WG, Bitkom "SEPIA: SBOM Exchange Procedures, Interfaces and Architecture"). [S]
- **Bosch PSIRT** publishes advisories (listed on CERT@VDE). [S] Bosch being a CVE Numbering Authority: [U].
- Eclipse SW360 (component catalogue) is used at Bosch. [U]

**Implication for positioning:** Bosch judges already own an ORT-style "analyze, scan, advise, evaluate, report" pipeline. Do not pitch "we generate an SBOM and list CVEs" as the novelty. Pitch the parts their pipeline does not do: the *change* view, non-CVE anomaly investigation, evidence-vs-inference separation, and the approve → build → test → rescan loop. Using their vocabulary (Analyzer/Advisor/Evaluator/Reporter, "evidence", "curation") will land well.

### 1.3 Pitch sentences (say these, no more)

> "Since 11 September this year, the Cyber Resilience Act obliges manufacturers to report an actively exploited vulnerability in their products within 24 hours, and from December 2027 they must keep a machine-readable SBOM and handle vulnerabilities for the whole support period. Automotive type approval under UNECE R155 and industrial IEC 62443 ask the same question from a different angle: do you know what is in your product and can you show how you dealt with it? Our Guardian is a prototype of the engineering workflow behind those obligations: it produces a CycloneDX inventory, decides with evidence which findings matter, and leaves an audit trail from finding to human-approved, re-scanned fix. It is not a compliance tool and does not make a product compliant; it shortens the path from 'a CVE was published' to 'we know whether we are affected and have a verified fix'."

Overclaiming traps to avoid: "CRA-compliant", "meets ISO 21434", "the CRA requires a full transitive SBOM" (it requires at least top-level [U]), "the CRA is in force in 2027" (it has been in force since Dec 2024 [U]; obligations phase in), and any claim that reporting is automated.

---

## 2. Dashboard UX for security triage

### 2.1 What the best products do

| Pattern | Who does it | What to copy |
|---|---|---|
| **Noise funnel** "N findings → M that matter" | Endor Labs: worked example 1,000 raw → ~100 after reachability → ~20 after EPSS ranking; claims ~92% average noise reduction, ~98% with reachability + EPSS [V, vendor claims]. Snyk, Wiz and GitHub (Dependabot auto-triage) use the same idea [U]. | One horizontal funnel on Overview. Each stage is a named, deterministic filter with a count, and each stage is clickable to show what was dropped and why. Never hide the dropped items. |
| **Honest reachability labels** | Endor: evidence points to the vulnerable function, not just the package; "unreachable" is labelled separately from "undetermined"; coverage gaps are shown [V]. | Three states: Reachable (call path shown) / Not reachable / Unknown. Unknown must never be scored as safe. |
| **Dependency path** "introduced through" | Snyk issue cards, GitHub Dependabot alerts, Dependency-Track component view [U]. | A breadcrumb on every finding: `app → flask 2.0 → werkzeug 2.0.1 (vulnerable)`, with direct/transitive and prod/dev badges, plus the manifest file and line that pulls in the root. |
| **Change-centred story** | Socket "Pull Request Stories": each PR gets a generated title describing dependency changes, a table of changed direct dependencies, a table of alerts, "peak state vs final state", and a "suppressed" badge when someone bypassed an alert [V]. | Our Changes page: baseline vs current, a generated headline, added/removed/changed tables, alerts per change. Keep the "bypassed/accepted" badge for the audit trail. |
| **Behavioural alerts, not only CVEs** | Socket alert types: install scripts, network/shell/filesystem access, typosquat, new maintainer [S]/[U]. | A separate "Supply-chain anomalies" lane next to "Known vulnerabilities" so the non-CVE finding is visibly a different class. |
| **Audit trail per finding** | Dependency-Track: analysis state (exploitable / in triage / not affected / false positive), justification, comments, suppression, policy violations [U]. Maps to CycloneDX VEX states. | Every finding has a status and an append-only decision log with who/when/why. Export as VEX. |
| **Org-level rollup** | GitHub security overview, Wiz issues queue, Chainguard image comparison (CVE count of base image A vs B) [U]. | A before/after tile for the container base image is cheap and visual. |

### 2.2 Design rules

1. **One number per screen.** Each page has a headline sentence that is true and specific ("412 components, 37 findings, 3 need action today").
2. **Evidence drawer, not navigation.** Clicking any finding opens a right-side drawer; the list stays visible. Drawer sections, in this fixed order: Claim → Verified evidence (tool output, file/line, advisory ID, hash) → AI inference (visibly different background, labelled "Inference", with confidence) → Path → Recommended action.
3. **Verified vs inferred is a visual system**, used identically on every page: solid border + tool icon for verified, dashed border + "AI" tag for inference. The brief demands this separation explicitly.
4. **Explainable score.** Show the score as stacked contributions (severity, EPSS/KEV, reachability, exposure, prod/dev, fix available), not a bare number. Confidence is a separate chip.
5. **Diff is first-class.** Before/after appears three times with the same component: lockfile diff (Changes), package version diff (Investigation), SBOM/risk diff (Validation).
6. **Approval is a gate, not a toast.** A full-width panel stating exactly what will happen, the diff, expected risk reduction, compatibility impact, rollback command; buttons Approve / Reject / Request review; mandatory reason field; approver name and timestamp recorded. Nothing downstream runs until it is pressed.
7. **Agent activity is always visible.** A collapsible right rail showing the live step list (agent, tool call, duration, status) so the audience sees an agent, not a script.
8. **Projector constraints.** Minimum 18 px body text, dark-on-light theme (projectors wash out dark themes), severity encoded by icon and label as well as colour, browser at 125% zoom, no horizontal scroll at 1280x720.

### 2.3 Page-by-page layout

Left nav follows the brief's five verbs so judges can map the UI to their slide: **Discover** (Overview, Inventory, Changes) → **Detect** (Findings) → **Analyze** (Investigation) → **Remediate** (Remediation & Approval) → **Validate** (Validation, Report). Agent trace is a rail on every page plus its own page.

| # | Page | Layout | Projector moment |
|---|---|---|---|
| 1 | **Overview** | Top: headline sentence + target app, commit, scan time. Row of 4 tiles (components, direct/transitive split, findings, anomalies). Centre: the funnel (All findings → has fix → prod dependency → reachable/exposed → **Act now**). Bottom: "Top 3 risks" cards and a pipeline stepper (Discover … Validate) with status. | Day 1 opening ("what is in the application") and Day 2 opening ("37 findings, 3 matter"). Also the closing screen, with funnel and tiles in their after state. |
| 2 | **Inventory / Graph** | Left: searchable component table (name, version, ecosystem, direct/transitive, scope, licence, origin/registry, hash). Right: dependency graph, defaulting to a **collapsed tree filtered to vulnerable paths**, not the full hairball. Toggle: full graph. Tabs for app packages, container image layers/OS packages, CI workflow actions. SBOM download button (CycloneDX JSON). | Day 1: "Repository → SBOM → Dependency graph". Click a transitive node to light up its path to the root. |
| 3 | **Changes** | Baseline selector (previous commit/SBOM). Generated headline ("This change adds 2 packages, bumps 1, and one of the new packages runs an install script"). Three tables: added / removed / version-changed, each row with flags (new install script, new maintainer, name similarity, hash mismatch, unpinned action). Raw lockfile diff below. | Day 1: "what changed". This is the screen that differentiates the team; give it the most time on Day 1. |
| 4 | **Findings** | Two lanes as tabs: Known vulnerabilities / Supply-chain anomalies. Table sorted by Guardian priority, columns: priority, component, ID, severity, EPSS/KEV, reachability, fix version, path depth, status. Row click opens the evidence drawer. Toggle "show deprioritised (34)" with the reason for each. | Day 1: "what appears risky" with one drawer opened. Day 2: 10 seconds only, as the bridge from funnel to one finding. |
| 5 | **Investigation** | One finding, full page. Left column: verified evidence cards (advisory, affected range, call path or "not found", install-script source, registry metadata, package diff between versions). Right column: AI analysis (hypothesis, reasoning steps, confidence, what would change its mind). Bottom: score breakdown bar. | Day 2: the non-CVE anomaly investigation and the verified-vs-inference separation. |
| 6 | **Remediation & Approval** | Options table (upgrade / pin / replace / remove / block / escalate) with expected risk reduction, compatibility impact, effort; recommended option highlighted with rationale. Below: proposed diff (manifest + lockfile + Dockerfile), rollback instructions. Approval gate panel at the bottom. | Day 2 centrepiece. **Pause here.** A human on the team types a reason and presses Approve on stage. |
| 7 | **Validation** | Live stepper: create branch → apply patch → build image → unit tests → integration tests → rescan → SBOM diff, each with duration and expandable log. Then before/after: findings count, risk score, removed vulnerabilities, **newly introduced components or vulnerabilities** (show this section even when empty: "0 new"). | Day 2: watch steps turn green, land on before/after. |
| 8 | **Report** | Rendered Guardian report (inventory + paths, findings + evidence, ranking + actions, validation results, remaining/accepted risk, audit trail). Download buttons: HTML/PDF, JSON, CycloneDX SBOM, VEX. | Day 2: 15 seconds, scroll once, click download. |
| 9 | **Agent trace** | Timeline of every agent step: agent name, tool, inputs (redacted), output summary, duration, token count, model, status. Filter by finding. Marks human-approval events and policy blocks. | Q&A only ("how do you control hallucinations?", "what did the AI actually do?"). The mini-rail version is visible throughout. |

---

## 3. UI technology choice

### 3.1 Comparison

| Criterion | Streamlit | **NiceGUI** | FastAPI + HTMX | FastAPI + React/Vite |
|---|---|---|---|---|
| Execution model | Whole script reruns per interaction; `@st.fragment` limits scope [V] | Event-driven; handlers update only the elements they touch over a persistent websocket [V] | Request/response + SSE partials | SPA + REST/SSE/WS |
| Live agent event stream | Workable (`st.fragment(run_every=…)`, `st.status`, `st.write_stream`) but fights the rerun model; background work + approval gate needs careful `session_state` [U] | Natural: background asyncio task pushes into `ui.log`, `ui.timeline`, `ui.stepper`; `ui.timer` for polling [V for timer/live suitability] | Good (SSE extension) | Best |
| Interactive graph | Third-party components (`streamlit-agraph`, pyvis in an iframe); click-to-select round-trips are clumsy [U] | `ui.echart` (ECharts tree/graph series) built in; raw JS escape hatch for Cytoscape.js [V for raw HTML/JS + Quasar; component list U] | Hand-written JS | Any library |
| Layout for a 9-page app with drawers/dialogs | Fixed chrome, file-based navigation [V] | Explicit rows/columns/tabs/dialogs/drawers, Quasar + Tailwind [V] | Manual | Full control |
| Backend integration | Separate process or in-script | Built on FastAPI; UI and JSON API in one process (`ui.run_with(app)`) [V] | Native | Native, but two builds |
| Automated tests | `streamlit.testing.v1.AppTest` (headless, fast; does not exercise custom components) [S]/[U] | pytest plugin: `user` fixture (no browser, unit-test speed, recommended) and `screen` fixture (Selenium) [V] | Playwright | Playwright + vitest |
| 2-day risk with Claude Code | Low to start, medium once approval + streaming arrive | Low-medium; smaller community, pin the version [V] | Medium (lots of hand-rolled HTML) | High (two toolchains, state sync, build step) |

### 3.2 Recommendation (firm)

**NiceGUI on a single FastAPI process, Python only.** The product is an approval workflow with a live agent stream, which is exactly the shape Streamlit's rerun model handles worst and NiceGUI's event model handles best. One process also means the same FastAPI app serves the machine-readable report and SBOM endpoints.

Exact stack:

- `nicegui` (pin the exact 3.x version on hour one; do not upgrade mid-hackathon), which brings FastAPI, uvicorn, Quasar, Tailwind.
- Graph: `ui.echart` with a **`tree` series** for dependency paths (collapsible, readable on a projector) and a **`graph` series with force layout** for the full view. Stretch only if time allows: Cytoscape.js + `cytoscape-dagre` loaded from a local static file through `ui.add_head_html` and driven with `ui.run_javascript`.
- Tables: `ui.table` (or `ui.aggrid` if grouping is needed). Diffs: `difflib` unified diff rendered in `ui.code`, or `diff2html` as a static asset. Architecture diagram and call paths: `ui.mermaid`. Live trace: `ui.timeline` + `ui.log`. Validation: `ui.stepper`. Evidence drawer: `ui.right_drawer`. Approval: `ui.dialog` or an inline card. (Element names are from background knowledge [U]; confirm against the pinned version's docs.)
- Event bus: every agent/tool step is written as one JSON line to `runs/<run_id>/events.jsonl` and published on an `asyncio.Queue`; the UI subscribes. The same file drives replay mode (section 4) and the audit trail.
- **Vendor all JS/CSS locally.** Assume the venue network fails.

**Fallback: Streamlit**, decided by a hard checkpoint: if by Day 1 midday the NiceGUI app does not show Overview + Findings from real scan data, switch. Fallback libraries: `streamlit` (multipage via `st.navigation`), `streamlit-agraph` or `pyvis` + `st.components.v1.html` for the graph, `st.dataframe` with row selection, `st.status`/`st.fragment(run_every=1)` for progress, `st.dialog` for approval. Keep all logic in a UI-free `guardian/` package so the switch costs hours, not a day.

Not recommended: React/Vite (highest polish ceiling, but a second toolchain and state-sync bugs are the classic Day-2 time sink) and HTMX (no component library, so polish is all hand-made).

### 3.3 Automated UI testing

1. **Logic tests** (most of the value): pytest on the `guardian/` package with recorded scanner outputs as fixtures. No UI.
2. **NiceGUI `user` fixture**: `pytest -p nicegui.testing.plugin`, `asyncio_mode = auto` in `pytest.ini`, one test per page: open, `should_see` the headline, click the primary control, `should_see` the result [V]. Test the approval gate specifically: validation must not start before Approve.
3. **Playwright smoke test** (`pytest-playwright`, Chromium): start the app in replay mode, walk the exact demo click path, assert no console errors, save a screenshot of every page at 1280x720. Run it before every commit to main and once more 30 minutes before the demo. The screenshots double as slide material and as the last-resort fallback.
4. If on the Streamlit fallback: `AppTest.from_file("app.py").run()` then assert on `at.metric`, `at.dataframe`, `at.button[...].click().run()`; Playwright for anything involving custom components.

---

## 4. Performance and latency

| Technique | Detail |
|---|---|
| Parallel scanners | SBOM generation, vulnerability scan, container scan, CI-workflow lint and anomaly heuristics are independent: run with `asyncio.gather` over subprocesses. Generate the SBOM once and feed it to the vulnerability scanner instead of re-walking the filesystem. |
| Cache advisory lookups | Pre-download scanner vulnerability DBs before the demo and disable auto-update during it. Cache OSV/registry/EPSS/KEV responses on disk keyed by `purl@version` (SQLite or `diskcache`). Use OSV's batch query endpoint rather than one call per package [U]. |
| Cache LLM calls | Key on (prompt hash, model, evidence hash). Identical evidence gives an identical verdict, which also makes the demo deterministic and is a legitimate hallucination-control talking point. |
| Bound the LLM | AI only analyses the top-K findings after deterministic filtering; run those in parallel with a concurrency cap; stream tokens into the drawer. |
| Pre-pull and pre-build | Pull every base image and scanner image, warm pip/npm caches, and build the sample app image once so the validation build is a cached-layer rebuild. Pre-pull the *fixed* base image too. |
| Small test target | Pick or trim the sample app's test suite to under 30 s. A tagged `smoke` subset is fine if the full run is shown in the report. |
| Streaming progress | Emit an event at start and end of every step; the stepper shows elapsed time. Nothing on screen should be static for more than about 5 s. |
| **Replay mode** | `GUARDIAN_MODE=replay` plays back a recorded `events.jsonl` + artifacts through the same UI code at a configurable speed, with a visible "REPLAY of run <id>, recorded <time>" badge. Never present a replay as live. Record a fresh good run each evening. |

Target timings for the live demo (warm caches):

| Step | Target | Hard ceiling, then switch to replay |
|---|---|---|
| Discover + SBOM | 10 s | 25 s |
| Detect (all scanners) | 15 s | 30 s |
| AI prioritisation of top findings | 15 s | 30 s |
| Investigation of one anomaly | 10 s | 20 s |
| Approve → patch → build → test | 45 s | 90 s |
| Rescan + SBOM diff | 15 s | 30 s |
| **Total machine time inside a 6-minute demo** | **under 2 min** | |

Practical pattern: run Discover/Detect before walking on stage (results already on Overview), run Remediate/Validate live because that is the part the Day-2 prompt asks to see.

---

## 5. Demo and pitch

### 5.1 Advice from judges and organisers (cited)

- Lead with the problem: "Say what the problem is that you're solving." (Jono Bacon, via JetBrains) [V]
- Something working on screen within about 90 seconds of starting. (Jono Bacon) [V]
- One clear "this is now possible" contrast beats a tour of every feature. (Bonnie Xu, OpenAI) [V]
- Read the judging criteria before coding and talk to judges early. (Jan-Niklas Wortmann, JetBrains) [V]
- Scope creep loses: five half-features means nothing works end to end. A long demo is a scope problem. (Colin Lowenberg) [V]
- Remove stall points: mock slow calls, pre-fill forms. (Colin Lowenberg) [V]
- Be direct about what works and what does not; judges notice evasion and honesty reads as confidence. (Avi Press, Scarf) [V]
- Put the judge in the user's shoes and narrate. (Avi Press) [V]
- Rehearse against a clock; one person drives the laptop while one person speaks; run locally, use wired network, have a screencast ready. (Mark Headd, Hack Upstate) [V]

### 5.2 Story framing with a real incident

Use one incident and one persona. Recommended: **the September 2025 npm compromises** (maintainer account phishing leading to malicious versions of very widely used packages, followed by the self-propagating "Shai-Hulud" worm that used install-time scripts to steal credentials) [U: confirm details and dates before the pitch]. It fits because no CVE existed when it mattered, so a CVE scanner said "all clear", and the signals were exactly the ones in the brief: unexpected version bump, new install script, lockfile change.

Alternatives, pick whichever matches the sample app's ecosystem: xz-utils backdoor CVE-2024-3094 (maintainer trust), tj-actions/changed-files CVE-2025-30066 (unpinned CI action), Log4Shell (transitive "are we affected?" taking weeks) [all U].

Persona line: "Priya is the security engineer for a Bosch product team. On Monday morning her scanner shows 37 findings and a pull request that changes the lockfile. She has one hour."

### 5.3 Day-1 checkpoint, 3 minutes

Prompt: "Show us what is in the application, what changed, and what appears risky." Answer in those three beats, using those words as spoken signposts.

| Time | Screen | Say |
|---|---|---|
| 0:00-0:20 | Overview | One-sentence problem + target app. "First: what is in the application." |
| 0:20-1:00 | Inventory / Graph | N components, direct vs transitive, container and CI tabs, CycloneDX download. Click one transitive node, path lights up. |
| 1:00-1:50 | Changes | "Second: what changed." Baseline vs current, generated headline, the new package with the install script. |
| 1:50-2:40 | Findings + evidence drawer | "Third: what appears risky." One CVE with its path, one anomaly with its evidence, initial risk level, verified vs inference styling. |
| 2:40-3:00 | Overview funnel | "Tomorrow: which of these matter, a safe fix, and proof." |

### 5.4 Day-2 final demo, 5-7 minutes

Prompt: "Show us how the Guardian takes a finding from detection to verified remediation." Follow one finding end to end; mention the second (anomaly) finding as a 40-second side branch.

| Time | Screen | Beat |
|---|---|---|
| 0:00-0:40 | Slide 1-2 | Incident hook, persona, one-line product statement. |
| 0:40-1:20 | Overview | Funnel: 37 findings → 3 need action. Say why 34 were deprioritised and that they are still listed. **Working software is on screen before 0:45.** |
| 1:20-2:10 | Findings → Investigation | The chosen finding: path, reachability evidence, score breakdown, confidence. Point at the verified/inference split. |
| 2:10-2:50 | Investigation (anomaly) | Non-CVE branch: version diff, install script, Guardian recommends *block and escalate*, not auto-fix. |
| 2:50-3:40 | Remediation & Approval | Options, recommended upgrade, diff, risk reduction, compatibility, rollback. **Human types a reason and approves.** |
| 3:40-4:40 | Validation | Stepper runs live: build, tests, rescan. Talk through the architecture slide content verbally while it runs. |
| 4:40-5:20 | Validation before/after | Finding gone, 0 new vulnerabilities, 1 remaining accepted risk shown honestly. |
| 5:20-5:45 | Report | Scroll once, download JSON + SBOM, mention audit trail. |
| 5:45-6:30 | Slide 4-6 | Responsible AI in three sentences, limitations, what is next. Close on Overview after-state. |

### 5.5 Slides (max 6)

1. **Title + hook**: incident in one line, "Know what you build. Trust what you ship."
2. **Problem**: scanners give lists; teams need to know what changed, what matters, and whether the fix is safe. One sentence on CRA 24 h reporting.
3. **Live demo** (placeholder slide with the five verbs; switch to the app).
4. **Architecture**: agents, tools, data sources, AI interactions, approval point, evidence store. This is a required deliverable, so make it match the brief's wording exactly.
5. **Responsible AI & security**: where AI is used / where it is not, hallucination controls, approval gates, secret handling.
6. **Results, limits, next**: funnel numbers, timings, known limitations, stretch goals done, roadmap.

### 5.6 What to say about responsible AI

- "Tools produce facts; the model produces judgement." Every finding originates from a deterministic tool. The model cannot create a finding, a CVE ID or a version; IDs it mentions are checked against tool output and rejected otherwise.
- Verified evidence and AI inference are stored in separate fields and drawn differently on every screen and in the report.
- The model returns structured output with citations to evidence IDs; uncited claims are dropped. Low confidence routes to "request further review", which is a valid outcome in the brief.
- No change is merged, deployed or released by the agent. It writes to a sandbox branch after an explicit, logged human approval. Policy-as-code can block; only a human can allow.
- Only package metadata and minimal code snippets go to the model; secrets are redacted before any prompt; no real credentials exist in the sandbox; package contents are treated as untrusted data (prompt-injection in a README or install script is a finding, not an instruction).
- Full audit trail: prompts, model, tool calls, approvals.

### 5.7 Likely judge questions

| Question | Strong answer |
|---|---|
| How is this different from Trivy / Dependabot / our ORT pipeline? | Those produce the evidence and we use them. The Guardian adds the change view, non-CVE investigation, context-based ranking with an explanation, and a closed loop to a tested, rescanned fix with an audit trail. |
| How do you know the AI is not hallucinating? | It cannot introduce facts: IDs and versions are validated against tool output, claims need evidence citations, inference is labelled, and the fix is verified by build, tests and rescan, not by the model's opinion. |
| How do you determine reachability? | State the real method (e.g. import/call-graph search for the vulnerable symbol) and its limits; three states including Unknown; Unknown never lowers priority. |
| What if the upgrade breaks the app? | It runs in a sandbox branch; build and tests gate it; rollback is the stored diff; failed validation is reported as failed and the Guardian proposes the next option. Showing a prepared failing case is very persuasive. |
| What about false negatives / zero-days? | Not claimed. Anomaly heuristics cover some non-CVE cases; list which ones. Continuous monitoring re-evaluates the stored SBOM when new advisories appear. |
| Does it scale to a monorepo with 5,000 dependencies? | Deterministic stages scale like the underlying scanners; AI runs only on the post-filter top-K; results are cached by evidence hash. Give measured timings. |
| What leaves our network? | Exactly which fields go to the model; the model endpoint is swappable for an internal one; scanners run locally with offline DBs. |
| Was any of that pre-recorded? | Say precisely which parts ran live. If replay was used, it was badged on screen. |
| How does this relate to the CRA? | Use section 1.3; add "supporting workflow, not compliance". |
| What would you do with two more weeks? | Two concrete items tied to stretch goals (provenance verification, PR generation). |

### 5.8 Demo failure modes and mitigations

| Failure | Mitigation |
|---|---|
| Venue Wi-Fi down or slow | Everything local; offline scanner DBs; vendored JS; phone hotspot for the LLM call; LLM cache; replay mode. |
| LLM rate limit, timeout or different answer than rehearsed | Cache by evidence hash; temperature 0; second API key/provider configured; replay. |
| Docker build pulls from the network or is cold | Pre-pulled images, warmed layer cache, test with network disabled the night before. |
| Demo runs long | Rehearse with a timer three times; a cut list decided in advance (anomaly branch first, then report scroll). |
| Projector resolution or contrast | Test at 1280x720; light theme; 125% zoom; no red/green-only encoding. |
| Leftover state from the last run | `make demo-reset` restores the repo, branch and DB to a known state; run it before every rehearsal. |
| A click path nobody tested | Playwright script of the exact demo path; presenter does not improvise. |
| Laptop sleeps, notifications, updates | Do-not-disturb, power plugged, sleep off, close everything else, second laptop with the same build ready. |
| Total failure | 90-second screen recording of a good run plus the per-page screenshots from the Playwright run, already in the slide deck. |
| Overclaiming caught in Q&A | "Known limitations" on the last slide and in the README; answer limits directly. |

---

## 6. Inferred judging rubric and self-scoring

No official rubric was provided. This one is inferred from the deliverables slide and the line "Core capabilities demonstrate completeness. Stretch goals demonstrate innovation." Weights are a guess; ask the organisers on Day 1 whether a rubric exists.

| Criterion (inferred weight) | What a top score looks like |
|---|---|
| **Completeness of the core workflow (30%)** | All five stages work on a real open-source, containerised app; every Day-1 and Day-2 numbered item is demonstrably covered. |
| **Live demo (20%)** | One finding from detection to verified remediation, with approval, in the time limit, answering the organiser's prompt in its own words. |
| **Quality of reasoning and evidence (15%)** | Explainable score + confidence; verified vs inference separated; at least one non-CVE risk investigated; before/after proof. |
| **Responsible AI & security (10%)** | Written note covering the four required topics; approval gate visible in the product; none of the six out-of-scope rules touched. |
| **Architecture & engineering (10%)** | Diagram with agents, tools, data sources, AI interactions, approval points, evidence storage; clean setup; reproducible. |
| **Guardian report (5%)** | Human-readable and machine-readable, containing all five listed content items. |
| **Innovation / stretch (10%)** | One or two stretch goals done properly rather than six stubs. |

With about 100 teams there is probably a screening round based on the submission or a very short demo before any final. The README, the report and the first 60 seconds of the demo have to stand alone.

### Self-scoring checklist (score 0 = missing, 1 = partial, 2 = demonstrable live)

Day 1 core
- [ ] Manifests and lockfiles parsed; direct and transitive dependencies with versions
- [ ] CycloneDX or SPDX SBOM generated or consumed, downloadable
- [ ] Dependency graph shown; origin of each component identified
- [ ] At least one container image or CI/CD workflow inspected
- [ ] CVE, severity and fix version captured; transitive vulnerabilities traced to their source
- [ ] At least one supply-chain anomaly detected
- [ ] Evidence view: what, which component, dependency path, evidence, initial risk level

Day 2 core
- [ ] Priority combines severity, exploitability, reachability, exposure, prod/dev usage
- [ ] Explainable risk score and confidence level
- [ ] One non-CVE risk investigated with a version/manifest/lockfile comparison
- [ ] Verified evidence vs AI inference clearly separated
- [ ] Remediation options include risk reduction, compatibility impact, rollback
- [ ] Human approval gate, logged
- [ ] Fix applied in a branch or sandbox; build; unit and integration tests
- [ ] Rescan; before/after SBOM comparison; newly introduced issues detected
- [ ] Final report: finding, action, build/test results, before/after, remaining/accepted risk, confidence, audit trail

Deliverables
- [ ] Working prototype runs from a clean clone with documented steps
- [ ] Architecture diagram contains all six named elements
- [ ] Source, configuration, setup, sample policies, prompts, known limitations in the repo
- [ ] Report in human-readable and machine-readable form with all five content items
- [ ] Responsible AI & security note answers all four questions
- [ ] Sample app is public, open source, containerised, documented

Guardrails (any failure is disqualifying, score pass/fail)
- [ ] No production systems scanned; nothing outside the sandbox accessed
- [ ] Nothing published to public registries
- [ ] No real credentials or tokens anywhere, including git history and logs
- [ ] No automatic merge, deploy or release
- [ ] No impact on other teams or shared infrastructure

Stretch (count only if demonstrable)
- [ ] Reachability analysis  - [ ] PR generation  - [ ] Provenance verification (Cosign/SLSA)
- [ ] Advanced package risk detection  - [ ] Policy-as-code (OPA/Conftest)  - [ ] Continuous monitoring

Demo readiness
- [ ] Timed rehearsal done three times; cut list agreed
- [ ] Replay mode recorded today and badged
- [ ] Playwright path test green; screenshots and screencast in the deck
- [ ] `make demo-reset` works; second laptop ready

Target: every core and deliverable line at 2 before spending any time on a second stretch goal.

---

## Sources

Pages actually read this session:

- European Commission, CRA implementation factpage (milestone dates): https://digital-strategy.ec.europa.eu/en/factpages/cyber-resilience-act-implementation
- Skadden, "Get Ready: Reporting FAQs and Checklist as the EU's Cyber Resilience Act Comes Into Force" (Sep 2026): https://www.skadden.com/insights/publications/2026/09/get-ready-reporting-faqs-and-checklist
- cyberresilienceact.eu (independent guide), "CRA standardisation deadlines pushed back two months": https://www.cyberresilienceact.eu/news/cra-standardisation-deadlines-pushed-back-two-months.html
- Upstream, UNECE R155 milestones: https://upstream.io/blog/automotive-cybersecurity-regulation-unece-wp29-r155/
- DLA Piper, "NIS 2 Directive transposed in Germany" (Feb 2026): https://www.dlapiper.com/en/insights/publications/2026/02/nis-2-directive-transposed-in-germany
- OpenChain Project, "ORT Server at Bosch" / OCaaS (2026): https://openchainproject.org/news/2026/03/26/ort-server-at-bosch-used-in-one-pipeline-service-for-your-compliance-ocaas
- Endor Labs, "How to use reachability to reduce vulnerability alerts" (vendor claims): https://www.endorlabs.com/learn/how-to-use-reachability-to-reduce-vulnerability-alerts
- Socket, "Introducing Pull Request Stories": https://www.socket.dev/blog/introducing-pull-request-stories
- Bitdoze, "Streamlit vs NiceGUI": https://www.bitdoze.com/md/streamlit-vs-nicegui.md
- NiceGUI documentation, Testing: https://nicegui.io/documentation/section_testing
- JetBrains AI blog, "How to win a hackathon: notes from the judging table" (Jun 2026): https://blog.jetbrains.com/ai/2026/06/how-to-win-a-hackathon-notes-from-the-judging-table/
- Hack Upstate / Mark Headd, "8 Tips to a Successful Hackathon Demo and Presentation": https://medium.com/@hackupstate/8-tips-to-a-successful-hackathon-demo-and-presentation-4d1ae83415ad

Seen in search results only, not read ([S]):

- NXP blog snippet on R155 entering into force in Europe on 6 July 2022: https://nxp.com/company/about-nxp/smarter-world-blog/BL-THE-AUTO-INDUSTRY-IS-TAKING-CYBERSECURITY
- Eclipse Apoapsis project page: https://projects.eclipse.org/projects/technology.apoapsis/governance
- Bitkom SEPIA slides (SBOM exchange): https://bitkom.org/sites/main/files/2024-09/bfoss24-Praes-Kern-SEPIA-SBOM-Exchange-Procedures-Interfaces-and-Architecture.pdf
- CERT@VDE Bosch PSIRT bulletins: https://certvde.com/en/bulletins/source/BOSCH%20PSIRT?page=2
- Socket alert types: https://docs.socket.dev/docs/issues-list
- Streamlit app testing docs: https://docs.streamlit.io/develop/concepts/app-testing

Attempted and failed: a Medium article on CRA SBOM requirements (fetch error), so the Annex I SBOM wording remains unverified.

Not researched this session (all [U]): Snyk, Dependency-Track, GitHub security overview, Chainguard and Wiz UI specifics; IEC 62443 clause content; ISO/SAE 21434 clause content; NIS2 Article 21 text; incident details in 5.2; NiceGUI element names; OSV batch API.
