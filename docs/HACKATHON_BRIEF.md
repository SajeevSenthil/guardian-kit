# Hackathon brief (transcribed from the organiser's slides)

Organiser: Bosch. Two days. Roughly 100 teams get the same problem statement.
AI coding agents (Claude Code etc.) are allowed.

## Problem statement — "Software Supply Chain Guardian: Know what you build. Trust what you ship."

Build an **Agentic AI Solution** that continuously analyzes the software supply chain to
identify dependency risks, vulnerabilities, and suspicious changes before they impact applications.

Context given: modern apps are assembled from open-source libraries, transitive dependencies,
container images, build tools and third-party components that continuously change. Traditional
tools find known vulnerabilities, but teams still need to understand which risks actually matter,
whether they are reachable or exploitable, what changed in the supply chain, and how to remediate
safely. Build an AI-powered guardian that connects evidence from the software supply chain with
application context, prioritizes meaningful risks, and recommends safe actions.

### What a team's solution should do (Discover → Detect → Analyze → Remediate → Validate)

1. **Discover the software supply chain** — identify direct and transitive dependencies, container
   components, package versions and their relationships. Generate or consume an SBOM and build a
   dependency view.
2. **Detect risks & suspicious changes** — known vulnerabilities as well as suspicious changes such
   as typosquatted packages, unexpected dependencies, unsafe install scripts, untrusted images, or
   integrity changes.
3. **Analyze & prioritize with AI** — correlate severity with exploitability, reachability,
   exposure, provenance, and application context to determine which findings actually require attention.
4. **Recommend safe remediation** — the most appropriate action (upgrade, replace, pin, remove,
   mitigate, block, or request further review) with supporting evidence.
5. **Validate & report** — build and test proposed changes, rescan the resulting application,
   verify that the risk has been reduced, detect newly introduced problems, and provide a clear
   evidence-based report.

## Day 1: "Build the Guardian's Eyes"

Discover the software supply chain, detect risks, and explain what it found with evidence.

1. **Discover components** — analyze package manifests and lockfiles; identify direct and
   transitive dependencies; capture component names and versions.
2. **Build the supply chain view** — generate or consume an SBOM (CycloneDX or SPDX); build the
   dependency graph; identify where each component originates; inspect at least one container image
   or CI/CD workflow.
3. **Detect vulnerabilities** — correlate components with known vulnerabilities; capture CVE,
   severity and available fixes; trace vulnerable transitive dependencies back to their source.
4. **Detect suspicious changes** — identify at least one supply-chain anomaly, for example:
   unexpected dependency, typosquatted package, suspicious package update, unsafe install script,
   untrusted image, modified lockfile.
5. **Present evidence** — show what was detected, which component is affected, dependency path,
   supporting evidence, initial risk level.

**Day 1 checkpoint:** "Show us what is in the application, what changed, and what appears risky."
**Expected outcome:** Repository → SBOM → Dependency Graph → Risk Detection → Evidence.
**Key takeaway:** Day 1 is about visibility and detection. Remediation comes on Day 2.

## Day 2: "Build the Guardian's Brain & Shield"

Prioritize the most relevant risks, recommend safe remediation, and verify that the proposed change
protects the application without introducing new problems.

1. **Prioritize risks** (focus on what truly matters) — combine severity with exploitability,
   reachability and exposure; consider whether the dependency is used in production; distinguish
   urgent risks from lower-priority findings; provide an explainable risk score and confidence level.
2. **Investigate suspicious changes** (look beyond known CVEs) — analyze at least one non-CVE
   supply-chain risk; compare package versions, manifests or lockfiles; identify suspicious scripts,
   provenance gaps or integrity changes; clearly separate verified evidence from AI-generated inference.
3. **Recommend safe remediation** — upgrade to a safe version; replace or remove the dependency;
   pin a trusted version; update the container base image; block the unsafe component; escalate for
   security review; include expected risk reduction, compatibility impact and rollback option.
4. **Validate the proposed fix** (test before you trust) — apply the remediation in a controlled
   branch or sandbox; build the application; run unit and integration tests; rescan the resulting
   artifact; compare before-and-after SBOM; detect newly introduced vulnerabilities or dependencies.
5. **Verify & report** (show the complete story) — original finding and supporting evidence;
   recommended and approved action; build and test results; before-and-after risk status; remaining
   or accepted risk; final confidence and audit trail.

**Day 2 final demonstration:** "Show us how the Guardian takes a finding from detection to verified remediation."
**Expected outcome:** Prioritized Risk → Recommended Fix → Human Approval → Build & Test → Rescan → Verified Remediation.
**Key takeaway:** Day 2 is about contextual reasoning, safe action and verified protection.

## Important guidelines — "Build responsibly. Experiment safely. Create impact."

**Examples of supply-chain risks teams may analyze:** vulnerable direct dependency; vulnerable
transitive dependency; typosquatted or malicious package; suspicious package update or install
script; untrusted container image or artifact; unexpected lockfile or dependency change; unpinned
or unsafe CI/CD component.

**Sample application guidelines:**
- Use a free, open-source application from a public repository.
- The application should contain a realistic dependency tree with direct and transitive dependencies.
- The application should be containerized and runnable within the team's own local or sandbox environment.
- Teams should be able to build, test and scan the application locally.
- Teams should document the repository, setup steps, dependencies and tools used in their submission.

**Out of scope (hard rules):**
- Scanning or attacking real production systems.
- Accessing repositories, registries or infrastructure outside the team's authorized sandbox.
- Publishing malicious or modified packages to public package registries.
- Exposing or using real credentials, secrets or access tokens.
- Automatically merging, deploying or releasing remediation changes without human approval.
- Any activity that impacts other teams, participants or shared infrastructure.

## Stretch goals — "Core capabilities demonstrate completeness. Stretch goals demonstrate innovation."

1. **Reachability analysis** — determine whether vulnerable code is actually used by the
   application and adjust the risk priority accordingly.
2. **Automated remediation** — generate a dependency update or pull request with the proposed fix,
   rationale, validation results and rollback guidance.
3. **Provenance verification** — validate artifact signatures, attestations and build provenance
   using Cosign, Sigstore, in-toto or SLSA.
4. **Advanced package risk detection** — detect dependency confusion, maintainer changes, unusual
   release activity and suspicious package behavior.
5. **Policy-as-code** — use Open Policy Agent, Conftest or equivalent controls to block unsafe
   components or builds.
6. **Continuous monitoring** — monitor the software inventory for newly disclosed vulnerabilities
   and automatically reassess application risk.

## Expected deliverables — "Show. Explain. Enable. Inspire."

- **Working prototype** — a functional solution demonstrating the complete Guardian workflow.
- **Architecture overview** — a diagram showing agents, tools, data sources, AI interactions,
  approval points and evidence storage.
- **Source code & setup** — source code, configuration, setup instructions, sample policies,
  prompts and known limitations.
- **Live demonstration** — an end-to-end scenario covering discovery, detection, prioritization,
  remediation, approval and validation.
- **Guardian report** — a human-readable and machine-readable report containing: component
  inventory and dependency paths; findings and supporting evidence; risk ranking and recommended
  actions; validation results; remaining or accepted risks.
- **Responsible AI & security note** — explain where AI is used, how hallucinations are
  controlled, which actions require human approval and how source code, credentials and secrets
  are protected.
