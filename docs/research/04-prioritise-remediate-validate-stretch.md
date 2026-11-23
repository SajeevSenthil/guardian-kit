# 04 — Prioritise, remediate, validate, and the stretch goals (Day 2)

Scope: Day 2 of the brief ("Brain & Shield") plus all six stretch goals. Target app: `snyk-labs/nodejs-goof` (npm). Orchestrator: Python.

Verification legend, used throughout:

- **[V]** checked during this research session (2026-11-23) against the cited official page or live API response.
- **[U]** written from prior knowledge, not re-checked. Run `--help` or read the doc before relying on it in the demo.

Environment caveat found while researching: the research sandbox's egress proxy refused `api.first.org`, `www.cisa.gov` and `api.osv.dev` for `curl` (HTTP 403 on CONNECT). The responses quoted below were obtained through a web fetcher instead. If the hackathon network is similarly restricted, **cache EPSS/KEV/OSV responses to disk on first success** and make every enrichment step degrade to "unknown" rather than fail.

Two facts about the target that change the Day 2 plan:

- `nodejs-goof`'s `npm test` script is literally `snyk test` [V, package.json on `main`]. There are **no unit tests**. "Build and run tests" needs a smoke-test script the team writes (section 4.2).
- Direct deps include `lodash@4.17.4`, `express@4.12.4`, `marked@0.3.5`, `moment@2.15.1`, `mongoose@4.2.4`, `ejs@1.0.0`, `adm-zip@0.4.7`, `st@0.2.4`, and `method-override@latest` / `morgan@latest` (unpinned ranges — a free non-CVE finding) [V].

---

## 1. Risk prioritisation

### 1.1 The input signals

| Signal | What it measures | Where to get it | Trap |
|---|---|---|---|
| CVSS v3.1 base | Intrinsic technical severity, 0-10. Not likelihood, not your context. | OSV `severity[] {type:"CVSS_V3", score:"<vector>"}`; GHSA; NVD | OSV gives the **vector string**, not the number. Compute it (`pip install cvss` [U]) or use GHSA's `database_specific.severity` bucket (`CRITICAL`…) [V] |
| CVSS v4.0 | Same idea, new metric set: adds Attack Requirements (AT), drops Scope in favour of separate Vulnerable/Subsequent system impact (VC/VI/VA, SC/SI/SA). Names the score by what is included: CVSS-B, -BT (+Threat), -BE (+Environmental), -BTE. Exploit Maturity (E: A/P/U) is the only Threat metric. [U] | OSV `severity[] {type:"CVSS_V4"}` | Most published v4 scores are CVSS-B only, so they read higher than a v3 temporal-adjusted score. Don't mix v3 and v4 numbers silently; record which one you used. |
| EPSS | Probability (0-1) that the CVE sees exploitation activity in the wild in the next 30 days. | `GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B` [V] | See 1.2. CVE-only: GHSA-only and `MAL-` advisories have no EPSS. |
| CISA KEV | Binary: confirmed exploited in the wild. | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` [U — host was blocked from the sandbox]. Fields: `cveID, vendorProject, product, dateAdded, dueDate, requiredAction, knownRansomwareCampaignUse` [U] | Absence is not safety. KEV is skewed to enterprise/network products; few npm libraries are listed. |
| SSVC | A decision tree, not a score. Output is an action. | CISA / CERT-CC guides | See 1.3 |

### 1.2 EPSS: probability vs percentile

Live response shape (values dated 2026-11-22) [V]:

```json
{"status":"OK","total":2,"data":[
  {"cve":"CVE-2021-44228","epss":"0.99999","percentile":"1.0","date":"2026-11-22"},
  {"cve":"CVE-2019-10744","epss":"0.05006","percentile":"0.92445","date":"2026-11-22"}]}
```

(Field names and the two rows' values are verified; the envelope is abbreviated. Numbers arrive as **strings**.)

- `epss` is the **absolute probability**. Use this in arithmetic. 0.05 means "about a 5% chance of observed exploitation activity in 30 days".
- `percentile` is the **rank among all scored CVEs**. 0.924 means "higher than 92% of CVEs". Use it for communication and for thresholds that should stay stable when the model is recalibrated.
- The lodash row is the teaching example: **5% probability but 92nd percentile**, because the vast majority of CVEs sit below 1%. A UI that prints "EPSS 92%" for that row is wrong.
- EPSS is about the CVE globally, not your deployment. It says nothing about reachability.
- Batch by comma-separating CVEs in one request. Other query params such as `date=`, `scope=time-series`, `epss-gt=` exist [U]. A daily bulk CSV is also published [U — URL not checked].

### 1.3 SSVC in one paragraph

SSVC (Stakeholder-Specific Vulnerability Categorization) replaces a number with decision points and a looked-up outcome. CISA's tree uses **Exploitation** (none / PoC / active), **Automatable** (yes / no), **Technical impact** (partial / total) and **Mission & well-being** (low / medium / high), yielding **Track, Track\*, Attend, Act**. The CERT/CC "deployer" tree uses Exploitation, **Exposure** (small / controlled / open), Automatable and Human impact, yielding **Defer, Scheduled, Out-of-cycle, Immediate** [U]. Cheap mapping for the Guardian: KEV listed → `active`; EPSS ≥ 0.1 or an exploit reference in the advisory → `poc`; else `none`. Exposure from the app context (section 1.5). Showing an SSVC outcome next to the 0-100 score is a strong "explainable" signal for judges and costs about 30 lines.

### 1.4 How vendors combine them (for positioning, not copying)

All [U]:

- **Snyk Risk Score** (0-1000): impact × likelihood, with EPSS, exploit maturity, reachability, fix availability, social trends, package popularity as named contributing factors shown in the UI.
- **GitHub Dependabot**: severity + EPSS shown per alert; auto-triage rules can dismiss dev-scope alerts; "vulnerable function calls" existed only for a few ecosystems.
- **Grype**: recent versions print EPSS and KEV columns and a composite "risk" value.
- **Dependency-Track**: stores CVSS, EPSS, policy violations; "inherited risk score" is a weighted count by severity.
- **Endor / Socket (Coana) / Semgrep Supply Chain**: the differentiator is function-level reachability backed by proprietary vulnerable-symbol data.
- **Tenable VPR / Qualys TruRisk**: opaque ML scores. The Guardian's advantage over these is that every point is attributable.

Common pattern: `severity × threat likelihood × context`, with KEV as an override and reachability as the largest noise reducer.

### 1.5 Proposed Guardian score (0-100) with separate confidence

Design rules:

1. Five named factors, each normalised to 0..1, fixed weights summing to 100.
2. Every factor value carries an **evidence grade**: `verified`, `heuristic`, `inferred` (LLM), or `unknown`.
3. **Unknown never scores zero.** It takes a stated prior (neutral-to-pessimistic), lowers confidence, and widens the reported range.
4. A small number of named guardrails (floors/caps) applied after the sum, each reported when it fires.
5. Score answers "how urgently should a human look at this"; confidence answers "how much of that is evidence".

| Factor | Weight | Value rubric (0..1) | Prior when unknown |
|---|---|---|---|
| **Severity** | 30 | CVSS base / 10 (v4 if present, else v3; record which). GHSA bucket fallback: CRITICAL 0.95, HIGH 0.8, MODERATE 0.55, LOW 0.25 | 0.6 |
| **Exploitability** | 25 | KEV listed 1.0; EPSS ≥ 0.5 → 0.9; ≥ 0.1 → 0.7; ≥ 0.01 → 0.4; < 0.01 → 0.15. Exploit/PoC reference in advisory raises to at least 0.6 | 0.4 |
| **Reachability** | 20 | Tier R0 package not imported 0.1; R1 imported 0.5; R2 vulnerable symbol referenced 0.8; R3 symbol on a request path with untrusted input 1.0 (tiers in section 2) | 0.5 |
| **Exposure** | 15 | Prod runtime dep in an internet-facing service 1.0; prod dep, internal only 0.6; dev/build/test only 0.3 (CI still holds secrets, so not 0) | 0.6 |
| **Fix availability** | 10 | Fixed version within same major 1.0; fix needs a major bump 0.7; no fix published 0.5; package abandoned/deprecated 0.6 | 0.6 |

Fix availability is an *actionability* term: a cheap fix raises priority because the expected value of acting now is higher. Say so in the report so nobody reads it as "risk".

Guardrails:

- `KEV_FLOOR`: KEV listed and reachability tier ≥ R1 (or unknown) → score at least 90.
- `NOT_LOADED_CAP`: reachability R0 with grade `verified` or `heuristic`, and not KEV → score at most 39.
- `MALWARE_FLOOR`: an OSV `MAL-` advisory matches, or an anomaly is graded `verified` malicious → score at least 95.

Bands: 80-100 Urgent, 60-79 High, 40-59 Medium, 0-39 Low.

**Confidence** = Σ weightᵢ × qᵢ, with q: verified 1.0, heuristic 0.7, inferred 0.4, unknown 0.0. Bands: ≥ 80 High, 50-79 Medium, < 50 Low. Also report the **range**: recompute with every `unknown`/`inferred` factor at its minimum and maximum rubric value.

```python
WEIGHTS = {"severity": 30, "exploitability": 25, "reachability": 20, "exposure": 15, "fix": 10}
PRIOR   = {"severity": .6, "exploitability": .4, "reachability": .5, "exposure": .6, "fix": .6}
BOUNDS  = {"severity": (.25, 1), "exploitability": (.15, 1), "reachability": (.1, 1),
           "exposure": (.3, 1), "fix": (.5, 1)}
Q = {"verified": 1.0, "heuristic": 0.7, "inferred": 0.4, "unknown": 0.0}

def score(factors: dict) -> dict:
    """factors[name] = {"value": float|None, "grade": str, "evidence": [str]}"""
    def total(pick):
        return sum(WEIGHTS[k] * pick(k, f) for k, f in factors.items())
    val  = lambda k, f: PRIOR[k] if f["value"] is None else f["value"]
    soft = lambda f: f["grade"] in ("unknown", "inferred")
    lo   = lambda k, f: BOUNDS[k][0] if soft(f) else val(k, f)
    hi   = lambda k, f: BOUNDS[k][1] if soft(f) else val(k, f)
    return {
        "score": round(total(val)),
        "range": [round(total(lo)), round(total(hi))],
        "confidence": round(sum(WEIGHTS[k] * Q[f["grade"]] for k, f in factors.items())),
        "contributions": {k: round(WEIGHTS[k] * val(k, f), 1) for k, f in factors.items()},
        "unknown_factors": [k for k, f in factors.items() if f["value"] is None],
    }  # apply guardrails afterwards and append their names to "guardrails_fired"
```

### 1.6 Worked example A — `lodash@4.17.4`, GHSA-jf85-cpcp-j695 / CVE-2019-10744

Evidence: CVSS vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` (= 9.1), fixed in 4.17.12, GHSA severity CRITICAL [V, OSV record]. EPSS 0.05006, percentile 0.92445 [V]. KEV: believed not listed [U — check the feed]. The advisory text names `defaultsDeep` as the vulnerable function; no structured symbol list [V].

| Factor | Value | Grade | Points | Evidence line for the report |
|---|---|---|---|---|
| Severity | 0.91 | verified | 27.3 | CVSS 3.1 base 9.1 from OSV vector |
| Exploitability | 0.40 | verified | 10.0 | EPSS 0.050 (92nd pct), not in KEV |
| Reachability | 0.50 (R1) | heuristic | 10.0 | `require('lodash')` found in app source; no `defaultsDeep` call found by grep |
| Exposure | 1.00 | heuristic | 15.0 | in `dependencies`, present in `npm ls --omit=dev`; Dockerfile exposes an HTTP port |
| Fix | 1.00 | verified | 10.0 | 4.17.21 available, same major |

**Score 72 (High). Confidence 30 + 25 + 14 + 10.5 + 10 = 90 (High). Range 72-72.** No guardrail fires.

Same finding if the import scan had not been run: reachability `unknown` → prior 0.5 → score still 72, but range 64-82 and confidence 76 (Medium). The score did not drop because of missing evidence; the confidence did. That is the behaviour the brief asks for.

Contrast to show in the demo: lodash also carries prototype-pollution advisories for `merge`/`mergeWith` (e.g. CVE-2018-16487). If the app calls `_.merge` with `req.body` in a route handler [U — grep `routes/` in goof to confirm], that advisory gets R3 = 1.0 → 82 (Urgent), outranking the higher-CVSS one. One package, two advisories, different priorities because of reachability.

### 1.7 Scoring non-CVE anomalies

Same five factor names and weights, so findings sort in one list; different rubrics, and `type` is shown so nobody confuses the two.

| Factor | Meaning for anomalies | Rubric |
|---|---|---|
| Severity | Worst plausible impact of the class | Known-malicious package 1.0; lockfile integrity/`resolved` host mismatch 0.9; suspected typosquat 0.85; install script doing network/exec/env access 0.7; unpinned third-party Action 0.5; unpinned base image tag 0.4; floating `latest` npm range 0.35 |
| Exploitability | **Signal strength** that it is hostile | `MAL-` advisory 1.0; edit distance 1 from a top package *and* (new package or low downloads) 0.8; install script fetches remote code 0.8; name similarity alone 0.5; pure hygiene issue (unpinned ref, no hostile signal) 0.3 |
| Reachability | Does it execute? | Runs at install (`hasInstallScript`) 1.0 — no import needed; imported by app 0.8; present in lockfile only 0.4; Action in a workflow with secrets or `pull_request_target` 1.0, read-only workflow 0.5 |
| Exposure | Where it runs | CI/build with secrets or prod runtime 1.0; developer laptop only 0.6; isolated sandbox 0.3 |
| Fix | Remedy available | Remove/replace/pin available 1.0; needs upstream change 0.5 |

Worked example B — the kit's demo package `lodahs` (edit distance 1 from `lodash`; its `package.json` declares `"postinstall": "node scripts/setup.js"` and `"private": true` [V, `demo/packages/lodahs/package.json`]): 0.85×30 + 0.8×25 + 1.0×20 + 1.0×15 + 1.0×10 = **90.5 → 91 (Urgent)**. Grades: name distance and `hasInstallScript` are `verified` (read from the lockfile); "this is hostile" is `inferred` unless a human or a `MAL-` record confirms → confidence 30 + 10 + 20 + 15 + 10 = 85.

Worked example C — `uses: actions/checkout@v4` in a workflow with no secrets: 0.5×30 + 0.3×25 + 0.5×20 + 1.0×15 + 1.0×10 = **57.5 → 58 (Medium)**.

Finding record shape (what the scorer emits and what policy and the report consume):

```json
{
  "id": "F-0007", "type": "vulnerability",
  "advisory": {"id": "GHSA-jf85-cpcp-j695", "aliases": ["CVE-2019-10744"]},
  "package": {"name": "lodash", "version": "4.17.4", "purl": "pkg:npm/lodash@4.17.4",
              "scope": "prod", "direct": true, "paths": [["goof", "lodash"]]},
  "severity": "CRITICAL", "cvss": {"version": "3.1", "score": 9.1, "vector": "CVSS:3.1/..."},
  "epss": {"probability": 0.05006, "percentile": 0.92445, "date": "2026-11-22"},
  "kev": false,
  "reachability": {"tier": "R1", "grade": "heuristic", "evidence": ["routes/index.js:3 require('lodash')"]},
  "fix": {"version": "4.17.21", "semver_distance": "patch"},
  "risk": {"score": 72, "band": "High", "range": [72, 72], "confidence": 90,
           "contributions": {"severity": 27.3, "exploitability": 10.0, "reachability": 10.0, "exposure": 15.0, "fix": 10.0},
           "guardrails_fired": [], "unknown_factors": []},
  "verified_evidence": ["OSV record fetched 2026-11-23", "package-lock.json resolved version"],
  "ai_inference": []
}
```

Keep `verified_evidence` and `ai_inference` as **separate arrays** in the data model. The brief explicitly asks for that separation and it is far easier to enforce in a schema than in prose.

---

## 2. Reachability for JavaScript on a 2-day budget

### 2.1 Tiers

| Tier | Claim | How to establish cheaply | Honest label |
|---|---|---|---|
| R0 | Package is never imported by first-party code (and not transitively required by something that is) | import scan of app source + lockfile graph | heuristic (dynamic `require(variable)` defeats it) |
| R1 | Package is imported somewhere | same scan, with `file:line` | heuristic |
| R2 | The vulnerable **symbol** is referenced | grep/Semgrep for the function named in the advisory | heuristic if the symbol came from structured data; inferred if an LLM extracted it from prose |
| R3 | Symbol is called in a request handler with attacker-influenced input | handler heuristics or Semgrep taint mode | inferred, unless a human confirms |

Add an orthogonal flag `scope: prod | dev` from the lockfile. A dev-only package is not "unreachable"; it is reachable in CI.

Transitive deps: for a vulnerable package the app never imports directly, tier R1 means "a first-party-imported package depends on it" (walk the lockfile graph upward). Going deeper (does `express` actually call the vulnerable function in `qs`?) is whole-program analysis; skip it and say so.

### 2.2 Where function-level vulnerability data exists

- **Go**: yes. The Go vulndb publishes `affected[].ecosystem_specific.imports[].{path, symbols[]}` in OSV format; `govulncheck` consumes it [U].
- **Rust**: RustSec advisories carry affected functions, surfaced in OSV `ecosystem_specific` [U].
- **GHSA**: the advisory form has an "affected functions" field, sparsely populated and mostly for non-npm ecosystems [U].
- **npm: effectively nothing public and structured.** Verified sample: the OSV record for GHSA-jf85-cpcp-j695 has **no** `ecosystem_specific` on any `affected[]` entry; the function name `defaultsDeep` appears only in the free-text `details` [V].
- Commercial vendors (Snyk, Endor Labs, Socket/Coana, Semgrep Supply Chain) maintain proprietary symbol data for npm [U].

Consequence: for npm the vulnerable symbol must be **derived**: from advisory prose, from the fix commit (`references[]` entries of type `FIX`, or `GIT` ranges in OSV [U]), or from a hand-written table for the demo's top findings. Whatever the source, record it.

### 2.3 Cheap implementations

**Prod vs dev** (deterministic, do this first):

```bash
npm ls --all --omit=dev --json > prod-tree.json     # production closure [U flags; npm >= 8]
npm ls lodash                                        # which paths pull it in
npm explain lodash                                   # same, reverse view (alias: npm why) [U]
```

Lockfile v2/v3 also marks it directly: `packages["node_modules/<name>"].dev === true`, plus `hasInstallScript`, `resolved`, `integrity` [U — inspect goof's lockfile; if it is lockfileVersion 1 run `npm install --package-lock-only` in a scratch copy to upgrade it].

**Import scan in 25 lines** (covers `require`, `import … from`, dynamic `import()`):

```python
import re, pathlib, collections
PAT = re.compile(r"""(?:require\(\s*|from\s+|import\(\s*|import\s+)['"]([^'"]+)['"]""")
SKIP = {"node_modules", ".git", "dist", "public"}

def pkg_name(spec):                      # 'lodash/merge' -> 'lodash', '@a/b/c' -> '@a/b'
    if spec.startswith((".", "/", "node:")): return None
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") else parts[0]

def import_sites(root):
    sites = collections.defaultdict(list)
    for p in pathlib.Path(root).rglob("*"):
        if p.suffix not in {".js", ".cjs", ".mjs", ".ts"} or SKIP & set(p.parts): continue
        for n, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
            for spec in PAT.findall(line):
                if (name := pkg_name(spec)): sites[name].append(f"{p}:{n}")
    return sites   # R0 = declared dependency with no entry here
```

Known blind spots to print in the report: `require(variable)`, packages loaded by name through a framework (Express view engines such as `ejs`, `hbs`, `dustjs-linkedin` are loaded by string — goof uses these [V deps]), and CLI tools invoked from `scripts`. Treat "view engine configured" as an import.

**Off-the-shelf graph tools** [U flags]:

```bash
npx madge --json app.js > module-graph.json            # first-party module graph
npx depcruise --no-config --output-type json . > dc.json
npx depcheck --json                                     # declared-but-unused deps (feeds "remove")
```

**Semgrep for R2/R3**. One generated rule per (package, symbol):

```yaml
rules:
  - id: guardian.lodash.defaultsDeep
    languages: [javascript, typescript]
    severity: WARNING
    message: "Call to lodash.defaultsDeep (GHSA-jf85-cpcp-j695)"
    patterns:
      - pattern-either:
          - pattern: |
              $L = require('lodash')
              ...
              $L.defaultsDeep(...)
          - pattern: require('lodash').defaultsDeep(...)
          - pattern: require('lodash/defaultsDeep')
          - pattern: require('lodash.defaultsdeep')
```

```bash
semgrep scan --config rules/reach/ --json --output reach.json .     # [U on exact flags]
```

R3 with taint mode (sources = `req.body`, `req.query`, `req.params`; sink = the symbol):

```yaml
rules:
  - id: guardian.lodash.merge.tainted
    mode: taint
    languages: [javascript]
    severity: ERROR
    message: "Request data flows into lodash merge"
    pattern-sources:
      - pattern-either: [{pattern: req.body}, {pattern: req.query}, {pattern: req.params}]
    pattern-sinks:
      - pattern-either: [{pattern: $L.merge(...)}, {pattern: $L.mergeWith(...)}, {pattern: $L.defaultsDeep(...)}]
```

(Both rules are sketches [U]; run them once against goof and fix syntax before relying on them.)

**Heavier OSS options**

- **Jelly** (`cs-au-dk/jelly`, BSD-3-Clause): static call-graph and "vulnerability exposure analysis" for Node.js. `npm install -g @cs-au-dk/jelly`; `jelly -j cg.json -m cg.html <dir>` produces JSON and HTML call graphs [V, README]. It is deliberately unsound in places, treats the Node standard library as unknown code, and whole-dependency analysis can be slow (`--timeout`, `--max-indirections`) [V]. The vulnerability-pattern input format is not documented on the README page; check `jelly --help` [U]. Worth 30 minutes as a "call-graph evidence" attachment, not as the core.
- **reachble** (`RJonMshka/reachble`, MIT): npm-only CLI that reads `package-lock.json`, pulls CVEs from OSV/NVD/EPSS, does function-level import-graph analysis, scores by entry-point exposure (CRITICAL / HIGH / LOW / SAFE) and emits CycloneDX VEX and OpenVEX. `npx reachble scan`; CI form `reachble scan --format vex --fail-on high` [V, README]. Status "MVP", no releases published, and the README does not say where its vulnerable-symbol mapping comes from [V]. Use it as a **comparison baseline** ("our tiers vs theirs on the same lockfile"), pin an exact version, and run it in the sandbox container — pulling an unvetted young package with `npx` inside a supply-chain-security demo deserves the same scrutiny the Guardian applies to everything else.
- **SōjiTantei** (academic, arXiv 2109.08931): function-call reachability for npm; a citation for the architecture note, not a tool to install.
- A 2026 NDSS paper on npm reachability and Socket's "comparing reachability analysis providers" post turned up in search; neither was read. Listed in Sources as leads only.

### 2.4 LLM-assisted reachability, labelled as inference

Pipeline that keeps the model on a short leash:

1. **Deterministic**: collect import sites (2.3) and the advisory JSON (`summary`, `details`, `references`).
2. **LLM step 1 — symbol extraction**. Input: advisory text only. Output schema:
   ```json
   {"symbols": [{"name": "defaultsDeep", "access": ["_.defaultsDeep", "require('lodash/defaultsDeep')"],
                 "quote": "<exact sentence from the advisory>"}],
    "preconditions": ["attacker controls an object passed as a source argument"],
    "none_found": false}
   ```
   Reject the output unless every `quote` is a literal substring of the advisory text. That check is the hallucination control, and it is deterministic.
3. **Deterministic**: `grep -rnE` / Semgrep for each `access` pattern → call sites with `file:line` and ±15 lines of context.
4. **LLM step 2 — judgement**. Input: preconditions + the call-site snippets. Output: `{tier, attacker_controlled: yes|no|unclear, cited_lines: ["routes/index.js:42"], reasoning}`. Reject if a cited line is not among the snippets supplied.
5. **Record** with grades: import sites and grep hits → `verified_evidence`; symbol list and tier judgement → `ai_inference` with `grade: "inferred"`.

Rules worth stating in the Responsible-AI note: the model never lowers a finding below R1 on its own (absence of a call site is only as good as the grep); an `inferred` R0 cannot trigger `NOT_LOADED_CAP`; a VEX `not_affected` statement requires human approval.

---

## 3. Remediation strategies for npm

Semver distance drives the compatibility estimate everywhere below: **patch** (low), **minor** (low-moderate), **major** (assume breaking until shown otherwise), and for 0.x packages treat a minor bump as major. Lookups that turn the estimate into evidence:

```bash
npm view lodash versions --json                       # candidate versions
npm view lodash@4.17.21 engines peerDependencies deprecated dist.integrity
npm diff --diff=lodash@4.17.4 --diff=lodash@4.17.21   # actual published-tarball diff [U flags]
gh api repos/lodash/lodash/releases --jq '.[] | {tag_name, body}'   # release notes when the repo uses them
```

`npm diff` is also the right tool for "investigate a suspicious update": it diffs what was published, not what is in git.

| Strategy | Command / change | Expected risk reduction | Compatibility risk | Rollback |
|---|---|---|---|---|
| **Direct upgrade** | `npm install lodash@4.17.21 --save-exact` | Removes every advisory fixed at or below the target; rescan confirms | By semver distance. Goof's deps are years old (`express@4.12.4`, `mongoose@4.2.4`, `marked@0.3.5`), so several fixes are major jumps | `git revert <sha>` or `git checkout <base> -- package.json package-lock.json && npm ci` |
| **`overrides` for transitive** | `package.json`: `"overrides": {"qs": "6.5.3"}` or scoped `"overrides": {"express": {"qs": "6.5.3"}}`; then `npm install` [U syntax; npm ≥ 8.3] | Fixes a transitive vuln when the parent has no fixed release | Forces a version the parent never tested; high if it crosses the parent's declared range major. Overrides persist silently — record each one with an expiry in the report | Delete the override key, `npm install`, or revert the commit |
| **`npm audit fix`** | `npm audit fix --dry-run --json` to preview; `npm audit fix --package-lock-only` to change only the lockfile; `--omit=dev`; `--force` allows semver-major [V, npm docs] | Broad, in-range fixes in one step | Low without `--force` (stays within declared ranges). `--force` is explicitly discouraged by npm's docs [V]; never let the agent use it unprompted | Lockfile restore |
| **`osv-scanner fix`** | see below | In-place: patches lockfile within existing constraints. Relax: bumps direct deps in `package.json` to resolve more | Controlled with `--upgrade-config`; still **experimental** [V] | Lockfile/manifest restore |
| **Remove unused dep** | `npx depcheck --json`, confirm with the import scan, `npm uninstall <pkg>` | 100% for that package and any subtree only it pulled in; best ratio of risk removed to effort | Dynamic/string-loaded modules (view engines) give false "unused" — smoke test is mandatory | Revert |
| **Replace abandoned package** | Signals: `deprecated` on the version, last publish years ago (`time.modified`), archived repo. Swap for a maintained equivalent or a Node built-in | Removes the current vuln and the unpatched-forever tail | Highest: API changes need code edits. Usually "recommend + escalate", not auto-apply, in a 2-day build | Revert |
| **Pin base image by digest** | `FROM node:22-bookworm-slim@sha256:<digest>`; resolve with `docker buildx imagetools inspect node:22-bookworm-slim` or `crane digest` [U] | Removes tag-mutation risk; **does not fix CVEs by itself**. Moving goof off its EOL Node base to a current slim/distroless base is the actual CVE reduction | Node major jump can break old deps. Goof's scripts set `NODE_OPTIONS=--openssl-legacy-provider` [V], a hint it has already been nudged onto newer Node | Revert the Dockerfile line; old digest stays pullable |
| **Pin Actions by SHA** | `uses: actions/checkout@<40-hex-sha> # v4.x.y`; resolve: `gh api repos/actions/checkout/commits/v4 --jq .sha` [U] | Removes tag-retargeting risk (the tj-actions class of incident) | Near zero; cost is update toil (Dependabot/Renovate understand the trailing comment) | Revert |
| **Block via policy** | Conftest rule (6.4); `.npmrc` `ignore-scripts=true` for installs in CI | Preventive: stops reintroduction | `ignore-scripts` breaks packages that need native builds; needs an allow-list | Remove rule / add time-boxed waiver |
| **Mitigate / accept / escalate** | Input validation, WAF rule, feature flag; or record acceptance | Partial; state residual risk | None to the build | n/a — record owner and expiry |

**`osv-scanner fix`** (Guided Remediation) [V against `docs/guided-remediation.md` on `main`]:

```bash
osv-scanner fix --strategy=in-place -L path/to/package-lock.json
osv-scanner fix --strategy=relax -M path/to/package.json -L path/to/package-lock.json
osv-scanner fix --format json --strategy=relax -M path/to/package.json
osv-scanner fix --interactive -M path/to/package.json -L path/to/package-lock.json   # TUI, npm only
```

- Strategies: `in-place` (npm lockfile), `relax` (npm `package.json`; the docs also call it "relock"), `override` (Maven `pom.xml` only — **not** npm overrides).
- Useful flags: `--apply-top=<n>` (default -1 = all), `--no-introduce` (skip patches that add new vulns), `--max-depth`, `--min-severity=<cvss>` (vulns with no CVSS are *not* excluded), `--ignore-dev`, `--vulns=<ids>`, `--ignore-vulns=<ids>`, `--upgrade-config=[pkg:]major|minor|patch|none` (repeatable), `--data-source=native` (default is deps.dev), `--format text|json`.
- Caveats from the docs: marked experimental; it edits manifest/lockfile in place (commit first); it does **not** reinstall `node_modules` (run `npm ci`); it ignores `osv-scanner.toml`.
- Agent-friendly call: `osv-scanner fix --format json --strategy=in-place --no-introduce --upgrade-config=minor -L package-lock.json` inside the worktree, then parse the JSON as the "proposed patch set".

Recommendation record (one per finding, feeds approval and the PR body):

```json
{"finding_id": "F-0007", "action": "upgrade", "target": "lodash@4.17.21",
 "alternatives": [{"action": "override"}, {"action": "accept", "why_not": "fix is patch-level"}],
 "expected_risk_reduction": {"advisories_resolved": ["GHSA-jf85-cpcp-j695"], "score_before": 72, "score_after_estimate": 0},
 "compatibility": {"semver_distance": "patch", "breaking_changes_found": false,
                   "evidence": ["npm diff summary", "release notes 4.17.5..4.17.21"], "grade": "inferred"},
 "rollback": "git revert <commit>  |  git checkout <base> -- package.json package-lock.json && npm ci",
 "requires_approval": true}
```

`score_after_estimate` is a prediction; the validated number comes from the rescan (section 4) and the report should show both.

---

## 4. Validation

### 4.1 Apply in isolation

```bash
BASE=$(git rev-parse HEAD)
git worktree add -b guardian/fix-F-0007 ../wt-F-0007 "$BASE"
cd ../wt-F-0007
npm install lodash@4.17.21 --save-exact --package-lock-only   # change manifest + lock only; no scripts run
git add package.json package-lock.json
git commit -m "fix(deps): lodash 4.17.4 -> 4.17.21 (GHSA-jf85-cpcp-j695)"
# afterwards:  git worktree remove ../wt-F-0007   (the branch survives)
```

Worktrees let the baseline and the candidate be built and scanned side by side. Keep installs out of the host: do `npm ci` only inside the container build.

### 4.2 Build and test in Docker

```bash
docker build -t goof:base  "$REPO"         # once, from the base commit
docker build -t goof:F-0007 ../wt-F-0007
docker network create guardian-test 2>/dev/null || true
docker run -d --rm --name gt-mongo --network guardian-test mongo:<pinned>
docker run -d --rm --name gt-app --network guardian-test -p 127.0.0.1:3001:3001 \
  -e MONGO_URI=mongodb://gt-mongo/express-todo goof:F-0007      # env var name and port: check goof's README [U]
./scripts/smoke.sh http://127.0.0.1:3001; echo "exit=$?"
docker logs gt-app > evidence/F-0007/app.log 2>&1
docker rm -f gt-app gt-mongo
```

Because goof's `npm test` is `snyk test` [V], write `scripts/smoke.sh` (10-15 `curl` assertions: home page 200, create a todo, list shows it, a static asset, each view engine route renders) and call it "integration smoke tests" in the report. Run it against `goof:base` first: a test that fails on the baseline proves nothing about the fix. Record exit code, duration, image digest and log path as evidence.

Sandbox hygiene for the Responsible-AI note: bind to `127.0.0.1`, no host mounts, no secrets in the build context, `--network` limited to the test network, and optionally `--cap-drop=ALL --read-only`.

### 4.3 Rescan and compare

```bash
# SBOMs (pick one generator and use it on both sides) [U flags]
npx @cyclonedx/cyclonedx-npm --output-format JSON --output-file sbom.after.cdx.json   # in the worktree
syft goof:F-0007 -o cyclonedx-json=sbom.image.after.cdx.json                           # image-level

# Vulnerabilities [U flags]
osv-scanner scan source -L package-lock.json --format json > osv.after.json
grype sbom:sbom.after.cdx.json -o json > grype.after.json
```

**SBOM diff** with the official CLI [V, cyclonedx-cli README]:

```bash
cyclonedx diff sbom.before.cdx.json sbom.after.cdx.json --output-format json --component-versions
# containerised:
docker run --rm -v "$PWD:/w" cyclonedx/cyclonedx-cli diff /w/sbom.before.cdx.json /w/sbom.after.cdx.json \
  --output-format json --component-versions
cyclonedx validate --input-file sbom.after.cdx.json --fail-on-errors
```

`diff` takes `<from-file> <to-file>`, `--from-format/--to-format autodetect|json|protobuf|xml`, `--output-format json|text` (text default) [V]. `sbomdiff` (PyPI) is an alternative [U]. A custom diff is 15 lines and gives exactly the shape the report needs:

```python
import json
def comps(path):
    return {c["purl"].rsplit("@", 1)[0]: c.get("version")
            for c in json.load(open(path)).get("components", []) if c.get("purl")}

def sbom_diff(before, after):
    b, a = comps(before), comps(after)
    return {"added":   sorted(k for k in a if k not in b),
            "removed": sorted(k for k in b if k not in a),
            "changed": {k: [b[k], a[k]] for k in a if k in b and a[k] != b[k]}}

def vuln_diff(before_ids: set, after_ids: set):      # ids = {(advisory_id, purl_without_version)}
    return {"resolved": sorted(before_ids - after_ids),
            "introduced": sorted(after_ids - before_ids),
            "remaining": sorted(before_ids & after_ids)}
```

Caveat: a package installed at two versions collapses to one key here; key on full purl for the vulnerability diff if goof's tree has duplicates (it will).

**Verdict logic** (deterministic, no LLM):

- `verified` — target advisory in `resolved`, `introduced` empty, build OK, smoke tests pass on both base and candidate.
- `verified_with_new_risk` — as above but `introduced` or `added` non-empty: every added component is scored and listed; needs a second approval.
- `failed` — build or tests fail, or the target advisory is still present. Report it; a failed validation shown honestly is a good demo beat.

Every **added** component goes back through Day 1 detection (install script? typosquat? age?), since a fix that pulls in a new transitive dep is itself a supply-chain change.

### 4.4 VEX

**OpenVEX** minimal valid document, adapted from the spec's example [V for structure, context URL, required fields and status rules; the content values are illustrative]:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://guardian.local/vex/2026-11-23-0001",
  "author": "Supply Chain Guardian (approved by: <human>)",
  "role": "Document Creator",
  "timestamp": "2026-11-23T10:00:00Z",
  "version": 1,
  "statements": [
    {"vulnerability": {"name": "CVE-2019-10744"},
     "products": [{"@id": "pkg:npm/lodash@4.17.21"}],
     "status": "fixed"},
    {"vulnerability": {"name": "CVE-2020-0000"},
     "products": [{"@id": "pkg:npm/example@1.0.0"}],
     "status": "not_affected",
     "justification": "vulnerable_code_not_in_execute_path",
     "impact_statement": "Package is not imported by first-party code (import scan, heuristic)."}
  ]
}
```

Rules [V]: required document fields `@context, @id, author, timestamp, version, statements`; statement needs `vulnerability.name` and `status`, plus a product (direct or inherited). Statuses: `not_affected | affected | fixed | under_investigation`. `not_affected` **must** carry a `justification` (`component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`) or an `impact_statement`; `affected` **must** carry an `action_statement`; bump `version` on any change. Modelling choice to check with `vexctl`: whether `products` should name the application with the package as a subcomponent rather than the package itself [U].

Mapping from reachability tiers: R0 → `vulnerable_code_not_in_execute_path` (only after human approval); validated fix → `fixed`; R2/R3 unfixed → `affected` + `action_statement`; anything `inferred` and unreviewed → `under_investigation`.

**CycloneDX VEX** (a BOM with a `vulnerabilities` array) [U — field names and enums from memory of spec 1.5/1.6; run `cyclonedx validate` on the output]:

```json
{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "metadata": {"timestamp": "2026-11-23T10:00:00Z",
               "component": {"type": "application", "name": "nodejs-goof", "version": "1.0.1", "bom-ref": "app"}},
  "vulnerabilities": [{
    "id": "CVE-2019-10744",
    "source": {"name": "OSV", "url": "https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695"},
    "ratings": [{"method": "CVSSv31", "score": 9.1, "severity": "critical",
                 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"}],
    "analysis": {"state": "resolved", "response": ["update"],
                 "detail": "Upgraded lodash 4.17.4 -> 4.17.21; rescan clean; smoke tests pass."},
    "affects": [{"ref": "pkg:npm/lodash@4.17.21"}]
  }]
}
```

`analysis.state`: `resolved | resolved_with_pedigree | exploitable | in_triage | false_positive | not_affected`; `justification` (for `not_affected`): `code_not_present | code_not_reachable | requires_configuration | requires_dependency | requires_environment | protected_by_compiler | protected_at_runtime | protected_at_perimeter | protected_by_mitigating_control` [U].

### 4.5 SARIF

Minimal SARIF 2.1.0 for the machine-readable report (uploadable to GitHub code scanning) [U — structure from memory]:

```json
{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
 "runs": [{"tool": {"driver": {"name": "SupplyChainGuardian", "version": "0.1.0",
     "rules": [{"id": "GHSA-jf85-cpcp-j695", "shortDescription": {"text": "Prototype Pollution in lodash"},
                "properties": {"security-severity": "9.1"}}]}},
   "results": [{"ruleId": "GHSA-jf85-cpcp-j695", "level": "error",
     "message": {"text": "lodash@4.17.4 — Guardian score 72 (confidence 90). Fix: 4.17.21"},
     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "package-lock.json"}, "region": {"startLine": 1}}}],
     "properties": {"guardianScore": 72, "confidence": 90, "reachabilityTier": "R1"}}]}]}
```

`osv-scanner`, Grype, Trivy and Semgrep can emit SARIF themselves [U], and Conftest has `--output sarif` [V]. Lowest effort: write the Guardian's own findings JSON as the source of truth and generate SARIF from it.

---

## 5. Human approval and audit trail

### 5.1 Approval patterns that fit an agent system

- **Propose → approve → execute, with the approval bound to content.** The agent emits a plan (action, target, the exact diff). Approval records `sha256(diff)`. The executor refuses if the diff it is about to apply hashes differently. This closes the "approved one thing, applied another" gap and is trivial to demo.
- **Tiered autonomy.** Tier 0 read-only (scan, query, score): automatic. Tier 1 reversible and sandboxed (create worktree, build, test, rescan): automatic, logged. Tier 2 leaves the sandbox (push a branch, open a PR, write a VEX `not_affected`, add a policy waiver): human approval. Tier 3 (merge, deploy, publish): **never by the agent** — the brief makes this a hard rule.
- **Gate in code, not in the prompt.** The tool wrapper checks for an approval record before running a Tier 2 action. A system prompt saying "ask first" is not a control.
- **Two gates in the Day 2 flow.** Gate 1 before applying a fix in the sandbox is optional; Gate 2 before the PR is mandatory, and it is where the human sees validation results. If validation ends `verified_with_new_risk`, require a fresh approval.
- **Decisions are approve / reject / defer, with a reason and an expiry** for accepted risk. Rejections are logged too.
- **Separation of duties.** The component that proposes cannot write approval records; in a hackathon that means approvals come only from the CLI prompt or UI button, never from a tool the LLM can call.
- **Orchestrator mechanics.** A LangGraph-style interrupt/resume, or simply persisting `state.json` with `status: "awaiting_approval"` and exiting; `guardian approve F-0007 --by <name>` resumes. The persisted-state version survives a crashed demo.

### 5.2 Audit trail: append-only JSONL with hash chaining

```python
import json, hashlib, datetime, os
GENESIS = "0" * 64

def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def append(path, actor, kind, payload):
    prev, seq = GENESIS, 0
    if os.path.exists(path):
        with open(path, "rb") as f:
            for line in f:
                if line.strip():
                    last = json.loads(line); prev, seq = last["hash"], last["seq"] + 1
    rec = {"seq": seq, "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "actor": actor, "kind": kind, "payload": payload, "prev_hash": prev}
    rec["hash"] = hashlib.sha256(_canon(rec)).hexdigest()       # hash covers prev_hash
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n"); f.flush(); os.fsync(f.fileno())
    return rec["hash"]

def verify(path):
    prev = GENESIS
    for i, line in enumerate(open(path, encoding="utf-8")):
        rec = json.loads(line); claimed = rec.pop("hash")
        if rec["prev_hash"] != prev or rec["seq"] != i: return False, i
        if hashlib.sha256(_canon(rec)).hexdigest() != claimed: return False, i
        prev = claimed
    return True, prev          # prev is the head hash
```

Event kinds: `scan.completed`, `finding.scored`, `llm.call`, `recommendation.proposed`, `approval.granted|rejected`, `fix.applied`, `build.result`, `test.result`, `rescan.result`, `verdict`, `pr.opened`, `policy.evaluated`, `risk.accepted`.

Design notes:

- `actor` is one of `agent:<name>`, `tool:<name>@<version>`, `human:<id>`. This is what makes "verified evidence vs AI inference" queryable.
- For `llm.call` store model id, prompt hash, response hash and the path of the full transcript, not the transcript itself. Large artefacts (SBOMs, logs, diffs) go to `evidence/` and the log stores `{path, sha256}`.
- Never log secrets or environment dumps; redact tokens in command lines before writing.
- A hash chain is **tamper-evident, not tamper-proof**: anyone who can rewrite the file can rebuild the chain. Anchor the head hash somewhere else — print it in the final report, commit it to git, or `cosign sign-blob` it. State this limit in the known-limitations section.
- Demo beat: edit one byte of an old record, run `guardian audit verify`, show the failing sequence number.

---

## 6. Stretch goals — smallest credible demo for each

### 6.1 Automated remediation PR

Local-only version (no network, always works):

```bash
git -C ../wt-F-0007 format-patch -1 --stdout > out/F-0007.patch
git apply --check out/F-0007.patch        # proves it applies cleanly to base
```

PR to the **team's own fork**, after approval:

```bash
git -C ../wt-F-0007 push origin guardian/fix-F-0007
gh pr create --repo <team>/nodejs-goof --base main --head guardian/fix-F-0007 --draft \
  --title "fix(deps): lodash 4.17.4 -> 4.17.21 (GHSA-jf85-cpcp-j695)" --body-file out/F-0007.pr.md
```

Always pass `--repo`. In a fork, `gh` may resolve the default repository to the upstream parent, which would open a PR against `snyk-labs/nodejs-goof` — outside the authorised sandbox [U on the default behaviour; `gh repo set-default <team>/nodejs-goof` removes the doubt]. Open as `--draft`, never enable auto-merge, and use a token scoped to the fork only.

PR body template:

```markdown
## Guardian remediation: {{package}} {{from}} -> {{to}}

**Finding** {{finding_id}} — {{advisory_id}} ({{aliases}}) — {{title}}
**Risk before** {{score_before}}/100 ({{band}}), confidence {{confidence}} | **after rescan** {{score_after}}

### Why this change
{{rationale}}

| Factor | Value | Evidence | Grade |
|---|---|---|---|
{{factor_rows}}

### What changed
- {{manifest_changes}}
- SBOM diff: +{{added_n}} / -{{removed_n}} / ~{{changed_n}} components (attached)

### Validation (run {{run_id}}, image {{image_digest}})
- Build: {{build_status}}
- Smoke tests: {{tests_passed}}/{{tests_total}} (baseline: {{baseline_passed}}/{{tests_total}})
- Rescan: resolved {{resolved}}, introduced {{introduced}}, remaining {{remaining_n}}

### Compatibility
Semver distance: {{semver_distance}}. {{breaking_change_notes}}

### Rollback
`git revert {{commit_sha}}` or `git checkout {{base_sha}} -- package.json package-lock.json && npm ci`

### Provenance of this PR
Verified evidence: {{verified_list}}
AI-generated inference (review before trusting): {{inference_list}}
Approved by {{approver}} at {{approved_at}}; approved diff sha256 {{diff_sha}}; audit head {{audit_head}}

Generated by Supply Chain Guardian. Not auto-merged; human review required.
```

### 6.2 Provenance verification

**Distroless** (keyless, Google identity) [V, distroless README]:

```bash
cosign verify gcr.io/distroless/nodejs22-debian13 \
  --certificate-oidc-issuer https://accounts.google.com \
  --certificate-identity keyless@distroless.iam.gserviceaccount.com
```

Current Node images listed: `gcr.io/distroless/nodejs22-debian13`, `nodejs24-debian13`, `nodejs26-debian13`, with tags `latest`, `nonroot`, `debug`, `debug-nonroot`; older Debian bases are described as deprecated [V].

**Chainguard public images** [V, Chainguard support article]:

```bash
cosign verify \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main \
  cgr.dev/chainguard/node | jq
```

**Attestations** on a Chainguard image [U — the page that documents these did not render for the fetcher; the `--type` values are from memory]:

```bash
cosign verify-attestation \
  --type https://slsa.dev/provenance/v1 \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main \
  cgr.dev/chainguard/node | jq -r .payload | base64 -d | jq '.predicateType, .predicate.buildDefinition'

cosign verify-attestation --type https://spdx.dev/Document  <same identity flags>  cgr.dev/chainguard/node \
  | jq -r .payload | base64 -d | jq '.predicate.packages | length'
cosign download attestation cgr.dev/chainguard/node | jq -r .payload | base64 -d | jq .predicateType
cosign tree cgr.dev/chainguard/node        # lists attached signatures / attestations / SBOMs
```

Verify by digest (`image@sha256:…`) in the real flow so the thing verified is the thing pinned. A failed verification is a finding of type `provenance_gap`, not a crash.

**The team's own image** — sign and attest locally without touching public infrastructure [U flags; behaviour differs across cosign major versions, check `cosign sign --help`]:

```bash
docker run -d -p 127.0.0.1:5000:5000 --name reg registry:2
docker tag goof:F-0007 localhost:5000/goof:F-0007 && docker push localhost:5000/goof:F-0007
cosign generate-key-pair                                   # demo key; never commit cosign.key
cosign sign --key cosign.key --tlog-upload=false localhost:5000/goof@sha256:<digest>
cosign attest --key cosign.key --tlog-upload=false --type cyclonedx --predicate sbom.after.cdx.json localhost:5000/goof@sha256:<digest>
cosign verify --key cosign.pub --insecure-ignore-tlog=true localhost:5000/goof@sha256:<digest>
```

**npm** [V, npm docs for `npm audit`]:

```bash
npm ci --ignore-scripts
npm audit signatures
npm audit signatures --json --include-attestations
```

`npm audit signatures` verifies registry signatures of installed packages and also verifies provenance attestations; registry keys are served at `/-/npm/v1/keys` and signatures live in each version's `dist` in the packument [V]. On goof expect: signatures valid for nearly everything, provenance attestations for almost nothing, because the pinned versions predate npm provenance (2023). Report that as "provenance unavailable (unknown)", **not** as a failure and not as zero risk. Per-package check [U]: `npm view <pkg>@<ver> dist.attestations dist.signatures`.

Background for the architecture note [U]:

- **SLSA v1.0 build track**: L0 none; L1 provenance exists; L2 provenance signed by a hosted build platform; L3 hardened, isolated builds with non-forgeable provenance. npm provenance from GitHub Actions is commonly described as Build L2-L3.
- **in-toto**: a Statement `{"_type": "https://in-toto.io/Statement/v1", "subject": [{"name", "digest": {"sha256"}}], "predicateType", "predicate"}` wrapped in a DSSE envelope (`payloadType`, base64 `payload`, `signatures`). SLSA provenance, SPDX and CycloneDX attestations are all predicates in this envelope, which is why the `jq -r .payload | base64 -d` step appears above.

Smallest credible demo: one command verifying a signed base image, one showing goof's current base has no verifiable signature, both recorded as evidence and fed into the base-image recommendation.

### 6.3 Advanced package risk

Data source: the packument, `GET https://registry.npmjs.org/<name>` [U on field names; inspect one response]. Relevant fields: `time` (`created`, `modified`, and one ISO timestamp per version), `maintainers[]`, `versions[v]._npmUser`, `versions[v].scripts`, `versions[v].dependencies`, `versions[v].dist.{integrity, signatures, attestations}`, `versions[v].deprecated`. Weekly downloads: `https://api.npmjs.org/downloads/point/last-week/<name>`.

| Signal | Computation | Notes |
|---|---|---|
| Publisher change | `_npmUser.name` of the resolved version ≠ publisher of the previous N versions | Strongest cheap signal for account takeover; also common in legitimate handovers → `inferred` until reviewed |
| Dormancy then release | gap before this version > 2 years, or > 10× the package's median gap | From `time` |
| Burst | ≥ 3 versions within 24h after a quiet period | From `time` |
| Too fresh | resolved version published < 7 days before the lockfile commit | Basis for a cooldown policy |
| Install script appears | `scripts.preinstall/install/postinstall` present in this version, absent in the previous | Pair with lockfile `hasInstallScript` |
| Dependency added in a patch release | new key in `dependencies` between adjacent patch versions | The event-stream pattern |
| Provenance downgrade | earlier versions have `dist.attestations`, this one does not | |
| Version jump | major jumps by more than 1, or a version like `99.x` | Dependency-confusion marker |
| Typosquat | Damerau-Levenshtein ≤ 1-2 against a top-N popular list, plus separator/scope swaps, and low downloads or recent `created` | Embed a top-5000 list in the repo |
| Dependency confusion | lockfile `resolved` host ≠ expected registry; unscoped internal-looking name; scope with no registry mapping in `.npmrc`; name exists publicly at a higher version than the internal one | Local check, no publishing needed |

```python
from datetime import datetime
from statistics import median
def cadence_flags(time_map: dict, version: str) -> list[str]:
    t = {v: datetime.fromisoformat(ts.replace("Z", "+00:00"))
         for v, ts in time_map.items() if v not in ("created", "modified")}
    order = sorted(t, key=t.get); i = order.index(version); flags = []
    gaps = [(t[b] - t[a]).days for a, b in zip(order, order[1:])]
    if i > 0 and gaps:
        gap, med = gaps[i - 1], max(median(gaps), 1)
        if gap > 730 or gap > 10 * med: flags.append(f"dormant_then_release:{gap}d (median {med}d)")
    if sum(1 for v in order if abs((t[v] - t[version]).total_seconds()) < 86400) >= 3:
        flags.append("burst:3+_versions_within_24h")
    return flags
```

Smallest credible demo, within the rules: the kit's local `demo/packages/lodahs` fixture installed from a `file:` path or a throwaway local Verdaccio registry — **never published publicly** — plus two or three recorded packument fixtures (one clean, one with a publisher change, one with a new postinstall) so the detector can be shown without relying on live registry state. Label fixtures as fixtures.

### 6.4 Policy-as-code (Conftest / OPA, Rego v1)

Conftest facts [V, conftest.dev]: default policy dir `policy`, default namespace `main`; `--policy/-p`, `--namespace`, `--all-namespaces`, `--data/-d` (JSON/YAML loaded recursively, read as `data.<key>`), `--combine`, `--parser`; outputs `stdout, json, tap, table, junit, github, azuredevops, sarif`; rule names `deny`, `violation`, `warn` (optionally suffixed, e.g. `deny_kev`); exit code 1 when a policy fails, and with `--fail-on-warn` 1 = warnings only, 2 = failures; `conftest verify --policy ./policy` runs Rego unit tests. The docs' own examples use `if`/`contains` syntax. Whether Rego v1 is the default depends on the installed Conftest/OPA version [U]; `import rego.v1` below keeps the files valid either way on OPA ≥ 0.59.

`policy/data/guardian.yaml`:

```yaml
guardian:
  allow_install_scripts: ["esbuild", "bcrypt"]
  deny_licenses: ["AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0"]
  waivers: []          # [{finding_id: "F-0012", expires: "2026-12-31T00:00:00Z", approved_by: "..."}]
```

`policy/findings.rego` — over the Guardian's findings JSON (shape in 1.7, wrapped as `{"findings": [...]}`):

```rego
package guardian.findings

import rego.v1

waived(f) if {
	some w in data.guardian.waivers
	w.finding_id == f.id
	time.parse_rfc3339_ns(w.expires) > time.now_ns()
}

deny contains msg if {
	some f in input.findings
	f.type == "vulnerability"
	f.severity == "CRITICAL"
	f.kev == true
	not waived(f)
	msg := sprintf("%s: critical and in CISA KEV: %s@%s", [f.id, f.package.name, f.package.version])
}

deny contains msg if {
	some f in input.findings
	f.type == "install_script"
	not f.package.name in data.guardian.allow_install_scripts
	not waived(f)
	msg := sprintf("%s: install script not allow-listed: %s@%s", [f.id, f.package.name, f.package.version])
}

deny contains msg if {
	some f in input.findings
	f.risk.score >= 80
	f.risk.confidence >= 50
	not waived(f)
	msg := sprintf("%s: Guardian score %d (confidence %d)", [f.id, f.risk.score, f.risk.confidence])
}

warn contains msg if {
	some f in input.findings
	f.risk.score >= 80
	f.risk.confidence < 50
	msg := sprintf("%s: score %d but low confidence (%d): needs review", [f.id, f.risk.score, f.risk.confidence])
}
```

`policy/sbom.rego` — licence deny-list over a CycloneDX SBOM:

```rego
package guardian.sbom

import rego.v1

license_ids(c) := {l.license.id | some l in c.licenses; l.license.id} | {l.expression | some l in c.licenses; l.expression}

deny contains msg if {
	some c in input.components
	some id in license_ids(c)
	id in data.guardian.deny_licenses
	msg := sprintf("denied licence %s: %s@%s", [id, c.name, c.version])
}

warn contains msg if {
	some c in input.components
	count(object.get(c, "licenses", [])) == 0
	msg := sprintf("licence unknown: %s@%s", [c.name, c.version])
}
```

`policy/docker.rego` — Conftest's Dockerfile parser yields a list of instructions with `Cmd` and `Value` [U on exact shape; `conftest parse Dockerfile` prints it]:

```rego
package guardian.docker

import rego.v1

stage_names contains lower(input[i].Value[2]) if {
	input[i].Cmd == "from"
	count(input[i].Value) == 3          # FROM image AS name
}

deny contains msg if {
	some i
	input[i].Cmd == "from"
	image := input[i].Value[0]
	image != "scratch"
	not lower(image) in stage_names
	not contains(image, "@sha256:")
	msg := sprintf("base image not pinned by digest: %s", [image])
}
```

`policy/actions.rego` — over a workflow YAML:

```rego
package guardian.actions

import rego.v1

deny contains msg if {
	some job_name, job in input.jobs
	some step in job.steps
	uses := step.uses
	not startswith(uses, "./")
	not startswith(uses, "docker://")
	not regex.match(`@[0-9a-f]{40}$`, uses)
	msg := sprintf("job %s: action not pinned to a commit SHA: %s", [job_name, uses])
}
```

Commands:

```bash
conftest test out/findings.json        --policy policy --data policy/data --namespace guardian.findings --output json
conftest test sbom.after.cdx.json      --policy policy --data policy/data --namespace guardian.sbom
conftest test Dockerfile               --policy policy --namespace guardian.docker
conftest test .github/workflows/*.yml  --policy policy --namespace guardian.actions
conftest verify --policy policy        # Rego unit tests (*_test.rego)
```

All four Rego files are unexecuted sketches: `conftest`/`opa` were not installed in the research sandbox. Budget 30 minutes to run them and fix syntax. "Unknown licence" and "low-confidence high score" are `warn`, not `deny` and not pass — the same unknown-is-not-zero rule, applied to policy.

Smallest credible demo: gate runs before and after remediation; before → exit 1 with named denials, after → exit 0 (or fewer denials); both JSON outputs go into the audit log as `policy.evaluated`. Wire the same command into a GitHub Actions job in the fork for the "block the build" line of the brief.

### 6.5 Continuous monitoring

OSV batch endpoint [U — `api.osv.dev` was blocked for direct calls; shape from memory]:

```bash
curl -s -X POST https://api.osv.dev/v1/querybatch -d '{"queries":[
  {"package":{"purl":"pkg:npm/lodash@4.17.4"}},
  {"package":{"name":"express","ecosystem":"npm"},"version":"4.12.4"}]}'
# -> {"results":[{"vulns":[{"id":"GHSA-...","modified":"..."}]},{"vulns":[...]}]}   same order as queries
```

Batch results carry only `id` and `modified`; fetch detail with `GET https://api.osv.dev/v1/vulns/<id>` (this endpoint is what produced the lodash record quoted in 1.6 [V]). Batches are limited (1000 queries [U]) and paginate with `next_page_token` [U].

```python
def reassess(sbom_path, state_path):
    purls = [c["purl"] for c in load(sbom_path)["components"] if c.get("purl")]
    now   = {(p, v["id"]): v["modified"] for p, res in zip(purls, osv_querybatch(purls))
             for v in res.get("vulns", [])}
    old   = load(state_path, default={})                      # {"purl|id": modified}
    new      = [k for k in now if "|".join(k) not in old]
    updated  = [k for k in now if old.get("|".join(k)) not in (None, now[k])]
    withdrawn = [k for k in old if tuple(k.split("|")) not in now]
    for purl, vid in new + updated:
        finding = enrich(fetch_osv(vid), purl)                # + EPSS, KEV, stored reachability
        audit("finding.rescored", score(finding))
    save(state_path, {"|".join(k): m for k, m in now.items()})
    return {"new": new, "updated": updated, "withdrawn": withdrawn}
```

Also re-score when only the threat data moves: EPSS crossing a rubric threshold, or a CVE newly added to KEV (diff the KEV feed by `dateAdded`). Scheduling: a `guardian monitor --once` command plus either cron, a `while sleep` loop in a container, or a GitHub Actions `schedule:` workflow in the fork.

Smallest credible demo, honestly labelled: keep the stored SBOM, delete one advisory from the stored state file (or use a state snapshot taken before a known disclosure date), run `guardian monitor --once`, and show "1 newly disclosed advisory → scored 82 → policy gate now fails → notification". Say on the slide that the disclosure is simulated by rewinding state; the code path is the real one.

---

## 7. Cut list

Ordering principle: the Day 2 judging line is one finding carried from detection to verified remediation. Build that single thread end to end before widening anything.

### Build first (the spine — target: working by midday on Day 2)

1. Enrichment with on-disk cache: OSV detail, EPSS, KEV. Missing → `unknown`.
2. Scorer from 1.5 with contributions, range, confidence, guardrails. Pure function, unit-tested with the three worked examples.
3. Reachability R0/R1 from the regex import scan plus prod/dev from the lockfile. No LLM needed.
4. One remediation path: direct upgrade in a git worktree, lockfile-only change.
5. `scripts/smoke.sh`, Docker build, baseline-vs-candidate run.
6. Rescan + custom SBOM/vulnerability diff + deterministic verdict.
7. CLI approval gate bound to the diff hash; hash-chained JSONL audit log with `verify`.
8. Report: Markdown for humans + findings JSON for machines, with `verified_evidence` / `ai_inference` split.

### Build second (each about 1-2 hours, in this order)

9. Conftest gate over findings JSON + Dockerfile + workflow (covers stretch 5 and the "block" remediation, and gives a before/after exit-code moment).
10. LLM reachability to R2 for the top 3-5 findings, with the quote-must-be-substring check (stretch 1).
11. One non-CVE investigation end to end: `lodahs` typosquat with install script, scored and blocked by policy.
12. Draft PR to the fork from the template (stretch 2). Fallback: `git format-patch`.
13. OpenVEX output for the fixed finding.
14. `cosign verify` on a distroless or Chainguard base as provenance evidence in the base-image recommendation (stretch 3).

### Fake honestly (say so on screen and in known limitations)

- **Continuous monitoring**: real `monitor --once` code path, "new disclosure" simulated by rewinding the stored state.
- **Maintainer-change / cadence anomalies**: detector runs on recorded packument fixtures, plus one live package to show it is not hard-wired.
- **Exposure**: a declared `context.yaml` (`internet_facing: true`, `environment: prod`) rather than discovered; grade it `heuristic` and show that deleting the file turns it `unknown` and lowers confidence.
- **Vulnerable-symbol table**: hand-curated for the handful of demo advisories, with LLM extraction for the rest marked `inferred`.
- **Compatibility assessment**: semver distance + LLM summary of release notes, marked `inferred`; the smoke test is the actual evidence.
- **Unit tests**: goof has none; smoke tests stand in and are described as such.

### Skip

- Full call-graph / inter-package reachability (Jelly integration beyond a screenshot), R3 taint analysis beyond one Semgrep rule.
- CVSS v4 environmental re-scoring; a full SSVC tree UI (print the outcome string only).
- `overrides`-based transitive fixes and package replacement as automated paths — recommend and escalate instead.
- Signing with public Sigstore/Rekor, in-toto layouts, generating SLSA provenance for the team's own build.
- Dependency-confusion probing against real registries; anything that publishes a package anywhere public (also forbidden by the brief).
- Multi-ecosystem support, a web dashboard beyond a static HTML report, auto-merge of anything.
- CycloneDX VEX in addition to OpenVEX; SARIF unless the PR flow lands early.

### Risks to the plan

- **Network egress** at the venue may block the same hosts it blocked here. Pre-populate caches and container images the evening before.
- **Goof's age**: a modern Node base image may not run it; upgrading one dep may surface peer breakage. Pick the demo finding (lodash is the safest: patch-level, same major) and rehearse it before choosing anything more ambitious.
- **Lockfile format**: if goof ships lockfileVersion 1, `hasInstallScript`/`dev` flags are absent until it is regenerated; regenerating changes resolved versions, which is itself a diff to explain.
- **Unverified commands**: everything tagged [U] above, plus all Rego and Semgrep sketches, has not been executed.

---

## Sources

Read during this session:

- FIRST EPSS API, live response for CVE-2021-44228 and CVE-2019-10744: https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2019-10744
- OSV record for GHSA-jf85-cpcp-j695: https://api.osv.dev/v1/vulns/GHSA-jf85-cpcp-j695
- OSV-Scanner guided remediation docs: https://github.com/google/osv-scanner/blob/main/docs/guided-remediation.md
- npm CLI `npm audit` (signatures, fix flags): https://docs.npmjs.com/cli/v11/commands/npm-audit
- Conftest docs: https://www.conftest.dev/ and https://www.conftest.dev/options/
- CycloneDX CLI README (`diff`, `validate`, `merge`): https://github.com/CycloneDX/cyclonedx-cli
- OpenVEX specification: https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
- Distroless README (cosign verify, image list): https://github.com/GoogleContainerTools/distroless
- Chainguard support, verify image signatures with cosign: https://support.chainguard.dev/hc/en-us/articles/53833609818779-Verify-Chainguard-image-signatures-with-cosign
- reachble README: https://github.com/RJonMshka/reachble
- Jelly README: https://github.com/cs-au-dk/jelly
- nodejs-goof `package.json`: https://raw.githubusercontent.com/snyk-labs/nodejs-goof/main/package.json

Found but not read (leads only):

- Chainguard docs, verifying containers and metadata with cosign (page body did not render): https://www.chainguard.dev/docs/chainguard/containers/security-and-compliance/verifying-chainguard-images-and-metadata-signatures-with-cosign
- cosign `verify-attestation` reference: https://raw.githubusercontent.com/sigstore/cosign/main/doc/cosign_verify-attestation.md
- SōjiTantei paper: https://arxiv.org/pdf/2109.08931
- NDSS 2026 paper on npm reachability: https://www.ndss-symposium.org/wp-content/uploads/2026-f1902-paper.pdf
- Semgrep reachability whitepaper: https://semgrep.dev/assets/content/whitepapers/semgrep-reachabilityanalysis-whitepaper-1225.pdf
- Socket, comparing reachability analysis providers: https://socket.dev/blog/comparing-reachability-analysis-providers

Not reachable, cited from memory:

- CISA KEV JSON feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- OSV API `querybatch`: https://api.osv.dev/v1/querybatch (OSV-Scanner's own docs site, google.github.io/osv-scanner, also failed to load; the GitHub copy was used instead)
- CVSS v4.0 specification, SSVC guides (CISA, CERT/CC), SLSA v1.0, in-toto Statement v1, CycloneDX VEX schema, SARIF 2.1.0, npm `overrides` and packument docs.
