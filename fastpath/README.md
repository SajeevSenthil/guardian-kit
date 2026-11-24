# Guardian fast path: SBOM, dependency graph and risk detection

The fast path is a single Python script that compares two git refs of an npm app. It produces:

- a **CycloneDX SBOM** for each version, plus a diff of the two;
- a **dependency graph** with a direct / transitive split, the path from the app to every
  package, and each package's origin;
- **known vulnerabilities** from OSV, with CVE aliases, severity and fixed versions;
- **suspicious changes** between the two refs: look-alike names, install scripts, untrusted
  origins, suspicious updates, unused new imports, Docker base images, GitHub Actions;
- **one self-contained HTML page** with an interactive graph and three tabs: *What is in it*,
  *What changed*, *What is risky*.

Every finding carries a component, type, risk level (plus the rule that set it), dependency
path, the commit that introduced it, and evidence: file, line and exact excerpt.

Detection is deterministic: no LLM, no Docker, nothing to install beyond Python and git.
The script never modifies the target repo and never runs code from scanned packages.

This is the Day 1 deliverable ("Show us what is in the application, what changed, and what
appears risky"). Day 2 (prioritisation with reachability, EPSS and KEV; agents; remediation plans; validation; report)
is built separately in `guardian/` on top of these outputs: see the main README and `implementations.md`.

---

## Quick start

Run these from the kit root, the folder that contains `fastpath/` and `scripts/`.

```bash
# 1. Build the demo target (once). Creates ./target as a git repo with two refs:
#    guardian-baseline (the trusted app) and tampered (4 commits with planted risks).
bash scripts/make_demo_target.sh            # add --force to rebuild

# 2. Run Guardian (about 20 s; queries api.osv.dev, then caches the answers)
python fastpath/build.py

# 3. Open the dashboard in a browser
start fastpath/out/guardian.html            # Windows
open  fastpath/out/guardian.html            # macOS
xdg-open fastpath/out/guardian.html         # Linux
```

Expected console line:

```
packages=982 install_paths=1276 direct=37 transitive=945 suspicious_new=10 suspicious_present=5
vulns={'low': 82, 'medium': 148, 'high': 95, 'critical': 28} osv=evaluated findings=370
```

Advisory data changes over time, so the vulnerability counts may drift. The package and
suspicious-change counts should not.

### Options

```bash
python fastpath/build.py --base guardian-baseline --head tampered   # defaults shown
python fastpath/build.py --offline      # no network: use .cache only; a cache miss is "not evaluated"
python fastpath/build.py --help
```

`GUARDIAN_OFFLINE=1` has the same effect as `--offline`.

### Requirements

| Need | Version tested | Used for |
|---|---|---|
| Python | 3.12.1 (needs ≥ 3.11.4 for the safe `tarfile` filter) | `fastpath/build.py`, stdlib only |
| git | 2.47 | `git archive`, `git log` |
| Node + npm | 22 / 10 | only `scripts/make_demo_target.sh` (`npm pack`) |
| Bash | Git Bash on Windows | only `scripts/make_demo_target.sh` |
| Internet | api.osv.dev only | vulnerability lookup; optional with `--offline` |

---

## Windows notes (building the demo target)

`scripts/make_demo_target.sh` was written for macOS and Linux. On Windows, run it in **Git Bash**
and watch for three problems:

1. **`python3` opens the Microsoft Store.** Point `python3` at your real Python for this shell:
   ```bash
   mkdir -p ~/bin-shim && printf '#!/bin/sh\nexec python "$@"\n' > ~/bin-shim/python3 && chmod +x ~/bin-shim/python3
   export PATH="$HOME/bin-shim:$PATH"
   ```
2. **Git converts line endings** (`core.autocrlf=true`), which breaks the target's shell
   scripts. Turn that off for this shell only:
   ```bash
   export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.autocrlf GIT_CONFIG_VALUE_0=false
   ```
3. **The last step fails with `mv: … Permission denied`.** VS Code is holding the new folder
   open. Build outside the workspace folder, then move it into place:
   ```bash
   GUARDIAN_TARGET_DIR="$PWD/../_gtarget" bash scripts/make_demo_target.sh
   mv ../_gtarget target
   ```

---

## What you get (`fastpath/out/`)

| File | What it is |
|---|---|
| `guardian.html` | The dashboard: open it in any browser. Works offline, no server |
| `sbom.base.cdx.json` | CycloneDX 1.5 SBOM of `guardian-baseline` (981 packages) |
| `sbom.head.cdx.json` | CycloneDX 1.5 SBOM of `tampered` (982 packages) |
| `sbom.diff.json` | Packages added, removed or changed between the two SBOMs |
| `findings.json` | Every finding with risk, rule, path, commit and evidence, plus counts and metadata |
| `vis-network.min.js` | Graph library (vis-network 9.1.9). Also inlined into `guardian.html` |
| `shot*.png` | Screenshots used to check the page |

### Using the dashboard

- **Top bar.** Shows unique packages (with install paths in brackets), direct, transitive,
  vulnerabilities by severity, and suspicious findings split into *new since baseline* and
  *already present*.
- **Graph colours.** Red = suspicious change; orange = known vulnerability; grey = clean;
  purple boxes = repository files; dashed outline = new or changed since baseline.
- **Graph buttons.**
  - *Focused view* (the default) shows the app, its direct dependencies, the files, and the
    full paths to every suspicious change and every critical vulnerability.
  - *+ all vulnerable paths* adds every orange path.
  - *Whole graph* shows all 1,276 install paths.
- **Click a node** to open its version, origin, direct/transitive, dev/prod, install script,
  dependency path, findings and evidence.
- **Deep links for a demo.** Append one of these to the file URL:
  `#tab=risky`, `#tab=changed`, `#view=all`, `#node=node_modules/lodahs`,
  `#node=file:Dockerfile`.
- **Claim labels.** *verified* = read directly from a file or from OSV. *computed* = derived
  by code (edit distance, size ratio, usage count).

### Re-taking screenshots (optional)

```bash
CH="/c/Program Files/Google/Chrome/Application/chrome.exe"   # or msedge.exe / google-chrome
"$CH" --headless=new --window-size=1700,1050 --virtual-time-budget=10000 \
  --screenshot="$PWD/fastpath/out/shot1.png" "file:///$PWD/fastpath/out/guardian.html#tab=risky"
```

---

## How it works

All of this lives in `fastpath/build.py`. Every step is plain, deterministic code.

1. **Read both refs safely.** `git archive <ref>` is extracted with Python's `tarfile`
   (`filter="data"`) into a temp folder. `./target` is never checked out or modified.
2. **Inventory and SBOM.**
   - `scripts/lockfile_sbom_diff.py` writes the CycloneDX SBOMs and their diff.
   - `package-lock.json` is parsed again for the graph: one node per install path.
   - Edges follow Node.js module resolution: the nearest `node_modules/<dep>`, walking up the
     folders.
   - Breadth-first search from the app gives each node's shortest dependency path.
   - *Direct* means the package is listed in the root `package.json` and installed at the top
     level.
3. **Vulnerabilities.**
   - Registry packages are sent in batches to `POST https://api.osv.dev/v1/querybatch`; each
     advisory is then fetched from `GET /v1/vulns/{id}`.
   - The ID, aliases, severity (`database_specific.severity`) and fixed versions are kept.
   - Responses are cached under `fastpath/.cache/osv/` with their fetch time.
   - On a network failure, the page shows **"not evaluated"**, never zero.
   - Non-registry packages show "not evaluated (non-registry origin)".
   - Dev-only packages are rated one level lower.
4. **Compare the two refs.**
   - A package is *new* if its install path is missing in the base ref.
   - It is *changed* if its version, integrity hash or origin differs.
   - Dockerfile and workflow lines are *new* if that exact line is absent from the base file.
   - The introducing commit is found with `git log -S "<exact text>" base..head -- <file>`.
5. **Suspicious-change rules.** All rules are generic; no package name is hard-coded.

   | Rule | Trigger | Risk |
   |---|---|---|
   | Look-alike name | New name within edit distance 2 (1 if under 6 letters) of another dependency or `guardian/data/popular_npm_names.txt` | high |
   | Non-registry origin | `resolved` is not `https://registry.npmjs.org/…` | medium |
   | Unsafe install script | Install hook present. The script is read as text and checked for env-var reads (secret-like names), hard-coded URLs, network/process APIs, temp-dir writes and code files over 20 KB | 2+ signals → critical, else high |
   | Suspicious update | The new version adds an install hook, or its tarball grows 2× or more | high |
   | Unexpected dependency | A new `require()` of a new package whose variable is never used | medium |
   | Untrusted image | `FROM` without `@sha256:`; floating tag; changed since base | high / medium / low |
   | Unpinned CI component | `uses:` not pinned to a 40-char SHA (OSV is also checked for the action) | high if new third-party, medium third-party, low first-party |
   | Unsafe CI pattern | `permissions: write-all`, or `curl`/`wget` piped to a shell | high |
   | Lockfile drift | Dockerfile runs `npm install`/`npm update` instead of `npm ci` | low |

6. **Findings.** Same file + same type are merged into one finding (highest risk kept, all
   evidence lines kept). Everything is written to `findings.json` and inlined into
   `guardian.html`, from the template in `fastpath/template.html`.

---

## Results on the demo target

These are measured against `demo/ground_truth.yaml`.

| Ground truth | Expected | Result |
|---|---|---|
| GT-C1 | look-alike name `lodahs` | detected, high, commit `431ac1d` |
| GT-C2 | unsafe install script in `lodahs` | detected, critical (3 signals) |
| GT-C3 | unexpected dependency (`strutil` never used) | detected, medium |
| GT-C4 | Dockerfile `node:18.13.0` → `node:18` | detected, high, commit `a8de0f9` |
| GT-C5 | `tj-actions/changed-files@v45` unpinned | detected, high, commit `52e2fa6`; OSV lists 2 advisories |
| GT-C6 | `write-all` + `curl \| bash` | detected, high |
| GT-C7 | `guardian-demo-strfmt` 1.0.0 → 1.0.1 | detected: new preinstall hook (critical) and suspicious update (5.1× size), commit `05b9d85` |
| GT-P1, GT-P2 | preexisting `snyk/actions@master`, `npm update` in Dockerfile | detected, marked "already present" |
| GT-N1..N3 | must not flag lodash as a look-alike, strfmt 1.0.0, or checkout as malicious | not flagged |

These detectors were written with the planted risks known, so this table shows that they
work. It does not measure how well they generalise. The honest measure is the hold-out seeds
in `demo/ground_truth.yaml` plus a run on a second application; neither has been done yet.

---

## Safety

- `./target` is only read, through `git archive`. Nothing is checked out, installed or executed.
- Package archives are opened as data; their scripts are read as text, never run.
- The only network calls go to `api.osv.dev`. Nothing is published or pushed.
- No credentials are used. OSV needs no API key.

## Known limitations

- **npm only.** Packages come from `package-lock.json` v2/v3. Other ecosystems need their own
  lockfile parser. The Docker and CI rules work for any repo.
- **The target path is fixed.** The script always reads `./target` (a git repo containing
  both refs). To scan another app, place its repo there.
- **Registry install scripts are not opened.** Doing so would mean downloading the tarball, so
  they are reported as "content not inspected" at medium risk.
- **Bundled packages** (no `resolved` field, e.g. inside `nyc`) are not matched against OSV
  and show "not evaluated".
- **Vulnerability counts** are advisory × package pairs; there are 217 unique advisories.
- **Severity** here is OSV's GitHub-advisory severity. Reachability, EPSS and KEV are added by
  `python -m guardian prioritise` (Day 2), not by the fast path.
- **The dependency path shown is the shortest one.** A package may also be reachable by
  longer routes.
- **Static text rules can be evaded** by obfuscated code. The size-growth and large-file rules
  are the backstop.
- **The Docker image is not built and its layers are not scanned.** Only the Dockerfile is
  read.

## Files

```
fastpath/
  build.py         the pipeline (stdlib only)
  template.html    dashboard template; build.py inlines the data and vis-network into it
  README.md        this file
  out/             generated outputs (see above)
  .cache/osv/      cached OSV responses (git-ignored)
scripts/lockfile_sbom_diff.py   CycloneDX SBOM + SBOM diff (reused)
scripts/make_demo_target.sh     builds ./target with the planted risks
demo/ground_truth.yaml          what is planted, for checking results
```
