# 02 - Tool verification (hands-on, 2026-11-23)

## Read this first

**None of the eleven third-party tools could be installed in the verification sandbox, and none
of the five public APIs could be called.** The sandbox's egress policy only lets `git clone` /
`git ls-remote` of public GitHub repos through. Everything this document says about syft, grype,
osv-scanner, trivy, guarddog, hadolint, zizmor, conftest, cosign, semgrep and cyclonedx-npm is
therefore **not a run result**. It is labelled one of:

- **OBSERVED** - I ran it here and saw the output.
- **SOURCE** - read from the tool's own repo (shallow clone of the default branch on 2026-11-23). Reliable for flag
  names, rule names and JSON field names; says nothing about runtime, counts, or whether a rule
  really fires on our files.
- **NOT RUN** - nothing verified. Must be run on a machine with normal internet before a wrapper
  is trusted.

What was verified by running: npm's own commands on both branches, the `lodahs` install
behaviour (on a pruned lockfile, not the full tree), EINTEGRITY behaviour (same caveat), the
demo-target script's tarball determinism, and a stdlib fallback SBOM + diff script written
because no SBOM tool was available.

Environment: Ubuntu 24.04, node v22.23.5, npm 10.9.9, Python 3.13.18, go 1.24.7, docker CLI
present but no daemon. Work dir: `<scratchpad>/sim` (local clones of the three target branches).
Target commits: `baseline` 0e2a166, `tampered` 62999c1, `tampered-integrity` 3647651.

---

## 1. Install attempts (all failed)

| Route tried | Result (OBSERVED) |
|---|---|
| GitHub release binaries (`github.com/<repo>/releases/latest`) for syft, grype, osv-scanner, trivy, hadolint, conftest, cosign | HTTP 403 for all seven |
| `gh api repos/<repo>/releases/latest` | 403, "GitHub access to this repository is not enabled for this session" |
| `pip download zizmor` / `hadolint-bin` (PyPI) | `Failed to resolve 'pypi.org'`; forced through the proxy: `CONNECT tunnel failed, response 403` |
| `npm view` / `npm ci` (npm registry) | `getaddrinfo ENOTFOUND registry.npmjs.org` |
| Go module proxy, crates.io, vendor download hosts, container registries, apt, nix cache | no HTTP response |
| `docker info` | no daemon (`/var/run/docker.sock` missing), so no container-image route either |

Per-host detail: `samples/network-probe-observed.txt`. I stopped after these two independent
routes per tool (release binary, language registry) as instructed.

Not installed: **syft, grype, osv-scanner, trivy, guarddog, hadolint, zizmor, conftest, cosign,
semgrep, @cyclonedx/cyclonedx-npm, cdxgen** (all of them). No `--version` output exists.

Latest release tags, from `git ls-remote --tags` (OBSERVED, useful for pinning):

| Tool | Latest tag seen | Install command to try (NOT RUN) |
|---|---|---|
| syft | v1.57.2 | `curl -sSfL https://get.anchore.io/syft \| sh -s -- -b ./bin v1.57.2` |
| grype | v0.122.1 | `curl -sSfL https://get.anchore.io/grype \| sh -s -- -b ./bin v0.122.1` |
| osv-scanner | v2.7.1 | release binary `osv-scanner_linux_amd64`, or `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.1` |
| trivy | v0.76.2 | release tarball `trivy_0.76.2_Linux-64bit.tar.gz` |
| hadolint | v2.15.1 | release binary `hadolint-linux-x86_64` (asset name unverified for this version) |
| conftest | v0.71.1 | release tarball |
| cosign | v3.1.4 | release binary `cosign-linux-amd64` |
| guarddog | v3.2.0 | `pip install guarddog` |
| semgrep | v1.186.0 | `pip install semgrep` |
| zizmor | not determined (tag listing only returned sub-crate tags) | `pip install zizmor` |
| cyclonedx-npm | v7.0.1 | `npm i -g @cyclonedx/cyclonedx-npm` |

Asset file names above are from memory, not checked against these releases.

---

## 2. What ran: npm built-ins (OBSERVED)

### `npm ls --all --json --package-lock-only`

```
cd <target>; npm ls --all --json --package-lock-only > npm-ls.json
```

- Works with no `node_modules` and no network. Exit 0, wall 0.40 s (baseline), 0.45 s (tampered). Output ~352 KB.
- Top-level keys: `version`, `name`, `dependencies`. No `problems` key on either branch.
- Each node: `.dependencies.<name>.version`, `.resolved`, `.overridden`, and nested `.dependencies` (recursive).
  Registry packages carry `resolved` (948 nodes); nodes without it are deduped references.
- Baseline: 35 direct deps, 1931 tree nodes, 980 unique name@version. Tampered: 36 / 1932 / 981.
- `lodahs` appears as `.dependencies.lodahs = {version: "4.17.21", resolved: "file:<ABSOLUTE path>/vendor/lodahs-4.17.21.tgz", overridden: false}`.
  **Gotcha:** npm rewrites the relative `file:vendor/...` to an absolute path here. The lockfile keeps the relative form.
- No `dev`/`hasInstallScript`/`integrity` in this output; read those from `package-lock.json`.
- Sample: `samples/npm-ls-tampered.trimmed.json`.

### `npm explain <pkg>`

- **Gotcha: needs an installed `node_modules`.** With only a lockfile, `npm explain lodahs --package-lock-only`
  and `npm explain minimist --package-lock-only` both fail: `npm error No dependencies found matching <pkg>`
  (`--json` gives `{"error":{"summary":...}}`). The flag is ignored.
- After `npm ci` (pruned project, see section 3) it works: `npm explain lodahs --json` returns an array;
  per item `name`, `version`, `location`, `dependents[].{type, name, spec, from.location}`, `dev`, `optional`, `bundled`, `overridden`.
  Follow `dependents[].from` recursively for the path to root. Sample: `samples/npm-explain-lodahs.json`.
- Consequence: for dependency paths before install, walk the `npm ls` JSON or the lockfile yourself
  (`scripts/lockfile_sbom_diff.py` builds the edges, see section 4). Not verified on a transitive package with an installed tree.

### Lockfile facts (read directly from `package-lock.json`)

| | baseline | tampered |
|---|---|---|
| `lockfileVersion` | 2 (has both `packages` and legacy `dependencies`) | 2 |
| `packages` entries (excl. root) | 1274 | 1275 |
| `resolved` on registry.npmjs.org / absent / other | 948 / 326 / 0 | 948 / 326 / 1 (`file:vendor/lodahs-4.17.21.tgz`) |
| `hasInstallScript` | core-js, fsevents, kerberos, nodemon | + lodahs |
| integrity sha512 / sha1 / none | 532 / 416 / 326 | 533 / 416 / 326 |
| `dev: true` entries | 563 | 563 |

Gotchas for the demo narrative: the baseline already has four packages with install scripts, 326
entries with no `resolved`/`integrity`, `method-override` and `morgan` requested as `latest`, and
several workflows using `snyk/actions/setup@master` and `@v1/@v2/@v3` tags. A detector that
reports absolute state will be noisy on baseline; report the **diff**.

---

## 3. Tampered branch install checks

### OBSERVED (pruned project only)

The full tree cannot be installed here (registry unreachable, cache empty), so I copied the
tampered `package.json`/`package-lock.json`, kept only the root entry and the three hand-written
`lodahs` entries verbatim (`packages[""].dependencies.lodahs`, `packages["node_modules/lodahs"]`,
legacy `dependencies.lodahs`), copied `vendor/lodahs-4.17.21.tgz`, and ran:

| Command | Result |
|---|---|
| `npm ci --offline --no-audit --no-fund` | exit 0, `added 1 package`, 0.22 s. `/tmp/guardian-demo-postinstall.txt` rewritten (mtime 07:41 -> 07:54, content "DEMO: postinstall executed at 2026-11-23T07:54:12.588Z ..."). `require('lodahs').trim('  hi  ')` returns `"hi"`. |
| `npm ci --offline --no-audit --no-fund --ignore-scripts` (fresh copy) | exit 0, marker mtime unchanged (script skipped), `require('lodahs')` works. |
| same with `integrity` set to `sha512-AAAA...==` | `npm error code EINTEGRITY ... wanted sha512-AAAA... but got sha512-YxXxT8/...` after two "seems to be corrupted" warnings. |

So npm 10.9.9 accepts the hand-written lockfile entry shape and enforces integrity on `file:` tarballs.
Transcript: `samples/npm-ci-observed.txt`.

### NOT VERIFIED

- **`npm ci` on the full tampered tree.** Failed with `ENOTFOUND registry.npmjs.org` / `ENOTCACHED`
  on the first registry package (nyc 11.9.0), before lodahs was reached. Whether npm accepts the
  entry inside the full v2 lockfile (for example key ordering, the legacy `dependencies` section)
  is still open, although the pruned test makes rejection unlikely.
- **`tampered-integrity` branch produces EINTEGRITY.** Same failure (`ENOTCACHED` first). The branch
  changes lodash 4.17.4 `integrity` from `sha1-eCA6TRwyiuHYbcpkYONptX9AVa4=` to
  `sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=` in both lockfile sections (OBSERVED via git diff). The
  EINTEGRITY result above is for a sha512 hash on a `file:` tarball, not a sha1 hash on a registry
  tarball. Note a warm npm cache keyed by the real hash may change the error path; test with a clean cache.
- **`docker build`**: `failed to connect to the docker API at unix:///var/run/docker.sock`. CLI and
  compose v5.7.1 are present, daemon is not. `guardian/smoke-test.sh` cannot run here.

### Script changes

**No fix was made to `scripts/make_demo_target.sh`**; nothing observed required one.
`npm pack` of `demo/packages/lodahs` is byte-deterministic (two packs one second apart and the
committed tarball all have sha256 `756ab98ca00d84b3...`), so the hand-computed integrity is stable.

---

## 4. SBOM and SBOM diff

No SBOM tool was available, so I added **`scripts/lockfile_sbom_diff.py`** (stdlib, offline):

```
python3 scripts/lockfile_sbom_diff.py sbom <project-dir> > sbom.cdx.json     # 0.06 s
python3 scripts/lockfile_sbom_diff.py diff old.cdx.json new.cdx.json > diff.json
```

OBSERVED:

| | baseline | tampered | tampered-integrity |
|---|---|---|---|
| components (unique purl) | 980 | 981 | 981 |
| `dependencies[]` nodes / edges | 981 / 1647 | 982 / 1648 | 982 / 1648 |

- Output is CycloneDX-1.5-shaped: `components[].{bom-ref, name, version, purl, scope, properties[]}`,
  `dependencies[].{ref, dependsOn[]}`, root at `metadata.component`. Edges come from Node resolution
  over lockfile paths. **Not validated against the CycloneDX schema** and not compared with syft output.
- Custom properties: `guardian:resolved`, `guardian:registrySource`, `guardian:hasInstallScript`,
  `guardian:integrity`, `guardian:dev`, `guardian:lockPath`.
- baseline -> tampered diff (`samples/sbom-diff-baseline-vs-tampered.json`): exactly one added
  component, `pkg:npm/lodahs@4.17.21`, `resolved: "file:vendor/lodahs-4.17.21.tgz"`,
  `introducedBy: ["pkg:npm/goof@1.0.1"]`, flags `non-registry-source`, `install-script`,
  `name-resembles:lodash`. Nothing removed.
- tampered -> tampered-integrity diff (`samples/sbom-diff-tampered-vs-integrity.json`): no added or
  removed components; `changedSamePurl` reports `pkg:npm/lodash@4.17.4` `guardian:integrity`
  `sha1-eCA6...` -> `sha1-AAAA...`. Same version with a different hash is the tamper signal.
- The `name-resembles` flag only compares against names already in the old SBOM (one edit or one
  adjacent swap). It is not a popularity-based typosquat check.
- The diff half keys on `purl`, so it should accept syft or cyclonedx-npm output, but the
  `resolved`/install-script flags depend on the `guardian:*` properties. NOT RUN against real tool output.

Open questions that stay open (NOT RUN): whether syft's directory scan emits a `dependencies`
section for npm lockfiles, its component count, whether it records `file:` resolved sources, and
whether cyclonedx-npm gives a better graph (it needs an installed tree by default).

---

## 5. Per-tool notes for tools that did not run

All commands below are **NOT RUN**. Flag and field names marked SOURCE were read from the repo.

### syft
- Intended: `syft dir:<target> -o cyclonedx-json=sbom.cdx.json`. Nothing verified.

### grype
- Intended: `grype sbom:sbom.cdx.json -o json > grype.json`. Needs its DB download (`grype.anchore.io`, unreachable here).
- SOURCE (`grype/presenter/models`): document keys `matches[]`, `ignoredMatches`, `source`, `distro`, `descriptor`.
  Per match: `vulnerability`, `relatedVulnerabilities[]`, `matchDetails[]`, `artifact`.
  `vulnerability.fix.{versions[], state, available[].{version,date,kind}}`, `vulnerability.advisories[].{id,link}`,
  `vulnerability.risk` (float), plus metadata fields `severity`, `namespace`, `dataSource`, `cvss[]`, `cwes[]`,
  `epss[].{cve, epss, percentile}`, `knownExploited[].{cve, dateAdded, knownRansomwareCampaignUse, ...}`,
  `matchDetails[].fix.suggestedVersion`.
  So EPSS and KEV are in the JSON model; whether they are populated for our findings is unverified.

### osv-scanner v2
- Intended: `osv-scanner scan source -r <target> --format json --output-file osv.json`;
  `osv-scanner fix --non-interactive --strategy=in-place -L package-lock.json` (or `--strategy=relax -M package.json`).
- SOURCE: `scan source` flags include `--lockfile/-L`, `--sbom`, `--recursive`, `--format`, `--output-file`, `--offline`,
  `--offline-vulnerabilities`, `--download-offline-databases`, `--local-db-path`, `--call-analysis`, `--all-packages`, `--licenses`.
  `fix` flags: `--manifest`, `--lockfile`, `--strategy`, `--non-interactive`, `--data-source` (`deps.dev` default, or `native`),
  `--apply-top`, `--no-introduce`, `--upgrade-config`, `--max-depth`, `--min-severity`, `--vulns`, `--ignore-vulns`,
  `--ignore-dev`, `--offline-vulnerabilities`, `--download-offline-databases`, `--local-db-path`.
- Offline: `fix` has offline *vulnerability* flags, but its default dependency data source is `api.deps.dev:443`
  (gRPC) and `native` uses the registry. Expect it to need network for resolution. Unverified; proposals unknown.

### trivy
- Intended: `trivy fs --format json --scanners vuln <target>`; `trivy config --format json <target>/Dockerfile`. Nothing verified.

### hadolint
- Intended: `hadolint -f json Dockerfile` (add `--no-fail` so findings do not fail the wrapper).
- SOURCE (README rule table): `DL3007` (Warning) "Using latest is prone to errors..." is the rule that should flag
  `FROM node:latest`. `DL3006` covers untagged images. Flags `-f/--format`, `--no-fail`, `-t/--failure-threshold` exist. Firing on our file unverified.

### zizmor
- Intended: `zizmor --format=json .github/workflows/` (offline by default with no token); add `--gh-token` for online audits.
- SOURCE (docs): JSON is a flat array; per finding `ident`, `desc`, `url`, `determinations.{confidence,severity,persona}`,
  `locations[].symbolic.{key.Local.verbatim_path, annotation, route}`. JSON line numbers are 0-based (key `row`).
  Exit codes: 0 none, 1 error, 2 args, 3 no inputs, 11/12/13/14 = highest finding informational/low/medium/high.
  So a wrapper must not treat non-zero as failure.
- Relevant audits that exist: `unpinned-uses`, `excessive-permissions`, `known-vulnerable-actions` (**does not work offline**,
  needs a GitHub token and GHSA access), `impostor-commit`, `stale-action-refs`, `ref-confusion`, `forbidden-uses`, `typosquat-uses`,
  `unpinned-tools`, `adhoc-packages`.
- **Caution:** `GH_TOKEN`/`GITHUB_TOKEN` in the environment silently switch zizmor to online mode. Pass `--offline` for determinism.
- I found no audit that names `curl | bash` in `run:` steps; assume it is **not** flagged. Unverified.

### guarddog (v3.x)
- Intended: `guarddog npm scan <dir-or-tgz> --output-format=json`; `guarddog npm verify <path/to/package.json> --output-format=json`.
- SOURCE: source rules are now YARA files, not semgrep. `threat-npm-preinstall-script.yar` matches only `"preinstall"`.
  `threat-process-hooks.yar` includes `"postinstall"` and `node <file>.js` strings, so it is the candidate for our
  `postinstall: node scripts/setup.js` (rule condition not fully read; firing unverified).
  Typosquat detector uses Levenshtein distance 1 and adjacent swaps against a bundled `top_npm_packages.json` that
  contains `lodash`; "lodahs" is an adjacent swap, so it should match if the detector runs for local scans (unverified;
  the list can also refresh over the network). JSON result shape: `{issues, errors, results, path}`; `verify` returns
  a list of `{dependency, version, result}`.
- `npm verify` resolves each dependency against the registry and logs "Package/Version ... not on NPM" on failure.
  Expect the `file:` lodahs dependency to be skipped or errored, not scanned. Scan the tarball directly instead.
- An attempt to import guarddog's typosquat module from the clone and call it was blocked by the sandbox permission
  system, so even that logic is unexecuted.

### semgrep, conftest, cosign, cyclonedx-npm, cdxgen
- Nothing verified. Stand-in for the semgrep call-site check (OBSERVED, plain grep on tampered):
  `routes/index.js:20: var _ = require('lodash');`, `routes/index.js:21: var strutil = require('lodahs');`,
  `routes/index.js:361: _.merge(message, req.body.message, {` (the prototype-pollution sink for lodash 4.17.4).

---

## 6. Public APIs (all NOT RUN)

| API | Request that was to be sent | Observed |
|---|---|---|
| OSV | `POST https://api.osv.dev/v1/query` `{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.4"}` | `CONNECT tunnel failed, response 403` |
| EPSS | `GET https://api.first.org/data/v1/epss?cve=CVE-2019-10744` | no response |
| CISA KEV | `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | no response |
| deps.dev v3 | `GET https://api.deps.dev/v3/systems/npm/packages/lodash/versions/4.17.4` and project scorecard | no response |
| npm registry / downloads | `GET https://registry.npmjs.org/lodahs`, `https://api.npmjs.org/downloads/point/last-week/lodash` | DNS failure / no response |

No response shapes were captured. Whether a public `lodahs` package exists on npm, its creation
date, and whether OSV carries function-level `ecosystem_specific` data for lodash are **unknown**.
If a public `lodahs` exists, registry-based tools may describe that package rather than our local tarball.

---

## 7. Detection coverage matrix

Only the first two columns are observed. Legend: **CAUGHT** = observed here. *expected* / *unlikely* =
prediction from source or docs, not run. `?` = no basis.

| Seeded item | `lockfile_sbom_diff.py` (OBSERVED) | grep/stdlib (OBSERVED) | syft+grype | osv-scanner | trivy | hadolint | zizmor | guarddog | semgrep |
|---|---|---|---|---|---|---|---|---|---|
| Unexpected new dependency `lodahs` | CAUGHT (added) | - | *expected* via SBOM diff, if syft lists file: deps | ? | ? | - | - | - | - |
| Non-registry source (`file:` tarball) | CAUGHT | CAUGHT (lockfile `resolved`) | ? | ? | ? | - | - | *unlikely* (direct-URL rule lists http/git schemes) | - |
| Look-alike name (lodahs vs lodash) | CAUGHT (vs existing names only) | - | - | - | - | - | - | *expected* (`typosquatting`) | - |
| Install script (postinstall) | CAUGHT (`hasInstallScript`) | CAUGHT | - | - | - | - | - | *expected* (`threat-process-hooks`) | - |
| Install script content (env read, collector URL) | missed | not attempted | - | - | - | - | - | ? | ? |
| `FROM node:latest` | - | CAUGHT (`Dockerfile:2`) | - | - | ? (`trivy config`) | *expected* DL3007 | - | - | - |
| Unpinned action `tj-actions/changed-files@v45` | - | CAUGHT (line listed, no judgement) | - | - | - | - | *expected* `unpinned-uses` | - | - |
| Known-compromised action (CVE-2025-30066) | - | missed | - | ? | ? | - | *expected only online* (`known-vulnerable-actions`) | - | - |
| `permissions: write-all` | - | CAUGHT (line listed) | - | - | - | - | *expected* `excessive-permissions` | - | - |
| `curl ... \| bash` in workflow | - | CAUGHT (regex) | - | - | - | - | *unlikely* | - | ? (custom rule) |
| Lockfile integrity change (lodash) | CAUGHT (`changedSamePurl`) | - | ? | ? | ? | - | - | - | - |
| Known CVEs in baseline deps (lodash 4.17.4, adm-zip 0.4.7, marked 0.3.5, mongoose 4.2.4, st 0.2.4, ...) | missed (no vuln data) | - | *expected* | *expected* | *expected* | - | - | - | - |
| Reachability (`_.merge` on request body) | - | CAUGHT by regex only | - | ? (`--call-analysis` is Go/Rust oriented) | - | - | - | - | *expected* |

## 8. Gaps that need custom code

1. **Dependency paths without `node_modules`**: `npm explain` does not work lockfile-only. Walk `npm ls` JSON or the
   edges from `lockfile_sbom_diff.py`.
2. **Non-registry `resolved` and same-version integrity change**: done in `lockfile_sbom_diff.py` against a baseline.
   Checking integrity against the registry (no baseline) needs `registry.npmjs.org/<pkg>/<ver>` `.dist.integrity`; not built.
3. **Install-script diff**: `hasInstallScript` set-difference is done; inspecting script content is not.
4. **Typosquat against a popularity list**: current check is only against names already in the project.
5. **`curl | bash` in workflow `run:` steps**: regex or a semgrep/conftest rule.
6. **Known-compromised actions offline**: a local deny-list (tj-actions/changed-files, reviewdog/action-setup) or OSV
   GitHub Actions ecosystem lookup; zizmor needs a token for this.
7. **Baseline noise suppression**: diff-first reporting, since baseline already has install scripts, `latest` ranges and `@master` actions.
8. **EPSS/KEV enrichment and prioritisation**: field names known for grype JSON, nothing fetched.
9. **Validation loop** (`npm ci`, docker build, smoke test, rescan): untested end to end here.

## 9. To finish this verification on a networked machine

Run in order and replace the NOT RUN / *expected* cells: tool installs + `--version`; `npm ci` on full `tampered`
(with and without `--ignore-scripts`) and on `tampered-integrity` with a clean cache; syft + grype on both branches;
`osv-scanner scan source` and `fix`; trivy; hadolint; zizmor with `--offline` and with a token; guarddog on
`vendor/lodahs-4.17.21.tgz`; the five API calls; `npm view lodahs`.
