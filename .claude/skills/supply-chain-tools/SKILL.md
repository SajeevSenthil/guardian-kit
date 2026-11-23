---
name: supply-chain-tools
description: Which open-source supply-chain security tools and public data sources Guardian uses, what each is for, starting-point commands, and the rule that every command must be verified on this machine before a wrapper is written. Use when installing, probing or wrapping syft, grype, osv-scanner, trivy, hadolint, zizmor, guarddog, conftest, cosign, semgrep, or calling OSV, EPSS, KEV, npm registry or deps.dev.
---

# Supply-chain tools

**Status of everything below: starting points, not verified.** The kit was written in a sandbox
with no network, so none of these tools was executed (see
`docs/research/02-tool-verification.md`, which also holds field names read from the tools' source
code). Before using any command: run `<tool> --help`, run it on `./target`, and record the truth
in `docs/tool-notes/<tool>.md` (use the `tool-probe` subagent). If a note exists, trust the note
over this file.

## What each tool is for

Required: **syft, grype, osv-scanner, docker**. Everything else is optional extra evidence;
install it only if that takes under five minutes, and never make a requirement depend on it.

| Need (brief item) | Primary | Backup | Our own code must also |
|---|---|---|---|
| SBOM, CycloneDX (D1-2) | syft | @cyclonedx/cyclonedx-npm, cdxgen, `scripts/lockfile_sbom_diff.py` | add dependency edges if the generator omits them |
| Dependency paths (D1-2, D1-3) | lockfile walk (ours) | `npm ls --all --json --package-lock-only` | `npm explain` needs node_modules: do not rely on it |
| Known vulnerabilities (D1-3) | grype on the SBOM | osv-scanner on the lockfile; OSV API | merge aliases CVE/GHSA |
| Exploitability (D2-1) | EPSS API, CISA KEV feed | grype output may already carry EPSS/KEV | cache; unknown if offline |
| Malicious package / install script (D1-4) | our capability profile | guarddog | recompute from the tarball, never trust lockfile flags alone |
| Typosquat (D1-4) | ours | guarddog `typosquatting` rule | popular-name list bundled locally |
| Dockerfile / image (D1-2, D1-4) | ours | hadolint, trivy config, grype on image | flag floating tag / no digest / pipe-to-shell |
| CI workflows (D1-2, D1-4) | ours + zizmor | — | SHA-pin check, write-all, curl-pipe-bash, known-compromised lookup |
| Reachability (S-1) | our import graph | semgrep | witness file:line as evidence |
| Policy gate (S-5) | conftest (OPA, Rego v1) | — | `conftest verify` for policy tests |
| Provenance (S-3) | cosign verify | `npm audit signatures` | report unsigned / unknown honestly |
| Fix candidates (D2-3) | ours | `osv-scanner fix` (experimental), `npm audit fix --dry-run` | always dry-run in a throwaway clone |

## Starting-point commands (verify each)

```bash
# SBOM
syft dir:target -o cyclonedx-json=sbom.cdx.json
syft <image:tag> -o cyclonedx-json=image.cdx.json
npx --yes @cyclonedx/cyclonedx-npm --package-lock-only --output-file sbom.cdx.json   # run inside target

# Vulnerabilities
grype sbom:sbom.cdx.json -o json > grype.json
osv-scanner scan source --lockfile target/package-lock.json --format json > osv.json
trivy fs --scanners vuln --format json target > trivy.json
trivy config --format json target > trivy-config.json

# Dockerfile, workflows
hadolint -f json target/Dockerfile
zizmor --format json target/.github/workflows

# Malicious-package heuristics (never executes the package; needs its sandbox or --no-sandbox)
guarddog npm scan <package-dir-or-tarball> --output-format=json

# Policy
conftest test --policy policy --output json runs/<id>/policy-input.json
conftest verify --policy policy

# Provenance (exact identities in docs/research/04 section 6.2)
cosign verify <image> --certificate-oidc-issuer <issuer> --certificate-identity <identity>
```

Public data (read-only lookups; cache every response under `.cache/` with fetch time):

```text
POST https://api.osv.dev/v1/query            {"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.4"}
POST https://api.osv.dev/v1/querybatch       {"queries":[ ... ]}
GET  https://api.first.org/data/v1/epss?cve=CVE-2019-10744
GET  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
GET  https://registry.npmjs.org/<name>       (packument: time, maintainers, dist.integrity, scripts)
GET  https://api.npmjs.org/downloads/point/last-week/<name>
GET  https://api.deps.dev/v3/systems/npm/packages/<name>/versions/<version>
```

## Rules

- Only ever point tools at `./target`, images built from it, or public metadata endpoints.
- Run every tool through `guardian/tools/proc.py`; record version + command + output hash as
  evidence.
- Pin tool versions in `tools.lock`; print them in the report. Our own toolchain is part of the
  supply chain (a scanner's GitHub Action was itself compromised in 2026; see research 03).
- Do not send whole scanner outputs to a model. Summarise in code first.
- A scanner disagreeing with another scanner is information: keep both sources on the finding.
- Scanner databases and the KEV feed must be downloaded before the demo (`guardian doctor`
  shows their age).
- Never execute a scanned package. `guarddog` and our capability profile are static.
