# Known limitations

Add to this file the moment a limitation is discovered. Frank limitations are a deliverable
and score better than a judge finding them.

## Known before the build started

- **Tool commands were not verified when the kit was written.** The authoring sandbox had no
  network access, so no scanner was installed or run and no public API was called. Phase 0
  exists to fix this. See `docs/research/02-tool-verification.md`.
- **The demo target's container build was not tested.** `guardian/smoke-test.sh` and the full
  `npm ci` of goof (about 980 packages) could not be run. Phase 0 step 4 tests them first.
- **The seeded packages were tested only in isolation.** The lockfile entries for `lodahs` and
  `guardian-demo-strfmt` install correctly with `npm ci --offline` in a pruned project (install
  scripts ran, `require()` works, a corrupted hash gives EINTEGRITY), not yet in the full tree.
- **The seeded packages say they are harmless** in their own comments and descriptions (so
  anyone who finds the files knows what they are). Agents and detectors must not treat that
  self-description as evidence; two tests check this.
- **The scorecard's seeded entries are what the detectors were developed against.** Only the
  hold-out seeds (phase 7) and the second application say anything about generality.
- **A checked quote is not a checked conclusion.** For AI claims, code confirms that the cited
  text exists in the evidence, not that the conclusion follows from it. That is why AI claims
  are never shown as facts.
- **The safety hook is a guard rail, not a boundary.** It was tested standalone against 25
  commands, not inside a live Claude Code session. The real protections are no git remote and
  no credentials.
- **goof ships no unit tests.** Its `npm test` is `snyk test` (needs a token). "Run unit and
  integration tests" is covered by our smoke test; say so.
- **npm only.** Design allows other ecosystems; none is implemented.
- **Reachability is a heuristic** (import graph + symbol references), not a call graph. npm
  advisories rarely carry function-level data in structured form.
- **Starter Rego policies are untested**, and the bundled popular-package list was written
  from general knowledge, not from download statistics.
- **`scripts/setup_tools.sh` relies on Homebrew** for the scanner binaries; without it, install
  from each tool's release page.
- **Research notes contain unverified items**, each marked in the note.

## Found during the build

- _(add here)_
