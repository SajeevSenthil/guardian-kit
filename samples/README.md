# Samples

Small real outputs captured while the kit was being written (offline sandbox, npm built-ins and
`scripts/lockfile_sbom_diff.py` only; no third-party scanner could be run).

- `sbom-diff-*.json` were regenerated after the final demo target was built (with the
  `guardian-demo-strfmt` seed) and match the current `scripts/make_demo_target.sh`.
- The other files were captured one seed earlier (before `guardian-demo-strfmt` was added), so
  package counts in them and in `docs/research/02-tool-verification.md` are lower by one.
  They are shape examples, not expected values. Phase 0 replaces them with fixtures from real
  tools under `tests/fixtures/`.
