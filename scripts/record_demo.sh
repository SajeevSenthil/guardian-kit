#!/usr/bin/env bash
# Freeze a run's human-readable and machine-readable outputs into demo/recorded/final/<run_id>/
# so the demo has a fallback when the live system misbehaves. Copies files only.
# Usage: scripts/record_demo.sh [run_id]   (default: the latest run)
set -euo pipefail
KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="${1:-$(ls -d "$KIT"/runs/2*/ 2>/dev/null | sort | tail -1 | xargs -n1 basename)}"
SRC="$KIT/runs/$RUN"
[ -f "$SRC/run.json" ] || { echo "no run $RUN under $KIT/runs" >&2; exit 2; }
[ -d "$SRC/report" ] || { echo "run $RUN has no report yet: python -m guardian report" >&2; exit 2; }
DST="$KIT/demo/recorded/final/$RUN"
mkdir -p "$DST"
cp "$SRC"/run.json "$SRC"/audit.jsonl "$DST"/ 2>/dev/null || true
cp -r "$SRC"/report "$DST"/
for d in plans approvals validation decisions; do
  [ -d "$SRC/$d" ] && mkdir -p "$DST/$d" && find "$SRC/$d" -maxdepth 1 -name '*.json' -exec cp {} "$DST/$d/" \; || true
done
[ -f "$SRC/plans" ] || cp "$SRC"/plans/*.patch "$DST/plans/" 2>/dev/null || true
cp "$KIT/fastpath/out/guardian.html" "$DST/dashboard.html"
echo "recorded $RUN -> ${DST#$KIT/}"
ls "$DST"
