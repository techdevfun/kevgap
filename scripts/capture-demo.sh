#!/usr/bin/env bash
# Capture the demo transcript from the REAL CLI (no hand-edited output).
# The audit/check/diff steps run on the REAL bundled KEV snapshot
# (catalog 2026.11.24, 1,795 entries) with the GT13 example inventory.
# The baseline is produced by a real audit run in this script, with the
# date pinned to 2026-11-18 so the diff shows a real growing window.
# Runs from inside the scratch dir with relative paths, so the
# transcript never contains the builder's absolute paths.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH=/tmp/kevgap-demo
BIN="$SCRATCH/bin"
rm -rf "$SCRATCH"
mkdir -p "$BIN" "$ROOT/demo"
ln -sf "$ROOT/dist/cli.js" "$BIN/kevgap"
chmod +x "$ROOT/dist/cli.js"
export PATH="$BIN:$PATH"

OUT="$ROOT/demo/transcript.txt"
BASELINE="$SCRATCH/baseline.json"
cd "$ROOT"
{
  echo "# kevgap demo - real CLI output"
  echo "# (audit runs on the REAL bundled KEV snapshot: catalog 2026.11.24,"
  echo "#  1,795 entries; inventory is examples/gt13-inventory.json;"
  echo "#  the baseline below is produced by a real audit run)"
  echo ""
  echo "$ kevgap init demo-estate"
  (cd "$SCRATCH" && kevgap init demo-estate)
  echo ""
  echo "$ kevgap audit examples/gt13-inventory.json"
  kevgap audit examples/gt13-inventory.json || echo "exit: $?"
  echo ""
  echo "$ kevgap check examples/gt13-inventory.json"
  kevgap check examples/gt13-inventory.json || echo "exit: $?"
  echo ""
  echo "$ KEVGAP_TODAY=2026-11-18 kevgap audit examples/gt13-inventory.json --save-baseline baseline.json > /dev/null"
  KEVGAP_TODAY=2026-11-18 kevgap audit examples/gt13-inventory.json --save-baseline "$BASELINE" > /dev/null || echo "exit: $?"
  echo "(baseline receipt written, $(wc -c < "$BASELINE") bytes)"
  echo ""
  echo "$ kevgap diff --baseline baseline.json examples/gt13-inventory.json"
  kevgap diff --baseline "$BASELINE" examples/gt13-inventory.json || echo "exit: $?"
  echo ""
  echo "$ kevgap explain CVE-2026-16232"
  kevgap explain CVE-2026-16232
} > "$OUT" 2>&1

echo "transcript written: $OUT ($(wc -l < "$OUT") lines)"
