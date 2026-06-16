#!/usr/bin/env bash
#
# test-floor.sh — Python test-count floor guard for the Concordia SDK.
#
# A test-count ratchet: the number of pytest test items collected must never
# drop below the integer in the repo-root `.test-baseline`. This catches the
# silent-deletion class of regression, where a refactor or a bad merge removes
# test coverage without anyone noticing because the remaining tests still pass.
#
# The floor is a FLOOR, not an exact match: adding tests is always fine and does
# not require touching the baseline. When you intentionally raise coverage and
# want the new count protected, bump `.test-baseline` to the new collected count
# in the same change (reviewed like any other diff).
#
# Run locally:  bash scripts/test-floor.sh
# Exit code:    0 = at or above floor, 1 = below floor (or collection error).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASELINE_FILE="$ROOT/.test-baseline"
if [ ! -f "$BASELINE_FILE" ]; then
  echo "test-floor: FAIL — missing baseline file $BASELINE_FILE"
  exit 1
fi

# Read and validate the baseline as a positive integer.
floor="$(tr -d '[:space:]' < "$BASELINE_FILE")"
if ! [[ "$floor" =~ ^[0-9]+$ ]]; then
  echo "test-floor: FAIL — baseline is not an integer: '$floor'"
  exit 1
fi

# Collect (do not run) the test items. `--collect-only -q` prints one line per
# test plus a trailing summary line "<N> tests collected in <t>s". We parse the
# summary line, which is stable across pytest 8.x.
collect_out="$(pytest --collect-only -q 2>/dev/null)"
collect_rc=$?
if [ "$collect_rc" -ne 0 ]; then
  echo "test-floor: FAIL — pytest collection errored (rc=$collect_rc)"
  echo "$collect_out" | tail -20
  exit 1
fi

count="$(printf '%s\n' "$collect_out" | grep -Eo '[0-9]+ tests? collected' | grep -Eo '^[0-9]+')"
if ! [[ "$count" =~ ^[0-9]+$ ]]; then
  echo "test-floor: FAIL — could not parse collected test count from pytest output"
  echo "$collect_out" | tail -20
  exit 1
fi

echo "test-floor (python): collected=$count  floor=$floor"
if [ "$count" -lt "$floor" ]; then
  echo "test-floor: FAIL — collected $count tests, below the floor of $floor."
  echo "A test was removed or a collection error hid some. Restore coverage, or"
  echo "if the drop is intentional, lower .test-baseline in this change."
  exit 1
fi

echo "test-floor: PASS"
exit 0
