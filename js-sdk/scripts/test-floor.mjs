#!/usr/bin/env node
//
// test-floor.mjs — JS-SDK test-count floor guard for the Concordia TypeScript SDK.
//
// A test-count ratchet: the number of vitest test cases must never drop below
// the integer in `js-sdk/.test-baseline`. This catches the silent-deletion
// class of regression, where a refactor or a bad merge removes test coverage
// without anyone noticing because the remaining tests still pass.
//
// The floor is a FLOOR, not an exact match: adding tests is always fine. When
// you intentionally raise coverage and want the new count protected, bump
// `.test-baseline` in the same change (reviewed like any other diff).
//
// We run vitest with the JSON reporter and read `numTotalTests` (passed +
// skipped + failed). Skipped tests still count toward the floor so that
// `it.skip`-ing a test rather than deleting it is also caught as a coverage
// drop is not — a skip keeps the case in the total but is surfaced separately.
//
// Run locally:  node scripts/test-floor.mjs   (from js-sdk/)
// Exit code:    0 = at or above floor, 1 = below floor (or a run error).

import { readFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const sdkRoot = join(here, '..');
const baselineFile = join(sdkRoot, '.test-baseline');

let floor;
try {
  floor = parseInt(readFileSync(baselineFile, 'utf8').trim(), 10);
} catch {
  console.error(`test-floor: FAIL — missing or unreadable baseline ${baselineFile}`);
  process.exit(1);
}
if (!Number.isInteger(floor) || floor < 0) {
  console.error(`test-floor: FAIL — baseline is not a non-negative integer`);
  process.exit(1);
}

// Run vitest once, emitting a JSON summary to a temp file. Using a file (not
// stdout) keeps the JSON clean even if a test logs to stdout.
const outFile = join(mkdtempSync(join(tmpdir(), 'concordia-testfloor-')), 'vitest.json');
try {
  execFileSync(
    'npx',
    ['vitest', 'run', '--reporter=json', `--outputFile=${outFile}`],
    { cwd: sdkRoot, stdio: ['ignore', 'ignore', 'inherit'] },
  );
} catch (err) {
  // A non-zero exit means a test failed; that is a real failure the test job
  // already surfaces. Re-raise so the floor job is also red rather than masking it.
  console.error('test-floor: FAIL — vitest run exited non-zero (a test failed).');
  process.exit(err.status ?? 1);
}

let report;
try {
  report = JSON.parse(readFileSync(outFile, 'utf8'));
} catch {
  console.error('test-floor: FAIL — could not parse vitest JSON report');
  process.exit(1);
}

const total = report.numTotalTests;
const passed = report.numPassedTests ?? 0;
const pending = report.numPendingTests ?? 0;
if (!Number.isInteger(total)) {
  console.error('test-floor: FAIL — vitest JSON report missing numTotalTests');
  process.exit(1);
}

console.log(`test-floor (js-sdk): total=${total} (passed=${passed}, skipped=${pending})  floor=${floor}`);
if (total < floor) {
  console.error(`test-floor: FAIL — ${total} tests, below the floor of ${floor}.`);
  console.error('A test was removed. Restore coverage, or if the drop is');
  console.error('intentional, lower js-sdk/.test-baseline in this change.');
  process.exit(1);
}

console.log('test-floor: PASS');
