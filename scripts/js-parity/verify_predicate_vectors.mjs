// 13-vector parity harness for the v0.6 predicate canonicalization.
//
// Reads tests/fixtures/predicate_canonical/vector_*/expected_canonical.txt,
// parses each via JSON.parse, runs canonicalizePredicate, compares UTF-8
// bytes to the original file (trailing newline stripped). Exits 0 if all
// 13 vectors pass, 1 if any fail, 2 on unexpected errors.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

import { canonicalizePredicate } from "./canonicalize.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");
const fixtureRoot = join(repoRoot, "tests", "fixtures", "predicate_canonical");

function listVectors() {
  let entries;
  try {
    entries = readdirSync(fixtureRoot);
  } catch (err) {
    throw new Error(`Cannot read fixture root ${fixtureRoot}: ${err.message}`);
  }
  return entries
    .filter((name) => name.startsWith("vector_"))
    .filter((name) => {
      try {
        return statSync(join(fixtureRoot, name)).isDirectory();
      } catch {
        return false;
      }
    })
    .sort();
}

function stripTrailingNewlineBytes(buf) {
  let end = buf.length;
  while (end > 0 && (buf[end - 1] === 0x0a || buf[end - 1] === 0x0d)) {
    end -= 1;
  }
  return buf.subarray(0, end);
}

function firstDivergence(a, b) {
  const limit = Math.min(a.length, b.length);
  for (let i = 0; i < limit; i++) {
    if (a[i] !== b[i]) return i;
  }
  return a.length === b.length ? -1 : limit;
}

function snippet(buf, idx, span = 20) {
  const start = Math.max(0, idx - span);
  const end = Math.min(buf.length, idx + span);
  const slice = buf.subarray(start, end);
  return JSON.stringify(slice.toString("utf8"));
}

function runVector(name) {
  const path = join(fixtureRoot, name, "expected_canonical.txt");
  const rawBytes = readFileSync(path);
  const expectedBytes = stripTrailingNewlineBytes(rawBytes);
  const expectedText = expectedBytes.toString("utf8");
  const parsed = JSON.parse(expectedText);
  const actualBytes = canonicalizePredicate(parsed);
  const idx = firstDivergence(expectedBytes, actualBytes);
  if (idx === -1) {
    return { name, pass: true };
  }
  return {
    name,
    pass: false,
    idx,
    expectedLen: expectedBytes.length,
    actualLen: actualBytes.length,
    expectedSnippet: snippet(expectedBytes, idx),
    actualSnippet: snippet(actualBytes, idx),
  };
}

function main() {
  const vectors = listVectors();
  if (vectors.length !== 13) {
    console.error(
      `EXPECTED 13 vector_* directories, found ${vectors.length}: ${vectors.join(", ")}`,
    );
    process.exit(2);
  }
  let passes = 0;
  for (const name of vectors) {
    let result;
    try {
      result = runVector(name);
    } catch (err) {
      console.error(`[ERROR] ${name}: ${err.message}`);
      process.exit(2);
    }
    if (result.pass) {
      console.log(`[PASS] ${name}`);
      passes += 1;
    } else {
      console.log(
        `[FAIL] ${name}: diverged at byte ${result.idx} (expected ${result.expectedLen} bytes, got ${result.actualLen})`,
      );
      console.log(`  expected ~ ${result.expectedSnippet}`);
      console.log(`  actual   ~ ${result.actualSnippet}`);
    }
  }
  if (passes === vectors.length) {
    console.log(`PARITY: ${passes}/${vectors.length} vectors pass`);
    process.exit(0);
  }
  console.log(
    `PARITY: ${passes}/${vectors.length} vectors pass — see above for failures`,
  );
  process.exit(1);
}

main();
