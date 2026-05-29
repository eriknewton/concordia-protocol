#!/usr/bin/env node
// Sync fixture vectors from the Python repo into the JS test surface.
// Run from the js-sdk/ directory: node scripts/sync-fixtures-from-python.mjs

import { copyFileSync, mkdirSync, readdirSync, writeFileSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { execFileSync } from 'child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = join(__dirname, '..');
const CONCORDIA_ROOT = join(SDK_ROOT, '..');

// Sync v0.6 predicate canonical fixtures (13 vectors)
const PREDICATE_SRC = join(CONCORDIA_ROOT, 'tests/fixtures/predicate_canonical');
const PREDICATE_DST = join(SDK_ROOT, 'tests/fixtures/predicate_canonical');

if (!existsSync(PREDICATE_SRC)) {
  console.error(`Source fixtures missing: ${PREDICATE_SRC}`);
  process.exit(1);
}

mkdirSync(PREDICATE_DST, { recursive: true });
const vectors = readdirSync(PREDICATE_SRC).filter(d => d.startsWith('vector_'));
for (const vec of vectors) {
  const srcDir = join(PREDICATE_SRC, vec);
  const dstDir = join(PREDICATE_DST, vec);
  mkdirSync(dstDir, { recursive: true });
  for (const file of readdirSync(srcDir)) {
    copyFileSync(join(srcDir, file), join(dstDir, file));
  }
}
console.log(`Synced ${vectors.length} predicate fixtures from Python repo.`);

// DELTA-20 vectors (inline, extracted from tests/test_canonicalization_vectors.py)
const DELTA20_VECTORS = [
  { input: { a: 1 }, expected: '{"a":1}' },
  { input: { b: 'hello' }, expected: '{"b":"hello"}' },
  { input: { x: null }, expected: '{"x":null}' },
  { input: { t: true, f: false }, expected: '{"f":false,"t":true}' },
  { input: { z: 1, a: 2, m: 3 }, expected: '{"a":2,"m":3,"z":1}' },
  { input: { greeting: 'h\u00e9llo' }, expected: '{"greeting":"h\u00e9llo"}' },
  { input: { emoji: '\u2713' }, expected: '{"emoji":"\u2713"}' },
  { input: { p: 1.5 }, expected: '{"p":1.5}' },
  { input: { n: -3.25 }, expected: '{"n":-3.25}' },
  { input: { n: 0 }, expected: '{"n":0}' },
  { input: { n: 42 }, expected: '{"n":42}' },
  { input: { n: -7 }, expected: '{"n":-7}' },
  { input: { outer: { z: 1, a: 2 } }, expected: '{"outer":{"a":2,"z":1}}' },
  { input: { items: [3, 1, 2] }, expected: '{"items":[3,1,2]}' },
  { input: { items: ['b', 'a'] }, expected: '{"items":["b","a"]}' },
  { input: { items: [{ b: 2, a: 1 }, { y: 'z' }] }, expected: '{"items":[{"a":1,"b":2},{"y":"z"}]}' },
  { input: { e: {}, a: [] }, expected: '{"a":[],"e":{}}' },
  { input: { q: 'he said "hi"' }, expected: '{"q":"he said \\"hi\\""}' },
  { input: { bs: 'a\\b' }, expected: '{"bs":"a\\\\b"}' },
  { input: { nl: 'x\ny' }, expected: '{"nl":"x\\ny"}' },
];

mkdirSync(join(SDK_ROOT, 'tests/fixtures/delta20'), { recursive: true });
writeFileSync(
  join(SDK_ROOT, 'tests/fixtures/delta20/vectors.json'),
  JSON.stringify(DELTA20_VECTORS, null, 2),
);
console.log(`Wrote ${DELTA20_VECTORS.length} DELTA-20 vectors.`);

const pythonBin = process.env.PYTHON ?? 'python3';

// Ed25519 signing parity fixtures. Generated FROM the Python reference
// (concordia.signing) via scripts/gen-signing-fixtures.py so the expected
// signatures come straight from Python, never hand-authored. Run the
// generator with the repo root on PYTHONPATH so `import concordia` resolves.
const SIGNING_GEN = join(SDK_ROOT, 'scripts/gen-signing-fixtures.py');
const SIGNING_DST = join(SDK_ROOT, 'tests/fixtures/signing/ed25519_vectors.json');
try {
  const out = execFileSync(pythonBin, [SIGNING_GEN], {
    cwd: CONCORDIA_ROOT,
    env: { ...process.env, PYTHONPATH: CONCORDIA_ROOT },
    encoding: 'utf8',
  });
  mkdirSync(dirname(SIGNING_DST), { recursive: true });
  writeFileSync(SIGNING_DST, out);
  const parsed = JSON.parse(out);
  console.log(
    `Wrote ${parsed.cases.length} Ed25519 signing vectors (+ tamper cases) from Python.`,
  );
} catch (err) {
  console.error(
    `Failed to generate signing fixtures from Python: ${err.message}`,
  );
  process.exit(1);
}

// Foundational-types parity fixtures. Generated FROM the Python reference
// (concordia.types) via scripts/gen-types-fixtures.py so every enum value,
// to_dict() expectation, and round() expectation comes straight from Python,
// never hand-authored. Run the generator with the repo root on PYTHONPATH so
// `import concordia` resolves.
const TYPES_GEN = join(SDK_ROOT, 'scripts/gen-types-fixtures.py');
const TYPES_DST = join(SDK_ROOT, 'tests/fixtures/types/types_vectors.json');
try {
  const out = execFileSync(pythonBin, [TYPES_GEN], {
    cwd: CONCORDIA_ROOT,
    env: { ...process.env, PYTHONPATH: CONCORDIA_ROOT },
    encoding: 'utf8',
  });
  mkdirSync(dirname(TYPES_DST), { recursive: true });
  writeFileSync(TYPES_DST, out);
  const parsed = JSON.parse(out);
  console.log(
    `Wrote types parity fixtures from Python: ` +
      `${Object.keys(parsed.enums).length} enums, ` +
      `${parsed.behavior_record_cases.length} behavior cases, ` +
      `${parsed.round_parity.length} round-parity vectors.`,
  );
} catch (err) {
  console.error(
    `Failed to generate types fixtures from Python: ${err.message}`,
  );
  process.exit(1);
}
