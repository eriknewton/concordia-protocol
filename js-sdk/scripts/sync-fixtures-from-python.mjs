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

// v0.6 signed-predicate parity fixtures. Generated FROM the Python reference
// (concordia.predicate / concordia.predicate_type_profiles /
// concordia.attestation) via scripts/gen-predicate-fixtures.py so every
// canonical-byte string, signature, verification outcome, and validation error
// list comes straight from Python, never hand-authored. Run the generator with
// the repo root on PYTHONPATH so `import concordia` resolves.
const PREDICATE_GEN = join(SDK_ROOT, 'scripts/gen-predicate-fixtures.py');
const PREDICATE_VEC_DST = join(
  SDK_ROOT,
  'tests/fixtures/predicate/predicate_vectors.json',
);
try {
  const out = execFileSync(pythonBin, [PREDICATE_GEN], {
    cwd: CONCORDIA_ROOT,
    env: { ...process.env, PYTHONPATH: CONCORDIA_ROOT },
    encoding: 'utf8',
  });
  mkdirSync(dirname(PREDICATE_VEC_DST), { recursive: true });
  writeFileSync(PREDICATE_VEC_DST, out);
  const parsed = JSON.parse(out);
  console.log(
    `Wrote predicate parity fixtures from Python: ` +
      `${parsed.sign_cases.length} sign+verify cases, ` +
      `${parsed.verify_fail_cases.length} verify-failure cases, ` +
      `${parsed.profile_cases.length} profile cases, ` +
      `${parsed.write_cases.length} write-validation cases, ` +
      `${parsed.reference_cases.length} reference cases.`,
  );
} catch (err) {
  console.error(
    `Failed to generate predicate fixtures from Python: ${err.message}`,
  );
  process.exit(1);
}

// Mandate-MODELS parity fixtures. Generated FROM the Python reference
// (concordia.models.mandate) via scripts/gen-mandate-fixtures.py so every enum
// value, to_dict()/from_dict() expectation, error string, and canonical schema
// byte-string comes straight from Python, never hand-authored. Only the data
// layer is exercised; mandate signing/verification (concordia/mandate.py) is
// deferred to the engine PR. The generator imports only stdlib model code, so
// it runs under any Python 3.9+.
const MANDATE_GEN = join(SDK_ROOT, 'scripts/gen-mandate-fixtures.py');
const MANDATE_DST = join(
  SDK_ROOT,
  'tests/fixtures/mandate/mandate_vectors.json',
);
try {
  const out = execFileSync(pythonBin, [MANDATE_GEN], {
    cwd: CONCORDIA_ROOT,
    env: { ...process.env, PYTHONPATH: CONCORDIA_ROOT },
    encoding: 'utf8',
  });
  mkdirSync(dirname(MANDATE_DST), { recursive: true });
  writeFileSync(MANDATE_DST, out);
  const parsed = JSON.parse(out);
  console.log(
    `Wrote mandate-models parity fixtures from Python: ` +
      `${Object.keys(parsed.enums).length} enums, ` +
      `${parsed.delegation_to_dict_cases.length} delegation to_dict, ` +
      `${parsed.validity_to_dict_cases.length} validity to_dict, ` +
      `${parsed.mandate_to_dict_cases.length} mandate to_dict, ` +
      `${parsed.mandate_from_dict_cases.length} mandate from_dict, ` +
      `${parsed.result_to_dict_cases.length} verification-result to_dict.`,
  );
} catch (err) {
  console.error(
    `Failed to generate mandate fixtures from Python: ${err.message}`,
  );
  process.exit(1);
}

// Mandate-ENGINE parity fixtures. Generated FROM the Python reference
// (concordia.mandate + concordia.signing) via gen-mandate-engine-fixtures.py so
// every Ed25519 signature, schema/constraint error string, temporal/chain
// outcome, and end-to-end verify_mandate result comes straight from Python,
// never hand-authored. Revocation NETWORK I/O is deferred; verify_mandate is
// exercised with check_revocation_status=False. The generator imports jsonschema
// + cryptography (the engine's own deps), so run it under the same Python the
// engine targets (python3.12 in CI / dev).
const MANDATE_ENGINE_GEN = join(
  SDK_ROOT,
  'scripts/gen-mandate-engine-fixtures.py',
);
const MANDATE_ENGINE_DST = join(
  SDK_ROOT,
  'tests/fixtures/mandate/mandate_engine_vectors.json',
);
// The engine generator imports jsonschema + cryptography (the engine's own
// validation/signing deps). Pin python3.12 (verified jsonschema message text)
// unless PYTHON is explicitly overridden.
const enginePythonBin =
  process.env.PYTHON ?? 'python3.12';
try {
  const out = execFileSync(enginePythonBin, [MANDATE_ENGINE_GEN], {
    cwd: CONCORDIA_ROOT,
    env: { ...process.env, PYTHONPATH: CONCORDIA_ROOT },
    encoding: 'utf8',
  });
  mkdirSync(dirname(MANDATE_ENGINE_DST), { recursive: true });
  writeFileSync(MANDATE_ENGINE_DST, out);
  const parsed = JSON.parse(out);
  console.log(
    `Wrote mandate-engine parity fixtures from Python: ` +
      `${parsed.sign_mandate_cases.length} sign_mandate, ` +
      `${parsed.sign_delegation_cases.length} sign_delegation, ` +
      `${parsed.schema_cases.length} schema, ` +
      `${parsed.constraint_cases.length} constraint, ` +
      `${parsed.scope_cases.length} scope, ` +
      `${parsed.compose_cases.length} compose, ` +
      `${parsed.temporal_cases.length} temporal, ` +
      `${parsed.chain_cases.length} chain, ` +
      `${parsed.verify_cases.length} verify_mandate.`,
  );
} catch (err) {
  console.error(
    `Failed to generate mandate-engine fixtures from Python: ${err.message}`,
  );
  process.exit(1);
}

// Session-lifecycle parity fixtures. Generated FROM the Python reference
// (concordia.session + concordia.message + concordia.signing) via
// gen-session-fixtures.py so the transition table, every applied-message
// outcome (state, round_count, prev_hash, behavior records), invalid-transition
// / invalid-signature / unknown-MessageType error text, expire/make_dormant
// outcomes, the _compute_concession arithmetic, and compute_hash / validate_chain
// outcomes all come straight from Python, never hand-authored. Messages are real
// signed envelopes (built via build_envelope with deterministic seeded keys), so
// the JS suite verifies the SAME Python signatures with the SAME keys. The
// generator imports cryptography (the signing dep); pin python3.12 unless PYTHON
// is overridden.
const SESSION_GEN = join(SDK_ROOT, 'scripts/gen-session-fixtures.py');
const SESSION_DST = join(
  SDK_ROOT,
  'tests/fixtures/session/session_vectors.json',
);
const sessionPythonBin = process.env.PYTHON ?? 'python3.12';
try {
  const out = execFileSync(sessionPythonBin, [SESSION_GEN], {
    cwd: CONCORDIA_ROOT,
    env: { ...process.env, PYTHONPATH: CONCORDIA_ROOT },
    encoding: 'utf8',
  });
  mkdirSync(dirname(SESSION_DST), { recursive: true });
  writeFileSync(SESSION_DST, out);
  const parsed = JSON.parse(out);
  console.log(
    `Wrote session-lifecycle parity fixtures from Python: ` +
      `${parsed.transition_table.length} transition entries, ` +
      `${parsed.runs.length} runs, ` +
      `${parsed.lifecycle_cases.length} lifecycle, ` +
      `${parsed.invalid_transitions.length} invalid-transition, ` +
      `${parsed.invalid_lifecycle.length} invalid-lifecycle, ` +
      `${parsed.invalid_signatures.length} invalid-signature, ` +
      `${parsed.unknown_type_cases.length} unknown-type, ` +
      `${parsed.body_shape_cases.length} body-shape, ` +
      `${parsed.concession_cases.length} concession, ` +
      `${parsed.hash_cases.length} hash, ` +
      `${parsed.chain_cases.length} chain.`,
  );
} catch (err) {
  console.error(
    `Failed to generate session fixtures from Python: ${err.message}`,
  );
  process.exit(1);
}

// Reputation-attestation parity fixtures. Generated FROM the Python reference
// (concordia.attestation driven over concordia.session + concordia.signing) via
// gen-attestation-fixtures.py so the full attestation object (header fields,
// outcome with conditional terms_count, per-party behavioral records and their
// real Python Ed25519 signatures, transcript_hash, meta, normalized references,
// validity_temporal, and the 4-line summary), the validate_validity_temporal
// normalization + error text, the is_valid_now temporal checks, the
// generate_receipt_summary formatting, and the no-raw-terms PRIVACY INVARIANT
// all come straight from Python, never hand-authored. The non-deterministic
// attestation_id / timestamp are captured per case so the JS side can inject
// them as overrides and compare the ENTIRE object byte-for-byte. The generator
// imports cryptography (the signing dep); pin python3.12 unless PYTHON is
// overridden.
const ATTESTATION_GEN = join(SDK_ROOT, 'scripts/gen-attestation-fixtures.py');
const ATTESTATION_DST = join(
  SDK_ROOT,
  'tests/fixtures/attestation/attestation_vectors.json',
);
const attestationPythonBin = process.env.PYTHON ?? 'python3.12';
try {
  const out = execFileSync(attestationPythonBin, [ATTESTATION_GEN], {
    cwd: CONCORDIA_ROOT,
    env: { ...process.env, PYTHONPATH: CONCORDIA_ROOT },
    encoding: 'utf8',
  });
  mkdirSync(dirname(ATTESTATION_DST), { recursive: true });
  writeFileSync(ATTESTATION_DST, out);
  const parsed = JSON.parse(out);
  console.log(
    `Wrote attestation parity fixtures from Python: ` +
      `${parsed.cases.length} generate-attestation cases, ` +
      `${parsed.vt_norm_cases.length} validity-temporal normalize, ` +
      `${parsed.vt_error_cases.length} validity-temporal error, ` +
      `${parsed.valid_now_cases.length} is-valid-now, ` +
      `${parsed.valid_now_error_cases.length} is-valid-now error, ` +
      `${parsed.summary_cases.length} receipt-summary, ` +
      `${parsed.reference_strictness_cases.length} reference-strictness, ` +
      `${parsed.terms_count_cases.length} terms-count.`,
  );
} catch (err) {
  console.error(
    `Failed to generate attestation fixtures from Python: ${err.message}`,
  );
  process.exit(1);
}

// Schema-validator + approval-receipt parity fixtures. Generated FROM the Python
// reference (concordia.schema_validator + concordia.approval_receipt) via
// gen-schema-validator-fixtures.py so every ORDERED error list (validate_message
// / validate_approval_receipt / validate_fulfillment_attestation, matching
// CPython jsonschema's iter_errors traversal + message text + json_path), and
// every ApprovalReceipt verification result (the 7c consumer), comes straight
// from Python, never hand-authored. Receipts are signed with deterministic seeded
// Ed25519 keys, so the JS suite verifies the SAME Python signatures with the SAME
// keys. The generator imports jsonschema + cryptography (the reference's deps);
// pin python3.12 (the jsonschema version whose message templates the JS port
// reproduces) unless PYTHON is overridden.
const SCHEMA_VALIDATOR_GEN = join(
  SDK_ROOT,
  'scripts/gen-schema-validator-fixtures.py',
);
const SCHEMA_VALIDATOR_DST = join(
  SDK_ROOT,
  'tests/fixtures/validation/schema_validator_vectors.json',
);
const schemaValidatorPythonBin = process.env.PYTHON ?? 'python3.12';
try {
  const out = execFileSync(schemaValidatorPythonBin, [SCHEMA_VALIDATOR_GEN], {
    cwd: CONCORDIA_ROOT,
    env: { ...process.env, PYTHONPATH: CONCORDIA_ROOT },
    encoding: 'utf8',
  });
  mkdirSync(dirname(SCHEMA_VALIDATOR_DST), { recursive: true });
  writeFileSync(SCHEMA_VALIDATOR_DST, out);
  const parsed = JSON.parse(out);
  console.log(
    `Wrote schema-validator parity fixtures from Python: ` +
      `${parsed.message_cases.length} message, ` +
      `${parsed.approval_receipt_schema_cases.length} approval-receipt schema, ` +
      `${parsed.fulfillment_cases.length} fulfillment, ` +
      `${parsed.verify_cases.length} approval-receipt verify, ` +
      `${parsed.datetime_format_cases.length} date-time format, ` +
      `${parsed.datetime_parse_cases.length} date-time parse, ` +
      `${parsed.attestation_constraint_cases.length} constraint-render, ` +
      `1 deferred-attestation boundary.`,
  );
} catch (err) {
  console.error(
    `Failed to generate schema-validator fixtures from Python: ${err.message}`,
  );
  process.exit(1);
}
