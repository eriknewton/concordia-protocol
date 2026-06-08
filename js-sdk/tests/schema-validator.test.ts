import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

import {
  validateMessage,
  isValidMessage,
  validateAttestation,
  isValidAttestation,
  validateApprovalReceipt,
  isValidApprovalReceipt,
  validateFulfillmentAttestation,
  isValidFulfillmentAttestation,
  verifyApprovalReceipt,
  approvalReceiptResultToDict,
  conformsFormat,
} from '../src/validation/index.js';
import { iterErrors } from '../src/internal/jsonschema.js';
import {
  isCpythonIsoDateTime,
  cpythonIsoDateTimeToEpochMs,
} from '../src/internal/iso-datetime.js';
import { KeyPair, sign } from '../src/crypto/signing.js';
import { fromBase64Url } from '../src/crypto/base64url.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Fixture shapes (Python-generated; see scripts/gen-schema-validator-fixtures.py).
// ---------------------------------------------------------------------------

interface MessageCase {
  name: string;
  message: Record<string, unknown>;
  expected: string[];
}
interface ReceiptSchemaCase {
  name: string;
  receipt: Record<string, unknown>;
  expected: string[];
}
interface FulfillmentCase {
  name: string;
  attestation: Record<string, unknown>;
  expected: string[];
}
interface VerifyCase {
  name: string;
  receipt: Record<string, unknown>;
  offer: Record<string, unknown>;
  now: string;
  issuer_public_key_b64: string | null;
  expected: Record<string, unknown>;
}
interface DeferredAttestation {
  valid_attestation: Record<string, unknown>;
  valid_expected: string[];
  bad_oneof_attestation: Record<string, unknown>;
  bad_oneof_expected: string[];
}
interface DateTimeFormatCase {
  name: string;
  value: string;
  expected: boolean;
}
interface DateTimeParseCase {
  name: string;
  value: string;
  expected: number | null;
}
interface Fixtures {
  seed_hex: string;
  public_key_b64: string;
  message_cases: MessageCase[];
  approval_receipt_schema_cases: ReceiptSchemaCase[];
  fulfillment_cases: FulfillmentCase[];
  verify_cases: VerifyCase[];
  datetime_format_cases: DateTimeFormatCase[];
  datetime_parse_cases: DateTimeParseCase[];
  deferred_attestation: DeferredAttestation;
}

const fixtures: Fixtures = JSON.parse(
  readFileSync(
    join(__dirname, 'fixtures/validation/schema_validator_vectors.json'),
    'utf8',
  ),
);

/** Parse a fixture `now` ISO string to epoch ms (the offset is explicit). */
function nowMs(iso: string): number {
  return Date.parse(iso);
}

// ===========================================================================
// validate_message — full ordered error-list parity
// ===========================================================================

describe('validateMessage — Python parity', () => {
  for (const c of fixtures.message_cases) {
    it(`message: ${c.name}`, () => {
      expect(validateMessage(c.message)).toEqual(c.expected);
    });
  }

  it('isValidMessage agrees with the empty-error-list cases', () => {
    for (const c of fixtures.message_cases) {
      expect(isValidMessage(c.message)).toBe(c.expected.length === 0);
    }
  });
});

// ===========================================================================
// validate_approval_receipt — full ordered error-list parity
// ===========================================================================

describe('validateApprovalReceipt — Python parity', () => {
  for (const c of fixtures.approval_receipt_schema_cases) {
    it(`receipt schema: ${c.name}`, () => {
      expect(validateApprovalReceipt(c.receipt)).toEqual(c.expected);
    });
  }

  it('isValidApprovalReceipt agrees with the empty-error-list cases', () => {
    for (const c of fixtures.approval_receipt_schema_cases) {
      expect(isValidApprovalReceipt(c.receipt)).toBe(c.expected.length === 0);
    }
  });
});

// ===========================================================================
// validate_fulfillment_attestation — schema + companion-invariant parity
// ===========================================================================

describe('validateFulfillmentAttestation — Python parity', () => {
  for (const c of fixtures.fulfillment_cases) {
    it(`fulfillment: ${c.name}`, () => {
      expect(validateFulfillmentAttestation(c.attestation)).toEqual(c.expected);
    });
  }

  it('isValidFulfillmentAttestation agrees with the empty-error-list cases', () => {
    for (const c of fixtures.fulfillment_cases) {
      expect(isValidFulfillmentAttestation(c.attestation)).toBe(
        c.expected.length === 0,
      );
    }
  });
});

// ===========================================================================
// verify_approval_receipt — typed-result parity (the 7c consumer)
// ===========================================================================

describe('verifyApprovalReceipt — Python parity', () => {
  for (const c of fixtures.verify_cases) {
    it(`verify: ${c.name}`, () => {
      const issuerPublicKey =
        c.issuer_public_key_b64 === null
          ? null
          : fromBase64Url(c.issuer_public_key_b64);
      const result = verifyApprovalReceipt(c.receipt, c.offer, {
        now: nowMs(c.now),
        issuerPublicKey,
      });
      expect(approvalReceiptResultToDict(result)).toEqual(c.expected);
    });
  }

  it('a Python-signed valid receipt verifies under the same key', () => {
    const valid = fixtures.verify_cases.find((c) => c.name === 'valid_approve');
    expect(valid).toBeDefined();
    if (!valid || valid.issuer_public_key_b64 === null) return;
    const key = fromBase64Url(valid.issuer_public_key_b64);
    const result = verifyApprovalReceipt(valid.receipt, valid.offer, {
      now: nowMs(valid.now),
      issuerPublicKey: key,
    });
    expect(result.valid).toBe(true);
    expect(result.failureReason).toBeNull();
    expect(result.decision).toBe('approve');
  });

  it('accepts a KeyPair as the issuer key (not just raw bytes)', () => {
    const valid = fixtures.verify_cases.find((c) => c.name === 'valid_approve');
    if (!valid || valid.issuer_public_key_b64 === null) return;
    const pub = fromBase64Url(valid.issuer_public_key_b64);
    // Reconstruct a KeyPair from the fixture seed so `verify` can take an object.
    const seed = hexToBytes(fixtures.seed_hex);
    const kp = KeyPair.fromPrivateKey(seed);
    expect(toHex(kp.publicKey)).toBe(toHex(pub));
    const result = verifyApprovalReceipt(valid.receipt, valid.offer, {
      now: nowMs(valid.now),
      issuerPublicKey: kp,
    });
    expect(result.valid).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // YEAR-9999 OVERFLOW — end-to-end fail-CLOSED parity (2026-05-30 finding #3)
  // ---------------------------------------------------------------------------
  //
  // A year-9999 `expires_at` with a tz offset that pushes the UTC instant past
  // `datetime.max` parses through CPython `fromisoformat` (so it PASSES the schema
  // `date-time` format check), but Python `_parse_datetime`'s
  // `.astimezone(timezone.utc)` then raises `OverflowError`. The reference verifier
  // does NOT catch that, so the receipt is NOT honored. The old TS parser computed
  // a finite far-future ms and the verifier reported the receipt VALID/not-expired
  // -- a fail-OPEN relative to Python. The fail-closed guard in
  // `cpythonIsoDateTimeToEpochMs` now returns `null` for the overflow instant, so
  // `verifyApprovalReceipt` reports it EXPIRED (a clean validation failure, not an
  // uncaught throw). This re-signs the Python-signed valid receipt with only
  // `expires_at` changed -- TS `sign` is byte-identical to Python (asserted above),
  // so the signature stays valid and the ONLY thing under test is the expiry guard.
  it('rejects a year-9999 overflow expires_at (fail-closed, matches Python reject)', () => {
    const valid = fixtures.verify_cases.find((c) => c.name === 'valid_approve');
    expect(valid).toBeDefined();
    if (!valid || valid.issuer_public_key_b64 === null) return;
    const seed = hexToBytes(fixtures.seed_hex);
    const kp = KeyPair.fromPrivateKey(seed);

    // Sanity: the unmodified valid receipt verifies, so any rejection below is
    // attributable to the overflow expiry alone, not a broken fixture.
    const baseline = verifyApprovalReceipt(valid.receipt, valid.offer, {
      now: nowMs(valid.now),
      issuerPublicKey: kp,
    });
    expect(baseline.valid).toBe(true);

    // The overflow expiry CPython rejects (verified against python3.12:
    // `fromisoformat` ok, `astimezone(utc)` -> OverflowError).
    const overflowReceipt: Record<string, unknown> = {
      ...(valid.receipt as Record<string, unknown>),
      expires_at: '9999-12-31T23:59:59-14:00',
      signature: { alg: 'Ed25519', value: '' },
    };
    overflowReceipt.signature = {
      alg: 'Ed25519',
      value: sign(overflowReceipt, kp),
    };

    // Schema format check still passes (mirrors CPython `_is_date_time` -> True);
    // the overflow only bites at the expiry parse, exactly like Python.
    expect(conformsFormat('date-time', '9999-12-31T23:59:59-14:00')).toBe(true);
    expect(
      cpythonIsoDateTimeToEpochMs('9999-12-31T23:59:59-14:00'),
    ).toBeNull();

    const result = verifyApprovalReceipt(overflowReceipt, valid.offer, {
      now: nowMs(valid.now),
      issuerPublicKey: kp,
    });
    // Fail CLOSED: NOT valid, reported expired (Python rejects the receipt).
    expect(result.valid).toBe(false);
    expect(result.failureReason).toBe('expired');
    expect(result.checks.not_expired).toBe(false);
  });
});

// ===========================================================================
// date-time FORMAT CHECK — CPython-3.12 fromisoformat parity (codex gap 1)
// ===========================================================================
//
// `conformsFormat('date-time', value)` maps to Python `_is_date_time`
// (datetime.fromisoformat(value.replace("Z","+00:00")); tzinfo is not None).
// These cases pin the alternate-spelling forms the TS layer previously rejected
// as FALSE-invalids on valid Python-signed receipts (+0000, +00, comma fraction,
// basic form, sub-minute offset) plus the naive/garbage rejects. Expecteds come
// straight from python3.12.

describe('date-time format check — CPython 3.12 fromisoformat parity', () => {
  for (const c of fixtures.datetime_format_cases) {
    it(`format: ${c.name} (${c.value})`, () => {
      // Public surface: the registered `date-time` format checker.
      expect(conformsFormat('date-time', c.value)).toBe(c.expected);
      // And the shared parser the checker delegates to.
      expect(isCpythonIsoDateTime(c.value)).toBe(c.expected);
    });
  }

  it('a non-string conforms (Python returns True, deferring to `type`)', () => {
    expect(conformsFormat('date-time', 12345)).toBe(true);
    expect(isCpythonIsoDateTime(12345)).toBe(true);
  });
});

// ===========================================================================
// date-time EXPIRY PARSE — epoch-ms parity (codex gap 2: Date.parse NaN bug)
// ===========================================================================
//
// `cpythonIsoDateTimeToEpochMs` is what `parseDateTimeMs` (approval-receipt.ts)
// delegates to instead of `Date.parse`. `Date.parse` returns NaN on `+0000` /
// `+00` / comma-fractional / sub-minute-offset forms, which made the verifier
// compute `NaN >= now` -> false -> WRONGLY `expired` on valid receipts. The
// shared parser returns the correct epoch ms (byte-identical to Python's
// _parse_datetime). The verifier first does `.replace(/Z/g,'+00:00')`, so the
// test mirrors that single replace before calling the parser.

describe('date-time expiry parse — epoch-ms parity (Date.parse NaN fix)', () => {
  for (const c of fixtures.datetime_parse_cases) {
    it(`parse: ${c.name} (${c.value})`, () => {
      const ms = cpythonIsoDateTimeToEpochMs(c.value.replace(/Z/g, '+00:00'));
      expect(ms).toBe(c.expected);
    });
  }

  it('Date.parse is unreliable on these forms; the parser is not', () => {
    // Documents WHY the dedicated parser is needed: `Date.parse` is engine- and
    // version-dependent on these CPython-valid alternate spellings -- it returns
    // NaN on some (`+00`, `+00:00:30`, comma-fractional) and silently parses
    // others (`+0000`) -- so it can never be trusted for the expiry check. The
    // shared parser always yields the correct, finite Python-equal instant.
    const cases: Array<[string, number]> = [
      ['2026-05-10T14:22:08+0000', 1778422928000],
      ['2026-05-10T14:22:08+00', 1778422928000],
      ['2026-05-10T14:22:08+00:00:30', 1778422898000],
      ['2026-05-10T14:22:08,5+00:00', 1778422928500],
    ];
    // At least one form must be a `Date.parse` NaN (the false-expired trigger),
    // proving `Date.parse` is not a safe substitute for the parser.
    const anyDateParseFails = cases.some(([form]) =>
      Number.isNaN(Date.parse(form)),
    );
    expect(anyDateParseFails).toBe(true);
    // The shared parser is correct on every one of them.
    for (const [form, expected] of cases) {
      expect(cpythonIsoDateTimeToEpochMs(form)).toBe(expected);
    }
  });
});

// ===========================================================================
// Edge cases the validator must handle without throwing (fail-closed posture)
// ===========================================================================

describe('schema validators — robustness on malformed top-level input', () => {
  it('a non-object message reports the type error, never throws', () => {
    // CPython: `$: '...' is not of type 'object'` (the root `type` keyword).
    expect(validateMessage('not-an-object')).toEqual([
      "$: 'not-an-object' is not of type 'object'",
    ]);
    expect(validateMessage(null)).toEqual(["$: None is not of type 'object'"]);
    expect(validateMessage([1, 2])).toEqual([
      '$: [1, 2] is not of type \'object\'',
    ]);
  });

  it('a non-object approval receipt reports the type error', () => {
    expect(validateApprovalReceipt(42)).toEqual([
      "$: 42 is not of type 'object'",
    ]);
  });

  it('verifyApprovalReceipt does not throw on a malformed receipt', () => {
    const result = verifyApprovalReceipt({}, {});
    expect(result.valid).toBe(false);
    // Empty receipt fails schema; with no approves ref the reason is
    // missing_approves_reference (matching Python's schema-failure branch).
    expect(result.failureReason).toBe('missing_approves_reference');
  });
});

// ===========================================================================
// validate_attestation — §9.6 schema, $ref/$defs/oneOf fail-closed coverage
// ===========================================================================

function validAttestation(): Record<string, unknown> {
  const behavior = {
    offers_made: 1,
    concessions: 0,
    concession_magnitude: 0,
    signals_shared: 0,
    constraints_declared: 0,
    constraints_violated: 0,
    reasoning_provided: true,
    withdrawal: false,
  };
  return {
    concordia_attestation: '0.1.0',
    attestation_id: 'att_valid',
    session_id: 'ses_valid',
    timestamp: '2026-05-10T14:22:08Z',
    outcome: {
      status: 'agreed',
      rounds: 2,
      duration_seconds: 60,
      terms_count: 3,
      resolution_mechanism: 'direct',
    },
    parties: [
      {
        agent_id: 'agent_a',
        role: 'initiator',
        behavior,
        signature: 'sig_a',
      },
      {
        agent_id: 'agent_b',
        role: 'responder',
        behavior,
        signature: 'sig_b',
      },
    ],
    meta: {
      category: 'electronics.cameras',
      value_range: '1000-5000_USD',
      extensions_used: [],
      mediator_invoked: false,
    },
    transcript_hash:
      'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    fulfillment: null,
  };
}

describe('validateAttestation — Python parity and fail-closed behavior', () => {
  it('matches the Python-produced deferred boundary fixture exactly', () => {
    const d = fixtures.deferred_attestation;
    expect(validateAttestation(d.valid_attestation)).toEqual(d.valid_expected);
    expect(validateAttestation(d.bad_oneof_attestation)).toEqual(
      d.bad_oneof_expected,
    );
  });

  it('accepts a valid §9.6 attestation with null fulfillment', () => {
    const attestation = validAttestation();
    expect(validateAttestation(attestation)).toEqual([]);
    expect(isValidAttestation(attestation)).toBe(true);
  });

  it('accepts a valid in-line fulfillment block through $ref/oneOf', () => {
    const attestation = validAttestation();
    attestation.fulfillment = {
      status: 'fulfilled',
      settled_at: '2026-05-11T00:00:00Z',
      fulfilled_at: '2026-05-11T00:05:00Z',
      settlement_protocol: 'acp',
      delivery_confirmed: true,
      disputes: [],
      counterparty_attestation: {
        agent_id: 'agent_b',
        confirms_fulfillment: true,
        signature: 'sig_fulfillment',
      },
    };
    expect(validateAttestation(attestation)).toEqual([]);
  });

  it('rejects malformed and unknown attestations instead of failing open', () => {
    expect(validateAttestation(null)).toEqual([
      "$: None is not of type 'object'",
    ]);
    expect(validateAttestation({})).toEqual([
      "$: 'concordia_attestation' is a required property",
      "$: 'attestation_id' is a required property",
      "$: 'session_id' is a required property",
      "$: 'timestamp' is a required property",
      "$: 'outcome' is a required property",
      "$: 'parties' is a required property",
      "$: 'meta' is a required property",
      "$: 'transcript_hash' is a required property",
    ]);
  });

  it('rejects invalid date-time formats with the Python format checker', () => {
    const attestation = validAttestation();
    attestation.timestamp = '2026-05-10T14:22:08';
    expect(validateAttestation(attestation)).toEqual([
      "$.timestamp: '2026-05-10T14:22:08' is not a 'date-time'",
    ]);
  });

  it('rejects invalid $ref targets under references[]', () => {
    const attestation = validAttestation();
    attestation.references = [{ id: '', type: '', relationship: '' }];
    expect(validateAttestation(attestation)).toEqual([
      "$.references[0].id: '' should be non-empty",
      "$.references[0].type: '' should be non-empty",
      "$.references[0].relationship: '' should be non-empty",
    ]);
  });

  it('rejects invalid oneOf temporal and fulfillment variants', () => {
    const badTemporal = validAttestation();
    badTemporal.validity_temporal = { mode: 'absolute' };
    expect(validateAttestation(badTemporal)).toEqual([
      "$.validity_temporal: {'mode': 'absolute'} is not valid under any of the given schemas",
    ]);

    const badFulfillment = validAttestation();
    badFulfillment.fulfillment = { status: 'fulfilled' };
    expect(validateAttestation(badFulfillment)).toEqual([
      "$.fulfillment: {'status': 'fulfilled'} is not valid under any of the given schemas",
    ]);
  });
});

describe('internal jsonschema $ref/oneOf support', () => {
  const schema = {
    type: 'object',
    properties: {
      choice: {
        oneOf: [{ $ref: '#/$defs/text' }, { $ref: '#/$defs/count' }],
      },
    },
    $defs: {
      text: { type: 'string', minLength: 1 },
      count: { type: 'integer', minimum: 1 },
    },
  };

  it('resolves intra-document refs while evaluating oneOf', () => {
    expect(iterErrors(schema, { choice: 'ok' })).toEqual([]);
    expect(iterErrors(schema, { choice: 2 })).toEqual([]);
    expect(iterErrors(schema, { choice: 0 })).toEqual([
      {
        jsonPath: '$.choice',
        message: '0 is not valid under any of the given schemas',
      },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Small hex helpers (KeyPair.fromPrivateKey takes raw seed bytes).
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
