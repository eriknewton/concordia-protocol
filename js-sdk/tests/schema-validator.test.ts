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
interface AttestationConstraintCase {
  name: string;
  attestation: Record<string, unknown>;
  expected: string[];
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
  attestation_constraint_cases: AttestationConstraintCase[];
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
    // Post-#95 no-echo rendering: the violated CONSTRAINT, never the instance.
    expect(validateMessage('not-an-object')).toEqual([
      '$: violates \'type\' constraint: "object"',
    ]);
    expect(validateMessage(null)).toEqual([
      '$: violates \'type\' constraint: "object"',
    ]);
    expect(validateMessage([1, 2])).toEqual([
      '$: violates \'type\' constraint: "object"',
    ]);
  });

  it('a non-object approval receipt reports the type error', () => {
    expect(validateApprovalReceipt(42)).toEqual([
      '$: violates \'type\' constraint: "object"',
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
      '$: violates \'type\' constraint: "object"',
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
    // The constraint (the format NAME) is reported; the rejected timestamp
    // string is not echoed (mirrors Python post-#95).
    expect(validateAttestation(attestation)).toEqual([
      '$.timestamp: violates \'format\' constraint: "date-time"',
    ]);
  });

  // The next four mirror Python test_schema.py's hardened assertions: the
  // additionalProperties violation is reported WITHOUT naming the
  // attacker-chosen keys or echoing their values.
  it('rejects raw deal terms carried as extra attestation fields', () => {
    const attestation = validAttestation();
    attestation.price = { value: 1900, currency: 'USD' };
    const errors = validateAttestation(attestation);
    expect(errors).toContain(
      "$: violates 'additionalProperties' constraint: false",
    );
    expect(errors.some((e) => e.includes('price') || e.includes('1900'))).toBe(
      false,
    );
  });

  it('rejects raw agreed terms carried under outcome', () => {
    const attestation = validAttestation();
    (attestation.outcome as Record<string, unknown>).agreed_terms = {
      price: { value: 1900, currency: 'USD' },
      quantity: 2,
    };
    const errors = validateAttestation(attestation);
    expect(errors).toContain(
      "$.outcome: violates 'additionalProperties' constraint: false",
    );
    expect(
      errors.some((e) => e.includes('agreed_terms') || e.includes('1900')),
    ).toBe(false);
  });

  it('rejects raw price fields carried under party behavior', () => {
    const attestation = validAttestation();
    const parties = attestation.parties as Array<Record<string, unknown>>;
    const behavior = parties[0].behavior as Record<string, unknown>;
    behavior.price_floor = 1750;
    behavior.accepted_price = 1900;
    const errors = validateAttestation(attestation);
    expect(errors).toContain(
      "$.parties[0].behavior: violates 'additionalProperties' constraint: false",
    );
    expect(
      errors.some(
        (e) =>
          e.includes('price_floor') || e.includes('1750') || e.includes('1900'),
      ),
    ).toBe(false);
  });

  it('rejects raw term payloads carried under reference extensions', () => {
    const attestation = validAttestation();
    attestation.references = [
      {
        id: 'urn:concordia:predicate:privacy',
        type: 'predicate',
        relationship: 'references',
        extensions: {
          price: 1900,
          quantity: 2,
        },
      },
    ];
    const errors = validateAttestation(attestation);
    expect(errors).toContain(
      "$.references[0].extensions: violates 'additionalProperties' constraint: false",
    );
    expect(
      errors.some((e) => e.includes('1900') || e.includes('quantity')),
    ).toBe(false);
  });

  it('accepts a legitimate behavioral summary', () => {
    const attestation = validAttestation();
    attestation.summary = [
      'Parties: agent_a, agent_b',
      'Topic: electronics.cameras',
      'Outcome: AGREED',
      'Transcript hash: aaaaaaaaaaaaaaaa',
    ].join('\n');
    expect(validateAttestation(attestation)).toEqual([]);
  });

  it('rejects overlong attestation free text without echoing it', () => {
    const attestation = validAttestation();
    attestation.summary = 'x'.repeat(1025);
    const errors = validateAttestation(attestation);
    expect(errors).toEqual([
      "$.summary: violates 'maxLength' constraint: 1024",
    ]);
    // Non-echo: the oversized instance string never rides in the error
    // (mirrors Python test_rejects_overlong_attestation_free_text).
    expect(errors.some((e) => e.includes('xxxx'))).toBe(false);
  });

  it('rejects obvious raw terms in attestation free text without echoing them', () => {
    const attestation = validAttestation();
    attestation.summary = 'Raw terms: price 1900 USD, quantity 2';
    attestation.fulfillment = {
      status: 'disputed',
      settled_at: '2026-05-11T00:00:00Z',
      delivery_confirmed: false,
      disputes: [
        {
          term_id: 'delivery',
          complainant_agent_id: 'agent_a',
          description: 'Counterparty asked for qty: 2',
          resolution: 'unresolved',
        },
      ],
      counterparty_attestation: {
        agent_id: 'agent_b',
        confirms_fulfillment: false,
        notes: 'Asked for $1900 before delivery.',
        signature: 'sig_fulfillment',
      },
    };
    const errors = validateAttestation(attestation);
    expect(errors).toContain(
      '$.summary: free-text field must not contain obvious raw deal terms',
    );
    expect(errors).toContain(
      '$.fulfillment.disputes[0].description: free-text field must not contain obvious raw deal terms',
    );
    expect(errors).toContain(
      '$.fulfillment.counterparty_attestation.notes: free-text field must not contain obvious raw deal terms',
    );
    expect(
      errors.some(
        (e) =>
          e.includes('1900') || e.includes('quantity 2') || e.includes('$1900'),
      ),
    ).toBe(false);
  });

  it('rejects invalid $ref targets under references[]', () => {
    const attestation = validAttestation();
    attestation.references = [{ id: '', type: '', relationship: '' }];
    // The post-#95 canonical schema also carries the `^\S+$` whitespace ban
    // on every reference string field (the previous stripped bundle predated
    // it), so each empty field violates BOTH constraints, exactly as Python
    // reports them.
    expect(validateAttestation(attestation)).toEqual([
      "$.references[0].id: violates 'minLength' constraint: 1",
      '$.references[0].id: violates \'pattern\' constraint: "^\\\\S+$"',
      "$.references[0].type: violates 'minLength' constraint: 1",
      '$.references[0].type: violates \'pattern\' constraint: "^\\\\S+$"',
      "$.references[0].relationship: violates 'minLength' constraint: 1",
      '$.references[0].relationship: violates \'pattern\' constraint: "^\\\\S+$"',
    ]);
  });

  it('rejects invalid oneOf temporal and fulfillment variants', () => {
    const badTemporal = validAttestation();
    badTemporal.validity_temporal = { mode: 'absolute' };
    // The oneOf constraint rendering is schema-side only (branch subschemas,
    // sorted keys) and hits Python's 120-character truncation cap.
    expect(validateAttestation(badTemporal)).toEqual([
      "$.validity_temporal: violates 'oneOf' constraint: " +
        '[{"additionalProperties": false, "description": "Absolute ' +
        'clock-bounded validity. Added in v0.4.0 (WP3).", "properties":...',
    ]);

    const badFulfillment = validAttestation();
    badFulfillment.fulfillment = { status: 'fulfilled' };
    expect(validateAttestation(badFulfillment)).toEqual([
      "$.fulfillment: violates 'oneOf' constraint: " +
        '[{"type": "null"}, {"$ref": "#/$defs/fulfillment_attestation"}]',
    ]);
  });
});

// ===========================================================================
// Error-echo hardening — Python #95 finding 5 parity (no instance echo)
// ===========================================================================

describe('schema-validation errors never echo the instance (Python #95 parity)', () => {
  // Python-generated fixtures: every expected list comes straight from the
  // hardened _format_validation_error path, including the FLOAT-SOURCED
  // bounds ("0.0" / "1.0") JS numbers cannot represent natively.
  for (const c of fixtures.attestation_constraint_cases) {
    it(`constraint render: ${c.name}`, () => {
      const errors = validateAttestation(c.attestation);
      expect(errors).toEqual(c.expected);
      // The hostile markers planted in the violating instances must never
      // ride in ANY error string (free-text errors report a fixed sentence).
      expect(
        errors.some((e) => e.includes('SECRET') || e.includes('4350')),
      ).toBe(false);
    });
  }

  it('renders float-sourced bounds Python-style across all four surfaces', () => {
    // Direct pin of the int/float distinction: the schema source `0.0` must
    // render "0.0" (Python json.dumps of the loaded float), while the int
    // sources elsewhere render bare ("1024", "1", "0").
    const c = fixtures.attestation_constraint_cases.find(
      (x) => x.name === 'concession_magnitude_below_float_minimum',
    );
    expect(c).toBeDefined();
    expect(c?.expected).toEqual([
      "$.parties[0].behavior.concession_magnitude: violates 'minimum' constraint: 0.0",
    ]);
  });

  it('truncates long constraint renderings at 120 characters + "..."', () => {
    // The message `type` enum rendering exceeds the cap; Python slices the
    // RENDERED schema-side text at 120 code points and appends "...".
    const msg: Record<string, unknown> = {
      concordia: '0.5.0',
      type: 'negotiate.SECRET_TERMS price=4350',
      id: 'm1',
      session_id: 's1',
      timestamp: '2026-05-10T14:22:08Z',
      from: { agent_id: 'agent-a' },
      body: {},
      signature: 'sig',
    };
    const errors = validateMessage(msg);
    expect(errors).toHaveLength(1);
    const [error] = errors;
    const prefix = "$.type: violates 'enum' constraint: ";
    expect(error?.startsWith(prefix)).toBe(true);
    expect(error?.endsWith('...')).toBe(true);
    expect(error).toHaveLength(prefix.length + 120 + 3);
    expect(error?.includes('SECRET') || error?.includes('4350')).toBe(false);
  });

  it('keeps the upstream message for required (schema-side names only)', () => {
    // Python preserves `'x' is a required property` because it names only
    // schema-side property names; everything else is constraint-rendered.
    expect(validateMessage({})).toEqual([
      "$: 'concordia' is a required property",
      "$: 'type' is a required property",
      "$: 'id' is a required property",
      "$: 'session_id' is a required property",
      "$: 'timestamp' is a required property",
      "$: 'from' is a required property",
      "$: 'body' is a required property",
      "$: 'signature' is a required property",
    ]);
  });

  it('hostile instance strings never surface through any validator', () => {
    const probe = 'SECRET_TERMS price=4350 qty=2';
    const surfaces: Array<(v: unknown) => string[]> = [
      validateMessage,
      validateAttestation,
      validateApprovalReceipt,
      validateFulfillmentAttestation,
    ];
    for (const validate of surfaces) {
      for (const instance of [
        probe,
        { [probe]: probe },
        { artifact_type: probe, scope: probe, timestamp: probe },
        [probe],
      ]) {
        const errors = validate(instance);
        expect(errors.length).toBeGreaterThan(0);
        expect(
          errors.some((e) => e.includes('SECRET') || e.includes('4350')),
        ).toBe(false);
      }
    }
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
    // toMatchObject: the error also carries the CPython validator stamping
    // (keyword / validatorValue / schema), pinned separately below.
    expect(iterErrors(schema, { choice: 0 })).toMatchObject([
      {
        jsonPath: '$.choice',
        message: '0 is not valid under any of the given schemas',
        keyword: 'oneOf',
      },
    ]);
  });

  it('rejects oneOf values that match multiple branches', () => {
    expect(iterErrors({ oneOf: [{ type: 'number' }, { minimum: 0 }] }, 1)).toMatchObject([
      {
        jsonPath: '$',
        message: "1 is valid under each of {'type': 'number'}, {'minimum': 0}",
        keyword: 'oneOf',
      },
    ]);
  });

  it('stamps CPython validator / validator_value / schema on each error', () => {
    // Leaf keyword error: stamped with ITS OWN keyword, not an ancestor's
    // (CPython `descend` preserves the leaf validator).
    const node = { type: 'object', properties: { n: { minimum: 3 } } };
    const [minErr] = iterErrors(node, { n: 1 });
    expect(minErr).toMatchObject({
      jsonPath: '$.n',
      keyword: 'minimum',
      validatorValue: 3,
      schema: { minimum: 3 },
    });

    // `required` error: keyword 'required', validator_value the schema list
    // (the public formatter keeps the upstream message for this keyword only).
    const [reqErr] = iterErrors({ required: ['a', 'b'] }, {});
    expect(reqErr).toMatchObject({
      keyword: 'required',
      validatorValue: ['a', 'b'],
      message: "'a' is a required property",
    });

    // Boolean `false` schema: CPython yields validator=None / validator_value=
    // None, mirrored as null (rendered by the formatter as 'schema').
    const [falseErr] = iterErrors({ properties: { x: false } }, { x: 1 });
    expect(falseErr).toMatchObject({
      jsonPath: '$.x',
      keyword: null,
      validatorValue: null,
      schema: false,
    });
  });

  it('throws for missing $ref targets', () => {
    expect(() =>
      iterErrors({ $ref: '#/$defs/missing', $defs: {} }, 'x'),
    ).toThrow("schema-validator: unresolved $ref '#/$defs/missing'");
  });

  it('throws for malformed $ref JSON Pointers', () => {
    expect(() =>
      iterErrors({ $ref: '#/$defs/~2bad', $defs: {} }, 'x'),
    ).toThrow("schema-validator: malformed $ref '#/$defs/~2bad'");
  });

  it('throws for unsupported external $refs', () => {
    expect(() => iterErrors({ $ref: 'https://example.com/schema.json' }, 'x')).toThrow(
      "schema-validator: unsupported $ref 'https://example.com/schema.json'; only intra-document JSON Pointer refs are supported",
    );
  });

  it('throws for cyclic $refs', () => {
    const cyclicSchema = {
      $ref: '#/$defs/self',
      $defs: {
        self: { $ref: '#/$defs/self' },
      },
    };
    expect(() => iterErrors(cyclicSchema, 'x')).toThrow(
      "schema-validator: cyclic $ref '#/$defs/self'",
    );
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
