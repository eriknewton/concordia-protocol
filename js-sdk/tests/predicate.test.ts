import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { KeyPair } from '../src/crypto/signing.js';
import {
  Predicate,
  PredicateValidationError,
  serializePredicateCanonical,
  signPredicate,
  verifyPredicate,
  validatePredicateForWrite,
  type PredicateResolver,
} from '../src/predicate/predicate.js';
import { validateConditionForProfile } from '../src/predicate/profiles.js';
import {
  validateReference,
  ReferenceValidationError,
} from '../src/predicate/references.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface VerifyOutcome {
  valid: boolean;
  failure_reason: string | null;
  verified_subject: string | null;
  verified_authority: string | null;
  predicate_id: string | null;
  issuer: string | null;
  checks: Record<string, boolean>;
  errors: string[];
  warnings: string[];
  revoked_at: string | null;
  tier: string | null;
}

interface PredicateFixtures {
  seed_hex: string;
  public_key_b64: string;
  other_public_key_b64: string;
  sign_cases: Array<{
    name: string;
    signed_predicate: Record<string, unknown>;
    expected_canonical: string;
    expected_signature: string;
    expected_verify: VerifyOutcome;
  }>;
  verify_fail_cases: Array<{
    name: string;
    predicate: Record<string, unknown>;
    expected_verify: VerifyOutcome;
  }>;
  profile_cases: Array<{
    name: string;
    type_id: string;
    condition: unknown;
    expected_errors: string[];
  }>;
  write_cases: Array<{
    name: string;
    predicate: Record<string, unknown>;
    expected_error: string | null;
  }>;
  reference_cases: Array<{
    name: string;
    ref: unknown;
    index: number;
    normalized: Record<string, unknown> | null;
    error: string | null;
  }>;
  condition_type_cases: Array<{
    name: string;
    type_id: string;
    condition: unknown;
    expected_profile_errors: string[];
    expected_write_error: string | null;
  }>;
  metadata_cases: Array<{
    name: string;
    metadata: unknown;
    signs: boolean;
  }>;
  iso_error_cases: Array<{
    name: string;
    predicate: Record<string, unknown>;
    expected_write_error: string | null;
  }>;
  deferred_revocation: {
    signed_predicate: Record<string, unknown>;
    referenced_artifact_id: string;
    revocation_record: Record<string, unknown>;
    now: string;
    expected_verify_without: VerifyOutcome;
    expected_verify_with: VerifyOutcome;
  };
}

const fixtures = JSON.parse(
  readFileSync(
    join(__dirname, 'fixtures/predicate/predicate_vectors.json'),
    'utf8',
  ),
) as PredicateFixtures;

function seedKeyPair(): KeyPair {
  return KeyPair.fromPrivateKey(
    new Uint8Array(Buffer.from(fixtures.seed_hex, 'hex')),
  );
}

/**
 * Reconstruct a signed-predicate input dict for signing: take the
 * Python-produced signed predicate, drop the signature and the signer-injected
 * metadata so the TS signer regenerates both. This proves the TS signer
 * reproduces Python's full sign path (metadata injection + canonical bytes +
 * Ed25519) and not merely a copied signature.
 */
function signingInputFromSigned(
  signed: Record<string, unknown>,
): Record<string, unknown> {
  const input = { ...signed };
  delete input.signature;
  // The Python signer injects metadata.issuer_public_key_b64. If that was the
  // only metadata key, drop metadata entirely so the TS signer re-injects it.
  const metadata = input.metadata as Record<string, unknown> | undefined;
  if (
    metadata &&
    Object.keys(metadata).length === 1 &&
    'issuer_public_key_b64' in metadata
  ) {
    delete input.metadata;
  }
  return input;
}

describe('Predicate - canonical signing bytes parity with Python', () => {
  for (const c of fixtures.sign_cases) {
    it(`${c.name}: serializePredicateCanonical matches Python`, () => {
      const predicate = Predicate.fromDict(c.signed_predicate);
      const bytes = serializePredicateCanonical(predicate);
      expect(bytes.toString('utf8')).toBe(c.expected_canonical);
    });

    it(`${c.name}: canonical bytes match for a raw dict too`, () => {
      const bytes = serializePredicateCanonical(c.signed_predicate);
      expect(bytes.toString('utf8')).toBe(c.expected_canonical);
    });
  }
});

describe('Predicate - signature parity with Python (signPredicate)', () => {
  const kp = seedKeyPair();

  it('derives the Python-identical issuer public key', () => {
    expect(kp.publicKeyB64()).toBe(fixtures.public_key_b64);
  });

  for (const c of fixtures.sign_cases) {
    it(`${c.name}: signPredicate reproduces the Python signature`, () => {
      const input = signingInputFromSigned(c.signed_predicate);
      const signed = signPredicate(input, kp);
      expect(signed.signature).toBe(c.expected_signature);
    });

    it(`${c.name}: signPredicate injects the Python-identical metadata`, () => {
      const input = signingInputFromSigned(c.signed_predicate);
      const signed = signPredicate(input, kp);
      // The signed predicate's full dict must equal Python's signed dict.
      expect(signed.toDict()).toEqual(c.signed_predicate);
    });
  }
});

describe('Predicate - verification outcome parity (valid cases)', () => {
  for (const c of fixtures.sign_cases) {
    it(`${c.name}: verifyPredicate matches Python (valid)`, () => {
      const result = verifyPredicate(Predicate.fromDict(c.signed_predicate));
      expect(result).toEqual(c.expected_verify);
    });

    it(`${c.name}: verifyPredicate accepts a raw dict identically`, () => {
      const result = verifyPredicate(c.signed_predicate);
      expect(result).toEqual(c.expected_verify);
    });
  }
});

describe('Predicate - verification outcome parity (failure cases)', () => {
  for (const c of fixtures.verify_fail_cases) {
    it(`${c.name}: verifyPredicate matches Python failure outcome`, () => {
      const result = verifyPredicate(c.predicate);
      // failure_reason and the check map are the load-bearing fields a policy
      // engine reads; assert the whole outcome object for full parity.
      expect(result.valid).toBe(c.expected_verify.valid);
      expect(result.failure_reason).toBe(c.expected_verify.failure_reason);
      expect(result.checks).toEqual(c.expected_verify.checks);
      expect(result).toEqual(c.expected_verify);
    });
  }
});

describe('Predicate - type-profile gate parity (validateConditionForProfile)', () => {
  for (const c of fixtures.profile_cases) {
    it(`${c.name}: error list matches Python jsonschema output`, () => {
      const errors = validateConditionForProfile(c.type_id, c.condition);
      expect(errors).toEqual(c.expected_errors);
    });
  }
});

describe('Predicate - write-validation parity (validatePredicateForWrite)', () => {
  for (const c of fixtures.write_cases) {
    it(`${c.name}: matches Python validate_predicate_for_write`, () => {
      if (c.expected_error === null) {
        expect(() => validatePredicateForWrite(c.predicate)).not.toThrow();
      } else {
        let thrown: unknown;
        try {
          validatePredicateForWrite(c.predicate);
        } catch (err) {
          thrown = err;
        }
        expect(thrown).toBeInstanceOf(PredicateValidationError);
        expect((thrown as Error).message).toBe(c.expected_error);
      }
    });
  }
});

describe('Predicate - reference normalization parity (validateReference)', () => {
  for (const c of fixtures.reference_cases) {
    it(`${c.name}: matches Python _validate_reference`, () => {
      if (c.error === null) {
        const normalized = validateReference(c.ref, c.index);
        expect(normalized).toEqual(c.normalized);
      } else {
        let thrown: unknown;
        try {
          validateReference(c.ref, c.index);
        } catch (err) {
          thrown = err;
        }
        expect(thrown).toBeInstanceOf(ReferenceValidationError);
        expect((thrown as Error).message).toBe(c.error);
      }
    });
  }
});

describe('Predicate - sign/verify round-trip with a fresh key', () => {
  it('signs and verifies a freshly generated predicate end-to-end', () => {
    const kp = KeyPair.generate();
    const signed = signPredicate(
      {
        predicate_id: 'urn:concordia:predicate:roundtrip',
        type: 'urn:concordia:predicate-type:authority_gate:v1',
        authority: 'urn:concordia:authority:test',
        issuer: 'did:web:issuer.test#key-1',
        subject: 'did:web:subject.test#agent',
        condition: { result: 'satisfied' },
        issued_at: '2026-05-14T00:00:00Z',
        expires_at: '2126-06-14T00:00:00Z',
        references: [],
        algorithm: 'EdDSA',
        status: 'active',
        signature: '',
      },
      kp,
    );
    const result = verifyPredicate(signed);
    expect(result.valid).toBe(true);
    expect(result.failure_reason).toBeNull();
    expect(result.verified_subject).toBe('did:web:subject.test#agent');
  });

  it('rejects a non-EdDSA signing request, matching Python', () => {
    const kp = KeyPair.generate();
    expect(() =>
      signPredicate(
        {
          predicate_id: 'urn:concordia:predicate:es256',
          type: 'urn:concordia:predicate-type:authority_gate:v1',
          authority: 'urn:concordia:authority:test',
          issuer: 'did:web:issuer.test#key-1',
          subject: 'did:web:subject.test#agent',
          condition: { result: 'satisfied' },
          issued_at: '2026-05-14T00:00:00Z',
          expires_at: '2126-06-14T00:00:00Z',
          references: [],
          algorithm: 'ES256',
          status: 'active',
          signature: '',
        },
        kp,
      ),
    ).toThrow(PredicateValidationError);
  });
});

// ---------------------------------------------------------------------------
// FINDING #3 (fail-OPEN, fixed): year-9999 expiry overflow in the predicate
// verifier. A year-9999 (or year-0001) expires_at/issued_at with a tz offset
// that pushes the UTC instant past datetime.max/min parses through CPython
// `fromisoformat`, but `_parse_datetime`'s `.astimezone(timezone.utc)` raises
// OverflowError. Python's predicate `_schema_errors` wraps that in try/except
// and appends `str(exc)` == `date value out of range`, so such a predicate FAILS
// the schema check (verify -> schema_invalid) AND `sign_predicate` /
// `validate_predicate_for_write` raise. The TS verifier used a guard-less
// `Date.parse`, returned a finite far-future ms, and reported the predicate
// VALID -- a fail-OPEN vs Python. The shared CPython-faithful parser detects the
// overflow (returns null) and we throw the same `date value out of range` text.
// Confirmed against python3.12 (sign + verify both reject; failure_reason
// schema_invalid; errors == ["date value out of range"]).
describe('Predicate - Finding #3: year-9999 expiry overflow (fail-closed)', () => {
  const OVERFLOW = '9999-12-31T23:59:59-14:00'; // CPython astimezone OverflowError

  it('control: a far-future in-range expiry verifies (baseline)', () => {
    const kp = KeyPair.generate();
    const signed = signPredicate(
      baseSigningInput({ issuer: 'did:web:issuer.test#key-1' }),
      kp,
    );
    const result = verifyPredicate(signed);
    expect(result.valid).toBe(true);
  });

  it('verifyPredicate rejects an overflow expires_at as schema_invalid', () => {
    // A signature-less raw dict: the schema check runs first, so the overflow
    // expiry is caught at schema (matching Python's failure_reason ordering)
    // before the signature check is ever reached.
    const result = verifyPredicate(baseSigningInput({ expires_at: OVERFLOW }));
    expect(result.valid).toBe(false);
    expect(result.failure_reason).toBe('schema_invalid');
    expect(result.errors).toContain('date value out of range');
  });

  it('verifyPredicate rejects an overflow issued_at as schema_invalid', () => {
    const result = verifyPredicate(
      baseSigningInput({ issued_at: '0001-01-01T00:00:00+23:59' }),
    );
    expect(result.valid).toBe(false);
    expect(result.failure_reason).toBe('schema_invalid');
    expect(result.errors).toContain('date value out of range');
  });

  it('validatePredicateForWrite throws on an overflow expiry (sign path)', () => {
    let thrown: unknown;
    try {
      validatePredicateForWrite(baseSigningInput({ expires_at: OVERFLOW }));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(PredicateValidationError);
    expect((thrown as Error).message).toContain('date value out of range');
  });

  it('signPredicate refuses to sign an overflow-expiry predicate, matching Python', () => {
    const kp = KeyPair.generate();
    expect(() =>
      signPredicate(baseSigningInput({ expires_at: OVERFLOW }), kp),
    ).toThrow(PredicateValidationError);
  });
});

// A minimal valid predicate-signing input, mirroring the generator's
// `_base_predicate`, used to inject malformed condition / metadata values.
function baseSigningInput(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    predicate_id: 'urn:concordia:predicate:edge',
    type: 'urn:concordia:predicate-type:authority_gate:v1',
    authority: 'urn:concordia:authority:procurement',
    issuer: 'did:web:issuer.example#key-1',
    subject: 'did:web:buyer.example#agent',
    condition: { result: 'satisfied' },
    issued_at: '2026-05-14T00:00:00Z',
    expires_at: '2126-06-14T00:00:00Z',
    references: [],
    algorithm: 'EdDSA',
    status: 'active',
    signature: '',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// FINDING 1 (BLOCKER, fail-open): strict-dict `condition` check.
// Python gates `condition` on `isinstance(_, dict)`. A non-dict condition must
// be REJECTED by both the profile gate and the write/schema check.
// ---------------------------------------------------------------------------
describe('Predicate - Finding 1: strict-dict condition (profile + write)', () => {
  for (const c of fixtures.condition_type_cases) {
    it(`${c.name}: profile gate matches Python`, () => {
      expect(validateConditionForProfile(c.type_id, c.condition)).toEqual(
        c.expected_profile_errors,
      );
    });

    it(`${c.name}: write-validation matches Python`, () => {
      const pred = baseSigningInput({ condition: c.condition, signature: 'x' });
      if (c.expected_write_error === null) {
        expect(() => validatePredicateForWrite(pred)).not.toThrow();
      } else {
        let thrown: unknown;
        try {
          validatePredicateForWrite(pred);
        } catch (err) {
          thrown = err;
        }
        expect(thrown).toBeInstanceOf(PredicateValidationError);
        expect((thrown as Error).message).toBe(c.expected_write_error);
      }
    });
  }

  // Probe parity: a JS CLASS INSTANCE / Date / Map cannot be carried in a JSON
  // fixture, but Python rejects every non-dict, so the JS strict-dict check
  // must reject these too (the prior loose `typeof === 'object'` check accepted
  // them -> the fail-open the reviewer flagged).
  it('rejects a class-instance condition (Python rejects non-dict)', () => {
    class FakeCondition {
      result = 'satisfied';
    }
    expect(
      validateConditionForProfile(
        'urn:concordia:predicate-type:authority_gate:v1',
        new FakeCondition(),
      ),
    ).toEqual(['condition must be an object']);
    expect(() =>
      validatePredicateForWrite(
        baseSigningInput({ condition: new FakeCondition(), signature: 'x' }),
      ),
    ).toThrow(PredicateValidationError);
  });

  it('rejects a Date / Map condition (not a plain mapping)', () => {
    for (const value of [new Date(), new Map([['result', 'satisfied']])]) {
      expect(
        validateConditionForProfile(
          'urn:concordia:predicate-type:authority_gate:v1',
          value,
        ),
      ).toEqual(['condition must be an object']);
    }
  });
});

// ---------------------------------------------------------------------------
// FINDING 2 (BLOCKER, fail-open): metadata coercion.
// Python `sign_predicate` does `dict(metadata or {})`: a truthy non-mapping
// raises; a falsy value collapses to {}. `signPredicate` must throw iff Python
// raises (a loose spread `{...5}` would silently yield {} -> fail-open).
// ---------------------------------------------------------------------------
describe('Predicate - Finding 2: metadata coercion parity', () => {
  const kp = seedKeyPair();
  for (const c of fixtures.metadata_cases) {
    it(`${c.name} (${JSON.stringify(c.metadata)}): signs=${c.signs} matches Python`, () => {
      const input = baseSigningInput({ metadata: c.metadata });
      if (c.signs) {
        expect(() => signPredicate(input, kp)).not.toThrow();
      } else {
        expect(() => signPredicate(input, kp)).toThrow(PredicateValidationError);
      }
    });
  }

  it('rejects a class-instance metadata (Python dict(...) would raise)', () => {
    class FakeMeta {
      issuer_public_key_b64 = 'x';
    }
    expect(() =>
      signPredicate(baseSigningInput({ metadata: new FakeMeta() }), kp),
    ).toThrow(PredicateValidationError);
  });
});

// ---------------------------------------------------------------------------
// FINDING 3 (MAJOR): reference validation diagnostics.
// The non-dict type-name parity is already pinned by the new reference_cases
// (int/float/bool/None/list). These probes additionally pin the JS-only inputs
// (function, Date) that JSON cannot carry: both must FAIL CLOSED (rejected),
// and a function must report `function`, not the prior `dict` fallback.
// ---------------------------------------------------------------------------
describe('Predicate - Finding 3: reference diagnostics fail-closed', () => {
  it('rejects a function reference and names it `function`', () => {
    let thrown: unknown;
    try {
      validateReference(() => 1, 0);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(ReferenceValidationError);
    expect((thrown as Error).message).toBe(
      'references[0] must be a dict, got function per SPEC §11.5.6',
    );
  });

  it('rejects a Date reference (Python isinstance(_, dict) is False)', () => {
    expect(() => validateReference(new Date(), 0)).toThrow(
      ReferenceValidationError,
    );
  });

  it('rejects a Map reference (not a plain mapping)', () => {
    expect(() => validateReference(new Map(), 0)).toThrow(
      ReferenceValidationError,
    );
  });

  it('still accepts a genuine plain-object reference', () => {
    expect(
      validateReference(
        { type: 'predicate', id: 'urn:x', relationship: 'extends' },
        0,
      ),
    ).toEqual({ type: 'predicate', id: 'urn:x', relationship: 'extends' });
  });
});

// ---------------------------------------------------------------------------
// FINDING 4 (MAJOR): ISO-8601 error strings.
// Python surfaces datetime.fromisoformat's exact text in the validation error
// list. The write error for each malformed issued_at / expires_at must match.
// ---------------------------------------------------------------------------
describe('Predicate - Finding 4: ISO-8601 error-string parity', () => {
  for (const c of fixtures.iso_error_cases) {
    it(`${c.name}: write error matches Python fromisoformat text`, () => {
      let thrown: unknown;
      try {
        validatePredicateForWrite(c.predicate);
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(PredicateValidationError);
      // The malformed-datetime message is the load-bearing substring; assert it
      // appears verbatim in the joined error (other fields are valid here).
      expect((thrown as Error).message).toContain(c.expected_write_error);
    });
  }

  it('matches CPython leap-year boundary (2024-02-29 OK, 2026-02-29 reject)', () => {
    // 2024 is a leap year: this date is valid, so no datetime error fires.
    expect(() =>
      validatePredicateForWrite(
        baseSigningInput({ expires_at: '2024-02-29T00:00:00Z', signature: 'x' }),
      ),
    ).not.toThrow();
    // 2026 is not: CPython rejects with "day is out of range for month".
    let thrown: unknown;
    try {
      validatePredicateForWrite(
        baseSigningInput({ expires_at: '2026-02-29T00:00:00Z', signature: 'x' }),
      );
    } catch (err) {
      thrown = err;
    }
    expect((thrown as Error).message).toContain('day is out of range for month');
  });
});

// ---------------------------------------------------------------------------
// FINDING 5 (DEFERRED): revocation_records / now path.
// The cmpc revocation path is NOT ported in this PR (depends on the unported
// concordia.cmpc module). The no-revocation-records outcome is asserted today;
// the with-revocation-records outcome is pinned by a Python-generated fixture
// and an it.skip that documents the expected outcome once cmpc lands.
// ---------------------------------------------------------------------------
describe('Predicate - Finding 5: deferred revocation_records boundary', () => {
  const fx = fixtures.deferred_revocation;

  it('without revocation records: verifies VALID (parity today)', () => {
    const result = verifyPredicate(fx.signed_predicate);
    expect(result).toEqual(fx.expected_verify_without);
  });

  it.skip(
    'with revocation records: should fail REVOKED once concordia.cmpc is ported (deferred to PR-N)',
    () => {
      // When the cmpc revocation layer is ported, verifyPredicate should accept
      // { revocationRecords, now } and reproduce fx.expected_verify_with
      // (valid=false, failure_reason="revoked", checks.revocation_records=false,
      // errors=["referenced artifact revoked by <revocation_id>"]).
      expect(fx.expected_verify_with.valid).toBe(false);
      expect(fx.expected_verify_with.failure_reason).toBe('revoked');
    },
  );
});

describe('Predicate - resolver-based reference binding', () => {
  it('reports resolver_miss when a referenced predicate is unresolvable', () => {
    const kp = seedKeyPair();
    const signed = signPredicate(
      {
        predicate_id: 'urn:concordia:predicate:needs_parent',
        type: 'urn:concordia:predicate-type:authority_gate:v1',
        authority: 'urn:concordia:authority:test',
        issuer: 'did:web:issuer.test#key-1',
        subject: 'did:web:subject.test#agent',
        condition: { result: 'satisfied' },
        issued_at: '2026-05-14T00:00:00Z',
        expires_at: '2126-06-14T00:00:00Z',
        references: [
          {
            type: 'predicate',
            id: 'urn:concordia:predicate:missing_parent',
            relationship: 'extends',
          },
        ],
        algorithm: 'EdDSA',
        status: 'active',
        signature: '',
      },
      kp,
    );
    const emptyResolver: PredicateResolver = () => null;
    const result = verifyPredicate(signed, { resolver: emptyResolver });
    expect(result.valid).toBe(false);
    expect(result.failure_reason).toBe('resolver_miss');
    // The resolver runs after schema + profile, before signature.
    expect(result.checks.schema).toBe(true);
    expect(result.checks.profile_condition).toBe(true);
    expect(result.checks.signature).toBeUndefined();
  });
});
