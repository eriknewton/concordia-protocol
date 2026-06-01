import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { KeyPair } from '../src/crypto/signing.js';
import { fromBase64Url } from '../src/crypto/base64url.js';
import {
  type Mandate,
  type DelegationLink,
  type ValidityWindow,
  mandateFromDict,
  delegationLinkFromDict,
  validityWindowFromDict,
  makeValidityWindow,
  TemporalMode,
  signMandate,
  signDelegation,
  validateMandateSchema,
  validateConstraints,
  scopeRestrictionToSchema,
  composeEffectiveConstraints,
  checkTemporalValidity,
  verifyDelegationChain,
  verifyMandate,
  mandateToDict,
  delegationLinkToDict,
  mandateVerificationResultToDict,
  MandateValidationError,
} from '../src/mandate/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Fixture shapes (Python-generated; see scripts/gen-mandate-engine-fixtures.py).
// ---------------------------------------------------------------------------

interface KeyEntry {
  seed_b64: string;
  public_b64: string;
}
interface SignCase {
  name: string;
  input_to_dict: Record<string, unknown>;
  signature: string;
  signed_to_dict: Record<string, unknown>;
}
interface SchemaCase {
  name: string;
  input: Record<string, unknown>;
  errors: string[];
}
interface ConstraintCase {
  name: string;
  constraints: Record<string, unknown>;
  action: Record<string, unknown> | null;
  compliant: boolean;
  errors: string[];
}
interface ScopeCase {
  name: string;
  scope: Record<string, unknown>;
  schema: Record<string, unknown> | null;
  errors: string[];
}
interface ComposeCase {
  name: string;
  constraints: Record<string, unknown>;
  chain: Record<string, unknown>[];
  effective: Record<string, unknown> | null;
  errors: string[];
}
interface TemporalCase {
  name: string;
  validity: Record<string, unknown>;
  now: string;
  sequence_key: string | null;
  state_active: boolean | null;
  valid: boolean;
  errors: string[];
}
interface NaiveTemporalCase {
  name: string;
  validity: Record<string, unknown>;
  now: string;
  // Python RAISES (TypeError) rather than returning; recorded for the contract.
  python_raises: { type: string; message: string };
  ts_valid: boolean;
}
interface NaiveVerifyCase {
  _comment: string;
  mandate_dict: Record<string, unknown>;
  issuer_key: string;
  now: string;
  python_raises: { type: string; message: string };
  ts_valid: boolean;
}
interface ChainCase {
  name: string;
  chain: Record<string, unknown>[];
  issuer: string;
  subject: string;
  public_keys: Record<string, string>; // agent_id -> named key (issuer/mid/leaf/wrong)
  valid: boolean;
  errors: string[];
}
interface VerifyCase {
  name: string;
  mandate_dict: Record<string, unknown>;
  issuer_key: string;
  now: string;
  sequence_key: string | null;
  state_active: boolean | null;
  action: Record<string, unknown> | null;
  delegation_keys: Record<string, string> | null;
  check_revocation_status: boolean;
  require_binding_context: boolean;
  result: Record<string, unknown>;
}
interface EngineFixtures {
  keys: Record<string, KeyEntry>;
  clock: { now: string; now_before: string; now_after: string };
  sign_mandate_cases: SignCase[];
  sign_delegation_cases: SignCase[];
  schema_cases: SchemaCase[];
  constraint_cases: ConstraintCase[];
  scope_cases: ScopeCase[];
  compose_cases: ComposeCase[];
  temporal_cases: TemporalCase[];
  naive_temporal_cases: NaiveTemporalCase[];
  chain_cases: ChainCase[];
  verify_cases: VerifyCase[];
  naive_verify_case: NaiveVerifyCase;
  deferred_revocation_case: {
    _comment: string;
    mandate_dict: Record<string, unknown>;
    issuer_key: string;
    now: string;
  };
}

const fixtures = JSON.parse(
  readFileSync(
    join(__dirname, 'fixtures/mandate/mandate_engine_vectors.json'),
    'utf8',
  ),
) as EngineFixtures;

// ---------------------------------------------------------------------------
// Helpers: reconstruct the deterministic KeyPairs from the Python seeds, and
// the camelCase TS mandate/link models from the snake_case wire dicts.
// ---------------------------------------------------------------------------

function keyPairFor(named: string): KeyPair {
  const entry = fixtures.keys[named];
  if (entry === undefined) {
    throw new Error(`unknown key name: ${named}`);
  }
  const seed = fromBase64Url(entry.seed_b64);
  return KeyPair.fromPrivateKey(seed);
}

function publicKeyBytesFor(named: string): Uint8Array {
  return keyPairFor(named).publicKey;
}

function epochMs(iso: string): number {
  return Date.parse(iso);
}

// ---------------------------------------------------------------------------
// sign_mandate / sign_delegation: byte-identical signatures.
// ---------------------------------------------------------------------------

describe('signMandate - byte parity with Python sign_mandate', () => {
  for (const c of fixtures.sign_mandate_cases) {
    it(`case ${c.name}`, () => {
      // Rebuild the mandate from the Python signed_to_dict (minus signature) so
      // the TS-side signing input is identical, then sign with the issuer key.
      const unsigned: Record<string, unknown> = { ...c.signed_to_dict };
      delete unsigned.signature;
      const mandate = mandateFromDict(unsigned);
      const signed = signMandate(mandate, keyPairFor('issuer'));
      expect(signed.signature).toBe(c.signature);
      // The full signed to_dict must match Python's byte-for-byte.
      expect(mandateToDict(signed)).toEqual(c.signed_to_dict);
    });
  }
});

describe('signDelegation - byte parity with Python sign_delegation', () => {
  // Cases are signed by the delegator: basic by issuer, scope case by mid.
  const keyByCase: Record<string, string> = {
    basic: 'issuer',
    with_scope_restriction: 'mid',
  };
  for (const c of fixtures.sign_delegation_cases) {
    it(`case ${c.name}`, () => {
      const unsigned: Record<string, unknown> = { ...c.signed_to_dict };
      delete unsigned.signature;
      const link = delegationLinkFromDict(unsigned);
      const signed = signDelegation(link, keyPairFor(keyByCase[c.name] ?? 'issuer'));
      expect(signed.signature).toBe(c.signature);
      expect(delegationLinkToDict(signed)).toEqual(c.signed_to_dict);
    });
  }
});

describe('signMandate / signDelegation - ES256 is deferred (throws)', () => {
  it('signMandate rejects ES256', () => {
    const m = mandateFromDict({
      mandate_id: 'urn:concordia:mandate:es',
      issuer: 'i',
      subject: 's',
      issued_at: '2026-05-14T00:00:00Z',
      constraints: { k: 'v' },
      algorithm: 'ES256',
    });
    expect(() => signMandate(m, keyPairFor('issuer'))).toThrow(
      MandateValidationError,
    );
  });
});

// ---------------------------------------------------------------------------
// validate_mandate_schema: error-string parity (ajv -> CPython jsonschema text).
// ---------------------------------------------------------------------------

describe('validateMandateSchema - error-string parity with Python jsonschema', () => {
  for (const c of fixtures.schema_cases) {
    it(`case ${c.name}`, () => {
      expect(validateMandateSchema(c.input)).toEqual(c.errors);
    });
  }
});

// ---------------------------------------------------------------------------
// validate_constraints.
// ---------------------------------------------------------------------------

describe('validateConstraints - parity with Python validate_constraints', () => {
  // The meta-schema-INVALID cases carry a jsonschema-internal error tail that is
  // version-coupled and not worth byte-pinning; for those we assert the boolean
  // + the stable "Constraint schema invalid: " PREFIX. Every other case
  // (empty, valid, action-pass, action-violate) is byte-pinned in full.
  const metaSchemaInvalid = new Set([
    'meta_schema_invalid_bad_type',
    'meta_schema_invalid_minimum_str',
  ]);
  for (const c of fixtures.constraint_cases) {
    it(`case ${c.name}`, () => {
      const [compliant, errors] = validateConstraints(
        c.constraints,
        c.action,
      );
      expect(compliant).toBe(c.compliant);
      if (metaSchemaInvalid.has(c.name)) {
        expect(errors).toHaveLength(1);
        expect(errors[0]).toContain('Constraint schema invalid: ');
        // The covered meta-schema cases DO reproduce the CPython tail; assert it.
        expect(errors).toEqual(c.errors);
      } else {
        expect(errors).toEqual(c.errors);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// _scope_restriction_to_schema.
// ---------------------------------------------------------------------------

describe('scopeRestrictionToSchema - parity with Python _scope_restriction_to_schema', () => {
  const metaSchemaInvalid = new Set(['bad_jsonschema']);
  for (const c of fixtures.scope_cases) {
    it(`case ${c.name}`, () => {
      const [schema, errors] = scopeRestrictionToSchema(c.scope);
      expect(schema).toEqual(c.schema);
      if (metaSchemaInvalid.has(c.name)) {
        expect(errors).toHaveLength(1);
        expect(errors[0]).toContain('unsupported_scope_restriction');
        expect(errors).toEqual(c.errors);
      } else {
        expect(errors).toEqual(c.errors);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// compose_effective_constraints.
// ---------------------------------------------------------------------------

describe('composeEffectiveConstraints - parity with Python', () => {
  for (const c of fixtures.compose_cases) {
    it(`case ${c.name}`, () => {
      const chain: DelegationLink[] = c.chain.map(delegationLinkFromDict);
      const [effective, errors] = composeEffectiveConstraints(
        c.constraints,
        chain,
      );
      expect(effective).toEqual(c.effective);
      expect(errors).toEqual(c.errors);
    });
  }
});

// ---------------------------------------------------------------------------
// check_temporal_validity.
// ---------------------------------------------------------------------------

describe('checkTemporalValidity - parity with Python check_temporal_validity', () => {
  for (const c of fixtures.temporal_cases) {
    it(`case ${c.name}`, () => {
      const vw: ValidityWindow = validityWindowFromDict(c.validity);
      const [valid, errors] = checkTemporalValidity(vw, {
        now: epochMs(c.now),
        sequenceKey: c.sequence_key,
        stateActive: c.state_active,
      });
      expect(valid).toBe(c.valid);
      expect(errors).toEqual(c.errors);
    });
  }
});

// ---------------------------------------------------------------------------
// check_temporal_validity - tz-NAIVE not_before/not_after must FAIL CLOSED.
//
// Python's `check_temporal_validity` parses a naive timestamp successfully but
// then raises `TypeError` comparing it against the tz-aware `now`; the
// `except ValueError` does NOT catch it, so the mandate is NOT honored. There
// is no Python (valid, errors) tuple to byte-match -- the fixture records the
// raised exception. TS has no uncaught-exception-aborts idiom here; the
// faithful behavioral mirror is to REJECT (valid=false), which is what the
// fix does. The pre-fix code appended a synthetic `"Z"` and HONORED the naive
// window -- the fail-OPEN this closes.
// ---------------------------------------------------------------------------

describe('checkTemporalValidity - tz-naive timestamps fail closed (Python raises TypeError)', () => {
  for (const c of fixtures.naive_temporal_cases) {
    it(`case ${c.name}`, () => {
      // Confirm the fixture pins Python's TypeError, the behavior we mirror.
      expect(c.python_raises.type).toBe('TypeError');
      const vw: ValidityWindow = validityWindowFromDict(c.validity);
      const [valid, errors] = checkTemporalValidity(vw, {
        now: epochMs(c.now),
      });
      // TS must NOT honor a window Python refuses to honor.
      expect(valid).toBe(false);
      expect(c.ts_valid).toBe(false);
      // The rejection names the tz-naive problem (it is a valid isoformat, so
      // it must NOT be mislabeled as an "Invalid timestamp format").
      expect(errors).toHaveLength(1);
      expect(errors[0]).toContain('Timezone-naive timestamp not permitted');
    });
  }

  it('valid offset / Z timestamps still verify unchanged', () => {
    // Z form.
    const z = makeValidityWindow({
      mode: TemporalMode.WINDOWED,
      notBefore: '2026-05-14T00:00:00Z',
      notAfter: '2126-06-14T00:00:00Z',
    });
    expect(
      checkTemporalValidity(z, { now: epochMs('2026-06-01T00:00:00Z') })[0],
    ).toBe(true);
    // Explicit +00:00 offset.
    const off = makeValidityWindow({
      mode: TemporalMode.WINDOWED,
      notBefore: '2026-05-14T00:00:00+00:00',
      notAfter: '2126-06-14T00:00:00+00:00',
    });
    expect(
      checkTemporalValidity(off, { now: epochMs('2026-06-01T00:00:00Z') })[0],
    ).toBe(true);
    // Non-UTC offset (still tz-aware -> honored).
    const tokyo = makeValidityWindow({
      mode: TemporalMode.WINDOWED,
      notBefore: '2026-05-14T09:00:00+09:00',
      notAfter: '2126-06-14T00:00:00Z',
    });
    expect(
      checkTemporalValidity(tokyo, { now: epochMs('2026-06-01T00:00:00Z') })[0],
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// verify_delegation_chain.
// ---------------------------------------------------------------------------

describe('verifyDelegationChain - parity with Python verify_delegation_chain', () => {
  for (const c of fixtures.chain_cases) {
    it(`case ${c.name}`, () => {
      const chain: DelegationLink[] = c.chain.map(delegationLinkFromDict);
      const publicKeys: Record<string, Uint8Array> = {};
      for (const [agentId, named] of Object.entries(c.public_keys)) {
        publicKeys[agentId] = publicKeyBytesFor(named);
      }
      const [valid, errors] = verifyDelegationChain(
        chain,
        c.issuer,
        c.subject,
        publicKeys,
      );
      expect(valid).toBe(c.valid);
      expect(errors).toEqual(c.errors);
    });
  }
});

// ---------------------------------------------------------------------------
// verify_mandate end-to-end.
// ---------------------------------------------------------------------------

describe('verifyMandate - end-to-end parity with Python verify_mandate', () => {
  for (const c of fixtures.verify_cases) {
    it(`case ${c.name}`, () => {
      const issuerKey = publicKeyBytesFor(c.issuer_key);
      let delegationKeys: Record<string, Uint8Array> | null = null;
      if (c.delegation_keys !== null) {
        delegationKeys = {};
        for (const [agentId, named] of Object.entries(c.delegation_keys)) {
          delegationKeys[agentId] = publicKeyBytesFor(named);
        }
      }
      const result = verifyMandate(c.mandate_dict, issuerKey, {
        now: epochMs(c.now),
        sequenceKey: c.sequence_key,
        stateActive: c.state_active,
        action: c.action,
        delegationPublicKeys: delegationKeys,
        checkRevocationStatus: c.check_revocation_status,
        requireBindingContext: c.require_binding_context,
      });
      // Strongest parity check: the TS result's wire form (via the merged
      // mandateVerificationResultToDict) must equal Python's
      // MandateVerificationResult.to_dict() byte-for-byte -- same keys, same
      // conditional omission (failure_reason only when non-null), same
      // error/warning strings.
      const tsDict = mandateVerificationResultToDict(result);
      expect(tsDict).toEqual(c.result);
      // `toEqual` is order-insensitive; the `checks` map key ORDER is
      // load-bearing (it encodes which checks ran, in sequence), so assert it
      // explicitly against Python's insertion order.
      expect(Object.keys(tsDict.checks as Record<string, boolean>)).toEqual(
        Object.keys(c.result.checks as Record<string, boolean>),
      );
    });
  }
});

// ---------------------------------------------------------------------------
// verifyMandate end-to-end - a signed mandate with a tz-NAIVE not_before must
// fail CLOSED. Python verify_mandate reaches check_temporal_validity, which
// raises TypeError on the naive-vs-aware comparison (uncaught), so the mandate
// is NOT honored. TS must report it not-honored (valid false, temporal_validity
// false) -- never HONOR the naive window. This is the closed fail-open.
// ---------------------------------------------------------------------------

describe('verifyMandate - tz-naive temporal field fails closed (Python raises)', () => {
  it('does not honor a signed mandate whose not_before is tz-naive', () => {
    const c = fixtures.naive_verify_case;
    expect(c.python_raises.type).toBe('TypeError');
    const issuerKey = publicKeyBytesFor(c.issuer_key);
    const result = verifyMandate(c.mandate_dict, issuerKey, {
      now: epochMs(c.now),
      requireBindingContext: true,
    });
    expect(result.valid).toBe(false);
    expect(c.ts_valid).toBe(false);
    expect(result.checks.temporal_validity).toBe(false);
    // The signature still verifies (the mandate is genuinely signed); the
    // rejection is specifically temporal, naming the tz-naive cause.
    expect(result.checks.issuer_signature).toBe(true);
    expect(
      result.errors.some((e) =>
        e.includes('Timezone-naive timestamp not permitted'),
      ),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DEFERRED: revocation network fetch. Python verify_mandate with
// check_revocation_status=true + an endpoint calls check_revocation (urllib
// GET). The TS engine defers the network fetch: with no revocationChecker
// injected and a fetch required, it throws (no fail-open). This skipped test
// pins the boundary; when the fetch is ported the assertion becomes a real
// revocation outcome. The boundary CASE (endpoint set, check disabled -> no
// fetch, revocation_status true) IS exercised live above
// (revocation_endpoint_set_but_check_disabled).
// ---------------------------------------------------------------------------

describe('verifyMandate - revocation network fetch (DEFERRED)', () => {
  it('throws (no fail-open) when a fetch is required but no checker injected', () => {
    const c = fixtures.deferred_revocation_case;
    const issuerKey = publicKeyBytesFor(c.issuer_key);
    expect(() =>
      verifyMandate(c.mandate_dict, issuerKey, {
        now: epochMs(c.now),
        checkRevocationStatus: true,
      }),
    ).toThrow(MandateValidationError);
  });

  it('an injected revocationChecker supplies the revocation outcome', () => {
    const c = fixtures.deferred_revocation_case;
    const issuerKey = publicKeyBytesFor(c.issuer_key);
    // A checker that reports the mandate revoked -> verify fails on revocation.
    const revoked = verifyMandate(c.mandate_dict, issuerKey, {
      now: epochMs(c.now),
      checkRevocationStatus: true,
      revocationChecker: (mandateId) => [
        false,
        [`Mandate '${mandateId}' has been revoked`],
      ],
    });
    expect(revoked.valid).toBe(false);
    expect(revoked.checks.revocation_status).toBe(false);

    // A checker that reports not-revoked -> verify passes.
    const ok = verifyMandate(c.mandate_dict, issuerKey, {
      now: epochMs(c.now),
      checkRevocationStatus: true,
      revocationChecker: () => [true, []],
    });
    expect(ok.valid).toBe(true);
    expect(ok.checks.revocation_status).toBe(true);
  });

  // Documents the eventual ported-fetch outcome (skipped until the urllib fetch
  // lands in a future PR — see engine.ts module docblock + the generator's
  // deferred_revocation_case comment).
  it.skip('ported network fetch returns the live revocation outcome', () => {
    // Once a default urllib-style checker is ported, verifyMandate with
    // check_revocation_status=true + no injected checker should fetch the
    // endpoint and produce the same (not_revoked, errors) Python's
    // check_revocation returns. Pinned here so the boundary is explicit.
    expect(true).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Sanity: a hand-built round-trip (sign then verify) succeeds, exercising the
// merged crypto + this engine without a fixture (smoke of the public API).
// ---------------------------------------------------------------------------

describe('signMandate -> verifyMandate round-trip (smoke)', () => {
  it('a freshly signed windowed mandate verifies valid', () => {
    const kp = keyPairFor('issuer');
    const validity: ValidityWindow = makeValidityWindow({
      mode: TemporalMode.WINDOWED,
      notBefore: '2026-05-14T00:00:00Z',
      notAfter: '2126-06-14T00:00:00Z',
    });
    const mandate: Mandate = mandateFromDict({
      mandate_id: 'urn:concordia:mandate:smoke',
      issuer: 'did:web:issuer',
      subject: 'did:web:subject',
      issued_at: '2026-05-14T00:00:00Z',
      validity: validityWindowToDictLocal(validity),
      constraints: { type: 'object', properties: { x: { type: 'number' } } },
      algorithm: 'EdDSA',
    });
    const signed = signMandate(mandate, kp);
    const result = verifyMandate(signed, kp.publicKey, {
      now: epochMs('2026-06-01T00:00:00Z'),
      checkRevocationStatus: false,
    });
    expect(result.valid).toBe(true);
  });
});

// Minimal local helper to avoid importing validityWindowToDict into the smoke
// test's import block twice; mirrors the wire form a Mandate dict expects.
function validityWindowToDictLocal(vw: ValidityWindow): Record<string, unknown> {
  const d: Record<string, unknown> = { mode: vw.mode };
  if (vw.notBefore != null) d.not_before = vw.notBefore;
  if (vw.notAfter != null) d.not_after = vw.notAfter;
  if (vw.sequenceKey != null) d.sequence_key = vw.sequenceKey;
  if (vw.stateCondition != null) d.state_condition = vw.stateCondition;
  if (vw.maxUses != null) d.max_uses = vw.maxUses;
  return d;
}
