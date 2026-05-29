import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { canonicalizeJcs } from '../src/canonical/index.js';
import {
  TemporalMode,
  MandateStatus,
  MandateValidationError,
  type DelegationLink,
  delegationLinkToDict,
  delegationLinkFromDict,
  makeDelegationLink,
  type ValidityWindow,
  validityWindowToDict,
  validityWindowFromDict,
  makeValidityWindow,
  type Mandate,
  makeMandate,
  mandateToDict,
  mandateFromDict,
  createMandate,
  type MandateVerificationResult,
  makeMandateVerificationResult,
  mandateVerificationResultToDict,
  MANDATE_JSON_SCHEMA,
  CONSTRAINT_PATTERNS,
} from '../src/mandate/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface ToDictCase {
  name: string;
  to_dict: Record<string, unknown>;
}
interface RoundtripCase {
  name: string;
  input: Record<string, unknown>;
  to_dict: Record<string, unknown>;
}
interface ErrorCase {
  name: string;
  input: Record<string, unknown>;
  error: string;
}

interface MandateFixtures {
  enums: Record<string, Record<string, string>>;
  delegation_to_dict_cases: ToDictCase[];
  delegation_from_dict_cases: RoundtripCase[];
  delegation_from_dict_errors: ErrorCase[];
  validity_to_dict_cases: ToDictCase[];
  validity_from_dict_cases: RoundtripCase[];
  validity_from_dict_errors: ErrorCase[];
  mandate_to_dict_cases: ToDictCase[];
  mandate_from_dict_cases: RoundtripCase[];
  result_to_dict_cases: ToDictCase[];
  schema_constants: Record<
    string,
    { value: Record<string, unknown>; canonical: string }
  >;
}

const fixtures = JSON.parse(
  readFileSync(join(__dirname, 'fixtures/mandate/mandate_vectors.json'), 'utf8'),
) as MandateFixtures;

// ---------------------------------------------------------------------------
// Enum value parity.
// ---------------------------------------------------------------------------

const TS_ENUMS: Record<string, Record<string, string>> = {
  TemporalMode,
  MandateStatus,
};

describe('mandate enums - value parity with Python concordia.models.mandate', () => {
  for (const [enumName, pyMap] of Object.entries(fixtures.enums)) {
    it(`${enumName} maps every member name to the Python value`, () => {
      const tsMap = TS_ENUMS[enumName];
      expect(tsMap, `TS enum ${enumName} is exported`).toBeDefined();
      expect(Object.keys(tsMap).sort()).toEqual(Object.keys(pyMap).sort());
      for (const [member, value] of Object.entries(pyMap)) {
        expect(tsMap[member]).toBe(value);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// DelegationLink.
// ---------------------------------------------------------------------------

// Build a DelegationLink from the snake_case wire dict the fixtures used as
// Python constructor input, mapping to the camelCase TS shape.
function delegationFromWire(d: Record<string, unknown>): DelegationLink {
  return makeDelegationLink({
    delegator: d.delegator as string,
    delegate: d.delegate as string,
    scopeRestriction:
      'scope_restriction' in d
        ? (d.scope_restriction as Record<string, unknown> | null)
        : null,
    delegatedAt: (d.delegated_at as string) ?? '',
    signature: (d.signature as string) ?? '',
    algorithm: (d.algorithm as string) ?? 'EdDSA',
  });
}

// The fixture only records the OUTPUT to_dict, so re-derive the TS input from
// the expected output (it is the to_dict of a link built from the same fields).
// We reconstruct the link from the to_dict and assert round-trip identity, plus
// hand-build the same links to assert ordering/omission. To keep this faithful
// to "fixtures from Python", we drive each case by reconstructing a TS link
// whose serialization MUST equal the recorded Python to_dict.
describe('delegationLinkToDict - parity with DelegationLink.to_dict()', () => {
  for (const { name, to_dict } of fixtures.delegation_to_dict_cases) {
    it(`case ${name}`, () => {
      // Reconstruct the link from the Python-recorded wire dict and re-serialize.
      const link = delegationFromWire(to_dict);
      const out = delegationLinkToDict(link);
      expect(out).toEqual(to_dict);
      // Key ORDER parity: canonical bytes are key-sorted, but to_dict insertion
      // order must match Python for structural-equality consumers.
      expect(Object.keys(out)).toEqual(Object.keys(to_dict));
    });
  }

  it('omits scope_restriction when null but emits an empty-object restriction', () => {
    expect(
      delegationLinkToDict(
        makeDelegationLink({ delegator: 'a', delegate: 'b' }),
      ),
    ).not.toHaveProperty('scope_restriction');
    expect(
      delegationLinkToDict(
        makeDelegationLink({
          delegator: 'a',
          delegate: 'b',
          scopeRestriction: {},
        }),
      ),
    ).toHaveProperty('scope_restriction', {});
  });
});

describe('delegationLinkFromDict - parity with DelegationLink.from_dict()', () => {
  for (const { name, input, to_dict } of fixtures.delegation_from_dict_cases) {
    it(`case ${name} round-trips to Python to_dict`, () => {
      const link = delegationLinkFromDict(input);
      expect(delegationLinkToDict(link)).toEqual(to_dict);
    });
  }

  for (const { name, input, error } of fixtures.delegation_from_dict_errors) {
    it(`case ${name} raises with Python's exact KeyError text`, () => {
      let thrown: Error | null = null;
      try {
        delegationLinkFromDict(input);
      } catch (err) {
        thrown = err as Error;
      }
      expect(thrown).toBeInstanceOf(MandateValidationError);
      expect(thrown?.message).toBe(error);
    });
  }
});

// ---------------------------------------------------------------------------
// ValidityWindow.
// ---------------------------------------------------------------------------

function validityFromWire(d: Record<string, unknown>): ValidityWindow {
  return makeValidityWindow({
    mode: d.mode as TemporalMode,
    notBefore: 'not_before' in d ? (d.not_before as string) : null,
    notAfter: 'not_after' in d ? (d.not_after as string) : null,
    sequenceKey: 'sequence_key' in d ? (d.sequence_key as string) : null,
    stateCondition:
      'state_condition' in d ? (d.state_condition as string) : null,
    maxUses: 'max_uses' in d ? (d.max_uses as number) : null,
  });
}

describe('validityWindowToDict - parity with ValidityWindow.to_dict()', () => {
  for (const { name, to_dict } of fixtures.validity_to_dict_cases) {
    it(`case ${name}`, () => {
      const vw = validityFromWire(to_dict);
      const out = validityWindowToDict(vw);
      expect(out).toEqual(to_dict);
      expect(Object.keys(out)).toEqual(Object.keys(to_dict));
    });
  }

  it('always emits mode first and omits null optionals', () => {
    const out = validityWindowToDict(
      makeValidityWindow({ mode: TemporalMode.SEQUENCE }),
    );
    expect(out).toEqual({ mode: 'sequence' });
  });

  it('emits max_uses=0 (not-None guard, not truthiness)', () => {
    const out = validityWindowToDict(
      makeValidityWindow({ mode: TemporalMode.WINDOWED, maxUses: 0 }),
    );
    expect(out).toHaveProperty('max_uses', 0);
  });
});

describe('validityWindowFromDict - parity with ValidityWindow.from_dict()', () => {
  for (const { name, input, to_dict } of fixtures.validity_from_dict_cases) {
    it(`case ${name} round-trips to Python to_dict`, () => {
      const vw = validityWindowFromDict(input);
      expect(validityWindowToDict(vw)).toEqual(to_dict);
    });
  }

  for (const { name, input, error } of fixtures.validity_from_dict_errors) {
    it(`case ${name} raises with Python's exact error text`, () => {
      let thrown: Error | null = null;
      try {
        validityWindowFromDict(materializeSpecialFloats(input));
      } catch (err) {
        thrown = err as Error;
      }
      expect(thrown).toBeInstanceOf(MandateValidationError);
      expect(thrown?.message).toBe(error);
    });
  }
});

// The fixture encodes NaN / +Infinity / -Infinity `mode` values as a
// `{ __special_float__: 'nan' | 'inf' | '-inf' }` sentinel because those
// non-finite floats cannot survive a standard-JSON round-trip (Python json.dump
// emits the non-standard `NaN`/`Infinity` literals, which JS JSON.parse
// rejects). This rebuilds the real JS float so the value reaching
// validityWindowFromDict is the genuine non-finite number Python repr()'d.
function materializeSpecialFloats(
  input: Record<string, unknown>,
): Record<string, unknown> {
  const mode = input.mode;
  if (
    mode !== null &&
    typeof mode === 'object' &&
    !Array.isArray(mode) &&
    '__special_float__' in (mode as Record<string, unknown>)
  ) {
    const tag = (mode as Record<string, unknown>).__special_float__;
    const value =
      tag === 'nan' ? NaN : tag === 'inf' ? Infinity : -Infinity;
    return { ...input, mode: value };
  }
  return input;
}

// ---------------------------------------------------------------------------
// Mandate.
// ---------------------------------------------------------------------------

// Reconstruct a Mandate from the Python-recorded wire to_dict, then re-serialize
// and assert byte/structure parity. mandateFromDict already does this faithfully
// (it is the from_dict port), so we route through it -- a wire dict that Python's
// to_dict produced is, by construction, valid from_dict input.
describe('mandateToDict - parity with Mandate.to_dict()', () => {
  for (const { name, to_dict } of fixtures.mandate_to_dict_cases) {
    it(`case ${name}`, () => {
      const mandate = mandateFromDict(to_dict);
      const out = mandateToDict(mandate);
      expect(out).toEqual(to_dict);
      // Top-level insertion-order parity (the always-present keys must lead in
      // Python's exact order, conditionals follow).
      expect(Object.keys(out)).toEqual(Object.keys(to_dict));
    });
  }

  it('bare default mandate emits only the six always-present keys', () => {
    const out = mandateToDict(makeMandate());
    expect(Object.keys(out)).toEqual([
      'mandate_id',
      'issuer',
      'subject',
      'issued_at',
      'algorithm',
      'status',
    ]);
    expect(out.status).toBe('active');
    expect(out.algorithm).toBe('EdDSA');
  });

  it('omits empty constraints/metadata/chain but emits empty-string endpoint', () => {
    const out = mandateToDict(
      makeMandate({
        mandateId: 'urn:concordia:mandate:x',
        issuer: 'i',
        subject: 's',
        constraints: {},
        metadata: {},
        delegationChain: [],
        revocationEndpoint: '',
      }),
    );
    expect(out).not.toHaveProperty('constraints');
    expect(out).not.toHaveProperty('metadata');
    expect(out).not.toHaveProperty('delegation_chain');
    // Empty string is NOT None -> emitted (the not-None vs truthiness split).
    expect(out).toHaveProperty('revocation_endpoint', '');
  });
});

describe('mandateFromDict - parity with Mandate.from_dict()', () => {
  for (const { name, input, to_dict } of fixtures.mandate_from_dict_cases) {
    it(`case ${name} round-trips to Python to_dict`, () => {
      const mandate = mandateFromDict(input);
      expect(mandateToDict(mandate)).toEqual(to_dict);
    });
  }

  it('unknown status silently defaults to ACTIVE (fail-safe, matches Python)', () => {
    const mandate = mandateFromDict({
      mandate_id: 'urn:concordia:mandate:x',
      issuer: 'i',
      subject: 's',
      issued_at: '2026-05-14T00:00:00Z',
      constraints: { k: 'v' },
      status: 'bogus',
    });
    expect(mandate.status).toBe(MandateStatus.ACTIVE);
    expect(mandateToDict(mandate).status).toBe('active');
  });
});

describe('createMandate - factory shape parity with Mandate.create()', () => {
  it('produces a urn:concordia:mandate: id and Python-format timestamp', () => {
    const mandate = createMandate({
      issuer: 'i',
      subject: 's',
      constraints: { k: 'v' },
      validity: makeValidityWindow({ mode: TemporalMode.SEQUENCE }),
    });
    expect(mandate.mandateId).toMatch(/^urn:concordia:mandate:/);
    // Python strftime("%Y-%m-%dT%H:%M:%SZ"): whole-second precision, trailing Z.
    expect(mandate.issuedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(mandate.algorithm).toBe('EdDSA');
    expect(mandate.delegationChain).toEqual([]);
    expect(mandate.metadata).toEqual({});
    expect(mandate.revocationEndpoint).toBeNull();
  });

  it('honors injected clock for deterministic output', () => {
    const mandate = createMandate(
      {
        issuer: 'i',
        subject: 's',
        constraints: { k: 'v' },
        validity: makeValidityWindow({ mode: TemporalMode.SEQUENCE }),
        algorithm: 'ES256',
      },
      { now: () => '2026-05-14T00:00:00Z', uuid: () => 'fixed-uuid' },
    );
    expect(mandate.mandateId).toBe('urn:concordia:mandate:fixed-uuid');
    expect(mandate.issuedAt).toBe('2026-05-14T00:00:00Z');
    expect(mandate.algorithm).toBe('ES256');
  });
});

// ---------------------------------------------------------------------------
// MandateVerificationResult (data carrier only).
// ---------------------------------------------------------------------------

// Reconstruct a result from the Python-recorded to_dict, then re-serialize.
function resultFromWire(
  d: Record<string, unknown>,
): MandateVerificationResult {
  let mandate: Mandate | null = null;
  if ('mandate' in d && d.mandate !== null && d.mandate !== undefined) {
    mandate = mandateFromDict(d.mandate as Record<string, unknown>);
  }
  return makeMandateVerificationResult({
    valid: d.valid as boolean,
    mandateId: (d.mandate_id as string) ?? '',
    issuer: (d.issuer as string) ?? '',
    subject: (d.subject as string) ?? '',
    checks: (d.checks as Record<string, boolean>) ?? {},
    errors: (d.errors as string[]) ?? [],
    warnings: (d.warnings as string[]) ?? [],
    failureReason:
      'failure_reason' in d ? (d.failure_reason as string) : null,
    revokedAt: 'revoked_at' in d ? (d.revoked_at as string) : null,
    tier: 'tier' in d ? (d.tier as string) : null,
    mandate,
  });
}

describe('mandateVerificationResultToDict - parity with MandateVerificationResult.to_dict()', () => {
  for (const { name, to_dict } of fixtures.result_to_dict_cases) {
    it(`case ${name}`, () => {
      const result = resultFromWire(to_dict);
      const out = mandateVerificationResultToDict(result);
      expect(out).toEqual(to_dict);
      expect(Object.keys(out)).toEqual(Object.keys(to_dict));
    });
  }

  it('minimal invalid result emits only the seven always-present keys', () => {
    const out = mandateVerificationResultToDict(
      makeMandateVerificationResult({ valid: false }),
    );
    expect(Object.keys(out)).toEqual([
      'valid',
      'mandate_id',
      'issuer',
      'subject',
      'checks',
      'errors',
      'warnings',
    ]);
  });

  it('emits empty-string failure_reason (not-None guard)', () => {
    const out = mandateVerificationResultToDict(
      makeMandateVerificationResult({ valid: false, failureReason: '' }),
    );
    expect(out).toHaveProperty('failure_reason', '');
  });
});

// ---------------------------------------------------------------------------
// Static constants - byte-identical canonical JSON.
// ---------------------------------------------------------------------------

describe('static schema constants - canonical-byte parity with Python', () => {
  const TS_CONSTANTS: Record<string, Record<string, unknown>> = {
    MANDATE_JSON_SCHEMA,
    CONSTRAINT_PATTERNS,
  };

  for (const [constName, { value, canonical }] of Object.entries(
    fixtures.schema_constants,
  )) {
    it(`${constName} structurally equals the Python constant`, () => {
      expect(TS_CONSTANTS[constName]).toEqual(value);
    });

    it(`${constName} canonicalizes to byte-identical JCS bytes`, () => {
      const tsCanonical = canonicalizeJcs(TS_CONSTANTS[constName]).toString(
        'utf8',
      );
      expect(tsCanonical).toBe(canonical);
    });
  }
});
