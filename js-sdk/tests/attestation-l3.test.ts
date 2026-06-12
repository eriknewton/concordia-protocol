/**
 * L3 attestation-input hardening: JS-side rejection classes.
 *
 * Port of the issuance-side coverage in the Python suite
 * `tests/test_attestation_l3_bucket_vocabulary.py` (Python PR #95), plus the
 * JS-SPECIFIC paranoia classes that have no Python equivalent:
 *
 * - REGEX ANCHORING: Python anchors with `\Z`; the TS port uses a
 *   non-multiline `$`, which (unlike Python's `$`) has no trailing-newline
 *   allowance. A trailing `\n` must reject.
 * - UNICODE WHITESPACE: Python `\s` and JS `\s` are DIFFERENT sets (Python
 *   adds U+001C..U+001F and U+0085; JS adds U+FEFF). The port bans the UNION
 *   (stricter than both); every member of either set must reject.
 * - BYTE-LENGTH vs UTF-16 LENGTH: the 2048 extensions cap counts UTF-8 bytes
 *   of canonical JSON, never `String.prototype.length`.
 * - NO SILENT COERCION: malformed inputs throw; nothing is truncated,
 *   stringified, or dropped to produce an attestation anyway.
 * - EXOTIC OBJECTS: a `Date`/`Map` inside extensions must not slip through
 *   `stableStringify` as `{}` (Python's canonical_json raises TypeError).
 *
 * Cross-language byte parity of accept/reject for JSON-representable inputs
 * is covered by the Python-generated fixtures (`l3_meta_cases`,
 * `reference_strictness_cases` in attestation_vectors.json and
 * `reference_cases` in predicate_vectors.json); this file pins the rejection
 * classes and the JS-only strictness decisions.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  Session,
  type Message,
  type PublicKeyResolver,
} from '../src/session/index.js';
import {
  generateAttestation,
  AttestationError,
  VALUE_RANGE_BUCKETS,
  MAX_CATEGORY_LENGTH,
  MAX_REFERENCES,
  type GenerateAttestationOptions,
} from '../src/attestation/index.js';
import {
  validateReference,
  ReferenceValidationError,
  MAX_REFERENCE_TYPE_LENGTH,
  MAX_REFERENCE_RELATIONSHIP_LENGTH,
  MAX_REFERENCE_ID_LENGTH,
  MAX_REFERENCE_OPTIONAL_STRING_LENGTH,
  MAX_REFERENCE_EXTENSIONS_BYTES,
  MAX_REFERENCE_EXTENSIONS_DEPTH,
  MAX_REFERENCE_EXTENSIONS_NODES,
} from '../src/predicate/index.js';
import { PartyRole, SessionState } from '../src/types/index.js';
import { KeyPair, verify } from '../src/crypto/signing.js';

// ---------------------------------------------------------------------------
// A real AGREED session, replayed from the Python-signed fixture transcript
// (same rebuild approach as attestation.test.ts) so every generateAttestation
// call below runs over a legitimate concluded session.
// ---------------------------------------------------------------------------
const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(
  readFileSync(
    join(__dirname, 'fixtures/attestation/attestation_vectors.json'),
    'utf8',
  ),
) as {
  seeds: {
    agent_a: { id: string; seed_hex: string };
    agent_b: { id: string; seed_hex: string };
  };
  l3_meta_cases: Array<{
    name: string;
    session: {
      session_id: string;
      parties: Array<{ agent_id: string; role: string }>;
      transcript: Message[];
      created_at_ms: number;
      concluded_at_ms: number | null;
      state: string;
    };
  }>;
};

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const KP_A = KeyPair.fromPrivateKey(hexToBytes(fixtures.seeds.agent_a.seed_hex));
const KP_B = KeyPair.fromPrivateKey(hexToBytes(fixtures.seeds.agent_b.seed_hex));
const AGENT_A = fixtures.seeds.agent_a.id;
const AGENT_B = fixtures.seeds.agent_b.id;
const KP_BY_AGENT: Record<string, KeyPair> = {
  [AGENT_A]: KP_A,
  [AGENT_B]: KP_B,
};
const resolver: PublicKeyResolver = (agentId) => {
  if (agentId === AGENT_A) return KP_A;
  if (agentId === AGENT_B) return KP_B;
  return null;
};

// Any l3_meta fixture session is a full AGREED negotiation; reuse the first.
const SESSION_FIXTURE = fixtures.l3_meta_cases[0]!.session;

/** Rebuild a fresh AGREED session (each test mutates nothing, but a fresh
 * session per call keeps the generator's terminal-state check honest). */
function agreedSession(): Session {
  const clockValues = [SESSION_FIXTURE.created_at_ms];
  if (SESSION_FIXTURE.concluded_at_ms !== null) {
    clockValues.push(SESSION_FIXTURE.concluded_at_ms);
  }
  let clockIdx = 0;
  const clock = (): number => {
    const v = clockValues[Math.min(clockIdx, clockValues.length - 1)];
    clockIdx += 1;
    return v as number;
  };
  const session = new Session({
    sessionId: SESSION_FIXTURE.session_id,
    clock,
  });
  for (const party of SESSION_FIXTURE.parties) {
    const kp = KP_BY_AGENT[party.agent_id];
    session.addParty(party.agent_id, party.role as PartyRole, kp ?? null);
  }
  for (const msg of SESSION_FIXTURE.transcript) {
    session.applyMessage(msg, resolver);
  }
  expect(session.state).toBe(SessionState.AGREED);
  return session;
}

function generate(opts: GenerateAttestationOptions): Record<string, unknown> {
  return generateAttestation(agreedSession(), KP_BY_AGENT, opts);
}

function captureError(fn: () => unknown): Error {
  try {
    fn();
  } catch (e) {
    return e as Error;
  }
  throw new Error('expected the call to throw');
}

function ref(i = 0): Record<string, unknown> {
  return {
    type: 'receipt',
    id: `att_${i.toString(16).padStart(8, '0')}`,
    relationship: 'references',
  };
}

// ---------------------------------------------------------------------------
// value_range: enumerated bucket vocabulary.
// ---------------------------------------------------------------------------
describe('L3 value_range bucket vocabulary', () => {
  for (const bucket of VALUE_RANGE_BUCKETS) {
    it(`accepts bucket ${bucket}`, () => {
      const att = generate({ valueRange: `${bucket}_USD` });
      expect((att.meta as Record<string, unknown>).value_range).toBe(
        `${bucket}_USD`,
      );
    });
  }

  const rejected: Array<[string, string]> = [
    ['free text deal terms', 'I will pay $4,350 for the camera'],
    ['prose key=value terms', 'price=4350 USD, qty=1, ship to 90210'],
    ['exact-price degenerate range', '4350-4351_USD'],
    ['equal-bounds degenerate range', '4350-4350_USD'],
    ['non-vocabulary band', '500-1500_USD'],
    ['lowercase currency', '1000-5000_usd'],
    ['4-letter currency', '1000-5000_USDT'],
    ['2-letter currency', '1000-5000_US'],
    ['missing currency', '1000-5000'],
    ['space before currency', '1000-5000 USD'],
    ['empty bucket', '_USD'],
    ['empty currency', '1000-5000_'],
    ['trailing space', '1000-5000_USD '],
    ['leading space', ' 1000-5000_USD'],
    // THE anchor probe: Python \Z == JS non-multiline $. A Python port that
    // had used re's `$` semantics (or a JS `m` flag) would accept this.
    ['trailing newline', '1000-5000_USD\n'],
    ['trailing CRLF', '1000-5000_USD\r\n'],
    ['embedded newline', '1000-\n5000_USD'],
  ];
  for (const [name, bad] of rejected) {
    it(`rejects ${name}`, () => {
      expect(() => generate({ valueRange: bad })).toThrow(AttestationError);
      expect(() => generate({ valueRange: bad })).toThrow(/value_range/);
    });
  }

  it('rejects, never coerces: no attestation object on bad input', () => {
    expect(() => generate({ valueRange: 'totally free text' })).toThrow();
  });

  it('never echoes the invalid input (content-injection lens)', () => {
    const injected = 'EVIL_INJECTED_MARKER_${jndi}';
    const err = captureError(() => generate({ valueRange: injected }));
    expect(err.message).not.toContain(injected);
    expect(err.message).not.toContain('EVIL_INJECTED_MARKER');
  });

  it('omits value_range entirely when not supplied', () => {
    const att = generate({});
    expect('value_range' in (att.meta as Record<string, unknown>)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// category: dotted taxonomy path.
// ---------------------------------------------------------------------------
describe('L3 category taxonomy', () => {
  for (const ok of [
    'electronics',
    'electronics.cameras',
    'electronics.cameras.mirrorless',
    'compute.gpu',
    'zero-score-only',
    'a_b.c-d.e2',
  ]) {
    it(`accepts taxonomy path "${ok}"`, () => {
      const att = generate({ category: ok });
      expect((att.meta as Record<string, unknown>).category).toBe(ok);
    });
  }

  it('accepts the exact max-length boundary', () => {
    const boundary = 'x'.repeat(MAX_CATEGORY_LENGTH);
    const att = generate({ category: boundary });
    expect((att.meta as Record<string, unknown>).category).toBe(boundary);
  });

  for (const bad of [
    'Selling 4 units at $1200 each',
    'electronics cameras',
    'Electronics',
    'electronics..cameras',
    '.electronics',
    'electronics.',
    'x'.repeat(MAX_CATEGORY_LENGTH + 1),
    'electronics.cameras!',
    'electronics\n',
  ]) {
    it(`rejects ${JSON.stringify(bad.slice(0, 40))}`, () => {
      expect(() => generate({ category: bad })).toThrow(AttestationError);
      expect(() => generate({ category: bad })).toThrow(/category/);
    });
  }

  it('never echoes the invalid input', () => {
    const injected = 'EVIL CATEGORY $4,350 deal terms';
    const err = captureError(() => generate({ category: injected }));
    expect(err.message).not.toContain('EVIL');
    expect(err.message).not.toContain('4,350');
  });
});

// ---------------------------------------------------------------------------
// references[]: count cap + per-field caps at the issuance boundary.
// ---------------------------------------------------------------------------
describe('L3 references caps at issuance', () => {
  it('accepts exactly MAX_REFERENCES entries', () => {
    const refs = Array.from({ length: MAX_REFERENCES }, (_, i) => ref(i));
    const att = generate({ references: refs });
    expect((att.references as unknown[]).length).toBe(MAX_REFERENCES);
  });

  it('rejects MAX_REFERENCES + 1 entries with the count-cap error', () => {
    const refs = Array.from({ length: MAX_REFERENCES + 1 }, (_, i) => ref(i));
    const err = captureError(() => generate({ references: refs }));
    expect(err).toBeInstanceOf(AttestationError);
    expect(err.message).toBe(
      `references[] exceeds the maximum of ${MAX_REFERENCES} entries`,
    );
  });

  const requiredCaps: Array<[string, number]> = [
    ['type', MAX_REFERENCE_TYPE_LENGTH],
    ['id', MAX_REFERENCE_ID_LENGTH],
    ['relationship', MAX_REFERENCE_RELATIONSHIP_LENGTH],
  ];
  for (const [field, cap] of requiredCaps) {
    it(`caps ${field} at ${cap} chars (boundary accepted, +1 rejected)`, () => {
      const okRef = ref();
      okRef[field] = 'x'.repeat(cap);
      const att = generate({ references: [okRef] });
      expect(
        (att.references as Array<Record<string, unknown>>)[0]![field],
      ).toBe('x'.repeat(cap));

      const badRef = ref();
      badRef[field] = 'x'.repeat(cap + 1);
      const err = captureError(() => generate({ references: [badRef] }));
      expect(err).toBeInstanceOf(ReferenceValidationError);
      expect(err.message).toContain(`.${field}`);
    });
  }

  for (const field of ['version', 'signed_at', 'signer_did']) {
    it(`caps optional ${field} at ${MAX_REFERENCE_OPTIONAL_STRING_LENGTH}, rejects non-string and empty`, () => {
      const okRef = ref();
      okRef[field] = 'x'.repeat(MAX_REFERENCE_OPTIONAL_STRING_LENGTH);
      expect(() => generate({ references: [okRef] })).not.toThrow();

      const longRef = ref();
      longRef[field] = 'x'.repeat(MAX_REFERENCE_OPTIONAL_STRING_LENGTH + 1);
      expect(() => generate({ references: [longRef] })).toThrow(
        new RegExp(field),
      );

      const objRef = ref();
      objRef[field] = { sneaky: 'object' };
      expect(() => generate({ references: [objRef] })).toThrow(
        new RegExp(field),
      );

      const emptyRef = ref();
      emptyRef[field] = '';
      expect(() => generate({ references: [emptyRef] })).toThrow(
        new RegExp(field),
      );
    });
  }

  it('never echoes a rejected reference value', () => {
    const bad = ref();
    bad.id = 'EVIL_MARKER price=4350 USD qty=1';
    const err = captureError(() => generate({ references: [bad] }));
    expect(err.message).not.toContain('EVIL_MARKER');
    expect(err.message).not.toContain('4350');
  });
});

// ---------------------------------------------------------------------------
// Whitespace ban: the documented UNION of Python \s and JS \s.
// ---------------------------------------------------------------------------
describe('L3 whitespace ban (union of Python \\s and JS \\s)', () => {
  const FIELDS = [
    'type',
    'id',
    'relationship',
    'version',
    'signed_at',
    'signer_did',
  ] as const;

  // ASCII whitespace: in BOTH languages' \s.
  const asciiWs = [' ', '\t', '\n', '\r', '\f', '\v'];
  // Unicode whitespace in BOTH: NBSP, OGHAM, EN QUAD..HAIR SPACE, LS, PS,
  // NNBSP, MMSP, IDEOGRAPHIC SPACE.
  const bothWs = [
    '\u00a0', // NO-BREAK SPACE
    '\u1680', // OGHAM SPACE MARK
    '\u2000', // EN QUAD
    '\u2007', // FIGURE SPACE
    '\u200a', // HAIR SPACE
    '\u2028', // LINE SEPARATOR
    '\u2029', // PARAGRAPH SEPARATOR
    '\u202f', // NARROW NO-BREAK SPACE
    '\u205f', // MEDIUM MATHEMATICAL SPACE
    '\u3000', // IDEOGRAPHIC SPACE
  ];
  // Python-ONLY \s members (JS \s does NOT match these): the port must still
  // reject them or it would be more lenient than the Python reference.
  const pythonOnlyWs = ['\u001c', '\u001d', '\u001e', '\u001f', '\u0085'];
  // JS-ONLY \s member (Python ACCEPTS a U+FEFF in identifiers): rejected here
  // by the documented stricter-union decision.
  const jsOnlyWs = ['\ufeff'];

  for (const field of FIELDS) {
    it(`rejects every banned whitespace class embedded in ${field}`, () => {
      for (const ws of [...asciiWs, ...bothWs, ...pythonOnlyWs, ...jsOnlyWs]) {
        const bad = ref();
        bad[field] = `a${ws}b`;
        const err = captureError(() => validateReference(bad, 0));
        expect(err).toBeInstanceOf(ReferenceValidationError);
        expect(err.message).toContain('whitespace-free');
      }
    });
  }

  it('rejects leading and trailing whitespace too', () => {
    for (const value of ['trailing ', ' leading', 'x\n']) {
      const bad = ref();
      bad.id = value;
      expect(() => validateReference(bad, 0)).toThrow(/whitespace-free/);
    }
  });

  it('accepts legitimate whitespace-free identifier shapes', () => {
    const cases: Array<[string, string]> = [
      ['id', 'urn:concordia:attestation:att_0f9b2c1a'],
      ['type', 'receipt'],
      ['relationship', 'references'],
      ['version', '1.2.3-rc.1+build.5'],
      ['signed_at', '2026-05-07T18:30:00Z'],
      ['signer_did', 'did:web:log.example.dev:agent-7'],
    ];
    for (const [field, ok] of cases) {
      const r = ref();
      r[field] = ok;
      expect(validateReference(r, 0)[field]).toBe(ok);
    }
  });
});

// ---------------------------------------------------------------------------
// extensions: structural pre-check, byte cap, serializability.
// ---------------------------------------------------------------------------
describe('L3 extensions structure and byte caps', () => {
  /** n nested single-key dicts; the innermost holds a scalar. */
  function chain(nDicts: number): unknown {
    let value: unknown = 0;
    for (let i = 0; i < nDicts; i += 1) value = { a: value };
    return value;
  }

  function withExtensions(extensions: unknown): Record<string, unknown> {
    const r = ref();
    r.extensions = extensions;
    return r;
  }

  it('accepts depth exactly at the bound', () => {
    const ext = chain(MAX_REFERENCE_EXTENSIONS_DEPTH - 1);
    expect(validateReference(withExtensions(ext), 0).extensions).toEqual(ext);
  });

  it('rejects depth one over the bound', () => {
    const ext = chain(MAX_REFERENCE_EXTENSIONS_DEPTH);
    expect(() => validateReference(withExtensions(ext), 0)).toThrow(
      /nesting depth/,
    );
  });

  it('rejects a deeply nested array chain', () => {
    let value: unknown = [0];
    for (let i = 0; i < MAX_REFERENCE_EXTENSIONS_DEPTH; i += 1) {
      value = [value];
    }
    expect(() => validateReference(withExtensions({ a: value }), 0)).toThrow(
      /nesting depth/,
    );
  });

  it('accepts the node count exactly at the bound', () => {
    // Nodes: extensions dict (1) + array (1) + 254 scalars = 256.
    const ext = { a: new Array(MAX_REFERENCE_EXTENSIONS_NODES - 2).fill(0) };
    expect(validateReference(withExtensions(ext), 0).extensions).toEqual(ext);
  });

  it('rejects the node count one over the bound', () => {
    const ext = { a: new Array(MAX_REFERENCE_EXTENSIONS_NODES - 1).fill(0) };
    expect(() => validateReference(withExtensions(ext), 0)).toThrow(/nodes/);
  });

  it('rejects a wide flat object via the cheap node bound, not the byte cap', () => {
    const ext: Record<string, number> = {};
    for (let i = 0; i < 10_000; i += 1) ext[`k${i}`] = 0;
    expect(() => validateReference(withExtensions(ext), 0)).toThrow(/nodes/);
  });

  it('rejects a non-object extensions value', () => {
    expect(() =>
      validateReference(withExtensions('free text deal terms: $4,350'), 0),
    ).toThrow(/extensions must be an object/);
  });

  it('round-trips a small extensions object', () => {
    const out = validateReference(withExtensions({ chain_depth: 2 }), 0);
    expect(out.extensions).toEqual({ chain_depth: 2 });
  });

  it('enforces the cap in UTF-8 BYTES of canonical JSON, not UTF-16 length', () => {
    // 1200 x U+00E9 (2 UTF-8 bytes each): the canonical JSON string is ~1211
    // UTF-16 units (WELL UNDER 2048) but ~2411 UTF-8 bytes (OVER 2048). An
    // implementation that measured `String.prototype.length` would ACCEPT
    // this -- a fail-open the Python byte semantics forbid.
    const overByBytesOnly = { blob: 'é'.repeat(1200) };
    const err = captureError(() =>
      validateReference(withExtensions(overByBytesOnly), 0),
    );
    expect(err.message).toBe(
      `references[0].extensions exceeds ${MAX_REFERENCE_EXTENSIONS_BYTES} canonical-JSON bytes`,
    );
    // And the same payload sized under the BYTE cap is accepted.
    const underBytes = { blob: 'é'.repeat(1000) }; // ~2011 UTF-8 bytes
    expect(
      validateReference(withExtensions(underBytes), 0).extensions,
    ).toEqual(underBytes);
  });

  it('rejects an ASCII payload over the byte cap', () => {
    const ext = { blob: 'x'.repeat(MAX_REFERENCE_EXTENSIONS_BYTES + 1) };
    expect(() => validateReference(withExtensions(ext), 0)).toThrow(
      /canonical-JSON bytes/,
    );
  });

  it('rejects non-canonically-serializable numeric values (NaN/Infinity)', () => {
    for (const bad of [NaN, Infinity, -Infinity]) {
      expect(() => validateReference(withExtensions({ bad }), 0)).toThrow(
        /not canonically serializable/,
      );
    }
  });

  it('rejects exotic objects (Date/Map) instead of serializing them as {}', () => {
    // Python's canonical_json raises TypeError for these; JS stableStringify
    // would silently emit "{}" for a Date (fail-open). The walk flags them.
    for (const exotic of [new Date(), new Map()]) {
      expect(() =>
        validateReference(withExtensions({ v: exotic }), 0),
      ).toThrow(/not canonically serializable/);
    }
  });

  it('never echoes rejected extensions content', () => {
    const err = captureError(() =>
      validateReference(
        withExtensions({ secret: 'SECRET_TERMS $4,350 ' + 'x'.repeat(3000) }),
        0,
      ),
    );
    expect(err.message).not.toContain('SECRET_TERMS');
    expect(err.message).not.toContain('4,350');
  });
});

// ---------------------------------------------------------------------------
// Length caps count CODE POINTS (Python len), not UTF-16 units.
// ---------------------------------------------------------------------------
describe('L3 length caps use code points (Python len parity)', () => {
  it('accepts an id of MAX_REFERENCE_ID_LENGTH astral code points', () => {
    // U+1D11E MUSICAL SYMBOL G CLEF: 1 code point, 2 UTF-16 units. Python
    // len() counts 256; a UTF-16 .length check would see 512 and over-reject,
    // breaking byte parity with the Python reference.
    const astralId = '\u{1d11e}'.repeat(MAX_REFERENCE_ID_LENGTH);
    const r = ref();
    r.id = astralId;
    expect(validateReference(r, 0).id).toBe(astralId);
  });

  it('rejects an id one astral code point over the cap', () => {
    const r = ref();
    r.id = '\u{1d11e}'.repeat(MAX_REFERENCE_ID_LENGTH + 1);
    expect(() => validateReference(r, 0)).toThrow(/at most 256 chars/);
  });
});

// ---------------------------------------------------------------------------
// Signature round-trip and legacy attestations are unaffected.
// ---------------------------------------------------------------------------
describe('L3 hardening leaves signatures and legacy reads unaffected', () => {
  it('a fully validated attestation still signature-verifies per party', () => {
    const att = generate({
      category: 'electronics.cameras',
      valueRange: '1000-5000_USD',
      references: [ref()],
    });
    for (const party of att.parties as Array<Record<string, unknown>>) {
      const kp = KP_BY_AGENT[party.agent_id as string]!;
      const signed = {
        agent_id: party.agent_id,
        role: party.role,
        behavior: party.behavior,
      };
      expect(verify(signed, party.signature as string, kp)).toBe(true);
    }
  });

  it('legacy free-form meta mutated AFTER issuance still verifies (issuance-side only)', () => {
    const att = generate({});
    const meta = att.meta as Record<string, unknown>;
    meta.value_range = '500-1500_USD';
    meta.category = 'Legacy Free Text Category';
    for (const party of att.parties as Array<Record<string, unknown>>) {
      const kp = KP_BY_AGENT[party.agent_id as string]!;
      const signed = {
        agent_id: party.agent_id,
        role: party.role,
        behavior: party.behavior,
      };
      // Party signatures cover each party's own behavior record, not meta.
      expect(verify(signed, party.signature as string, kp)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Snapshot semantics (adversarial-review fix, 2026-06-12): accessor-backed
// input is rejected WITHOUT being executed, any foreign throw is sanitized
// (no echo of attacker-controlled error text), and the normalized reference
// is a detached plain-data snapshot (no TOCTOU between validation and any
// later serialization).
// ---------------------------------------------------------------------------
describe('L3 reference snapshot semantics (no getters, no echo, no TOCTOU)', () => {
  const SECRET = 'SECRET_TERMS price=4350';

  function expectSanitized(err: Error): void {
    expect(err).toBeInstanceOf(ReferenceValidationError);
    expect(err.message).not.toContain('SECRET_TERMS');
    expect(err.message).not.toContain('4350');
  }

  it('a throwing getter inside extensions is rejected without ever running', () => {
    let invoked = false;
    const ext: Record<string, unknown> = {};
    Object.defineProperty(ext, 'leak', {
      enumerable: true,
      configurable: true,
      get(): string {
        invoked = true;
        throw new Error(SECRET);
      },
    });
    const r = ref();
    r.extensions = ext;
    const err = captureError(() => validateReference(r, 0));
    expectSanitized(err);
    // The descriptor walk never performs [[Get]], so the hostile getter (and
    // therefore its throw) cannot execute at all.
    expect(invoked).toBe(false);
  });

  it('a throwing getter on a top-level reference field is rejected without running', () => {
    let invoked = false;
    const r = ref();
    Object.defineProperty(r, 'id', {
      enumerable: true,
      configurable: true,
      get(): string {
        invoked = true;
        throw new Error(SECRET);
      },
    });
    const err = captureError(() => validateReference(r, 0));
    expectSanitized(err);
    expect(err.message).toMatch(/plain enumerable data properties/);
    expect(invoked).toBe(false);
  });

  it('an accessor TOCTOU probe is rejected, never sampled', () => {
    // The classic probe: answer benignly on the first read, smuggle deal
    // terms on every later read. Rejecting accessors outright (instead of
    // snapshotting their first answer) means the probe never runs once.
    let reads = 0;
    const ext: Record<string, unknown> = {};
    Object.defineProperty(ext, 'note', {
      enumerable: true,
      configurable: true,
      get(): string {
        reads += 1;
        return reads === 1 ? 'benign' : SECRET;
      },
    });
    const r = ref();
    r.extensions = ext;
    const err = captureError(() => validateReference(r, 0));
    expectSanitized(err);
    expect(reads).toBe(0);
  });

  it('the normalized reference is detached: post-validation mutation cannot reach it', () => {
    const inner = { a: 1 };
    const ext: Record<string, unknown> = { inner, list: [1, 2] };
    const r = ref();
    r.extensions = ext;
    const out = validateReference(r, 0);
    expect(out).not.toBe(r);
    expect(out.extensions).not.toBe(ext);
    expect((out.extensions as Record<string, unknown>).inner).not.toBe(inner);
    // Mutate every layer of the caller's tree AFTER validation.
    inner.a = 999;
    (ext.list as number[]).push(4350);
    ext.smuggled = SECRET;
    (r as Record<string, unknown>).id = SECRET;
    const serialized = JSON.stringify(out);
    expect(serialized).not.toContain('SECRET_TERMS');
    expect(serialized).not.toContain('999');
    expect(serialized).not.toContain('4350');
    expect(out.extensions).toEqual({ inner: { a: 1 }, list: [1, 2] });
  });

  it('a Proxy whose traps throw is sanitized (extensions)', () => {
    const hostile = new Proxy(
      {},
      {
        ownKeys(): ArrayLike<string | symbol> {
          throw new Error(SECRET);
        },
      },
    );
    const r = ref();
    r.extensions = hostile;
    const err = captureError(() => validateReference(r, 0));
    expectSanitized(err);
    expect(err.message).toBe(
      'references[0].extensions could not be safely inspected',
    );
  });

  it('a Proxy whose traps throw is sanitized (the reference itself)', () => {
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf(): object | null {
          throw new Error(SECRET);
        },
      },
    );
    const err = captureError(() => validateReference(hostile, 0));
    expectSanitized(err);
    expect(err.message).toBe('references[0] could not be safely inspected');
  });

  it('a revoked Proxy is sanitized', () => {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    const err = captureError(() => validateReference(proxy, 0));
    expectSanitized(err);
    expect(err.message).toBe('references[0] could not be safely inspected');
  });

  it('symbol-keyed properties are rejected (reference and extensions)', () => {
    const r1 = ref();
    (r1 as Record<symbol | string, unknown>)[Symbol('smuggle')] = SECRET;
    expectSanitized(captureError(() => validateReference(r1, 0)));

    const r2 = ref();
    r2.extensions = { [Symbol('smuggle')]: SECRET } as Record<string, unknown>;
    expectSanitized(captureError(() => validateReference(r2, 0)));
  });

  it('non-enumerable own properties are rejected (reference and extensions)', () => {
    const r1 = ref();
    Object.defineProperty(r1, 'hidden', { enumerable: false, value: SECRET });
    expectSanitized(captureError(() => validateReference(r1, 0)));

    const ext: Record<string, unknown> = { ok: 1 };
    Object.defineProperty(ext, 'hidden', { enumerable: false, value: SECRET });
    const r2 = ref();
    r2.extensions = ext;
    expectSanitized(captureError(() => validateReference(r2, 0)));
  });

  it('an array hole inside extensions is rejected as not canonically serializable', () => {
    const holey = new Array<number>(2);
    holey[0] = 1; // index 1 stays a hole
    const r = ref();
    r.extensions = { list: holey };
    expect(() => validateReference(r, 0)).toThrow(
      /not canonically serializable/,
    );
  });

  it('a non-index own property on an array inside extensions is rejected', () => {
    const arr: number[] = [1, 2];
    (arr as unknown as Record<string, unknown>).smuggle = SECRET;
    const r = ref();
    r.extensions = { list: arr };
    expectSanitized(captureError(() => validateReference(r, 0)));
  });

  it('an accessor-backed array element inside extensions is rejected without running', () => {
    let invoked = false;
    const arr: unknown[] = [0];
    Object.defineProperty(arr, 0, {
      enumerable: true,
      configurable: true,
      get(): string {
        invoked = true;
        return SECRET;
      },
    });
    const r = ref();
    r.extensions = { list: arr };
    expectSanitized(captureError(() => validateReference(r, 0)));
    expect(invoked).toBe(false);
  });

  it('frozen plain data is still accepted (non-writable DATA props are fine)', () => {
    const r = ref();
    r.extensions = Object.freeze({
      a: Object.freeze([1, 2]),
      b: Object.freeze({ c: 'x' }),
    });
    Object.freeze(r);
    const out = validateReference(r, 0);
    expect(out.extensions).toEqual({ a: [1, 2], b: { c: 'x' } });
  });

  it('generateAttestation: a throwing index getter on references[] never runs and never echoes', () => {
    let invoked = false;
    const refs: unknown[] = [];
    Object.defineProperty(refs, 0, {
      enumerable: true,
      configurable: true,
      get(): unknown {
        invoked = true;
        throw new Error(SECRET);
      },
    });
    const err = captureError(() => generate({ references: refs }));
    expect(err).toBeInstanceOf(AttestationError);
    expect(err.message).not.toContain('SECRET_TERMS');
    expect(err.message).not.toContain('4350');
    expect(err.message).toBe(
      'references[] must contain only plain enumerable data elements',
    );
    expect(invoked).toBe(false);
  });

  it('generateAttestation: a hole in references[] rejects as NoneType (fail-closed)', () => {
    const refs = new Array<unknown>(1); // [ <hole> ]
    const err = captureError(() => generate({ references: refs }));
    expect(err).toBeInstanceOf(ReferenceValidationError);
    expect(err.message).toBe(
      'references[0] must be a dict, got NoneType per SPEC §11.5.6',
    );
  });

  it('generateAttestation: a Proxy references[] with throwing traps is sanitized', () => {
    const hostile = new Proxy([] as unknown[], {
      get(): unknown {
        throw new Error(SECRET);
      },
      getOwnPropertyDescriptor(): PropertyDescriptor | undefined {
        throw new Error(SECRET);
      },
    });
    const err = captureError(() => generate({ references: hostile }));
    expect(err).toBeInstanceOf(AttestationError);
    expect(err.message).not.toContain('SECRET_TERMS');
    expect(err.message).toBe('references[] could not be safely inspected');
  });

  it('the attested references carry the snapshot, not the caller objects', () => {
    const ext: Record<string, unknown> = { chain_depth: 2 };
    const r = ref();
    r.extensions = ext;
    const att = generate({ references: [r] });
    const attRefs = att.references as Array<Record<string, unknown>>;
    expect(attRefs[0]).not.toBe(r);
    expect(attRefs[0]!.extensions).not.toBe(ext);
    // Post-issuance mutation of the caller's object cannot alter the record.
    ext.smuggled = SECRET;
    expect(JSON.stringify(att)).not.toContain('SECRET_TERMS');
  });
});
