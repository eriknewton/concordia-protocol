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
