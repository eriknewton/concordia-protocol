import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { runInNewContext } from 'vm';
import { canonicalizeJcs, canonicalizePredicate } from '../src/canonical/canonicalize.js';
import { CanonicalizationError } from '../src/canonical/checks.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('canonicalizeJcs - DELTA-20 vectors', () => {
  const vectorsPath = join(__dirname, 'fixtures/delta20/vectors.json');
  const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8')) as Array<{
    input: unknown;
    expected: string;
  }>;

  for (const { input, expected } of vectors) {
    it(`canonicalizes ${expected.slice(0, 40)}...`, () => {
      const actual = canonicalizeJcs(input).toString('utf8');
      expect(actual).toBe(expected);
    });
  }
});

describe('canonicalizePredicate - 13 v0.6 predicate fixtures', () => {
  const fixturesRoot = join(__dirname, 'fixtures/predicate_canonical');
  const vectors = readdirSync(fixturesRoot)
    .filter((d) => d.startsWith('vector_'))
    .sort();

  for (const vec of vectors) {
    it(`${vec} round-trips byte-identically`, () => {
      const expectedPath = join(fixturesRoot, vec, 'expected_canonical.txt');
      const expectedRaw = readFileSync(expectedPath, 'utf8').replace(/\n$/, '');
      const predicate = JSON.parse(expectedRaw);
      const actualBytes = canonicalizePredicate(predicate);
      expect(actualBytes.toString('utf8')).toBe(expectedRaw);
    });
  }
});

describe('canonicalizeJcs - special-float rejection', () => {
  it('rejects NaN', () => {
    expect(() => canonicalizeJcs({ x: NaN })).toThrow(CanonicalizationError);
  });
  it('rejects Infinity', () => {
    expect(() => canonicalizeJcs({ x: Infinity })).toThrow(CanonicalizationError);
  });
  it('rejects -Infinity', () => {
    expect(() => canonicalizeJcs({ x: -Infinity })).toThrow(CanonicalizationError);
  });
  it('rejects -0', () => {
    expect(() => canonicalizeJcs({ x: -0 })).toThrow(CanonicalizationError);
  });
});

describe('canonicalizeJcs - lone-surrogate rejection (Python parity)', () => {
  // JSON.stringify happily emits \udXXX for a lone surrogate, so without an
  // explicit guard JS would ACCEPT input the Python reference cannot serialize
  // (UnicodeEncodeError) — a canonical parity break + verify divergence. Both
  // sides must fail closed identically.
  it('rejects a lone high surrogate in a value', () => {
    expect(() => canonicalizeJcs({ x: '\uD834' })).toThrow(CanonicalizationError);
  });
  it('rejects a lone low surrogate in a value', () => {
    expect(() => canonicalizeJcs({ x: 'ab\uDD1Ecd' })).toThrow(CanonicalizationError);
  });
  it('rejects a lone surrogate in an object key', () => {
    expect(() => canonicalizeJcs({ '\uD834': 'v' })).toThrow(CanonicalizationError);
  });
  it('accepts a valid astral surrogate pair', () => {
    // U+1D11E (musical G-clef) is a real character: high+low surrogate pair.
    expect(canonicalizeJcs({ s: '𝄞' }).toString('utf8')).toBe('{"s":"𝄞"}');
  });
});

describe('canonicalizeJcs - large-integer fail-closed (Python parity)', () => {
  // Python's canonical_json formats integers with str(value), preserving full
  // precision. A JS number cannot represent integers beyond
  // Number.MAX_SAFE_INTEGER (2^53 - 1) distinctly, so rather than silently
  // emit a wrong value that diverges from Python, canonicalization throws and
  // directs the caller to pass large integers as strings.
  it('throws on 9007199254740993 (2^53 + 1, the canonical example)', () => {
    // The precision loss is the behavior under test: canonicalization must
    // reject this unsafe integer.
    // eslint-disable-next-line no-loss-of-precision
    expect(() => canonicalizeJcs({ x: 9007199254740993 })).toThrow(CanonicalizationError);
  });

  it('throws on 2^53 itself (first unsafe integer)', () => {
    expect(() => canonicalizeJcs({ x: Math.pow(2, 53) })).toThrow(CanonicalizationError);
  });

  it('throws on a large negative unsafe integer', () => {
    // Precision loss is the behavior under test (see above).
    // eslint-disable-next-line no-loss-of-precision
    expect(() => canonicalizeJcs({ x: -9007199254740993 })).toThrow(CanonicalizationError);
  });

  it('throws on a plain-decimal unsafe integer (1e20 renders as digits)', () => {
    // 1e20 is integer-valued, beyond the safe range, and JSON.stringify emits
    // it as plain decimal (100000000000000000000), so it falls in the lossy
    // band and is rejected fail-closed.
    expect(() => canonicalizeJcs({ x: 1e20 })).toThrow(CanonicalizationError);
  });

  it('throws when an unsafe integer is nested in an array', () => {
    // Precision loss is the behavior under test (see above).
    // eslint-disable-next-line no-loss-of-precision
    expect(() => canonicalizeJcs({ x: [1, 9007199254740993] })).toThrow(CanonicalizationError);
  });

  it('accepts large floats that render in exponential form (1e30, parity-safe)', () => {
    // Python parses 1e+30 as a float and emits the byte-identical exponential
    // string, so there is no cross-language divergence. This is exactly the
    // predicate fixture vector_08 value; rejecting it would break a real
    // Python-sourced parity vector.
    expect(canonicalizeJcs({ x: 1e30 }).toString('utf8')).toBe('{"x":1e+30}');
    expect(canonicalizeJcs({ x: 1e21 }).toString('utf8')).toBe('{"x":1e+21}');
  });

  it('accepts Number.MAX_SAFE_INTEGER (2^53 - 1) unchanged', () => {
    expect(canonicalizeJcs({ x: 9007199254740991 }).toString('utf8')).toBe(
      '{"x":9007199254740991}',
    );
  });

  it('accepts small safe integers unchanged', () => {
    expect(canonicalizeJcs({ x: 42, y: -1, z: 0 }).toString('utf8')).toBe('{"x":42,"y":-1,"z":0}');
  });

  it('accepts normal (non-integer) floats unchanged', () => {
    expect(canonicalizeJcs({ a: 1.5, b: -3.25 }).toString('utf8')).toBe('{"a":1.5,"b":-3.25}');
  });

  it('large integers passed as strings canonicalize identically (the guidance)', () => {
    expect(canonicalizeJcs({ x: '9007199254740993' }).toString('utf8')).toBe(
      '{"x":"9007199254740993"}',
    );
  });
});

describe('snapshotPlainJson - the realm/Proxy class (Codex P2, Grok findings, 2026-09-16 delta-6 gate)', () => {
  it('canonicalizes a node:vm cross-realm JSON value identically to the same JSON parsed in this realm', () => {
    // Codex P2, proved fail-before against 37bfca7: `rejectForeignPrototype`
    // rejected this value outright (a different vm context's `JSON.parse`
    // produces an object whose `Object.prototype` is NOT this module's
    // `Object.prototype`), so `canonicalizeJcs(crossRealm)` threw
    // CanonicalizationError -- a genuine cross-realm canonicalization
    // regression, since the SAME JSON text canonicalizes fine when parsed in
    // this realm. Post-fix, prototype identity is never checked, so both
    // realms' parse of the same text canonicalize to the same bytes.
    const json = '{"b":2,"a":1,"nested":{"x":[3,1,2]},"s":"hi"}';
    const sameRealm = JSON.parse(json) as Record<string, unknown>;
    const crossRealm = runInNewContext(`JSON.parse(${JSON.stringify(json)})`, {}) as Record<
      string,
      unknown
    >;
    // Precondition the construction depends on: a genuinely different
    // realm's Object.prototype, not a same-realm no-op.
    expect(Object.getPrototypeOf(crossRealm)).not.toBe(Object.getPrototypeOf(sameRealm));

    expect(canonicalizeJcs(crossRealm).toString('utf8')).toBe(
      canonicalizeJcs(sameRealm).toString('utf8'),
    );
  });

  it('rejects an array index whose own-descriptor lies about a value an indexed read can still reach', () => {
    // Codex/Grok delta-6 gate, proved fail-before against 37bfca7 (this
    // exact construction canonicalized as the bytes `[0,7]` instead of
    // throwing). The pre-fix descriptor-only accessor check
    // (`isAccessorProperty`) treats "no own descriptor" as "nothing to
    // reject" and falls through to `value[index]`, an ordinary `[[Get]]`
    // that a Proxy can answer from a real value its OWN
    // `getOwnPropertyDescriptor` trap just claimed does not exist -- the
    // same gap a native sparse hole with an inherited index getter opens,
    // reproduced here without mutating `Array.prototype` (which would
    // otherwise also break the canonicalizer's own array bookkeeping, an
    // unrelated collision, not the vulnerability under test).
    // `snapshotPlainJson` reads the descriptor exactly once and copies
    // `descriptor.value` directly, so a `getOwnPropertyDescriptor` lie
    // means an absent element, never a value fetched by a separate
    // indexed read.
    const backing = [0, 7];
    const proxied = new Proxy(backing, {
      getOwnPropertyDescriptor(target, prop) {
        if (prop === '1') return undefined; // lies: index 1 looks absent
        return Reflect.getOwnPropertyDescriptor(target, prop);
      },
    });
    // Preconditions the construction depends on, not assertions about the
    // code under test: the descriptor genuinely looks absent, while the
    // indexed read genuinely still answers the backing value.
    expect(Object.getOwnPropertyDescriptor(proxied, 1)).toBeUndefined();
    expect((proxied as unknown as number[])[1]).toBe(7);

    expect(() => canonicalizeJcs(proxied)).toThrow(CanonicalizationError);
  });
});
