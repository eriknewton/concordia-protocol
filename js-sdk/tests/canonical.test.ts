import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
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
    expect(() => canonicalizeJcs({ x: Infinity })).toThrow(
      CanonicalizationError,
    );
  });
  it('rejects -Infinity', () => {
    expect(() => canonicalizeJcs({ x: -Infinity })).toThrow(
      CanonicalizationError,
    );
  });
  it('rejects -0', () => {
    expect(() => canonicalizeJcs({ x: -0 })).toThrow(CanonicalizationError);
  });
});

describe('canonicalizeJcs - large-integer fail-closed (Python parity)', () => {
  // Python's canonical_json formats integers with str(value), preserving full
  // precision. A JS number cannot represent integers beyond
  // Number.MAX_SAFE_INTEGER (2^53 - 1) distinctly, so rather than silently
  // emit a wrong value that diverges from Python, canonicalization throws and
  // directs the caller to pass large integers as strings.
  it('throws on 9007199254740993 (2^53 + 1, the canonical example)', () => {
    expect(() => canonicalizeJcs({ x: 9007199254740993 })).toThrow(
      CanonicalizationError,
    );
  });

  it('throws on 2^53 itself (first unsafe integer)', () => {
    expect(() => canonicalizeJcs({ x: Math.pow(2, 53) })).toThrow(
      CanonicalizationError,
    );
  });

  it('throws on a large negative unsafe integer', () => {
    expect(() => canonicalizeJcs({ x: -9007199254740993 })).toThrow(
      CanonicalizationError,
    );
  });

  it('throws on a plain-decimal unsafe integer (1e20 renders as digits)', () => {
    // 1e20 is integer-valued, beyond the safe range, and JSON.stringify emits
    // it as plain decimal (100000000000000000000), so it falls in the lossy
    // band and is rejected fail-closed.
    expect(() => canonicalizeJcs({ x: 1e20 })).toThrow(CanonicalizationError);
  });

  it('throws when an unsafe integer is nested in an array', () => {
    expect(() => canonicalizeJcs({ x: [1, 9007199254740993] })).toThrow(
      CanonicalizationError,
    );
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
    expect(canonicalizeJcs({ x: 42, y: -1, z: 0 }).toString('utf8')).toBe(
      '{"x":42,"y":-1,"z":0}',
    );
  });

  it('accepts normal (non-integer) floats unchanged', () => {
    expect(canonicalizeJcs({ a: 1.5, b: -3.25 }).toString('utf8')).toBe(
      '{"a":1.5,"b":-3.25}',
    );
  });

  it('large integers passed as strings canonicalize identically (the guidance)', () => {
    expect(canonicalizeJcs({ x: '9007199254740993' }).toString('utf8')).toBe(
      '{"x":"9007199254740993"}',
    );
  });
});
