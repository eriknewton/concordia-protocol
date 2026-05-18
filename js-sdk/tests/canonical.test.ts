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
