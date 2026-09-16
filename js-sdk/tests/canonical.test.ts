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

describe('snapshotPlainJson - plain-data prototype-chain test (Grok finding 2, 2026-09-16 delta-7 gate)', () => {
  // Removing prototype-IDENTITY checking (delta-6, to fix the cross-realm
  // case above) also removed the only thing that had been rejecting these
  // non-JSON types: each construction below canonicalized to the bytes
  // `{}` (or `[]` for the array subclass) against e1239db instead of
  // throwing -- proved fail-before per test, stashing this describe block's
  // sibling source fix and rerunning. Python's canonical_json raises
  // TypeError for a datetime; JS silently dropping every field of these
  // types to `{}`/`[]` is a JS-only over-acceptance, not a plain-JSON byte
  // change (no legitimate JSON value parses to one of these types), so
  // closing it cannot break a real cross-realm JSON.parse value -- which is
  // exactly what the two hop-count helpers this fix adds test for, instead
  // of the prototype identity the cross-realm fix had to remove.

  it('rejects a Date (fail-before against e1239db: canonicalized to "{}")', () => {
    expect(() => canonicalizeJcs({ t: new Date('2026-01-01T00:00:00Z') })).toThrow(
      CanonicalizationError,
    );
  });

  it('rejects a Map (fail-before against e1239db: canonicalized to "{}")', () => {
    expect(() => canonicalizeJcs({ m: new Map([['a', 1]]) })).toThrow(CanonicalizationError);
  });

  it('rejects a Set (fail-before against e1239db: canonicalized to "{}")', () => {
    expect(() => canonicalizeJcs({ s: new Set([1]) })).toThrow(CanonicalizationError);
  });

  it('rejects a boxed Number (fail-before against e1239db: canonicalized to "{}")', () => {
    expect(() => canonicalizeJcs({ n: new Number(1) })).toThrow(CanonicalizationError);
  });

  it('rejects a class instance (fail-before against e1239db: canonicalized to "{}")', () => {
    class Terms {
      amount = 1;
    }
    expect(() => canonicalizeJcs({ v: new Terms() })).toThrow(CanonicalizationError);
  });

  it('rejects an object more than two hops from null (fail-before against e1239db: canonicalized to "{}")', () => {
    // Object.create(Object.create({})): hop1 (its own prototype) is the
    // inner Object.create({}) result, itself not null; hop2 (that result's
    // prototype) is the `{}` literal, also not null -- one hop further than
    // the two-hop plain-object budget, so it is refused on the same test
    // that accepts an ordinary `{}` or a cross-realm JSON.parse object.
    const tooDeep = Object.create(Object.create({})) as Record<string, unknown>;
    expect(() => canonicalizeJcs({ v: tooDeep })).toThrow(CanonicalizationError);
  });

  it('rejects an Array subclass instance (fail-before against e1239db: canonicalized to "[]")', () => {
    class Vec extends Array {}
    const vec = Vec.from([1, 2, 3]);
    // Precondition the construction depends on: Array.isArray alone would
    // let this through, which is exactly why the array-side test counts
    // prototype hops instead of relying on Array.isArray by itself.
    expect(Array.isArray(vec)).toBe(true);
    expect(() => canonicalizeJcs({ v: vec })).toThrow(CanonicalizationError);
  });

  it('still accepts a null-prototype object and a cross-realm array (no regression)', () => {
    const nullProto = Object.assign(Object.create(null), { a: 1 }) as Record<string, unknown>;
    expect(canonicalizeJcs(nullProto).toString('utf8')).toBe('{"a":1}');

    const crossRealmArray = runInNewContext('[3, 1, 2]', {}) as unknown[];
    // Precondition: a genuinely different realm's Array.prototype, not a
    // same-realm no-op (mirrors the cross-realm object precondition above).
    expect(Object.getPrototypeOf(crossRealmArray)).not.toBe(Array.prototype);
    expect(canonicalizeJcs(crossRealmArray).toString('utf8')).toBe('[3,1,2]');
  });
});

describe('snapshotPlainJson - "__proto__" is a JSON key, not a prototype (Grok/Codex verbatim, 2026-09-16 delta-7 gate, fix round 8)', () => {
  // JSON.parse creates "__proto__" as an ordinary own enumerable data
  // property (CreateDataProperty, per the JSON grammar), exactly like
  // Python's json.loads -- it is only an object LITERAL's `{"__proto__": x}`
  // syntax that is special-cased to set a prototype instead, and none of
  // these four values go through that syntax. Expected bytes computed by
  // hand (sorted by UTF-16 code unit: "_" is U+005F, "a" is U+0061, so
  // "__proto__" always sorts before "a") and cross-checked once against
  // Python's `concordia.signing.canonical_json` (see the fix-round report).
  // Fail-before against 23439e2: `out[key] = ...` (a [[Set]]) let the
  // inherited `Object.prototype.__proto__` accessor intercept this exact
  // key on every one of the four cases below.

  it('canonicalizes {"__proto__":1} storing the key (fail-before: canonicalized to "{}")', () => {
    const value = JSON.parse('{"__proto__":1}');
    expect(canonicalizeJcs(value).toString('utf8')).toBe('{"__proto__":1}');
  });

  it('canonicalizes {"__proto__":null,"a":1} keeping both keys (fail-before: canonicalized to "{}", with the copy\'s own prototype set to null)', () => {
    const value = JSON.parse('{"__proto__":null,"a":1}');
    expect(canonicalizeJcs(value).toString('utf8')).toBe('{"__proto__":null,"a":1}');
  });

  it('canonicalizes {"__proto__":{"x":1}} storing the object value (fail-before: canonicalized to "{}", with the copy\'s own prototype retargeted to {x:1})', () => {
    const value = JSON.parse('{"__proto__":{"x":1}}');
    expect(canonicalizeJcs(value).toString('utf8')).toBe('{"__proto__":{"x":1}}');
  });

  it('canonicalizes {"a":1,"__proto__":2} sorting "__proto__" before "a" (fail-before: canonicalized to "{"a":1}", silently dropping the second key)', () => {
    const value = JSON.parse('{"a":1,"__proto__":2}');
    expect(canonicalizeJcs(value).toString('utf8')).toBe('{"__proto__":2,"a":1}');
  });
});

describe('snapshotPlainJson - brand check refuses a prototype-stripped builtin (Codex second probe, 2026-09-16 delta-7 gate, fix round 8)', () => {
  // The prototype-hop guard alone would accept both constructions below --
  // each precondition proves that -- because hop1 === null after
  // Object.setPrototypeOf(v, null) satisfies hasPlainObjectPrototypeChain on
  // its own. hasPlainObjectTag is the check that still rejects them: their
  // Object.prototype.toString tag ("Date" / "Number") comes from an internal
  // slot Object.setPrototypeOf cannot touch. Fail-before against 23439e2 (no
  // brand check existed): both canonicalized to "{}" instead of throwing.

  it('rejects a Date whose prototype was nulled to pass the hop count (fail-before: canonicalized to "{}")', () => {
    const brandedDate = new Date(0);
    Object.setPrototypeOf(brandedDate, null);
    expect(Object.getPrototypeOf(brandedDate)).toBeNull(); // precondition: hop count alone would accept this
    expect(() => canonicalizeJcs({ t: brandedDate })).toThrow(CanonicalizationError);
  });

  it('rejects a null-prototype boxed Number (fail-before: canonicalized to "{}")', () => {
    const brandedNumber = new Number(1);
    Object.setPrototypeOf(brandedNumber, null);
    expect(Object.getPrototypeOf(brandedNumber)).toBeNull(); // precondition: hop count alone would accept this
    expect(() => canonicalizeJcs({ n: brandedNumber })).toThrow(CanonicalizationError);
  });
});
