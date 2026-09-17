import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { runInNewContext } from 'vm';
import {
  canonicalizeJcs,
  canonicalizePredicate,
  fromJsonText,
} from '../src/canonical/canonicalize.js';
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

describe('snapshotPlainJson - cross-realm values must be re-parsed via fromJsonText (2026-09-16 fix round 11)', () => {
  // Rounds 5-10 tried to accept a cross-realm JSON.parse result directly, by
  // characterizing "plain enough" from outside (a hop count, then a brand
  // probe, then a symbol-key walk) rather than by identity, because a
  // same-realm identity check rejects a cross-realm object outright (its
  // Object.prototype is a DIFFERENT object from this module's). The tenth
  // review found that every one of those outside characterizations still
  // let through a same-realm value that should be refused (Error,
  // Arguments, Promise, a shortened class instance), because the probes
  // themselves are built from this realm's OWN mutable builtins, which a
  // hostile same-realm caller can replace before this module ever runs. This
  // round subtracts the outside characterization entirely and goes back to
  // same-realm identity, moving the cross-realm case to an explicit,
  // documented caller obligation: re-parse foreign JSON here first.

  it('refuses a node:vm cross-realm JSON value (values from another realm must be re-parsed here first)', () => {
    // Fail-before against 73194db: the hop-count test accepted this value
    // (a cross-realm Object.prototype still satisfies "reaches null within
    // two hops"), so canonicalizeJcs(crossRealm) canonicalized it as plain
    // data instead of throwing. Post-round-11, only THIS module's own
    // Object.prototype identity is accepted, so a genuinely different
    // realm's Object.prototype is refused outright.
    const json = '{"b":2,"a":1,"nested":{"x":[3,1,2]},"s":"hi"}';
    const crossRealm = runInNewContext(`JSON.parse(${JSON.stringify(json)})`, {}) as Record<
      string,
      unknown
    >;
    // Precondition the construction depends on: a genuinely different
    // realm's Object.prototype, not a same-realm no-op.
    expect(Object.getPrototypeOf(crossRealm)).not.toBe(Object.prototype);

    expect(() => canonicalizeJcs(crossRealm)).toThrow(CanonicalizationError);
  });

  it('fromJsonText(JSON.stringify(vmObject)) canonicalizes identically to the same JSON parsed in this realm', () => {
    // The documented escape hatch: a caller holding a cross-realm object
    // re-serializes it (JSON.stringify works on any realm's plain object)
    // and re-parses it HERE via fromJsonText, which is exactly JSON.parse
    // in this realm (routed through parseJsonStrict for the same
    // ingest-boundary unsafe-integer check every other parse path applies).
    // The resulting value's prototype is THIS module's Object.prototype, so
    // it canonicalizes byte-identically to the value the same JSON text
    // produces when parsed directly in this realm.
    const json = '{"b":2,"a":1,"nested":{"x":[3,1,2]},"s":"hi"}';
    const sameRealm = JSON.parse(json) as Record<string, unknown>;
    const crossRealm = runInNewContext(`JSON.parse(${JSON.stringify(json)})`, {}) as Record<
      string,
      unknown
    >;
    const reparsed = fromJsonText(JSON.stringify(crossRealm));

    expect(canonicalizeJcs(reparsed).toString('utf8')).toBe(
      canonicalizeJcs(sameRealm).toString('utf8'),
    );
  });

  it('fromJsonText(JSON.stringify(vmArray)) canonicalizes identically to the same array parsed in this realm', () => {
    const sameRealmArray = JSON.parse('[3,1,2]') as unknown[];
    const crossRealmArray = runInNewContext('[3, 1, 2]', {}) as unknown[];
    const reparsed = fromJsonText(JSON.stringify(crossRealmArray));

    expect(canonicalizeJcs(reparsed).toString('utf8')).toBe(
      canonicalizeJcs(sameRealmArray).toString('utf8'),
    );
  });
});

describe('snapshotPlainJson - the descriptor-map Proxy class (Codex P2, Grok findings, 2026-09-16 delta-6 gate)', () => {
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
    // indexed read. Unaffected by round 11's subtraction: the array's own
    // prototype identity is still exactly `Array.prototype` here, so this
    // construction still reaches the descriptor-observation code this test
    // pins.
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

describe('snapshotPlainJson - a non-enumerable array index is refused like a hole (Codex P2 and both Grok lenses, 2026-09-17 delta-13 gate)', () => {
  // One rule for both branches: a member is canonicalized iff it is an own
  // enumerable data descriptor. An object key that fails it is omitted; an
  // array index below `length` that fails it cannot be omitted without
  // renumbering the later elements, so it throws, exactly as a hole does.
  // Before this round the array branch checked presence and accessor status
  // only, so this value canonicalized as `[1]` while the README said every
  // index must be enumerable.
  it('throws on Object.defineProperty([1], "0", {value: 1, enumerable: false})', () => {
    const arr = [1];
    Object.defineProperty(arr, '0', { value: 1, enumerable: false });
    expect(() => canonicalizeJcs(arr)).toThrow(CanonicalizationError);
    expect(() => canonicalizeJcs(arr)).toThrow(/array index 0: it is a non-enumerable property/);
    expect(() => canonicalizeJcs({ wrapped: arr })).toThrow(CanonicalizationError);
  });

  it('still accepts the same array once the index is enumerable again', () => {
    const arr = [1];
    Object.defineProperty(arr, '0', { value: 1, enumerable: false });
    Object.defineProperty(arr, '0', { value: 1, enumerable: true });
    expect(canonicalizeJcs(arr).toString('utf8')).toBe('[1]');
  });

  it('omits a non-enumerable OBJECT key rather than throwing (the branches differ only in what failing the rule does)', () => {
    const obj: Record<string, unknown> = { a: 1 };
    Object.defineProperty(obj, 'hidden', { value: 2, enumerable: false });
    expect(canonicalizeJcs(obj).toString('utf8')).toBe('{"a":1}');
  });
});

describe('snapshotPlainJson - same-realm prototype-identity refusals (2026-09-16 fix round 11)', () => {
  // Each construction below has its OWN, natural prototype (Date.prototype,
  // Map.prototype, ...), never `Object.prototype` or `null`, so the single
  // identity comparison in isPlainObjectPrototype/isPlainArrayPrototype
  // refuses every one of them without needing a brand probe, a hop count,
  // or a symbol-key walk. Error, Arguments, and Promise are proved
  // fail-before against 73194db: the tenth review (Codex findings 1-3)
  // showed the round-10 brand-probe list had no probe for Error's
  // [[ErrorData]] slot, and that Promise's brand check depended on a
  // prototype-chain symbol lookup a one-hop Symbol.toStringTag spoof or a
  // nulled prototype could dodge, so both canonicalized as plain data
  // (`{}`) instead of throwing. Arguments is deliberately absent from this
  // refusal list (see the dedicated describe block below): unlike Date,
  // Map, Error, or Promise, an Arguments object's OWN `[[Prototype]]` is
  // exactly `%Object.prototype%` per ECMA-262 (CreateMappedArgumentsObject
  // / CreateUnmappedArgumentsObject both call `OrdinaryObjectCreate(
  // %Object.prototype%, ...)`), so identity comparison cannot and does not
  // try to distinguish it from plain data -- this was already true even in
  // round 10's hop-count layer (the tenth review noted a stock `arguments`
  // object is two hops to null "by default").

  it('rejects a Date', () => {
    expect(() => canonicalizeJcs({ t: new Date('2026-01-01T00:00:00Z') })).toThrow(
      CanonicalizationError,
    );
  });

  it('rejects a Map', () => {
    expect(() => canonicalizeJcs({ m: new Map([['a', 1]]) })).toThrow(CanonicalizationError);
  });

  it('rejects a Set', () => {
    expect(() => canonicalizeJcs({ s: new Set([1]) })).toThrow(CanonicalizationError);
  });

  it('rejects a boxed Number', () => {
    expect(() => canonicalizeJcs({ n: new Number(1) })).toThrow(CanonicalizationError);
  });

  it('rejects a class instance', () => {
    class Terms {
      amount = 1;
    }
    expect(() => canonicalizeJcs({ v: new Terms() })).toThrow(CanonicalizationError);
  });

  it('rejects an Array subclass instance', () => {
    class Vec extends Array {}
    const vec = Vec.from([1, 2, 3]);
    // Precondition the construction depends on: Array.isArray alone would
    // let this through, which is exactly why the array-side identity test
    // also compares the prototype, not only Array.isArray.
    expect(Array.isArray(vec)).toBe(true);
    expect(() => canonicalizeJcs({ v: vec })).toThrow(CanonicalizationError);
  });

  it('rejects an Error (fail-before against 73194db: canonicalized to "{}", no probe for [[ErrorData]])', () => {
    expect(() => canonicalizeJcs({ e: new Error('boom') })).toThrow(CanonicalizationError);
  });

  it('rejects a Promise (fail-before against 73194db: canonicalized to "{}" once its prototype was nulled, defeating the Symbol.toStringTag-property check the brand list relied on)', () => {
    const settled = Promise.resolve(1);
    // Swallow the unhandled-rejection-adjacent "unused promise" lint concern
    // by attaching a no-op handler; the promise itself, not its resolution,
    // is what this test canonicalizes.
    settled.catch(() => undefined);
    expect(() => canonicalizeJcs({ p: settled })).toThrow(CanonicalizationError);
  });

  it('still accepts an ordinary object and array (no regression)', () => {
    expect(canonicalizeJcs({ a: 1, b: [1, 2, 3] }).toString('utf8')).toBe('{"a":1,"b":[1,2,3]}');
  });
});

describe('snapshotPlainJson - identity-cannot-distinguish residuals (2026-09-16 fix round 11, documented)', () => {
  it('an Arguments object canonicalizes as its own enumerable indices only, never refused (its own prototype genuinely IS Object.prototype, per ECMA-262 -- not a probe gap)', () => {
    function capture(): unknown {
      // eslint-disable-next-line prefer-rest-params
      return arguments;
    }
    const args = capture.call(undefined, 'x', 'y') as unknown as Record<string, unknown>;
    // Preconditions: the facts this test depends on. A stock `arguments`
    // object's OWN prototype is this realm's Object.prototype, not a
    // distinct `Arguments.prototype` the way Date/Map/Error/Promise each
    // have their own, so no identity comparison, hop count, or brand probe
    // from any round could have refused it without also refusing an
    // ordinary object; its `length` and `callee` are non-enumerable (the
    // spec-mandated shape, e.g. CreateUnmappedArgumentsObject in ES2026),
    // so they are skipped the same way any non-enumerable own property is,
    // leaving only the two enumerable indices in the snapshot.
    expect(Object.getPrototypeOf(args)).toBe(Object.prototype);
    expect(Object.getOwnPropertyDescriptor(args, 'length')?.enumerable).toBe(false);
    expect(canonicalizeJcs(args).toString('utf8')).toBe('{"0":"x","1":"y"}');
  });

  it('a null-prototype object with own data canonicalizes as that data (documented residual, not a bug)', () => {
    // The contract states this explicitly: "when its prototype has been
    // set to null, is treated as the plain data of its own enumerable
    // properties." A null-prototype object is indistinguishable from
    // JSON.parse('{}')-then-Object.setPrototypeOf(...,null) by any
    // structural check this module could run without reading through the
    // very prototype link the check exists to interrogate, so this is
    // accepted by design rather than refused by omission.
    const nullProto = Object.assign(Object.create(null), { a: 1 }) as Record<string, unknown>;
    expect(canonicalizeJcs(nullProto).toString('utf8')).toBe('{"a":1}');
  });

  it('a symbol-keyed own property is silently ignored, never read and never rejected (documented: "symbol keys are ignored (never read)")', () => {
    // A plain object literal's prototype is unaffected by adding a symbol
    // property, so this value still passes the identity test; the snapshot
    // then enumerates only STRING keys (Object.keys of the descriptor map),
    // the same thing JSON.parse does, so the symbol key never reaches the
    // output -- not an error, and not a read of the symbol's value either.
    const marker = Symbol('marker');
    const value: Record<string | symbol, unknown> = { a: 1, [marker]: 'hidden' };
    expect(canonicalizeJcs(value).toString('utf8')).toBe('{"a":1}');
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
