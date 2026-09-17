import { CanonicalizationError, checkLoneSurrogates, checkNoSpecialFloatValue } from './checks.js';
import { parseJsonStrict } from './parse.js';

/**
 * Canonicalize a JSON-serializable value per RFC 8785 (JCS).
 * Returns a Buffer of the canonical UTF-8 bytes.
 *
 * Two steps, not one traversal of the caller's value: `snapshotPlainJson`
 * reads the caller's value exactly once, into a realm-local plain copy, and
 * `stableStringify` then serializes ONLY that copy. A single traversal that
 * both validated and serialized the caller's own value (the prior shape)
 * still read each member through a descriptor check and then a separate
 * `[[Get]]` (`obj[k]`, `value[index]`) -- two different reads a Proxy can
 * answer differently, and the second one alone is what a signature check
 * sees versus what a chain reconstruction sees when the SAME message is
 * canonicalized twice by two different callers (Codex P1, Grok findings 1-2,
 * 2026-09-16 delta-6 gate). Routing every caller-controlled read through
 * `snapshotPlainJson` and letting every other traversal -- including a
 * second, third, or Nth call to `canonicalizeJcs` on data that already IS a
 * snapshot -- run only against the realm-local copy closes that class
 * outright: nothing downstream can observe a second read of the caller's
 * own object at all.
 */
export function canonicalizeJcs(value: unknown): Buffer {
  const str = stableStringify(snapshotPlainJson(value));
  return Buffer.from(str, 'utf8');
}

/**
 * Canonicalize a predicate object, stripping the top-level `signature` field.
 * Nested signature fields are preserved.
 */
export function canonicalizePredicate(predicate: Record<string, unknown>): Buffer {
  const { signature: _stripped, ...rest } = predicate;
  return canonicalizeJcs(rest);
}

/**
 * Recursively drop every `"signature"` property from an object graph.
 *
 * Byte-for-byte mirror of Python `concordia.cosign.strip_signatures`: in
 * objects, the `"signature"` key is removed at every depth; arrays are
 * recursed; all other values pass through unchanged. Unlike
 * {@link canonicalizePredicate} (which strips ONLY the top-level signature),
 * this strips nested ones too -- required for the C-H2 outcome-binding
 * countersignature, whose payload must exclude every per-party signature.
 */
export function stripSignatures(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stripSignatures);
  }
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(obj)) {
      if (k === 'signature') continue;
      out[k] = stripSignatures(obj[k]);
    }
    return out;
  }
  return value;
}

/**
 * The exact bytes a counterparty signs on the co-signature / outcome-binding
 * lane: signature-stripped, then canonicalized. Equivalent to Python
 * `concordia.cosign.canonical_cosign_bytes`
 * (`canonical_json(strip_signatures(value))`). Reuses the proven RFC-8785
 * `canonicalizeJcs` so a signature produced here verifies against the Python
 * reference.
 */
export function canonicalCosignBytes(value: unknown): Buffer {
  return canonicalizeJcs(stripSignatures(value));
}

/**
 * Re-parse JSON text as THIS realm's plain data -- the documented escape
 * hatch for a value that came from another realm (a `node:vm` context, a
 * browser iframe) and therefore fails {@link snapshotPlainJson}'s same-realm
 * prototype-identity test. A string carries no prototype at all, so
 * `JSON.parse`, run HERE, always produces a value whose own prototype is
 * `null`, this module's `Object.prototype`, or this module's
 * `Array.prototype` -- exactly the set {@link snapshotPlainJson} accepts --
 * regardless of which realm originally produced `text`.
 *
 * Delegates to {@link parseJsonStrict} rather than a bare `JSON.parse` call
 * so a cross-realm value re-parsed through this function gets the same
 * ingest-boundary unsafe-integer-literal check every other parse-then-sign
 * or parse-then-canonicalize path in this package already applies (see
 * parse.ts): a bare `JSON.parse` can only be caught by
 * {@link checkNoSpecialFloatValue}'s POST-parse guard, which cannot reach
 * the >= 1e21 plain-decimal case that only the SOURCE-text scan in
 * `parseJsonStrict` catches.
 */
export function fromJsonText(text: string): unknown {
  return parseJsonStrict(text);
}

/**
 * Same-realm prototype-IDENTITY test for a non-array object: true only when
 * `value`'s own `[[Prototype]]` is exactly `null` or exactly THIS module's
 * `Object.prototype` -- the two prototypes an object literal or a
 * same-realm `JSON.parse` result can ever have. Comparing identity, not
 * shape or brand, is deliberate and is this round's entire subtraction: a
 * hop count, a `toString`/internal-slot brand probe, or a symbol-key walk
 * all tried to characterize "plain-enough" from OUTSIDE, and every one of
 * them borrowed a mutable builtin (`Date.prototype.getTime`,
 * `Array.prototype.some`, `Object.prototype.toString`) that a hostile
 * SAME-REALM caller can reassign before handing this function a value --
 * there is no probe a JavaScript library can build from its own realm's
 * builtins that survives a caller who controls that realm's builtins
 * (2026-09-16 delta-10 gate, Codex findings 1-3 and Grok lens A: replacing
 * `Array.prototype.some`, `Date.prototype.getTime`, or a Promise/Error/
 * Arguments/SharedArrayBuffer/shortened-class-instance construction each
 * defeated the brand or symbol machinery this replaces). `Object.
 * getPrototypeOf` performs a single structural `[[GetPrototypeOf]]`
 * operation and nothing else; comparing its result against a REFERENCE this
 * module already holds (`Object.prototype`) reads no property of `value`
 * and calls no method borrowed from `value`'s own realm, so there is
 * nothing left for a hostile same-realm caller to intercept. A cross-realm
 * `JSON.parse` result (a different `node:vm` context, an iframe) has a
 * DIFFERENT `Object.prototype` object and is refused by this test on
 * purpose: the caller re-parses it here first ({@link fromJsonText}), so
 * this module never compares identity across a realm boundary it cannot see
 * into. Must match `isPlainObjectPrototype` in
 * conformance/reference-runner-js/runner.mjs.
 */
function isPlainObjectPrototype(value: object): boolean {
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

/**
 * Same-realm prototype-IDENTITY test for an array: true only when `value`
 * is an exotic Array (`Array.isArray`, itself a structural check that reads
 * no property of `value`) whose own `[[Prototype]]` is exactly THIS
 * module's `Array.prototype`. An Array subclass instance, or a cross-realm
 * array, has a different prototype object and is refused here for the same
 * reason, and by the same single comparison, as
 * {@link isPlainObjectPrototype}. Must match `isPlainArrayPrototype` in
 * conformance/reference-runner-js/runner.mjs.
 */
function isPlainArrayPrototype(value: object): boolean {
  return Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype;
}

/**
 * Produce a realm-local, plain-data deep copy of `value` in a single
 * traversal, reading each member of the caller-supplied structure exactly
 * once.
 *
 * Exported so a caller that must consult a large caller-supplied structure
 * more than once -- once to verify a signature over a subset of it, again
 * to reconstruct a chain from it -- can snapshot it ONE time at the
 * boundary and have every later read touch only the returned copy, never
 * the original (see `verifyReceiptSetBinding` in
 * `js-sdk/src/attestation/attestation.ts` and the mirrored boundary
 * snapshot in `conformance/reference-runner-js/runner.mjs`; must match
 * both).
 *
 * Every own, string-keyed property (object) or index (array) is observed
 * through exactly ONE call to `Object.getOwnPropertyDescriptors`, which
 * performs one `[[OwnPropertyKeys]]` and one `[[GetOwnProperty]]` per key
 * and returns fresh, realm-local plain descriptor records whose `value` was
 * read exactly once -- never a separate `Object.keys` enumerability pass
 * followed by a per-key `Object.getOwnPropertyDescriptor` call, which is
 * two independent trap invocations a Proxy can answer differently (Grok
 * finding 1, 2026-09-16 delta-7 gate: a descriptor whose `value` field is
 * itself a getter answers `++n` on each of the two calls and the old code
 * kept the second answer). This function never calls `Object.keys`,
 * `Object.getOwnPropertyDescriptor`, or any indexed/keyed `[[Get]]`
 * (`obj[k]`, `value[index]`) on the caller's own value -- only on the
 * descriptor MAP this function itself built from that one call. An
 * accessor descriptor (`get`/`set`) throws outright, and an array index
 * absent from the map -- a sparse hole, including one an inherited index
 * getter would otherwise answer -- throws too, instead of falling through
 * to an indexed read that would reach the prototype chain. Symbol keys are
 * never read at all: `Object.keys` of the descriptor map this function
 * built enumerates only string keys, so a symbol-keyed own property simply
 * does not appear in the snapshot, the same way `JSON.parse` never produces
 * one.
 *
 * THE CONTRACT (2026-09-16 fix round 12 -- restated to name exactly the
 * predicate the code below evaluates, after Grok lens A's delta-11 finding
 * that the fix-round-11 wording above described a DIFFERENT, broader
 * function than this one: it said Proxies and retargeted class instances
 * are refused, when the identity tests below cannot tell them apart from
 * an ordinary object or array and accept them. This paragraph is aligned to
 * the code, per that finding's own instruction, because the code is right
 * -- an identity comparison against `Object.prototype`/`Array.prototype`
 * is the one probe a hostile same-realm caller cannot intercept; see
 * {@link isPlainObjectPrototype}'s comment for why, and the git history of
 * this file for what each earlier, broader-sounding probe tried and where
 * the next round's gate broke it):
 *
 * `canonicalizeJcs` accepts a value iff exactly one of:
 *   - it is an Array (`Array.isArray`) whose own prototype is exactly this
 *     realm's `Array.prototype`; or
 *   - (checked only when the first test is false, never as a fallback pair)
 *     its own prototype is exactly `null` or exactly this realm's
 *     `Object.prototype`.
 * A non-Array whose prototype happens to be `Array.prototype` (for example
 * `Object.create(Array.prototype)`) is refused, and an Array whose
 * prototype has been set to `null` (for example
 * `Object.setPrototypeOf([1], null)`) is refused too -- `Array.isArray`
 * gates which single branch runs; it is not a hint that lets a value try
 * the other branch. An accepted value is snapshotted once through
 * `Object.getOwnPropertyDescriptors`, keeping only enumerable, non-accessor,
 * string-keyed data (array elements under `length`, object keys otherwise):
 * a symbol key is silently omitted (never read, never rejected), an
 * accessor property throws, and a sparse array hole throws. ONE rule for
 * both branches: a member is canonicalized iff it is an own enumerable data
 * descriptor. An object key that fails it is omitted (JSON.stringify's own
 * behaviour); an array index below `length` that fails it cannot be omitted
 * without shifting every later element, so it throws instead: a hole, an
 * accessor, and a NON-ENUMERABLE index all throw (Codex P2 and both Grok
 * lenses, 2026-09-17 delta-13 gate: the array branch checked presence and
 * accessor status only, so `Object.defineProperty([1], "0", {value: 1,
 * enumerable: false})` canonicalized as `[1]` while the README said every
 * index must be enumerable).
 *
 * The predicate reads ONLY prototype identity (never a hop count, a
 * `toString`/internal-slot brand, or a symbol key) and the descriptor map
 * (never the value's construction history), so it is satisfied by values
 * `JSON.parse` cannot itself produce -- four DOCUMENTED residuals, each
 * covered by a test in canonical.test.ts, not a probe gap:
 *   - Proxies are not detected: a Proxy whose `getPrototypeOf` and
 *     `getOwnPropertyDescriptors` traps present a same-realm plain object
 *     or Array satisfies the same predicate and is snapshotted as the
 *     plain data those traps returned, once; the SDK does not attempt to
 *     detect Proxies.
 *   - a builtin or class instance (`Date`, `Map`, a boxed primitive, a
 *     `new Foo()`) is refused as constructed, but is ACCEPTED once its own
 *     prototype has been retargeted (by the caller, before this call) to
 *     `null` or this realm's `Object.prototype` -- it is then snapshotted
 *     as whatever own enumerable data it carries (none for a retargeted
 *     `Date`; `{"x":1}` for a retargeted `class Foo { x = 1 }` instance),
 *     because the predicate cannot see, and does not claim to see, what
 *     the value used to be.
 *   - a null-prototype object with own data (`Object.assign(Object.create(
 *     null), {a: 1})`) canonicalizes as that data: indistinguishable from
 *     `JSON.parse('{"a":1}')` by any check that does not read through the
 *     very prototype link the check exists to interrogate.
 *   - an `arguments` object canonicalizes as its own enumerable indices
 *     only: its OWN prototype genuinely IS this realm's `Object.prototype`
 *     per ECMA-262, so no identity comparison, at any round, could refuse
 *     it without also refusing an ordinary object.
 *
 * Values from another realm (an iframe, a `node:vm` context) are refused by
 * the same identity test -- a cross-realm `Object.prototype` or
 * `Array.prototype` is a distinct object -- and the supported path is to
 * re-parse the source text here (`fromJsonText(text)` is provided), not to
 * retarget the foreign value's prototype by hand. The library does not
 * defend against replacement of this realm's builtins; a hostile
 * same-realm environment is outside every JavaScript library's contract.
 *
 * The copy this function returns is built with `Object.create(null)` (for
 * an object) or `[]` (for an array) and populated ONLY through
 * `Object.defineProperty`, never `[[Set]]` (`out[key] = ...` /
 * `out[index] = ...`): a `{}` copy inherits `Object.prototype`, whose OWN
 * `__proto__` property is an ACCESSOR, not a plain data property, so
 * `out[key] = value` for the JSON key `"__proto__"` would invoke that
 * inherited setter instead of storing the key (Grok and Codex verbatim,
 * 2026-09-16 delta-7 gate). A null-prototype copy has no inherited accessor
 * at any key, so there is nothing left to intercept, and `"__proto__"`
 * survives as an ordinary own data property, exactly as RFC 8785 and the
 * Python implementation both treat it.
 */
export function snapshotPlainJson(value: unknown): unknown {
  if (value === null) return null;
  const t = typeof value;
  if (t === 'boolean') return value;
  if (t === 'number') {
    checkNoSpecialFloatValue(value as number);
    return value;
  }
  if (t === 'string') {
    checkLoneSurrogates(value as string);
    return value;
  }
  if (Array.isArray(value)) {
    if (!isPlainArrayPrototype(value)) {
      throw new CanonicalizationError(
        `Cannot canonicalize array: its prototype is not this realm's Array.prototype (an Array ` +
          `subclass instance, a Proxy, or a value from another realm); values from another realm ` +
          `must be re-parsed here first via fromJsonText. It is not plain JSON data.`,
      );
    }
    // One call observes every index AND `length` together; there is no
    // separate `value.length` read left for a `length` trap to answer
    // differently from the descriptor map this loop actually walks (Codex
    // P1, 2026-09-16 delta-6 gate: a transcript array reporting length 2
    // during validation and length 1 during reconstruction).
    // Cast, not a structural assignment: at runtime every property key on
    // the object `Object.getOwnPropertyDescriptors` returns is already a
    // string (array indices included -- `"0"`, `"1"`, ... -- same as any
    // other own key), so indexing it by `String(index)` below matches the
    // real keys exactly; the cast only tells TypeScript's mapped-array-type
    // inference to stop guessing and use that flat shape.
    const descriptors = Object.getOwnPropertyDescriptors(value) as unknown as Record<
      string,
      PropertyDescriptor
    >;
    const lengthDescriptor = descriptors.length;
    if (
      lengthDescriptor === undefined ||
      lengthDescriptor.get !== undefined ||
      typeof lengthDescriptor.value !== 'number' ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0
    ) {
      throw new CanonicalizationError(
        `Cannot canonicalize an array whose length is not a non-negative safe integer.`,
      );
    }
    const length = lengthDescriptor.value;
    // Built as `[]` and populated by `defineProperty` per index, never
    // `out[index] = ...` (a `[[Set]]`), for the same reason as the object
    // branch below: a plain array literal's indices have no inherited
    // accessor to intercept, so this is defence in depth here rather than
    // the fix for a live bug, but it keeps ONE population discipline for
    // both branches instead of two (must match the object branch's
    // `Object.defineProperty` use, and the mirrored array branch in
    // conformance/reference-runner-js/runner.mjs). Array's exotic
    // `[[DefineOwnProperty]]` still updates `length` to the highest index
    // defined, exactly as an array literal would.
    const out: unknown[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (descriptor === undefined) {
        throw new CanonicalizationError(
          `Cannot canonicalize array index ${index}: a sparse hole is not a plain element.`,
        );
      }
      if (descriptor.get !== undefined || descriptor.set !== undefined) {
        throw new CanonicalizationError(
          `Cannot canonicalize array index ${index}: it is an accessor property, not a plain ` +
            `element.`,
        );
      }
      if (!descriptor.enumerable) {
        // Same predicate as the object branch (own enumerable data
        // descriptors only), but an array cannot skip an index the way the
        // object branch skips a key: dropping it would renumber every later
        // element, so the index is refused, like a hole. Must match the
        // mirrored array branch in conformance/reference-runner-js/runner.mjs.
        throw new CanonicalizationError(
          `Cannot canonicalize array index ${index}: it is a non-enumerable property, not a ` +
            `plain element.`,
        );
      }
      Object.defineProperty(out, index, {
        value: snapshotPlainJson(descriptor.value),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  }
  if (t === 'object') {
    const obj = value as object;
    if (!isPlainObjectPrototype(obj)) {
      throw new CanonicalizationError(
        `Cannot canonicalize object: its prototype is not null or this realm's Object.prototype ` +
          `(a Date, Map, Set, boxed primitive, class instance, builtin, Proxy, or a value from ` +
          `another realm); values from another realm must be re-parsed here first via ` +
          `fromJsonText. It is not plain JSON data.`,
      );
    }
    // `Object.create(null)`, never `{}`: see this function's doc comment for
    // why a null-prototype copy is what makes the JSON key `"__proto__"` an
    // ordinary own data property instead of a trigger for an inherited
    // accessor.
    const out: Record<string, unknown> = Object.create(null);
    // The ONE call: every own key of `obj` is observed here, once. A key
    // absent from `obj` never appears in `descriptors` at all
    // (getOwnPropertyDescriptors omits it outright, rather than two calls
    // disagreeing about it), so there is no raced-deletion case left to
    // silently skip.
    const descriptors = Object.getOwnPropertyDescriptors(obj);
    // `Object.keys` of THIS descriptor map -- a fresh plain object this
    // function just built from the call above -- not of `obj`; enumerating
    // it performs no further read of the caller-controlled object at all,
    // and returns only string keys, so a symbol-keyed own property is
    // silently absent from the snapshot rather than read or rejected (the
    // same thing `JSON.parse` does: it never produces a symbol key either).
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key]!;
      if (!descriptor.enumerable) continue;
      if (descriptor.get !== undefined || descriptor.set !== undefined) {
        throw new CanonicalizationError(
          `Cannot canonicalize property ${JSON.stringify(key)}: it is an accessor property ` +
            `(getter/setter), not a plain data field.`,
        );
      }
      checkLoneSurrogates(key);
      // `defineProperty`, never `out[key] = ...`: see the invariant comment
      // on `Object.create(null)` above. `"__proto__"` is stored and later
      // emitted as the ordinary JSON key RFC 8785 and the Python
      // implementation both treat it as -- never as this copy's prototype.
      Object.defineProperty(out, key, {
        value: snapshotPlainJson(descriptor.value),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  }
  throw new CanonicalizationError(`Cannot canonicalize value of type ${t}`);
}

/**
 * Recursively serialize an ALREADY-SNAPSHOTTED plain value to RFC 8785
 * canonical JSON.
 *
 * Only `canonicalizeJcs` calls this, and only with `snapshotPlainJson`'s
 * return value: a fresh, realm-local copy this module built itself, holding
 * no accessor, no hole, and no foreign prototype. Reading `value[index]` or
 * `obj[k]` here is therefore never a second read of anything the CALLER
 * controls -- the caller's own object was read exactly once, by
 * `snapshotPlainJson`, before this function ever ran; this function only
 * ever reads data this module produced itself.
 *
 * `Object.keys(obj)` and `obj[k]` are safe reads here specifically because
 * `obj` is one of `snapshotPlainJson`'s null-prototype object copies (or a
 * plain `[]` array copy): with no prototype to inherit from, `obj[k]` for
 * ANY key -- including `"__proto__"` -- is an ordinary own-property
 * `[[Get]]`, never a hop onto an inherited accessor. `"__proto__"` sorts
 * into `keys` as an ordinary string (JCS orders member names by UTF-16 code
 * unit, and `Array.prototype.sort()`'s default comparator already does
 * that for ASCII key names), exactly as Python's `_stable_stringify` treats
 * it.
 */
function stableStringify(value: unknown): string {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') return JSON.stringify(value);
  if (t === 'string') return JSON.stringify(value as string);
  if (Array.isArray(value)) {
    const parts = value.map((item) => stableStringify(item));
    return '[' + parts.join(',') + ']';
  }
  // The only case left a snapshot can produce is a plain object built by
  // `snapshotPlainJson` itself (own string-keyed data properties only).
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
}
