import { CanonicalizationError, checkLoneSurrogates, checkNoSpecialFloatValue } from './checks.js';

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
 * Realm-agnostic plain-data test for a non-array object: true when the
 * prototype chain reaches null within two hops (a null-prototype object, or
 * an ordinary object whose one-hop prototype's own prototype is null --
 * `Object.prototype` in every realm, including a `node:vm` context or a
 * browser iframe, satisfies this without the two `Object.prototype`
 * identities ever being compared). This is a HOP COUNT, never an identity
 * check, which is what lets a cross-realm `JSON.parse` result pass while a
 * same-realm `Date`, `Map`, `Set`, boxed primitive, or class instance --
 * every one of them three or more hops from null -- does not (Grok finding
 * 2, 2026-09-16 delta-7 gate: removing the prior identity check to fix the
 * cross-realm case re-accepted those non-JSON types as `{}`).
 */
function hasPlainObjectPrototypeChain(value: object): boolean {
  const hop1 = Object.getPrototypeOf(value);
  return hop1 === null || Object.getPrototypeOf(hop1) === null;
}

/**
 * Realm-agnostic plain-data test for an array: true when the prototype
 * chain is exactly three hops to null (`Array.prototype`, then
 * `Object.prototype`, then null, in whichever realm constructed the
 * array). An `Array` subclass instance inserts an extra prototype level and
 * fails this count on purpose: `Array.isArray` alone does not distinguish a
 * plain array from a subclass instance, and a subclass instance is not
 * plain JSON data either (Grok finding 2, 2026-09-16 delta-7 gate).
 */
function hasPlainArrayPrototypeChain(value: object): boolean {
  const hop1 = Object.getPrototypeOf(value);
  if (hop1 === null) return false;
  const hop2 = Object.getPrototypeOf(hop1);
  if (hop2 === null) return false;
  return Object.getPrototypeOf(hop2) === null;
}

/**
 * Internal-slot brand test, not a prototype-chain test: true when `value`'s
 * `Object.prototype.toString` tag is the plain "Object" tag. A `Date`,
 * `RegExp`, `Error`, boxed primitive, or `Arguments` object carries its tag
 * on an internal slot the ECMAScript spec sets at construction; unlike
 * `[[Prototype]]`, that slot cannot be retargeted by
 * `Object.setPrototypeOf`, so this catches exactly the bypass the two
 * hop-count helpers above cannot: shortening or nulling such a value's
 * prototype chain to satisfy the hop count while its tag still reads e.g.
 * "Date" (Codex's second probe, 2026-09-16 delta-7 gate: "the
 * prototype-hop guard can be bypassed by shortening a branded object's or
 * class instance's prototype chain"). This tag itself reads an internal
 * slot, but the READ that exposes it -- `Object.prototype.toString.call` --
 * consults `value[Symbol.toStringTag]` first when present, so a value that
 * owns that symbol key directly, or whose one-hop prototype does, can make
 * this very function report "Object" for a `Date` or a boxed `Number`
 * without moving a single string key or changing the prototype-chain hop
 * count (Codex P1, 2026-09-16 delta-8 gate: a prototype-stripped `Date` or
 * boxed `Number` with an own `Symbol.toStringTag = "Object"` passed both
 * existing guards and canonicalized as `{}`). {@link hasDisallowedSymbolKey}
 * closes that by refusing any value, or its prototype, that owns a symbol
 * key the plain-data shape does not, and every call site below runs it
 * before trusting this function's answer.
 *
 * Bounded residual, stated once here for both this helper and
 * {@link hasPlainArrayPrototypeChain}'s array counterpart, now exact with
 * the symbol-key guard in place: an object whose prototype chain, tag, AND
 * own-and-prototype symbol keys have ALL been reduced to plain data (for
 * example a `Map` with its own prototype set to `null` and no symbol key on
 * itself or that null prototype -- it passes the hop count, tags as
 * "Object", and owns no disallowed symbol key) is indistinguishable from a
 * plain object holding the same own enumerable data properties -- it
 * canonicalizes as exactly those properties, and no such value can ever be
 * produced by `JSON.parse` or Python's `json.loads`, so cross-language
 * parity is unaffected. Mirrored in conformance/reference-runner-js/runner.mjs
 * as `hasPlainObjectTag`; must match.
 */
function hasPlainObjectTag(value: object): boolean {
  return Object.prototype.toString.call(value) === '[object Object]';
}

/**
 * Array counterpart of {@link hasPlainObjectTag}: true when `value` tags as
 * "[object Array]". `IsArray` (what this tag is keyed on) reflects the
 * exotic Array internal behaviour, not `[[Prototype]]`, so a real Array or
 * Array-subclass instance keeps this tag regardless of prototype tampering
 * -- the residual noted on {@link hasPlainObjectTag} applies here too, and
 * so does its symbol-key guard: an Array subclass instance with no own
 * properties beyond its indices and `length`, a shortened prototype chain,
 * and no disallowed symbol key, canonicalizes identically to a plain array
 * of the same elements and cannot be produced by `JSON.parse` either way.
 * Mirrored in conformance/reference-runner-js/runner.mjs as
 * `hasPlainArrayTag`; must match.
 */
function hasPlainArrayTag(value: object): boolean {
  return Object.prototype.toString.call(value) === '[object Array]';
}

/**
 * The own symbol keys a plain array's prototype (`Array.prototype`, in any
 * realm) legitimately owns: `Symbol.iterator` and `Symbol.unscopables`, and
 * nothing else, in every conforming realm including `node:vm`. Both are
 * well-known symbols, shared across realms by the ECMAScript spec (unlike a
 * registry symbol or a locally-constructed `Symbol()`), so comparing
 * against these exact two -- not merely "two symbols" -- is realm-safe.
 * Must match `ARRAY_PROTOTYPE_ALLOWED_SYMBOLS` in
 * conformance/reference-runner-js/runner.mjs.
 */
const ARRAY_PROTOTYPE_ALLOWED_SYMBOLS: readonly symbol[] = [Symbol.iterator, Symbol.unscopables];

/**
 * True when `value` itself owns a symbol-keyed property, or when its
 * prototype (when not null) owns a symbol-keyed property outside
 * `allowedPrototypeSymbols`. Run before the brand test above at every
 * `snapshotPlainJson` call site: `Symbol.toStringTag` is a symbol key, and
 * {@link hasPlainObjectTag} / {@link hasPlainArrayTag} read it through
 * `Object.prototype.toString`, so a value that owns one itself, or whose
 * one-hop prototype does, retargets the brand test's answer without moving
 * any string key or shortening the prototype chain (Codex P1, 2026-09-16
 * delta-8 gate).
 *
 * `value` itself never legitimately owns a symbol key for JSON data --
 * `JSON.parse` never produces one, and a plain object or array literal owns
 * none of its own -- so the allowed set applies ONLY to the prototype, and
 * only because a plain array's prototype is `Array.prototype`, which is not
 * itself plain data and does own two (see
 * {@link ARRAY_PROTOTYPE_ALLOWED_SYMBOLS}). A plain object's prototype
 * (`Object.prototype`, or null for a null-prototype object) owns no symbol
 * key at all, so callers pass an empty array there.
 */
function hasDisallowedSymbolKey(
  value: object,
  allowedPrototypeSymbols: readonly symbol[],
): boolean {
  if (Object.getOwnPropertySymbols(value).length !== 0) return true;
  const proto = Object.getPrototypeOf(value);
  if (proto === null) return false;
  const protoSymbols = Object.getOwnPropertySymbols(proto);
  return protoSymbols.some((s) => !allowedPrototypeSymbols.includes(s));
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
 * kept the second answer; a `getOwnPropertyDescriptor` trap that lies
 * starting on its second call passed the lie through the same way). This
 * function never calls `Object.keys`, `Object.getOwnPropertyDescriptor`, or
 * any indexed/keyed `[[Get]]` (`obj[k]`, `value[index]`) on the caller's
 * own value -- only on the descriptor MAP this function itself built from
 * that one call. An accessor descriptor (`get`/`set`) throws outright, and
 * an array index absent from the map -- a sparse hole, including one an
 * inherited index getter would otherwise answer -- throws too, instead of
 * falling through to an indexed read that would reach the prototype chain.
 *
 * Prototype IDENTITY is not checked -- that regressed cross-realm JSON (see
 * {@link hasPlainObjectPrototypeChain}) -- but prototype SHAPE is (the two
 * hop-count helpers above), internal-slot BRAND is (`hasPlainObjectTag`,
 * `hasPlainArrayTag`), and the absence of a disallowed SYMBOL KEY on the
 * value or its prototype is ({@link hasDisallowedSymbolKey}): shape alone
 * accepts a builtin whose `[[Prototype]]` was retargeted to pass the hop
 * count, brand alone accepts a cross-realm array whose `[[Prototype]]` a
 * hop-count-only test would reject, and brand alone is itself spoofable by
 * an own or one-hop-prototype `Symbol.toStringTag` (Codex P1, 2026-09-16
 * delta-8 gate), so a value must pass all three to snapshot.
 *
 * The copy this function returns is built with `Object.create(null)` (for
 * an object) or `[]` (for an array) and populated ONLY through
 * `Object.defineProperty`, never `[[Set]]` (`out[key] = ...` /
 * `out[index] = ...`): seeing details in the two branches below, this is
 * what makes the JSON key `"__proto__"` an ordinary own data property on
 * the copy instead of a trigger for the inherited `Object.prototype`
 * `__proto__` accessor.
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
    // Before the brand check below: a `Symbol.toStringTag` owned by
    // `value` itself, or by its one-hop prototype, would make
    // `hasPlainArrayTag` read whatever tag that symbol names instead of
    // the real internal slot (Codex P1, 2026-09-16 delta-8 gate).
    if (hasDisallowedSymbolKey(value, ARRAY_PROTOTYPE_ALLOWED_SYMBOLS)) {
      throw new CanonicalizationError(
        `Cannot canonicalize array: it or its prototype carries an own symbol-keyed property ` +
          `beyond the two well-known symbols a plain Array.prototype legitimately owns ` +
          `(Symbol.iterator, Symbol.unscopables); it is not plain JSON data.`,
      );
    }
    if (!hasPlainArrayPrototypeChain(value) || !hasPlainArrayTag(value)) {
      throw new CanonicalizationError(
        `Cannot canonicalize array: its prototype chain is not the plain three hops to null ` +
          `(Array.prototype, Object.prototype, null), or its internal tag is not "Array"; it ` +
          `is not plain JSON data.`,
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
    // Before the brand check below, and for the same reason as the array
    // branch above: an own or one-hop-prototype `Symbol.toStringTag` would
    // make `hasPlainObjectTag` read a spoofed tag (Codex P1, 2026-09-16
    // delta-8 gate: a prototype-stripped `Date` or null-prototype boxed
    // `Number` carrying `Symbol.toStringTag = "Object"` passed both
    // existing guards and canonicalized as `{}`). A plain object's
    // prototype legitimately owns no symbol key at all, so the allowed set
    // here is empty (contrast the array branch's two well-known symbols).
    if (hasDisallowedSymbolKey(obj, [])) {
      throw new CanonicalizationError(
        `Cannot canonicalize object: it or its prototype carries an own symbol-keyed ` +
          `property; it is not plain JSON data.`,
      );
    }
    if (!hasPlainObjectPrototypeChain(obj) || !hasPlainObjectTag(obj)) {
      throw new CanonicalizationError(
        `Cannot canonicalize object: its prototype chain does not reach null within two hops, ` +
          `or its internal tag is not "Object"; it is not plain JSON data (a Date, Map, Set, ` +
          `boxed primitive, class instance, or similar non-JSON type).`,
      );
    }
    // `Object.create(null)`, never `{}`: a `{}` copy inherits
    // `Object.prototype`, whose OWN `__proto__` property is an ACCESSOR
    // (get/set), not a plain data property. Populating such a copy with
    // `out[key] = value` (a `[[Set]]`) for the JSON key `"__proto__"` does
    // not create an own property at all -- it invokes that inherited
    // setter, which retargets the copy's OWN prototype to the JSON value
    // instead of storing it, so the key silently vanishes from every later
    // read (Grok and Codex verbatim, 2026-09-16 delta-7 gate: `{"a":1,
    // "__proto__":2}` canonicalized to `{"a":1}` against 23439e2, and an
    // object-valued `"__proto__"` additionally changed what the copy's OWN
    // prototype chain reported to the very hop-count test above). A
    // null-prototype copy has no inherited accessor at any key, so there is
    // nothing left to intercept.
    const out: Record<string, unknown> = Object.create(null);
    // The ONE call: every own key of `obj` is observed here, once. A key
    // absent from `obj` never appears in `descriptors` at all
    // (getOwnPropertyDescriptors omits it outright, rather than two calls
    // disagreeing about it), so there is no raced-deletion case left to
    // silently skip.
    const descriptors = Object.getOwnPropertyDescriptors(obj);
    // `Object.keys` of THIS descriptor map -- a fresh plain object this
    // function just built from the call above -- not of `obj`; enumerating
    // it performs no further read of the caller-controlled object at all.
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
