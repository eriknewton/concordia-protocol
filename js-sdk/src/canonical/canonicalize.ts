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
 * {@link hasPlainObjectPrototypeChain}) -- but prototype SHAPE is: see the
 * two hop-count helpers above.
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
    if (!hasPlainArrayPrototypeChain(value)) {
      throw new CanonicalizationError(
        `Cannot canonicalize array: its prototype chain is not the plain three hops to null ` +
          `(Array.prototype, Object.prototype, null); it is not plain JSON data.`,
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
    const out: unknown[] = new Array(length);
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
      out[index] = snapshotPlainJson(descriptor.value);
    }
    return out;
  }
  if (t === 'object') {
    const obj = value as object;
    if (!hasPlainObjectPrototypeChain(obj)) {
      throw new CanonicalizationError(
        `Cannot canonicalize object: its prototype chain does not reach null within two hops; ` +
          `it is not plain JSON data (a Date, Map, Set, boxed primitive, class instance, or ` +
          `similar non-JSON type).`,
      );
    }
    const out: Record<string, unknown> = {};
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
      out[key] = snapshotPlainJson(descriptor.value);
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
