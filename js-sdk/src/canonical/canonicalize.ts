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
 * Every own, enumerable, string-keyed DATA property is read through exactly
 * one call to `Object.getOwnPropertyDescriptor` and copied from that
 * descriptor's `value` field directly -- never through `obj[k]` or
 * `value[index]`, which perform a SEPARATE `[[Get]]` a Proxy can answer
 * differently than the descriptor it just reported for the same member
 * (Grok finding 1, 2026-09-16 delta-6 gate: a Proxy `get` trap returning one
 * value to a signature check and a different one to chain reconstruction).
 * An accessor descriptor (`get`/`set`) throws outright, and an array index
 * with no own descriptor -- a sparse hole, including one an inherited
 * index getter would otherwise answer -- throws too, instead of falling
 * through to an indexed read that would reach the prototype chain.
 *
 * Prototype identity is NOT checked. A plain object literal, `JSON.parse`
 * output in this realm, and `JSON.parse` output from a DIFFERENT realm (a
 * `node:vm` context, a browser iframe) all have different `Object.prototype`
 * identities but are equally plain JSON data; rejecting the foreign one was
 * itself a cross-realm canonicalization regression (Codex P2, 2026-09-16
 * delta-5 gate). `Object.keys`-style enumeration already promises to see
 * only own enumerable members regardless of prototype, so reading a value
 * through that same promise -- rather than layering a prototype-identity
 * check on top of it -- closes the accessor/Proxy class without reopening
 * the realm one.
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
    // `length` is read exactly once, right here; every index bound below
    // derives from THIS number, never from a fresh `value.length` read, so
    // a Proxy `length` trap that answers 2 on one call and 1 on another
    // cannot make this copy cover a shorter range than the one the loop
    // below actually visits (Codex P1, 2026-09-16 delta-6 gate: a transcript
    // array reporting length 2 during validation and length 1 during
    // reconstruction).
    const length = value.length;
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new CanonicalizationError(
        `Cannot canonicalize an array whose length is not a non-negative safe integer.`,
      );
    }
    const out: unknown[] = new Array(length);
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, index);
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
    const out: Record<string, unknown> = {};
    // `Object.keys` enumerates own enumerable string keys without reading
    // any member's value; the per-key descriptor read just below is the
    // ONLY read of that member's value, taken from the descriptor itself
    // rather than a follow-up `obj[k]`.
    for (const key of Object.keys(obj)) {
      const descriptor = Object.getOwnPropertyDescriptor(obj, key);
      if (descriptor === undefined) continue; // raced deletion between the two calls; absent either way
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
