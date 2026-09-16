import { CanonicalizationError, checkLoneSurrogates, checkNoSpecialFloatValue } from './checks.js';

/**
 * Canonicalize a JSON-serializable value per RFC 8785 (JCS).
 * Returns a Buffer of the canonical UTF-8 bytes.
 *
 * `stableStringify` is the ONLY traversal: it validates and serializes each
 * member on the same read (see its doc comment). A prior version ran
 * `checkNoSpecialFloats(value)` as a pre-pass ahead of this call, which read
 * every member of `value` twice before it produced any bytes -- exactly the
 * shape that let a getter answer the pre-pass one way and the serialization
 * pass another (Codex P1/P2, 2026-09-16 delta-5 gate).
 */
export function canonicalizeJcs(value: unknown): Buffer {
  const str = stableStringify(value);
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
 * True when `owner`'s own property `key` is a getter/setter rather than a
 * plain data slot.
 *
 * `Object.getOwnPropertyDescriptor` never invokes the accessor -- it only
 * inspects the property's shape -- so calling this ahead of the one read
 * that serializes the value does not add a second read of the VALUE. What it
 * closes is the case a descriptor check can see and a value read cannot: an
 * accessor is refused outright, every time, so it can never return one
 * number to a guard and a different one to the digest (Codex P1/P2,
 * 2026-09-16 delta-5 gate: an enumerable `prev_hash` getter that answered
 * chain reconstruction and the final `chain_head` comparison differently, and
 * a numeric getter that passed a special-float guard and then serialized as
 * `NaN`/`Infinity`/`-0`).
 */
function isAccessorProperty(owner: object, key: string | number): boolean {
  const descriptor = Object.getOwnPropertyDescriptor(owner, key);
  return descriptor !== undefined && (descriptor.get !== undefined || descriptor.set !== undefined);
}

/**
 * Reject an object or array whose prototype is not the plain shape this
 * traversal actually walks.
 *
 * `stableStringify` reads an object via `Object.keys` and an array via
 * index, which see only OWN enumerable members -- never a member reachable
 * solely through the prototype chain (an inherited getter, an inherited
 * `toJSON`). A `{...}` literal or `JSON.parse` output has prototype
 * `Object.prototype`; `Object.create(null)` has prototype `null`; both are
 * plain data and covered by this rule elsewhere in the SDK (see
 * `isPlainObject` in predicate/references.ts). A `{...}` or `[...]` array
 * literal has prototype `Array.prototype`. Any other prototype (a class
 * instance, a `Proxy`, a `toJSON`-bearing shape) is refused rather than
 * trusted, since canonicalization covers plain data only and cannot see
 * what such a prototype might add.
 */
function rejectForeignPrototype(value: object, kind: 'object' | 'array'): void {
  const proto = Object.getPrototypeOf(value);
  const isPlain =
    kind === 'array' ? proto === Array.prototype : proto === Object.prototype || proto === null;
  if (!isPlain) {
    throw new CanonicalizationError(
      `Cannot canonicalize a plain ${kind} whose prototype has been replaced; ` +
        `canonicalization covers plain data only.`,
    );
  }
}

/**
 * Recursively serialize `value` to RFC 8785 canonical JSON.
 *
 * This is the ONLY traversal `canonicalizeJcs` runs. Every check -- special
 * floats, lone surrogates, accessor properties, foreign prototypes -- fires
 * on the exact read that also produces the byte for that member, so there is
 * no earlier or later read of the same caller-controlled value that could
 * see something different (Codex P1/P2, 2026-09-16 delta-5 gate; must match
 * the equivalent single-traversal `jcs` in
 * conformance/reference-runner-js/runner.mjs).
 */
function stableStringify(value: unknown): string {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    checkNoSpecialFloatValue(value as number);
    return JSON.stringify(value);
  }
  if (t === 'string') {
    checkLoneSurrogates(value as string);
    return JSON.stringify(value as string);
  }
  if (Array.isArray(value)) {
    rejectForeignPrototype(value, 'array');
    // A manual index loop, not `.map`: `Array.prototype.map` performs its
    // own `Get` on each index to build the callback's `item` argument, which
    // would invoke an accessor BEFORE this function's own descriptor check
    // ever ran. Checking the descriptor first and reading `value[index]`
    // only afterward keeps this the single read the accessor guard depends
    // on, exactly as the object branch below does for `obj[k]`.
    const parts: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (isAccessorProperty(value, index)) {
        throw new CanonicalizationError(
          `Cannot canonicalize array index ${index}: it is an accessor property, not a plain ` +
            `element.`,
        );
      }
      parts.push(stableStringify(value[index]));
    }
    return '[' + parts.join(',') + ']';
  }
  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    rejectForeignPrototype(obj, 'object');
    const keys = Object.keys(obj).sort();
    return (
      '{' +
      keys
        .map((k) => {
          if (isAccessorProperty(obj, k)) {
            throw new CanonicalizationError(
              `Cannot canonicalize property ${JSON.stringify(k)}: it is an accessor property ` +
                `(getter/setter), not a plain data field.`,
            );
          }
          checkLoneSurrogates(k);
          return JSON.stringify(k) + ':' + stableStringify(obj[k]);
        })
        .join(',') +
      '}'
    );
  }
  throw new CanonicalizationError(`Cannot canonicalize value of type ${t}`);
}
