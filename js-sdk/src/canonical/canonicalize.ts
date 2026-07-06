import { CanonicalizationError, checkLoneSurrogates, checkNoSpecialFloats } from './checks.js';

/**
 * Canonicalize a JSON-serializable value per RFC 8785 (JCS).
 * Returns a Buffer of the canonical UTF-8 bytes.
 */
export function canonicalizeJcs(value: unknown): Buffer {
  checkNoSpecialFloats(value);
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

function stableStringify(value: unknown): string {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') return JSON.stringify(value);
  if (t === 'string') {
    checkLoneSurrogates(value as string);
    return JSON.stringify(value as string);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(stableStringify).join(',') + ']';
  }
  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return (
      '{' +
      keys
        .map((k) => {
          checkLoneSurrogates(k);
          return JSON.stringify(k) + ':' + stableStringify(obj[k]);
        })
        .join(',') +
      '}'
    );
  }
  throw new CanonicalizationError(`Cannot canonicalize value of type ${t}`);
}
