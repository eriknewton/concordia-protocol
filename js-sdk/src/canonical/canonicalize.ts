import {
  CanonicalizationError,
  checkLoneSurrogates,
  checkNoSpecialFloats,
} from './checks.js';

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
export function canonicalizePredicate(
  predicate: Record<string, unknown>,
): Buffer {
  const { signature: _stripped, ...rest } = predicate;
  return canonicalizeJcs(rest);
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
  throw new CanonicalizationError(
    `Cannot canonicalize value of type ${t}`,
  );
}
