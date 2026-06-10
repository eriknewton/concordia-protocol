export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalizationError';
  }
}

/**
 * Reject a string containing an unpaired UTF-16 surrogate.
 *
 * `JSON.stringify` happily emits the `\udXXX` escape for a lone surrogate, so
 * without this guard the JS SDK would ACCEPT input that the Python reference
 * (`json.dumps(...).encode("utf-8")`) cannot serialize at all — a canonical
 * parity break and a verify divergence (JS over-accepts, Python crashes).
 * Both sides now fail closed identically: a lone surrogate is non-canonical.
 */
export function checkLoneSurrogates(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      // High surrogate: must be immediately followed by a low surrogate.
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++; // valid pair, consume both units
        continue;
      }
      throw new CanonicalizationError(
        `Cannot canonicalize string with unpaired UTF-16 high surrogate ` +
          `U+${code.toString(16).toUpperCase().padStart(4, '0')}; surrogates ` +
          `are non-canonical and diverge across language implementations.`,
      );
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      // Low surrogate with no preceding high surrogate.
      throw new CanonicalizationError(
        `Cannot canonicalize string with unpaired UTF-16 low surrogate ` +
          `U+${code.toString(16).toUpperCase().padStart(4, '0')}; surrogates ` +
          `are non-canonical and diverge across language implementations.`,
      );
    }
  }
}

export function checkNoSpecialFloats(value: unknown): void {
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new CanonicalizationError(
        `Cannot serialize non-finite number: ${value}`,
      );
    }
    if (Object.is(value, -0)) {
      throw new CanonicalizationError('Cannot serialize negative zero (-0)');
    }
    // Fail-closed on lossy large integers (Erik decision, 2026-05-29).
    //
    // Python's canonical_json formats an integer-form JSON number with
    // str(value), preserving full precision (9007199254740993 ->
    // "9007199254740993"). A JavaScript number cannot represent integers
    // beyond Number.MAX_SAFE_INTEGER distinctly: 9007199254740993 is already
    // stored as ...992, so emitting its plain-decimal digits would assert a
    // precision JS does not have and diverge from Python. Rather than emit a
    // wrong value, reject it and direct the caller to pass large integers as
    // strings (strings canonicalize identically in both languages).
    //
    // The guard is narrowed to numbers JS renders in PLAIN-DECIMAL form. When
    // JS renders exponential notation (1e+21, 1e+30), Python parses the same
    // JSON token as a float and produces the byte-identical exponential string
    // (verified: predicate fixture vector_08 uses 1e+30 and round-trips in both
    // languages), so there is no divergence and no false precision claim. Only
    // plain-decimal unsafe integers are lossy. Non-integer floats (1.5, -3.25)
    // and safe integers are unaffected.
    //
    // ONE CORNER THIS POST-PARSE GUARD CANNOT REACH (closed at ingest; see
    // below). A bare integer >= ~1e21 written in PLAIN DECIMAL in source JSON
    // parses to a JS double that String()s as EXPONENTIAL, so it slips past
    // this check, while a Python peer that holds it as an int emits full
    // decimal -> divergence (a verification failure, never a fail-open accept).
    // JS cannot distinguish such a lossy int from a legitimate float (e.g. the
    // 1e30 limit above) once it is a double, so the only true closure is at the
    // JSON parse/ingest boundary, before the double exists. That boundary now
    // exists: `parseJsonStrict` (canonical/parse.ts) inspects the SOURCE literal
    // and rejects bare unsafe integers at ingest, closing this corner for any
    // caller that ingests untrusted JSON through it (`signJson` / `verifyJson`
    // do so by default). This guard remains as the post-parse line of defense
    // for values built in-process rather than parsed from JSON, where it catches
    // every plain-decimal unsafe integer. Concordia's schema does not carry bare
    // integers this large (amounts are small ints / strings; limits are floats;
    // timestamps are ISO-8601 strings), so the realistic precision-loss cases
    // (16-19 digit IDs, nanosecond timestamps < 1e21) are caught here too.
    if (
      Number.isInteger(value) &&
      !Number.isSafeInteger(value) &&
      !/[eE]/.test(String(value))
    ) {
      throw new CanonicalizationError(
        `Cannot serialize unsafe integer ${value}: integers beyond ` +
          `Number.MAX_SAFE_INTEGER (2^53 - 1) lose precision in JavaScript ` +
          `and would diverge from the Python reference. Pass large integers ` +
          `as strings to canonicalize identically across languages.`,
      );
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) checkNoSpecialFloats(item);
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value)) checkNoSpecialFloats(v);
  }
}
