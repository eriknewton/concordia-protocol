import { CanonicalizationError } from './checks.js';

/**
 * Parse untrusted JSON for signing, verification, or canonicalization, failing
 * closed on any bare integer literal that JavaScript cannot hold without
 * precision loss (|value| > Number.MAX_SAFE_INTEGER, i.e. 2^53 - 1).
 *
 * WHY THIS EXISTS -- parse-boundary hardening, the follow-up logged in the
 * canonicalizer's large-integer guard (`checkNoSpecialFloats` in checks.ts).
 *
 * `canonicalizeJcs` / `checkNoSpecialFloats` reject a lossy integer only when
 * JavaScript renders it in PLAIN-DECIMAL form (e.g. `9007199254740993`, or
 * `1e20` which `String()`s as `"100000000000000000000"`). They cannot close
 * one corner: a bare integer >= ~1e21 written in plain decimal in the source
 * JSON (`123456789012345678901`) is parsed by `JSON.parse` into a JS double
 * whose `String()` is EXPONENTIAL (`"1.2345678901234568e+20"`), so it slips
 * past the canonicalizer's plain-decimal guard, while a Python peer holding the
 * same token as an arbitrary-precision `int` emits full decimal -> the canonical
 * bytes diverge (a verification failure, never a fail-open accept). Once parsed,
 * JavaScript cannot tell such a lossy integer apart from a legitimate large
 * float -- the `1e30` predicate limit in fixture vector_08 lives in the same
 * exponential band -- so the only place to distinguish them is the SOURCE TEXT,
 * before `JSON.parse` collapses the literal into a double. That is what this
 * function inspects.
 *
 * THE RULE. A number literal is rejected iff it is written in INTEGER form (no
 * `.`, no `e`/`E` exponent) AND its value is not a safe integer. Everything
 * else is accepted unchanged:
 *   - floats and exponential literals (`1.5`, `-3.25`, `1e+30`, `1e-9`) --
 *     Python parses these as floats and emits the byte-identical form, so there
 *     is no divergence and no false precision claim (fixture vector_08's
 *     `1e+30` still round-trips);
 *   - safe integers up to and including `Number.MAX_SAFE_INTEGER`;
 *   - big integers carried as JSON STRINGS (`"123456789012345678901"`) -- the
 *     supported escape hatch, since strings canonicalize identically in both
 *     languages.
 *
 * Reading the literal from the SOURCE (not from the parsed value) is what lets
 * this catch the >= 1e21 plain-decimal case the canonicalizer misses, on top of
 * the 16-19 digit cases it already catches. It is a lexical scan rather than a
 * `JSON.parse` reviver because the reviver's source-text `context` argument
 * (which would expose the same literal) only exists on Node 21+/ES2025, and this
 * package supports Node >= 20; a reviver without it sees only the already-lossy
 * double and so cannot detect the >= 1e21 case at all.
 *
 * Malformed JSON propagates as the native `SyntaxError` from `JSON.parse`. The
 * unsafe-integer rejection is a {@link CanonicalizationError} -- the same error
 * type and the same fail-closed posture as the canonicalizer's large-integer
 * guard, because it enforces the same cross-language precision invariant one
 * step earlier, at ingest.
 *
 * @param text Raw JSON source text.
 * @returns The parsed value, safe to hand to `canonicalizeJcs`, `sign`, or
 *   `verify` without silent precision loss.
 * @throws {SyntaxError} if `text` is not well-formed JSON.
 * @throws {CanonicalizationError} if `text` contains a bare (non-string)
 *   integer literal outside the JS safe-integer range, or `text` is not a
 *   string.
 */
export function parseJsonStrict(text: string): unknown {
  if (typeof text !== 'string') {
    throw new CanonicalizationError('parseJsonStrict expects a JSON string');
  }
  // Validate the grammar with the authoritative native parser first: a
  // malformed document throws SyntaxError here, before the scan runs, so the
  // scan only ever sees well-formed JSON.
  const parsed: unknown = JSON.parse(text);
  // Then scan the SOURCE text for unsafe integer literals. The parsed value is
  // returned only if the scan finds none, so a lossy double never escapes this
  // function as an accepted result.
  rejectUnsafeIntegerLiterals(text);
  return parsed;
}

const QUOTE = 0x22; // "
const BACKSLASH = 0x5c; // \
const MINUS = 0x2d; // -
const PLUS = 0x2b; // +
const DOT = 0x2e; // .
const LOWER_E = 0x65; // e
const UPPER_E = 0x45; // E
const ZERO = 0x30; // 0
const NINE = 0x39; // 9

/**
 * Single left-to-right pass over well-formed JSON source that throws on the
 * first bare integer literal outside the JS safe-integer range. String literals
 * (including big integers carried as strings) are skipped wholesale, so only
 * structural number tokens are inspected.
 */
function rejectUnsafeIntegerLiterals(text: string): void {
  const n = text.length;
  let i = 0;
  while (i < n) {
    const ch = text.charCodeAt(i);

    if (ch === QUOTE) {
      // Skip the entire string literal, honoring backslash escapes, so a value
      // carried as a string ("123...901") is never inspected as a number.
      i += 1;
      while (i < n) {
        const c = text.charCodeAt(i);
        if (c === BACKSLASH) {
          i += 2; // skip the escape and the escaped character together
          continue;
        }
        i += 1;
        if (c === QUOTE) break; // closing quote
      }
      continue;
    }

    // A number token starts with '-' or a digit. In well-formed JSON, '-' only
    // ever begins a (negative) number.
    if (ch === MINUS || (ch >= ZERO && ch <= NINE)) {
      const start = i;
      let integerForm = true; // until a '.' or an exponent marker appears
      i += 1;
      while (i < n) {
        const c = text.charCodeAt(i);
        if (c >= ZERO && c <= NINE) {
          i += 1;
        } else if (c === DOT || c === LOWER_E || c === UPPER_E) {
          // Fraction or exponent -> a float literal, parity-safe across
          // languages; this token is exempt from the integer check.
          integerForm = false;
          i += 1;
        } else if (c === PLUS || c === MINUS) {
          // '+' / '-' only follow an exponent marker in well-formed JSON.
          i += 1;
        } else {
          break;
        }
      }
      if (integerForm) {
        const literal = text.slice(start, i);
        if (!Number.isSafeInteger(Number(literal))) {
          throw new CanonicalizationError(
            `Cannot ingest unsafe integer literal ${literal}: bare integers ` +
              `beyond Number.MAX_SAFE_INTEGER (2^53 - 1) lose precision when ` +
              `parsed into a JavaScript number and would diverge from the ` +
              `Python reference's canonical bytes. Carry large integers as ` +
              `JSON strings ("${literal}") to canonicalize identically across ` +
              `languages.`,
          );
        }
      }
      continue;
    }

    i += 1;
  }
}
