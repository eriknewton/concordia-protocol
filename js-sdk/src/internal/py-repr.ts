/**
 * Shared CPython `repr()` helpers for byte-identical enum-`ValueError` text.
 *
 * Several layers reproduce Python's `f"{value!r} is not a valid <Enum>"` error
 * text when coercing a wire value into an enum (mandate `TemporalMode`, session
 * `MessageType`). The text must be BYTE-IDENTICAL to CPython's, which means the
 * value must be rendered exactly as CPython `repr()` would render it -- including
 * CPython's quote-selection and escaping rules for strings.
 *
 * This module is the single source of truth for that rendering so the mandate
 * and session layers share ONE implementation instead of drifting copies. It was
 * extracted from `src/mandate/mandate.ts` (the most complete prior copy) without
 * behavior change; the mandate layer now imports from here.
 */

/**
 * Render a value the way CPython's `repr()` would, so enum-`ValueError` text is
 * BYTE-IDENTICAL to Python's `f"{value!r} is not a valid <Enum>"`.
 *
 * The value reaching this path is any JSON-shaped value (string, number,
 * boolean, null, array, object), possibly nested. Python's `repr()` quotes
 * strings, renders `None`/`True`/`False`, and reprs list / dict elements
 * RECURSIVELY with `[a, b]` / `{k: v}` spacing -- e.g. `[]` gives `"[]"` (not JS
 * `String([])` -> `""`), and `{}` gives `"{}"` (not `"[object Object]"`). This
 * reproduces CPython `repr()` for that value space.
 */
export function pyRepr(value: unknown): string {
  if (typeof value === 'string') return pyReprString(value);
  if (value === null || value === undefined) return 'None';
  if (value === true) return 'True';
  if (value === false) return 'False';
  if (typeof value === 'number') return pyReprNumber(value);
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) {
    return `[${value.map(pyRepr).join(', ')}]`;
  }
  if (typeof value === 'object') {
    // dict: `{repr(k): repr(v), ...}` in insertion order, recursive.
    const inner = Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${pyRepr(k)}: ${pyRepr(v)}`)
      .join(', ');
    return `{${inner}}`;
  }
  // Any other JS type (symbol, function) cannot appear in a JSON-shaped wire
  // value; fall back to String() so the helper is still total.
  return String(value);
}

/**
 * CPython `repr()` of a `str`, byte-identical to `unicode_repr` in CPython.
 *
 * Quote selection: CPython quotes with `'` by default, but switches to `"` when
 * the string contains a `'` AND no `"`. The active quote and `\` are
 * backslash-escaped inside; `\t` / `\n` / `\r` use their named escapes; every
 * other non-"printable" code point (CPython `str.isprintable()`, i.e. NOT in
 * Unicode categories Cc/Cf/Cs/Co/Cn/Zl/Zp/Zs, with ASCII space 0x20 the one
 * printable separator) escapes as `\xNN` (cp < 0x100), `\uNNNN` (< 0x10000), or
 * `\UNNNNNNNN` (astral), lowercase hex, fixed width. Iterates by CODE POINT
 * (`[...s]`) so astral chars get one `\U........` escape, not two surrogate
 * halves -- matching CPython, which reprs by code point.
 */
export function pyReprString(s: string): string {
  // CPython: default single-quote; use double only when a single-quote is
  // present and a double-quote is absent.
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = quote;
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    if (ch === quote || ch === '\\') {
      out += '\\' + ch;
    } else if (ch === '\t') {
      out += '\\t';
    } else if (ch === '\n') {
      out += '\\n';
    } else if (ch === '\r') {
      out += '\\r';
    } else if (isPyPrintable(ch, cp)) {
      out += ch;
    } else if (cp < 0x100) {
      out += '\\x' + cp.toString(16).padStart(2, '0');
    } else if (cp < 0x10000) {
      out += '\\u' + cp.toString(16).padStart(4, '0');
    } else {
      out += '\\U' + cp.toString(16).padStart(8, '0');
    }
  }
  return out + quote;
}

/**
 * Non-printable code points per CPython `str.isprintable()`: any character whose
 * Unicode general category is Other (Cc control, Cf format, Cs surrogate, Co
 * private-use, Cn unassigned) or Separator (Zl line, Zp paragraph, Zs space),
 * EXCEPT ASCII space 0x20 which CPython treats as printable.
 *
 * KNOWN PARITY RESIDUAL (accepted 2026-05-29, fail-CLOSED + unreachable): this
 * uses the JS runtime's Unicode tables (\p{...}), which can disagree with
 * CPython's Unicode database VERSION at the printability boundary for some
 * UNASSIGNED astral code points (e.g. U+3203F: Node may treat printable while
 * CPython escapes it). It only affects the repr() ERROR TEXT of an INVALID enum
 * value that is such a code point -- a value that is rejected either way (no
 * fail-open) and never occurs as a real value (TemporalMode and MessageType are
 * tiny ASCII enums). Full closure would require pinning a Unicode-DB version to
 * CPython's, which is brittle and not worth it; deferred.
 */
const NON_PRINTABLE_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;

/** True when CPython `str.isprintable()` would treat this code point as printable. */
function isPyPrintable(ch: string, cp: number): boolean {
  if (cp === 0x20) return true; // ASCII space: the lone printable separator.
  return !NON_PRINTABLE_RE.test(ch);
}

/**
 * CPython `repr()` of a number reaching an enum path. The value is JSON-shaped,
 * and JSON carries no int/float tag, so a wire `100.0` and `100` BOTH parse to a
 * JS `number` that `repr()`s as the integer `100` on either side (Python
 * `json.loads("100.0")` -> int via the same collapse) -- so an integer-valued
 * finite number reprs WITHOUT a trailing `.0`, matching the value space that can
 * actually arrive. The only floats that cannot be JSON-sourced are the
 * non-finite ones (an in-memory JS value, never parsed JSON): CPython reprs those
 * as `nan` / `inf` / `-inf`, which JS `String()` would wrongly render as `NaN` /
 * `Infinity` / `-Infinity`, so map them explicitly. Finite non-integers (e.g.
 * `1.5`) match JS `String()` for the decimal forms that survive a JSON
 * round-trip.
 */
export function pyReprNumber(n: number): string {
  if (Number.isNaN(n)) return 'nan';
  if (n === Infinity) return 'inf';
  if (n === -Infinity) return '-inf';
  return String(n);
}
