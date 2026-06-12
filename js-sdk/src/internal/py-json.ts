/**
 * CPython `json.dumps(value, sort_keys=True)` parity renderer.
 *
 * The post-#95 schema-validation error format reports the violated constraint
 * as `json.dumps(error.validator_value, sort_keys=True)` (Python
 * `concordia/schema_validator.py` `_format_validation_error`). This module
 * reproduces that rendering byte-for-byte for the value space that can appear
 * as a `validator_value` in the bundled Concordia schemas (parsed-JSON
 * scalars, arrays, and objects):
 *
 * - DEFAULT SEPARATORS: `", "` between items and `": "` after keys (Python's
 *   defaults when `indent` is None), NOT the compact JCS separators used by
 *   the canonicalization layer.
 * - `sort_keys=True`: object keys sorted ascending. Python compares `str` by
 *   CODE POINT; JS default sort compares UTF-16 code units, which diverges for
 *   astral-plane keys, so the comparator here sorts by code point explicitly.
 * - `ensure_ascii=True` (Python's default): every non-ASCII character (and
 *   every control character) is `\uXXXX`-escaped, with astral characters
 *   emitted as surrogate PAIRS — exactly Python's behavior. This also makes
 *   the rendered string pure ASCII, so the caller's code-point truncation cap
 *   can use plain `.length` / `.slice`.
 * - INT vs FLOAT: Python renders `0.0` (a JSON-source float) as "0.0" but `0`
 *   as "0". A JS number cannot carry that distinction, so the schema bundle
 *   exports a generated registry of float-sourced constraint locations
 *   (`FLOAT_CONSTRAINT_PATHS` in `validation/schemas.ts`); the caller passes
 *   it here as a WeakMap of schema-object node -> set of float-valued keys,
 *   plus a flag for the root value itself. Integral numbers at a marked
 *   location render with a trailing ".0". Non-integral numbers use JS
 *   shortest-round-trip `String(n)`, which equals Python `repr(float)` for
 *   the magnitude range schema constraints live in (Python switches to
 *   exponent notation at 1e16 / 1e-5, JS at 1e21 / 1e-7; the bundled schemas
 *   contain no such values, and the Python-generated fixtures would catch one
 *   the moment it appeared).
 * - Non-JSON leaf types (`undefined`, functions, symbols, bigints), which
 *   Python's `json.dumps` raises `TypeError` on, throw here, and the caller
 *   renders Python's content-free `<unrenderable>` fallback.
 *
 * SECURITY: this renderer is only ever fed SCHEMA-SIDE values (the violated
 * constraint), never the rejected instance, so nothing here can echo
 * attacker-controlled input. Keep it that way.
 */

/** Schema-object node -> names of its float-sourced numeric keys. */
export type FloatConstraintMap = WeakMap<object, Set<string>>;

/**
 * Render `value` exactly like CPython `json.dumps(value, sort_keys=True)`.
 *
 * @param value The (parsed-JSON) value to render.
 * @param floatConstraints Optional registry of float-sourced schema numbers.
 * @param rootIsFloat Whether `value` ITSELF is a float-sourced number (the
 *   registry is keyed by parent object, so a scalar root needs this flag).
 */
export function pyJsonDumps(
  value: unknown,
  floatConstraints?: FloatConstraintMap,
  rootIsFloat = false,
): string {
  return render(value, rootIsFloat, floatConstraints);
}

function render(
  value: unknown,
  isFloat: boolean,
  floats: FloatConstraintMap | undefined,
): string {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') return renderNumber(value, isFloat);
  if (typeof value === 'string') return renderString(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    // Array ELEMENTS are never float-marked: the generated registry only keys
    // object properties, and no bundled schema carries a float inside an
    // array (enum lists are strings; a float there would surface as a fixture
    // mismatch the moment Python rendered it differently).
    return `[${value.map((el) => render(el, false, floats)).join(', ')}]`;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort(codePointCompare);
    if (keys.length === 0) return '{}';
    const floatKeys = floats?.get(obj);
    const parts = keys.map(
      (k) =>
        `${renderString(k)}: ${render(obj[k], floatKeys?.has(k) ?? false, floats)}`,
    );
    return `{${parts.join(', ')}}`;
  }
  // undefined / function / symbol / bigint: Python json.dumps raises
  // TypeError ("Object of type ... is not JSON serializable"). Fail loudly so
  // the caller's catch renders the content-free `<unrenderable>` fallback.
  throw new TypeError(`pyJsonDumps: value of type ${typeof value} is not JSON serializable`);
}

/** Python `json.dumps` number rendering (int repr vs float repr). */
function renderNumber(n: number, isFloat: boolean): string {
  if (!Number.isFinite(n)) {
    // Python's default allow_nan=True renders these literals. Unreachable
    // from parsed-JSON schemas; kept for strict parity.
    if (Number.isNaN(n)) return 'NaN';
    return n > 0 ? 'Infinity' : '-Infinity';
  }
  if (Object.is(n, -0)) {
    // JSON `-0.0` parses to JS -0 and Python float -0.0 (repr "-0.0"); a JSON
    // source `-0` is Python int 0 (repr "0"), matching JS String(-0)'s "0"
    // only via this branch's else.
    return isFloat ? '-0.0' : '0';
  }
  const base = String(n);
  if (
    isFloat &&
    Number.isInteger(n) &&
    !base.includes('.') &&
    !base.includes('e') &&
    !base.includes('E')
  ) {
    return `${base}.0`;
  }
  return base;
}

/** Python `json.dumps` string rendering with `ensure_ascii=True`. */
function renderString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    const ch = s[i];
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (code === 0x08) out += '\\b';
    else if (code === 0x0c) out += '\\f';
    else if (code < 0x20 || code > 0x7e) {
      // Python escapes everything outside printable ASCII (space..~),
      // including DEL (0x7f), per UTF-16 unit (astral chars come through this
      // loop as their surrogate pair, exactly like Python's output).
      out += `\\u${code.toString(16).padStart(4, '0')}`;
    } else out += ch;
  }
  return `${out}"`;
}

/** Python `sorted(dict)` string ordering: ascending by CODE POINT. */
function codePointCompare(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const ca = a.codePointAt(i) as number;
    const cb = b.codePointAt(j) as number;
    if (ca !== cb) return ca - cb;
    i += ca > 0xffff ? 2 : 1;
    j += cb > 0xffff ? 2 : 1;
  }
  return a.length - i - (b.length - j);
}
