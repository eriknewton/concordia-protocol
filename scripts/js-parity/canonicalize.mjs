// RFC 8785 JSON Canonicalization Scheme (JCS) — JavaScript reference.
//
// Mirrors concordia.canonicalization.canonicalize_jcs() and
// canonicalize_predicate() exactly. Output is byte-identical to
// concordia.signing.canonical_json for any value JSON.parse can produce.
//
// Semantics (per concordia/canonicalization.py docstring):
//   1. Object keys sorted by UTF-16 code units (JS default sort).
//   2. No whitespace between JSON tokens.
//   3. Strings use RFC 8259 mandatory escapes + \u00XX for U+0000-U+001F;
//      all other characters (including non-ASCII) emit raw UTF-8.
//      JSON.stringify(str) already produces this exact form.
//   4. Numbers formatted per ECMA-262 Number::toString
//      (JSON.stringify(num) produces this natively for finite numbers).
//   5. null for missing/null; booleans serialize as true / false.
//   6. NaN, Infinity, and -0 are rejected with a thrown Error before
//      serialization. Negative zero is detected via Object.is(v, -0).
//   7. canonicalizePredicate strips the top-level `signature` field
//      (nested signature fields are preserved, per the Python helper).

function rejectSpecialNumber(value) {
  if (typeof value !== "number") return;
  if (!Number.isFinite(value)) {
    throw new Error(`Cannot serialize non-finite number: ${value}`);
  }
  if (Object.is(value, -0)) {
    throw new Error("Cannot serialize negative zero (-0)");
  }
}

function stableStringify(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    rejectSpecialNumber(value);
    return JSON.stringify(value);
  }
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  if (t === "object") {
    const keys = Object.keys(value).sort();
    return (
      "{" +
      keys
        .map((k) => JSON.stringify(k) + ":" + stableStringify(value[k]))
        .join(",") +
      "}"
    );
  }
  throw new TypeError(`Cannot canonicalize type: ${t}`);
}

function checkNoSpecialFloats(value) {
  if (typeof value === "number") {
    rejectSpecialNumber(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) checkNoSpecialFloats(v);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const v of Object.values(value)) checkNoSpecialFloats(v);
  }
}

export function canonicalizeJcs(value) {
  checkNoSpecialFloats(value);
  return Buffer.from(stableStringify(value), "utf8");
}

export function canonicalizePredicate(predicate) {
  if (predicate === null || typeof predicate !== "object" || Array.isArray(predicate)) {
    throw new TypeError("canonicalizePredicate expects a JSON object");
  }
  const { signature: _stripped, ...rest } = predicate;
  return canonicalizeJcs(rest);
}
