/**
 * Attestation-level reference validation (SPEC §11.5).
 *
 * Port of `concordia.attestation._validate_reference` -- the only piece of the
 * attestation module the predicate layer strictly depends on. The full
 * attestation generator depends on the not-yet-ported `Session` lifecycle and
 * is deferred; this helper is session-independent and is reused by the
 * predicate primitive (both on read in `Predicate.from_dict` and on write in
 * the predicate schema check).
 *
 * Parity contract (verified against Python `_validate_reference` via fixtures
 * in `tests/fixtures/predicate/predicate_vectors.json`, `reference_cases`):
 * - Required keys are `type`, `id`, `relationship` (§11.5.6). A non-dict ref,
 *   a missing required key, or an empty/non-string required value raises
 *   `ReferenceValidationError` with the SAME message text Python's `ValueError`
 *   carries (the SPEC clause citations are part of the contract because callers
 *   surface the text).
 * - The missing-keys error lists keys in the canonical order
 *   `(id, type, relationship)`-checked-as-`(type, id, relationship)`: Python
 *   builds the list via `[k for k in ("type", "id", "relationship") if k not in ref]`,
 *   so the order in the message is type, then id, then relationship.
 * - `type` and `relationship` values OUTSIDE the canonical vocabularies are
 *   PRESERVED as opaque strings (§11.5.8 forward-compat MUST), not rejected.
 * - Optional keys `version`, `signed_at`, `signer_did`, `extensions` are passed
 *   through when present; ALL OTHER keys are DROPPED from the normalized output
 *   (Python rebuilds a fresh dict with only the known keys).
 *
 * L3 hardening (security audit 2026-06-09; port of Python PR #95): every
 * string field is length-capped and whitespace-banned (legitimate identifiers
 * such as UUIDs, DIDs, URNs, ISO timestamps, and semver never contain
 * whitespace, so any whitespace indicates prose deal terms), and `extensions`
 * is structure-capped (nesting depth, node count) BEFORE being size-capped
 * (canonical-JSON UTF-8 bytes), so the §11.5.8 opaque-string forward-compat
 * clause cannot be used to smuggle free-text deal terms or unbounded payloads
 * into a signed attestation. Fail-closed: oversize or wrongly-typed values
 * throw {@link ReferenceValidationError}; invalid values are NEVER echoed back
 * in the error text (content-injection lens: these errors can land in logs and
 * MCP responses), and nothing is ever silently truncated or coerced.
 *
 * SNAPSHOT SEMANTICS (adversarial-review fix, 2026-06-12): validation runs
 * against a defensive plain-data SNAPSHOT of the input, never against the
 * caller's live object, and the normalized result (including `extensions`) is
 * that snapshot, never a reference to caller-owned data. Concretely:
 * - Property values are read via `Object.getOwnPropertyDescriptor(...).value`,
 *   so a GETTER IS NEVER EXECUTED. The previous walk used `Object.values()`,
 *   which invokes enumerable getters; a getter that throws leaked its
 *   attacker-controlled error text verbatim (no-echo violation), and a getter
 *   that answers differently across reads could pass validation with one value
 *   and serialize another later (TOCTOU). Accessor properties are REJECTED
 *   outright rather than sampled: Python's plain-dict model cannot represent
 *   an accessor, so nothing legitimate is lost, and rejecting (instead of
 *   snapshotting the getter's current answer) means hostile code is never run
 *   at all.
 * - Symbol keys, non-enumerable own properties, array holes, non-index array
 *   properties, and array subclasses are likewise rejected (none is
 *   representable in canonical JSON or in a Python dict). Non-writable DATA
 *   properties (e.g. a frozen input) remain accepted.
 * - The ENTIRE inspection is wrapped so that ANY foreign throw (a Proxy trap,
 *   a revoked proxy, a hostile prototype) is converted to a sanitized
 *   {@link ReferenceValidationError} that includes NEITHER the caught error
 *   text NOR any input value.
 * - The canonical-byte cap is measured over the SNAPSHOT, and the snapshot is
 *   what callers get back, so the bytes that were capped are exactly the bytes
 *   any later serialization will emit.
 *
 * JS/Python divergence decisions (each resolved in the STRICTER, fail-closed
 * direction, and each pinned by a test):
 * - WHITESPACE: Python's `\s` on `str` patterns matches Unicode whitespace
 *   INCLUDING U+001C..U+001F (FS/GS/RS/US separators) and U+0085 (NEL), but
 *   NOT U+FEFF. JS `\s` matches U+FEFF (zero-width no-break space / BOM) but
 *   NOT U+001C..U+001F / U+0085. Neither set contains the other, so
 *   {@link WHITESPACE_RE} is the UNION of both: everything Python rejects is
 *   rejected here, plus U+FEFF which only JS rejects (over-strict, safe).
 * - LENGTH CAPS count Unicode CODE POINTS (Python `len(str)` semantics), NOT
 *   UTF-16 code units (`String.prototype.length`), so a cap boundary behaves
 *   identically in both languages even for astral characters.
 * - The extensions BYTE cap counts UTF-8 BYTES of the canonical JSON (Python
 *   `len(canonical_json(...))` over `bytes`), NEVER the UTF-16 string length:
 *   a multibyte payload that is under 2048 UTF-16 units but over 2048 UTF-8
 *   bytes is REJECTED, exactly as Python.
 * - A non-JSON exotic object inside `extensions` (a `Date`, `Map`, class
 *   instance) is rejected as not canonically serializable, matching Python's
 *   `canonical_json` TypeError path; JS's `stableStringify` alone would have
 *   silently serialized e.g. a `Date` as `{}` (fail-open), so the structural
 *   walk flags exotics explicitly and rejects AFTER the structural bounds
 *   (preserving Python's error ordering: depth/node errors fire during the
 *   walk; serializability errors fire after it).
 */

import { canonicalizeJcs } from '../canonical/canonicalize.js';

// L3 hardening caps, value-identical to the Python constants in
// `concordia/attestation.py` and to the shared schemas
// (`schemas/reference.schema.json`, `schemas/attestation.schema.json`).
export const MAX_REFERENCE_TYPE_LENGTH = 64;
export const MAX_REFERENCE_RELATIONSHIP_LENGTH = 64;
export const MAX_REFERENCE_ID_LENGTH = 256;
export const MAX_REFERENCE_OPTIONAL_STRING_LENGTH = 256;
export const MAX_REFERENCE_EXTENSIONS_BYTES = 2048;

// Structural pre-check bounds for extensions (Python review fix, finding 4):
// the canonical-byte cap alone is enforced only AFTER full canonical
// serialization, so a huge or deeply nested extensions object would be fully
// walked before rejection (DoS lens). These bounds are checked with a cheap
// early-bailing walk BEFORE canonicalization, mirroring Python
// `_check_extensions_structure`.
export const MAX_REFERENCE_EXTENSIONS_DEPTH = 8;
export const MAX_REFERENCE_EXTENSIONS_NODES = 256;

/**
 * Whitespace ban for identifier-shaped reference string fields.
 *
 * UNION of Python's Unicode `\s` and JS `\s` (see the module-header divergence
 * note): JS `\s` already covers tab/LF/VT/FF/CR/space, NBSP, OGHAM space,
 * U+2000..U+200A, LS/PS, NNBSP, MMSP, ideographic space, and U+FEFF; the
 * explicit ranges add the Python-only U+001C..U+001F (file/group/record/unit
 * separators) and U+0085 (NEL). The union is stricter than either language
 * alone -- fail-closed.
 */
const WHITESPACE_RE = /[\s\u001c-\u001f\u0085]/;

/**
 * Python `len(str)` semantics: the number of Unicode CODE POINTS, not UTF-16
 * code units. `for..of` iterates by code point. Early-bails via the UTF-16
 * length: a code point occupies at most 2 UTF-16 units, so a string whose
 * `.length` exceeds `2 * cap` has more than `cap` code points without needing
 * the O(n) walk (keeps pathological multi-megabyte inputs cheap to reject).
 */
function pyLen(s: string, capHint: number): number {
  if (s.length > 2 * capHint) return s.length; // already > capHint code points
  let n = 0;
  for (const _cp of s) n += 1;
  return n;
}

/** The three optional STRING reference keys, in Python's iteration order. */
const OPTIONAL_STRING_KEYS = ['version', 'signed_at', 'signer_did'] as const;

/** Error raised when an attestation-level reference is structurally invalid. */
export class ReferenceValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReferenceValidationError';
  }
}

/**
 * Python's `type(ref).__name__` for the non-dict diagnostic.
 *
 * Covers the JSON-representable inputs a reference value can carry, mapping each
 * to Python's type name exactly: `None`/missing -> `NoneType`, booleans ->
 * `bool` (checked BEFORE number, since `typeof NaN` etc. is `number` but a JS
 * boolean is its own type), integers -> `int`, non-integers -> `float`, strings
 * -> `str`, arrays -> `list`, plain objects -> `dict`.
 *
 * For NON-JSON inputs that have no Python-mapping equivalent (a `function`, a
 * `Date`, a `Map`, a class instance, a `symbol`, a `bigint`), this returns the
 * JS-native type name (`function`, `object` for the exotic objects, etc.). The
 * prior code fell back to `'dict'` for ALL of these, mislabeling a `function`
 * as `dict`; functions in particular get their own name to match CPython's
 * `type(lambda).__name__ == "function"`. These inputs are all rejected by
 * {@link validateReference} (they are not plain objects), so the type name is a
 * diagnostic only -- but a wrong name is still a parity defect.
 */
function pyTypeName(value: unknown): string {
  if (value === null || value === undefined) return 'NoneType';
  if (typeof value === 'boolean') return 'bool';
  if (typeof value === 'number') return Number.isInteger(value) ? 'int' : 'float';
  if (typeof value === 'string') return 'str';
  if (typeof value === 'function') return 'function';
  if (Array.isArray(value)) return 'list';
  if (isPlainObject(value)) return 'dict';
  // Exotic non-JSON object (Date, Map, RegExp, class instance, ...): not a
  // Python dict. Surface its JS type rather than mislabel it `dict`.
  return typeof value;
}

/**
 * Strict plain-object test mirroring Python's `isinstance(ref, dict)`.
 *
 * `_validate_reference` accepts a reference ONLY when it is an actual mapping.
 * A loose `typeof === 'object'` check fails-open: it accepts a `Date`, a `Map`,
 * or a class instance as a dict-like reference, which Python rejects. A plain
 * object is one whose prototype is `Object.prototype` (a `{...}` literal or
 * `JSON.parse` output) or `null` (`Object.create(null)`); anything else
 * (including arrays, which are handled separately) is not a dict.
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * True when the value is an identifier-shaped string acceptable for a
 * reference field: a non-empty whitespace-free string of at most `cap` code
 * points. Mirrors the Python compound condition
 * `isinstance(v, str) and v and len(v) <= cap and not _WHITESPACE_RE.search(v)`.
 */
function isValidIdentifierString(value: unknown, cap: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    pyLen(value, cap) <= cap &&
    !WHITESPACE_RE.test(value)
  );
}

/**
 * Sanitized rejection for ANY error thrown by foreign code while the input is
 * being inspected (a Proxy trap, a revoked proxy, a hostile prototype). The
 * caught error's text is NEVER included: a thrown message is attacker-
 * controlled content, and echoing it would reopen the no-echo invariant the
 * rest of this module enforces (probe: a trap throwing
 * `Error("SECRET_TERMS price=4350")` must not surface those bytes in logs or
 * MCP responses).
 */
function sanitizedInspectionError(label: string): ReferenceValidationError {
  return new ReferenceValidationError(`${label} could not be safely inspected`);
}

/**
 * Rejection for property shapes a Python dict (and canonical JSON) cannot
 * represent: accessor properties, non-enumerable own properties, symbol keys,
 * array holes, and non-index array properties. Deliberately content-free.
 */
function shapeError(label: string): ReferenceValidationError {
  return new ReferenceValidationError(
    `${label} must contain only plain enumerable data properties`,
  );
}

/**
 * Snapshot the own enumerable string-keyed DATA properties of an object into
 * a fresh plain object WITHOUT executing any caller code.
 *
 * Values are read via `Object.getOwnPropertyDescriptor(...).value`, so a
 * getter is never invoked: its side effects never run, its thrown errors
 * never escape, and its answer can never differ between validation and later
 * use. An accessor property, a non-enumerable own property, or a symbol key
 * throws {@link shapeError} (fail-closed; Python's plain-dict model cannot
 * represent any of those shapes, so nothing legitimate is lost). Non-writable
 * data properties (e.g. a frozen input) are accepted.
 */
function snapshotOwnData(
  source: object,
  label: string,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(source)) {
    if (typeof key !== 'string') {
      throw shapeError(label);
    }
    const desc = Object.getOwnPropertyDescriptor(source, key);
    if (desc === undefined || !desc.enumerable || !('value' in desc)) {
      throw shapeError(label);
    }
    out[key] = desc.value;
  }
  return out;
}

/** Result of {@link snapshotExtensionsTree}. */
interface ExtensionsSnapshot {
  /** Fresh plain-data deep copy; shares no object identity with the input. */
  snapshot: Record<string, unknown>;
  /**
   * True when the walk saw a value canonical JSON cannot represent (a `Date`,
   * `Map`, class instance, function, bigint, `undefined`, array hole, or
   * array subclass). The CALLER rejects those as not canonically serializable
   * AFTER the structural bounds pass, matching Python's error ordering
   * (Python's walk treats such values as opaque scalar leaves and its
   * `canonical_json` then raises TypeError). JS's `stableStringify` would
   * instead serialize a `Date` as `{}` -- a silent fail-open this flag closes.
   */
  sawNonJson: boolean;
}

/**
 * Single-pass defensive deep copy of `extensions` (adversarial-review fix;
 * supersedes the separate `checkExtensionsStructure` pre-walk, which read
 * values with `Object.values()` and therefore EXECUTED enumerable getters).
 *
 * In one descriptor-based walk this:
 * - enforces the structural bounds, rejecting nesting deeper than
 *   {@link MAX_REFERENCE_EXTENSIONS_DEPTH} and more than
 *   {@link MAX_REFERENCE_EXTENSIONS_NODES} nodes, bailing out as soon as
 *   either bound is crossed (the byte cap alone would only fire after a full
 *   canonical serialization -- DoS lens, Python `_check_extensions_structure`
 *   parity);
 * - rejects accessor properties, non-enumerable own properties, symbol keys,
 *   array holes, non-index array properties, and array subclasses WITHOUT
 *   invoking any of them (see {@link snapshotOwnData} for the rationale);
 * - copies every accepted value into a fresh plain-data tree, so the caller
 *   can canonicalize, byte-cap, and RETURN the snapshot with the guarantee
 *   that no later read can observe content that was not validated (TOCTOU
 *   closure).
 *
 * Invalid input is never echoed back. Foreign throws are converted to a
 * sanitized error by the CALLER's wrapper, not here.
 */
function snapshotExtensionsTree(
  extensions: Record<string, unknown>,
  index: number,
): ExtensionsSnapshot {
  const label = `references[${index}].extensions`;
  let nodes = 1; // the extensions object itself
  let sawNonJson = false;

  const guardChild = (childDepth: number): void => {
    if (childDepth > MAX_REFERENCE_EXTENSIONS_DEPTH) {
      throw new ReferenceValidationError(
        `references[${index}].extensions exceeds the maximum ` +
          `nesting depth of ${MAX_REFERENCE_EXTENSIONS_DEPTH}`,
      );
    }
    nodes += 1;
    if (nodes > MAX_REFERENCE_EXTENSIONS_NODES) {
      throw new ReferenceValidationError(
        `references[${index}].extensions exceeds the maximum ` +
          `of ${MAX_REFERENCE_EXTENSIONS_NODES} nodes`,
      );
    }
  };

  const snapshotValue = (value: unknown, depth: number): unknown => {
    if (
      value === null ||
      typeof value === 'boolean' ||
      typeof value === 'number' ||
      typeof value === 'string'
    ) {
      // NaN/Infinity and lone surrogates pass the walk and are rejected by
      // the canonicalization step afterwards (Python error-ordering parity).
      return value;
    }
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        // Array subclass: not a plain JSON array. Leaf; rejected after walk.
        sawNonJson = true;
        return undefined;
      }
      return snapshotArray(value, depth);
    }
    if (isPlainObject(value)) {
      return snapshotObject(value, depth);
    }
    // Date, Map, class instance, function, bigint, undefined, symbol: not
    // representable in canonical JSON (nor in a Python dict). Counted as a
    // leaf and rejected AFTER the structural walk (see ExtensionsSnapshot).
    sawNonJson = true;
    return undefined;
  };

  const snapshotObject = (
    obj: Record<string, unknown>,
    depth: number,
  ): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    const childDepth = depth + 1;
    for (const key of Reflect.ownKeys(obj)) {
      if (typeof key !== 'string') {
        throw shapeError(label);
      }
      const desc = Object.getOwnPropertyDescriptor(obj, key);
      if (desc === undefined || !desc.enumerable || !('value' in desc)) {
        throw shapeError(label);
      }
      guardChild(childDepth);
      out[key] = snapshotValue(desc.value, childDepth);
    }
    return out;
  };

  const snapshotArray = (arr: unknown[], depth: number): unknown[] => {
    const length = arr.length;
    const childDepth = depth + 1;
    // Count every element FIRST so a pathological length bails out at the
    // node bound without walking (or allocating) anything proportional to it.
    for (let i = 0; i < length; i += 1) {
      guardChild(childDepth);
    }
    // A plain JSON array's own keys are exactly its indices plus the
    // non-enumerable `length`; any other own property smuggles content the
    // canonical serializer would silently DROP from the byte cap while a
    // naive consumer could still read it. Reject.
    for (const key of Reflect.ownKeys(arr)) {
      if (typeof key !== 'string') {
        throw shapeError(label);
      }
      if (key === 'length') {
        continue;
      }
      const n = Number(key);
      // String(n) === key pins the CANONICAL index spelling: '01' or '-0'
      // round-trips differently and is a string property, not an index.
      if (!Number.isInteger(n) || n < 0 || n >= length || String(n) !== key) {
        throw shapeError(label);
      }
    }
    const out = new Array<unknown>(length);
    for (let i = 0; i < length; i += 1) {
      const desc = Object.getOwnPropertyDescriptor(arr, i);
      if (desc === undefined) {
        // Hole: nothing canonical JSON can represent. Leaf; rejected after.
        sawNonJson = true;
        out[i] = undefined;
        continue;
      }
      if (!desc.enumerable || !('value' in desc)) {
        throw shapeError(label);
      }
      out[i] = snapshotValue(desc.value, childDepth);
    }
    return out;
  };

  return { snapshot: snapshotObject(extensions, 1), sawNonJson };
}

/**
 * Validate and normalize a single attestation-level reference per SPEC §11.5.
 * Mirrors Python `concordia.attestation._validate_reference(ref, index)`,
 * including the L3 hardening (length caps, whitespace ban, extensions
 * structure + canonical-byte caps). See the module header for the parity
 * contract and the JS/Python strictness decisions.
 *
 * Validation runs against a defensive plain-data SNAPSHOT of `ref` (see the
 * module header, SNAPSHOT SEMANTICS): getters are never executed, accessor /
 * non-enumerable / symbol-keyed properties are rejected, any foreign throw is
 * converted to a sanitized error, and the returned object (including its
 * `extensions`) is the snapshot, never the caller's object.
 *
 * @param ref The reference value (expected to be a plain object).
 * @param index The reference's position, used verbatim in error messages.
 * @returns A normalized reference object containing exactly the required keys
 *   plus any present optional keys, in the same insertion order Python emits.
 *   Always a FRESH plain-data object: mutating the input afterwards cannot
 *   change it, and it shares no object identity with the input.
 * @throws {ReferenceValidationError} with Python-identical text on any
 *   structural violation. Neither the invalid value NOR any caught error text
 *   is ever echoed back.
 */
export function validateReference(
  ref: unknown,
  index: number,
): Record<string, unknown> {
  // Snapshot first: everything BELOW this block touches only plain local
  // data, so no caller code (getter, Proxy trap) can run during validation.
  let snap: Record<string, unknown>;
  try {
    if (!isPlainObject(ref)) {
      throw new ReferenceValidationError(
        `references[${index}] must be a dict, got ${pyTypeName(ref)} ` +
          `per SPEC §11.5.6`,
      );
    }
    snap = snapshotOwnData(ref, `references[${index}]`);
  } catch (err) {
    if (err instanceof ReferenceValidationError) {
      throw err;
    }
    // A Proxy trap (or revoked proxy / hostile prototype) threw. Never echo
    // the caught error text: it is attacker-controlled content.
    throw sanitizedInspectionError(`references[${index}]`);
  }
  const missing = ['type', 'id', 'relationship'].filter((k) => !(k in snap));
  if (missing.length > 0) {
    const list = '[' + missing.map((k) => `'${k}'`).join(', ') + ']';
    throw new ReferenceValidationError(
      `references[${index}] missing required keys ${list} ` +
        `per SPEC §11.5.6 (id, type, relationship)`,
    );
  }
  const refType = snap.type;
  const refId = snap.id;
  const relationship = snap.relationship;
  if (!isValidIdentifierString(refType, MAX_REFERENCE_TYPE_LENGTH)) {
    throw new ReferenceValidationError(
      `references[${index}].type must be a non-empty whitespace-free ` +
        `string of at most ${MAX_REFERENCE_TYPE_LENGTH} chars ` +
        `per SPEC §11.5.6`,
    );
  }
  if (!isValidIdentifierString(refId, MAX_REFERENCE_ID_LENGTH)) {
    throw new ReferenceValidationError(
      `references[${index}].id must be a non-empty whitespace-free ` +
        `string of at most ${MAX_REFERENCE_ID_LENGTH} chars ` +
        `per SPEC §11.5.6`,
    );
  }
  if (
    !isValidIdentifierString(relationship, MAX_REFERENCE_RELATIONSHIP_LENGTH)
  ) {
    throw new ReferenceValidationError(
      `references[${index}].relationship must be a non-empty ` +
        `whitespace-free string of at most ` +
        `${MAX_REFERENCE_RELATIONSHIP_LENGTH} chars per SPEC §11.5.6`,
    );
  }
  const normalized: Record<string, unknown> = {
    type: refType,
    id: refId,
    relationship,
  };
  for (const key of OPTIONAL_STRING_KEYS) {
    if (key in snap) {
      const value = snap[key];
      if (
        !isValidIdentifierString(value, MAX_REFERENCE_OPTIONAL_STRING_LENGTH)
      ) {
        throw new ReferenceValidationError(
          `references[${index}].${key} must be a ` +
            `non-empty whitespace-free string of at most ` +
            `${MAX_REFERENCE_OPTIONAL_STRING_LENGTH} chars`,
        );
      }
      normalized[key] = value;
    }
  }
  if ('extensions' in snap) {
    // The extensions VALUE came out of the top-level snapshot, but its own
    // tree is still caller-owned (and possibly accessor-backed or a Proxy):
    // deep-copy it under the same sanitized wrapper before anything reads it.
    const extensions = snap.extensions;
    let walked: ExtensionsSnapshot;
    try {
      if (!isPlainObject(extensions)) {
        throw new ReferenceValidationError(
          `references[${index}].extensions must be an object`,
        );
      }
      walked = snapshotExtensionsTree(extensions, index);
    } catch (err) {
      if (err instanceof ReferenceValidationError) {
        throw err;
      }
      throw sanitizedInspectionError(`references[${index}].extensions`);
    }
    if (walked.sawNonJson) {
      // Python's canonical_json raises TypeError on a non-JSON object; JS's
      // stableStringify would silently emit `{}` for a Date/Map (fail-open),
      // so reject explicitly with the same error Python's catch produces.
      throw new ReferenceValidationError(
        `references[${index}].extensions is not canonically serializable`,
      );
    }
    // From here on, only the plain-data snapshot is read: the byte cap is
    // measured over EXACTLY the bytes a later serialization will emit.
    let extensionsBytes: number;
    try {
      extensionsBytes = canonicalizeJcs(walked.snapshot).length;
    } catch {
      throw new ReferenceValidationError(
        `references[${index}].extensions is not canonically serializable`,
      );
    }
    if (extensionsBytes > MAX_REFERENCE_EXTENSIONS_BYTES) {
      throw new ReferenceValidationError(
        `references[${index}].extensions exceeds ` +
          `${MAX_REFERENCE_EXTENSIONS_BYTES} canonical-JSON bytes`,
      );
    }
    normalized.extensions = walked.snapshot;
  }
  return normalized;
}
