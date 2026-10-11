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
 * - Optional keys `version`, `signed_at`, and `signer_did` are passed through
 *   when present. Python 0.6 closes the member set, so `extensions` and every
 *   other extra key are rejected before normalized output is built.
 *
 * L3 hardening (security audit 2026-06-09; port of Python PR #95): every
 * string field is NFC-normalized, UTF-8-octet-capped, and forbidden-control /
 * whitespace-banned. Fail-closed: oversize or wrongly-typed values throw
 * {@link ReferenceValidationError}; invalid values are NEVER echoed back in the
 * error text (content-injection lens: these errors can land in logs and MCP
 * responses), and nothing is ever silently truncated or coerced.
 *
 * SNAPSHOT SEMANTICS (adversarial-review fix, 2026-06-12): validation runs
 * against a defensive plain-data SNAPSHOT of the input, never against the
 * caller's source object, and the normalized result is that snapshot, never a
 * reference to caller-owned data. Concretely:
 * - Property values are read via `Object.getOwnPropertyDescriptor(...).value`,
 *   so a GETTER IS NEVER EXECUTED. Accessor properties are REJECTED outright
 *   rather than sampled: Python's plain-dict model cannot represent an
 *   accessor, and rejecting keeps validation side-effect-free.
 * - Symbol keys, non-enumerable own properties, array holes, non-index array
 *   properties, and array subclasses are likewise rejected (none is
 *   representable in canonical JSON or in a Python dict). Non-writable DATA
 *   properties (e.g. a frozen input) remain accepted.
 * - The ENTIRE inspection is wrapped so that ANY foreign throw (a Proxy trap,
 *   a revoked proxy, an unusual prototype) is converted to a sanitized
 *   {@link ReferenceValidationError} that includes NEITHER the caught error
 *   text NOR any input value.
 * - The snapshot is what callers get back, so no caller-owned mutation can
 *   change the validated reference after the check.
 *
 * JS/Python divergence decisions (each resolved in the STRICTER, fail-closed
 * direction, and each pinned by a test):
 * - LENGTH CAPS count UTF-8 OCTETS, matching Python `_require_string`.
 *   Multibyte identifiers over the octet cap are rejected even when they are
 *   under the JSON Schema code-point cap.
 */

// L3 hardening caps, value-identical to the Python constants in
// `concordia/attestation.py` and to the shared schemas
// (`schemas/reference.schema.json`, `schemas/attestation.schema.json`).
export const MAX_REFERENCE_TYPE_LENGTH = 64;
export const MAX_REFERENCE_RELATIONSHIP_LENGTH = 64;
export const MAX_REFERENCE_ID_LENGTH = 256;
export const MAX_REFERENCE_OPTIONAL_STRING_LENGTH = 256;
// Retained as exported alpha API constants for older callers; Python 0.6
// rejects reference-level `extensions` before these caps are reached.
export const MAX_REFERENCE_EXTENSIONS_BYTES = 2048;
export const MAX_REFERENCE_EXTENSIONS_DEPTH = 8;
export const MAX_REFERENCE_EXTENSIONS_NODES = 256;

/**
 * Forbidden reference identifier controls. Must match the Python
 * `_reference_string` path in `concordia/attestation.py`: whitespace plus C0,
 * DEL, C1, zero-width controls, and bidi override controls.
 */
// U+0000..U+001F and U+007F..U+009F are intentional C0/C1 control ranges.
// eslint-disable-next-line no-control-regex
const REFERENCE_FORBIDDEN_RE =
  /[\p{White_Space}\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202E]/u;

function hasLoneSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function utf8ByteLength(value: string): number {
  return Buffer.byteLength(value, 'utf8');
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
 * reference field: a non-empty NFC string of at most `cap` UTF-8 octets with
 * no whitespace, C0/C1 controls, zero-width controls, or bidi overrides.
 * Mirrors Python `_reference_string`, which wraps `_require_string`.
 */
function isValidIdentifierString(value: unknown, cap: number): value is string {
  return (
    typeof value === 'string' &&
    !hasLoneSurrogate(value) &&
    value.normalize('NFC') === value &&
    utf8ByteLength(value) > 0 &&
    utf8ByteLength(value) <= cap &&
    !REFERENCE_FORBIDDEN_RE.test(value)
  );
}

/**
 * Sanitized rejection for ANY error thrown by foreign code while the input is
 * being inspected (a Proxy trap, a revoked proxy, an unusual prototype). The
 * caught error's text is NEVER included; thrown messages are caller-controlled
 * content, and the no-echo invariant requires sanitized diagnostics.
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
function snapshotOwnData(source: object, label: string): Record<string, unknown> {
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

/** Result of {@link snapshotPlainData} / {@link snapshotExtensionsTree}. */
export interface PlainDataSnapshot {
  /** Fresh plain-data deep copy; shares no object identity with the input. */
  snapshot: Record<string, unknown>;
  /**
   * True when the walk saw a value canonical JSON cannot represent (a `Date`,
   * `Map`, class instance, function, bigint, `undefined`, array hole, or
   * array subclass) under `nonJson: 'flag'`. The CALLER rejects those as not
   * canonically serializable AFTER the structural bounds pass, matching
   * Python's error ordering (Python's walk treats such values as opaque
   * scalar leaves and its `canonical_json` then raises TypeError). JS's
   * `stableStringify` would instead serialize a `Date` as `{}` -- a silent
   * fail-open this flag closes. Always `false` under `nonJson: 'pass'`.
   */
  sawNonJson: boolean;
}

/** Options for {@link snapshotPlainData}. */
export interface PlainDataSnapshotOptions {
  /**
   * Diagnostic prefix for every rejection message. Never joined with input
   * content: the no-echo invariant requires error text to stay content-free.
   */
  label: string;
  /**
   * Constructor for rejection errors. Defaults to
   * {@link ReferenceValidationError}; predicate-level callers pass their own
   * error type so rejections surface in the vocabulary their callers already
   * catch.
   */
  makeError?: (message: string) => Error;
  /** Reject nesting deeper than this many levels (the root object is 1). */
  maxDepth?: number;
  /** Reject trees with more than this many nodes (the root counts as 1). */
  maxNodes?: number;
  /**
   * Handling for a leaf value canonical JSON cannot represent (a `Date`,
   * `Map`, class instance, function, bigint, `undefined`, array hole, or
   * array subclass):
   * - `'flag'` (default): snapshot `undefined` in its place and set
   *   `sawNonJson`, so the caller can reject AFTER the structural bounds pass
   *   (Python error-ordering parity; see {@link PlainDataSnapshot}).
   * - `'pass'`: carry the value through UNCHANGED, by reference. Used by
   *   `Predicate.fromDict`, whose plain-data semantics must not change: such
   *   a value was previously accepted by the `{ ...data }` spread and is
   *   rejected (or not) downstream exactly as before. Exotic objects are
   *   LEAVES -- their internals are never walked, so they cannot smuggle
   *   accessor-backed properties into the snapshot, and they never survive
   *   canonical serialization anyway.
   */
  nonJson?: 'flag' | 'pass';
}

/**
 * Single-pass defensive deep copy of a plain-data tree (adversarial-review
 * fix). Shared by reference validation and by `Predicate.fromDict`, whose
 * `{ ...data }` spread had the same accessor-execution / throw-echo exposure.
 *
 * In one descriptor-based walk this:
 * - enforces the optional structural bounds (`maxDepth`, `maxNodes`),
 *   bailing out as soon as either bound is crossed;
 * - rejects accessor properties, non-enumerable own properties, symbol keys,
 *   array holes, non-index array properties, and array subclasses WITHOUT
 *   invoking any of them (see {@link snapshotOwnData} for the rationale;
 *   holes and array subclasses are non-JSON LEAVES handled per `nonJson`
 *   rather than shape rejections);
 * - copies every accepted value into a fresh plain-data tree, so no later read
 *   can observe content that was not validated, and no later mutation of the
 *   caller's tree can reach the snapshot.
 *
 * Invalid input is never echoed back. Foreign throws are converted to a
 * sanitized error by the CALLER's wrapper, not here.
 */
export function snapshotPlainData(
  source: Record<string, unknown>,
  options: PlainDataSnapshotOptions,
): PlainDataSnapshot {
  const { label, maxDepth, maxNodes } = options;
  const makeError = options.makeError ?? ((m: string) => new ReferenceValidationError(m));
  const passNonJson = options.nonJson === 'pass';
  let nodes = 1; // the root object itself
  let sawNonJson = false;

  const shapeRejection = (): Error =>
    makeError(`${label} must contain only plain enumerable data properties`);

  const guardChild = (childDepth: number): void => {
    if (maxDepth !== undefined && childDepth > maxDepth) {
      throw makeError(`${label} exceeds the maximum nesting depth of ${maxDepth}`);
    }
    nodes += 1;
    if (maxNodes !== undefined && nodes > maxNodes) {
      throw makeError(`${label} exceeds the maximum of ${maxNodes} nodes`);
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
        // Array subclass: not a plain JSON array. Non-JSON leaf.
        if (passNonJson) return value;
        sawNonJson = true;
        return undefined;
      }
      return snapshotArray(value, depth);
    }
    if (isPlainObject(value)) {
      return snapshotObject(value, depth);
    }
    // Date, Map, class instance, function, bigint, undefined, symbol: not
    // representable in canonical JSON (nor in a Python dict). A non-JSON
    // leaf: passed through under 'pass', otherwise counted and rejected
    // AFTER the structural walk (see PlainDataSnapshot).
    if (passNonJson) return value;
    sawNonJson = true;
    return undefined;
  };

  const snapshotObject = (obj: Record<string, unknown>, depth: number): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    const childDepth = depth + 1;
    for (const key of Reflect.ownKeys(obj)) {
      if (typeof key !== 'string') {
        throw shapeRejection();
      }
      const desc = Object.getOwnPropertyDescriptor(obj, key);
      if (desc === undefined || !desc.enumerable || !('value' in desc)) {
        throw shapeRejection();
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
        throw shapeRejection();
      }
      if (key === 'length') {
        continue;
      }
      const n = Number(key);
      // String(n) === key pins the CANONICAL index spelling: '01' or '-0'
      // round-trips differently and is a string property, not an index.
      if (!Number.isInteger(n) || n < 0 || n >= length || String(n) !== key) {
        throw shapeRejection();
      }
    }
    const out = new Array<unknown>(length);
    for (let i = 0; i < length; i += 1) {
      const desc = Object.getOwnPropertyDescriptor(arr, i);
      if (desc === undefined) {
        // Hole: nothing canonical JSON can represent. Non-JSON leaf; the
        // snapshot slot stays undefined either way (there is no value to
        // pass through), but only 'flag' mode marks it for rejection.
        if (!passNonJson) {
          sawNonJson = true;
        }
        out[i] = undefined;
        continue;
      }
      if (!desc.enumerable || !('value' in desc)) {
        throw shapeRejection();
      }
      out[i] = snapshotValue(desc.value, childDepth);
    }
    return out;
  };

  return { snapshot: snapshotObject(source, 1), sawNonJson };
}

/**
 * Validate and normalize a single attestation-level reference per SPEC §11.5.
 * Mirrors Python `concordia.attestation._validate_reference(ref, index)`,
 * including the 0.6 string hardening (NFC, UTF-8 byte caps, and forbidden
 * controls). See the module header for the parity contract.
 *
 * Validation runs against a defensive plain-data SNAPSHOT of `ref` (see the
 * module header, SNAPSHOT SEMANTICS): getters are never executed, accessor /
 * non-enumerable / symbol-keyed properties are rejected, any foreign throw is
 * converted to a sanitized error, and the returned object is the snapshot,
 * never the caller's object.
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
export function validateReference(ref: unknown, index: number): Record<string, unknown> {
  // Snapshot first: everything BELOW this block touches only plain local
  // data, so no caller code (getter, Proxy trap) can run during validation.
  let snap: Record<string, unknown>;
  try {
    if (!isPlainObject(ref)) {
      throw new ReferenceValidationError(
        `references[${index}] must be a dict, got ${pyTypeName(ref)} ` + `per SPEC §11.5.6`,
      );
    }
    snap = snapshotOwnData(ref, `references[${index}]`);
  } catch (err) {
    if (err instanceof ReferenceValidationError) {
      throw err;
    }
    // A Proxy trap or revoked proxy threw. Never echo the caught error text:
    // it is caller-controlled content.
    throw sanitizedInspectionError(`references[${index}]`);
  }
  const allowedKeys = new Set(['id', 'type', 'relationship', 'version', 'signed_at', 'signer_did']);
  if (Object.keys(snap).some((key) => !allowedKeys.has(key))) {
    throw new ReferenceValidationError(
      `references[${index}] contains undefined member(s) for attestation format 0.6.0`,
    );
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
      `references[${index}].type must be a non-empty whitespace-free string per SPEC §11.5.6`,
    );
  }
  if (!isValidIdentifierString(refId, MAX_REFERENCE_ID_LENGTH)) {
    throw new ReferenceValidationError(
      `references[${index}].id must be a non-empty whitespace-free string per SPEC §11.5.6`,
    );
  }
  if (!isValidIdentifierString(relationship, MAX_REFERENCE_RELATIONSHIP_LENGTH)) {
    throw new ReferenceValidationError(
      `references[${index}].relationship must be a non-empty whitespace-free string per SPEC §11.5.6`,
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
      if (!isValidIdentifierString(value, MAX_REFERENCE_OPTIONAL_STRING_LENGTH)) {
        throw new ReferenceValidationError(
          `references[${index}].${key} must be a non-empty whitespace-free string per SPEC §11.5.6`,
        );
      }
      normalized[key] = value;
    }
  }
  return normalized;
}
