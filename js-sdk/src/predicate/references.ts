/**
 * Attestation-level reference validation (SPEC §11.5).
 *
 * Port of `concordia.attestation._validate_reference` — the only piece of the
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
 *   through unchanged when present; ALL OTHER keys are DROPPED from the
 *   normalized output (Python rebuilds a fresh dict with only the known keys).
 */

/** Error raised when an attestation-level reference is structurally invalid. */
export class ReferenceValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReferenceValidationError';
  }
}

/** The four optional reference keys passed through unchanged, in Python order. */
const OPTIONAL_REFERENCE_KEYS = [
  'version',
  'signed_at',
  'signer_did',
  'extensions',
] as const;

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
 * diagnostic only — but a wrong name is still a parity defect.
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
 * Validate and normalize a single attestation-level reference per SPEC §11.5.
 * Mirrors Python `concordia.attestation._validate_reference(ref, index)`.
 *
 * @param ref The reference value (expected to be a plain object).
 * @param index The reference's position, used verbatim in error messages.
 * @returns A normalized reference object containing exactly the required keys
 *   plus any present optional keys, in the same insertion order Python emits.
 * @throws {ReferenceValidationError} with Python-identical text on any
 *   structural violation.
 */
export function validateReference(
  ref: unknown,
  index: number,
): Record<string, unknown> {
  if (!isPlainObject(ref)) {
    throw new ReferenceValidationError(
      `references[${index}] must be a dict, got ${pyTypeName(ref)} ` +
        `per SPEC §11.5.6`,
    );
  }
  const missing = ['type', 'id', 'relationship'].filter((k) => !(k in ref));
  if (missing.length > 0) {
    const list = '[' + missing.map((k) => `'${k}'`).join(', ') + ']';
    throw new ReferenceValidationError(
      `references[${index}] missing required keys ${list} ` +
        `per SPEC §11.5.6 (id, type, relationship)`,
    );
  }
  const refType = ref.type;
  const refId = ref.id;
  const relationship = ref.relationship;
  if (typeof refType !== 'string' || refType.length === 0) {
    throw new ReferenceValidationError(
      `references[${index}].type must be a non-empty string per SPEC §11.5.6`,
    );
  }
  if (typeof refId !== 'string' || refId.length === 0) {
    throw new ReferenceValidationError(
      `references[${index}].id must be a non-empty string per SPEC §11.5.6`,
    );
  }
  if (typeof relationship !== 'string' || relationship.length === 0) {
    throw new ReferenceValidationError(
      `references[${index}].relationship must be a non-empty string ` +
        `per SPEC §11.5.6`,
    );
  }
  const normalized: Record<string, unknown> = {
    type: refType,
    id: refId,
    relationship,
  };
  for (const key of OPTIONAL_REFERENCE_KEYS) {
    if (key in ref) {
      normalized[key] = ref[key];
    }
  }
  return normalized;
}
