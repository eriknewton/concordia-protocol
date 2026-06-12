/**
 * JSON Schema validation for Concordia messages and artifacts.
 *
 * Port of `concordia/schema_validator.py`. Validates a Concordia message
 * envelope against the SPEC §4.1 schema, a §9.6 Reputation Attestation against
 * `attestation.schema.json`, an ApprovalReceipt against
 * `approval_receipt.schema.json`, and a standalone FulfillmentAttestation
 * against `fulfillment_attestation.schema.json` — each returning a list of
 * error strings (empty when valid), byte-identical to the Python reference for
 * the supported schema surface.
 *
 * ERROR-ECHO HARDENING (Python #95 finding 5). jsonschema's default
 * `error.message` embeds the rejected INSTANCE value for pattern / maxLength /
 * enum / type / oneOf failures, so building errors from it can echo raw
 * rejected deal text back through MCP responses and logs (parse-boundary
 * posture: never echo attacker-controlled input). Python's
 * `_format_validation_error` therefore reports the JSON path plus the violated
 * CONSTRAINT — the validator keyword and its schema-side value rendered with
 * `json.dumps(..., sort_keys=True)`, truncated at 120 characters — and keeps
 * the upstream message ONLY for `required` (it names schema-side property
 * names, never instance content). {@link formatValidationError} reproduces
 * that formatting byte-for-byte (via {@link pyJsonDumps}); the truncation only
 * ever drops schema-side text, never instance content, and a render failure
 * falls back to Python's content-free `<unrenderable>` (fail closed, no echo).
 *
 * PARITY APPROACH. Python drives `jsonschema.Draft202012Validator(...,
 * format_checker=...).iter_errors(...)` and formats each error with
 * `_format_validation_error`. The mandate ENGINE (PR 6) reproduced jsonschema's
 * SINGLE best-match message by translating ajv errors, but that does NOT
 * reproduce the FULL ORDERED error list this surface returns. So this layer uses
 * {@link iterErrors} — a hand-port of CPython jsonschema's `iter_errors`
 * traversal (in `src/internal/jsonschema.ts`) that yields the same ordered list
 * with the same `json_path` shape, the same `validator` / `validator_value`
 * stamping, and (for `required`) the same CPython-`repr()`-rendered message
 * text (sharing `pyRepr` with the engine via `src/internal/py-repr.ts`).
 *
 * FORMAT CHECKING. Python registers a CUSTOM `FormatChecker` asserting
 * `date-time` (requires a tz-aware ISO 8601 instant) and `uuid`. CRITICALLY,
 * `validate_message` / `validate_approval_receipt` PASS this checker (so a bad
 * `date-time` is REJECTED), whereas the mandate engine ran with formats OFF
 * (mandate's `validate_mandate_schema` passes no checker). {@link conformsFormat}
 * reproduces the two custom checks; both return "conforms" for a NON-string
 * (Python's checks `return True` for non-strings, deferring to the `type`
 * keyword). `validate_fulfillment_attestation` passes NO checker (its `format`
 * keywords are inert), matching Python.
 *
 * `validate_attestation` warning side effect: Python emits `UserWarning`s for
 * non-canonical but schema-valid reference type/relationship strings. JavaScript
 * has no matching warnings API on this validation surface, so this port preserves
 * the fail-closed schema behavior and intentionally does not emit side-channel
 * warnings.
 */

import {
  iterErrors,
  assertSupportedSchema,
  type FormatChecker,
  type SchemaError,
} from '../internal/jsonschema.js';
import { isCpythonIsoDateTime } from '../internal/iso-datetime.js';
import {
  pyJsonDumps,
  type FloatConstraintMap,
} from '../internal/py-json.js';
import {
  MESSAGE_SCHEMA,
  ATTESTATION_SCHEMA,
  APPROVAL_RECEIPT_SCHEMA,
  FULFILLMENT_ATTESTATION_SCHEMA,
  FLOAT_CONSTRAINT_PATHS,
} from './schemas.js';

// Fail fast at module load if a bundled schema introduces a keyword the internal
// validator does not support (which would silently under-validate vs Python).
assertSupportedSchema(MESSAGE_SCHEMA, 'message');
assertSupportedSchema(ATTESTATION_SCHEMA, 'attestation');
assertSupportedSchema(APPROVAL_RECEIPT_SCHEMA, 'approval_receipt');
assertSupportedSchema(FULFILLMENT_ATTESTATION_SCHEMA, 'fulfillment_attestation');

// ---------------------------------------------------------------------------
// Constraint rendering (mirrors `_format_validation_error` post-#95)
// ---------------------------------------------------------------------------

/**
 * Python `_MAX_CONSTRAINT_RENDER_LENGTH`: schema-side constraint values
 * (patterns, enum lists, subschemas) can be long; truncate the rendering so
 * error strings stay log-friendly. The truncation only ever drops schema-side
 * text, never instance content. Python counts CODE POINTS (`len(str)`); the
 * rendering is pure ASCII (`ensure_ascii=True`), so `.length` / `.slice`
 * count the same units here.
 */
const MAX_CONSTRAINT_RENDER_LENGTH = 120;

/**
 * Float-sourced schema constraints, resolved from the generated
 * `FLOAT_CONSTRAINT_PATHS` registry into object-identity form (schema node ->
 * float-valued key names) so {@link pyJsonDumps} can render Python's "0.0"
 * for constraints whose JSON source is a float literal. Built once at module
 * load; an unresolvable registry path is a generation bug and fails loudly
 * rather than silently degrading the rendering.
 */
const FLOAT_CONSTRAINTS: FloatConstraintMap = new WeakMap();
{
  const roots: Record<string, unknown> = {
    MESSAGE_SCHEMA,
    ATTESTATION_SCHEMA,
    APPROVAL_RECEIPT_SCHEMA,
    FULFILLMENT_ATTESTATION_SCHEMA,
  };
  for (const [name, paths] of Object.entries(FLOAT_CONSTRAINT_PATHS)) {
    const root = roots[name];
    if (root === undefined) {
      throw new Error(
        `schema-validator: FLOAT_CONSTRAINT_PATHS names unknown schema '${name}'`,
      );
    }
    for (const path of paths) {
      let node: unknown = root;
      for (const key of path.slice(0, -1)) {
        node = (node as Record<string, unknown> | undefined)?.[key];
      }
      const leaf = path[path.length - 1];
      if (
        leaf === undefined ||
        node === null ||
        typeof node !== 'object' ||
        typeof (node as Record<string, unknown>)[leaf] !== 'number'
      ) {
        throw new Error(
          `schema-validator: FLOAT_CONSTRAINT_PATHS path ${JSON.stringify(path)} ` +
            `does not resolve to a number in ${name}`,
        );
      }
      let keys = FLOAT_CONSTRAINTS.get(node as object);
      if (keys === undefined) {
        keys = new Set<string>();
        FLOAT_CONSTRAINTS.set(node as object, keys);
      }
      keys.add(leaf);
    }
  }
}

/**
 * Format one schema error WITHOUT echoing the instance, byte-identical to
 * Python `_format_validation_error`:
 *
 * - `required` keeps the upstream message (`'x' is a required property`): it
 *   names only schema-side property names, and the missing property name is
 *   the whole diagnostic.
 * - Every other keyword renders
 *   `{json_path}: violates '{keyword}' constraint: {json.dumps(validator_value,
 *   sort_keys=True)}`, truncated at {@link MAX_CONSTRAINT_RENDER_LENGTH} with
 *   a `...` suffix. CPython's `validator=None` (boolean `false` schema)
 *   renders as the generic `'schema'` keyword.
 * - A rendering failure produces Python's content-free `<unrenderable>`:
 *   fail closed, never fall back to the instance-echoing message.
 */
function formatValidationError(error: SchemaError): string {
  if (error.keyword === 'required') {
    return `${error.jsonPath}: ${error.message}`;
  }
  const keyword = error.keyword ?? 'schema';
  let rendered: string;
  try {
    const rootIsFloat =
      typeof error.keyword === 'string' &&
      error.schema !== null &&
      typeof error.schema === 'object'
        ? (FLOAT_CONSTRAINTS.get(error.schema)?.has(error.keyword) ?? false)
        : false;
    rendered = pyJsonDumps(error.validatorValue, FLOAT_CONSTRAINTS, rootIsFloat);
  } catch {
    rendered = '<unrenderable>';
  }
  if (rendered.length > MAX_CONSTRAINT_RENDER_LENGTH) {
    rendered = `${rendered.slice(0, MAX_CONSTRAINT_RENDER_LENGTH)}...`;
  }
  return `${error.jsonPath}: violates '${keyword}' constraint: ${rendered}`;
}

const FREE_TEXT_TERM_ERROR =
  'free-text field must not contain obvious raw deal terms';
const RAW_TERM_PATTERNS = [
  /[$€£¥]\s*\d/i,
  /\b(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|CNY|INR)\s*\d/i,
  /\b\d+(?:[.,]\d+)?\s*(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|CNY|INR)\b/i,
  /\bprice\s*:/i,
  /\b(?:qty|quantity)\s*[:=]?\s*\d+\b/i,
  /\b\d+\s*(?:units?|items?|pcs|pieces)\b/i,
];

// ---------------------------------------------------------------------------
// Format checker (mirrors `concordia/schema_validator.py` `_FORMAT_CHECKER`)
// ---------------------------------------------------------------------------

/**
 * Reproduce the two custom format checks Python registers, returning `true` when
 * the value CONFORMS (so the validator only emits an error when this is `false`).
 *
 * - `date-time`: Python `_is_date_time` parses
 *   `datetime.fromisoformat(value.replace("Z", "+00:00"))` and requires the
 *   result to be timezone-AWARE (`tzinfo is not None`). A naive timestamp
 *   (no offset, no `Z`), a date-only string, or any value `fromisoformat`
 *   rejects -> NOT conforming. A non-string -> conforming (Python returns `True`).
 *   Delegated to the shared {@link isCpythonIsoDateTime}, which reproduces
 *   CPython 3.12's FULL `fromisoformat` accept set (extended AND basic date/time
 *   forms, week dates, `.`/`,` fractional seconds, and offsets `±HH`, `±HHMM`,
 *   `±HH:MM`, `±HHMMSS`, `±HH:MM:SS`) so a Python-signed receipt carrying any of
 *   those alternate spellings is not FALSELY rejected.
 * - `uuid`: Python `_is_uuid` constructs `UUID(value)`; conforms iff that
 *   succeeds. A non-string -> conforming.
 * - Any other format name is not registered by Python (the schemas only use
 *   `date-time`), so it conforms (no assertion).
 */
export const conformsFormat: FormatChecker = (format, value) => {
  switch (format) {
    case 'date-time':
      // The shared parser handles the `Z`->`+00:00` replace and the tz-aware
      // requirement, and returns `true` for a non-string (Python's behavior).
      return isCpythonIsoDateTime(value);
    case 'uuid':
      return isUuid(value);
    default:
      return true;
  }
};

/**
 * Python `_is_uuid`: `UUID(value)` must succeed. Mirrors CPython's accepted
 * forms — 32 hex digits, optionally hyphen-grouped 8-4-4-4-12, optionally with a
 * `urn:uuid:` prefix or surrounding braces, case-insensitive — by normalizing the
 * same way `uuid.UUID.__init__` does (strip `urn:uuid:`, braces, and hyphens)
 * and requiring exactly 32 hex digits.
 */
function isUuid(value: string): boolean {
  let hex = value.replace(/urn:uuid:/i, '');
  hex = hex.replace(/[{}]/g, '');
  hex = hex.replace(/-/g, '');
  return /^[0-9a-fA-F]{32}$/.test(hex);
}

// ---------------------------------------------------------------------------
// Public validators (mirror schema_validator.py)
// ---------------------------------------------------------------------------

/** Format the internal errors with the no-echo constraint rendering. */
function format(errors: ReturnType<typeof iterErrors>): string[] {
  return errors.map(formatValidationError);
}

/**
 * Validate a Concordia message against the envelope schema (SPEC §4.1).
 * Mirrors Python `validate_message`: returns a list of validation error messages
 * (empty if valid). The `date-time` `format` on `timestamp` IS asserted (the
 * custom checker is passed), matching Python.
 */
export function validateMessage(message: unknown): string[] {
  return format(iterErrors(MESSAGE_SCHEMA, message, conformsFormat));
}

/** Return `true` if the message passes schema validation (Python `is_valid_message`). */
export function isValidMessage(message: unknown): boolean {
  return validateMessage(message).length === 0;
}

/**
 * Validate a §9.6 Reputation Attestation against `attestation.schema.json`.
 * Mirrors Python `validate_attestation` for schema errors, including asserted
 * `date-time` formats and intra-document `$ref` / `oneOf` applicators.
 */
export function validateAttestation(attestation: unknown): string[] {
  return [
    ...format(iterErrors(ATTESTATION_SCHEMA, attestation, conformsFormat)),
    ...validateAttestationFreeText(attestation),
  ];
}

/** Return `true` if the Reputation Attestation passes schema validation. */
export function isValidAttestation(attestation: unknown): boolean {
  return validateAttestation(attestation).length === 0;
}

/**
 * Validate an ApprovalReceipt against `approval_receipt.schema.json`. Mirrors
 * Python `validate_approval_receipt`: returns a list of validation error messages
 * (empty if valid), with `date-time` formats asserted via the custom checker.
 */
export function validateApprovalReceipt(receipt: unknown): string[] {
  return format(iterErrors(APPROVAL_RECEIPT_SCHEMA, receipt, conformsFormat));
}

/** Return `true` if the ApprovalReceipt passes schema validation (Python `is_valid_approval_receipt`). */
export function isValidApprovalReceipt(receipt: unknown): boolean {
  return validateApprovalReceipt(receipt).length === 0;
}

/**
 * Validate a standalone FulfillmentAttestation artifact. Mirrors Python
 * `validate_fulfillment_attestation`: JSON-Schema-validates against
 * `fulfillment_attestation.schema.json` (NO format checker — Python passes none,
 * so the schema's `format` keywords are inert), THEN appends the companion local
 * equality invariant: when `agreement_attestation_id` is a string and
 * `references` is a list, every `fulfills`-relationship reference's `id` must
 * equal `agreement_attestation_id`; otherwise the error
 * `"$.references: fulfills reference id must equal agreement_attestation_id"` is
 * appended.
 */
export function validateFulfillmentAttestation(attestation: unknown): string[] {
  // Python passes NO format_checker here, so `format` keywords do not assert.
  const errors = format(iterErrors(FULFILLMENT_ATTESTATION_SCHEMA, attestation));

  // Companion equality invariant (Python's hand-coded check, run unconditionally
  // AFTER schema validation — Python does not short-circuit on schema errors).
  if (isPlainObject(attestation)) {
    const agreementId = attestation.agreement_attestation_id;
    const references = attestation.references;
    if (typeof agreementId === 'string' && Array.isArray(references)) {
      // Python: `[ref.get("id") for ref in references if isinstance(ref, dict)
      // and ref.get("relationship") == "fulfills"]`.
      const fulfillsTargets: unknown[] = [];
      for (const ref of references) {
        if (isPlainObject(ref) && ref.relationship === 'fulfills') {
          fulfillsTargets.push(ref.id);
        }
      }
      if (
        fulfillsTargets.length > 0 &&
        !fulfillsTargets.includes(agreementId)
      ) {
        errors.push(
          '$.references: fulfills reference id must equal ' +
            'agreement_attestation_id',
        );
      }
    }
  }

  return errors;
}

/** Return `true` if the FulfillmentAttestation passes all validation (Python `is_valid_fulfillment_attestation`). */
export function isValidFulfillmentAttestation(attestation: unknown): boolean {
  return validateFulfillmentAttestation(attestation).length === 0;
}

/** Python `isinstance(x, dict)`: a plain object, not an array / null. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validateAttestationFreeText(attestation: unknown): string[] {
  if (!isPlainObject(attestation)) return [];

  const candidates: Array<[string, unknown]> = [['$.summary', attestation.summary]];
  const fulfillment = attestation.fulfillment;
  if (isPlainObject(fulfillment)) {
    const disputes = fulfillment.disputes;
    if (Array.isArray(disputes)) {
      disputes.forEach((dispute, index) => {
        if (isPlainObject(dispute)) {
          candidates.push([
            `$.fulfillment.disputes[${index}].description`,
            dispute.description,
          ]);
        }
      });
    }

    const counterparty = fulfillment.counterparty_attestation;
    if (isPlainObject(counterparty)) {
      candidates.push([
        '$.fulfillment.counterparty_attestation.notes',
        counterparty.notes,
      ]);
    }
  }

  const errors: string[] = [];
  for (const [path, value] of candidates) {
    if (typeof value === 'string' && containsObviousRawTerm(value)) {
      errors.push(`${path}: ${FREE_TEXT_TERM_ERROR}`);
    }
  }
  return errors;
}

function containsObviousRawTerm(value: string): boolean {
  return RAW_TERM_PATTERNS.some((pattern) => pattern.test(value));
}
