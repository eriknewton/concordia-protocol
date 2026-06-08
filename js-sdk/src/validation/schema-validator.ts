/**
 * JSON Schema validation for Concordia messages and artifacts.
 *
 * Port of `concordia/schema_validator.py`. Validates a Concordia message
 * envelope against the SPEC §4.1 schema, a §9.6 Reputation Attestation against
 * `attestation.schema.json`, an ApprovalReceipt against
 * `approval_receipt.schema.json`, and a standalone FulfillmentAttestation
 * against `fulfillment_attestation.schema.json` — each returning a list of
 * `"{json_path}: {message}"` strings (empty when valid), byte-identical to the
 * Python reference for the supported schema surface.
 *
 * PARITY APPROACH. Python drives `jsonschema.Draft202012Validator(...,
 * format_checker=...).iter_errors(...)` and joins `f"{error.json_path}:
 * {error.message}"`. The mandate ENGINE (PR 6) reproduced jsonschema's
 * SINGLE best-match message by translating ajv errors, but that does NOT
 * reproduce the FULL ORDERED error list this surface returns. So this layer uses
 * {@link iterErrors} — a hand-port of CPython jsonschema's `iter_errors`
 * traversal (in `src/internal/jsonschema.ts`) that yields the same ordered list
 * with the same `json_path` shape and the same CPython-`repr()`-rendered message
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
} from '../internal/jsonschema.js';
import { isCpythonIsoDateTime } from '../internal/iso-datetime.js';
import {
  MESSAGE_SCHEMA,
  ATTESTATION_SCHEMA,
  APPROVAL_RECEIPT_SCHEMA,
  FULFILLMENT_ATTESTATION_SCHEMA,
} from './schemas.js';

// Fail fast at module load if a bundled schema introduces a keyword the internal
// validator does not support (which would silently under-validate vs Python).
assertSupportedSchema(MESSAGE_SCHEMA, 'message');
assertSupportedSchema(ATTESTATION_SCHEMA, 'attestation');
assertSupportedSchema(APPROVAL_RECEIPT_SCHEMA, 'approval_receipt');
assertSupportedSchema(FULFILLMENT_ATTESTATION_SCHEMA, 'fulfillment_attestation');

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

/** Join the internal errors into Python's `"{json_path}: {message}"` strings. */
function format(errors: ReturnType<typeof iterErrors>): string[] {
  return errors.map((e) => `${e.jsonPath}: ${e.message}`);
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
  return format(iterErrors(ATTESTATION_SCHEMA, attestation, conformsFormat));
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
