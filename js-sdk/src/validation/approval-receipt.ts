/**
 * ApprovalReceipt verification (Concordia v0.5).
 *
 * Port of `concordia/approval_receipt.py`. An ApprovalReceipt is a standalone
 * signed artifact emitted when a human-in-the-loop authority approves (or denies)
 * a negotiation event that crossed an approval threshold (A2CN §14 HITL
 * pause-resume). {@link verifyApprovalReceipt} runs the same five ordered checks
 * Python does and returns the same typed result:
 *   1. schema (via {@link validateApprovalReceipt}),
 *   2. an `approves` reference to a negotiation session,
 *   3. an Ed25519 signature with a supplied issuer public key,
 *   4. not-expired against `expires_at`,
 *   5. `scope.offer_hash` equals the SHA-256 of the canonicalized offer.
 *
 * PARITY (asserted against `concordia.approval_receipt` via Python-generated
 * fixtures):
 * - The `failure_reason` constants and ORDER match Python: a schema failure
 *   reports `missing_approves_reference` when the `approves` link is ALSO absent
 *   (Python checks `_has_approves_reference` inside the schema-failure branch),
 *   else `schema_invalid`; then `missing_approves_reference`, `signature_invalid`,
 *   `expired`, `offer_hash_mismatch` in that sequence.
 * - The `checks` map is populated in the same order with the same keys
 *   (`schema`, `approves_reference`, `signature`, `not_expired`, `offer_hash`).
 * - The offer hash is `"sha256:" + sha256(canonicalJcs(offer)).hex`, reusing the
 *   merged canonicalizer so the bytes match Python `canonical_json(offer)`.
 * - The signature is verified with the merged EdDSA `verify()` over the receipt
 *   minus its top-level `signature` field (Python `verify_signature` strips the
 *   same key), so a receipt signed by Python verifies here and vice versa.
 *
 * Like Python, the issuer public key is supplied by the caller (the receipt does
 * NOT carry it); with no key, the signature check fails `signature_invalid`.
 */

import { createHash } from 'node:crypto';

import { canonicalizeJcs } from '../canonical/canonicalize.js';
import { verify, KeyPair } from '../crypto/signing.js';
import { cpythonIsoDateTimeToEpochMs } from '../internal/iso-datetime.js';
import { validateApprovalReceipt } from './schema-validator.js';

/** The decision an ApprovalReceipt records. */
export type ApprovalDecision = 'approve' | 'deny';

// Failure-reason constants, byte-identical to Python's module-level strings.
export const SCHEMA_INVALID = 'schema_invalid';
export const SIGNATURE_INVALID = 'signature_invalid';
export const EXPIRED = 'expired';
export const OFFER_HASH_MISMATCH = 'offer_hash_mismatch';
export const MISSING_APPROVES_REFERENCE = 'missing_approves_reference';

/** Reference `type` values accepted as a negotiation-session link (Python set). */
const NEGOTIATION_SESSION_TYPES = new Set<string>([
  'negotiation_session',
  'a2cn:negotiation_session',
]);

/** Typed result returned by {@link verifyApprovalReceipt} (mirrors Python's dataclass). */
export interface ApprovalReceiptResult {
  valid: boolean;
  decision: ApprovalDecision | null;
  failureReason: string | null;
  receiptId: string | null;
  approver: string | null;
  references: Array<Record<string, unknown>>;
  checks: Record<string, boolean>;
  errors: string[];
}

/**
 * Render an {@link ApprovalReceiptResult} as the snake_cased, JSON-serializable
 * dict Python's `ApprovalReceiptResult.to_dict()` produces (for fixture parity).
 */
export function approvalReceiptResultToDict(
  result: ApprovalReceiptResult,
): Record<string, unknown> {
  return {
    valid: result.valid,
    decision: result.decision,
    failure_reason: result.failureReason,
    receipt_id: result.receiptId,
    approver: result.approver,
    references: result.references,
    checks: result.checks,
    errors: result.errors,
  };
}

/** Options for {@link verifyApprovalReceipt}, mirroring Python's keyword args. */
export interface VerifyApprovalReceiptOptions {
  /**
   * "Now" as epoch milliseconds for the expiry check. Defaults to `Date.now()`.
   * Python uses `datetime.now(timezone.utc)`; the comparison is
   * `expires_at >= now`.
   */
  now?: number;
  /**
   * The issuer's Ed25519 public key (raw 32 bytes or a {@link KeyPair}). The
   * receipt does not carry it, matching Python. With none supplied (or an invalid
   * key), the signature check fails `signature_invalid`.
   */
  issuerPublicKey?: Uint8Array | KeyPair | null;
}

/**
 * Verify a signed ApprovalReceipt against schema, the `approves` reference,
 * signature, expiry, and the offer hash. Port of Python `verify_approval_receipt`.
 *
 * @param receipt The ApprovalReceipt object.
 * @param offer The offer the approver evaluated; its canonical SHA-256 must match
 *   `receipt.scope.offer_hash`.
 * @param options `now` (epoch ms) and `issuerPublicKey`.
 */
export function verifyApprovalReceipt(
  receipt: Record<string, unknown>,
  offer: Record<string, unknown>,
  options: VerifyApprovalReceiptOptions = {},
): ApprovalReceiptResult {
  const scope = isPlainObject(receipt.scope) ? receipt.scope : {};
  const approverObj = isPlainObject(receipt.approver) ? receipt.approver : {};
  const refs = receipt.references;

  const result: ApprovalReceiptResult = {
    valid: false,
    decision: isPlainObject(receipt.scope)
      ? (scope.decision as ApprovalDecision | undefined) ?? null
      : null,
    failureReason: null,
    receiptId: (receipt.id as string | undefined) ?? null,
    approver: isPlainObject(receipt.approver)
      ? (approverObj.identity as string | undefined) ?? null
      : null,
    references: Array.isArray(refs) ? (refs as Array<Record<string, unknown>>) : [],
    checks: {},
    errors: [],
  };

  // --- Check 1: schema ---
  const schemaErrors = validateApprovalReceipt(receipt);
  result.checks.schema = schemaErrors.length === 0;
  if (schemaErrors.length > 0) {
    result.errors.push(...schemaErrors);
    if (!hasApprovesReference(receipt)) {
      result.failureReason = MISSING_APPROVES_REFERENCE;
      result.checks.approves_reference = false;
    } else {
      result.failureReason = SCHEMA_INVALID;
    }
    return result;
  }

  // --- Check 2: approves reference ---
  result.checks.approves_reference = hasApprovesReference(receipt);
  if (!result.checks.approves_reference) {
    result.failureReason = MISSING_APPROVES_REFERENCE;
    result.errors.push('Missing approves reference for negotiation session');
    return result;
  }

  // --- Check 3: signature ---
  const signature = receipt.signature;
  if (!isPlainObject(signature) || signature.alg !== 'Ed25519') {
    result.checks.signature = false;
    result.failureReason = SIGNATURE_INVALID;
    result.errors.push('ApprovalReceipt signature must use Ed25519');
    return result;
  }

  const publicKey = publicKeyFrom(options.issuerPublicKey);
  if (publicKey === null) {
    result.checks.signature = false;
    result.failureReason = SIGNATURE_INVALID;
    result.errors.push('Missing or invalid Ed25519 issuer public key');
    return result;
  }

  const sigValue =
    typeof signature.value === 'string' ? signature.value : '';
  result.checks.signature = verify(receipt, sigValue, publicKey);
  if (!result.checks.signature) {
    result.failureReason = SIGNATURE_INVALID;
    result.errors.push('Invalid ApprovalReceipt signature');
    return result;
  }

  // --- Check 4: not expired ---
  // Schema validation already guaranteed `expires_at` is a valid tz-aware
  // date-time string (per the `date-time` format check), so the parse here
  // returns a real instant; if a caller bypassed schema validation and the parse
  // fails, treat it as expired (fail-CLOSED) rather than comparing against `NaN`.
  const expiresAt = parseDateTimeMs(receipt.expires_at as string);
  const now = options.now ?? Date.now();
  result.checks.not_expired = expiresAt !== null && expiresAt >= now;
  if (!result.checks.not_expired) {
    result.failureReason = EXPIRED;
    result.errors.push('ApprovalReceipt expired');
    return result;
  }

  // --- Check 5: offer hash ---
  const expectedHash = offerHash(offer);
  const receiptHash = (scope as Record<string, unknown>).offer_hash;
  result.checks.offer_hash = receiptHash === expectedHash;
  if (!result.checks.offer_hash) {
    result.failureReason = OFFER_HASH_MISMATCH;
    result.errors.push(
      `Offer hash mismatch: receipt=${String(receiptHash)} computed=${expectedHash}`,
    );
    return result;
  }

  result.valid = true;
  result.failureReason = null;
  return result;
}

// ---------------------------------------------------------------------------
// Internal helpers (mirror the Python module-level functions)
// ---------------------------------------------------------------------------

/**
 * Python `_has_approves_reference`: true iff `references` is a list containing a
 * dict with `relationship == "approves"` and a `type` in the negotiation-session
 * set.
 */
function hasApprovesReference(receipt: Record<string, unknown>): boolean {
  const references = receipt.references;
  if (!Array.isArray(references)) {
    return false;
  }
  for (const reference of references) {
    if (!isPlainObject(reference)) {
      continue;
    }
    if (
      reference.relationship === 'approves' &&
      typeof reference.type === 'string' &&
      NEGOTIATION_SESSION_TYPES.has(reference.type)
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Python `_offer_hash`: `"sha256:" + sha256(canonical_json(offer)).hexdigest()`.
 * `canonicalizeJcs` produces the same bytes as Python `canonical_json`.
 */
function offerHash(offer: Record<string, unknown>): string {
  const digest = createHash('sha256')
    .update(canonicalizeJcs(offer))
    .digest('hex');
  return `sha256:${digest}`;
}

/**
 * Parse an ISO 8601 timestamp to epoch ms, mirroring Python's `_parse_datetime`
 * (`datetime.fromisoformat(value.replace("Z","+00:00"))`, naive -> UTC). Returns
 * `null` when the value is not a valid CPython isoformat.
 *
 * Delegates to the shared CPython-3.12-`fromisoformat`-faithful parser so it
 * accepts EXACTLY what Python's `_parse_datetime` accepts -- including the
 * alternate spellings `Date.parse` chokes on (offset without a colon `+0000`,
 * hour-only offset `+00`, comma fractional seconds, basic form, and sub-minute
 * offsets `...+00:00:30`). `Date.parse` returned `NaN` for several of those,
 * which made `expiresAt >= now` false and FALSELY reported a valid receipt as
 * `expired`; the shared parser computes the correct instant instead.
 */
function parseDateTimeMs(value: string): number | null {
  return cpythonIsoDateTimeToEpochMs(value.replace(/Z/g, '+00:00'));
}

/**
 * Python `_public_key_from_bytes`: accept a {@link KeyPair} or raw 32-byte key,
 * returning the verifying key or `null` (an invalid-length key -> `null`, which
 * Python reproduces by catching the `ValueError` from `from_public_bytes`).
 */
function publicKeyFrom(
  key: Uint8Array | KeyPair | null | undefined,
): Uint8Array | KeyPair | null {
  if (key === null || key === undefined) {
    return null;
  }
  if (key instanceof KeyPair) {
    return key;
  }
  // Raw bytes: Python's `Ed25519PublicKey.from_public_bytes` requires exactly 32
  // bytes; a wrong length raises -> `None`. The merged `verify()` likewise
  // returns false for a wrong-length key, but matching Python we reject up front
  // so the failure reason is the missing/invalid-key path.
  if (key instanceof Uint8Array && key.length === 32) {
    return key;
  }
  return null;
}

/** Python `isinstance(x, dict)`: a plain object, not an array / null. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
