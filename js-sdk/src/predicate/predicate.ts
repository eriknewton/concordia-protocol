/**
 * Concordia v0.6 signed predicate primitive.
 *
 * Port of `concordia/predicate.py`. A predicate is an Ed25519-signed,
 * authority-issued statement that some `condition` holds about a `subject`
 * (e.g. "this agent is authorized for procurement up to a limit"). Verifiers
 * resolve and check predicates to gate downstream actions.
 *
 * Cross-language parity is load-bearing on three axes, each asserted against
 * fixtures generated FROM Python (`tests/fixtures/predicate/predicate_vectors.json`):
 *   1. Canonical signing bytes: `serializePredicateCanonical` must produce the
 *      same bytes as Python `serialize_predicate_canonical` (JCS over the
 *      predicate dict with `signature` stripped). It reuses the already-ported
 *      `canonicalizePredicate`.
 *   2. Signature bytes: `signPredicate` must produce the same base64url Ed25519
 *      signature as Python `sign_predicate`, including the side effect of
 *      injecting `metadata.issuer_public_key_b64` and defaulting `algorithm`
 *      to `EdDSA` before signing.
 *   3. Verification outcome: `verifyPredicate` must reproduce Python
 *      `verify_predicate`'s `valid` flag, `failure_reason`, and per-check map,
 *      including the exact ORDER of checks (schema -> profile -> resolver ->
 *      signature -> lifecycle -> subject -> reference). The ordering matters:
 *      a predicate whose `status` was changed to `revoked` AFTER signing fails
 *      the SIGNATURE check (the status is inside the signed bytes) before the
 *      lifecycle check ever runs, so its `failure_reason` is `bad_signature`,
 *      not `revoked`. The Python-generated fixtures capture that exactly.
 *
 * Scope: this PR ports the EdDSA path only (the v0.6 reference signer emits
 * EdDSA exclusively, matching Python `sign_predicate` which raises on anything
 * else). The `resolver`-based reference-binding path is ported. ES256 predicate
 * verification, like ES256 message signing, is deferred.
 */

import { canonicalizePredicate } from '../canonical/canonicalize.js';
import { sign, verify, KeyPair } from '../crypto/signing.js';
import { toBase64Url, fromBase64Url } from '../crypto/base64url.js';
import { cpythonIsoDateTimeToEpochMs } from '../internal/iso-datetime.js';
import { validateReference, snapshotPlainData } from './references.js';
import { validateConditionForProfile } from './profiles.js';

/** Predicate lifecycle status values. Mirrors Python `PredicateStatus`. */
export const PredicateStatus = {
  ACTIVE: 'active',
  EXPIRED: 'expired',
  REVOKED: 'revoked',
  SUSPENDED: 'suspended',
} as const;
export type PredicateStatus =
  (typeof PredicateStatus)[keyof typeof PredicateStatus];

/** Stable, policy-readable failure reasons. Mirrors Python `PredicateFailureReason`. */
export const PredicateFailureReason = {
  SCHEMA_INVALID: 'schema_invalid',
  BAD_SIGNATURE: 'bad_signature',
  EXPIRED: 'expired',
  REVOKED: 'revoked',
  UNKNOWN_AUTHORITY: 'unknown_authority',
  REF_MISMATCH: 'ref_mismatch',
  WRONG_SUBJECT: 'wrong_subject',
  RESOLVER_MISS: 'resolver_miss',
} as const;
export type PredicateFailureReason =
  (typeof PredicateFailureReason)[keyof typeof PredicateFailureReason];

/** Error raised for invalid predicate write/sign input (Python `ValueError`). */
export class PredicateValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PredicateValidationError';
  }
}

/**
 * Strict plain-object test mirroring Python's `isinstance(value, dict)`.
 *
 * Python's predicate schema check gates `condition` (and the signer gates
 * `metadata`) on being an actual mapping. A class instance, a `Date`, a `Map`,
 * a boxed primitive, etc. are NOT dicts and Python rejects them. A naive
 * `typeof === 'object'` check would fail-open by accepting those. A plain
 * object is one whose prototype is `Object.prototype` (a `{...}` literal or
 * `JSON.parse` output) or `null` (`Object.create(null)`); anything with a
 * different prototype is rejected.
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * A resolver maps a predicate id (or reference id) to a {@link Predicate}, or
 * `null`/`undefined` if it cannot be resolved. Mirrors Python
 * `PredicateResolver`.
 */
export type PredicateResolver = (
  predicateId: string,
) => Predicate | null | undefined;

/** The wire/dict shape of a predicate. Mirrors Python `Predicate.to_dict()`. */
export interface PredicateDict {
  predicate_id: string;
  type: string;
  authority: string;
  issuer: string;
  subject: string;
  condition: Record<string, unknown>;
  issued_at: string;
  expires_at: string;
  references: Record<string, unknown>[];
  algorithm: string;
  status: string;
  signature?: string;
  validity?: Record<string, unknown> | null;
  constraints?: Record<string, unknown> | null;
  delegation_chain?: Record<string, unknown>[] | null;
  revocation_endpoint?: string | null;
  revoked_at?: string | null;
  metadata?: Record<string, unknown> | null;
  [key: string]: unknown;
}

/**
 * An immutable signed predicate. Mirrors the frozen Python dataclass
 * `Predicate`. Field names follow Python's snake_case wire form (these names
 * cross the wire into canonical JSON), preserving byte-parity.
 */
export class Predicate {
  readonly predicate_id: string;
  readonly type: string;
  readonly authority: string;
  readonly issuer: string;
  readonly subject: string;
  readonly condition: Record<string, unknown>;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly references: Record<string, unknown>[];
  readonly algorithm: string;
  readonly status: string;
  readonly signature: string;
  readonly validity: Record<string, unknown> | null;
  readonly constraints: Record<string, unknown> | null;
  readonly delegation_chain: Record<string, unknown>[] | null;
  readonly revocation_endpoint: string | null;
  readonly revoked_at: string | null;
  readonly metadata: Record<string, unknown> | null;

  private constructor(fields: {
    predicate_id: string;
    type: string;
    authority: string;
    issuer: string;
    subject: string;
    condition: Record<string, unknown>;
    issued_at: string;
    expires_at: string;
    references: Record<string, unknown>[];
    algorithm: string;
    status: string;
    signature: string;
    validity: Record<string, unknown> | null;
    constraints: Record<string, unknown> | null;
    delegation_chain: Record<string, unknown>[] | null;
    revocation_endpoint: string | null;
    revoked_at: string | null;
    metadata: Record<string, unknown> | null;
  }) {
    this.predicate_id = fields.predicate_id;
    this.type = fields.type;
    this.authority = fields.authority;
    this.issuer = fields.issuer;
    this.subject = fields.subject;
    this.condition = fields.condition;
    this.issued_at = fields.issued_at;
    this.expires_at = fields.expires_at;
    this.references = fields.references;
    this.algorithm = fields.algorithm;
    this.status = fields.status;
    this.signature = fields.signature;
    this.validity = fields.validity;
    this.constraints = fields.constraints;
    this.delegation_chain = fields.delegation_chain;
    this.revocation_endpoint = fields.revocation_endpoint;
    this.revoked_at = fields.revoked_at;
    this.metadata = fields.metadata;
    Object.freeze(this);
  }

  /**
   * Parse predicate data, accepting `predicate_type` as a read-only alias for
   * `type`. Each entry in `references` is validated/normalized through
   * {@link validateReference}. Mirrors Python `Predicate.from_dict`.
   *
   * SNAPSHOT SEMANTICS (adversarial-review residual fix, 2026-06-12): parsing
   * runs against a defensive plain-data deep SNAPSHOT of `data`, taken with
   * the same descriptor-walk machinery `validateReference` uses
   * ({@link snapshotPlainData}). The previous `{ ...data }` spread performed
   * [[Get]] on every own enumerable property, so a hostile getter EXECUTED
   * during parse and its thrown text (attacker-controlled; probe:
   * `throw Error("SECRET_TERMS price=4350")`) escaped to the caller verbatim,
   * violating the no-echo invariant references.ts enforces. The descriptor
   * walk never performs [[Get]]: accessor properties, symbol keys, and
   * non-enumerable own properties are rejected WITHOUT being invoked; any
   * foreign throw (a Proxy trap, a revoked proxy, a hostile prototype) is
   * converted to a content-free {@link PredicateValidationError} that echoes
   * neither the caught error text nor any input value; and because every
   * nested plain object/array is deep-copied, mutating the caller's tree
   * after construction can never reach this predicate's serialized form
   * (TOCTOU closure). Plain-data semantics are unchanged: non-JSON leaves
   * (e.g. `undefined` optional fields) pass through exactly as the spread
   * carried them, and validation/normalization below is untouched.
   */
  static fromDict(data: Record<string, unknown>): Predicate {
    let normalized: Record<string, unknown>;
    try {
      if (!isPlainObject(data)) {
        throw new PredicateValidationError(
          'predicate data must be a plain object',
        );
      }
      normalized = snapshotPlainData(data, {
        label: 'predicate data',
        makeError: (m: string) => new PredicateValidationError(m),
        nonJson: 'pass',
      }).snapshot;
    } catch (err) {
      if (err instanceof PredicateValidationError) {
        throw err;
      }
      // Foreign throw while inspecting hostile input. Never echo the caught
      // error text: it is attacker-controlled content.
      throw new PredicateValidationError(
        'predicate data could not be safely inspected',
      );
    }
    if (!('type' in normalized) && 'predicate_type' in normalized) {
      normalized.type = normalized.predicate_type;
      delete normalized.predicate_type;
    }
    const rawRefs = (normalized.references as unknown[]) ?? [];
    normalized.references = rawRefs.map((ref, index) =>
      validateReference(ref, index),
    );
    return new Predicate({
      predicate_id: normalized.predicate_id as string,
      type: normalized.type as string,
      authority: normalized.authority as string,
      issuer: normalized.issuer as string,
      subject: normalized.subject as string,
      condition: normalized.condition as Record<string, unknown>,
      issued_at: normalized.issued_at as string,
      expires_at: normalized.expires_at as string,
      references: normalized.references as Record<string, unknown>[],
      algorithm: normalized.algorithm as string,
      status: normalized.status as string,
      signature: (normalized.signature as string) ?? '',
      validity: (normalized.validity as Record<string, unknown>) ?? null,
      constraints: (normalized.constraints as Record<string, unknown>) ?? null,
      delegation_chain:
        (normalized.delegation_chain as Record<string, unknown>[]) ?? null,
      revocation_endpoint: (normalized.revocation_endpoint as string) ?? null,
      revoked_at: (normalized.revoked_at as string) ?? null,
      metadata: (normalized.metadata as Record<string, unknown>) ?? null,
    });
  }

  /**
   * Serialize to the wire/dict form. Emits the eleven core fields in the same
   * insertion order as Python `Predicate.to_dict`, the `signature` (unless
   * suppressed), then any non-null optional fields in Python's fixed key order.
   *
   * @param includeSignature When `false`, omit the `signature` field (used by
   *   the canonical signing-bytes path). Default `true`.
   */
  toDict(includeSignature = true): PredicateDict {
    const data: PredicateDict = {
      predicate_id: this.predicate_id,
      type: this.type,
      authority: this.authority,
      issuer: this.issuer,
      subject: this.subject,
      condition: this.condition,
      issued_at: this.issued_at,
      expires_at: this.expires_at,
      references: this.references,
      algorithm: this.algorithm,
      status: this.status,
    };
    if (includeSignature) {
      data.signature = this.signature;
    }
    const optionalKeys = [
      'validity',
      'constraints',
      'delegation_chain',
      'revocation_endpoint',
      'revoked_at',
      'metadata',
    ] as const;
    for (const key of optionalKeys) {
      const value = this[key];
      if (value !== null && value !== undefined) {
        data[key] = value as never;
      }
    }
    return data;
  }
}

/** A single verification check result map and the overall verdict. */
export interface PredicateVerificationResult {
  valid: boolean;
  failure_reason: PredicateFailureReason | null;
  verified_subject: string | null;
  verified_authority: string | null;
  predicate_id: string | null;
  issuer: string | null;
  checks: Record<string, boolean>;
  errors: string[];
  warnings: string[];
  revoked_at: string | null;
  tier: string | null;
}

/**
 * Return the canonical signing bytes for a predicate: JCS over the predicate
 * dict with its `signature` member removed. Mirrors Python
 * `serialize_predicate_canonical`. Accepts a {@link Predicate} or a dict.
 */
export function serializePredicateCanonical(
  predicate: Predicate | Record<string, unknown>,
): Buffer {
  const dict =
    predicate instanceof Predicate ? predicate.toDict() : predicate;
  return canonicalizePredicate(dict);
}

function failResult(
  predicate: Predicate | null,
  reason: PredicateFailureReason,
  error: string,
  checks: Record<string, boolean> = {},
  warnings: string[] = [],
): PredicateVerificationResult {
  return {
    valid: false,
    failure_reason: reason,
    predicate_id: predicate ? predicate.predicate_id : null,
    issuer: predicate ? predicate.issuer : null,
    verified_subject: predicate ? predicate.subject : null,
    verified_authority: predicate ? predicate.authority : null,
    checks,
    errors: [error],
    warnings,
    revoked_at: predicate ? predicate.revoked_at : null,
    tier: null,
  };
}

/**
 * Reproduce CPython's `datetime.fromisoformat(s)` error text for the value the
 * predicate validator feeds it (already `Z`->`+00:00` normalized). CPython
 * distinguishes two failure shapes, and `_schema_errors` surfaces the raw text
 * verbatim, so the JS message must match byte-for-byte:
 *
 *   1. STRUCTURALLY malformed (cannot even split into Y-M-D[/time] digit
 *      groups): `Invalid isoformat string: '<s>'` where `<s>` is the
 *      POST-replace string (confirmed against CPython 3.12: `"xZ"` ->
 *      `"x+00:00"` shows up in the message).
 *   2. Structurally parseable but a field is OUT OF RANGE (e.g. month 13, hour
 *      25): a field-specific message like `month must be in 1..12` or
 *      `hour must be in 0..23`.
 *
 * This matches the two `datetime` constructor message families CPython emits.
 * `MONTH must be in 1..12` and friends come straight from the `datetime`
 * C-accelerator's range checks; the regex below extracts the calendar fields
 * from a structurally-valid string and validates each in CPython's check order
 * (month, day, hour, minute, second), returning the first violation.
 *
 * @returns the CPython error message, or `null` if `s` parses cleanly.
 */
function fromIsoformatError(s: string): string | null {
  // CPython's isoformat grammar: YYYY-MM-DD, optionally followed by a
  // 'T'/' ' separator and HH[:MM[:SS[.ffffff]]] then an optional tz offset
  // (+HH:MM[:SS[.ffffff]] / -HH:MM... / +00:00). This regex captures the
  // calendar/time fields when the OVERALL SHAPE is valid; anything that does
  // not match is treated as structurally malformed (category 1).
  const m =
    /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,6})?)?(?:[+-]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?)?)?$/.exec(
      s,
    );
  if (m === null) {
    return `Invalid isoformat string: '${s}'`;
  }
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = m[4] !== undefined ? Number(m[4]) : 0;
  const minute = m[5] !== undefined ? Number(m[5]) : 0;
  const second = m[6] !== undefined ? Number(m[6]) : 0;
  // CPython checks month before day, then hour/minute/second.
  if (month < 1 || month > 12) return 'month must be in 1..12';
  // Feb is leap-aware (proper Gregorian rule), matching CPython: 2024-02-29 OK,
  // 2026/2100-02-29 reject, 2000-02-29 OK.
  const isLeap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  // month is already validated to 1..12 above, so this index is always in range.
  const daysInMonth =
    [31, isLeap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][
      month - 1
    ] ?? 31;
  if (day < 1 || day > daysInMonth) return `day is out of range for month`;
  if (hour > 23) return 'hour must be in 0..23';
  if (minute > 59) return 'minute must be in 0..59';
  if (second > 59) return 'second must be in 0..59';
  return null;
}

/**
 * Parse an ISO-8601 timestamp to epoch milliseconds in UTC, mirroring Python's
 * `datetime.fromisoformat(value.replace("Z", "+00:00"))` followed by a forced
 * UTC interpretation when the parsed value is naive.
 *
 * Only millisecond resolution is compared (lifecycle expiry is a coarse "is it
 * past `expires_at`" check), which is more than sufficient and avoids any
 * sub-millisecond drift between platforms.
 *
 * Error parity: a non-string raises Python's `"{field} must be an ISO 8601
 * string"` (from `_parse_datetime`); a malformed string raises CPython's exact
 * `datetime.fromisoformat` message (see {@link fromIsoformatError}), NOT a
 * generic placeholder, because `_schema_errors` surfaces that text in `errors`.
 *
 * FAIL-CLOSED YEAR-9999 OVERFLOW (2026-05-30 finding #3, predicate caller).
 * Python's predicate `_parse_datetime` is `fromisoformat(...).astimezone(
 * timezone.utc)`. A year-9999 (or year-0001) civil time with a tz offset that
 * pushes the UTC instant past `datetime.max` / before `datetime.min` parses
 * through `fromisoformat` (so `fromIsoformatError` returns null) but raises
 * `OverflowError` at `astimezone`. The predicate `_schema_errors` wraps that
 * call in `try/except Exception` and appends `str(exc)` -- the literal text
 * `date value out of range` -- so such a predicate FAILS Python's schema check
 * (failure_reason `schema_invalid`) and is NOT honored. `Date.parse` has no such
 * ceiling and returns a finite far-future ms, which made the TS verifier mark
 * lifecycle valid and return `valid: true` -- a fail-OPEN relative to Python.
 * We detect the overflow with the shared CPython-faithful parser (it returns
 * null on exactly the inputs `astimezone` overflows on) and throw the SAME
 * `date value out of range` text so the schema error list matches Python
 * byte-for-byte. The non-overflow ms value still comes from the existing
 * `Date.parse` path, preserving all prior epoch-ms parity. Reject, not clamp.
 */
function parseDatetimeMs(value: unknown, fieldName: string): number {
  if (typeof value !== 'string') {
    throw new PredicateValidationError(
      `${fieldName} must be an ISO 8601 string`,
    );
  }
  // Python treats a trailing 'Z' as +00:00 (it does `value.replace("Z",
  // "+00:00")` before `fromisoformat`). Mirror the replace so the error text
  // (which quotes the post-replace string) and the parse agree with CPython.
  const s = value.replace(/Z/g, '+00:00');
  const isoError = fromIsoformatError(s);
  if (isoError !== null) {
    throw new PredicateValidationError(isoError);
  }
  // The string is a structurally-valid CPython isoformat. CPython's
  // `_parse_datetime` then does `.astimezone(timezone.utc)`, which raises
  // `OverflowError: date value out of range` when the offset pushes the UTC
  // instant out of `[datetime.min, datetime.max]`. The shared guarded parser
  // returns null on exactly those inputs; mirror Python's raise as the same
  // schema-error text (fail-closed: the predicate is rejected, never honored).
  if (cpythonIsoDateTimeToEpochMs(s) === null) {
    throw new PredicateValidationError('date value out of range');
  }
  // For the epoch-ms comparison, append 'Z' when there is no explicit offset so
  // JS parses it as UTC (Python forces naive timestamps to UTC in
  // `_parse_datetime`).
  let forParse = s;
  const hasOffset = /[+-]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?$/.test(forParse);
  if (!hasOffset) {
    forParse = forParse + 'Z';
  }
  const ms = Date.parse(forParse);
  if (Number.isNaN(ms)) {
    // Defensive: CPython accepted it but JS Date.parse did not. Surface the
    // same isoformat-style message rather than a generic placeholder.
    throw new PredicateValidationError(`Invalid isoformat string: '${s}'`);
  }
  return ms;
}

/** Quietly try to parse a datetime; returns `null` on failure (for schema check). */
function tryParseDatetimeError(value: unknown, fieldName: string): string | null {
  try {
    parseDatetimeMs(value, fieldName);
    return null;
  } catch (err) {
    return (err as Error).message;
  }
}

/**
 * Structural schema check for a predicate dict. Mirrors Python `_schema_errors`
 * exactly, including the error strings and the early-return after a
 * missing-required-fields error. The `predicate_type` read alias is accepted
 * for the `type` check but is itself flagged as a write-only violation in
 * {@link validatePredicateForWrite}, not here.
 */
function schemaErrors(input: Record<string, unknown>): string[] {
  const required = [
    'predicate_id',
    'type',
    'authority',
    'issuer',
    'subject',
    'condition',
    'issued_at',
    'expires_at',
    'references',
    'algorithm',
    'status',
    'signature',
  ];
  const errors: string[] = [];
  let data = input;
  if (!('type' in data) && 'predicate_type' in data) {
    data = { ...data, type: data.predicate_type };
  }
  const allowed = new Set<string>([
    ...required,
    'predicate_type',
    'validity',
    'constraints',
    'delegation_chain',
    'revocation_endpoint',
    'revoked_at',
    'metadata',
  ]);
  const extra = Object.keys(data)
    .filter((k) => !allowed.has(k))
    .sort();
  if (extra.length > 0) {
    errors.push(
      `additional predicate properties are not allowed: [${extra
        .map((k) => `'${k}'`)
        .join(', ')}]`,
    );
  }
  const missing = required.filter((f) => !(f in data));
  if (missing.length > 0) {
    errors.push(
      `missing required predicate fields: [${missing
        .map((f) => `'${f}'`)
        .join(', ')}]`,
    );
    return errors;
  }
  if (!String(data.predicate_id).startsWith('urn:concordia:predicate:')) {
    errors.push('predicate_id must start with urn:concordia:predicate:');
  }
  for (const field of [
    'type',
    'authority',
    'issuer',
    'subject',
    'algorithm',
    'status',
  ]) {
    const v = data[field];
    if (typeof v !== 'string' || v.length === 0) {
      errors.push(`${field} must be a non-empty string`);
    }
  }
  if (data.algorithm !== 'EdDSA' && data.algorithm !== 'ES256') {
    errors.push('algorithm must be EdDSA or ES256');
  }
  const statusValues = new Set<string>(Object.values(PredicateStatus));
  if (typeof data.status !== 'string' || !statusValues.has(data.status)) {
    errors.push('status must be active, expired, revoked, or suspended');
  }
  // Python: `if not isinstance(data["condition"], dict) or not data["condition"]`.
  // A strict plain-object test matches `isinstance(_, dict)` (rejecting class
  // instances / Date / Map that a loose `typeof === 'object'` would fail-open
  // on); the empty check matches Python's truthiness on an empty mapping.
  if (
    !isPlainObject(data.condition) ||
    Object.keys(data.condition).length === 0
  ) {
    errors.push('condition must be a non-empty object');
  }
  if (!Array.isArray(data.references)) {
    errors.push('references must be an array');
  } else {
    data.references.forEach((ref, index) => {
      try {
        validateReference(ref, index);
      } catch (err) {
        errors.push((err as Error).message);
      }
    });
  }
  for (const field of ['issued_at', 'expires_at']) {
    const errMsg = tryParseDatetimeError(data[field], field);
    if (errMsg !== null) {
      errors.push(errMsg);
    }
  }
  return errors;
}

/**
 * Validate a predicate (dict or {@link Predicate}) for writing/signing.
 * Mirrors Python `validate_predicate_for_write`: runs the structural schema
 * check, flags the read-only `predicate_type` alias, runs the type-profile
 * gate, and throws a {@link PredicateValidationError} joining all messages with
 * `"; "` if any are present.
 */
export function validatePredicateForWrite(
  predicate: Predicate | Record<string, unknown>,
): void {
  const data =
    predicate instanceof Predicate ? predicate.toDict() : { ...predicate };
  const errors = schemaErrors(data);
  if ('predicate_type' in data) {
    errors.push('predicate_type is read-only compatibility; write type instead');
  }
  const candidateType = data.type ?? data.predicate_type;
  if (typeof candidateType === 'string') {
    errors.push(
      ...validateConditionForProfile(candidateType, data.condition),
    );
  }
  if (errors.length > 0) {
    throw new PredicateValidationError(errors.join('; '));
  }
}

/**
 * Sign a predicate (dict or {@link Predicate}) with Ed25519 and return the
 * signed immutable {@link Predicate}. Mirrors Python `sign_predicate`:
 * defaults `algorithm` to `EdDSA` (and rejects anything else), injects
 * `metadata.issuer_public_key_b64` if absent, clears `signature`, runs
 * write-validation, then signs the canonical bytes and re-parses via
 * {@link Predicate.fromDict}.
 */
export function signPredicate(
  predicate: Predicate | Record<string, unknown>,
  keyPair: KeyPair,
): Predicate {
  const data: Record<string, unknown> =
    predicate instanceof Predicate ? predicate.toDict() : { ...predicate };
  data.algorithm = data.algorithm ?? 'EdDSA';
  if (data.algorithm !== 'EdDSA') {
    throw new PredicateValidationError('v0.6 reference signer emits EdDSA only');
  }
  // Python: `metadata = dict(data.get("metadata") or {})`.
  //   - A FALSY metadata (None/undefined, {}, "", 0, false, []) collapses to an
  //     empty mapping via `or {}` (no error).
  //   - A TRUTHY mapping is copied.
  //   - A TRUTHY non-mapping (e.g. `metadata: 5`, `3.5`, `true`, a non-empty
  //     string, a non-empty list) makes `dict(...)` RAISE (int/float/bool are
  //     not iterable; str/list are not key/value sequences). A loose spread
  //     `{...5}` would silently yield `{}` here — a fail-open. Reject instead,
  //     matching Python's raise.
  const rawMetadata = data.metadata;
  const metadata: Record<string, unknown> = {};
  if (isPlainObject(rawMetadata) && Object.keys(rawMetadata).length > 0) {
    Object.assign(metadata, rawMetadata);
  } else if (isPlainObject(rawMetadata)) {
    // empty plain object: falsy-equivalent, stays empty (matches `{} or {}`).
  } else if (
    rawMetadata === null ||
    rawMetadata === undefined ||
    rawMetadata === false ||
    rawMetadata === 0 ||
    rawMetadata === '' ||
    (Array.isArray(rawMetadata) && rawMetadata.length === 0)
  ) {
    // falsy: collapses to {} exactly as Python's `or {}` does.
  } else {
    // truthy non-mapping: Python `dict(...)` raises; mirror as a rejection.
    //
    // KNOWN PARITY RESIDUALS (accepted 2026-05-29, both fail-CLOSED / safe
    // direction; neither is reachable from wire/JSON data):
    //  (a) metadata: Python's `dict(metadata or {})` also accepts an iterable
    //      of key/value PAIRS (e.g. [["k","v"]]); this rejects it. That is TS
    //      being STRICTER than Python, never looser — a Python-constructed
    //      pairs-list metadata simply won't round-trip. JSON metadata is always
    //      an object, so this cannot occur over the wire.
    //  (b) ISO-8601 (see fromIsoformatError below): error text + accept/reject
    //      match CPython for normal timestamps, but diverge on exotic/invalid
    //      offsets (+24:00, +00:60, sub-minute offsets). Those are INVALID
    //      timestamps rejected either way; CPython's own behavior here is
    //      version-dependent (3.9 != 3.12). Real Concordia timestamps are
    //      normal `...Z` / `+HH:MM`. No fail-open in either case.
    //  Full parity for both is deferred; not worth chasing version-dependent
    //  CPython edge behavior on inputs that do not occur.
    throw new PredicateValidationError('metadata must be an object');
  }
  if (!('issuer_public_key_b64' in metadata)) {
    metadata.issuer_public_key_b64 = keyPair.publicKeyB64();
  }
  data.metadata = metadata;
  data.signature = '';
  validatePredicateForWrite(data);
  // Python signs with key_pair.private_key.sign(canonical_bytes) then
  // base64url-encodes; sign() does the same canonical-bytes -> base64url path.
  const signature = sign(data, keyPair);
  data.signature = signature;
  return Predicate.fromDict(data);
}

/**
 * Recover the issuer's raw Ed25519 public key from
 * `metadata.issuer_public_key_b64`, or `null` if absent/undecodable. Mirrors
 * Python `_public_key_from_predicate`.
 */
function publicKeyFromPredicate(predicate: Predicate): Uint8Array | null {
  const metadata = predicate.metadata ?? {};
  const raw = (metadata as Record<string, unknown>).issuer_public_key_b64;
  if (typeof raw !== 'string') {
    return null;
  }
  try {
    return fromBase64Url(raw);
  } catch {
    return null;
  }
}

/**
 * Verify a signed predicate and return a stable, policy-readable result.
 * Mirrors Python `verify_predicate`, including the exact check ORDER:
 *   schema -> profile_condition -> (resolver references) -> signature
 *   -> lifecycle -> [DEFERRED: revocation_records] -> subject_binding
 *   -> reference_binding.
 *
 * DEFERRED PARITY GAP -- `revocation_records` / `now` verification:
 *   Python `verify_predicate` accepts two extra keyword args -- a
 *   `revocation_records` mapping and a `now` timestamp -- and, between the
 *   lifecycle and subject checks, calls
 *   `concordia.cmpc.revocation.find_revocation_for_references(...)`; a match
 *   adds `checks["revocation_records"] = False` and fails with
 *   `REVOKED` / "referenced artifact revoked by <id>".
 *   That path strictly depends on the UNPORTED `concordia.cmpc` module (the
 *   `RevocationRecord` type, its canonical form, its schema validation and
 *   signing all live there). Per the JS-SDK staged-port discipline this is
 *   DEFERRED to a future PR pending the `cmpc` (cross-mandate revocation) port,
 *   rather than half-implemented. `verifyPredicate` therefore does not yet
 *   accept `revocationRecords` / `now`; predicates that Python would fail via a
 *   referenced-artifact revocation are NOT yet failed here. The boundary is
 *   pinned by a fixture (`deferred_revocation_records`, generated from Python)
 *   and an `it.skip` test in tests/predicate.test.ts that documents the
 *   expected outcome once the port lands. See CHANGELOG.
 *
 * @param predicate A {@link Predicate}, a dict, or a predicate-id string
 *   (which requires `resolver`).
 * @param options.resolver Optional resolver for id-string input and for
 *   binding `references[].type === "predicate"` entries.
 */
export function verifyPredicate(
  predicate: Predicate | Record<string, unknown> | string,
  options: { resolver?: PredicateResolver } = {},
): PredicateVerificationResult {
  const checks: Record<string, boolean> = {};
  const warnings: string[] = [];
  const resolver = options.resolver;

  let working: Predicate | Record<string, unknown> = predicate as
    | Predicate
    | Record<string, unknown>;

  if (typeof predicate === 'string') {
    if (!resolver) {
      return failResult(
        null,
        PredicateFailureReason.RESOLVER_MISS,
        'resolver required',
      );
    }
    const resolved = resolver(predicate);
    if (resolved === null || resolved === undefined) {
      return failResult(null, PredicateFailureReason.RESOLVER_MISS, predicate);
    }
    if (resolved.predicate_id !== predicate) {
      return failResult(resolved, PredicateFailureReason.REF_MISMATCH, predicate);
    }
    working = resolved;
  }

  const raw =
    working instanceof Predicate ? working.toDict() : { ...working };
  const errs = schemaErrors(raw);
  if (errs.length > 0) {
    return failResult(
      null,
      PredicateFailureReason.SCHEMA_INVALID,
      errs.join('; '),
      { schema: false },
    );
  }

  let parsed: Predicate;
  try {
    parsed = Predicate.fromDict(raw);
  } catch (err) {
    return failResult(
      null,
      PredicateFailureReason.SCHEMA_INVALID,
      (err as Error).message,
      { schema: false },
    );
  }
  checks.schema = true;

  const profileErrors = validateConditionForProfile(
    parsed.type,
    parsed.condition,
  );
  checks.profile_condition = profileErrors.length === 0;
  if (profileErrors.length > 0) {
    return failResult(
      parsed,
      PredicateFailureReason.SCHEMA_INVALID,
      profileErrors.join('; '),
      checks,
      warnings,
    );
  }

  if (resolver) {
    for (const ref of parsed.references) {
      if (ref.type !== 'predicate') continue;
      const refId = ref.id as string;
      const resolved = resolver(refId);
      if (resolved === null || resolved === undefined) {
        return failResult(
          parsed,
          PredicateFailureReason.RESOLVER_MISS,
          refId,
          checks,
        );
      }
      if (resolved.predicate_id !== refId) {
        return failResult(
          parsed,
          PredicateFailureReason.REF_MISMATCH,
          refId,
          checks,
        );
      }
    }
    checks.resolver_binding = true;
  }

  if (!parsed.signature || parsed.algorithm !== 'EdDSA') {
    return failResult(
      parsed,
      PredicateFailureReason.BAD_SIGNATURE,
      'missing or unsupported predicate signature',
      checks,
    );
  }
  const publicKey = publicKeyFromPredicate(parsed);
  if (publicKey === null) {
    return failResult(
      parsed,
      PredicateFailureReason.UNKNOWN_AUTHORITY,
      'issuer public key unavailable',
      checks,
    );
  }
  // Python: verify_signature(parsed.to_dict(), parsed.signature, public_key,
  // alg="EdDSA"). The TS verify() strips `signature` and canonicalizes, which
  // is the same signing-input shape.
  const signatureOk = verify(parsed.toDict(), parsed.signature, publicKey);
  checks.signature = signatureOk;
  if (!signatureOk) {
    return failResult(
      parsed,
      PredicateFailureReason.BAD_SIGNATURE,
      'invalid predicate signature',
      checks,
    );
  }

  const now = Date.now();
  const expiresMs = parseDatetimeMs(parsed.expires_at, 'expires_at');
  if (parsed.status === PredicateStatus.EXPIRED || expiresMs < now) {
    checks.lifecycle = false;
    return failResult(
      parsed,
      PredicateFailureReason.EXPIRED,
      'predicate expired',
      checks,
    );
  }
  if (parsed.status === PredicateStatus.REVOKED || parsed.revoked_at !== null) {
    checks.lifecycle = false;
    return failResult(
      parsed,
      PredicateFailureReason.REVOKED,
      'predicate revoked',
      checks,
    );
  }
  if (parsed.status === PredicateStatus.SUSPENDED) {
    checks.lifecycle = false;
    return failResult(
      parsed,
      PredicateFailureReason.REVOKED,
      'predicate suspended',
      checks,
    );
  }
  checks.lifecycle = true;

  // DEFERRED: Python runs the `revocation_records` referenced-artifact check
  // here (predicate.py:383), via the unported `concordia.cmpc` module. It is
  // intentionally NOT ported in this PR; see the verifyPredicate docblock and
  // CHANGELOG ("revocation_records/now verification deferred pending the cmpc
  // port"). When ported, the check goes in this slot, before subject_binding,
  // adding `checks.revocation_records`.

  const expectedSubject = (parsed.metadata ?? {}).expected_subject;
  if (typeof expectedSubject === 'string' && expectedSubject !== parsed.subject) {
    checks.subject_binding = false;
    return failResult(
      parsed,
      PredicateFailureReason.WRONG_SUBJECT,
      'predicate subject mismatch',
      checks,
    );
  }
  checks.subject_binding = true;

  for (const ref of parsed.references) {
    if (ref.type === 'receipt' && ref.relationship === 'fulfills') {
      // Python calls `_call_approval_receipt_verifier`, which tries to import
      // `concordia.approval_receipt` and appends `approval_receipt_verifier_-
      // unavailable` ONLY if that import fails. In the Python reference the
      // module is always present, so no warning is emitted (verified against
      // the `with_references` fixture: `warnings == []`). The JS SDK treats the
      // approval-receipt capability as available, matching that outcome; no
      // warning is appended. (If a JS approval-receipt verifier is later added
      // with an availability probe, this is where the parity warning would go.)
      void ref;
    }
  }
  checks.reference_binding = true;

  return {
    valid: true,
    failure_reason: null,
    verified_subject: parsed.subject,
    verified_authority: parsed.authority,
    predicate_id: parsed.predicate_id,
    issuer: parsed.issuer,
    checks,
    errors: [],
    warnings,
    revoked_at: null,
    tier: null,
  };
}
