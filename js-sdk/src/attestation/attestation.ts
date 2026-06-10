/**
 * Reputation attestation generation (SPEC §9.6).
 *
 * Port of `concordia/attestation.py`. Every concluded Concordia session --
 * whether it ends in agreement, rejection, or expiry -- produces a Reputation
 * Attestation: a signed, structured record of what happened.
 *
 * PRIVACY INVARIANT (load-bearing, SECURITY.md constraint 8): an attestation
 * records BEHAVIORAL SIGNALS ONLY -- offers_made, concession_magnitude,
 * reasoning_provided, etc. -- and NEVER the raw deal terms (prices, quantities,
 * the term values themselves). The only term-derived number that ever reaches
 * the attestation is `outcome.terms_count` (the *count* of negotiated dimensions,
 * not their values). The port mirrors Python exactly here: it copies
 * `behaviorRecordToDict(...)` into each party record and never reads
 * `session.terms` except to take its length. There is no code path that copies a
 * term value into the attestation.
 *
 * Cross-language parity is the load-bearing property. A signature produced by
 * this generator over a party's behavioral record MUST be byte-identical to, and
 * verifiable by, the Python implementation. Parity contract (verified against
 * `concordia.attestation` via Python-generated fixtures in
 * `tests/fixtures/attestation/attestation_vectors.json`):
 *
 * - `generateAttestation` rejects a non-terminal, non-EXPIRED session with the
 *   exact Python `ValueError` text
 *   (`Cannot generate attestation for session in state <state>`).
 * - The party-record signing payload is `{agent_id, role, behavior}` (NO
 *   `signature` key at signing time, matching Python: the signature is computed
 *   over the record before the `signature` field is attached). `sign()` strips
 *   any top-level `signature`, so the bytes are identical either way. An agent
 *   absent from `keyPairs` gets an empty-string signature, exactly as Python.
 * - `outcome` key insertion order matches Python's
 *   (`status`, `rounds`, `duration_seconds`, optional `terms_count`,
 *   `resolution_mechanism`); `terms_count` is conditionally omitted when the
 *   session has zero terms (Python's `if terms_count > 0`). Canonical JSON sorts
 *   keys, so order does not affect the signed bytes of the per-party records, but
 *   matching insertion order keeps the attestation object structurally identical
 *   for direct comparison.
 * - `meta` emits `extensions_used: []` and `mediator_invoked: false` always, plus
 *   optional `category` / `value_range` (conditionally omitted when not supplied,
 *   matching Python's `if category` / `if value_range`).
 * - `transcriptHash` is the SHA-256 over the CONCATENATED canonical-JSON bytes of
 *   every transcript message (NOT the per-message `computeHash`; this is the
 *   distinct whole-transcript digest Python's `_compute_transcript_hash` produces).
 * - `references` and `validityTemporal` reuse the merged predicate-layer
 *   `validateReference` (NO re-port) and the temporal validators ported here,
 *   with Python-identical normalization, omission, and error text.
 * - `summary` is the 4-line plaintext receipt summary (`generateReceiptSummary`),
 *   computed last and attached, matching Python.
 */

import { createHash } from 'node:crypto';

import { canonicalizeJcs } from '../canonical/canonicalize.js';
import { sign, KeyPair } from '../crypto/signing.js';
import {
  cpythonIsoDateTimeToEpochMs,
  cpythonIsoDateTimeToEpochMicros,
} from '../internal/iso-datetime.js';
import {
  OutcomeStatus,
  ResolutionMechanism,
  SessionState,
  behaviorRecordToDict,
} from '../types/index.js';
import { validateReference } from '../predicate/references.js';
import type { Session } from '../session/index.js';

/** Attestation schema version, byte-identical to Python `ATTESTATION_VERSION`. */
export const ATTESTATION_VERSION = '0.1.0';

/**
 * The three validity_temporal modes, mirroring Python `VALIDITY_TEMPORAL_MODES`.
 * Distinct from the mandate-layer `ValidityWindow` (sequence/windowed/state_bound);
 * these are the WP3 attestation-level temporal modes.
 */
export const VALIDITY_TEMPORAL_MODES = ['absolute', 'relative', 'window'] as const;

/** Error raised when an attestation cannot be generated or its inputs are invalid. */
export class AttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AttestationError';
  }
}

/**
 * Parse an ISO 8601 UTC timestamp string, mirroring Python `_parse_iso8601`.
 *
 * Returns the parsed instant as epoch milliseconds (a number is sufficient for
 * the ordering / span comparisons the validators perform; we never re-emit it).
 * Parity contract:
 * - A non-string input raises {@link AttestationError} with Python's
 *   `<field_name> must be an ISO 8601 string`.
 * - A trailing `Z` is accepted (Python replaces it with `+00:00`).
 * - A value that does not parse raises
 *   `<field_name> is not a valid ISO 8601 timestamp: <detail>`. The `<detail>`
 *   half is the underlying parser's message and is NOT asserted for byte-parity
 *   (CPython's `datetime.fromisoformat` and our port produce different detail
 *   text); the prefix up to and including the colon is the stable, asserted part.
 * - A timestamp with no timezone offset is treated as UTC (Python's
 *   `tzinfo is None -> replace(tzinfo=utc)`), so naive and `Z`-suffixed forms of
 *   the same wall-clock instant compare equal.
 *
 * FAIL-CLOSED PARSE (Python parity, not lenient `Date.parse`). The prior
 * implementation normalized a naive form to UTC and then handed the string to
 * JS `Date.parse`. `Date.parse` is FAR more permissive than Python's
 * `datetime.fromisoformat`: it accepts RFC-822 / RFC-1123 forms like
 * `"Mon, 01 Jun 2026 00:00:00 GMT"`, `"June 1, 2026"`, and `"2026/06/01"`, all
 * of which `fromisoformat` REJECTS with a `ValueError`. That was a fail-OPEN: an
 * attestation carrying such a `validity_temporal` timestamp would be HONORED by
 * the TS SDK while the Python reference rejects it outright. We now delegate to
 * the shared CPython-3.12-`fromisoformat`-faithful parser
 * ({@link cpythonIsoDateTimeToEpochMs}, the same source of truth the schema
 * validator and approval-receipt verifier use), so anything Python's
 * `fromisoformat` rejects is rejected here too, while every valid ISO-8601
 * spelling (extended/basic, `Z` / `±HH:MM` / `±HHMM` / `±HH` offsets, comma or
 * dot fractional seconds, naive-is-UTC) still parses to the identical instant.
 */
function parseIso8601(ts: unknown, fieldName: string): number {
  if (typeof ts !== 'string') {
    throw new AttestationError(`${fieldName} must be an ISO 8601 string`);
  }
  // Python `_parse_iso8601`: `ts.replace("Z", "+00:00") if ts.endswith("Z")
  // else ts`, then `datetime.fromisoformat(...)`, then naive -> UTC. The shared
  // strict parser does the `Z -> +00:00` substitution internally and interprets
  // a naive value as UTC, so passing the raw string reproduces Python exactly --
  // and, unlike `Date.parse`, it REJECTS any form `fromisoformat` rejects
  // (RFC-822 / RFC-1123 / locale date spellings), closing the fail-open.
  const ms = cpythonIsoDateTimeToEpochMs(ts);
  if (ms === null) {
    throw new AttestationError(
      `${fieldName} is not a valid ISO 8601 timestamp: invalid isoformat string: ${jsRepr(ts)}`,
    );
  }
  return ms;
}

/** A minimal Python-flavored repr of a string for the parse-error detail. */
function jsRepr(value: string): string {
  return `'${value}'`;
}

/**
 * Python's `type(value).__name__`, for the diagnostic text in the parity-strict
 * reject paths (`int() argument must be ... not '<pytype>'`, `object of type
 * '<pytype>' has no len()`, `'<pytype>' object is not iterable`).
 *
 * Maps the JSON-representable values these paths can carry to CPython's type
 * name: `None`/missing -> `NoneType`, booleans -> `bool` (BEFORE number, since a
 * JS boolean's `typeof` is its own type), integers -> `int`, non-integers ->
 * `float`, strings -> `str`, arrays -> `list`, plain objects -> `dict`. A
 * non-JSON exotic (function, `Date`, `Map`, class instance) returns its JS type
 * name rather than mislabeling it.
 */
function pyTypeName(value: unknown): string {
  if (value === null || value === undefined) return 'NoneType';
  if (typeof value === 'boolean') return 'bool';
  if (typeof value === 'number') return Number.isInteger(value) ? 'int' : 'float';
  if (typeof value === 'string') return 'str';
  if (typeof value === 'function') return 'function';
  if (Array.isArray(value)) return 'list';
  if (isPlainObject(value)) return 'dict';
  return typeof value;
}

/** A normalized validity_temporal tagged union (the three WP3 modes). */
export type ValidityTemporal =
  | { mode: 'absolute'; from: string; until: string }
  | { mode: 'relative'; from: string; duration_seconds: number }
  | { mode: 'window'; start: string; end: string; duration_seconds: number };

/**
 * Strict plain-object test mirroring Python's `isinstance(x, dict)`. A loose
 * `typeof === 'object'` check fails open (it accepts a `Date`, `Map`, or class
 * instance); Python rejects those. A plain object is one whose prototype is
 * `Object.prototype` (a `{...}` literal or `JSON.parse` output) or `null`.
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Python's `isinstance(x, int)` semantics for the `duration_seconds` field.
 *
 * Python requires a true `int` (NOT a float): `isinstance(duration, int)`. A
 * Python `bool` is an `int` subclass, so `True`/`False` would pass the isinstance
 * gate, but then fail the `< 1` magnitude check unless it is `True` (== 1).
 * Mirror this exactly: a JS number that is an integer (and not NaN/Infinity)
 * counts; a JS boolean counts as 1/0 (Python `bool` -> int); everything else
 * (a float with a fractional part, a string, null, object) does NOT.
 */
function pyIntValue(value: unknown): number | null {
  if (typeof value === 'boolean') return value ? 1 : 0;
  if (typeof value === 'number') {
    return Number.isInteger(value) ? value : null;
  }
  return null;
}

/**
 * Python truthiness for the values these attestation code paths can encounter.
 *
 * Mirrors CPython `bool(x)`: `None`/`undefined`, `False`, `0`, `0.0`, `NaN`-free
 * zero, `""`, an empty list `[]`, and an empty dict `{}` are FALSY; everything
 * else is truthy. JS-specific note: a `number` `0` (and `-0`) is falsy and `NaN`
 * is falsy in JS too, but Python has no `NaN` literal in this position; we follow
 * JS here since `NaN` cannot arise from a JSON-parsed value. Arrays use length;
 * plain objects use key count (Python `len(dict) == 0` is falsy).
 */
function pyTruthy(value: unknown): boolean {
  if (value === null || value === undefined || value === false) return false;
  if (typeof value === 'number') return value !== 0 && !Number.isNaN(value);
  if (typeof value === 'string') return value.length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (isPlainObject(value)) return Object.keys(value).length > 0;
  return true;
}

/**
 * Replicate Python's `int(value)` coercion used by `is_valid_now` on
 * `duration_seconds` (a hand-built attestation can carry a non-int here because
 * `is_valid_now` does NOT re-run `_validate_validity_temporal`). Parity with
 * CPython `int(...)`:
 * - A `bool` -> `1`/`0` (Python `bool` is an `int` subclass).
 * - A finite `number` -> truncated TOWARD ZERO (`int(2.9) == 2`,
 *   `int(-2.9) == -2`). A non-finite number (`Infinity`/`NaN`) raises (Python
 *   `int(float('inf'))` -> `OverflowError`; `int(float('nan'))` -> `ValueError`).
 * - A `string` -> parsed as a base-10 integer with surrounding ASCII whitespace
 *   stripped and an optional leading `+`/`-`. A float-formatted string
 *   (`"1.5"`), a hex string (`"0x10"`), or any non-integer literal raises
 *   `ValueError: invalid literal for int() with base 10: '<repr>'`.
 * - Anything else (`null`/`undefined`, object, array) raises
 *   `TypeError: int() argument must be a string, a bytes-like object or a real
 *   number, not '<pytype>'`.
 *
 * Throws {@link AttestationError} carrying Python's exact error text on any
 * non-coercible input, so a malformed `duration_seconds` is REJECTED exactly
 * where Python's `int(...)` would raise -- never silently coerced (the prior
 * `Number(...)` accepted `"1.5"` -> `1.5` and `NaN` where Python raises).
 */
function pyIntCoerce(value: unknown): number {
  if (typeof value === 'boolean') return value ? 1 : 0;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      // int(inf) -> OverflowError; int(nan) -> ValueError. We surface a single
      // reject; the exact Python class differs but both are rejections.
      throw new AttestationError(
        Number.isNaN(value)
          ? 'cannot convert float NaN to integer'
          : 'cannot convert float infinity to integer',
      );
    }
    return Math.trunc(value);
  }
  if (typeof value === 'string') {
    // Python strips ASCII whitespace, then requires an optional sign + digits.
    const stripped = value.replace(/^[\s]+|[\s]+$/g, '');
    if (/^[+-]?\d+$/.test(stripped)) {
      return parseInt(stripped, 10);
    }
    throw new AttestationError(
      `invalid literal for int() with base 10: ${jsRepr(value)}`,
    );
  }
  throw new AttestationError(
    `int() argument must be a string, a bytes-like object or a real number, ` +
      `not '${pyTypeName(value)}'`,
  );
}

/**
 * Replicate Python's `len(value)`, gated by Python truthiness, for the
 * `terms_count` computation (`if session.terms: terms_count = len(session.terms)`).
 *
 * A malformed `terms` value reaches here via the OPEN message body
 * (`session.terms` is `body.get("terms")`, unvalidated). Python's behavior:
 * - A FALSY value (`None`/`undefined`, `{}`, `[]`, `""`, `0`, `False`) -> the
 *   `if session.terms:` guard is false, so `terms_count` stays `0`.
 * - A TRUTHY sized value -> its `len()`: a dict's key count, a list's element
 *   count, a string's char count.
 * - A TRUTHY NON-sized value (`int`, `float`, `bool`) -> Python raises
 *   `TypeError: object of type '<pytype>' has no len()`. The prior
 *   `Object.keys(session.terms).length` silently returned `0` for these,
 *   over-accepting where Python rejects.
 *
 * Returns the count (0 when falsy). Throws {@link AttestationError} carrying
 * Python's exact `TypeError` text for a truthy non-sized value.
 */
function pyTermsCount(value: unknown): number {
  if (!pyTruthy(value)) return 0;
  if (typeof value === 'string') return value.length;
  if (Array.isArray(value)) return value.length;
  if (isPlainObject(value)) return Object.keys(value).length;
  // Truthy but non-sized (number/boolean/exotic): Python's len() raises.
  throw new AttestationError(
    `object of type '${pyTypeName(value)}' has no len()`,
  );
}

/**
 * Normalize the `references` argument with Python-identical strictness,
 * mirroring `generate_attestation`'s `if references: [_validate_reference(ref, i)
 * for i, ref in enumerate(references)] else []`.
 *
 * - A FALSY `references` (`null`/`undefined`, `[]`, `{}`, `""`, `0`, `false`) ->
 *   `[]` (Python's `if references:` is false). NOTE an empty object `{}` is
 *   falsy in BOTH languages, so it yields `[]` -- only a NON-empty non-array is
 *   rejected.
 * - A TRUTHY ARRAY -> each element validated via {@link validateReference}
 *   (which raises {@link ReferenceValidationError} with Python's exact text).
 * - A TRUTHY ITERABLE non-array that Python iterates as strings (a plain object
 *   iterates its KEYS; a string iterates its CHARS) -> the first element is a
 *   string, so {@link validateReference} raises
 *   `references[0] must be a dict, got str per SPEC §11.5.6`, exactly as Python.
 * - A TRUTHY NON-iterable (`number`, `boolean`) -> Python's `enumerate(...)`
 *   raises `TypeError: '<pytype>' object is not iterable`; we throw
 *   {@link AttestationError} with that exact text.
 *
 * The prior `references && references.length > 0 ? ... : []` silently treated a
 * truthy non-array (e.g. `{"a":1}`) as `[]`, over-accepting where Python raises.
 */
function normalizeReferences(
  references: unknown,
): Array<Record<string, unknown>> {
  if (!pyTruthy(references)) {
    return [];
  }
  // Determine the Python iteration order of "elements" the comprehension sees.
  let elements: unknown[];
  if (Array.isArray(references)) {
    elements = references;
  } else if (typeof references === 'string') {
    // Python iterates a string by characters.
    elements = Array.from(references);
  } else if (isPlainObject(references)) {
    // Python iterates a dict by KEYS (strings).
    elements = Object.keys(references);
  } else {
    // number, boolean, or any non-iterable: Python's enumerate(...) raises.
    throw new AttestationError(
      `'${pyTypeName(references)}' object is not iterable`,
    );
  }
  return elements.map((ref, i) => validateReference(ref, i));
}

/**
 * Validate a validity_temporal tagged union, mirroring Python
 * `_validate_validity_temporal`. Returns the normalized object (exactly the
 * keys Python rebuilds, in Python's insertion order). Throws
 * {@link AttestationError} with Python-identical text on any violation.
 */
export function validateValidityTemporal(vt: unknown): ValidityTemporal {
  if (!isPlainObject(vt)) {
    throw new AttestationError('validity_temporal must be a dict');
  }
  const mode = vt.mode;
  if (mode !== 'absolute' && mode !== 'relative' && mode !== 'window') {
    throw new AttestationError(
      `validity_temporal.mode ${pyReprValue(mode)} not in ` +
        `('absolute', 'relative', 'window')`,
    );
  }

  if (mode === 'absolute') {
    const missing = ['from', 'until'].filter((k) => !(k in vt));
    if (missing.length > 0) {
      throw new AttestationError(
        `validity_temporal[absolute] missing: ${pyListRepr(missing)}`,
      );
    }
    const frm = parseIso8601(vt.from, 'validity_temporal.from');
    const until = parseIso8601(vt.until, 'validity_temporal.until');
    if (until <= frm) {
      throw new AttestationError(
        'validity_temporal[absolute]: until must be after from',
      );
    }
    return { mode: 'absolute', from: vt.from as string, until: vt.until as string };
  }

  if (mode === 'relative') {
    const missing = ['from', 'duration_seconds'].filter((k) => !(k in vt));
    if (missing.length > 0) {
      throw new AttestationError(
        `validity_temporal[relative] missing: ${pyListRepr(missing)}`,
      );
    }
    parseIso8601(vt.from, 'validity_temporal.from');
    const duration = pyIntValue(vt.duration_seconds);
    if (duration === null || duration < 1) {
      throw new AttestationError(
        'validity_temporal[relative].duration_seconds must be a positive int',
      );
    }
    return {
      mode: 'relative',
      from: vt.from as string,
      duration_seconds: duration,
    };
  }

  // window
  const missing = ['start', 'end', 'duration_seconds'].filter((k) => !(k in vt));
  if (missing.length > 0) {
    throw new AttestationError(
      `validity_temporal[window] missing: ${pyListRepr(missing)}`,
    );
  }
  const start = parseIso8601(vt.start, 'validity_temporal.start');
  const end = parseIso8601(vt.end, 'validity_temporal.end');
  if (end <= start) {
    throw new AttestationError(
      'validity_temporal[window]: end must be after start',
    );
  }
  const duration = pyIntValue(vt.duration_seconds);
  if (duration === null || duration < 1) {
    throw new AttestationError(
      'validity_temporal[window].duration_seconds must be a positive int',
    );
  }
  // Python compares `duration_seconds` against `(end - start).total_seconds()`,
  // which carries MICROSECOND precision (a Python `datetime`'s resolution). The
  // ms-floored `start`/`end` above are correct for the ordering check, but using
  // them for the SPAN floors a sub-millisecond fractional second down to the whole
  // ms -- INFLATING the apparent span to the next ms and ACCEPTING a window Python
  // REJECTS (fail-OPEN; e.g. start=...00.000999Z / end=...01.000000Z is a
  // 0.999001s span that floors to a flat 1.000s, so duration_seconds=1 wrongly
  // passes `1 > 1.0`, while Python's `1 > 0.999001` rejects). Recompute the span
  // at EXACT microsecond precision (bigint, exact across the full year 1..9999
  // datetime range) so the comparison is byte-identical to Python's
  // `total_seconds()`. Using bigint -- rather than a number with a safe-integer
  // fallback to the coarse-ms span -- is deliberate: that fallback would reopen
  // this same fail-open for valid far-future windows (> ~year 2255). `vt.start`/
  // `vt.end` are strings here (`parseIso8601` above already rejected a non-string
  // or unparseable value), so the micros parse cannot be null; treat null
  // defensively as fail-closed rather than falling back to a coarser span.
  const startMicros = cpythonIsoDateTimeToEpochMicros(vt.start as string);
  const endMicros = cpythonIsoDateTimeToEpochMicros(vt.end as string);
  if (startMicros === null || endMicros === null) {
    throw new AttestationError(
      'validity_temporal[window] start/end not parseable at microsecond precision',
    );
  }
  // Compare at EXACT integer-microsecond precision: `duration_seconds > span`
  // is equivalent to `duration_seconds * 1_000_000 (micros) > (end - start)
  // micros`, an all-bigint comparison with NO floating point. This is the
  // ground-truth rational comparison, so no rounding can let a sub-span window
  // through at ANY datetime range. (Narrowing the bigint delta to a Number and
  // dividing -- as an earlier draft did -- rounds the delta to a double BEFORE
  // dividing for spans beyond ~285 years, which diverges from Python and reopened
  // the fail-open for a near-full-range window.) The only residual vs Python's
  // lossy float `total_seconds()` is at extreme (>285-year) spans and is in the
  // over-STRICT (fail-closed, safe) direction -- the same residual class the ms
  // ordering check above already carries. `duration` is a validated positive int.
  if (BigInt(duration) * 1_000_000n > endMicros - startMicros) {
    throw new AttestationError(
      'validity_temporal[window].duration_seconds exceeds the window span',
    );
  }
  return {
    mode: 'window',
    start: vt.start as string,
    end: vt.end as string,
    duration_seconds: duration,
  };
}

/**
 * Return `true` if the attestation's `validity_temporal` contains `now`,
 * mirroring Python `is_valid_now`.
 *
 * - No `validity_temporal` field -> `true` (no temporal constraint).
 * - A `validity_temporal` that is not a dict, or a dict missing `mode` -> `false`.
 * - `absolute`: `from <= now < until`.
 * - `relative`: `from <= now < from + duration_seconds`.
 * - `window`: `start <= now < end` AND a `duration_seconds`-sized window anchored
 *   at `now` still fits before `end` (`end - now >= duration_seconds`).
 * - Any unknown mode -> `false`.
 *
 * @param attestation The attestation object (or any dict with an optional
 *   `validity_temporal`).
 * @param now Epoch milliseconds for "now". Defaults to `Date.now()`.
 */
export function isValidNow(
  attestation: Record<string, unknown>,
  now?: number,
): boolean {
  const vt = attestation.validity_temporal;
  if (vt === undefined || vt === null) {
    return true;
  }
  if (!isPlainObject(vt) || !('mode' in vt)) {
    return false;
  }
  const nowMs = now ?? Date.now();
  const mode = vt.mode;
  if (mode === 'absolute') {
    const frm = parseIso8601(vt.from, 'validity_temporal.from');
    const until = parseIso8601(vt.until, 'validity_temporal.until');
    return frm <= nowMs && nowMs < until;
  }
  if (mode === 'relative') {
    const frm = parseIso8601(vt.from, 'validity_temporal.from');
    // Python: `frm + timedelta(seconds=int(vt["duration_seconds"]))`. Use the
    // Python-`int()` coercion (truncate-toward-zero / reject non-int-coercible),
    // NOT the lenient `Number(...)` which accepted "1.5" and produced NaN.
    const until = frm + pyIntCoerce(vt.duration_seconds) * 1000;
    return frm <= nowMs && nowMs < until;
  }
  if (mode === 'window') {
    const start = parseIso8601(vt.start, 'validity_temporal.start');
    const end = parseIso8601(vt.end, 'validity_temporal.end');
    if (!(start <= nowMs && nowMs < end)) {
      return false;
    }
    // Python: `timedelta(seconds=int(vt["duration_seconds"]))`. Mirror Python's
    // `int()` coercion exactly (truncate / reject), not the lenient `Number()`.
    const durationMs = pyIntCoerce(vt.duration_seconds) * 1000;
    return end - nowMs >= durationMs;
  }
  return false;
}

/** Map a terminal session state to an outcome status, mirroring Python `_map_state_to_outcome`. */
function mapStateToOutcome(state: SessionState): OutcomeStatus {
  switch (state) {
    case SessionState.AGREED:
      return OutcomeStatus.AGREED;
    case SessionState.REJECTED:
      return OutcomeStatus.REJECTED;
    case SessionState.EXPIRED:
      return OutcomeStatus.EXPIRED;
    default:
      return OutcomeStatus.REJECTED;
  }
}

/** Options for {@link generateAttestation}, mirroring Python's keyword-only args. */
export interface GenerateAttestationOptions {
  /** Optional transaction category (e.g. 'electronics.cameras'). */
  category?: string | null;
  /** Optional value bucket (e.g. '1000-5000_USD'). */
  valueRange?: string | null;
  /** How agreement was reached. Defaults to {@link ResolutionMechanism.DIRECT}. */
  resolutionMechanism?: ResolutionMechanism;
  /** Optional attestation-level references per SPEC §11.5. */
  references?: Array<Record<string, unknown>> | null;
  /** Optional temporal validity window (three-mode tagged union). */
  validityTemporal?: Record<string, unknown> | null;
  /**
   * Override for the random `attestation_id` suffix. Defaults to a fresh random
   * 8-hex string (Python `uuid.uuid4().hex[:8]`). Injectable for deterministic
   * tests; not part of the signed per-party bytes.
   */
  attestationId?: string;
  /**
   * Override for the attestation `timestamp` (an ISO 8601 `...Z` string).
   * Defaults to the current time formatted like Python's
   * `strftime("%Y-%m-%dT%H:%M:%SZ")`. Injectable for deterministic tests; not
   * part of the signed per-party bytes.
   */
  timestamp?: string;
}

/**
 * Generate a reputation attestation from a concluded session. Port of Python
 * `generate_attestation`.
 *
 * @param session The concluded {@link Session}.
 * @param keyPairs Mapping of `agentId -> KeyPair` for signing each party's
 *   behavioral record. An agent absent from the map gets an empty-string
 *   signature, matching Python.
 * @param options Optional category / value_range / resolution_mechanism /
 *   references / validity_temporal, plus test-only `attestationId` / `timestamp`
 *   overrides for the non-deterministic header fields.
 * @returns The attestation object (§9.6.2).
 * @throws {AttestationError} if the session is not terminal and not EXPIRED.
 */
export function generateAttestation(
  session: Session,
  keyPairs: Record<string, KeyPair>,
  options: GenerateAttestationOptions = {},
): Record<string, unknown> {
  const {
    category = null,
    valueRange = null,
    resolutionMechanism = ResolutionMechanism.DIRECT,
    references = null,
    validityTemporal = null,
  } = options;

  if (!session.isTerminal && session.state !== SessionState.EXPIRED) {
    throw new AttestationError(
      `Cannot generate attestation for session in state ${session.state}`,
    );
  }

  const outcomeStatus = mapStateToOutcome(session.state);

  // Count terms from the open message body, if available. PRIVACY: only the
  // COUNT is taken; the term values themselves never enter the attestation.
  // Python: `if session.terms: terms_count = len(session.terms)`. `pyTermsCount`
  // mirrors Python's truthiness gate + `len()` exactly: a truthy non-sized value
  // (int/float/bool) REJECTS (Python `TypeError`), where the prior
  // `Object.keys(...).length` silently returned 0.
  const termsCount = pyTermsCount(session.terms);

  // Build outcome (insertion order matches Python).
  const outcome: Record<string, unknown> = {
    status: outcomeStatus,
    rounds: session.roundCount,
    duration_seconds: session.durationSeconds(),
  };
  if (termsCount > 0) {
    outcome.terms_count = termsCount;
  }
  outcome.resolution_mechanism = resolutionMechanism;

  // Build party records with signatures (parties in registration order; the
  // Map preserves insertion order, matching Python's insertion-ordered dict).
  const parties: Array<Record<string, unknown>> = [];
  for (const [agentId, role] of session.parties) {
    const behavior = session.getBehavior(agentId);
    const partyRecord: Record<string, unknown> = {
      agent_id: agentId,
      role,
      behavior: behaviorRecordToDict(behavior),
    };
    // Sign the party's behavioral record. The record has no `signature` key yet,
    // so the signed bytes are `{agent_id, role, behavior}` -- identical to
    // Python (whose `sign_message` would strip `signature` anyway).
    const kp = keyPairs[agentId];
    if (kp !== undefined) {
      partyRecord.signature = sign(partyRecord, kp);
    } else {
      partyRecord.signature = '';
    }
    parties.push(partyRecord);
  }

  // Compute the whole-transcript hash (distinct from the per-message hash).
  const transcriptHash = computeTranscriptHash(session.transcript);

  // Build meta.
  const meta: Record<string, unknown> = {
    extensions_used: [],
    mediator_invoked: false,
  };
  if (category) {
    meta.category = category;
  }
  if (valueRange) {
    meta.value_range = valueRange;
  }

  // Validate + normalize references[] with Python-identical strictness. Python:
  // `if references: [_validate_reference(ref, i) for i, ref in enumerate(...)]`.
  // `normalizeReferences` mirrors the truthiness gate + enumerate iteration:
  // a truthy non-array (e.g. `{"a":1}`) is iterated as Python would and REJECTS,
  // where the prior `references && references.length > 0` silently yielded [].
  const normalizedRefs = normalizeReferences(references);

  // Validate validity_temporal if supplied.
  let normalizedVt: ValidityTemporal | null = null;
  if (validityTemporal !== null && validityTemporal !== undefined) {
    normalizedVt = validateValidityTemporal(validityTemporal);
  }

  const attestation: Record<string, unknown> = {
    concordia_attestation: ATTESTATION_VERSION,
    attestation_id:
      options.attestationId ?? `att_${randomHex8()}`,
    session_id: session.sessionId,
    timestamp: options.timestamp ?? nowIso8601(),
    outcome,
    parties,
    meta,
    transcript_hash: transcriptHash,
    fulfillment: null,
    references: normalizedRefs,
  };
  if (normalizedVt !== null) {
    attestation.validity_temporal = normalizedVt;
  }

  // Attach a plaintext 4-line summary for quick human/agent inspection.
  attestation.summary = generateReceiptSummary(attestation);

  return attestation;
}

/**
 * Generate a 4-line plaintext summary of a receipt/attestation. Port of Python
 * `generate_receipt_summary`.
 *
 * Format:
 * ```
 * Parties: <party_a_did_short>, <party_b_did_short>
 * Topic: <topic or N/A>
 * Outcome: <AGREED/REJECTED/EXPIRED>
 * Transcript hash: <first 16 chars of hex digest>
 * ```
 *
 * Parity notes:
 * - `_short`: an empty DID renders `unknown`; a DID longer than 16 chars renders
 *   `...<last 12 chars>`; otherwise the whole DID. There are always at least two
 *   party slots (missing slots are empty strings -> `unknown`).
 * - Topic falls back `meta.category -> meta.topic -> "N/A"` using Python's `or`
 *   truthiness (an empty string falls through to the next).
 * - Outcome uppercases the status; an empty/missing status renders `UNKNOWN`.
 * - Transcript hash strips a leading `sha256:` (anything up to the FIRST `:`)
 *   and takes the first 16 chars of the remaining hex digest.
 */
export function generateReceiptSummary(receipt: Record<string, unknown>): string {
  const short = (did: string): string => {
    if (!did) return 'unknown';
    return did.length <= 16 ? did : `...${did.slice(-12)}`;
  };

  const partiesRaw = receipt.parties;
  const parties = Array.isArray(partiesRaw) ? partiesRaw : [];
  const partyIds: string[] = parties.map((p) => {
    if (isPlainObject(p)) {
      const id = p.agent_id;
      return typeof id === 'string' ? id : '';
    }
    return '';
  });
  while (partyIds.length < 2) {
    partyIds.push('');
  }
  const partiesLine = `Parties: ${short(partyIds[0] ?? '')}, ${short(partyIds[1] ?? '')}`;

  const meta = isPlainObject(receipt.meta) ? receipt.meta : {};
  const topic = pyOr(meta.category, pyOr(meta.topic, 'N/A'));
  const topicLine = `Topic: ${String(topic)}`;

  const outcome = isPlainObject(receipt.outcome) ? receipt.outcome : {};
  const status = outcome.status;
  const outcomeLine = `Outcome: ${status ? String(status).toUpperCase() : 'UNKNOWN'}`;

  const transcriptHashRaw = receipt.transcript_hash;
  const transcriptHash =
    typeof transcriptHashRaw === 'string' ? transcriptHashRaw : '';
  // Python: `transcript_hash.split(":", 1)[1] if ":" in transcript_hash else ...`
  const colonIdx = transcriptHash.indexOf(':');
  const digest =
    colonIdx >= 0 ? transcriptHash.slice(colonIdx + 1) : transcriptHash;
  const hashLine = `Transcript hash: ${digest.slice(0, 16)}`;

  return [partiesLine, topicLine, outcomeLine, hashLine].join('\n');
}

/**
 * Compute a single SHA-256 hash over the entire transcript. Port of Python
 * `_compute_transcript_hash`.
 *
 * This is DISTINCT from the per-message `computeHash`: it CONCATENATES the
 * canonical-JSON bytes of every message in order, then takes one SHA-256 over the
 * concatenation, returning `sha256:<hex>`. An empty transcript hashes the empty
 * byte string (Python's `combined = b""` start), so the result is well-defined.
 */
export function computeTranscriptHash(
  transcript: Array<Record<string, unknown>>,
): string {
  const parts: Buffer[] = [];
  for (const msg of transcript) {
    parts.push(canonicalizeJcs(msg));
  }
  const combined = Buffer.concat(parts);
  const digest = createHash('sha256').update(combined).digest('hex');
  return `sha256:${digest}`;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Python's `or`-chain truthiness for the topic fallback: returns `a` if it is
 * Python-truthy, else `b`. A Python-falsy value is: `None`/`undefined`, `false`,
 * `0`, `""`, `[]`, `{}`. We only ever feed strings (or the `"N/A"` literal)
 * here, but model the general rule so an empty string falls through.
 */
function pyOr(a: unknown, b: unknown): unknown {
  return isPyTruthy(a) ? a : b;
}

/** Python truthiness for the values topic-resolution can encounter. */
function isPyTruthy(value: unknown): boolean {
  if (value === null || value === undefined || value === false) return false;
  if (value === 0 || value === '') return false;
  if (typeof value === 'number' && Number.isNaN(value)) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (isPlainObject(value)) return Object.keys(value).length > 0;
  return true;
}

/**
 * A small Python-`repr`-flavored renderer for the `validity_temporal.mode` and
 * missing-key diagnostics. `None`/`undefined` -> `None`; a string -> single-quoted;
 * a boolean -> `True`/`False`; a number -> its decimal form; everything else ->
 * `JSON.stringify`. The mode value reaching here is whatever the caller passed,
 * so it can be any JSON value; the asserted cases are strings and `None`.
 */
function pyReprValue(value: unknown): string {
  if (value === null || value === undefined) return 'None';
  if (typeof value === 'string') return `'${value}'`;
  if (typeof value === 'boolean') return value ? 'True' : 'False';
  if (typeof value === 'number') return String(value);
  return JSON.stringify(value);
}

/** Render a list of string keys as Python's list repr: `['a', 'b']`. */
function pyListRepr(keys: string[]): string {
  return `[${keys.map((k) => `'${k}'`).join(', ')}]`;
}

/**
 * Eight lowercase hex chars, matching Python `uuid.uuid4().hex[:8]`.
 *
 * Backed by the platform CSPRNG (`crypto.randomUUID`, a global in Node >= 20 —
 * the SDK's engine floor — and a Web standard) rather than `Math.random()`,
 * which is not cryptographically random and only 32-bit. The first group of a
 * v4 UUID is eight lowercase hex chars.
 */
function randomHex8(): string {
  return crypto.randomUUID().slice(0, 8);
}

/**
 * Format the current instant like Python's
 * `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")`: a second-precision
 * UTC ISO 8601 string with a trailing `Z` (no fractional seconds).
 */
function nowIso8601(): string {
  const d = new Date();
  const pad = (n: number, w = 2): string => String(n).padStart(w, '0');
  return (
    `${pad(d.getUTCFullYear(), 4)}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}` +
    `T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}Z`
  );
}
