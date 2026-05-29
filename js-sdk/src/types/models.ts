/**
 * Core data structures for the Concordia Protocol.
 *
 * Port of the dataclasses in the Python reference (`concordia/types.py`).
 * Cross-language parity is the load-bearing property: where a Python
 * dataclass exposes a `to_dict()` method whose output crosses the wire (and
 * is therefore canonicalized / signed), the matching `*ToDict` function here
 * MUST produce a structurally identical object — same field names, same
 * presence/absence rules, same numeric values. The remaining dataclasses are
 * plain data carriers with no custom serialization in Python; they are
 * modeled as TypeScript interfaces (with factory helpers that supply the same
 * defaults Python's dataclass fields declare).
 */

import {
  type TermType,
  type Flexibility,
} from './enums.js';

/**
 * Decompose a finite IEEE-754 double into the exact rational `p / q` it
 * represents (`q` a power of two, both `BigInt`). No precision is lost: the
 * returned fraction is the true value of the binary float, not a decimal
 * approximation of it.
 */
function exactBinaryFraction(value: number): { p: bigint; q: bigint } {
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, value);
  const bits = view.getBigUint64(0);
  const sign = (bits >> 63n) & 1n;
  const exponent = Number((bits >> 52n) & 0x7ffn);
  const mantissa = bits & 0xfffffffffffffn;

  // value = significand * 2^scale
  let significand: bigint;
  let scale: number;
  if (exponent === 0) {
    // Subnormal: no implicit leading bit.
    significand = mantissa;
    scale = -1074;
  } else {
    // Normal: restore the implicit leading 1.
    significand = mantissa | 0x10000000000000n;
    scale = exponent - 1075;
  }
  if (sign) significand = -significand;

  if (scale >= 0) return { p: significand << BigInt(scale), q: 1n };
  return { p: significand, q: 1n << BigInt(-scale) };
}

/**
 * Round a number to `ndigits` decimal places with results bit-identical to
 * Python 3's built-in `round(value, ndigits)`.
 *
 * Parity contract: CPython's `round` does NOT round the decimal string of the
 * value. It rounds the underlying IEEE-754 double to the nearest value with
 * `ndigits` decimal places using round-half-to-EVEN (banker's rounding) on the
 * exact binary value, then returns the double nearest that decimal. V8's
 * `Number.prototype.toFixed` rounds half-AWAY-from-zero, so the prior
 * `parseFloat(value.toFixed(n))` diverged on every exact binary half-tie
 * (e.g. 0.125 -> Python 0.12, toFixed 0.13). This matters because
 * `BehaviorRecord.to_dict()` rounds `concession_magnitude` (4 places) and
 * `response_time_avg_seconds` (2 places), and those values cross the wire and
 * are canonicalized + signed; a single divergent rounding breaks cross-language
 * signature parity.
 *
 * Algorithm: take the exact binary value `p / q`, scale by `10^ndigits` to the
 * exact rational `(p * 10^n) / q`, round that to the nearest integer with ties
 * to even via integer (`BigInt`) arithmetic, then express the result
 * `rounded / 10^ndigits` as its EXACT decimal string and hand it to `Number()`.
 * JS string->number conversion is correctly rounded (IEEE round-to-nearest-even
 * over the full decimal value), so it yields the same double CPython returns,
 * and -- unlike `Number(rounded) / Number(10n ** BigInt(|ndigits|))` -- it never
 * overflows to `Infinity` for large `|ndigits|` (e.g. `round(1.2345, 400)`),
 * which would have produced `NaN`. This equivalence is verified across the
 * random, adversarial near-tie, and large-`|ndigits|` vectors generated FROM
 * Python in `tests/fixtures/types/types_vectors.json` (`round_parity` block);
 * any divergence fails the test suite rather than silently shipping a parity
 * bug.
 */
export function pyRound(value: number, ndigits: number): number {
  if (!Number.isFinite(value)) return value;
  if (value === 0) return value; // preserves signed zero, matches Python

  const { p, q } = exactBinaryFraction(value);
  const pow = 10n ** BigInt(Math.abs(ndigits));

  // Express value * 10^ndigits as the exact rational scaledNum / scaledDen.
  let scaledNum: bigint;
  let scaledDen: bigint;
  if (ndigits >= 0) {
    scaledNum = p * pow;
    scaledDen = q;
  } else {
    scaledNum = p;
    scaledDen = q * pow;
  }

  // Round scaledNum / scaledDen to the nearest integer, ties to even.
  const negative = scaledNum < 0n;
  const absNum = negative ? -scaledNum : scaledNum;
  let quotient = absNum / scaledDen;
  const remainderTwice = (absNum - quotient * scaledDen) * 2n;
  if (remainderTwice > scaledDen) {
    quotient += 1n;
  } else if (remainderTwice === scaledDen) {
    // Exact half: round to even.
    if (quotient % 2n === 1n) quotient += 1n;
  }
  const rounded = negative ? -quotient : quotient;

  // Build the EXACT decimal string for `rounded / 10^ndigits`, then let
  // `Number()` do the (correctly-rounded) decimal->double conversion. This
  // avoids ever materializing `10^|ndigits|` as a Number, which overflows to
  // Infinity for |ndigits| >= 309 and yields NaN. The string carries the full
  // value, so huge exponents collapse to the same double CPython's round()
  // returns (e.g. round(1.2345, 400) -> 1.2345, round(1.23, 309) -> 1.23).
  let result = Number(decimalString(quotient, ndigits));
  if (negative) result = -result;
  // CPython preserves the sign of zero (round(-0.0001, 2) -> -0.0,
  // round(-1.23, -400) -> -0.0). A zero magnitude loses its sign through the
  // string/Number path, so restore it from the input.
  if (result === 0 && value < 0) result = -0;
  return result;
}

/**
 * Render the non-negative integer `absQuotient` divided by `10^ndigits` as its
 * exact decimal string (no sign; the caller applies it).
 *
 * - `ndigits > 0`: place a decimal point `ndigits` digits from the right of the
 *   integer, zero-padding the integer part to at least one leading digit and
 *   the fractional part to `ndigits` digits (e.g. quotient `12345`, ndigits 4
 *   -> `"1.2345"`; quotient `5`, ndigits 4 -> `"0.0005"`).
 * - `ndigits <= 0`: the value is an integer; append `|ndigits|` trailing zeros
 *   (e.g. quotient `12`, ndigits -2 -> `"1200"`; quotient `0` -> `"0"`).
 *
 * The output is always a finite decimal literal `Number()` parses exactly.
 */
function decimalString(absQuotient: bigint, ndigits: number): string {
  const digits = absQuotient.toString(); // non-negative, no sign
  if (ndigits <= 0) {
    if (absQuotient === 0n) return '0';
    return digits + '0'.repeat(-ndigits);
  }
  if (digits.length <= ndigits) {
    // Pure fraction: pad to `ndigits` places behind "0.".
    return '0.' + digits.padStart(ndigits, '0');
  }
  const cut = digits.length - ndigits;
  return digits.slice(0, cut) + '.' + digits.slice(cut);
}

// ---------------------------------------------------------------------------
// §3.1  Term
// ---------------------------------------------------------------------------

/** A single dimension of a deal -- one thing being negotiated (SPEC §3.1). */
export interface Term {
  id: string;
  type: TermType;
  label: string;
  /** Optional unit of measure (e.g. "USD", "days"). Python default: `None`. */
  unit?: string | null;
  /** Optional constraint object. Python default: `None`. */
  constraints?: Record<string, unknown> | null;
}

// ---------------------------------------------------------------------------
// §3.4  Preference signal
// ---------------------------------------------------------------------------

/** Voluntary preference information shared by an agent (SPEC §3.4). */
export interface PreferenceSignal {
  /** Python default: `None`. */
  priorityRanking?: string[] | null;
  /** Per-term flexibility levels. Python default: `None`. */
  flexibility?: Record<string, Flexibility> | null;
  /** Aspiration values per term. Python default: `None`. */
  aspiration?: Record<string, unknown> | null;
  /** Reservation (walk-away) values per term. Python default: `None`. */
  reservation?: Record<string, unknown> | null;
}

// ---------------------------------------------------------------------------
// §4.1  Sender / recipient identities
// ---------------------------------------------------------------------------

/** An agent's identity in a Concordia message (SPEC §4.1). */
export interface AgentIdentity {
  agentId: string;
  /** Optional principal on whose behalf the agent acts. Python default: `None`. */
  principalId?: string | null;
}

/**
 * Serialize an {@link AgentIdentity} to its wire form.
 *
 * Parity with Python `AgentIdentity.to_dict()`: the `principal_id` key is
 * present only when a non-null principal is set (Python checks
 * `if self.principal_id is not None`). The wire key names are snake_case
 * (`agent_id`, `principal_id`) to match the Python serialization exactly.
 */
export function agentIdentityToDict(
  identity: AgentIdentity,
): Record<string, unknown> {
  const d: Record<string, unknown> = { agent_id: identity.agentId };
  if (identity.principalId !== undefined && identity.principalId !== null) {
    d.principal_id = identity.principalId;
  }
  return d;
}

// ---------------------------------------------------------------------------
// §5.3  Timing configuration
// ---------------------------------------------------------------------------

/** Timing parameters for a negotiation session (SPEC §5.3). */
export interface TimingConfig {
  /** Session time-to-live in seconds. Python default: 86400 (24 hours). */
  sessionTtl: number;
  /** Offer time-to-live in seconds. Python default: 3600 (1 hour). */
  offerTtl: number;
  /** Maximum negotiation rounds. Python default: 20. */
  maxRounds: number;
}

/**
 * Construct a {@link TimingConfig} with the same field defaults the Python
 * `TimingConfig` dataclass declares (`session_ttl=86400`, `offer_ttl=3600`,
 * `max_rounds=20`).
 */
export function makeTimingConfig(
  overrides: Partial<TimingConfig> = {},
): TimingConfig {
  return {
    sessionTtl: 86400,
    offerTtl: 3600,
    maxRounds: 20,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// §9.6.2  Behavior record
// ---------------------------------------------------------------------------

/** Quantified behavioral signals derived from the transcript (SPEC §9.6.2). */
export interface BehaviorRecord {
  /** Python default: 0. */
  offersMade: number;
  /** Python default: 0. */
  concessions: number;
  /** Python default: 0.0. */
  concessionMagnitude: number;
  /** Python default: 0. */
  signalsShared: number;
  /** Python default: 0. */
  constraintsDeclared: number;
  /** Python default: 0. */
  constraintsViolated: number;
  /** Python default: false. */
  reasoningProvided: boolean;
  /** Python default: false. */
  withdrawal: boolean;
  /** Python default: 0.0. */
  responseTimeAvgSeconds: number;
}

/**
 * Construct a {@link BehaviorRecord} with the same field defaults the Python
 * `BehaviorRecord` dataclass declares (all counters 0, magnitudes 0.0, flags
 * false).
 */
export function makeBehaviorRecord(
  overrides: Partial<BehaviorRecord> = {},
): BehaviorRecord {
  return {
    offersMade: 0,
    concessions: 0,
    concessionMagnitude: 0.0,
    signalsShared: 0,
    constraintsDeclared: 0,
    constraintsViolated: 0,
    reasoningProvided: false,
    withdrawal: false,
    responseTimeAvgSeconds: 0.0,
    ...overrides,
  };
}

/**
 * Serialize a {@link BehaviorRecord} to its wire form.
 *
 * Parity with Python `BehaviorRecord.to_dict()`:
 * - Wire keys are snake_case, in the exact order the Python method emits them.
 * - `concession_magnitude` is rounded to 4 decimal places and
 *   `response_time_avg_seconds` to 2, using {@link pyRound} so the rounded
 *   values are bit-identical to Python's `round(..., 4)` / `round(..., 2)`.
 *   (Canonical JSON sorts keys, so wire order does not affect signature bytes,
 *   but matching insertion order keeps `to_dict()` output structurally
 *   identical for direct object comparison in the parity tests.)
 */
export function behaviorRecordToDict(
  record: BehaviorRecord,
): Record<string, unknown> {
  return {
    offers_made: record.offersMade,
    concessions: record.concessions,
    concession_magnitude: pyRound(record.concessionMagnitude, 4),
    signals_shared: record.signalsShared,
    constraints_declared: record.constraintsDeclared,
    constraints_violated: record.constraintsViolated,
    reasoning_provided: record.reasoningProvided,
    withdrawal: record.withdrawal,
    response_time_avg_seconds: pyRound(record.responseTimeAvgSeconds, 2),
  };
}
