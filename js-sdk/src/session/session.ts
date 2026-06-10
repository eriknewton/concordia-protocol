/**
 * Negotiation session and state machine (SPEC §5).
 *
 * Port of `concordia/session.py` — the six-state lifecycle
 *   PROPOSED -> ACTIVE -> AGREED / REJECTED / EXPIRED -> DORMANT
 * enforced by the strict transition table from §5.2, with hash-chained
 * transcript tracking (§9.3) and behavioral-signal accumulation (§5.4, §9.6).
 *
 * Cross-language parity is the load-bearing property:
 * - The transition table is keyed by `(fromState, messageType)` exactly as the
 *   Python `_TRANSITIONS` dict; the SAME set of pairs are legal and every legal
 *   pair maps to the SAME target state. An illegal pair raises
 *   {@link InvalidTransitionError} with Python-identical message text.
 * - Signature verification follows the SEC-010 / SEC-005 contract: a mandatory
 *   resolver maps `agentId -> public key | null`; a missing `from.agent_id`, a
 *   missing `signature`, an unresolved identity, or a cryptographically invalid
 *   signature each raises {@link InvalidSignatureError} with Python-identical
 *   text. The resolver is called BEFORE the transition is validated (matching
 *   Python's ordering: signature first, transition second).
 * - `MessageType(message["type"])` parity: an unknown `type` value raises a
 *   {@link RangeError} carrying CPython's `ValueError` text
 *   (`<repr> is not a valid MessageType`) BEFORE the transition lookup, where
 *   `<repr>` is the value rendered by the shared CPython-`repr()` helper
 *   (`../internal/py-repr.js`) with full quote-selection + escaping (so a `type`
 *   containing a quote, e.g. `negotiate.o'ops`, renders `"negotiate.o'ops"`
 *   exactly as Python does); a missing `type` key throws the way Python's
 *   `message["type"]` `KeyError` does.
 * - `body` shape parity: the OPEN / OFFER / COUNTER handlers read
 *   `body.get(...)` the way Python does, so a present-but-non-mapping `body`
 *   (list / string / number / bool / `null`) is REJECTED with
 *   {@link InvalidMessageError} (Python raises `AttributeError`), an absent body
 *   uses the `{}` default, and a mapping body is used verbatim. Message types
 *   that never read `body` (e.g. SIGNAL) are unaffected by a non-mapping body.
 * - Behavioral tracking reproduces Python's accumulation arithmetic bit-for-bit:
 *   the running-average concession magnitude is computed with the same operation
 *   order over IEEE-754 doubles, and term values that are JS booleans are treated
 *   as numeric (`true`->1, `false`->0) because Python's
 *   `isinstance(v, (int, float))` is True for `bool` (a subclass of `int`).
 * - `durationSeconds()` mirrors `max(0, int((end - created).total_seconds()))`
 *   with truncation toward zero (Python `int()`), driven by an injectable clock
 *   so the wall-clock-dependent value is deterministic in tests.
 *
 * The raw (unrounded) `concessionMagnitude` accumulated here is what the
 * attestation layer later rounds to 4 places via `behaviorRecordToDict`; keeping
 * the raw accumulation parity-exact is therefore a prerequisite for downstream
 * attestation signature parity.
 */

import {
  MessageType,
  PartyRole,
  SessionState,
  makeBehaviorRecord,
  type BehaviorRecord,
} from '../types/index.js';
import { verify, KeyPair } from '../crypto/signing.js';
import { GENESIS_HASH, computeHash } from './message.js';
import { makeTimingConfig, type TimingConfig } from '../types/models.js';
import { pyRepr } from '../internal/py-repr.js';

/** Raised when a message would cause an illegal state transition. */
export class InvalidTransitionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidTransitionError';
  }
}

/** Raised when a message has an invalid, missing, or unverifiable signature. */
export class InvalidSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidSignatureError';
  }
}

/**
 * Raised when a message is structurally malformed in a way Python's reference
 * rejects by raising (rather than coercing). Specifically: a present-but-non-mapping
 * `body` on a message type whose handler reads `body.get(...)` (OPEN, OFFER,
 * COUNTER). Python does `message.get("body", {}).get(...)`, which raises
 * `AttributeError` when `body` is present and not a dict (a list, string, number,
 * bool, or `null`); this fail-closed error reproduces that REJECT decision. An
 * absent `body` is NOT an error (Python's `{}` default applies), and message
 * types that never read `body` (e.g. SIGNAL) are unaffected.
 */
export class InvalidMessageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidMessageError';
  }
}

/**
 * The set of valid `MessageType` *values*, used to reproduce Python's
 * `MessageType(value)` enum coercion: an unknown value raises a `ValueError`
 * with the text `'<value>' is not a valid MessageType`.
 */
const MESSAGE_TYPE_VALUES: ReadonlySet<string> = new Set(
  Object.values(MessageType),
);

/**
 * Coerce a raw `type` value into a {@link MessageType}, mirroring Python's
 * `MessageType(message["type"])`. Throws a `RangeError` whose message is
 * byte-identical to CPython's `ValueError` for an unknown value. The rendered
 * value uses the shared {@link pyRepr} helper (`../internal/py-repr.js`), which
 * reproduces CPython `repr()`'s quote-selection + escaping rules so a `type`
 * value containing quotes/control chars (e.g. `negotiate.o'ops`) renders exactly
 * as Python would (`"negotiate.o'ops"`). The helper is shared with the mandate
 * layer rather than duplicated.
 */
function coerceMessageType(value: unknown): MessageType {
  if (typeof value === 'string' && MESSAGE_TYPE_VALUES.has(value)) {
    return value as MessageType;
  }
  throw new RangeError(`${pyRepr(value)} is not a valid MessageType`);
}

// §5.2 — Transition table encoded as a map keyed by `${fromState}|${messageType}`
// -> toState. Transitions to the *same* state (e.g. ACTIVE -> ACTIVE) are listed
// explicitly, matching Python's `_TRANSITIONS` dict entries one-for-one.
function transitionKey(state: SessionState, msgType: MessageType): string {
  return `${state}|${msgType}`;
}

const TRANSITIONS: ReadonlyMap<string, SessionState> = new Map<
  string,
  SessionState
>([
  // The OPEN message creates the session in PROPOSED state
  [transitionKey(SessionState.PROPOSED, MessageType.OPEN), SessionState.PROPOSED],
  // From PROPOSED
  [
    transitionKey(SessionState.PROPOSED, MessageType.ACCEPT_SESSION),
    SessionState.ACTIVE,
  ],
  [
    transitionKey(SessionState.PROPOSED, MessageType.DECLINE_SESSION),
    SessionState.REJECTED,
  ],
  // From ACTIVE — messages that keep the session active
  [transitionKey(SessionState.ACTIVE, MessageType.OFFER), SessionState.ACTIVE],
  [transitionKey(SessionState.ACTIVE, MessageType.COUNTER), SessionState.ACTIVE],
  [transitionKey(SessionState.ACTIVE, MessageType.SIGNAL), SessionState.ACTIVE],
  [transitionKey(SessionState.ACTIVE, MessageType.INQUIRE), SessionState.ACTIVE],
  [
    transitionKey(SessionState.ACTIVE, MessageType.CONSTRAIN),
    SessionState.ACTIVE,
  ],
  [
    transitionKey(SessionState.ACTIVE, MessageType.PROPOSE_MEDIATOR),
    SessionState.ACTIVE,
  ],
  [transitionKey(SessionState.ACTIVE, MessageType.RESOLVE), SessionState.ACTIVE],
  // From ACTIVE — terminal transitions
  [transitionKey(SessionState.ACTIVE, MessageType.ACCEPT), SessionState.AGREED],
  [
    transitionKey(SessionState.ACTIVE, MessageType.REJECT),
    SessionState.REJECTED,
  ],
  [
    transitionKey(SessionState.ACTIVE, MessageType.WITHDRAW),
    SessionState.REJECTED,
  ],
  [transitionKey(SessionState.ACTIVE, MessageType.COMMIT), SessionState.AGREED],
  // From DORMANT — reactivation
  [transitionKey(SessionState.DORMANT, MessageType.OFFER), SessionState.ACTIVE],
]);

/** A signed message envelope as a plain object (parsed JSON). */
export type Message = Record<string, unknown>;

/**
 * Resolver mapping an `agentId` to its Ed25519 public key (raw 32 bytes or a
 * {@link KeyPair}), or `null` when the identity is unknown. Mirrors the Python
 * `public_key_resolver` SEC-005 contract: mandatory, with a `null` return
 * treated as a rejection.
 */
export type PublicKeyResolver = (
  agentId: string,
) => Uint8Array | KeyPair | null;

/** A monotonic-ish clock returning epoch milliseconds. Defaults to `Date.now`. */
export type SessionClock = () => number;

/** Options for constructing a {@link Session}. */
export interface SessionOptions {
  sessionId?: string;
  timing?: TimingConfig;
  /** Best-effort callback fired once when the session reaches a terminal state. */
  onTerminal?: (session: Session) => void;
  /**
   * Injectable clock (epoch ms). Defaults to `Date.now`. The session captures
   * `createdAt` at construction time using this clock, and uses it again for
   * `concludedAt` and `durationSeconds()`, so wall-clock-dependent values are
   * deterministic under test.
   */
  clock?: SessionClock;
}

/**
 * A Concordia negotiation session. Tracks state, parties (in insertion order),
 * the hash-chained message transcript, and per-agent behavioral signals.
 */
export class Session {
  readonly sessionId: string;
  state: SessionState;
  timing: TimingConfig;
  transcript: Message[];
  /** Parties in registration order, mirroring Python's insertion-ordered dict. */
  readonly parties: Map<string, PartyRole>;
  /** Epoch milliseconds at construction. */
  readonly createdAt: number;
  /**
   * DELTA-09: sessions are private by default and must be opted into public
   * disclosure before a public view reveals even the agent IDs.
   */
  public: boolean;
  /** Epoch milliseconds at conclusion, or `null` while ongoing. */
  concludedAt: number | null;
  roundCount: number;
  reactivatable: boolean;

  onTerminal: ((session: Session) => void) | null;

  private readonly clock: SessionClock;
  private termsValue: Record<string, Record<string, unknown>> | null;
  private terminalFired: boolean;
  private readonly behaviors: Map<string, BehaviorRecord>;
  private readonly lastOffers: Map<string, Record<string, unknown>>;
  private readonly partyKeys: Map<string, Uint8Array | KeyPair>;

  constructor(options: SessionOptions = {}) {
    this.clock = options.clock ?? (() => Date.now());
    this.sessionId = options.sessionId ?? `ses_${randomHex8()}`;
    this.state = SessionState.PROPOSED;
    this.timing = options.timing ?? makeTimingConfig();
    this.transcript = [];
    this.parties = new Map();
    this.createdAt = this.clock();
    this.public = false;
    this.concludedAt = null;
    this.roundCount = 0;
    this.reactivatable = false;
    this.termsValue = null;
    this.onTerminal = options.onTerminal ?? null;
    this.terminalFired = false;
    this.behaviors = new Map();
    this.lastOffers = new Map();
    this.partyKeys = new Map();
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  /** The hash of the last transcript message (for chaining), or genesis. */
  get prevHash(): string {
    const last = this.transcript[this.transcript.length - 1];
    if (last === undefined) {
      return GENESIS_HASH;
    }
    return computeHash(last);
  }

  /** The term space defined when the session was opened (`null` until OPEN). */
  get terms(): Record<string, Record<string, unknown>> | null {
    return this.termsValue;
  }

  /** Whether the session is in a terminal state. */
  get isTerminal(): boolean {
    return (
      this.state === SessionState.AGREED ||
      this.state === SessionState.REJECTED ||
      this.state === SessionState.EXPIRED
    );
  }

  /**
   * Register a party in this session. Mirrors Python `add_party`: re-registering
   * an existing agent updates its role (Map insertion order is preserved on
   * update) and does NOT reset its behavior record; a fresh behavior record is
   * created only the first time an agent is seen. A provided public key is stored
   * for later resolver lookups.
   */
  addParty(
    agentId: string,
    role: PartyRole,
    publicKey?: Uint8Array | KeyPair | null,
  ): void {
    this.parties.set(agentId, role);
    if (!this.behaviors.has(agentId)) {
      this.behaviors.set(agentId, makeBehaviorRecord());
    }
    if (publicKey !== undefined && publicKey !== null) {
      this.partyKeys.set(agentId, publicKey);
    }
  }

  /**
   * Apply a message to the session, advancing state if needed. Verifies the
   * signature, validates the transition, appends to the transcript, updates
   * behavioral tracking, and returns the new state.
   *
   * @throws {InvalidSignatureError} if the signature is missing, the agent
   *   identity cannot be resolved, or the signature is cryptographically invalid.
   * @throws {InvalidTransitionError} if the message type is not valid for the
   *   current state.
   * @throws {RangeError} if `message.type` is not a valid `MessageType` value
   *   (mirrors Python `MessageType(...)` `ValueError`).
   */
  applyMessage(message: Message, resolver: PublicKeyResolver): SessionState {
    // --- Signature verification (SEC-010) ---
    const from = message.from;
    const agentId =
      from && typeof from === 'object' && !Array.isArray(from)
        ? (from as Record<string, unknown>).agent_id
        : undefined;
    if (!agentId || typeof agentId !== 'string') {
      throw new InvalidSignatureError(
        "Message missing 'from.agent_id' — cannot verify identity",
      );
    }

    const signature = message.signature;
    if (!signature || typeof signature !== 'string') {
      throw new InvalidSignatureError(
        "Message missing 'signature' — unsigned messages are rejected",
      );
    }

    const publicKey = resolver(agentId);
    if (publicKey === null || publicKey === undefined) {
      throw new InvalidSignatureError(
        `Unknown agent identity '${agentId}' — resolver returned None`,
      );
    }

    if (!verify(message, signature, publicKey)) {
      throw new InvalidSignatureError(
        `Invalid signature for agent '${agentId}' — ` +
          'message content does not match signature',
      );
    }

    // --- State transition validation ---
    // Mirrors Python `MessageType(message["type"])`: a missing key throws the
    // way `message["type"]` would, an unknown value raises the enum ValueError.
    if (!('type' in message)) {
      throw new RangeError("'type'");
    }
    const msgType = coerceMessageType(message.type);

    const key = transitionKey(this.state, msgType);
    if (!TRANSITIONS.has(key)) {
      throw new InvalidTransitionError(
        `Cannot apply ${msgType} in state ${this.state}`,
      );
    }
    const newState = TRANSITIONS.get(key) as SessionState;

    // Append to transcript.
    //
    // PARITY (intentional, do NOT add a per-append prev_hash check): Python's
    // `apply_message` does NOT validate `message["prev_hash"]` against the
    // current chain head when appending. Chain integrity is enforced separately
    // by `validate_chain` (`validateChain` here) over the whole transcript, not
    // per-append. Adding a per-append prev_hash guard would REJECT messages
    // Python accepts and break cross-language parity, so it is deliberately
    // omitted; tamper-evidence is still provided by `validateChain`.
    this.transcript.push(message);

    // Track term space from the open message. Python: `body =
    // message.get("body", {})` then `self._terms = body.get("terms")`. A present
    // key yields its value (which may itself be `null`); an absent `terms` key
    // yields `None`. `resolveBody` reproduces Python's `message.get("body", {})`
    // + the `AttributeError` REJECT when `body` is present and not a mapping.
    if (msgType === MessageType.OPEN) {
      const body = resolveBody(message);
      this.termsValue =
        'terms' in body
          ? (body.terms as Record<string, Record<string, unknown>> | null)
          : null;
    }

    // Track behavioral signals
    this.trackBehavior(agentId, msgType, message);

    // Update state
    const oldState = this.state;
    this.state = newState;

    // Mark conclusion time + fire terminal callback (AGREED / REJECTED).
    if (
      (newState === SessionState.AGREED || newState === SessionState.REJECTED) &&
      oldState !== newState
    ) {
      this.concludedAt = this.clock();
      this.fireTerminal();
    }

    return this.state;
  }

  /** Expire the session (TTL elapsed). Valid from PROPOSED or ACTIVE. */
  expire(): void {
    if (
      this.state !== SessionState.PROPOSED &&
      this.state !== SessionState.ACTIVE
    ) {
      throw new InvalidTransitionError(
        `Cannot expire session in state ${this.state}`,
      );
    }
    this.state = SessionState.EXPIRED;
    this.concludedAt = this.clock();
    this.fireTerminal();
  }

  /** Move to DORMANT state (§5.1). Valid from REJECTED or EXPIRED. */
  makeDormant(): void {
    if (
      this.state !== SessionState.REJECTED &&
      this.state !== SessionState.EXPIRED
    ) {
      throw new InvalidTransitionError(
        `Cannot make dormant from state ${this.state}`,
      );
    }
    this.state = SessionState.DORMANT;
    this.reactivatable = true;
  }

  /** Return the behavioral record for an agent (a fresh default if unseen). */
  getBehavior(agentId: string): BehaviorRecord {
    const record = this.behaviors.get(agentId);
    return record ?? makeBehaviorRecord();
  }

  /**
   * Wall-clock seconds from creation to conclusion (or now), truncated toward
   * zero and clamped at 0. Mirrors Python
   * `max(0, int((end - created).total_seconds()))`.
   */
  durationSeconds(): number {
    const end = this.concludedAt ?? this.clock();
    const seconds = (end - this.createdAt) / 1000;
    return Math.max(0, Math.trunc(seconds));
  }

  // ------------------------------------------------------------------
  // Internal: terminal callback + behavioral tracking
  // ------------------------------------------------------------------

  /** Fire the terminal callback once, swallowing any exception. */
  private fireTerminal(): void {
    if (this.terminalFired || this.onTerminal === null) {
      return;
    }
    this.terminalFired = true;
    try {
      this.onTerminal(this);
    } catch {
      // Reputation reporting is best-effort. A failure here must not raise into
      // the caller's transition path (Python swallows the exception likewise).
    }
  }

  /** Behavioral-signal accumulation (§5.4, §9.6). Mirrors Python `_track_behavior`. */
  private trackBehavior(
    agentId: string,
    msgType: MessageType,
    message: Message,
  ): void {
    let b = this.behaviors.get(agentId);
    if (b === undefined) {
      b = makeBehaviorRecord();
      this.behaviors.set(agentId, b);
    }

    if (msgType === MessageType.OFFER || msgType === MessageType.COUNTER) {
      b.offersMade += 1;
      this.roundCount += 1;
      // Python: `body = message.get("body", {})` then `current_terms =
      // body.get("terms", {})`, gated on Python truthiness (`if ... and
      // current_terms:`), i.e. a non-empty mapping. `resolveBody` reproduces
      // Python's `message.get("body", {})` + the `AttributeError` REJECT when
      // `body` is present and not a mapping. For every spec-conformant offer the
      // `terms` body is a dict (or absent); an absent or empty `terms` is falsy
      // and skips both the concession and the last-offer update, matching Python.
      const body = resolveBody(message);
      const currentTerms = isPlainObject(body.terms)
        ? (body.terms as Record<string, unknown>)
        : {};
      const hasCurrentTerms = Object.keys(currentTerms).length > 0;
      const prior = this.lastOffers.get(agentId);
      if (prior !== undefined && hasCurrentTerms) {
        const concession = computeConcession(prior, currentTerms);
        if (concession > 0) {
          b.concessions += 1;
          // Running average of concession magnitude — same op order as Python.
          const n = b.concessions;
          b.concessionMagnitude =
            (b.concessionMagnitude * (n - 1) + concession) / n;
        }
      }
      if (hasCurrentTerms) {
        this.lastOffers.set(agentId, currentTerms);
      }
    } else if (msgType === MessageType.SIGNAL) {
      b.signalsShared += 1;
    } else if (msgType === MessageType.CONSTRAIN) {
      b.constraintsDeclared += 1;
    } else if (msgType === MessageType.WITHDRAW) {
      b.withdrawal = true;
    }

    if (message.reasoning) {
      b.reasoningProvided = true;
    }
  }
}

/**
 * Estimate concession magnitude between two successive offers. Mirrors Python
 * `Session._compute_concession`.
 *
 * Returns the average fractional movement toward the counterparty across the
 * numeric terms that appear in BOTH offers, approximated by the relative change
 * in each term's `value`. Parity notes:
 * - Term values that are JS booleans count as numeric (`true`->1, `false`->0),
 *   because Python's `isinstance(v, (int, float))` is True for `bool`.
 * - The movement for a term is skipped when the previous value is exactly 0
 *   (Python's `if prev_val != 0` guard avoids division by zero).
 * - The average sums movements left-to-right and divides by the count, matching
 *   Python's `sum(movements) / len(movements)`; an empty movement list yields 0.0.
 */
export function computeConcession(
  prevTerms: Record<string, unknown>,
  currTerms: Record<string, unknown>,
): number {
  const movements: number[] = [];
  for (const termId of Object.keys(prevTerms)) {
    if (!(termId in currTerms)) {
      continue;
    }
    const prev = prevTerms[termId];
    const curr = currTerms[termId];
    const prevVal = isPlainObject(prev)
      ? (prev as Record<string, unknown>).value
      : undefined;
    const currVal = isPlainObject(curr)
      ? (curr as Record<string, unknown>).value
      : undefined;
    const prevNum = pyNumeric(prevVal);
    const currNum = pyNumeric(currVal);
    if (prevNum !== null && currNum !== null) {
      if (prevNum !== 0) {
        movements.push(Math.abs(currNum - prevNum) / Math.abs(prevNum));
      }
    }
  }
  if (movements.length === 0) {
    return 0.0;
  }
  let sum = 0;
  for (const m of movements) {
    sum += m;
  }
  return sum / movements.length;
}

/**
 * Coerce a value to the number Python's numeric path would use, or `null` if
 * Python's `isinstance(v, (int, float))` would be False. JS numbers map
 * directly; JS booleans map to 1/0 (Python `bool` is an `int` subclass);
 * everything else (strings, null, objects, arrays) is non-numeric.
 */
function pyNumeric(value: unknown): number | null {
  if (typeof value === 'number') {
    return value;
  }
  if (typeof value === 'boolean') {
    return value ? 1 : 0;
  }
  return null;
}

/** Strict plain-object test (a `{...}` literal or `JSON.parse` output). */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Resolve a message's `body` exactly as Python's `message.get("body", {})` then
 * `body.get(...)` does, for the message types whose handler reads the body
 * (OPEN, OFFER, COUNTER):
 * - `body` absent: return `{}` (Python's default — the `.get(...)` succeeds).
 * - `body` present and a plain mapping: return it.
 * - `body` present and NOT a mapping (list, string, number, bool, `null`):
 *   REJECT by throwing {@link InvalidMessageError}. Python's `body.get(...)`
 *   raises `AttributeError` here; the accept/reject decision is what must match
 *   (we fail closed rather than silently coercing a non-mapping body to `{}`,
 *   which would accept inputs Python rejects).
 *
 * Note that `{"body": null}` REJECTS: Python's `{}` default applies only when the
 * key is ABSENT, so a present `null` flows into `null.get(...)` and raises.
 */
function resolveBody(message: Message): Record<string, unknown> {
  if (!('body' in message)) {
    return {};
  }
  const body = message.body;
  if (isPlainObject(body)) {
    return body;
  }
  throw new InvalidMessageError(
    "Message 'body' must be an object when present — " +
      `got ${describeJsonType(body)}; rejecting (Python raises AttributeError here)`,
  );
}

/** A short Python-flavored description of a non-object body's JSON shape. */
function describeJsonType(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';
  if (typeof value === 'string') return 'a string';
  if (typeof value === 'boolean') return 'a boolean';
  if (typeof value === 'number') return 'a number';
  return typeof value;
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
