/**
 * Core enumerations for the Concordia Protocol.
 *
 * Port of the enum definitions in the Python reference
 * (`concordia/types.py`). Cross-language parity is the load-bearing property:
 * every enum value here MUST be byte-identical to the Python `Enum` member
 * value, because these strings appear verbatim in canonical-JSON message
 * payloads that are signed and hash-chained. A divergence in any value would
 * break signature parity across the two SDKs.
 *
 * Enums are modeled as `const` objects mapping the Python member NAME to its
 * string VALUE, plus a companion union type. This is the idiomatic TypeScript
 * shape for a string enum whose *values* (not names) cross the wire: the
 * values are what get serialized, exactly as Python's `Enum` serializes via
 * its `.value`.
 */

/**
 * The six states of a Concordia negotiation lifecycle (SPEC §5.1).
 * Mirrors Python `SessionState`.
 */
export const SessionState = {
  PROPOSED: 'proposed',
  ACTIVE: 'active',
  AGREED: 'agreed',
  REJECTED: 'rejected',
  EXPIRED: 'expired',
  DORMANT: 'dormant',
} as const;
export type SessionState = (typeof SessionState)[keyof typeof SessionState];

/**
 * All fourteen Concordia message types (SPEC §4.2).
 * Mirrors Python `MessageType`.
 */
export const MessageType = {
  OPEN: 'negotiate.open',
  ACCEPT_SESSION: 'negotiate.accept_session',
  DECLINE_SESSION: 'negotiate.decline_session',
  OFFER: 'negotiate.offer',
  COUNTER: 'negotiate.counter',
  ACCEPT: 'negotiate.accept',
  REJECT: 'negotiate.reject',
  INQUIRE: 'negotiate.inquire',
  CONSTRAIN: 'negotiate.constrain',
  SIGNAL: 'negotiate.signal',
  WITHDRAW: 'negotiate.withdraw',
  PROPOSE_MEDIATOR: 'negotiate.propose_mediator',
  RESOLVE: 'negotiate.resolve',
  COMMIT: 'negotiate.commit',
} as const;
export type MessageType = (typeof MessageType)[keyof typeof MessageType];

/**
 * Data types for negotiation terms (SPEC §3.1.1).
 * Mirrors Python `TermType`.
 */
export const TermType = {
  NUMERIC: 'numeric',
  TEMPORAL: 'temporal',
  CATEGORICAL: 'categorical',
  BOOLEAN: 'boolean',
  TEXT: 'text',
  COMPOSITE: 'composite',
} as const;
export type TermType = (typeof TermType)[keyof typeof TermType];

/**
 * Flexibility levels for preference signals (SPEC §3.4).
 * Mirrors Python `Flexibility`.
 */
export const Flexibility = {
  FIRM: 'firm',
  SOMEWHAT_FLEXIBLE: 'somewhat_flexible',
  VERY_FLEXIBLE: 'very_flexible',
} as const;
export type Flexibility = (typeof Flexibility)[keyof typeof Flexibility];

/**
 * Attestation / outcome status (SPEC §9.6).
 * Mirrors Python `OutcomeStatus`.
 */
export const OutcomeStatus = {
  AGREED: 'agreed',
  REJECTED: 'rejected',
  EXPIRED: 'expired',
  WITHDRAWN: 'withdrawn',
} as const;
export type OutcomeStatus = (typeof OutcomeStatus)[keyof typeof OutcomeStatus];

/**
 * Resolution mechanism for a concluded negotiation (SPEC §9.6).
 * Mirrors Python `ResolutionMechanism`.
 */
export const ResolutionMechanism = {
  DIRECT: 'direct',
  SPLIT: 'split',
  FOA: 'foa',
  TRADEOFF: 'tradeoff',
  ESCALATION: 'escalation',
  NONE: 'none',
} as const;
export type ResolutionMechanism =
  (typeof ResolutionMechanism)[keyof typeof ResolutionMechanism];

/**
 * Fulfillment status of an agreed outcome (SPEC §9.6).
 * Mirrors Python `FulfillmentStatus`, including the v0.4.1
 * `FULFILLED_WITH_MEDIATION` member emitted when an A2CN
 * `DISPUTE_RESOLVED` message closes the dispute lifecycle.
 */
export const FulfillmentStatus = {
  FULFILLED: 'fulfilled',
  PARTIAL: 'partial',
  UNFULFILLED: 'unfulfilled',
  DISPUTED: 'disputed',
  PENDING: 'pending',
  FULFILLED_WITH_MEDIATION: 'fulfilled_with_mediation',
} as const;
export type FulfillmentStatus =
  (typeof FulfillmentStatus)[keyof typeof FulfillmentStatus];

/**
 * Party roles in a negotiation (SPEC §9.6).
 * Mirrors Python `PartyRole`.
 */
export const PartyRole = {
  INITIATOR: 'initiator',
  RESPONDER: 'responder',
  MEDIATOR: 'mediator',
  WITNESS: 'witness',
} as const;
export type PartyRole = (typeof PartyRole)[keyof typeof PartyRole];
