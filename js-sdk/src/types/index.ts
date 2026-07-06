/**
 * Concordia foundational types layer.
 *
 * Port of `concordia/types.py`: the session/message/term enumerations and the
 * core data structures every other primitive (predicate, mandate,
 * attestation, session lifecycle) builds on. Pure data + serialization; no
 * crypto dependency.
 */

export {
  SessionState,
  MessageType,
  TermType,
  Flexibility,
  OutcomeStatus,
  ResolutionMechanism,
  FulfillmentStatus,
  PartyRole,
} from './enums.js';

export {
  type Term,
  type PreferenceSignal,
  type AgentIdentity,
  type TimingConfig,
  type BehaviorRecord,
  pyRound,
  agentIdentityToDict,
  makeTimingConfig,
  behaviorRecordToDict,
  makeBehaviorRecord,
} from './models.js';
