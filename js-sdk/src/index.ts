/**
 * Concordia JS SDK public API.
 *
 * Start here for signed predicates: use `generateKeyPair()` to create an
 * Ed25519 key pair, `signPredicate()` to produce a signed predicate, and
 * `verifyPredicate()` to run the high-level predicate verifier. For portable
 * third-party signature checks when the verifier has only a public key and no
 * process-local predicate profile registry, use the low-level `verify()` helper
 * with the predicate dict and detached signature.
 *
 * Predicate ids must start with `urn:concordia:predicate:`. Predicate type ids
 * must use full URNs, not bare shorthand. The four canonical built-in profile
 * URNs are `urn:concordia:predicate-type:authority_gate:v1`,
 * `urn:concordia:predicate-type:procurement_eligibility:v1`,
 * `urn:concordia:predicate-type:policy_gate:v1`, and
 * `urn:concordia:predicate-type:non_deterministic_test:v1`.
 *
 * Predicate `algorithm` is the closed enum `EdDSA | ES256`; `signPredicate()`
 * emits `EdDSA` only. Predicate `status` is the closed enum
 * `active | expired | revoked | suspended`.
 */

export {
  A2A_EXTENSION_URI,
  A2A_CARRIER_TYPE,
  A2A_CARRIER_VERSION,
  A2A_CARRIER_SCHEMA_URI,
  A2A_CARRIER_MEDIA_TYPE,
  A2ACarrierError,
  buildA2ADataPart,
  parseA2ADataPart,
  type A2ADataPart,
  type ConcordiaEnvelope,
} from './a2a/carrier.js';

export {
  canonicalizeJcs,
  canonicalizePredicate,
  stripSignatures,
  canonicalCosignBytes,
} from './canonical/canonicalize.js';
export { CanonicalizationError, checkNoSpecialFloats } from './canonical/checks.js';
export { parseJsonStrict } from './canonical/parse.js';
export {
  KeyPair,
  SigningError,
  sign,
  verify,
  signJson,
  verifyJson,
  generateKeyPair,
} from './crypto/signing.js';
export { toBase64Url, fromBase64Url, Base64UrlError } from './crypto/base64url.js';
export {
  SessionState,
  MessageType,
  TermType,
  Flexibility,
  OutcomeStatus,
  ResolutionMechanism,
  FulfillmentStatus,
  PartyRole,
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
} from './types/index.js';
export {
  Predicate,
  PredicateStatus,
  PredicateFailureReason,
  PredicateValidationError,
  serializePredicateCanonical,
  validatePredicateForWrite,
  signPredicate,
  verifyPredicate,
  type PredicateDict,
  type PredicateResolver,
  type PredicateVerificationResult,
  BUILTIN_PREDICATE_TYPE_PROFILE_URNS,
  registerPredicateTypeProfile,
  getPredicateTypeProfile,
  validateConditionForProfile,
  PredicateTypeProfileLookupError,
  type PredicateTypeProfile,
  ReferenceValidationError,
  validateReference,
  MAX_REFERENCE_TYPE_LENGTH,
  MAX_REFERENCE_RELATIONSHIP_LENGTH,
  MAX_REFERENCE_ID_LENGTH,
  MAX_REFERENCE_OPTIONAL_STRING_LENGTH,
  MAX_REFERENCE_EXTENSIONS_BYTES,
  MAX_REFERENCE_EXTENSIONS_DEPTH,
  MAX_REFERENCE_EXTENSIONS_NODES,
} from './predicate/index.js';
export {
  TemporalMode,
  MandateStatus,
  MandateValidationError,
  type DelegationLink,
  makeDelegationLink,
  delegationLinkToDict,
  delegationLinkFromDict,
  type ValidityWindow,
  makeValidityWindow,
  validityWindowToDict,
  validityWindowFromDict,
  type Mandate,
  makeMandate,
  mandateToDict,
  mandateFromDict,
  type CreateMandateClock,
  createMandate,
  type MandateVerificationResult,
  makeMandateVerificationResult,
  mandateVerificationResultToDict,
  MANDATE_JSON_SCHEMA,
  CONSTRAINT_PATTERNS,
  signMandate,
  signDelegation,
  validateMandateSchema,
  validateConstraints,
  scopeRestrictionToSchema,
  composeEffectiveConstraints,
  checkTemporalValidity,
  verifyDelegationChain,
  verifyMandate,
  type RevocationChecker,
  type VerifyMandateOptions,
} from './mandate/index.js';
export {
  GENESIS_HASH,
  computeHash,
  validateChain,
  Session,
  InvalidTransitionError,
  InvalidSignatureError,
  InvalidMessageError,
  computeConcession,
  type Message,
  type PublicKeyResolver,
  type SessionClock,
  type SessionOptions,
} from './session/index.js';
export {
  ATTESTATION_VERSION,
  VALIDITY_TEMPORAL_MODES,
  VALUE_RANGE_BUCKETS,
  MAX_CATEGORY_LENGTH,
  MAX_REFERENCES,
  AttestationError,
  generateAttestation,
  countersignAttestation,
  verifyAttestationCountersignature,
  verifyReceiptSetBinding,
  generateReceiptSummary,
  computeTranscriptHash,
  validateValidityTemporal,
  isValidNow,
  type ReceiptSetBindingResult,
  type ReceiptSetBindingState,
  type ValidityTemporal,
  type GenerateAttestationOptions,
} from './attestation/index.js';
export {
  validateMessage,
  isValidMessage,
  validateAttestation,
  isValidAttestation,
  validateApprovalReceipt,
  isValidApprovalReceipt,
  validateFulfillmentAttestation,
  isValidFulfillmentAttestation,
  conformsFormat,
  MESSAGE_SCHEMA,
  ATTESTATION_SCHEMA,
  APPROVAL_RECEIPT_SCHEMA,
  FULFILLMENT_ATTESTATION_SCHEMA,
  verifyApprovalReceipt,
  approvalReceiptResultToDict,
  SCHEMA_INVALID,
  SIGNATURE_INVALID,
  EXPIRED,
  OFFER_HASH_MISMATCH,
  MISSING_APPROVES_REFERENCE,
  type ApprovalDecision,
  type ApprovalReceiptResult,
  type VerifyApprovalReceiptOptions,
} from './validation/index.js';
