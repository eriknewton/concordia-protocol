"""Concordia — Reference implementation of the Concordia Protocol.

An open standard for structured negotiation between autonomous agents.
"""

__version__ = "0.7.0a1"

from .agent import Agent
from .attestation import generate_attestation, is_valid_now
from .discovery import Have, Match, Want, find_matches
from .message import GENESIS_HASH, build_envelope, compute_hash, validate_chain
from .offer import (
    BasicOffer,
    Bundle,
    BundleOffer,
    Condition,
    ConditionalOffer,
    Offer,
    PartialOffer,
)
from .schema_validator import (
    is_valid_approval_receipt,
    is_valid_attestation,
    is_valid_message,
    validate_approval_receipt,
    validate_attestation,
    validate_message,
)
from .session import InvalidSignatureError, InvalidTransitionError, Session
from .receipt_bundle import BundleSummary, ReceiptBundle, verify_bundle, screen_bundle
from .signing import KeyPair, ES256KeyPair, sign_message, verify_signature
from .envelope import build_trust_evidence_envelope, verify_envelope_signature
from .verascore import VerascoreClient, make_verascore_auto_hook
from .mandate import sign_mandate, verify_mandate, validate_constraints
from .approval_receipt import ApprovalReceiptResult, verify_approval_receipt
from .predicate import (
    Predicate,
    PredicateFailureReason,
    PredicateStatus,
    PredicateVerificationResult,
    sign_predicate,
    verify_predicate,
)
from .predicate_resolver import BasicHttpsResolver, ResolverProtocolError
from .ctef import predicate_to_ctef_claim
from .models.mandate import (
    Mandate,
    MandateVerificationResult,
    ValidityWindow,
    TemporalMode,
    MandateStatus,
    DelegationLink,
    MANDATE_JSON_SCHEMA,
)
from .types import (
    AgentIdentity,
    BehaviorRecord,
    Flexibility,
    FulfillmentStatus,
    MessageType,
    OutcomeStatus,
    PartyRole,
    PreferenceSignal,
    ResolutionMechanism,
    SessionState,
    Term,
    TermType,
    TimingConfig,
)

__all__ = [
    # Agent
    "Agent",
    # Session
    "Session",
    "InvalidSignatureError",
    "InvalidTransitionError",
    # Offers
    "BasicOffer",
    "PartialOffer",
    "ConditionalOffer",
    "BundleOffer",
    "Condition",
    "Bundle",
    "Offer",
    # Messages
    "build_envelope",
    "compute_hash",
    "validate_chain",
    "GENESIS_HASH",
    # Signing
    "KeyPair",
    "ES256KeyPair",
    "sign_message",
    "verify_signature",
    # Envelope
    "build_trust_evidence_envelope",
    "verify_envelope_signature",
    # Verascore
    "VerascoreClient",
    "make_verascore_auto_hook",
    # Attestation
    "generate_attestation",
    "is_valid_now",
    # Receipt Bundles
    "ReceiptBundle",
    "BundleSummary",
    "verify_bundle",
    "screen_bundle",
    # Discovery
    "Want",
    "Have",
    "Match",
    "find_matches",
    # Validation
    "validate_message",
    "validate_approval_receipt",
    "validate_attestation",
    "is_valid_message",
    "is_valid_approval_receipt",
    "is_valid_attestation",
    # Mandate
    "Mandate",
    "MandateVerificationResult",
    "ValidityWindow",
    "TemporalMode",
    "MandateStatus",
    "DelegationLink",
    "MANDATE_JSON_SCHEMA",
    "sign_mandate",
    "verify_mandate",
    "validate_constraints",
    # ApprovalReceipt
    "ApprovalReceiptResult",
    "verify_approval_receipt",
    # Predicate
    "Predicate",
    "PredicateFailureReason",
    "PredicateStatus",
    "PredicateVerificationResult",
    "sign_predicate",
    "verify_predicate",
    "BasicHttpsResolver",
    "ResolverProtocolError",
    "predicate_to_ctef_claim",
    # Types
    "AgentIdentity",
    "BehaviorRecord",
    "Flexibility",
    "FulfillmentStatus",
    "MessageType",
    "OutcomeStatus",
    "PartyRole",
    "PreferenceSignal",
    "ResolutionMechanism",
    "SessionState",
    "Term",
    "TermType",
    "TimingConfig",
]
