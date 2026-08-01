"""Concordia — Reference implementation of the Concordia Protocol.

An open standard for structured negotiation between autonomous agents.
"""

import warnings
from typing import Any

__version__ = "0.7.0a1"

from .agent import Agent
from .approval_receipt import ApprovalReceiptResult, verify_approval_receipt
from .attestation import (
    ATTESTATION_VERSION,
    AttestationVerifyResult,
    countersign_attestation,
    generate_attestation,
    is_valid_now,
    verify_attestation,
    verify_attestation_countersignature,
)
from .canonicalization import canonicalize_jcs
from .ctef import predicate_to_ctef_claim
from .discovery import Have, Match, Want, find_matches
from .envelope import build_trust_evidence_envelope, verify_envelope_signature
from .mandate import sign_mandate, validate_constraints, verify_mandate
from .message import GENESIS_HASH, build_envelope, compute_hash, validate_chain
from .models.mandate import (
    MANDATE_JSON_SCHEMA,
    DelegationLink,
    Mandate,
    MandateStatus,
    MandateVerificationResult,
    TemporalMode,
    ValidityWindow,
)
from .offer import (
    BasicOffer,
    Bundle,
    BundleOffer,
    Condition,
    ConditionalOffer,
    Offer,
    PartialOffer,
)
from .predicate import (
    Predicate,
    PredicateFailureReason,
    PredicateStatus,
    PredicateVerificationResult,
    sign_predicate,
    verify_predicate,
)
from .predicate_resolver import BasicHttpsResolver, ResolverProtocolError
from .receipt_bundle import BundleSummary, ReceiptBundle, screen_bundle, verify_bundle
from .schema_validator import (
    is_valid_approval_receipt,
    is_valid_attestation,
    is_valid_message,
    validate_approval_receipt,
    validate_attestation,
    validate_message,
)
from .session import (
    ChainIntegrityError,
    InvalidSignatureError,
    InvalidTransitionError,
    MaxRoundsExceededError,
    Session,
    SessionBindingError,
)
from .signing import (
    ES256KeyPair,
    KeyPair,
    public_key_from_b64url,
    sign_message,
    verify_signature,
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


def __getattr__(name: str) -> Any:
    if name in {"VerascoreClient", "make_verascore_auto_hook"}:
        warnings.warn(
            f"concordia.{name} is deprecated; import from concordia.verascore instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        from .verascore import VerascoreClient, make_verascore_auto_hook

        return {
            "VerascoreClient": VerascoreClient,
            "make_verascore_auto_hook": make_verascore_auto_hook,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Agent
    "Agent",
    # Session
    "Session",
    "InvalidSignatureError",
    "InvalidTransitionError",
    "SessionBindingError",
    "ChainIntegrityError",
    "MaxRoundsExceededError",
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
    "public_key_from_b64url",
    "canonicalize_jcs",
    # Envelope
    "build_trust_evidence_envelope",
    "verify_envelope_signature",
    # Attestation
    "ATTESTATION_VERSION",
    "AttestationVerifyResult",
    "generate_attestation",
    "verify_attestation",
    "countersign_attestation",
    "verify_attestation_countersignature",
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
