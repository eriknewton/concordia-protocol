"""Concordia — Reference implementation of the Concordia Protocol.

An open standard for structured negotiation between autonomous agents.
"""

__version__ = "0.2.0"

from .agent import Agent
from .attestation import generate_attestation
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
    is_valid_attestation,
    is_valid_message,
    validate_attestation,
    validate_message,
)
from .session import InvalidSignatureError, InvalidTransitionError, Session
from .receipt_bundle import BundleSummary, ReceiptBundle, verify_bundle, screen_bundle
from .signing import KeyPair, sign_message, verify_signature
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
    "sign_message",
    "verify_signature",
    # Attestation
    "generate_attestation",
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
    "validate_attestation",
    "is_valid_message",
    "is_valid_attestation",
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
