"""Core types and enumerations for the Concordia Protocol.

Defines the fundamental building blocks used throughout the SDK:
session states, message types, term types, and typed data structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# §5.1  Session states
# ---------------------------------------------------------------------------

class SessionState(Enum):
    """The six states of a Concordia negotiation lifecycle."""
    PROPOSED = "proposed"
    ACTIVE = "active"
    AGREED = "agreed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    DORMANT = "dormant"


# ---------------------------------------------------------------------------
# §4.2  Message types
# ---------------------------------------------------------------------------

class MessageType(Enum):
    """All fourteen Concordia message types."""
    OPEN = "negotiate.open"
    ACCEPT_SESSION = "negotiate.accept_session"
    DECLINE_SESSION = "negotiate.decline_session"
    OFFER = "negotiate.offer"
    COUNTER = "negotiate.counter"
    ACCEPT = "negotiate.accept"
    REJECT = "negotiate.reject"
    INQUIRE = "negotiate.inquire"
    CONSTRAIN = "negotiate.constrain"
    SIGNAL = "negotiate.signal"
    WITHDRAW = "negotiate.withdraw"
    PROPOSE_MEDIATOR = "negotiate.propose_mediator"
    RESOLVE = "negotiate.resolve"
    COMMIT = "negotiate.commit"


# ---------------------------------------------------------------------------
# §3.1.1  Term types
# ---------------------------------------------------------------------------

class TermType(Enum):
    """Data types for negotiation terms."""
    NUMERIC = "numeric"
    TEMPORAL = "temporal"
    CATEGORICAL = "categorical"
    BOOLEAN = "boolean"
    TEXT = "text"
    COMPOSITE = "composite"


# ---------------------------------------------------------------------------
# §3.4  Flexibility levels for preference signals
# ---------------------------------------------------------------------------

class Flexibility(Enum):
    FIRM = "firm"
    SOMEWHAT_FLEXIBLE = "somewhat_flexible"
    VERY_FLEXIBLE = "very_flexible"


# ---------------------------------------------------------------------------
# §9.6  Attestation / outcome enums
# ---------------------------------------------------------------------------

class OutcomeStatus(Enum):
    AGREED = "agreed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"


class ResolutionMechanism(Enum):
    DIRECT = "direct"
    SPLIT = "split"
    FOA = "foa"
    TRADEOFF = "tradeoff"
    ESCALATION = "escalation"
    NONE = "none"


class FulfillmentStatus(Enum):
    FULFILLED = "fulfilled"
    PARTIAL = "partial"
    UNFULFILLED = "unfulfilled"
    DISPUTED = "disputed"
    PENDING = "pending"


class PartyRole(Enum):
    INITIATOR = "initiator"
    RESPONDER = "responder"
    MEDIATOR = "mediator"
    WITNESS = "witness"


# ---------------------------------------------------------------------------
# §3.1  Term
# ---------------------------------------------------------------------------

@dataclass
class Term:
    """A single dimension of a deal — one thing being negotiated."""
    id: str
    type: TermType
    label: str
    unit: str | None = None
    constraints: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# §3.4  Preference signal
# ---------------------------------------------------------------------------

@dataclass
class PreferenceSignal:
    """Voluntary preference information shared by an agent."""
    priority_ranking: list[str] | None = None
    flexibility: dict[str, Flexibility] | None = None
    aspiration: dict[str, Any] | None = None
    reservation: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# §4.1  Sender / recipient identities
# ---------------------------------------------------------------------------

@dataclass
class AgentIdentity:
    """An agent's identity in a Concordia message."""
    agent_id: str
    principal_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"agent_id": self.agent_id}
        if self.principal_id is not None:
            d["principal_id"] = self.principal_id
        return d


# ---------------------------------------------------------------------------
# §5.3  Timing configuration
# ---------------------------------------------------------------------------

@dataclass
class TimingConfig:
    """Timing parameters for a negotiation session."""
    session_ttl: int = 86400       # 24 hours in seconds
    offer_ttl: int = 3600          # 1 hour in seconds
    max_rounds: int = 20


# ---------------------------------------------------------------------------
# §9.6.2  Behavior record
# ---------------------------------------------------------------------------

@dataclass
class BehaviorRecord:
    """Quantified behavioral signals derived from the transcript."""
    offers_made: int = 0
    concessions: int = 0
    concession_magnitude: float = 0.0
    signals_shared: int = 0
    constraints_declared: int = 0
    constraints_violated: int = 0
    reasoning_provided: bool = False
    withdrawal: bool = False
    response_time_avg_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "offers_made": self.offers_made,
            "concessions": self.concessions,
            "concession_magnitude": round(self.concession_magnitude, 4),
            "signals_shared": self.signals_shared,
            "constraints_declared": self.constraints_declared,
            "constraints_violated": self.constraints_violated,
            "reasoning_provided": self.reasoning_provided,
            "withdrawal": self.withdrawal,
            "response_time_avg_seconds": round(self.response_time_avg_seconds, 2),
        }
