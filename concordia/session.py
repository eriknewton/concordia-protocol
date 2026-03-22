"""Negotiation session and state machine (§5).

Implements the six-state lifecycle:
  PROPOSED → ACTIVE → AGREED / REJECTED / EXPIRED → DORMANT

The Session class enforces transition rules from §5.2, tracks the message
transcript as a hash chain (§9.3), and computes concession trajectories (§5.4).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from .message import GENESIS_HASH, build_envelope, compute_hash
from .signing import KeyPair
from .types import (
    AgentIdentity,
    BehaviorRecord,
    MessageType,
    PartyRole,
    SessionState,
    TimingConfig,
)


class InvalidTransitionError(Exception):
    """Raised when a message would cause an illegal state transition."""


# §5.2 — Transition table encoded as {(from_state, message_type): to_state}.
# Transitions to the *same* state (e.g. ACTIVE → ACTIVE) are also listed.
_TRANSITIONS: dict[tuple[SessionState, MessageType], SessionState] = {
    # The OPEN message creates the session in PROPOSED state
    (SessionState.PROPOSED, MessageType.OPEN): SessionState.PROPOSED,
    # From PROPOSED
    (SessionState.PROPOSED, MessageType.ACCEPT_SESSION): SessionState.ACTIVE,
    (SessionState.PROPOSED, MessageType.DECLINE_SESSION): SessionState.REJECTED,
    # From ACTIVE — messages that keep the session active
    (SessionState.ACTIVE, MessageType.OFFER): SessionState.ACTIVE,
    (SessionState.ACTIVE, MessageType.COUNTER): SessionState.ACTIVE,
    (SessionState.ACTIVE, MessageType.SIGNAL): SessionState.ACTIVE,
    (SessionState.ACTIVE, MessageType.INQUIRE): SessionState.ACTIVE,
    (SessionState.ACTIVE, MessageType.CONSTRAIN): SessionState.ACTIVE,
    (SessionState.ACTIVE, MessageType.PROPOSE_MEDIATOR): SessionState.ACTIVE,
    (SessionState.ACTIVE, MessageType.RESOLVE): SessionState.ACTIVE,
    # From ACTIVE — terminal transitions
    (SessionState.ACTIVE, MessageType.ACCEPT): SessionState.AGREED,
    (SessionState.ACTIVE, MessageType.REJECT): SessionState.REJECTED,
    (SessionState.ACTIVE, MessageType.WITHDRAW): SessionState.REJECTED,
    (SessionState.ACTIVE, MessageType.COMMIT): SessionState.AGREED,
    # From DORMANT — reactivation
    (SessionState.DORMANT, MessageType.OFFER): SessionState.ACTIVE,
}


class Session:
    """A Concordia negotiation session.

    Tracks state, parties, message transcript, and behavioral signals.
    """

    def __init__(
        self,
        session_id: str | None = None,
        timing: TimingConfig | None = None,
    ):
        self.session_id: str = session_id or f"ses_{uuid.uuid4().hex[:8]}"
        self.state: SessionState = SessionState.PROPOSED
        self.timing: TimingConfig = timing or TimingConfig()
        self.transcript: list[dict[str, Any]] = []
        self.parties: dict[str, PartyRole] = {}
        self.created_at: datetime = datetime.now(timezone.utc)
        self.concluded_at: datetime | None = None
        self.round_count: int = 0
        self.reactivatable: bool = False
        self._terms: dict[str, dict[str, Any]] | None = None

        # Per-agent tracking for attestation generation
        self._behaviors: dict[str, BehaviorRecord] = {}
        self._last_offers: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def prev_hash(self) -> str:
        """The hash of the last message in the transcript (for chaining)."""
        if not self.transcript:
            return GENESIS_HASH
        return compute_hash(self.transcript[-1])

    @property
    def terms(self) -> dict[str, dict[str, Any]] | None:
        """The term space defined when the session was opened."""
        return self._terms

    @property
    def is_terminal(self) -> bool:
        """Whether the session is in a terminal state."""
        return self.state in (
            SessionState.AGREED,
            SessionState.REJECTED,
            SessionState.EXPIRED,
        )

    def add_party(self, agent_id: str, role: PartyRole) -> None:
        """Register a party in this session."""
        self.parties[agent_id] = role
        if agent_id not in self._behaviors:
            self._behaviors[agent_id] = BehaviorRecord()

    def apply_message(self, message: dict[str, Any]) -> SessionState:
        """Apply a message to the session, advancing state if needed.

        Validates the transition, appends to the transcript, updates
        behavioral tracking, and returns the new state.

        Raises ``InvalidTransitionError`` if the message type is not
        valid for the current state.
        """
        msg_type = MessageType(message["type"])
        agent_id = message["from"]["agent_id"]

        # Look up transition
        key = (self.state, msg_type)
        if key not in _TRANSITIONS:
            raise InvalidTransitionError(
                f"Cannot apply {msg_type.value} in state {self.state.value}"
            )

        new_state = _TRANSITIONS[key]

        # Append to transcript
        self.transcript.append(message)

        # Track term space from the open message
        if msg_type == MessageType.OPEN:
            body = message.get("body", {})
            self._terms = body.get("terms")

        # Track behavioral signals
        self._track_behavior(agent_id, msg_type, message)

        # Update state
        old_state = self.state
        self.state = new_state

        # Mark conclusion time
        if new_state in (SessionState.AGREED, SessionState.REJECTED) and old_state != new_state:
            self.concluded_at = datetime.now(timezone.utc)

        return self.state

    def expire(self) -> None:
        """Expire the session (TTL elapsed). Valid from PROPOSED or ACTIVE."""
        if self.state not in (SessionState.PROPOSED, SessionState.ACTIVE):
            raise InvalidTransitionError(
                f"Cannot expire session in state {self.state.value}"
            )
        self.state = SessionState.EXPIRED
        self.concluded_at = datetime.now(timezone.utc)

    def make_dormant(self) -> None:
        """Move to DORMANT state (§5.1). Valid from REJECTED or EXPIRED."""
        if self.state not in (SessionState.REJECTED, SessionState.EXPIRED):
            raise InvalidTransitionError(
                f"Cannot make dormant from state {self.state.value}"
            )
        self.state = SessionState.DORMANT
        self.reactivatable = True

    def get_behavior(self, agent_id: str) -> BehaviorRecord:
        """Return the behavioral record for an agent."""
        return self._behaviors.get(agent_id, BehaviorRecord())

    def duration_seconds(self) -> int:
        """Wall-clock seconds from creation to conclusion (or now)."""
        end = self.concluded_at or datetime.now(timezone.utc)
        return max(0, int((end - self.created_at).total_seconds()))

    # ------------------------------------------------------------------
    # Behavioral tracking (§5.4, §9.6)
    # ------------------------------------------------------------------

    def _track_behavior(self, agent_id: str, msg_type: MessageType,
                        message: dict[str, Any]) -> None:
        if agent_id not in self._behaviors:
            self._behaviors[agent_id] = BehaviorRecord()
        b = self._behaviors[agent_id]

        if msg_type in (MessageType.OFFER, MessageType.COUNTER):
            b.offers_made += 1
            self.round_count += 1
            # Track concessions
            body = message.get("body", {})
            current_terms = body.get("terms", {})
            if agent_id in self._last_offers and current_terms:
                concession = self._compute_concession(
                    self._last_offers[agent_id], current_terms
                )
                if concession > 0:
                    b.concessions += 1
                    # Running average of concession magnitude
                    n = b.concessions
                    b.concession_magnitude = (
                        b.concession_magnitude * (n - 1) + concession
                    ) / n
            if current_terms:
                self._last_offers[agent_id] = current_terms

        elif msg_type == MessageType.SIGNAL:
            b.signals_shared += 1

        elif msg_type == MessageType.CONSTRAIN:
            b.constraints_declared += 1

        elif msg_type == MessageType.WITHDRAW:
            b.withdrawal = True

        if message.get("reasoning"):
            b.reasoning_provided = True

    @staticmethod
    def _compute_concession(
        prev_terms: dict[str, Any], curr_terms: dict[str, Any]
    ) -> float:
        """Estimate concession magnitude between two successive offers.

        Returns a value in [0, 1] representing the average fractional
        movement toward the counterparty, approximated by the relative
        change in numeric term values.
        """
        movements: list[float] = []
        for term_id, prev in prev_terms.items():
            if term_id not in curr_terms:
                continue
            curr = curr_terms[term_id]
            prev_val = prev.get("value")
            curr_val = curr.get("value")
            if isinstance(prev_val, (int, float)) and isinstance(curr_val, (int, float)):
                if prev_val != 0:
                    movements.append(abs(curr_val - prev_val) / abs(prev_val))
        return sum(movements) / len(movements) if movements else 0.0
