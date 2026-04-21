"""Negotiation session and state machine (§5).

Implements the six-state lifecycle:
  PROPOSED → ACTIVE → AGREED / REJECTED / EXPIRED → DORMANT

The Session class enforces transition rules from §5.2, tracks the message
transcript as a hash chain (§9.3), and computes concession trajectories (§5.4).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .message import GENESIS_HASH, build_envelope, compute_hash
from .signing import KeyPair, verify_signature
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


class InvalidSignatureError(Exception):
    """Raised when a message has an invalid, missing, or unverifiable signature."""


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
        on_terminal: Callable[["Session"], None] | None = None,
    ):
        self.session_id: str = session_id or f"ses_{uuid.uuid4().hex[:8]}"
        self.state: SessionState = SessionState.PROPOSED
        self.timing: TimingConfig = timing or TimingConfig()
        self.transcript: list[dict[str, Any]] = []
        self.parties: dict[str, PartyRole] = {}
        self.created_at: datetime = datetime.now(timezone.utc)
        # DELTA-09: sessions are private by default; must be opted into
        # public disclosure via Session.mark_public() before
        # session_public_view will reveal even the agent_ids.
        self.public: bool = False
        self.concluded_at: datetime | None = None
        self.round_count: int = 0
        self.reactivatable: bool = False
        self._terms: dict[str, dict[str, Any]] | None = None

        # WP5 v0.4.0: optional callback fired when the session reaches a
        # terminal state (AGREED / REJECTED / EXPIRED). Best-effort — any
        # exception raised by the callback is swallowed so reputation
        # reporting never blocks a state transition. Per the §9.6 hard
        # constraint, reputation reporting is informational; commitment
        # correctness is independent of the report succeeding. Publicly
        # assignable so callers can attach it after Session construction.
        self.on_terminal: Callable[["Session"], None] | None = on_terminal
        self._terminal_fired: bool = False

        # Per-agent tracking for attestation generation
        self._behaviors: dict[str, BehaviorRecord] = {}
        self._last_offers: dict[str, dict[str, Any]] = {}

        # Public key registry for signature verification (SEC-010)
        self._party_keys: dict[str, Ed25519PublicKey] = {}

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

    def add_party(
        self,
        agent_id: str,
        role: PartyRole,
        public_key: Ed25519PublicKey | None = None,
    ) -> None:
        """Register a party in this session.

        Args:
            agent_id: The agent's unique identifier.
            role: The party's role (initiator or responder).
            public_key: The agent's Ed25519 public key for signature
                verification.  When provided, the key is stored in
                ``_party_keys`` so the resolver callback can look it up.
        """
        self.parties[agent_id] = role
        if agent_id not in self._behaviors:
            self._behaviors[agent_id] = BehaviorRecord()
        if public_key is not None:
            self._party_keys[agent_id] = public_key

    def apply_message(
        self,
        message: dict[str, Any],
        public_key_resolver: Callable[[str], Ed25519PublicKey | None],
    ) -> SessionState:
        """Apply a message to the session, advancing state if needed.

        Verifies the message signature, validates the transition, appends
        to the transcript, updates behavioral tracking, and returns the
        new state.

        Args:
            message: The signed message envelope dict.
            public_key_resolver: Mandatory callback that maps an agent_id
                to its Ed25519 public key, or returns ``None`` if the
                identity is unknown.  Follows the SEC-005 cluster contract:
                mandatory parameter, null return = rejection.

        Raises:
            InvalidSignatureError: If the signature is missing, the
                agent identity cannot be resolved, or the signature
                is cryptographically invalid.
            InvalidTransitionError: If the message type is not valid
                for the current state.
        """
        # --- Signature verification (SEC-010 fix) ---
        agent_id = message.get("from", {}).get("agent_id")
        if not agent_id:
            raise InvalidSignatureError(
                "Message missing 'from.agent_id' — cannot verify identity"
            )

        signature = message.get("signature")
        if not signature:
            raise InvalidSignatureError(
                "Message missing 'signature' — unsigned messages are rejected"
            )

        public_key = public_key_resolver(agent_id)
        if public_key is None:
            raise InvalidSignatureError(
                f"Unknown agent identity '{agent_id}' — resolver returned None"
            )

        if not verify_signature(message, signature, public_key):
            raise InvalidSignatureError(
                f"Invalid signature for agent '{agent_id}' — "
                "message content does not match signature"
            )

        # --- State transition validation ---
        msg_type = MessageType(message["type"])

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

        # WP5 v0.4.0: fire terminal callback (best-effort, idempotent)
        if new_state in (SessionState.AGREED, SessionState.REJECTED) and old_state != new_state:
            self._fire_terminal()

        return self.state

    def _fire_terminal(self) -> None:
        """Fire the on_terminal callback once, swallowing any exception."""
        if self._terminal_fired or self.on_terminal is None:
            return
        self._terminal_fired = True
        try:
            self.on_terminal(self)
        except Exception:
            # Reputation reporting is best-effort. A failure here must
            # not raise into the caller's transition path.
            pass

    def expire(self) -> None:
        """Expire the session (TTL elapsed). Valid from PROPOSED or ACTIVE."""
        if self.state not in (SessionState.PROPOSED, SessionState.ACTIVE):
            raise InvalidTransitionError(
                f"Cannot expire session in state {self.state.value}"
            )
        self.state = SessionState.EXPIRED
        self.concluded_at = datetime.now(timezone.utc)
        # WP5 v0.4.0: fire terminal callback on expiry as well
        self._fire_terminal()

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
