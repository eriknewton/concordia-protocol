"""Concordia Agent — sends and receives all 14 message types (§4.2).

An Agent represents one party in a negotiation. It holds a signing key pair,
maintains a reference to the active session, and provides typed methods for
every message in the protocol.
"""

from __future__ import annotations

from typing import Any

from .attestation import generate_attestation
from .message import build_envelope
from .offer import Offer, offer_to_body
from .session import Session
from .signing import KeyPair, verify_signature
from .types import (
    AgentIdentity,
    MessageType,
    PartyRole,
    PreferenceSignal,
    ResolutionMechanism,
    TimingConfig,
)


class Agent:
    """A Concordia protocol agent that can negotiate with other agents.

    Usage::

        seller = Agent("agent_seller_01")
        buyer = Agent("agent_buyer_42")

        session = seller.open_session(
            counterparty=buyer.identity,
            terms={...},
        )
        buyer.join_session(session)
        buyer.accept_session()
    """

    def __init__(
        self,
        agent_id: str,
        key_pair: KeyPair | None = None,
        principal_id: str | None = None,
    ):
        self.identity = AgentIdentity(agent_id=agent_id, principal_id=principal_id)
        self.key_pair = key_pair or KeyPair.generate()
        self.session: Session | None = None
        self._role: PartyRole | None = None

    @property
    def agent_id(self) -> str:
        return self.identity.agent_id

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def open_session(
        self,
        counterparty: AgentIdentity,
        terms: dict[str, dict[str, Any]],
        timing: TimingConfig | None = None,
        reasoning: str | None = None,
    ) -> Session:
        """Send ``negotiate.open`` and create a new session (§5, PROPOSED)."""
        session = Session(timing=timing)
        self.session = session
        self._role = PartyRole.INITIATOR
        session.add_party(self.agent_id, PartyRole.INITIATOR)

        body: dict[str, Any] = {"terms": terms}
        if timing:
            body["timing"] = {
                "session_ttl": timing.session_ttl,
                "offer_ttl": timing.offer_ttl,
                "max_rounds": timing.max_rounds,
            }

        msg = self._send(
            MessageType.OPEN,
            body=body,
            recipients=[counterparty],
            reasoning=reasoning,
        )
        return session

    def join_session(self, session: Session) -> None:
        """Join an existing session as the responder."""
        self.session = session
        self._role = PartyRole.RESPONDER
        session.add_party(self.agent_id, PartyRole.RESPONDER)

    def accept_session(self, reasoning: str | None = None) -> dict[str, Any]:
        """Send ``negotiate.accept_session`` (PROPOSED → ACTIVE)."""
        return self._send(MessageType.ACCEPT_SESSION, body={}, reasoning=reasoning)

    def decline_session(
        self, reason: str | None = None, reasoning: str | None = None,
    ) -> dict[str, Any]:
        """Send ``negotiate.decline_session`` (PROPOSED → REJECTED)."""
        body: dict[str, Any] = {}
        if reason:
            body["reason"] = reason
        return self._send(MessageType.DECLINE_SESSION, body=body, reasoning=reasoning)

    # ------------------------------------------------------------------
    # Offer messages
    # ------------------------------------------------------------------

    def send_offer(
        self, offer: Offer, reasoning: str | None = None,
    ) -> dict[str, Any]:
        """Send ``negotiate.offer`` with any offer type (§6)."""
        return self._send(
            MessageType.OFFER, body=offer.to_body(), reasoning=reasoning,
        )

    def send_counter(
        self, offer: Offer, reasoning: str | None = None,
    ) -> dict[str, Any]:
        """Send ``negotiate.counter`` with a counter-offer."""
        return self._send(
            MessageType.COUNTER, body=offer.to_body(), reasoning=reasoning,
        )

    def accept_offer(
        self,
        offer_id: str | None = None,
        reasoning: str | None = None,
    ) -> dict[str, Any]:
        """Send ``negotiate.accept`` (ACTIVE → AGREED)."""
        body: dict[str, Any] = {}
        if offer_id:
            body["offer_id"] = offer_id
        return self._send(MessageType.ACCEPT, body=body, reasoning=reasoning)

    def reject_offer(
        self,
        reason: str | None = None,
        reasoning: str | None = None,
    ) -> dict[str, Any]:
        """Send ``negotiate.reject`` (ACTIVE → REJECTED)."""
        body: dict[str, Any] = {}
        if reason:
            body["reason"] = reason
        return self._send(MessageType.REJECT, body=body, reasoning=reasoning)

    # ------------------------------------------------------------------
    # Information exchange messages
    # ------------------------------------------------------------------

    def inquire(
        self, term_ids: list[str], reasoning: str | None = None,
    ) -> dict[str, Any]:
        """Send ``negotiate.inquire`` — ask about terms without offering."""
        return self._send(
            MessageType.INQUIRE,
            body={"term_ids": term_ids},
            reasoning=reasoning,
        )

    def constrain(
        self, constraints: dict[str, Any], reasoning: str | None = None,
    ) -> dict[str, Any]:
        """Send ``negotiate.constrain`` — declare a hard constraint."""
        return self._send(
            MessageType.CONSTRAIN,
            body={"constraints": constraints},
            reasoning=reasoning,
        )

    def signal(
        self, preference: PreferenceSignal, reasoning: str | None = None,
    ) -> dict[str, Any]:
        """Send ``negotiate.signal`` — share preference information."""
        body: dict[str, Any] = {}
        if preference.priority_ranking:
            body["priority_ranking"] = preference.priority_ranking
        if preference.flexibility:
            body["flexibility"] = {
                k: v.value for k, v in preference.flexibility.items()
            }
        if preference.aspiration:
            body["aspiration"] = preference.aspiration
        if preference.reservation:
            body["reservation"] = preference.reservation
        return self._send(MessageType.SIGNAL, body=body, reasoning=reasoning)

    # ------------------------------------------------------------------
    # Resolution and control messages
    # ------------------------------------------------------------------

    def withdraw(
        self,
        reason: str | None = None,
        reactivatable: bool = False,
        reasoning: str | None = None,
    ) -> dict[str, Any]:
        """Send ``negotiate.withdraw`` — exit the negotiation."""
        body: dict[str, Any] = {"reactivatable": reactivatable}
        if reason:
            body["reason"] = reason
        msg = self._send(MessageType.WITHDRAW, body=body, reasoning=reasoning)
        if reactivatable and self.session:
            self.session.make_dormant()
        return msg

    def propose_mediator(
        self, mediator_id: str, reasoning: str | None = None,
    ) -> dict[str, Any]:
        """Send ``negotiate.propose_mediator``."""
        return self._send(
            MessageType.PROPOSE_MEDIATOR,
            body={"mediator_id": mediator_id},
            reasoning=reasoning,
        )

    def resolve(
        self, proposed_terms: dict[str, dict[str, Any]],
        mechanism: str = "split",
        reasoning: str | None = None,
    ) -> dict[str, Any]:
        """Send ``negotiate.resolve`` — propose a resolution (mediator)."""
        return self._send(
            MessageType.RESOLVE,
            body={"terms": proposed_terms, "mechanism": mechanism},
            reasoning=reasoning,
        )

    def commit(self, reasoning: str | None = None) -> dict[str, Any]:
        """Send ``negotiate.commit`` — finalize the agreement."""
        return self._send(MessageType.COMMIT, body={}, reasoning=reasoning)

    # ------------------------------------------------------------------
    # Attestation
    # ------------------------------------------------------------------

    def generate_attestation(
        self,
        key_pairs: dict[str, KeyPair],
        *,
        category: str | None = None,
        value_range: str | None = None,
        resolution_mechanism: ResolutionMechanism = ResolutionMechanism.DIRECT,
    ) -> dict[str, Any]:
        """Generate a reputation attestation from the current session (§9.6)."""
        if self.session is None:
            raise RuntimeError("No active session")
        return generate_attestation(
            self.session,
            key_pairs,
            category=category,
            value_range=value_range,
            resolution_mechanism=resolution_mechanism,
        )

    # ------------------------------------------------------------------
    # Message verification
    # ------------------------------------------------------------------

    def verify_message(
        self, message: dict[str, Any], sender_public_key: Any,
    ) -> bool:
        """Verify the Ed25519 signature on a received message."""
        sig = message.get("signature", "")
        return verify_signature(message, sig, sender_public_key)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _send(
        self,
        msg_type: MessageType,
        body: dict[str, Any],
        recipients: list[AgentIdentity] | None = None,
        reasoning: str | None = None,
    ) -> dict[str, Any]:
        """Build, sign, and apply a message to the session."""
        if self.session is None:
            raise RuntimeError("No active session")

        msg = build_envelope(
            message_type=msg_type,
            session_id=self.session.session_id,
            sender=self.identity,
            body=body,
            key_pair=self.key_pair,
            prev_hash=self.session.prev_hash,
            recipients=recipients,
            reasoning=reasoning,
        )

        self.session.apply_message(msg)
        return msg
