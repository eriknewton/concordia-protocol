"""Graceful Degradation & Protocol Meta-negotiation (Viral Strategy §16, §17).

When a Concordia-equipped agent encounters a non-Concordia peer, two things
happen:

1. **Graceful Degradation** — the agent still transacts, but through an
   unstructured fallback that makes the *absence* of Concordia visible.
   The fallback is deliberately less efficient: more rounds, more ambiguity,
   no binding commitments, no session receipts. The contrast between
   Concordia and non-Concordia interactions is the selling point.

2. **Protocol Meta-negotiation** — before falling back, the agent proposes
   Concordia as the negotiation protocol. This is a structured message
   saying: "I prefer Concordia for this interaction. Here's what it offers."
   If the peer accepts, the interaction upgrades to Concordia. If not,
   degradation kicks in.

This makes protocol adoption itself a negotiation — philosophically consistent
with Concordia's thesis.

The viral loop:
    Agent A (Concordia) meets Agent B (no Concordia)
    → A proposes Concordia to B
    → B declines (or doesn't understand)
    → A falls back to unstructured negotiation
    → The interaction takes 8 rounds instead of 3
    → B (or B's developer) sees the gap and adopts Concordia
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums and constants
# ---------------------------------------------------------------------------

class PeerProtocolStatus(str, Enum):
    """The detected protocol capability of a peer."""
    CONCORDIA = "concordia"
    UNKNOWN = "unknown"
    DECLINED = "declined"       # Peer was offered Concordia and declined
    INCOMPATIBLE = "incompatible"  # Peer uses a different protocol version


class InteractionMode(str, Enum):
    """The mode an interaction is operating in."""
    CONCORDIA_NATIVE = "concordia_native"    # Both peers speak Concordia
    DEGRADED = "degraded"                     # Fallback to unstructured
    META_NEGOTIATING = "meta_negotiating"     # Currently proposing Concordia
    UPGRADED = "upgraded"                     # Peer accepted Concordia mid-interaction


PROTOCOL_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Protocol Proposal — the meta-negotiation message
# ---------------------------------------------------------------------------

@dataclass
class ProtocolProposal:
    """A proposal to use Concordia for a given interaction.

    This is the message an agent sends when it encounters a peer that
    might not speak Concordia. It explains what Concordia offers and
    invites the peer to adopt it.
    """

    proposer_agent_id: str
    target_agent_id: str
    proposal_id: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.proposal_id:
            import uuid
            self.proposal_id = f"proto_prop_{uuid.uuid4().hex[:12]}"
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "concordia.protocol_proposal",
            "proposal_id": self.proposal_id,
            "proposer_agent_id": self.proposer_agent_id,
            "target_agent_id": self.target_agent_id,
            "timestamp": self.timestamp,
            "protocol": {
                "name": "concordia",
                "version": PROTOCOL_VERSION,
                "spec_url": "https://github.com/eriknewton/concordia-protocol",
            },
            "benefits": [
                "Structured multi-attribute offers with binding commitments",
                "Cryptographic session receipts for every interaction",
                "Reputation attestations that build portable trust",
                "Resolution mechanisms when negotiations stall",
                "Conditional offers for complex deal structures",
                "Natural-language reasoning fields for LLM-native negotiation",
            ],
            "comparison": {
                "without_concordia": {
                    "offer_structure": "Unstructured free-text or ad-hoc JSON",
                    "binding_commitments": False,
                    "session_receipts": False,
                    "reputation_building": False,
                    "resolution_mechanisms": False,
                    "typical_rounds": "5-15 (unstructured back-and-forth)",
                },
                "with_concordia": {
                    "offer_structure": "Typed, multi-attribute, conditional",
                    "binding_commitments": True,
                    "session_receipts": True,
                    "reputation_building": True,
                    "resolution_mechanisms": True,
                    "typical_rounds": "2-5 (structured convergence)",
                },
            },
            "adoption": {
                "how": "pip install concordia-protocol",
                "effort": "< 1 hour to integrate",
                "backwards_compatible": True,
            },
        }


# ---------------------------------------------------------------------------
# Protocol Response — peer's answer to a proposal
# ---------------------------------------------------------------------------

@dataclass
class ProtocolResponse:
    """A peer's response to a Concordia protocol proposal."""

    proposal_id: str
    responder_agent_id: str
    accepted: bool
    reason: str | None = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "concordia.protocol_response",
            "proposal_id": self.proposal_id,
            "responder_agent_id": self.responder_agent_id,
            "accepted": self.accepted,
            "timestamp": self.timestamp,
        }
        if self.reason:
            d["reason"] = self.reason
        return d


# ---------------------------------------------------------------------------
# Degraded Interaction tracker
# ---------------------------------------------------------------------------

@dataclass
class DegradedInteraction:
    """Tracks an interaction operating in degraded (non-Concordia) mode.

    Deliberately records the inefficiency of unstructured negotiation
    to make the contrast with Concordia visible.
    """

    interaction_id: str
    agent_id: str
    peer_id: str
    peer_status: PeerProtocolStatus
    mode: InteractionMode = InteractionMode.DEGRADED
    proposal_sent: bool = False
    proposal_id: str | None = None
    rounds: int = 0
    started_at: str = ""
    messages: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def add_message(self, from_agent: str, content: str) -> dict[str, Any]:
        """Record an unstructured message in the degraded interaction."""
        self.rounds += 1
        msg = {
            "round": self.rounds,
            "from": from_agent,
            "content": content,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "structured": False,
        }
        self.messages.append(msg)
        return msg

    def upgrade(self) -> None:
        """Upgrade this interaction to Concordia after peer acceptance."""
        self.mode = InteractionMode.UPGRADED
        self.messages.append({
            "round": self.rounds + 1,
            "from": "system",
            "content": "Interaction upgraded to Concordia protocol.",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "structured": True,
        })

    def to_dict(self) -> dict[str, Any]:
        return {
            "interaction_id": self.interaction_id,
            "agent_id": self.agent_id,
            "peer_id": self.peer_id,
            "peer_status": self.peer_status.value,
            "mode": self.mode.value,
            "proposal_sent": self.proposal_sent,
            "proposal_id": self.proposal_id,
            "rounds": self.rounds,
            "started_at": self.started_at,
            "message_count": len(self.messages),
        }

    def efficiency_report(self) -> dict[str, Any]:
        """Generate a report comparing this interaction to a Concordia equivalent.

        This is the viral payload — it shows the peer (or their developer)
        exactly what they're missing.
        """
        concordia_estimated_rounds = max(2, self.rounds // 3)
        return {
            "interaction_id": self.interaction_id,
            "mode": self.mode.value,
            "actual_rounds": self.rounds,
            "estimated_concordia_rounds": concordia_estimated_rounds,
            "rounds_saved": max(0, self.rounds - concordia_estimated_rounds),
            "had_binding_commitment": False,
            "had_session_receipt": False,
            "had_reputation_attestation": False,
            "had_structured_offers": False,
            "had_resolution_mechanisms": False,
            "recommendation": (
                "This interaction used unstructured negotiation. "
                f"With Concordia, it would have taken ~{concordia_estimated_rounds} "
                f"rounds instead of {self.rounds}, with binding commitments, "
                "session receipts, and reputation building. "
                "Learn more: https://github.com/eriknewton/concordia-protocol"
            ),
        }


# ---------------------------------------------------------------------------
# Interaction Manager
# ---------------------------------------------------------------------------

class InteractionManager:
    """Manages degraded interactions and protocol meta-negotiations.

    Tracks encounters with non-Concordia peers, generates protocol
    proposals, records degraded interaction rounds, and produces
    efficiency reports that highlight what Concordia would have provided.
    """

    def __init__(self) -> None:
        self._interactions: dict[str, DegradedInteraction] = {}
        self._proposals: dict[str, ProtocolProposal] = {}

    def propose_protocol(
        self,
        agent_id: str,
        peer_id: str,
    ) -> ProtocolProposal:
        """Generate a protocol proposal for a non-Concordia peer."""
        proposal = ProtocolProposal(
            proposer_agent_id=agent_id,
            target_agent_id=peer_id,
        )
        self._proposals[proposal.proposal_id] = proposal
        return proposal

    def handle_response(
        self,
        proposal_id: str,
        accepted: bool,
        reason: str | None = None,
        responder_agent_id: str = "",
    ) -> tuple[ProtocolResponse, InteractionMode]:
        """Handle a peer's response to a protocol proposal.

        Returns the response and the resulting interaction mode.
        """
        proposal = self._proposals.get(proposal_id)
        responder = responder_agent_id or (
            proposal.target_agent_id if proposal else "unknown"
        )

        response = ProtocolResponse(
            proposal_id=proposal_id,
            responder_agent_id=responder,
            accepted=accepted,
            reason=reason,
        )

        if accepted:
            # Check if there's an existing degraded interaction to upgrade
            for interaction in self._interactions.values():
                if interaction.proposal_id == proposal_id:
                    interaction.upgrade()
                    return response, InteractionMode.UPGRADED
            return response, InteractionMode.UPGRADED
        else:
            return response, InteractionMode.DEGRADED

    def start_degraded(
        self,
        agent_id: str,
        peer_id: str,
        peer_status: PeerProtocolStatus = PeerProtocolStatus.UNKNOWN,
        proposal_id: str | None = None,
    ) -> DegradedInteraction:
        """Start tracking a degraded (non-Concordia) interaction."""
        import uuid
        interaction_id = f"degraded_{uuid.uuid4().hex[:12]}"

        interaction = DegradedInteraction(
            interaction_id=interaction_id,
            agent_id=agent_id,
            peer_id=peer_id,
            peer_status=peer_status,
            proposal_sent=proposal_id is not None,
            proposal_id=proposal_id,
        )
        self._interactions[interaction_id] = interaction
        return interaction

    def add_message(
        self,
        interaction_id: str,
        from_agent: str,
        content: str,
    ) -> dict[str, Any] | None:
        """Record a message in a degraded interaction."""
        interaction = self._interactions.get(interaction_id)
        if interaction is None:
            return None
        return interaction.add_message(from_agent, content)

    def get_interaction(self, interaction_id: str) -> DegradedInteraction | None:
        return self._interactions.get(interaction_id)

    def get_efficiency_report(self, interaction_id: str) -> dict[str, Any] | None:
        """Get the efficiency comparison for a degraded interaction."""
        interaction = self._interactions.get(interaction_id)
        if interaction is None:
            return None
        return interaction.efficiency_report()

    def get_proposal(self, proposal_id: str) -> ProtocolProposal | None:
        return self._proposals.get(proposal_id)

    def stats(self) -> dict[str, Any]:
        """Summary statistics across all tracked interactions."""
        total = len(self._interactions)
        degraded = sum(
            1 for i in self._interactions.values()
            if i.mode == InteractionMode.DEGRADED
        )
        upgraded = sum(
            1 for i in self._interactions.values()
            if i.mode == InteractionMode.UPGRADED
        )
        total_proposals = len(self._proposals)
        avg_rounds = (
            sum(i.rounds for i in self._interactions.values()) / total
            if total > 0 else 0
        )

        return {
            "total_interactions": total,
            "degraded": degraded,
            "upgraded": upgraded,
            "total_proposals_sent": total_proposals,
            "upgrade_rate": round(upgraded / total, 4) if total > 0 else 0.0,
            "avg_rounds_degraded": round(avg_rounds, 1),
        }
