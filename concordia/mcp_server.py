"""Concordia MCP Server — exposes the Concordia negotiation protocol as MCP tools.

Implements the tool interface described in §10.2 of the Concordia Protocol spec.
Any MCP-compatible agent can open sessions, exchange offers, and reach agreements
through structured tool calls.

Built on the official Python MCP SDK (``mcp`` package), matching the same SDK
family used by the Sanctuary Framework's TypeScript server. Both servers can
run side by side in a single MCP client configuration.

Tools — Negotiation:
    concordia_open_session    — Create a new negotiation session with terms and timing
    concordia_propose         — Send an initial offer into an active session
    concordia_counter         — Send a counter-offer in response to the other party's offer
    concordia_accept          — Accept the current offer (ACTIVE → AGREED)
    concordia_reject          — Reject the negotiation (ACTIVE → REJECTED)
    concordia_commit          — Finalize an agreed deal with cryptographic commitment
    concordia_session_status  — Read current session state, transcript, and analytics
    concordia_session_receipt — Generate a reputation attestation for a concluded session

Tools — Reputation (§9.6):
    concordia_ingest_attestation — Submit a signed attestation for ingestion and scoring
    concordia_reputation_query   — Query an agent's reputation per §9.6.7 format
    concordia_reputation_score   — Get a raw reputation score (no query envelope needed)

Tools — Discovery (§7, §10.1):
    concordia_register_agent   — Register an agent with capabilities and Concordia Preferred badge
    concordia_search_agents    — Find negotiation partners by category, role, or capability
    concordia_agent_card       — Get A2A-compatible Agent Card for a registered agent
    concordia_deregister_agent — Remove an agent from the registry

Tools — Want Registry (§7):
    concordia_post_want       — Publish a structured Want (demand) and get immediate matches
    concordia_post_have       — Publish a structured Have (supply) and get immediate matches
    concordia_get_want        — Retrieve a specific Want by ID
    concordia_get_have        — Retrieve a specific Have by ID
    concordia_withdraw_want   — Remove an active Want from the registry
    concordia_withdraw_have   — Remove an active Have from the registry
    concordia_find_matches    — Query stored matches by want, have, or agent
    concordia_search_wants    — Browse active Wants, optionally filtered by category
    concordia_search_haves    — Browse active Haves, optionally filtered by category
    concordia_want_registry_stats — Get summary statistics for the Want Registry

Tools — Relay (SERVICE_ARCHITECTURE §3):
    concordia_relay_create        — Create a relay session for message routing
    concordia_relay_join          — Responder joins a pending relay session
    concordia_relay_send          — Route a message through the relay to the counterparty
    concordia_relay_receive       — Poll for pending messages (store-and-forward)
    concordia_relay_status        — Get relay session status and participant info
    concordia_relay_conclude      — Manually conclude a relay session
    concordia_relay_transcript    — Retrieve the full relayed message transcript
    concordia_relay_archive       — Archive a concluded session for compliance
    concordia_relay_list_archives — List transcript archives
    concordia_relay_stats         — Get relay-wide summary statistics

Tools — Adoption (Viral Strategy §16, §17):
    concordia_propose_protocol    — Propose Concordia to a non-Concordia peer
    concordia_respond_to_proposal — Accept or decline a protocol proposal
    concordia_start_degraded      — Track an unstructured fallback interaction
    concordia_degraded_message    — Record a round in a degraded interaction
    concordia_efficiency_report   — Compare degraded interaction to Concordia equivalent

Usage:
    python -m concordia                     # stdio transport (default)
    python -m concordia --transport sse     # SSE transport (HTTP)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP

from .agent import Agent
from .attestation import generate_attestation
from .auth import AuthTokenStore
from .degradation import InteractionManager, PeerProtocolStatus
from .sanctuary_bridge import (
    SanctuaryBridgeConfig,
    BridgeResult,
    bridge_on_agreement,
    bridge_on_attestation,
    build_commitment_payload,
    build_reveal_payload,
)
from .message import validate_chain
from .offer import BasicOffer, ConditionalOffer, Condition, PartialOffer
from .registry import AgentRegistry
from .relay import NegotiationRelay
from .reputation import AttestationStore, ReputationScorer, ReputationQueryHandler
from .want_registry import WantRegistry
from .session import InvalidTransitionError, Session
from .signing import KeyPair
from .types import (
    AgentIdentity,
    MessageType,
    ResolutionMechanism,
    SessionState,
    TimingConfig,
)


# ---------------------------------------------------------------------------
# MCP Server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "concordia-mcp",
    instructions=(
        "Concordia Protocol negotiation tools. Use these tools to open "
        "negotiation sessions between agents, exchange offers and counter-offers, "
        "reach agreements, and generate cryptographic receipts."
    ),
)


# ---------------------------------------------------------------------------
# Session store — manages all active negotiation sessions
# ---------------------------------------------------------------------------

@dataclass
class SessionContext:
    """Everything needed to drive a negotiation session through MCP tools."""

    session: Session
    initiator: Agent
    responder: Agent
    initiator_key: KeyPair
    responder_key: KeyPair
    terms: dict[str, dict[str, Any]]
    created_at: str
    metadata: dict[str, Any] = field(default_factory=dict)


class SessionStore:
    """In-memory store for active negotiation sessions.

    Each session is fully self-contained: it holds both agents, their key
    pairs, and the session object. This means an MCP client can drive a
    complete negotiation through tool calls alone — no external state needed.
    """

    MAX_SESSIONS = 10_000

    def __init__(self) -> None:
        self._sessions: dict[str, SessionContext] = {}

    def create(
        self,
        initiator_id: str,
        responder_id: str,
        terms: dict[str, dict[str, Any]],
        timing: TimingConfig | None = None,
        reasoning: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SessionContext:
        """Create a new session with a fresh agent pair and open it.

        Raises ValueError if initiator and responder are the same agent.
        """
        if len(self._sessions) >= self.MAX_SESSIONS:
            raise ValueError("Session store capacity reached")

        if initiator_id == responder_id:
            raise ValueError("Self-negotiation is not allowed: initiator and responder must be different agents")

        initiator = Agent(initiator_id)
        responder = Agent(responder_id)

        session = initiator.open_session(
            counterparty=responder.identity,
            terms=terms,
            timing=timing,
            reasoning=reasoning,
        )
        responder.join_session(session)
        responder.accept_session(reasoning="Session accepted via MCP tool interface")

        ctx = SessionContext(
            session=session,
            initiator=initiator,
            responder=responder,
            initiator_key=initiator.key_pair,
            responder_key=responder.key_pair,
            terms=terms,
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            metadata=metadata or {},
        )
        self._sessions[session.session_id] = ctx
        return ctx

    def get(self, session_id: str) -> SessionContext | None:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[dict[str, Any]]:
        """Return a summary of all sessions."""
        results = []
        for sid, ctx in self._sessions.items():
            results.append({
                "session_id": sid,
                "state": ctx.session.state.value,
                "initiator": ctx.initiator.agent_id,
                "responder": ctx.responder.agent_id,
                "round_count": ctx.session.round_count,
                "created_at": ctx.created_at,
            })
        return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Global session store — shared across all tool invocations
_store = SessionStore()

# Global auth token store — validates caller identity on every tool call
_auth = AuthTokenStore()


def _auth_error(identity: str) -> str:
    """Return a JSON error for failed authentication.

    The error deliberately does NOT include the token value or reveal
    whether the identity exists — only that authentication failed.
    """
    return json.dumps({
        "error": f"Authentication required: invalid or missing auth_token for '{identity}'."
    })


def _resolve_role(ctx: SessionContext, role: str) -> Agent:
    """Map a role string to the correct agent."""
    role_lower = role.lower()
    if role_lower in ("initiator", "seller", "proposer"):
        return ctx.initiator
    elif role_lower in ("responder", "buyer", "receiver"):
        return ctx.responder
    else:
        raise ValueError(
            f"Unknown role '{role}'. Use 'initiator'/'seller' or 'responder'/'buyer'."
        )


def _build_offer(terms: dict[str, dict[str, Any]], offer_type: str = "basic",
                 open_terms: list[str] | None = None,
                 conditions: list[dict[str, Any]] | None = None) -> Any:
    """Construct an Offer object from tool parameters."""
    if offer_type == "partial" and open_terms:
        return PartialOffer(terms=terms, open_terms=open_terms)
    elif offer_type == "conditional" and conditions:
        parsed = [
            Condition(if_clause=c["if"], then_clause=c["then"])
            for c in conditions
        ]
        return ConditionalOffer(conditions=parsed)
    else:
        return BasicOffer(terms=terms)


def _transcript_summary(transcript: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    """Produce a compact summary of the last N transcript messages."""
    messages = transcript[-limit:] if len(transcript) > limit else transcript
    summary = []
    for msg in messages:
        entry: dict[str, Any] = {
            "type": msg.get("type", ""),
            "from": msg.get("from", {}).get("agent_id", ""),
            "timestamp": msg.get("timestamp", ""),
        }
        if msg.get("reasoning"):
            entry["reasoning"] = msg["reasoning"]
        body = msg.get("body", {})
        if "terms" in body:
            entry["terms_snapshot"] = {
                k: v.get("value") for k, v in body["terms"].items()
                if isinstance(v, dict) and "value" in v
            }
        if "offer_id" in body:
            entry["offer_id"] = body["offer_id"]
        summary.append(entry)
    return summary


# ---------------------------------------------------------------------------
# Tool: open_session
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_open_session",
    description=(
        "Open a new Concordia negotiation session between two agents. "
        "Creates both parties with Ed25519 key pairs, establishes the "
        "term space (what's being negotiated), and activates the session. "
        "Returns session_id and public keys for both parties."
    ),
)
def tool_open_session(
    initiator_id: Annotated[str, "Unique identifier for the initiating agent (e.g. 'agent_seller_01')"],
    responder_id: Annotated[str, "Unique identifier for the responding agent (e.g. 'agent_buyer_42')"],
    terms: Annotated[dict, "The negotiation term space — a dict of term_id to term definition with 'type', 'label', and optionally 'unit' and 'constraints'"],
    session_ttl: Annotated[int, "Session time-to-live in seconds (default: 86400 = 24 hours)"] = 86400,
    offer_ttl: Annotated[int, "Per-offer time-to-live in seconds (default: 3600 = 1 hour)"] = 3600,
    max_rounds: Annotated[int, "Maximum number of offer/counter rounds (default: 20)"] = 20,
    reasoning: Annotated[str | None, "Optional natural-language reasoning for opening the session"] = None,
    metadata: Annotated[dict | None, "Optional metadata to attach to the session (not part of the protocol)"] = None,
) -> str:
    """Open a new Concordia negotiation session."""
    timing = TimingConfig(
        session_ttl=session_ttl,
        offer_ttl=offer_ttl,
        max_rounds=max_rounds,
    )

    try:
        ctx = _store.create(
            initiator_id=initiator_id,
            responder_id=responder_id,
            terms=terms,
            timing=timing,
            reasoning=reasoning,
            metadata=metadata,
        )
    except ValueError as e:
        error_result = {
            "error": str(e),
            "session_id": None,
            "state": "error",
            "message": f"Failed to open session: {e}",
        }
        return json.dumps(error_result, indent=2)

    # Issue session-scoped auth tokens for both roles
    init_token, resp_token = _auth.register_session_tokens(
        ctx.session.session_id, initiator_id, responder_id,
    )

    result = {
        "session_id": ctx.session.session_id,
        "state": ctx.session.state.value,
        "initiator": {
            "agent_id": ctx.initiator.agent_id,
            "public_key": ctx.initiator_key.public_key_b64(),
        },
        "responder": {
            "agent_id": ctx.responder.agent_id,
            "public_key": ctx.responder_key.public_key_b64(),
        },
        "initiator_token": init_token,
        "responder_token": resp_token,
        "terms": terms,
        "timing": {
            "session_ttl": session_ttl,
            "offer_ttl": offer_ttl,
            "max_rounds": max_rounds,
        },
        "transcript_length": len(ctx.session.transcript),
        "message": "Session opened and active. Both parties ready to negotiate.",
    }
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: propose
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_propose",
    description=(
        "Send an initial offer into an active Concordia negotiation session. "
        "Specify which role is making the offer and the proposed term values. "
        "The offer is Ed25519-signed and appended to the cryptographic transcript."
    ),
)
def tool_propose(
    session_id: Annotated[str, "The session to send the offer into"],
    role: Annotated[str, "Who is making the offer: 'initiator'/'seller' or 'responder'/'buyer'"],
    terms: Annotated[dict, "The proposed values for each term, e.g. {'price': {'value': 850}}"],
    auth_token: Annotated[str, "Session-scoped auth token for the claimed role (returned by concordia_open_session)"],
    offer_type: Annotated[str, "Type of offer: 'basic' (default), 'partial', or 'conditional'"] = "basic",
    open_terms: Annotated[list[str] | None, "For partial offers: list of term_ids left open"] = None,
    conditions: Annotated[list[dict] | None, "For conditional offers: list of {'if': ..., 'then': ...} clauses"] = None,
    reasoning: Annotated[str | None, "Natural-language reasoning explaining the offer"] = None,
) -> str:
    """Send an initial offer into an active session."""
    if not _auth.validate_session_token(session_id, role, auth_token):
        return _auth_error(f"session={session_id}, role={role}")
    ctx = _store.get(session_id)
    if ctx is None:
        return json.dumps({"error": f"Session '{session_id}' not found."})

    if ctx.session.state != SessionState.ACTIVE:
        return json.dumps({"error": f"Session is in state '{ctx.session.state.value}', not 'active'."})

    try:
        agent = _resolve_role(ctx, role)
        offer = _build_offer(terms, offer_type, open_terms, conditions)
        msg = agent.send_offer(offer, reasoning=reasoning)

        result = {
            "session_id": session_id,
            "message_id": msg.get("id", ""),
            "type": "negotiate.offer",
            "from": agent.agent_id,
            "offer_id": msg.get("body", {}).get("offer_id", ""),
            "state": ctx.session.state.value,
            "round_count": ctx.session.round_count,
            "transcript_length": len(ctx.session.transcript),
            "message": f"Offer sent by {agent.agent_id}.",
        }
        return json.dumps(result, indent=2, default=str)
    except (InvalidTransitionError, ValueError) as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: counter
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_counter",
    description=(
        "Send a counter-offer in a Concordia negotiation session. "
        "Same interface as propose but semantically indicates a counter-position "
        "rather than an opening offer."
    ),
)
def tool_counter(
    session_id: Annotated[str, "The session to send the counter-offer into"],
    role: Annotated[str, "Who is countering: 'initiator'/'seller' or 'responder'/'buyer'"],
    terms: Annotated[dict, "The counter-proposed values for each term"],
    auth_token: Annotated[str, "Session-scoped auth token for the claimed role (returned by concordia_open_session)"],
    offer_type: Annotated[str, "Type of offer: 'basic', 'partial', or 'conditional'"] = "basic",
    open_terms: Annotated[list[str] | None, "For partial offers: term_ids left open"] = None,
    conditions: Annotated[list[dict] | None, "For conditional offers: if/then clauses"] = None,
    reasoning: Annotated[str | None, "Natural-language reasoning explaining the counter-offer"] = None,
) -> str:
    """Send a counter-offer in response to the other party's offer."""
    if not _auth.validate_session_token(session_id, role, auth_token):
        return _auth_error(f"session={session_id}, role={role}")
    ctx = _store.get(session_id)
    if ctx is None:
        return json.dumps({"error": f"Session '{session_id}' not found."})

    if ctx.session.state != SessionState.ACTIVE:
        return json.dumps({"error": f"Session is in state '{ctx.session.state.value}', not 'active'."})

    try:
        agent = _resolve_role(ctx, role)
        offer = _build_offer(terms, offer_type, open_terms, conditions)
        msg = agent.send_counter(offer, reasoning=reasoning)

        result = {
            "session_id": session_id,
            "message_id": msg.get("id", ""),
            "type": "negotiate.counter",
            "from": agent.agent_id,
            "offer_id": msg.get("body", {}).get("offer_id", ""),
            "state": ctx.session.state.value,
            "round_count": ctx.session.round_count,
            "transcript_length": len(ctx.session.transcript),
            "message": f"Counter-offer sent by {agent.agent_id}.",
        }
        return json.dumps(result, indent=2, default=str)
    except (InvalidTransitionError, ValueError) as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: accept
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_accept",
    description=(
        "Accept the current offer in a Concordia negotiation, moving the "
        "session to AGREED state. The acceptance is Ed25519-signed and the "
        "full transcript hash chain is validated."
    ),
)
def tool_accept(
    session_id: Annotated[str, "The session in which to accept the offer"],
    role: Annotated[str, "Who is accepting: 'initiator'/'seller' or 'responder'/'buyer'"],
    auth_token: Annotated[str, "Session-scoped auth token for the claimed role (returned by concordia_open_session)"],
    offer_id: Annotated[str | None, "Optional: specific offer_id to accept"] = None,
    reasoning: Annotated[str | None, "Natural-language reasoning for accepting"] = None,
) -> str:
    """Accept the current offer, moving the session to AGREED."""
    if not _auth.validate_session_token(session_id, role, auth_token):
        return _auth_error(f"session={session_id}, role={role}")
    ctx = _store.get(session_id)
    if ctx is None:
        return json.dumps({"error": f"Session '{session_id}' not found."})

    if ctx.session.state != SessionState.ACTIVE:
        return json.dumps({"error": f"Session is in state '{ctx.session.state.value}', not 'active'."})

    try:
        agent = _resolve_role(ctx, role)
        msg = agent.accept_offer(offer_id=offer_id, reasoning=reasoning)

        result = {
            "session_id": session_id,
            "message_id": msg.get("id", ""),
            "type": "negotiate.accept",
            "from": agent.agent_id,
            "state": ctx.session.state.value,
            "round_count": ctx.session.round_count,
            "transcript_length": len(ctx.session.transcript),
            "transcript_valid": validate_chain(ctx.session.transcript),
            "message": f"Offer accepted by {agent.agent_id}. Session is now AGREED.",
        }
        return json.dumps(result, indent=2, default=str)
    except (InvalidTransitionError, ValueError) as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: reject
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_reject",
    description=(
        "Reject the negotiation, moving the session to REJECTED state. "
        "Optionally provide a reason and reasoning."
    ),
)
def tool_reject(
    session_id: Annotated[str, "The session to reject"],
    role: Annotated[str, "Who is rejecting: 'initiator'/'seller' or 'responder'/'buyer'"],
    auth_token: Annotated[str, "Session-scoped auth token for the claimed role (returned by concordia_open_session)"],
    reason: Annotated[str | None, "Structured reason for rejection"] = None,
    reasoning: Annotated[str | None, "Natural-language reasoning for rejection"] = None,
) -> str:
    """Reject the negotiation, moving the session to REJECTED."""
    if not _auth.validate_session_token(session_id, role, auth_token):
        return _auth_error(f"session={session_id}, role={role}")
    ctx = _store.get(session_id)
    if ctx is None:
        return json.dumps({"error": f"Session '{session_id}' not found."})

    if ctx.session.state != SessionState.ACTIVE:
        return json.dumps({"error": f"Session is in state '{ctx.session.state.value}', not 'active'."})

    try:
        agent = _resolve_role(ctx, role)
        msg = agent.reject_offer(reason=reason, reasoning=reasoning)

        result = {
            "session_id": session_id,
            "message_id": msg.get("id", ""),
            "type": "negotiate.reject",
            "from": agent.agent_id,
            "state": ctx.session.state.value,
            "round_count": ctx.session.round_count,
            "transcript_length": len(ctx.session.transcript),
            "message": f"Negotiation rejected by {agent.agent_id}. Session is now REJECTED.",
        }
        return json.dumps(result, indent=2, default=str)
    except (InvalidTransitionError, ValueError) as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: commit
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_commit",
    description=(
        "Finalize an agreed deal with a cryptographic commitment. "
        "Locks the transcript and produces a verifiable agreement record. "
        "Only valid when the session is ACTIVE."
    ),
)
def tool_commit(
    session_id: Annotated[str, "The session to commit"],
    role: Annotated[str, "Who is committing: 'initiator'/'seller' or 'responder'/'buyer'"],
    auth_token: Annotated[str, "Session-scoped auth token for the claimed role (returned by concordia_open_session)"],
    reasoning: Annotated[str | None, "Natural-language reasoning for the commitment"] = None,
) -> str:
    """Finalize an agreed deal with a cryptographic commitment."""
    if not _auth.validate_session_token(session_id, role, auth_token):
        return _auth_error(f"session={session_id}, role={role}")
    ctx = _store.get(session_id)
    if ctx is None:
        return json.dumps({"error": f"Session '{session_id}' not found."})

    if ctx.session.state != SessionState.ACTIVE:
        return json.dumps({"error": f"Session is in state '{ctx.session.state.value}', not 'active'."})

    try:
        agent = _resolve_role(ctx, role)
        msg = agent.commit(reasoning=reasoning)

        result = {
            "session_id": session_id,
            "message_id": msg.get("id", ""),
            "type": "negotiate.commit",
            "from": agent.agent_id,
            "state": ctx.session.state.value,
            "round_count": ctx.session.round_count,
            "transcript_length": len(ctx.session.transcript),
            "transcript_valid": validate_chain(ctx.session.transcript),
            "message": f"Deal committed by {agent.agent_id}. Agreement is now finalized.",
        }
        return json.dumps(result, indent=2, default=str)
    except (InvalidTransitionError, ValueError) as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: session_status
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_session_status",
    description=(
        "Get the current status of a Concordia negotiation session. "
        "Returns state, round count, terms, behavioral analytics for "
        "both parties, transcript validity, and optional message history."
    ),
)
def tool_session_status(
    session_id: Annotated[str, "The session to query"],
    auth_token: Annotated[str, "Session-scoped auth token (initiator or responder token from concordia_open_session)"],
    include_transcript: Annotated[bool, "Whether to include a transcript summary (default: false)"] = False,
    transcript_limit: Annotated[int, "Max number of recent messages to include in transcript summary"] = 10,
) -> str:
    """Get the current status of a negotiation session."""
    if _auth.get_any_session_role(session_id, auth_token) is None:
        return _auth_error(f"session={session_id}")
    ctx = _store.get(session_id)
    if ctx is None:
        return json.dumps({"error": f"Session '{session_id}' not found."})

    session = ctx.session

    # Build behavioral analytics for each party
    behaviors: dict[str, Any] = {}
    for agent_id in session.parties:
        behavior = session.get_behavior(agent_id)
        behaviors[agent_id] = behavior.to_dict()

    result: dict[str, Any] = {
        "session_id": session_id,
        "state": session.state.value,
        "initiator": ctx.initiator.agent_id,
        "responder": ctx.responder.agent_id,
        "round_count": session.round_count,
        "terms": ctx.terms,
        "timing": {
            "session_ttl": session.timing.session_ttl,
            "offer_ttl": session.timing.offer_ttl,
            "max_rounds": session.timing.max_rounds,
        },
        "transcript_length": len(session.transcript),
        "transcript_valid": validate_chain(session.transcript),
        "behaviors": behaviors,
        "created_at": ctx.created_at,
        "is_terminal": session.is_terminal,
        "duration_seconds": session.duration_seconds(),
    }

    if session.concluded_at:
        result["concluded_at"] = session.concluded_at.strftime("%Y-%m-%dT%H:%M:%SZ")

    if include_transcript:
        result["transcript"] = _transcript_summary(
            session.transcript, limit=transcript_limit,
        )

    if ctx.metadata:
        result["metadata"] = ctx.metadata

    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: session_receipt
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_session_receipt",
    description=(
        "Generate a cryptographic receipt (reputation attestation) for a "
        "concluded negotiation session. Includes outcome, behavioral records, "
        "transcript hash, and Ed25519 signatures from both parties. "
        "Only available for sessions in terminal state (agreed/rejected/expired)."
    ),
)
def tool_session_receipt(
    session_id: Annotated[str, "The concluded session to generate a receipt for"],
    auth_token: Annotated[str, "Session-scoped auth token (initiator or responder token from concordia_open_session)"],
    category: Annotated[str | None, "Optional transaction category (e.g. 'electronics.cameras')"] = None,
    value_range: Annotated[str | None, "Optional value bucket (e.g. '1000-5000_USD')"] = None,
) -> str:
    """Generate a cryptographic receipt for a concluded session."""
    if _auth.get_any_session_role(session_id, auth_token) is None:
        return _auth_error(f"session={session_id}")
    ctx = _store.get(session_id)
    if ctx is None:
        return json.dumps({"error": f"Session '{session_id}' not found."})

    session = ctx.session

    if not session.is_terminal:
        return json.dumps({
            "error": f"Session is in state '{session.state.value}'. "
                     f"Receipts can only be generated for concluded sessions "
                     f"(agreed, rejected, or expired).",
        })

    try:
        # Determine resolution mechanism based on state
        mechanism = ResolutionMechanism.DIRECT
        if session.state == SessionState.REJECTED:
            mechanism = ResolutionMechanism.NONE
        elif session.state == SessionState.EXPIRED:
            mechanism = ResolutionMechanism.NONE

        key_pairs = {
            ctx.initiator.agent_id: ctx.initiator_key,
            ctx.responder.agent_id: ctx.responder_key,
        }

        attestation = generate_attestation(
            session,
            key_pairs,
            category=category,
            value_range=value_range,
            resolution_mechanism=mechanism,
        )

        result = {
            "session_id": session_id,
            "receipt": attestation,
            "transcript_valid": validate_chain(session.transcript),
            "message": "Session receipt generated with cryptographic signatures from both parties.",
        }
        return json.dumps(result, indent=2, default=str)
    except (ValueError, RuntimeError) as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Reputation service — attestation store, scorer, and query handler
# ---------------------------------------------------------------------------

_attestation_store = AttestationStore()
_scorer = ReputationScorer(_attestation_store)
_service_key = KeyPair.generate()
_query_handler = ReputationQueryHandler(
    store=_attestation_store,
    scorer=_scorer,
    service_id="concordia_mcp_reputation_service",
    service_key=_service_key,
)


# ---------------------------------------------------------------------------
# Tool: ingest_attestation
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_ingest_attestation",
    description=(
        "Submit a signed attestation to the Concordia Reputation Service. "
        "The attestation is validated (schema, signatures, transcript hash), "
        "deduplicated, checked for Sybil signals, and stored. Returns "
        "acceptance status and any warnings."
    ),
)
def tool_ingest_attestation(
    agent_id: Annotated[str, "The agent ingesting this attestation"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
    attestation: Annotated[dict, "The full attestation dict as produced by concordia_session_receipt"],
) -> str:
    """Ingest a signed attestation into the reputation store."""
    if not _auth.validate_agent_token(agent_id, auth_token):
        return _auth_error(agent_id)
    try:
        accepted, validation = _attestation_store.ingest(attestation)
        result: dict[str, Any] = {
            "accepted": accepted,
            "attestation_id": attestation.get("attestation_id", ""),
            "session_id": attestation.get("session_id", ""),
            "errors": validation.errors,
            "warnings": validation.warnings,
            "store_count": _attestation_store.count(),
        }
        if accepted:
            result["message"] = "Attestation accepted and stored."
        else:
            result["message"] = "Attestation rejected during validation."
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": f"Ingestion failed: {e}"})


# ---------------------------------------------------------------------------
# Tool: reputation_query
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_reputation_query",
    description=(
        "Query an agent's reputation using the standard §9.6.7 format. "
        "Returns overall score, confidence, summary statistics, context-specific "
        "sub-scores (by category, value range, and role), flags, and a signed "
        "service response. This is the primary reputation interface for agents "
        "evaluating a counterparty before entering a negotiation."
    ),
)
def tool_reputation_query(
    subject_agent_id: Annotated[str, "The agent to look up (the potential counterparty)"],
    requester_agent_id: Annotated[str, "The agent requesting the reputation check"],
    category: Annotated[str | None, "Optional category filter (e.g. 'electronics')"] = None,
    value_range: Annotated[str | None, "Optional value range filter (e.g. '1000-5000_USD')"] = None,
    role: Annotated[str | None, "Optional role filter (e.g. 'seller', 'buyer')"] = None,
) -> str:
    """Query an agent's reputation per §9.6.7."""
    query: dict[str, Any] = {
        "type": "concordia.reputation.query",
        "subject_agent_id": subject_agent_id,
        "requester_agent_id": requester_agent_id,
    }
    context: dict[str, str] = {}
    if category:
        context["category"] = category
    if value_range:
        context["value_range"] = value_range
    if role:
        context["role"] = role
    if context:
        query["context"] = context

    response = _query_handler.handle(query)
    return json.dumps(response, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: reputation_score
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_reputation_score",
    description=(
        "Get a raw reputation score for an agent without the full §9.6.7 "
        "query envelope. Simpler than concordia_reputation_query — returns "
        "score components, confidence, and attestation counts directly."
    ),
)
def tool_reputation_score(
    agent_id: Annotated[str, "The agent to score"],
    category: Annotated[str | None, "Optional category filter"] = None,
    value_range: Annotated[str | None, "Optional value range filter"] = None,
    role: Annotated[str | None, "Optional role filter"] = None,
) -> str:
    """Get a raw reputation score for an agent."""
    score = _scorer.score(
        agent_id, category=category, value_range=value_range, role=role,
    )
    if score is None:
        return json.dumps({
            "agent_id": agent_id,
            "score": None,
            "message": f"No attestation data found for agent '{agent_id}'.",
        })

    result = {
        "agent_id": agent_id,
        "score": score.to_dict(),
        "message": f"Score computed from {score.total_negotiations} attestations.",
    }
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Discovery registry — agent registration, lookup, capability advertising
# ---------------------------------------------------------------------------

_registry = AgentRegistry()


# ---------------------------------------------------------------------------
# Tool: register_agent
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_register_agent",
    description=(
        "Register an agent in the Concordia Discovery Registry. "
        "Advertises that this agent speaks Concordia and specifies "
        "its capabilities: supported roles, categories, and resolution "
        "mechanisms. Grants the 'Concordia Preferred' badge."
    ),
)
def tool_register_agent(
    agent_id: Annotated[str, "Unique agent identifier"],
    roles: Annotated[list[str] | None, "Roles this agent can play: 'buyer', 'seller', or both (default: both)"] = None,
    categories: Annotated[list[str] | None, "Categories this agent operates in (e.g. ['electronics', 'furniture']). Empty = all."] = None,
    resolution_mechanisms: Annotated[list[str] | None, "Supported resolution mechanisms (default: ['split', 'foa', 'tradeoff'])"] = None,
    endpoint: Annotated[str | None, "Optional agent endpoint URL for direct contact"] = None,
    description: Annotated[str | None, "Optional human-readable description of the agent"] = None,
) -> str:
    """Register an agent in the discovery registry."""
    agent = _registry.register(
        agent_id=agent_id,
        roles=roles,
        categories=categories,
        resolution_mechanisms=resolution_mechanisms,
        endpoint=endpoint,
        description=description,
    )
    # Issue agent-scoped auth token
    agent_token = _auth.register_agent_token(agent_id)
    result = {
        "registered": True,
        "agent": agent.to_dict(),
        "auth_token": agent_token,
        "concordia_preferred": True,
        "registry_count": _registry.count(),
        "message": f"Agent '{agent_id}' registered with Concordia Preferred badge.",
    }
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: search_agents
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_search_agents",
    description=(
        "Search the Concordia Discovery Registry for agents matching "
        "criteria. Find negotiation partners by category, role, or "
        "resolution mechanism support. Returns agents with the "
        "'Concordia Preferred' badge."
    ),
)
def tool_search_agents(
    category: Annotated[str | None, "Filter by category (e.g. 'electronics.cameras')"] = None,
    role: Annotated[str | None, "Filter by role (e.g. 'seller', 'buyer')"] = None,
    resolution_mechanism: Annotated[str | None, "Filter by resolution mechanism support (e.g. 'tradeoff')"] = None,
    limit: Annotated[int, "Max results to return (default: 20)"] = 20,
) -> str:
    """Search the registry for Concordia-speaking agents."""
    agents = _registry.search(
        category=category,
        role=role,
        resolution_mechanism=resolution_mechanism,
        limit=limit,
    )
    result = {
        "count": len(agents),
        "agents": [a.to_dict() for a in agents],
        "filters": {
            k: v for k, v in {
                "category": category,
                "role": role,
                "resolution_mechanism": resolution_mechanism,
            }.items() if v is not None
        },
    }
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: agent_card
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_agent_card",
    description=(
        "Get the A2A-compatible Agent Card for a registered Concordia agent. "
        "Returns capabilities, roles, categories, and the Concordia Preferred "
        "badge in a format compatible with A2A Agent Cards (§10.1)."
    ),
)
def tool_agent_card(
    agent_id: Annotated[str, "The agent to look up"],
) -> str:
    """Get an agent's A2A-compatible capability card."""
    card = _registry.get_agent_card(agent_id)
    if card is None:
        return json.dumps({
            "found": False,
            "concordia_preferred": False,
            "message": f"Agent '{agent_id}' is not registered in the Concordia registry.",
        })
    return json.dumps({
        "found": True,
        "agent_card": card,
        "concordia_preferred": True,
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: concordia_preferred_badge
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_preferred_badge",
    description=(
        "Get the machine-readable 'Concordia Preferred' badge for an agent. "
        "This is a structured, embeddable signal that the agent speaks Concordia, "
        "including capabilities, supported features, and adoption info. "
        "Can be embedded in A2A Agent Cards, MCP metadata, or any profile system."
    ),
)
def tool_concordia_preferred_badge(
    agent_id: Annotated[str, "The agent to get the badge for"],
) -> str:
    """Get the Concordia Preferred badge for an agent."""
    badge = _registry.get_badge(agent_id)
    if badge is None:
        return json.dumps({
            "found": False,
            "concordia_preferred": False,
            "message": (
                f"Agent '{agent_id}' is not registered. "
                "Register with concordia_register_agent to earn the badge."
            ),
        })
    return json.dumps({
        "found": True,
        "badge": badge,
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: deregister_agent
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_deregister_agent",
    description="Remove an agent from the Concordia Discovery Registry.",
)
def tool_deregister_agent(
    agent_id: Annotated[str, "The agent to remove"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
) -> str:
    """Remove an agent from the registry."""
    if not _auth.validate_agent_token(agent_id, auth_token):
        return _auth_error(agent_id)
    removed = _registry.deregister(agent_id)
    _auth.revoke_agent_token(agent_id)
    return json.dumps({
        "removed": removed,
        "agent_id": agent_id,
        "registry_count": _registry.count(),
        "message": f"Agent '{agent_id}' {'removed from' if removed else 'not found in'} registry.",
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Graceful degradation & protocol meta-negotiation (Viral Strategy §16, §17)
# ---------------------------------------------------------------------------

_interaction_mgr = InteractionManager()


# ---------------------------------------------------------------------------
# Tool: propose_protocol
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_propose_protocol",
    description=(
        "Propose the Concordia protocol to a non-Concordia peer. "
        "Generates a structured proposal explaining what Concordia offers "
        "and how to adopt it. This is the 'meta-negotiation' — negotiating "
        "about which protocol to negotiate with. If the peer accepts, the "
        "interaction upgrades to Concordia. If not, falls back to degraded mode."
    ),
)
def tool_propose_protocol(
    agent_id: Annotated[str, "Your agent ID (the Concordia-equipped agent)"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
    peer_id: Annotated[str, "The peer agent to propose Concordia to"],
) -> str:
    """Propose Concordia to a non-Concordia peer."""
    if not _auth.validate_agent_token(agent_id, auth_token):
        return _auth_error(agent_id)
    proposal = _interaction_mgr.propose_protocol(agent_id, peer_id)
    result = {
        "proposal": proposal.to_dict(),
        "message": (
            f"Protocol proposal sent to '{peer_id}'. "
            "If they accept, the interaction upgrades to Concordia. "
            "If not, use concordia_start_degraded to track the unstructured fallback."
        ),
    }
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: respond_to_proposal
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_respond_to_proposal",
    description=(
        "Respond to a Concordia protocol proposal — accept or decline. "
        "If accepted, the interaction upgrades to full Concordia negotiation. "
        "If declined, the interaction continues in degraded (unstructured) mode."
    ),
)
def tool_respond_to_proposal(
    proposal_id: Annotated[str, "The proposal_id from the protocol proposal"],
    accepted: Annotated[bool, "Whether to accept (true) or decline (false) Concordia"],
    responder_agent_id: Annotated[str, "Your agent ID (the responding agent)"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
    reason: Annotated[str | None, "Optional reason for accepting or declining"] = None,
) -> str:
    """Respond to a protocol proposal."""
    if not _auth.validate_agent_token(responder_agent_id, auth_token):
        return _auth_error(responder_agent_id)
    response, mode = _interaction_mgr.handle_response(
        proposal_id=proposal_id,
        accepted=accepted,
        reason=reason,
        responder_agent_id=responder_agent_id,
    )
    result: dict[str, Any] = {
        "response": response.to_dict(),
        "resulting_mode": mode.value,
    }
    if accepted:
        result["message"] = (
            "Protocol accepted! The interaction is now upgraded to Concordia. "
            "Use concordia_open_session to begin a structured negotiation."
        )
    else:
        result["message"] = (
            "Protocol declined. The interaction will continue in degraded mode. "
            "Use concordia_start_degraded to track the unstructured fallback."
        )
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: start_degraded
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_start_degraded",
    description=(
        "Start tracking a degraded (non-Concordia) interaction with a peer. "
        "Records the unstructured negotiation rounds for efficiency comparison. "
        "At the end, use concordia_efficiency_report to see what Concordia "
        "would have provided."
    ),
)
def tool_start_degraded(
    agent_id: Annotated[str, "Your agent ID"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
    peer_id: Annotated[str, "The non-Concordia peer's agent ID"],
    peer_status: Annotated[str, "Peer status: 'unknown', 'declined', or 'incompatible'"] = "unknown",
    proposal_id: Annotated[str | None, "If a protocol proposal was sent, its ID"] = None,
) -> str:
    """Start tracking a degraded interaction."""
    if not _auth.validate_agent_token(agent_id, auth_token):
        return _auth_error(agent_id)
    status_map = {
        "unknown": PeerProtocolStatus.UNKNOWN,
        "declined": PeerProtocolStatus.DECLINED,
        "incompatible": PeerProtocolStatus.INCOMPATIBLE,
    }
    status = status_map.get(peer_status, PeerProtocolStatus.UNKNOWN)

    interaction = _interaction_mgr.start_degraded(
        agent_id=agent_id,
        peer_id=peer_id,
        peer_status=status,
        proposal_id=proposal_id,
    )
    return json.dumps({
        "interaction": interaction.to_dict(),
        "message": (
            f"Degraded interaction started with '{peer_id}'. "
            "Use concordia_degraded_message to record each round. "
            "Use concordia_efficiency_report when done to see the comparison."
        ),
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: degraded_message
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_degraded_message",
    description=(
        "Record a message in a degraded (non-Concordia) interaction. "
        "Each message increments the round count. The round count feeds "
        "the efficiency report that shows what Concordia would have saved."
    ),
)
def tool_degraded_message(
    interaction_id: Annotated[str, "The degraded interaction ID"],
    from_agent: Annotated[str, "Which agent sent this message"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
    content: Annotated[str, "The message content (free text)"],
) -> str:
    """Record a message in a degraded interaction."""
    if not _auth.validate_agent_token(from_agent, auth_token):
        return _auth_error(from_agent)
    msg = _interaction_mgr.add_message(interaction_id, from_agent, content)
    if msg is None:
        return json.dumps({"error": f"Interaction '{interaction_id}' not found."})

    interaction = _interaction_mgr.get_interaction(interaction_id)
    return json.dumps({
        "message_recorded": msg,
        "total_rounds": interaction.rounds,
        "mode": interaction.mode.value,
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: efficiency_report
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_efficiency_report",
    description=(
        "Generate an efficiency comparison for a degraded interaction. "
        "Shows how many rounds were used vs. how many Concordia would have "
        "needed, plus what features were missing (binding commitments, "
        "receipts, reputation building). This is the viral payload — it "
        "shows peers what they're missing."
    ),
)
def tool_efficiency_report(
    interaction_id: Annotated[str, "The degraded interaction to report on"],
) -> str:
    """Generate an efficiency report for a degraded interaction."""
    report = _interaction_mgr.get_efficiency_report(interaction_id)
    if report is None:
        return json.dumps({"error": f"Interaction '{interaction_id}' not found."})
    return json.dumps(report, indent=2, default=str)


# ---------------------------------------------------------------------------
# Want Registry — demand-side discovery (§7)
# ---------------------------------------------------------------------------

_want_registry = WantRegistry()


# ---------------------------------------------------------------------------
# Tool: post_want
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_post_want",
    description=(
        "Publish a structured Want — what this agent is looking for. "
        "Immediately matches against existing Haves and returns any matches. "
        "Other agents posting Haves will also match against this Want. "
        "Schema follows §7.1."
    ),
)
def tool_post_want(
    agent_id: Annotated[str, "The agent posting the Want"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
    category: Annotated[str, "Hierarchical category (e.g. 'electronics.cameras.mirrorless')"],
    terms: Annotated[dict, "Term constraints — e.g. {price: {max: 2500, currency: 'USD'}, condition: {min: 'good'}}"],
    location: Annotated[dict | None, "Location constraint — {within_km: 50, of: {lat: 37.77, lng: -122.42}}"] = None,
    ttl: Annotated[int, "Time-to-live in seconds (default: 604800 = 7 days)"] = 604_800,
    notify: Annotated[bool, "Whether to receive match notifications (default: true)"] = True,
    metadata: Annotated[dict | None, "Optional metadata"] = None,
) -> str:
    """Post a Want and get immediate matches."""
    if not _auth.validate_agent_token(agent_id, auth_token):
        return _auth_error(agent_id)
    try:
        want, matches = _want_registry.post_want(
            agent_id=agent_id,
            category=category,
            terms=terms,
            location=location,
            ttl=ttl,
            notify=notify,
            metadata=metadata,
        )
        result = {
            "want": want.to_dict(),
            "immediate_matches": [m.to_dict() for m in matches],
            "match_count": len(matches),
            "message": (
                f"Want '{want.id}' posted. "
                f"Found {len(matches)} immediate match(es)."
                + (" Use concordia_open_session to start negotiating with a match." if matches else "")
            ),
        }
        return json.dumps(result, indent=2, default=str)
    except ValueError as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: post_have
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_post_have",
    description=(
        "Publish a structured Have — what this agent has available. "
        "Immediately matches against existing Wants and returns any matches. "
        "Other agents posting Wants will also match against this Have. "
        "Schema follows §7.2."
    ),
)
def tool_post_have(
    agent_id: Annotated[str, "The agent posting the Have"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
    category: Annotated[str, "Hierarchical category (e.g. 'electronics.cameras.mirrorless')"],
    terms: Annotated[dict, "Term values — e.g. {price: {min: 1800, currency: 'USD'}, condition: {value: 'like_new'}}"],
    location: Annotated[dict | None, "Location — {coordinates: {lat: 37.78, lng: -122.41}}"] = None,
    ttl: Annotated[int, "Time-to-live in seconds (default: 2592000 = 30 days)"] = 2_592_000,
    metadata: Annotated[dict | None, "Optional metadata"] = None,
) -> str:
    """Post a Have and get immediate matches."""
    if not _auth.validate_agent_token(agent_id, auth_token):
        return _auth_error(agent_id)
    try:
        have, matches = _want_registry.post_have(
            agent_id=agent_id,
            category=category,
            terms=terms,
            location=location,
            ttl=ttl,
            metadata=metadata,
        )
        result = {
            "have": have.to_dict(),
            "immediate_matches": [m.to_dict() for m in matches],
            "match_count": len(matches),
            "message": (
                f"Have '{have.id}' posted. "
                f"Found {len(matches)} immediate match(es)."
                + (" Use concordia_open_session to start negotiating with a match." if matches else "")
            ),
        }
        return json.dumps(result, indent=2, default=str)
    except ValueError as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: get_want
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_get_want",
    description="Retrieve a specific Want by ID.",
)
def tool_get_want(
    want_id: Annotated[str, "The Want ID to retrieve"],
) -> str:
    """Get a Want by ID."""
    want = _want_registry.get_want(want_id)
    if want is None:
        return json.dumps({"found": False, "want_id": want_id})
    return json.dumps({"found": True, "want": want.to_dict()}, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: get_have
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_get_have",
    description="Retrieve a specific Have by ID.",
)
def tool_get_have(
    have_id: Annotated[str, "The Have ID to retrieve"],
) -> str:
    """Get a Have by ID."""
    have = _want_registry.get_have(have_id)
    if have is None:
        return json.dumps({"found": False, "have_id": have_id})
    return json.dumps({"found": True, "have": have.to_dict()}, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: withdraw_want
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_withdraw_want",
    description="Remove an active Want from the registry.",
)
def tool_withdraw_want(
    want_id: Annotated[str, "The Want ID to withdraw"],
    agent_id: Annotated[str, "The agent withdrawing the Want (must be the owner)"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
) -> str:
    """Withdraw a Want."""
    if not _auth.validate_agent_token(agent_id, auth_token):
        return _auth_error(agent_id)
    # Verify ownership before withdrawing
    want = _want_registry.get_want(want_id)
    if want is not None and want.agent_id != agent_id:
        return json.dumps({"error": f"Agent '{agent_id}' does not own want '{want_id}'."})
    removed = _want_registry.withdraw_want(want_id)
    return json.dumps({
        "withdrawn": removed,
        "want_id": want_id,
        "message": f"Want '{want_id}' {'withdrawn' if removed else 'not found'}.",
    })


# ---------------------------------------------------------------------------
# Tool: withdraw_have
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_withdraw_have",
    description="Remove an active Have from the registry.",
)
def tool_withdraw_have(
    have_id: Annotated[str, "The Have ID to withdraw"],
    agent_id: Annotated[str, "The agent withdrawing the Have (must be the owner)"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
) -> str:
    """Withdraw a Have."""
    if not _auth.validate_agent_token(agent_id, auth_token):
        return _auth_error(agent_id)
    # Verify ownership before withdrawing
    have = _want_registry.get_have(have_id)
    if have is not None and have.agent_id != agent_id:
        return json.dumps({"error": f"Agent '{agent_id}' does not own have '{have_id}'."})
    removed = _want_registry.withdraw_have(have_id)
    return json.dumps({
        "withdrawn": removed,
        "have_id": have_id,
        "message": f"Have '{have_id}' {'withdrawn' if removed else 'not found'}.",
    })


# ---------------------------------------------------------------------------
# Tool: find_matches
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_find_matches",
    description=(
        "Query stored matches. Filter by want_id, have_id, or agent_id. "
        "Returns matches sorted by quality score (highest first)."
    ),
)
def tool_find_matches(
    want_id: Annotated[str | None, "Filter by Want ID"] = None,
    have_id: Annotated[str | None, "Filter by Have ID"] = None,
    agent_id: Annotated[str | None, "Filter by agent ID (either side of match)"] = None,
    limit: Annotated[int, "Max results (default: 20)"] = 20,
) -> str:
    """Find matches."""
    matches = _want_registry.find_matches(
        want_id=want_id,
        have_id=have_id,
        agent_id=agent_id,
        limit=limit,
    )
    return json.dumps({
        "matches": [m.to_dict() for m in matches],
        "count": len(matches),
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: search_wants
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_search_wants",
    description=(
        "Browse active Wants in the registry, optionally filtered by category. "
        "Use this to discover demand in a particular market."
    ),
)
def tool_search_wants(
    category: Annotated[str | None, "Filter by category (prefix match)"] = None,
    limit: Annotated[int, "Max results (default: 20)"] = 20,
) -> str:
    """Search active Wants."""
    wants = _want_registry.search_wants(category=category, limit=limit)
    return json.dumps({
        "wants": [w.to_dict() for w in wants],
        "count": len(wants),
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: search_haves
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_search_haves",
    description=(
        "Browse active Haves in the registry, optionally filtered by category. "
        "Use this to discover supply in a particular market."
    ),
)
def tool_search_haves(
    category: Annotated[str | None, "Filter by category (prefix match)"] = None,
    limit: Annotated[int, "Max results (default: 20)"] = 20,
) -> str:
    """Search active Haves."""
    haves = _want_registry.search_haves(category=category, limit=limit)
    return json.dumps({
        "haves": [h.to_dict() for h in haves],
        "count": len(haves),
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: want_registry_stats
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_want_registry_stats",
    description="Get summary statistics for the Want Registry — active wants, haves, matches, and unique agents.",
)
def tool_want_registry_stats() -> str:
    """Get Want Registry stats."""
    return json.dumps(_want_registry.stats(), indent=2, default=str)


# ---------------------------------------------------------------------------
# Negotiation Relay — message routing and session management
# ---------------------------------------------------------------------------

_relay = NegotiationRelay()


# ---------------------------------------------------------------------------
# Tool: relay_create
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_relay_create",
    description=(
        "Create a relay session for routing messages between agents. "
        "The relay provides store-and-forward delivery, timeout enforcement, "
        "and transcript archival. Useful when agents lack persistent endpoints "
        "or need firewall traversal."
    ),
)
def tool_relay_create(
    initiator_id: Annotated[str, "The initiating agent's ID"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
    responder_id: Annotated[str | None, "The responding agent's ID (can join later if omitted)"] = None,
    concordia_session_id: Annotated[str | None, "Link to an existing Concordia session"] = None,
    session_ttl: Annotated[int, "Session timeout in seconds (default: 86400 = 24h)"] = 86_400,
    auto_attest: Annotated[bool, "Auto-generate attestation on conclusion (default: true)"] = True,
    initiator_endpoint: Annotated[str | None, "Optional callback endpoint for the initiator"] = None,
) -> str:
    """Create a relay session."""
    if not _auth.validate_agent_token(initiator_id, auth_token):
        return _auth_error(initiator_id)
    try:
        session = _relay.create_session(
            initiator_id=initiator_id,
            responder_id=responder_id,
            concordia_session_id=concordia_session_id,
            session_ttl=session_ttl,
            auto_attest=auto_attest,
            initiator_endpoint=initiator_endpoint,
        )
        return json.dumps({
            "session": session.to_dict(),
            "message": (
                f"Relay session '{session.relay_session_id}' created. "
                + ("Responder can join with concordia_relay_join." if not responder_id else "Both parties connected.")
            ),
        }, indent=2, default=str)
    except ValueError as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: relay_join
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_relay_join",
    description="Responder joins a pending relay session.",
)
def tool_relay_join(
    relay_session_id: Annotated[str, "The relay session to join"],
    agent_id: Annotated[str, "The joining agent's ID"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
    endpoint: Annotated[str | None, "Optional callback endpoint"] = None,
) -> str:
    """Join a relay session as the responder."""
    if not _auth.validate_agent_token(agent_id, auth_token):
        return _auth_error(agent_id)
    session = _relay.join_session(relay_session_id, agent_id, endpoint)
    if session is None:
        return json.dumps({"error": f"Cannot join relay session '{relay_session_id}'. Not found or not pending."})
    return json.dumps({
        "joined": True,
        "session": session.to_dict(),
        "message": f"Agent '{agent_id}' joined relay session. Both parties connected.",
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: relay_send
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_relay_send",
    description=(
        "Route a message through the relay to the counterparty. "
        "The message is stored in the transcript and placed in the "
        "recipient's mailbox for retrieval via concordia_relay_receive."
    ),
)
def tool_relay_send(
    relay_session_id: Annotated[str, "The relay session ID"],
    from_agent: Annotated[str, "The sending agent's ID"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
    message_type: Annotated[str, "Message type (e.g. 'negotiate.offer', 'negotiate.accept')"],
    payload: Annotated[dict, "The message payload"],
    ttl: Annotated[int, "Message TTL in seconds (default: 3600)"] = 3600,
) -> str:
    """Send a message through the relay."""
    if not _auth.validate_agent_token(from_agent, auth_token):
        return _auth_error(from_agent)
    try:
        msg = _relay.send_message(
            relay_session_id=relay_session_id,
            from_agent=from_agent,
            message_type=message_type,
            payload=payload,
            ttl=ttl,
        )
        if msg is None:
            return json.dumps({"error": f"Cannot send message. Session not found, not active, or agent not a participant."})
        return json.dumps({
            "sent": True,
            "message": msg.to_dict(),
        }, indent=2, default=str)
    except ValueError as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: relay_receive
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_relay_receive",
    description=(
        "Poll for pending messages. Returns messages queued for this agent "
        "and marks them as delivered. Store-and-forward model."
    ),
)
def tool_relay_receive(
    agent_id: Annotated[str, "The receiving agent's ID"],
    auth_token: Annotated[str, "Agent-scoped auth token (returned by concordia_register_agent)"],
    relay_session_id: Annotated[str | None, "Filter by relay session (optional)"] = None,
    limit: Annotated[int, "Max messages to retrieve (default: 50)"] = 50,
) -> str:
    """Receive pending messages from the relay."""
    if not _auth.validate_agent_token(agent_id, auth_token):
        return _auth_error(agent_id)
    messages = _relay.receive_messages(
        agent_id=agent_id,
        relay_session_id=relay_session_id,
        limit=limit,
    )
    return json.dumps({
        "messages": [m.to_dict() for m in messages],
        "count": len(messages),
        "payloads": [m.payload for m in messages],
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: relay_status
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_relay_status",
    description="Get the status of a relay session including participant info and message count.",
)
def tool_relay_status(
    relay_session_id: Annotated[str, "The relay session ID"],
) -> str:
    """Get relay session status."""
    session = _relay.get_session(relay_session_id)
    if session is None:
        return json.dumps({"error": f"Relay session '{relay_session_id}' not found."})
    return json.dumps({
        "session": session.to_dict(),
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: relay_conclude
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_relay_conclude",
    description="Manually conclude a relay session. Use after the Concordia negotiation reaches a terminal state.",
)
def tool_relay_conclude(
    relay_session_id: Annotated[str, "The relay session to conclude"],
    reason: Annotated[str, "Reason for conclusion (e.g. 'agreed', 'rejected', 'manual')"] = "manual",
) -> str:
    """Conclude a relay session."""
    session = _relay.conclude_session(relay_session_id, reason)
    if session is None:
        return json.dumps({"error": f"Relay session '{relay_session_id}' not found."})
    return json.dumps({
        "concluded": True,
        "session": session.to_dict(),
        "message": f"Relay session concluded (reason: {reason}). Use concordia_relay_archive to archive the transcript.",
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: relay_transcript
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_relay_transcript",
    description="Retrieve the full relayed message transcript for a session.",
)
def tool_relay_transcript(
    relay_session_id: Annotated[str, "The relay session ID"],
    agent_id: Annotated[str | None, "Optional: the requesting agent's ID (for access control)"] = None,
    limit: Annotated[int | None, "Limit to last N messages (default: all)"] = None,
) -> str:
    """Get relay transcript."""
    transcript = _relay.get_transcript(relay_session_id, requesting_agent=agent_id, limit=limit)
    if transcript is None:
        return json.dumps({"error": f"Relay session '{relay_session_id}' not found or access denied."})
    return json.dumps({
        "relay_session_id": relay_session_id,
        "messages": transcript,
        "count": len(transcript),
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: relay_archive
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_relay_archive",
    description=(
        "Archive a concluded relay session's transcript for compliance and dispute resolution. "
        "The transcript is frozen and stored with a configurable retention period."
    ),
)
def tool_relay_archive(
    relay_session_id: Annotated[str, "The concluded relay session to archive"],
    retention_days: Annotated[int, "How long to retain the archive in days (default: 365)"] = 365,
) -> str:
    """Archive a relay session."""
    try:
        archive = _relay.archive_session(relay_session_id, retention_days)
        if archive is None:
            return json.dumps({"error": f"Cannot archive session '{relay_session_id}'. Not found or not concluded."})
        return json.dumps({
            "archived": True,
            "archive": archive.to_dict(),
            "message": f"Transcript archived ({archive.message_count} messages, {retention_days}-day retention).",
        }, indent=2, default=str)
    except ValueError as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: relay_list_archives
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_relay_list_archives",
    description="List transcript archives, optionally filtered by participant agent.",
)
def tool_relay_list_archives(
    agent_id: Annotated[str | None, "Filter by participant agent ID"] = None,
    limit: Annotated[int, "Max results (default: 20)"] = 20,
) -> str:
    """List transcript archives."""
    archives = _relay.list_archives(agent_id=agent_id, limit=limit)
    return json.dumps({
        "archives": [a.to_dict() for a in archives],
        "count": len(archives),
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: relay_stats
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_relay_stats",
    description="Get relay-wide summary statistics — sessions, messages, deliveries, archives.",
)
def tool_relay_stats() -> str:
    """Get relay stats."""
    return json.dumps(_relay.stats(), indent=2, default=str)


# ---------------------------------------------------------------------------
# Sanctuary Bridge — optional Concordia ↔ Sanctuary integration
# ---------------------------------------------------------------------------

_bridge_config = SanctuaryBridgeConfig(enabled=False)


# ---------------------------------------------------------------------------
# Tool: sanctuary_bridge_configure
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_sanctuary_bridge_configure",
    description=(
        "Configure the Sanctuary bridge. When enabled, Concordia agreements "
        "produce Sanctuary commitment payloads (L3), and attestations produce "
        "Sanctuary reputation payloads (L4). Map Concordia agent IDs to "
        "Sanctuary identity IDs and DIDs."
    ),
)
def tool_sanctuary_bridge_configure(
    enabled: Annotated[bool, "Enable or disable the Sanctuary bridge"],
    identity_mappings: Annotated[list[dict] | None, "List of {agent_id, sanctuary_id, did} mappings"] = None,
    default_context: Annotated[str | None, "Default reputation context (default: 'concordia_negotiation')"] = None,
    commitment_on_agree: Annotated[bool, "Auto-generate commitment payloads on AGREED (default: true)"] = True,
    reputation_on_receipt: Annotated[bool, "Auto-generate reputation payloads on receipt (default: true)"] = True,
) -> str:
    """Configure the Sanctuary bridge."""
    _bridge_config.enabled = enabled
    _bridge_config.commitment_on_agree = commitment_on_agree
    _bridge_config.reputation_on_receipt = reputation_on_receipt

    if default_context:
        _bridge_config.default_context = default_context

    if identity_mappings:
        for mapping in identity_mappings:
            agent_id = mapping.get("agent_id", "")
            sanctuary_id = mapping.get("sanctuary_id", "")
            did = mapping.get("did")
            if agent_id and sanctuary_id:
                _bridge_config.map_identity(agent_id, sanctuary_id, did)

    return json.dumps({
        "enabled": _bridge_config.enabled,
        "identity_count": len(_bridge_config.identity_map),
        "default_context": _bridge_config.default_context,
        "commitment_on_agree": _bridge_config.commitment_on_agree,
        "reputation_on_receipt": _bridge_config.reputation_on_receipt,
        "message": f"Sanctuary bridge {'enabled' if enabled else 'disabled'}.",
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: sanctuary_bridge_commit
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_sanctuary_bridge_commit",
    description=(
        "Generate a Sanctuary commitment payload for a Concordia agreement. "
        "Returns a pre-built payload ready to forward to sanctuary/proof_commitment. "
        "The commitment binds the agreed terms cryptographically via Sanctuary's L3."
    ),
)
def tool_sanctuary_bridge_commit(
    session_id: Annotated[str, "The Concordia session that reached agreement"],
) -> str:
    """Generate a Sanctuary commitment payload for a Concordia agreement."""
    if not _bridge_config.enabled:
        return json.dumps({
            "error": "Sanctuary bridge is not enabled. Use concordia_sanctuary_bridge_configure first.",
        })

    ctx = _store.get(session_id)
    if ctx is None:
        return json.dumps({"error": f"Session '{session_id}' not found."})

    session = ctx.session
    if session.state.value not in ("agreed",):
        return json.dumps({
            "error": f"Session is in state '{session.state.value}'. "
                     "Sanctuary commitments require an agreed session.",
        })

    from .message import validate_chain
    transcript_hash = None
    if session.transcript:
        last_msg = session.transcript[-1]
        transcript_hash = last_msg.get("previous_hash")

    parties = [ctx.initiator.agent_id, ctx.responder.agent_id]

    result = bridge_on_agreement(
        session_id=session_id,
        agreed_terms=ctx.terms,
        parties=parties,
        transcript_hash=transcript_hash,
        config=_bridge_config,
    )

    return json.dumps(result.to_dict(), indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: sanctuary_bridge_attest
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_sanctuary_bridge_attest",
    description=(
        "Generate Sanctuary reputation payloads from a Concordia attestation. "
        "Returns pre-built payloads ready to forward to sanctuary/reputation_record. "
        "One payload per party that has a Sanctuary identity mapped."
    ),
)
def tool_sanctuary_bridge_attest(
    attestation: Annotated[dict, "The Concordia attestation dict"],
) -> str:
    """Generate Sanctuary reputation payloads from a Concordia attestation."""
    if not _bridge_config.enabled:
        return json.dumps({
            "error": "Sanctuary bridge is not enabled. Use concordia_sanctuary_bridge_configure first.",
        })

    result = bridge_on_attestation(attestation, _bridge_config)

    return json.dumps(result.to_dict(), indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: sanctuary_bridge_status
# ---------------------------------------------------------------------------

@mcp.tool(
    name="concordia_sanctuary_bridge_status",
    description=(
        "Check the status of the Sanctuary bridge — whether it's enabled, "
        "how many identity mappings are configured, and what features are active."
    ),
)
def tool_sanctuary_bridge_status() -> str:
    """Get the current Sanctuary bridge configuration status."""
    return json.dumps({
        "enabled": _bridge_config.enabled,
        "identity_mappings": {
            agent_id: {
                "sanctuary_id": sid,
                "did": _bridge_config.get_did(agent_id),
            }
            for agent_id, sid in _bridge_config.identity_map.items()
        },
        "identity_count": len(_bridge_config.identity_map),
        "default_context": _bridge_config.default_context,
        "commitment_on_agree": _bridge_config.commitment_on_agree,
        "reputation_on_receipt": _bridge_config.reputation_on_receipt,
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Programmatic access — for direct Python usage and testing
# ---------------------------------------------------------------------------

def _parse_result(json_str: str) -> dict[str, Any]:
    """Parse a JSON tool result string back to a dict."""
    return json.loads(json_str)


def handle_tool_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatch an MCP tool call to the appropriate handler.

    Convenience function for direct invocation (testing, embedding).
    Takes a tool name and arguments dict, returns the result dict.
    """
    handlers = {
        "concordia_open_session": tool_open_session,
        "concordia_propose": tool_propose,
        "concordia_counter": tool_counter,
        "concordia_accept": tool_accept,
        "concordia_reject": tool_reject,
        "concordia_commit": tool_commit,
        "concordia_session_status": tool_session_status,
        "concordia_session_receipt": tool_session_receipt,
        "concordia_ingest_attestation": tool_ingest_attestation,
        "concordia_reputation_query": tool_reputation_query,
        "concordia_reputation_score": tool_reputation_score,
        "concordia_register_agent": tool_register_agent,
        "concordia_search_agents": tool_search_agents,
        "concordia_agent_card": tool_agent_card,
        "concordia_deregister_agent": tool_deregister_agent,
        "concordia_propose_protocol": tool_propose_protocol,
        "concordia_respond_to_proposal": tool_respond_to_proposal,
        "concordia_start_degraded": tool_start_degraded,
        "concordia_degraded_message": tool_degraded_message,
        "concordia_efficiency_report": tool_efficiency_report,
        "concordia_preferred_badge": tool_concordia_preferred_badge,
        "concordia_post_want": tool_post_want,
        "concordia_post_have": tool_post_have,
        "concordia_get_want": tool_get_want,
        "concordia_get_have": tool_get_have,
        "concordia_withdraw_want": tool_withdraw_want,
        "concordia_withdraw_have": tool_withdraw_have,
        "concordia_find_matches": tool_find_matches,
        "concordia_search_wants": tool_search_wants,
        "concordia_search_haves": tool_search_haves,
        "concordia_want_registry_stats": tool_want_registry_stats,
        "concordia_relay_create": tool_relay_create,
        "concordia_relay_join": tool_relay_join,
        "concordia_relay_send": tool_relay_send,
        "concordia_relay_receive": tool_relay_receive,
        "concordia_relay_status": tool_relay_status,
        "concordia_relay_conclude": tool_relay_conclude,
        "concordia_relay_transcript": tool_relay_transcript,
        "concordia_relay_archive": tool_relay_archive,
        "concordia_relay_list_archives": tool_relay_list_archives,
        "concordia_relay_stats": tool_relay_stats,
        "concordia_sanctuary_bridge_configure": tool_sanctuary_bridge_configure,
        "concordia_sanctuary_bridge_commit": tool_sanctuary_bridge_commit,
        "concordia_sanctuary_bridge_attest": tool_sanctuary_bridge_attest,
        "concordia_sanctuary_bridge_status": tool_sanctuary_bridge_status,
    }
    handler = handlers.get(name)
    if handler is None:
        return {"error": f"Unknown tool: '{name}'. Available: {list(handlers.keys())}"}

    try:
        result_str = handler(**arguments)
        return json.loads(result_str)
    except TypeError as e:
        return {"error": f"Invalid arguments for '{name}': {e}"}
    except Exception as e:
        return {"error": f"Tool '{name}' failed: {e}"}


def get_tool_definitions() -> list[dict[str, Any]]:
    """Return the MCP tool definitions for capability advertisement.

    Reads definitions from the FastMCP tool registry, which auto-generates
    JSON schemas from the Python type annotations on each tool function.
    """
    tools = mcp._tool_manager.list_tools()
    definitions = []
    for tool in tools:
        definitions.append({
            "name": tool.name,
            "description": tool.description or "",
            "inputSchema": tool.parameters,
        })
    return definitions


# ---------------------------------------------------------------------------
# Entry point — run the MCP server
# ---------------------------------------------------------------------------

def run_stdio() -> None:
    """Run the Concordia MCP server on stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run_stdio()
