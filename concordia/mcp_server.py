"""Concordia MCP Server — exposes the Concordia negotiation protocol as MCP tools.

Implements the tool interface described in §10.2 of the Concordia Protocol spec.
Any MCP-compatible agent can open sessions, exchange offers, and reach agreements
through structured tool calls.

Tools:
    open_session    — Create a new negotiation session with terms and timing
    propose         — Send an initial offer into an active session
    counter         — Send a counter-offer in response to the other party's offer
    accept          — Accept the current offer (ACTIVE → AGREED)
    reject          — Reject the negotiation (ACTIVE → REJECTED)
    commit          — Finalize an agreed deal with cryptographic commitment
    session_status  — Read current session state, transcript, and analytics
    session_receipt — Generate a reputation attestation for a concluded session

Usage:
    python -m concordia.mcp_server          # stdio transport (default)
    python -m concordia.mcp_server --sse    # SSE transport (HTTP)
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .agent import Agent
from .attestation import generate_attestation
from .message import validate_chain
from .offer import BasicOffer, ConditionalOffer, Condition, PartialOffer
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
        """Create a new session with a fresh agent pair and open it."""
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
# Tool implementations
# ---------------------------------------------------------------------------

# Global session store — shared across all tool invocations
_store = SessionStore()


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

def tool_open_session(
    initiator_id: str,
    responder_id: str,
    terms: dict[str, dict[str, Any]],
    session_ttl: int = 86400,
    offer_ttl: int = 3600,
    max_rounds: int = 20,
    reasoning: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Open a new Concordia negotiation session.

    Creates both agents, generates Ed25519 key pairs, opens the session,
    and auto-accepts on the responder side so negotiation can begin
    immediately.

    Returns session_id and agent public keys for verification.
    """
    timing = TimingConfig(
        session_ttl=session_ttl,
        offer_ttl=offer_ttl,
        max_rounds=max_rounds,
    )

    ctx = _store.create(
        initiator_id=initiator_id,
        responder_id=responder_id,
        terms=terms,
        timing=timing,
        reasoning=reasoning,
        metadata=metadata,
    )

    return {
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
        "terms": terms,
        "timing": {
            "session_ttl": session_ttl,
            "offer_ttl": offer_ttl,
            "max_rounds": max_rounds,
        },
        "transcript_length": len(ctx.session.transcript),
        "message": "Session opened and active. Both parties ready to negotiate.",
    }


# ---------------------------------------------------------------------------
# Tool: propose
# ---------------------------------------------------------------------------

def tool_propose(
    session_id: str,
    role: str,
    terms: dict[str, dict[str, Any]],
    offer_type: str = "basic",
    open_terms: list[str] | None = None,
    conditions: list[dict[str, Any]] | None = None,
    reasoning: str | None = None,
) -> dict[str, Any]:
    """Send an initial offer into an active session.

    The offering agent is identified by role ('initiator'/'seller' or
    'responder'/'buyer'). The offer is signed and appended to the
    cryptographic transcript.
    """
    ctx = _store.get(session_id)
    if ctx is None:
        return {"error": f"Session '{session_id}' not found."}

    if ctx.session.state != SessionState.ACTIVE:
        return {"error": f"Session is in state '{ctx.session.state.value}', not 'active'."}

    try:
        agent = _resolve_role(ctx, role)
        offer = _build_offer(terms, offer_type, open_terms, conditions)
        msg = agent.send_offer(offer, reasoning=reasoning)

        return {
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
    except (InvalidTransitionError, ValueError) as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Tool: counter
# ---------------------------------------------------------------------------

def tool_counter(
    session_id: str,
    role: str,
    terms: dict[str, dict[str, Any]],
    offer_type: str = "basic",
    open_terms: list[str] | None = None,
    conditions: list[dict[str, Any]] | None = None,
    reasoning: str | None = None,
) -> dict[str, Any]:
    """Send a counter-offer in response to the other party's offer.

    Same interface as propose, but semantically indicates a counter
    rather than an opening position. Signed and transcript-chained.
    """
    ctx = _store.get(session_id)
    if ctx is None:
        return {"error": f"Session '{session_id}' not found."}

    if ctx.session.state != SessionState.ACTIVE:
        return {"error": f"Session is in state '{ctx.session.state.value}', not 'active'."}

    try:
        agent = _resolve_role(ctx, role)
        offer = _build_offer(terms, offer_type, open_terms, conditions)
        msg = agent.send_counter(offer, reasoning=reasoning)

        return {
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
    except (InvalidTransitionError, ValueError) as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Tool: accept
# ---------------------------------------------------------------------------

def tool_accept(
    session_id: str,
    role: str,
    offer_id: str | None = None,
    reasoning: str | None = None,
) -> dict[str, Any]:
    """Accept the current offer, moving the session to AGREED.

    The accepting agent is identified by role. Optionally reference a
    specific offer_id to accept.
    """
    ctx = _store.get(session_id)
    if ctx is None:
        return {"error": f"Session '{session_id}' not found."}

    if ctx.session.state != SessionState.ACTIVE:
        return {"error": f"Session is in state '{ctx.session.state.value}', not 'active'."}

    try:
        agent = _resolve_role(ctx, role)
        msg = agent.accept_offer(offer_id=offer_id, reasoning=reasoning)

        return {
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
    except (InvalidTransitionError, ValueError) as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Tool: reject
# ---------------------------------------------------------------------------

def tool_reject(
    session_id: str,
    role: str,
    reason: str | None = None,
    reasoning: str | None = None,
) -> dict[str, Any]:
    """Reject the negotiation, moving the session to REJECTED.

    Optionally provide a structured reason and/or natural-language reasoning.
    """
    ctx = _store.get(session_id)
    if ctx is None:
        return {"error": f"Session '{session_id}' not found."}

    if ctx.session.state != SessionState.ACTIVE:
        return {"error": f"Session is in state '{ctx.session.state.value}', not 'active'."}

    try:
        agent = _resolve_role(ctx, role)
        msg = agent.reject_offer(reason=reason, reasoning=reasoning)

        return {
            "session_id": session_id,
            "message_id": msg.get("id", ""),
            "type": "negotiate.reject",
            "from": agent.agent_id,
            "state": ctx.session.state.value,
            "round_count": ctx.session.round_count,
            "transcript_length": len(ctx.session.transcript),
            "message": f"Negotiation rejected by {agent.agent_id}. Session is now REJECTED.",
        }
    except (InvalidTransitionError, ValueError) as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Tool: commit
# ---------------------------------------------------------------------------

def tool_commit(
    session_id: str,
    role: str,
    reasoning: str | None = None,
) -> dict[str, Any]:
    """Finalize an agreed deal with a cryptographic commitment.

    Can only be called when the session is in ACTIVE state (typically
    after both parties have signaled agreement through offers). The commit
    moves the session to AGREED and locks the transcript.
    """
    ctx = _store.get(session_id)
    if ctx is None:
        return {"error": f"Session '{session_id}' not found."}

    # commit is valid from ACTIVE state
    if ctx.session.state != SessionState.ACTIVE:
        return {"error": f"Session is in state '{ctx.session.state.value}', not 'active'."}

    try:
        agent = _resolve_role(ctx, role)
        msg = agent.commit(reasoning=reasoning)

        return {
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
    except (InvalidTransitionError, ValueError) as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Tool: session_status
# ---------------------------------------------------------------------------

def tool_session_status(
    session_id: str,
    include_transcript: bool = False,
    transcript_limit: int = 10,
) -> dict[str, Any]:
    """Get the current status of a negotiation session.

    Returns state, round count, timing, terms, behavioral analytics
    for both parties, and optionally a transcript summary.
    """
    ctx = _store.get(session_id)
    if ctx is None:
        return {"error": f"Session '{session_id}' not found."}

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

    return result


# ---------------------------------------------------------------------------
# Tool: session_receipt
# ---------------------------------------------------------------------------

def tool_session_receipt(
    session_id: str,
    category: str | None = None,
    value_range: str | None = None,
) -> dict[str, Any]:
    """Generate a cryptographic receipt (reputation attestation) for a concluded session.

    The receipt includes outcome, behavioral records for both parties,
    a transcript hash for verification, and Ed25519 signatures from
    both agents. Only available for sessions in a terminal state
    (AGREED, REJECTED, or EXPIRED).
    """
    ctx = _store.get(session_id)
    if ctx is None:
        return {"error": f"Session '{session_id}' not found."}

    session = ctx.session

    if not session.is_terminal:
        return {
            "error": f"Session is in state '{session.state.value}'. "
                     f"Receipts can only be generated for concluded sessions "
                     f"(agreed, rejected, or expired).",
        }

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

        return {
            "session_id": session_id,
            "receipt": attestation,
            "transcript_valid": validate_chain(session.transcript),
            "message": "Session receipt generated with cryptographic signatures from both parties.",
        }
    except (ValueError, RuntimeError) as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# MCP tool definitions — JSON Schema for each tool
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "concordia_open_session",
        "description": (
            "Open a new Concordia negotiation session between two agents. "
            "Creates both parties with Ed25519 key pairs, establishes the "
            "term space (what's being negotiated), and activates the session. "
            "Returns session_id and public keys for both parties."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "initiator_id": {
                    "type": "string",
                    "description": "Unique identifier for the initiating agent (e.g. 'agent_seller_01').",
                },
                "responder_id": {
                    "type": "string",
                    "description": "Unique identifier for the responding agent (e.g. 'agent_buyer_42').",
                },
                "terms": {
                    "type": "object",
                    "description": (
                        "The negotiation term space — a dict of term_id → term definition. "
                        "Each term has 'type', 'label', and optionally 'unit' and 'constraints'. "
                        "Example: {\"price\": {\"type\": \"numeric\", \"label\": \"Price\", \"unit\": \"USD\"}}"
                    ),
                    "additionalProperties": {"type": "object"},
                },
                "session_ttl": {
                    "type": "integer",
                    "description": "Session time-to-live in seconds (default: 86400 = 24 hours).",
                    "default": 86400,
                },
                "offer_ttl": {
                    "type": "integer",
                    "description": "Per-offer time-to-live in seconds (default: 3600 = 1 hour).",
                    "default": 3600,
                },
                "max_rounds": {
                    "type": "integer",
                    "description": "Maximum number of offer/counter rounds (default: 20).",
                    "default": 20,
                },
                "reasoning": {
                    "type": "string",
                    "description": "Optional natural-language reasoning for opening the session.",
                },
                "metadata": {
                    "type": "object",
                    "description": "Optional metadata to attach to the session (not part of the protocol).",
                },
            },
            "required": ["initiator_id", "responder_id", "terms"],
        },
    },
    {
        "name": "concordia_propose",
        "description": (
            "Send an initial offer into an active Concordia negotiation session. "
            "Specify which role is making the offer and the proposed term values. "
            "The offer is Ed25519-signed and appended to the cryptographic transcript."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session to send the offer into.",
                },
                "role": {
                    "type": "string",
                    "description": "Who is making the offer: 'initiator'/'seller' or 'responder'/'buyer'.",
                    "enum": ["initiator", "responder", "seller", "buyer"],
                },
                "terms": {
                    "type": "object",
                    "description": (
                        "The proposed values for each term. "
                        "Example: {\"price\": {\"value\": 850}, \"warranty\": {\"value\": \"12_months\"}}"
                    ),
                    "additionalProperties": {"type": "object"},
                },
                "offer_type": {
                    "type": "string",
                    "description": "Type of offer: 'basic' (default), 'partial', or 'conditional'.",
                    "enum": ["basic", "partial", "conditional"],
                    "default": "basic",
                },
                "open_terms": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "For partial offers: list of term_ids left open for negotiation.",
                },
                "conditions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "if": {"type": "object"},
                            "then": {"type": "object"},
                        },
                        "required": ["if", "then"],
                    },
                    "description": "For conditional offers: list of if/then clauses.",
                },
                "reasoning": {
                    "type": "string",
                    "description": "Natural-language reasoning explaining the offer.",
                },
            },
            "required": ["session_id", "role", "terms"],
        },
    },
    {
        "name": "concordia_counter",
        "description": (
            "Send a counter-offer in a Concordia negotiation session. "
            "Same interface as propose but semantically indicates a counter-position "
            "rather than an opening offer."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session to send the counter-offer into.",
                },
                "role": {
                    "type": "string",
                    "description": "Who is countering: 'initiator'/'seller' or 'responder'/'buyer'.",
                    "enum": ["initiator", "responder", "seller", "buyer"],
                },
                "terms": {
                    "type": "object",
                    "description": "The counter-proposed values for each term.",
                    "additionalProperties": {"type": "object"},
                },
                "offer_type": {
                    "type": "string",
                    "enum": ["basic", "partial", "conditional"],
                    "default": "basic",
                },
                "open_terms": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "For partial offers: term_ids left open.",
                },
                "conditions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "if": {"type": "object"},
                            "then": {"type": "object"},
                        },
                        "required": ["if", "then"],
                    },
                    "description": "For conditional offers: if/then clauses.",
                },
                "reasoning": {
                    "type": "string",
                    "description": "Natural-language reasoning explaining the counter-offer.",
                },
            },
            "required": ["session_id", "role", "terms"],
        },
    },
    {
        "name": "concordia_accept",
        "description": (
            "Accept the current offer in a Concordia negotiation, moving the "
            "session to AGREED state. The acceptance is Ed25519-signed and the "
            "full transcript hash chain is validated."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session in which to accept the offer.",
                },
                "role": {
                    "type": "string",
                    "description": "Who is accepting: 'initiator'/'seller' or 'responder'/'buyer'.",
                    "enum": ["initiator", "responder", "seller", "buyer"],
                },
                "offer_id": {
                    "type": "string",
                    "description": "Optional: specific offer_id to accept.",
                },
                "reasoning": {
                    "type": "string",
                    "description": "Natural-language reasoning for accepting.",
                },
            },
            "required": ["session_id", "role"],
        },
    },
    {
        "name": "concordia_reject",
        "description": (
            "Reject the negotiation, moving the session to REJECTED state. "
            "Optionally provide a reason and reasoning."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session to reject.",
                },
                "role": {
                    "type": "string",
                    "description": "Who is rejecting: 'initiator'/'seller' or 'responder'/'buyer'.",
                    "enum": ["initiator", "responder", "seller", "buyer"],
                },
                "reason": {
                    "type": "string",
                    "description": "Structured reason for rejection.",
                },
                "reasoning": {
                    "type": "string",
                    "description": "Natural-language reasoning for rejection.",
                },
            },
            "required": ["session_id", "role"],
        },
    },
    {
        "name": "concordia_commit",
        "description": (
            "Finalize an agreed deal with a cryptographic commitment. "
            "Locks the transcript and produces a verifiable agreement record. "
            "Only valid when the session is ACTIVE."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session to commit.",
                },
                "role": {
                    "type": "string",
                    "description": "Who is committing: 'initiator'/'seller' or 'responder'/'buyer'.",
                    "enum": ["initiator", "responder", "seller", "buyer"],
                },
                "reasoning": {
                    "type": "string",
                    "description": "Natural-language reasoning for the commitment.",
                },
            },
            "required": ["session_id", "role"],
        },
    },
    {
        "name": "concordia_session_status",
        "description": (
            "Get the current status of a Concordia negotiation session. "
            "Returns state, round count, terms, behavioral analytics for "
            "both parties, transcript validity, and optional message history."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session to query.",
                },
                "include_transcript": {
                    "type": "boolean",
                    "description": "Whether to include a transcript summary (default: false).",
                    "default": False,
                },
                "transcript_limit": {
                    "type": "integer",
                    "description": "Max number of recent messages to include in transcript summary.",
                    "default": 10,
                },
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "concordia_session_receipt",
        "description": (
            "Generate a cryptographic receipt (reputation attestation) for a "
            "concluded negotiation session. Includes outcome, behavioral records, "
            "transcript hash, and Ed25519 signatures from both parties. "
            "Only available for sessions in terminal state (agreed/rejected/expired)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The concluded session to generate a receipt for.",
                },
                "category": {
                    "type": "string",
                    "description": "Optional transaction category (e.g. 'electronics.cameras').",
                },
                "value_range": {
                    "type": "string",
                    "description": "Optional value bucket (e.g. '1000-5000_USD').",
                },
            },
            "required": ["session_id"],
        },
    },
]


# ---------------------------------------------------------------------------
# Tool dispatcher — routes MCP tool calls to implementations
# ---------------------------------------------------------------------------

_TOOL_HANDLERS: dict[str, Any] = {
    "concordia_open_session": tool_open_session,
    "concordia_propose": tool_propose,
    "concordia_counter": tool_counter,
    "concordia_accept": tool_accept,
    "concordia_reject": tool_reject,
    "concordia_commit": tool_commit,
    "concordia_session_status": tool_session_status,
    "concordia_session_receipt": tool_session_receipt,
}


def handle_tool_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatch an MCP tool call to the appropriate handler.

    This is the main entry point for MCP integration. Takes a tool name
    and arguments dict, returns the result dict.
    """
    handler = _TOOL_HANDLERS.get(name)
    if handler is None:
        return {"error": f"Unknown tool: '{name}'. Available: {list(_TOOL_HANDLERS.keys())}"}

    try:
        return handler(**arguments)
    except TypeError as e:
        return {"error": f"Invalid arguments for '{name}': {e}"}
    except Exception as e:
        return {"error": f"Tool '{name}' failed: {e}"}


def get_tool_definitions() -> list[dict[str, Any]]:
    """Return the MCP tool definitions for capability advertisement."""
    return TOOL_DEFINITIONS


# ---------------------------------------------------------------------------
# MCP JSON-RPC server (stdio transport)
# ---------------------------------------------------------------------------

def _handle_jsonrpc(request: dict[str, Any]) -> dict[str, Any]:
    """Handle a single JSON-RPC 2.0 request per MCP protocol."""
    method = request.get("method", "")
    req_id = request.get("id")
    params = request.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "concordia-mcp",
                    "version": "0.1.0",
                },
            },
        }

    elif method == "notifications/initialized":
        # Notification — no response needed
        return {}

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": get_tool_definitions()},
        }

    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        result = handle_tool_call(tool_name, arguments)

        is_error = "error" in result
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, indent=2, default=str),
                    }
                ],
                "isError": is_error,
            },
        }

    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}",
            },
        }


def run_stdio() -> None:
    """Run the MCP server on stdin/stdout (stdio transport).

    Reads JSON-RPC requests from stdin (one per line) and writes
    responses to stdout. This is the standard MCP stdio transport.
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            continue

        response = _handle_jsonrpc(request)

        # Notifications don't get responses
        if response:
            sys.stdout.write(json.dumps(response, default=str) + "\n")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_stdio()
