"""Concordia MCP Server — exposes the Concordia negotiation protocol as MCP tools.

Implements the tool interface described in §10.2 of the Concordia Protocol spec.
Any MCP-compatible agent can open sessions, exchange offers, and reach agreements
through structured tool calls.

Built on the official Python MCP SDK (``mcp`` package), matching the same SDK
family used by the Sanctuary Framework's TypeScript server. Both servers can
run side by side in a single MCP client configuration.

Tools:
    concordia_open_session    — Create a new negotiation session with terms and timing
    concordia_propose         — Send an initial offer into an active session
    concordia_counter         — Send a counter-offer in response to the other party's offer
    concordia_accept          — Accept the current offer (ACTIVE → AGREED)
    concordia_reject          — Reject the negotiation (ACTIVE → REJECTED)
    concordia_commit          — Finalize an agreed deal with cryptographic commitment
    concordia_session_status  — Read current session state, transcript, and analytics
    concordia_session_receipt — Generate a reputation attestation for a concluded session

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
# Internal helpers
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

    ctx = _store.create(
        initiator_id=initiator_id,
        responder_id=responder_id,
        terms=terms,
        timing=timing,
        reasoning=reasoning,
        metadata=metadata,
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
    offer_type: Annotated[str, "Type of offer: 'basic' (default), 'partial', or 'conditional'"] = "basic",
    open_terms: Annotated[list[str] | None, "For partial offers: list of term_ids left open"] = None,
    conditions: Annotated[list[dict] | None, "For conditional offers: list of {'if': ..., 'then': ...} clauses"] = None,
    reasoning: Annotated[str | None, "Natural-language reasoning explaining the offer"] = None,
) -> str:
    """Send an initial offer into an active session."""
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
    offer_type: Annotated[str, "Type of offer: 'basic', 'partial', or 'conditional'"] = "basic",
    open_terms: Annotated[list[str] | None, "For partial offers: term_ids left open"] = None,
    conditions: Annotated[list[dict] | None, "For conditional offers: if/then clauses"] = None,
    reasoning: Annotated[str | None, "Natural-language reasoning explaining the counter-offer"] = None,
) -> str:
    """Send a counter-offer in response to the other party's offer."""
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
    offer_id: Annotated[str | None, "Optional: specific offer_id to accept"] = None,
    reasoning: Annotated[str | None, "Natural-language reasoning for accepting"] = None,
) -> str:
    """Accept the current offer, moving the session to AGREED."""
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
    reason: Annotated[str | None, "Structured reason for rejection"] = None,
    reasoning: Annotated[str | None, "Natural-language reasoning for rejection"] = None,
) -> str:
    """Reject the negotiation, moving the session to REJECTED."""
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
    reasoning: Annotated[str | None, "Natural-language reasoning for the commitment"] = None,
) -> str:
    """Finalize an agreed deal with a cryptographic commitment."""
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
    include_transcript: Annotated[bool, "Whether to include a transcript summary (default: false)"] = False,
    transcript_limit: Annotated[int, "Max number of recent messages to include in transcript summary"] = 10,
) -> str:
    """Get the current status of a negotiation session."""
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
    category: Annotated[str | None, "Optional transaction category (e.g. 'electronics.cameras')"] = None,
    value_range: Annotated[str | None, "Optional value bucket (e.g. '1000-5000_USD')"] = None,
) -> str:
    """Generate a cryptographic receipt for a concluded session."""
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
