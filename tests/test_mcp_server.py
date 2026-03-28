"""Tests for the Concordia MCP Server (§10.2).

Covers all 8 MCP tools, session lifecycle flows, error handling,
JSON-RPC dispatch, and receipt generation.
"""

import json
import pytest

from concordia.mcp_server import (
    SessionStore,
    handle_tool_call,
    get_tool_definitions,
    tool_open_session,
    tool_propose,
    tool_counter,
    tool_accept,
    tool_reject,
    tool_commit,
    tool_session_status,
    tool_session_receipt,
    _handle_jsonrpc,
    _store,
)
from concordia.types import SessionState


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_TERMS = {
    "price": {
        "type": "numeric",
        "label": "Price",
        "unit": "USD",
    },
    "warranty": {
        "type": "categorical",
        "label": "Warranty Period",
    },
    "delivery": {
        "type": "temporal",
        "label": "Delivery Date",
    },
}

OFFER_TERMS = {
    "price": {"value": 1000},
    "warranty": {"value": "12_months"},
    "delivery": {"value": "2026-04-15"},
}

COUNTER_TERMS = {
    "price": {"value": 850},
    "warranty": {"value": "18_months"},
    "delivery": {"value": "2026-04-20"},
}


@pytest.fixture(autouse=True)
def clean_store():
    """Reset the global session store between tests."""
    _store._sessions.clear()
    yield
    _store._sessions.clear()


@pytest.fixture
def active_session():
    """Create an active session and return the result."""
    return tool_open_session(
        initiator_id="seller_01",
        responder_id="buyer_42",
        terms=SAMPLE_TERMS,
    )


@pytest.fixture
def session_with_offers(active_session):
    """Create a session with an offer and counter-offer exchanged."""
    sid = active_session["session_id"]
    tool_propose(
        session_id=sid,
        role="initiator",
        terms=OFFER_TERMS,
        reasoning="Opening offer — fair price for the condition.",
    )
    tool_counter(
        session_id=sid,
        role="responder",
        terms=COUNTER_TERMS,
        reasoning="Asking for lower price but longer warranty.",
    )
    return sid


# ---------------------------------------------------------------------------
# SessionStore unit tests
# ---------------------------------------------------------------------------

class TestSessionStore:
    """Unit tests for the SessionStore."""

    def test_create_session(self):
        store = SessionStore()
        ctx = store.create("agent_a", "agent_b", SAMPLE_TERMS)
        assert ctx.session.state == SessionState.ACTIVE
        assert ctx.initiator.agent_id == "agent_a"
        assert ctx.responder.agent_id == "agent_b"
        assert ctx.terms == SAMPLE_TERMS

    def test_get_session(self):
        store = SessionStore()
        ctx = store.create("agent_a", "agent_b", SAMPLE_TERMS)
        retrieved = store.get(ctx.session.session_id)
        assert retrieved is ctx

    def test_get_missing_session(self):
        store = SessionStore()
        assert store.get("nonexistent") is None

    def test_list_sessions(self):
        store = SessionStore()
        store.create("a1", "b1", SAMPLE_TERMS)
        store.create("a2", "b2", SAMPLE_TERMS)
        sessions = store.list_sessions()
        assert len(sessions) == 2
        assert all("session_id" in s for s in sessions)

    def test_session_has_transcript(self):
        """Opening + accepting should produce 2 transcript messages."""
        store = SessionStore()
        ctx = store.create("agent_a", "agent_b", SAMPLE_TERMS)
        # open + accept_session = 2 messages
        assert len(ctx.session.transcript) == 2


# ---------------------------------------------------------------------------
# Tool: open_session
# ---------------------------------------------------------------------------

class TestOpenSession:
    """Tests for concordia_open_session."""

    def test_basic_open(self, active_session):
        result = active_session
        assert "session_id" in result
        assert result["state"] == "active"
        assert result["initiator"]["agent_id"] == "seller_01"
        assert result["responder"]["agent_id"] == "buyer_42"
        assert "public_key" in result["initiator"]
        assert "public_key" in result["responder"]

    def test_open_with_custom_timing(self):
        result = tool_open_session(
            initiator_id="s", responder_id="b", terms=SAMPLE_TERMS,
            session_ttl=3600, offer_ttl=600, max_rounds=5,
        )
        assert result["timing"]["session_ttl"] == 3600
        assert result["timing"]["max_rounds"] == 5

    def test_open_with_metadata(self):
        result = tool_open_session(
            initiator_id="s", responder_id="b", terms=SAMPLE_TERMS,
            metadata={"marketplace": "test_market"},
        )
        assert result["session_id"]  # session created successfully

    def test_open_with_reasoning(self):
        result = tool_open_session(
            initiator_id="s", responder_id="b", terms=SAMPLE_TERMS,
            reasoning="Opening negotiation for a used camera.",
        )
        assert result["state"] == "active"

    def test_terms_preserved(self, active_session):
        assert active_session["terms"] == SAMPLE_TERMS


# ---------------------------------------------------------------------------
# Tool: propose
# ---------------------------------------------------------------------------

class TestPropose:
    """Tests for concordia_propose."""

    def test_basic_propose(self, active_session):
        sid = active_session["session_id"]
        result = tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
        )
        assert result["type"] == "negotiate.offer"
        assert result["from"] == "seller_01"
        assert result["round_count"] == 1

    def test_propose_with_reasoning(self, active_session):
        sid = active_session["session_id"]
        result = tool_propose(
            session_id=sid, role="seller", terms=OFFER_TERMS,
            reasoning="Fair market value based on recent comparables.",
        )
        assert "error" not in result
        assert result["message_id"]

    def test_propose_as_buyer(self, active_session):
        sid = active_session["session_id"]
        result = tool_propose(
            session_id=sid, role="buyer", terms=OFFER_TERMS,
        )
        assert result["from"] == "buyer_42"

    def test_propose_missing_session(self):
        result = tool_propose(
            session_id="fake_id", role="initiator", terms=OFFER_TERMS,
        )
        assert "error" in result

    def test_propose_invalid_role(self, active_session):
        sid = active_session["session_id"]
        result = tool_propose(
            session_id=sid, role="spectator", terms=OFFER_TERMS,
        )
        assert "error" in result

    def test_propose_partial_offer(self, active_session):
        sid = active_session["session_id"]
        result = tool_propose(
            session_id=sid, role="initiator",
            terms={"price": {"value": 900}},
            offer_type="partial",
            open_terms=["warranty", "delivery"],
        )
        assert "error" not in result

    def test_propose_conditional_offer(self, active_session):
        sid = active_session["session_id"]
        result = tool_propose(
            session_id=sid, role="initiator",
            terms=OFFER_TERMS,
            offer_type="conditional",
            conditions=[{
                "if": {"warranty": {"value": "24_months"}},
                "then": {"price": {"value": 1100}},
            }],
        )
        assert "error" not in result


# ---------------------------------------------------------------------------
# Tool: counter
# ---------------------------------------------------------------------------

class TestCounter:
    """Tests for concordia_counter."""

    def test_basic_counter(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        result = tool_counter(
            session_id=sid, role="responder", terms=COUNTER_TERMS,
        )
        assert result["type"] == "negotiate.counter"
        assert result["from"] == "buyer_42"
        assert result["round_count"] == 2

    def test_counter_with_reasoning(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        result = tool_counter(
            session_id=sid, role="responder", terms=COUNTER_TERMS,
            reasoning="Price is too high for current market conditions.",
        )
        assert "error" not in result

    def test_counter_missing_session(self):
        result = tool_counter(
            session_id="fake", role="responder", terms=COUNTER_TERMS,
        )
        assert "error" in result


# ---------------------------------------------------------------------------
# Tool: accept
# ---------------------------------------------------------------------------

class TestAccept:
    """Tests for concordia_accept."""

    def test_accept_after_offer(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        result = tool_accept(session_id=sid, role="responder")
        assert result["state"] == "agreed"
        assert result["transcript_valid"] is True

    def test_accept_with_reasoning(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        result = tool_accept(
            session_id=sid, role="buyer",
            reasoning="Terms are acceptable.",
        )
        assert result["state"] == "agreed"

    def test_accept_after_counter_exchange(self, session_with_offers):
        sid = session_with_offers
        result = tool_accept(
            session_id=sid, role="initiator",
            reasoning="I'll take the counter-offer terms.",
        )
        assert result["state"] == "agreed"

    def test_accept_missing_session(self):
        result = tool_accept(session_id="fake", role="responder")
        assert "error" in result

    def test_cannot_accept_already_agreed(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        tool_accept(session_id=sid, role="responder")
        # Session is now AGREED — accepting again should fail
        result = tool_accept(session_id=sid, role="initiator")
        assert "error" in result


# ---------------------------------------------------------------------------
# Tool: reject
# ---------------------------------------------------------------------------

class TestReject:
    """Tests for concordia_reject."""

    def test_basic_reject(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        result = tool_reject(
            session_id=sid, role="responder",
            reason="price_too_high",
            reasoning="The asking price exceeds my budget.",
        )
        assert result["state"] == "rejected"

    def test_reject_without_offer(self, active_session):
        """Reject is valid from ACTIVE even without an offer exchange."""
        sid = active_session["session_id"]
        result = tool_reject(session_id=sid, role="responder")
        assert result["state"] == "rejected"

    def test_cannot_reject_already_rejected(self, active_session):
        sid = active_session["session_id"]
        tool_reject(session_id=sid, role="responder")
        result = tool_reject(session_id=sid, role="initiator")
        assert "error" in result


# ---------------------------------------------------------------------------
# Tool: commit
# ---------------------------------------------------------------------------

class TestCommit:
    """Tests for concordia_commit."""

    def test_commit_from_active(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        result = tool_commit(session_id=sid, role="initiator")
        assert result["state"] == "agreed"
        assert result["transcript_valid"] is True

    def test_commit_with_reasoning(self, session_with_offers):
        sid = session_with_offers
        result = tool_commit(
            session_id=sid, role="responder",
            reasoning="Both parties satisfied. Finalizing deal.",
        )
        assert result["state"] == "agreed"

    def test_cannot_commit_from_rejected(self, active_session):
        sid = active_session["session_id"]
        tool_reject(session_id=sid, role="responder")
        result = tool_commit(session_id=sid, role="initiator")
        assert "error" in result


# ---------------------------------------------------------------------------
# Tool: session_status
# ---------------------------------------------------------------------------

class TestSessionStatus:
    """Tests for concordia_session_status."""

    def test_basic_status(self, active_session):
        sid = active_session["session_id"]
        result = tool_session_status(session_id=sid)
        assert result["state"] == "active"
        assert result["initiator"] == "seller_01"
        assert result["responder"] == "buyer_42"
        assert result["transcript_valid"] is True
        assert result["is_terminal"] is False

    def test_status_with_transcript(self, session_with_offers):
        sid = session_with_offers
        result = tool_session_status(
            session_id=sid, include_transcript=True, transcript_limit=5,
        )
        assert "transcript" in result
        assert len(result["transcript"]) > 0
        # Should have open + accept_session + offer + counter = 4 messages
        assert result["transcript_length"] == 4

    def test_status_shows_behaviors(self, session_with_offers):
        sid = session_with_offers
        result = tool_session_status(session_id=sid)
        behaviors = result["behaviors"]
        assert "seller_01" in behaviors
        assert "buyer_42" in behaviors
        assert behaviors["seller_01"]["offers_made"] == 1
        assert behaviors["buyer_42"]["offers_made"] == 1

    def test_status_after_agreement(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        tool_accept(session_id=sid, role="responder")
        result = tool_session_status(session_id=sid)
        assert result["state"] == "agreed"
        assert result["is_terminal"] is True
        assert "concluded_at" in result

    def test_status_missing_session(self):
        result = tool_session_status(session_id="fake")
        assert "error" in result

    def test_status_includes_timing(self, active_session):
        sid = active_session["session_id"]
        result = tool_session_status(session_id=sid)
        assert result["timing"]["session_ttl"] == 86400
        assert result["timing"]["offer_ttl"] == 3600
        assert result["timing"]["max_rounds"] == 20

    def test_status_includes_duration(self, active_session):
        sid = active_session["session_id"]
        result = tool_session_status(session_id=sid)
        assert "duration_seconds" in result
        assert result["duration_seconds"] >= 0


# ---------------------------------------------------------------------------
# Tool: session_receipt
# ---------------------------------------------------------------------------

class TestSessionReceipt:
    """Tests for concordia_session_receipt."""

    def test_receipt_after_agreement(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        tool_accept(session_id=sid, role="responder")
        result = tool_session_receipt(session_id=sid)
        assert "receipt" in result
        receipt = result["receipt"]
        assert receipt["concordia_attestation"] == "0.1.0"
        assert receipt["outcome"]["status"] == "agreed"
        assert len(receipt["parties"]) == 2
        assert result["transcript_valid"] is True

    def test_receipt_with_category(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        tool_accept(session_id=sid, role="responder")
        result = tool_session_receipt(
            session_id=sid,
            category="electronics.cameras",
            value_range="500-1000_USD",
        )
        receipt = result["receipt"]
        assert receipt["meta"]["category"] == "electronics.cameras"
        assert receipt["meta"]["value_range"] == "500-1000_USD"

    def test_receipt_after_rejection(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        tool_reject(session_id=sid, role="responder", reason="too_expensive")
        result = tool_session_receipt(session_id=sid)
        receipt = result["receipt"]
        assert receipt["outcome"]["status"] == "rejected"
        assert receipt["outcome"]["resolution_mechanism"] == "none"

    def test_receipt_not_available_for_active_session(self, active_session):
        sid = active_session["session_id"]
        result = tool_session_receipt(session_id=sid)
        assert "error" in result

    def test_receipt_missing_session(self):
        result = tool_session_receipt(session_id="fake")
        assert "error" in result

    def test_receipt_has_signatures(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        tool_accept(session_id=sid, role="responder")
        result = tool_session_receipt(session_id=sid)
        for party in result["receipt"]["parties"]:
            assert party["signature"]  # non-empty signature
            assert len(party["signature"]) > 0

    def test_receipt_has_transcript_hash(self, active_session):
        sid = active_session["session_id"]
        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        tool_accept(session_id=sid, role="responder")
        result = tool_session_receipt(session_id=sid)
        assert result["receipt"]["transcript_hash"].startswith("sha256:")


# ---------------------------------------------------------------------------
# Full negotiation lifecycle
# ---------------------------------------------------------------------------

class TestFullLifecycle:
    """End-to-end negotiation flows through the MCP tool interface."""

    def test_open_propose_accept(self):
        """Simplest possible deal: open, propose, accept."""
        session = tool_open_session(
            initiator_id="seller", responder_id="buyer", terms=SAMPLE_TERMS,
        )
        sid = session["session_id"]

        tool_propose(session_id=sid, role="seller", terms=OFFER_TERMS)
        result = tool_accept(session_id=sid, role="buyer")
        assert result["state"] == "agreed"

    def test_multi_round_negotiation(self):
        """Multiple rounds of offers and counters before agreement."""
        session = tool_open_session(
            initiator_id="seller", responder_id="buyer", terms=SAMPLE_TERMS,
        )
        sid = session["session_id"]

        # Round 1: seller opens high
        tool_propose(session_id=sid, role="seller", terms={
            "price": {"value": 1200}, "warranty": {"value": "6_months"},
            "delivery": {"value": "2026-04-10"},
        })

        # Round 2: buyer counters low
        tool_counter(session_id=sid, role="buyer", terms={
            "price": {"value": 700}, "warranty": {"value": "24_months"},
            "delivery": {"value": "2026-04-30"},
        })

        # Round 3: seller moves toward middle
        tool_counter(session_id=sid, role="seller", terms={
            "price": {"value": 950}, "warranty": {"value": "12_months"},
            "delivery": {"value": "2026-04-15"},
        })

        # Round 4: buyer accepts
        result = tool_accept(
            session_id=sid, role="buyer",
            reasoning="Good compromise. I accept.",
        )
        assert result["state"] == "agreed"

        # Verify analytics
        status = tool_session_status(session_id=sid)
        assert status["round_count"] == 3  # 3 offer/counter rounds
        assert status["behaviors"]["seller"]["offers_made"] == 2
        assert status["behaviors"]["buyer"]["offers_made"] == 1

        # Generate receipt
        receipt = tool_session_receipt(
            session_id=sid, category="electronics",
        )
        assert receipt["receipt"]["outcome"]["status"] == "agreed"
        assert receipt["receipt"]["outcome"]["rounds"] == 3

    def test_rejection_flow(self):
        """Open, propose, reject, generate receipt."""
        session = tool_open_session(
            initiator_id="seller", responder_id="buyer", terms=SAMPLE_TERMS,
        )
        sid = session["session_id"]

        tool_propose(session_id=sid, role="seller", terms=OFFER_TERMS)
        tool_reject(
            session_id=sid, role="buyer",
            reason="no_deal",
            reasoning="Cannot afford at any reasonable price point.",
        )

        status = tool_session_status(session_id=sid)
        assert status["state"] == "rejected"
        assert status["is_terminal"] is True

        receipt = tool_session_receipt(session_id=sid)
        assert receipt["receipt"]["outcome"]["status"] == "rejected"

    def test_commit_flow(self):
        """Open, exchange offers, commit to finalize."""
        session = tool_open_session(
            initiator_id="seller", responder_id="buyer", terms=SAMPLE_TERMS,
        )
        sid = session["session_id"]

        tool_propose(session_id=sid, role="seller", terms=OFFER_TERMS)
        tool_counter(session_id=sid, role="buyer", terms=COUNTER_TERMS)
        result = tool_commit(
            session_id=sid, role="seller",
            reasoning="Committing to the buyer's counter-offer terms.",
        )
        assert result["state"] == "agreed"

    def test_transcript_integrity(self):
        """Verify the hash chain remains valid through a full negotiation."""
        session = tool_open_session(
            initiator_id="s", responder_id="b", terms=SAMPLE_TERMS,
        )
        sid = session["session_id"]

        tool_propose(session_id=sid, role="initiator", terms=OFFER_TERMS)
        tool_counter(session_id=sid, role="responder", terms=COUNTER_TERMS)
        tool_accept(session_id=sid, role="initiator")

        status = tool_session_status(session_id=sid)
        assert status["transcript_valid"] is True
        assert status["transcript_length"] == 5  # open + accept_session + offer + counter + accept


# ---------------------------------------------------------------------------
# handle_tool_call dispatcher
# ---------------------------------------------------------------------------

class TestToolDispatcher:
    """Tests for the central handle_tool_call dispatcher."""

    def test_dispatch_open_session(self):
        result = handle_tool_call("concordia_open_session", {
            "initiator_id": "a", "responder_id": "b", "terms": SAMPLE_TERMS,
        })
        assert "session_id" in result

    def test_dispatch_unknown_tool(self):
        result = handle_tool_call("nonexistent_tool", {})
        assert "error" in result
        assert "Unknown tool" in result["error"]

    def test_dispatch_bad_arguments(self):
        result = handle_tool_call("concordia_open_session", {
            "bad_param": "value",
        })
        assert "error" in result

    def test_dispatch_all_tools_registered(self):
        """Every tool definition has a corresponding handler."""
        defs = get_tool_definitions()
        for tool_def in defs:
            result = handle_tool_call(tool_def["name"], {})
            # Should either work or give a meaningful error, not "Unknown tool"
            if "error" in result:
                assert "Unknown tool" not in result["error"]


# ---------------------------------------------------------------------------
# JSON-RPC protocol handling
# ---------------------------------------------------------------------------

class TestJsonRpc:
    """Tests for the JSON-RPC 2.0 server layer."""

    def test_initialize(self):
        response = _handle_jsonrpc({
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        })
        assert response["id"] == 1
        assert response["result"]["serverInfo"]["name"] == "concordia-mcp"
        assert "tools" in response["result"]["capabilities"]

    def test_tools_list(self):
        response = _handle_jsonrpc({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        })
        tools = response["result"]["tools"]
        assert len(tools) == 8
        tool_names = {t["name"] for t in tools}
        assert "concordia_open_session" in tool_names
        assert "concordia_propose" in tool_names
        assert "concordia_accept" in tool_names
        assert "concordia_session_receipt" in tool_names

    def test_tools_call(self):
        response = _handle_jsonrpc({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "concordia_open_session",
                "arguments": {
                    "initiator_id": "s", "responder_id": "b",
                    "terms": SAMPLE_TERMS,
                },
            },
        })
        assert response["id"] == 3
        content = response["result"]["content"]
        assert len(content) == 1
        assert content[0]["type"] == "text"
        parsed = json.loads(content[0]["text"])
        assert "session_id" in parsed

    def test_tools_call_error(self):
        response = _handle_jsonrpc({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "concordia_session_status", "arguments": {
                "session_id": "nonexistent",
            }},
        })
        content = response["result"]["content"]
        parsed = json.loads(content[0]["text"])
        assert "error" in parsed
        assert response["result"]["isError"] is True

    def test_unknown_method(self):
        response = _handle_jsonrpc({
            "jsonrpc": "2.0", "id": 5, "method": "unknown/method", "params": {},
        })
        assert "error" in response
        assert response["error"]["code"] == -32601

    def test_notification_no_response(self):
        response = _handle_jsonrpc({
            "jsonrpc": "2.0", "method": "notifications/initialized", "params": {},
        })
        assert response == {}


# ---------------------------------------------------------------------------
# Tool definitions schema validation
# ---------------------------------------------------------------------------

class TestToolDefinitions:
    """Verify tool definitions are well-formed for MCP advertisement."""

    def test_all_tools_have_required_fields(self):
        for tool in get_tool_definitions():
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool
            assert tool["inputSchema"]["type"] == "object"
            assert "properties" in tool["inputSchema"]

    def test_all_tools_have_required_params(self):
        for tool in get_tool_definitions():
            schema = tool["inputSchema"]
            if "required" in schema:
                props = set(schema["properties"].keys())
                for req in schema["required"]:
                    assert req in props, f"{tool['name']}: required param '{req}' not in properties"

    def test_tool_count(self):
        assert len(get_tool_definitions()) == 8

    def test_tool_names_match_handlers(self):
        from concordia.mcp_server import _TOOL_HANDLERS
        def_names = {t["name"] for t in get_tool_definitions()}
        handler_names = set(_TOOL_HANDLERS.keys())
        assert def_names == handler_names
