"""Tests for the Concordia MCP Server (§10.2).

Covers all 45 MCP tools, session lifecycle flows, error handling,
tool dispatch, receipt generation, and SDK integration.
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
    mcp,
    _store,
    _auth,
)
from concordia.types import SessionState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse(result_str: str) -> dict:
    """Parse a JSON string tool result back to a dict."""
    return json.loads(result_str)


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
    """Reset the global session store and auth tokens between tests."""
    _store._sessions.clear()
    _auth._agent_tokens.clear()
    _auth._session_tokens.clear()
    _auth._token_to_agent.clear()
    yield
    _store._sessions.clear()
    _auth._agent_tokens.clear()
    _auth._session_tokens.clear()
    _auth._token_to_agent.clear()


@pytest.fixture
def active_session():
    """Create an active session and return the parsed result."""
    result_str = tool_open_session(
        initiator_id="seller_01",
        responder_id="buyer_42",
        terms=SAMPLE_TERMS,
    )
    return _parse(result_str)


@pytest.fixture
def session_with_offers(active_session):
    """Create a session with an offer and counter-offer exchanged."""
    sid = active_session["session_id"]
    tool_propose(
        session_id=sid,
        role="initiator",
        terms=OFFER_TERMS,
        auth_token=active_session["initiator_token"],
        reasoning="Opening offer — fair price for the condition.",
    )
    tool_counter(
        session_id=sid,
        role="responder",
        terms=COUNTER_TERMS,
        auth_token=active_session["responder_token"],
        reasoning="Asking for lower price but longer warranty.",
    )
    return active_session


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
        result = _parse(tool_open_session(
            initiator_id="s", responder_id="b", terms=SAMPLE_TERMS,
            session_ttl=3600, offer_ttl=600, max_rounds=5,
        ))
        assert result["timing"]["session_ttl"] == 3600
        assert result["timing"]["max_rounds"] == 5

    def test_open_with_metadata(self):
        result = _parse(tool_open_session(
            initiator_id="s", responder_id="b", terms=SAMPLE_TERMS,
            metadata={"marketplace": "test_market"},
        ))
        assert result["session_id"]  # session created successfully

    def test_open_with_reasoning(self):
        result = _parse(tool_open_session(
            initiator_id="s", responder_id="b", terms=SAMPLE_TERMS,
            reasoning="Opening negotiation for a used camera.",
        ))
        assert result["state"] == "active"

    def test_terms_preserved(self, active_session):
        assert active_session["terms"] == SAMPLE_TERMS

    def test_returns_valid_json(self):
        """Tool functions return valid JSON strings."""
        result_str = tool_open_session(
            initiator_id="s", responder_id="b", terms=SAMPLE_TERMS,
        )
        assert isinstance(result_str, str)
        parsed = json.loads(result_str)
        assert "session_id" in parsed


# ---------------------------------------------------------------------------
# Tool: propose
# ---------------------------------------------------------------------------

class TestPropose:
    """Tests for concordia_propose."""

    def test_basic_propose(self, active_session):
        sid = active_session["session_id"]
        result = _parse(tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        ))
        assert result["type"] == "negotiate.offer"
        assert result["from"] == "seller_01"
        assert result["round_count"] == 1

    def test_propose_with_reasoning(self, active_session):
        sid = active_session["session_id"]
        result = _parse(tool_propose(
            session_id=sid, role="seller", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
            reasoning="Fair market value based on recent comparables.",
        ))
        assert "error" not in result
        assert result["message_id"]

    def test_propose_as_buyer(self, active_session):
        sid = active_session["session_id"]
        result = _parse(tool_propose(
            session_id=sid, role="buyer", terms=OFFER_TERMS,
            auth_token=active_session["responder_token"],
        ))
        assert result["from"] == "buyer_42"

    def test_propose_missing_session(self):
        result = _parse(tool_propose(
            session_id="fake_id", role="initiator", terms=OFFER_TERMS,
            auth_token="fake_token",
        ))
        assert "error" in result

    def test_propose_invalid_role(self, active_session):
        sid = active_session["session_id"]
        result = _parse(tool_propose(
            session_id=sid, role="spectator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        ))
        assert "error" in result

    def test_propose_partial_offer(self, active_session):
        sid = active_session["session_id"]
        result = _parse(tool_propose(
            session_id=sid, role="initiator",
            terms={"price": {"value": 900}},
            offer_type="partial",
            open_terms=["warranty", "delivery"],
            auth_token=active_session["initiator_token"],
        ))
        assert "error" not in result

    def test_propose_conditional_offer(self, active_session):
        sid = active_session["session_id"]
        result = _parse(tool_propose(
            session_id=sid, role="initiator",
            terms=OFFER_TERMS,
            offer_type="conditional",
            conditions=[{
                "if": {"warranty": {"value": "24_months"}},
                "then": {"price": {"value": 1100}},
            }],
            auth_token=active_session["initiator_token"],
        ))
        assert "error" not in result


# ---------------------------------------------------------------------------
# Tool: counter
# ---------------------------------------------------------------------------

class TestCounter:
    """Tests for concordia_counter."""

    def test_basic_counter(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        result = _parse(tool_counter(
            session_id=sid, role="responder", terms=COUNTER_TERMS,
            auth_token=active_session["responder_token"],
        ))
        assert result["type"] == "negotiate.counter"
        assert result["from"] == "buyer_42"
        assert result["round_count"] == 2

    def test_counter_with_reasoning(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        result = _parse(tool_counter(
            session_id=sid, role="responder", terms=COUNTER_TERMS,
            auth_token=active_session["responder_token"],
            reasoning="Price is too high for current market conditions.",
        ))
        assert "error" not in result

    def test_counter_missing_session(self):
        result = _parse(tool_counter(
            session_id="fake", role="responder", terms=COUNTER_TERMS,
            auth_token="fake_token",
        ))
        assert "error" in result


# ---------------------------------------------------------------------------
# Tool: accept
# ---------------------------------------------------------------------------

class TestAccept:
    """Tests for concordia_accept."""

    def test_accept_after_offer(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        result = _parse(tool_accept(
            session_id=sid, role="responder",
            auth_token=active_session["responder_token"],
        ))
        assert result["state"] == "agreed"
        assert result["transcript_valid"] is True

    def test_accept_with_reasoning(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        result = _parse(tool_accept(
            session_id=sid, role="buyer",
            auth_token=active_session["responder_token"],
            reasoning="Terms are acceptable.",
        ))
        assert result["state"] == "agreed"

    def test_accept_after_counter_exchange(self, session_with_offers):
        sid = session_with_offers["session_id"]
        result = _parse(tool_accept(
            session_id=sid, role="initiator",
            auth_token=session_with_offers["initiator_token"],
            reasoning="I'll take the counter-offer terms.",
        ))
        assert result["state"] == "agreed"

    def test_accept_missing_session(self):
        result = _parse(tool_accept(
            session_id="fake", role="responder",
            auth_token="fake_token",
        ))
        assert "error" in result

    def test_cannot_accept_already_agreed(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        tool_accept(
            session_id=sid, role="responder",
            auth_token=active_session["responder_token"],
        )
        # Session is now AGREED — accepting again should fail
        result = _parse(tool_accept(
            session_id=sid, role="initiator",
            auth_token=active_session["initiator_token"],
        ))
        assert "error" in result


# ---------------------------------------------------------------------------
# Tool: reject
# ---------------------------------------------------------------------------

class TestReject:
    """Tests for concordia_reject."""

    def test_basic_reject(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        result = _parse(tool_reject(
            session_id=sid, role="responder",
            auth_token=active_session["responder_token"],
            reason="price_too_high",
            reasoning="The asking price exceeds my budget.",
        ))
        assert result["state"] == "rejected"

    def test_reject_without_offer(self, active_session):
        """Reject is valid from ACTIVE even without an offer exchange."""
        sid = active_session["session_id"]
        result = _parse(tool_reject(
            session_id=sid, role="responder",
            auth_token=active_session["responder_token"],
        ))
        assert result["state"] == "rejected"

    def test_cannot_reject_already_rejected(self, active_session):
        sid = active_session["session_id"]
        tool_reject(
            session_id=sid, role="responder",
            auth_token=active_session["responder_token"],
        )
        result = _parse(tool_reject(
            session_id=sid, role="initiator",
            auth_token=active_session["initiator_token"],
        ))
        assert "error" in result


# ---------------------------------------------------------------------------
# Tool: commit
# ---------------------------------------------------------------------------

class TestCommit:
    """Tests for concordia_commit."""

    def test_commit_from_active(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        result = _parse(tool_commit(
            session_id=sid, role="initiator",
            auth_token=active_session["initiator_token"],
        ))
        assert result["state"] == "agreed"
        assert result["transcript_valid"] is True

    def test_commit_with_reasoning(self, session_with_offers):
        sid = session_with_offers["session_id"]
        result = _parse(tool_commit(
            session_id=sid, role="responder",
            auth_token=session_with_offers["responder_token"],
            reasoning="Both parties satisfied. Finalizing deal.",
        ))
        assert result["state"] == "agreed"

    def test_cannot_commit_from_rejected(self, active_session):
        sid = active_session["session_id"]
        tool_reject(
            session_id=sid, role="responder",
            auth_token=active_session["responder_token"],
        )
        result = _parse(tool_commit(
            session_id=sid, role="initiator",
            auth_token=active_session["initiator_token"],
        ))
        assert "error" in result


# ---------------------------------------------------------------------------
# Tool: session_status
# ---------------------------------------------------------------------------

class TestSessionStatus:
    """Tests for concordia_session_status."""

    def test_basic_status(self, active_session):
        sid = active_session["session_id"]
        result = _parse(tool_session_status(
            session_id=sid,
            auth_token=active_session["initiator_token"],
        ))
        assert result["state"] == "active"
        assert result["initiator"] == "seller_01"
        assert result["responder"] == "buyer_42"
        assert result["transcript_valid"] is True
        assert result["is_terminal"] is False

    def test_status_with_transcript(self, session_with_offers):
        sid = session_with_offers["session_id"]
        result = _parse(tool_session_status(
            session_id=sid, include_transcript=True, transcript_limit=5,
            auth_token=session_with_offers["initiator_token"],
        ))
        assert "transcript" in result
        assert len(result["transcript"]) > 0
        # Should have open + accept_session + offer + counter = 4 messages
        assert result["transcript_length"] == 4

    def test_status_shows_behaviors(self, session_with_offers):
        sid = session_with_offers["session_id"]
        result = _parse(tool_session_status(
            session_id=sid,
            auth_token=session_with_offers["initiator_token"],
        ))
        behaviors = result["behaviors"]
        assert "seller_01" in behaviors
        assert "buyer_42" in behaviors
        assert behaviors["seller_01"]["offers_made"] == 1
        assert behaviors["buyer_42"]["offers_made"] == 1

    def test_status_after_agreement(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        tool_accept(
            session_id=sid, role="responder",
            auth_token=active_session["responder_token"],
        )
        result = _parse(tool_session_status(
            session_id=sid,
            auth_token=active_session["initiator_token"],
        ))
        assert result["state"] == "agreed"
        assert result["is_terminal"] is True
        assert "concluded_at" in result

    def test_status_missing_session(self):
        result = _parse(tool_session_status(
            session_id="fake",
            auth_token="fake_token",
        ))
        assert "error" in result

    def test_status_includes_timing(self, active_session):
        sid = active_session["session_id"]
        result = _parse(tool_session_status(
            session_id=sid,
            auth_token=active_session["initiator_token"],
        ))
        assert result["timing"]["session_ttl"] == 86400
        assert result["timing"]["offer_ttl"] == 3600
        assert result["timing"]["max_rounds"] == 20

    def test_status_includes_duration(self, active_session):
        sid = active_session["session_id"]
        result = _parse(tool_session_status(
            session_id=sid,
            auth_token=active_session["initiator_token"],
        ))
        assert "duration_seconds" in result
        assert result["duration_seconds"] >= 0


# ---------------------------------------------------------------------------
# Tool: session_receipt
# ---------------------------------------------------------------------------

class TestSessionReceipt:
    """Tests for concordia_session_receipt."""

    def test_receipt_after_agreement(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        tool_accept(
            session_id=sid, role="responder",
            auth_token=active_session["responder_token"],
        )
        result = _parse(tool_session_receipt(
            session_id=sid,
            auth_token=active_session["initiator_token"],
        ))
        assert "receipt" in result
        receipt = result["receipt"]
        assert receipt["concordia_attestation"] == "0.1.0"
        assert receipt["outcome"]["status"] == "agreed"
        assert len(receipt["parties"]) == 2
        assert result["transcript_valid"] is True

    def test_receipt_with_category(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        tool_accept(
            session_id=sid, role="responder",
            auth_token=active_session["responder_token"],
        )
        result = _parse(tool_session_receipt(
            session_id=sid,
            category="electronics.cameras",
            value_range="500-1000_USD",
            auth_token=active_session["initiator_token"],
        ))
        receipt = result["receipt"]
        assert receipt["meta"]["category"] == "electronics.cameras"
        assert receipt["meta"]["value_range"] == "500-1000_USD"

    def test_receipt_after_rejection(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        tool_reject(
            session_id=sid, role="responder", reason="too_expensive",
            auth_token=active_session["responder_token"],
        )
        result = _parse(tool_session_receipt(
            session_id=sid,
            auth_token=active_session["initiator_token"],
        ))
        receipt = result["receipt"]
        assert receipt["outcome"]["status"] == "rejected"
        assert receipt["outcome"]["resolution_mechanism"] == "none"

    def test_receipt_not_available_for_active_session(self, active_session):
        sid = active_session["session_id"]
        result = _parse(tool_session_receipt(
            session_id=sid,
            auth_token=active_session["initiator_token"],
        ))
        assert "error" in result

    def test_receipt_missing_session(self):
        result = _parse(tool_session_receipt(
            session_id="fake",
            auth_token="fake_token",
        ))
        assert "error" in result

    def test_receipt_has_signatures(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        tool_accept(
            session_id=sid, role="responder",
            auth_token=active_session["responder_token"],
        )
        result = _parse(tool_session_receipt(
            session_id=sid,
            auth_token=active_session["initiator_token"],
        ))
        for party in result["receipt"]["parties"]:
            assert party["signature"]  # non-empty signature
            assert len(party["signature"]) > 0

    def test_receipt_has_transcript_hash(self, active_session):
        sid = active_session["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=active_session["initiator_token"],
        )
        tool_accept(
            session_id=sid, role="responder",
            auth_token=active_session["responder_token"],
        )
        result = _parse(tool_session_receipt(
            session_id=sid,
            auth_token=active_session["initiator_token"],
        ))
        assert result["receipt"]["transcript_hash"].startswith("sha256:")


# ---------------------------------------------------------------------------
# Full negotiation lifecycle
# ---------------------------------------------------------------------------

class TestFullLifecycle:
    """End-to-end negotiation flows through the MCP tool interface."""

    def test_open_propose_accept(self):
        """Simplest possible deal: open, propose, accept."""
        session = _parse(tool_open_session(
            initiator_id="seller", responder_id="buyer", terms=SAMPLE_TERMS,
        ))
        sid = session["session_id"]

        tool_propose(
            session_id=sid, role="seller", terms=OFFER_TERMS,
            auth_token=session["initiator_token"],
        )
        result = _parse(tool_accept(
            session_id=sid, role="buyer",
            auth_token=session["responder_token"],
        ))
        assert result["state"] == "agreed"

    def test_multi_round_negotiation(self):
        """Multiple rounds of offers and counters before agreement."""
        session = _parse(tool_open_session(
            initiator_id="seller", responder_id="buyer", terms=SAMPLE_TERMS,
        ))
        sid = session["session_id"]

        # Round 1: seller opens high
        tool_propose(session_id=sid, role="seller", terms={
            "price": {"value": 1200}, "warranty": {"value": "6_months"},
            "delivery": {"value": "2026-04-10"},
        }, auth_token=session["initiator_token"])

        # Round 2: buyer counters low
        tool_counter(session_id=sid, role="buyer", terms={
            "price": {"value": 700}, "warranty": {"value": "24_months"},
            "delivery": {"value": "2026-04-30"},
        }, auth_token=session["responder_token"])

        # Round 3: seller moves toward middle
        tool_counter(session_id=sid, role="seller", terms={
            "price": {"value": 950}, "warranty": {"value": "12_months"},
            "delivery": {"value": "2026-04-15"},
        }, auth_token=session["initiator_token"])

        # Round 4: buyer accepts
        result = _parse(tool_accept(
            session_id=sid, role="buyer",
            auth_token=session["responder_token"],
            reasoning="Good compromise. I accept.",
        ))
        assert result["state"] == "agreed"

        # Verify analytics
        status = _parse(tool_session_status(
            session_id=sid,
            auth_token=session["initiator_token"],
        ))
        assert status["round_count"] == 3  # 3 offer/counter rounds
        assert status["behaviors"]["seller"]["offers_made"] == 2
        assert status["behaviors"]["buyer"]["offers_made"] == 1

        # Generate receipt
        receipt = _parse(tool_session_receipt(
            session_id=sid, category="electronics",
            auth_token=session["initiator_token"],
        ))
        assert receipt["receipt"]["outcome"]["status"] == "agreed"
        assert receipt["receipt"]["outcome"]["rounds"] == 3

    def test_rejection_flow(self):
        """Open, propose, reject, generate receipt."""
        session = _parse(tool_open_session(
            initiator_id="seller", responder_id="buyer", terms=SAMPLE_TERMS,
        ))
        sid = session["session_id"]

        tool_propose(
            session_id=sid, role="seller", terms=OFFER_TERMS,
            auth_token=session["initiator_token"],
        )
        tool_reject(
            session_id=sid, role="buyer",
            auth_token=session["responder_token"],
            reason="no_deal",
            reasoning="Cannot afford at any reasonable price point.",
        )

        status = _parse(tool_session_status(
            session_id=sid,
            auth_token=session["initiator_token"],
        ))
        assert status["state"] == "rejected"
        assert status["is_terminal"] is True

        receipt = _parse(tool_session_receipt(
            session_id=sid,
            auth_token=session["initiator_token"],
        ))
        assert receipt["receipt"]["outcome"]["status"] == "rejected"

    def test_commit_flow(self):
        """Open, exchange offers, commit to finalize."""
        session = _parse(tool_open_session(
            initiator_id="seller", responder_id="buyer", terms=SAMPLE_TERMS,
        ))
        sid = session["session_id"]

        tool_propose(
            session_id=sid, role="seller", terms=OFFER_TERMS,
            auth_token=session["initiator_token"],
        )
        tool_counter(
            session_id=sid, role="buyer", terms=COUNTER_TERMS,
            auth_token=session["responder_token"],
        )
        result = _parse(tool_commit(
            session_id=sid, role="seller",
            auth_token=session["initiator_token"],
            reasoning="Committing to the buyer's counter-offer terms.",
        ))
        assert result["state"] == "agreed"

    def test_transcript_integrity(self):
        """Verify the hash chain remains valid through a full negotiation."""
        session = _parse(tool_open_session(
            initiator_id="s", responder_id="b", terms=SAMPLE_TERMS,
        ))
        sid = session["session_id"]

        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=session["initiator_token"],
        )
        tool_counter(
            session_id=sid, role="responder", terms=COUNTER_TERMS,
            auth_token=session["responder_token"],
        )
        tool_accept(
            session_id=sid, role="initiator",
            auth_token=session["initiator_token"],
        )

        status = _parse(tool_session_status(
            session_id=sid,
            auth_token=session["initiator_token"],
        ))
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
# SDK integration
# ---------------------------------------------------------------------------

class TestSdkIntegration:
    """Tests for official MCP SDK integration."""

    def test_server_instance_exists(self):
        """The FastMCP server instance is properly configured."""
        assert mcp.name == "concordia-mcp"

    def test_tools_registered_with_sdk(self):
        """All 48 tools are registered with the FastMCP tool manager."""
        tools = mcp._tool_manager.list_tools()
        assert len(tools) == 48
        tool_names = {t.name for t in tools}
        assert "concordia_open_session" in tool_names
        assert "concordia_propose" in tool_names
        assert "concordia_counter" in tool_names
        assert "concordia_accept" in tool_names
        assert "concordia_reject" in tool_names
        assert "concordia_commit" in tool_names
        assert "concordia_session_status" in tool_names
        assert "concordia_session_receipt" in tool_names

    def test_tools_have_schemas(self):
        """Each registered tool has auto-generated parameter schemas."""
        tools = mcp._tool_manager.list_tools()
        for tool in tools:
            assert tool.parameters is not None
            assert tool.parameters.get("type") == "object"
            assert "properties" in tool.parameters

    def test_tools_have_descriptions(self):
        """Each registered tool has a description."""
        tools = mcp._tool_manager.list_tools()
        for tool in tools:
            assert tool.description
            assert len(tool.description) > 10


# ---------------------------------------------------------------------------
# Tool definitions (via get_tool_definitions helper)
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
        assert len(get_tool_definitions()) == 48

    def test_tool_names_match_handlers(self):
        from concordia.mcp_server import handle_tool_call
        def_names = {t["name"] for t in get_tool_definitions()}
        # Verify each defined tool dispatches without "Unknown tool" error
        for name in def_names:
            result = handle_tool_call(name, {})
            if "error" in result:
                assert "Unknown tool" not in result["error"]
