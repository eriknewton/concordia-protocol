"""Regression tests for SEC-007 — Caller Authentication.

These tests verify that Concordia's MCP tools enforce bearer-token
authentication and reject unauthenticated or wrongly-authenticated callers.

Test plan (per REMEDIATION_PLAN RT-05 and SPRINT_CONTRACT):

1. Session tools reject calls with no token.
2. Session tools reject calls with wrong token.
3. Session tools accept calls with the correct token.
4. Initiator token cannot act as responder (role isolation).
5. Deregister rejects wrong agent's token.
6. Relay receive rejects wrong agent's token.
7. open_session returns tokens in its response.
8. register_agent returns token in its response.
9. Public/read-only tools work without tokens.
10. Want withdraw rejects wrong agent's token.
"""

import json
import pytest

from concordia.mcp_server import (
    _auth,
    _store,
    _registry,
    _want_registry,
    _relay,
    tool_open_session,
    tool_propose,
    tool_counter,
    tool_accept,
    tool_reject,
    tool_session_status,
    tool_session_receipt,
    tool_register_agent,
    tool_deregister_agent,
    tool_search_agents,
    tool_reputation_score,
    tool_post_want,
    tool_withdraw_want,
    tool_relay_create,
    tool_relay_receive,
)


def _parse(result_str: str) -> dict:
    return json.loads(result_str)


SAMPLE_TERMS = {
    "price": {"type": "numeric", "label": "Price", "unit": "USD"},
}

OFFER_TERMS = {"price": {"value": 1000}}


@pytest.fixture(autouse=True)
def clean_state():
    """Reset all global state between tests."""
    _store._sessions.clear()
    _auth._agent_tokens.clear()
    _auth._session_tokens.clear()
    _auth._token_to_agent.clear()
    _registry._agents.clear()
    _want_registry._wants.clear()
    _want_registry._haves.clear()
    _want_registry._agent_wants.clear()
    _want_registry._agent_haves.clear()
    _relay._sessions.clear()
    yield
    _store._sessions.clear()
    _auth._agent_tokens.clear()
    _auth._session_tokens.clear()
    _auth._token_to_agent.clear()


@pytest.fixture
def session_with_tokens():
    """Create an active session and return (result_dict)."""
    result = _parse(tool_open_session(
        initiator_id="seller",
        responder_id="buyer",
        terms=SAMPLE_TERMS,
    ))
    return result


# ---- Test 1: Session tool rejects no token ----

class TestNoToken:
    def test_propose_rejects_no_token(self, session_with_tokens):
        sid = session_with_tokens["session_id"]
        # Pass empty string as token (missing)
        result = _parse(tool_propose(
            session_id=sid,
            role="initiator",
            terms=OFFER_TERMS,
            auth_token="",
        ))
        assert "error" in result
        assert "Authentication required" in result["error"]

    def test_accept_rejects_no_token(self, session_with_tokens):
        sid = session_with_tokens["session_id"]
        # First make a valid offer
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=session_with_tokens["initiator_token"],
        )
        result = _parse(tool_accept(
            session_id=sid, role="responder", auth_token="",
        ))
        assert "error" in result
        assert "Authentication required" in result["error"]

    def test_session_status_rejects_no_token(self, session_with_tokens):
        sid = session_with_tokens["session_id"]
        result = _parse(tool_session_status(
            session_id=sid, auth_token="",
        ))
        assert "error" in result
        assert "Authentication required" in result["error"]


# ---- Test 2: Session tool rejects wrong token ----

class TestWrongToken:
    def test_propose_rejects_wrong_token(self, session_with_tokens):
        sid = session_with_tokens["session_id"]
        result = _parse(tool_propose(
            session_id=sid,
            role="initiator",
            terms=OFFER_TERMS,
            auth_token="0000000000000000000000000000000000000000000000000000000000000000",
        ))
        assert "error" in result
        assert "Authentication required" in result["error"]

    def test_reject_rejects_wrong_token(self, session_with_tokens):
        sid = session_with_tokens["session_id"]
        result = _parse(tool_reject(
            session_id=sid, role="initiator",
            auth_token="deadbeef" * 8,
        ))
        assert "error" in result
        assert "Authentication required" in result["error"]


# ---- Test 3: Session tool accepts correct token ----

class TestCorrectToken:
    def test_propose_accepts_initiator_token(self, session_with_tokens):
        sid = session_with_tokens["session_id"]
        result = _parse(tool_propose(
            session_id=sid,
            role="initiator",
            terms=OFFER_TERMS,
            auth_token=session_with_tokens["initiator_token"],
        ))
        assert "error" not in result
        assert result["from"] == "seller"

    def test_counter_accepts_responder_token(self, session_with_tokens):
        sid = session_with_tokens["session_id"]
        tool_propose(
            session_id=sid, role="initiator", terms=OFFER_TERMS,
            auth_token=session_with_tokens["initiator_token"],
        )
        result = _parse(tool_counter(
            session_id=sid,
            role="responder",
            terms={"price": {"value": 800}},
            auth_token=session_with_tokens["responder_token"],
        ))
        assert "error" not in result
        assert result["from"] == "buyer"


# ---- Test 4: Role isolation ----

class TestRoleIsolation:
    def test_initiator_token_cannot_act_as_responder(self, session_with_tokens):
        sid = session_with_tokens["session_id"]
        # Try to propose as responder using initiator's token
        result = _parse(tool_propose(
            session_id=sid,
            role="responder",
            terms=OFFER_TERMS,
            auth_token=session_with_tokens["initiator_token"],
        ))
        assert "error" in result
        assert "Authentication required" in result["error"]

    def test_responder_token_cannot_act_as_initiator(self, session_with_tokens):
        sid = session_with_tokens["session_id"]
        result = _parse(tool_propose(
            session_id=sid,
            role="initiator",
            terms=OFFER_TERMS,
            auth_token=session_with_tokens["responder_token"],
        ))
        assert "error" in result
        assert "Authentication required" in result["error"]


# ---- Test 5: Deregister rejects wrong agent token ----

class TestDeregisterAuth:
    def test_deregister_rejects_wrong_token(self):
        reg_a = _parse(tool_register_agent(agent_id="agent_a"))
        reg_b = _parse(tool_register_agent(agent_id="agent_b"))
        token_a = reg_a["auth_token"]
        token_b = reg_b["auth_token"]
        # Try to deregister A with B's token
        result = _parse(tool_deregister_agent(
            agent_id="agent_a", auth_token=token_b,
        ))
        assert "error" in result
        assert "Authentication required" in result["error"]
        # A should still be registered
        search = _parse(tool_search_agents())
        agent_ids = [a["agent_id"] for a in search["agents"]]
        assert "agent_a" in agent_ids

    def test_deregister_accepts_correct_token(self):
        reg = _parse(tool_register_agent(agent_id="agent_a"))
        token = reg["auth_token"]
        result = _parse(tool_deregister_agent(
            agent_id="agent_a", auth_token=token,
        ))
        assert result["removed"] is True

    def test_revoked_token_rejected_after_deregistration(self):
        """SEC-007 evaluator condition 1: verify revoked tokens are rejected."""
        # (a) Register an agent and get a valid token
        reg = _parse(tool_register_agent(agent_id="agent_a"))
        token = reg["auth_token"]
        # Sanity check: token works before revocation
        posted = _parse(tool_post_want(
            agent_id="agent_a", auth_token=token,
            category="electronics", terms={"price": {"max": 50}},
        ))
        assert "want" in posted

        # (b) Deregister the agent (triggers revoke_agent_token)
        dereg = _parse(tool_deregister_agent(
            agent_id="agent_a", auth_token=token,
        ))
        assert dereg["removed"] is True

        # (c) Attempt to use the revoked token on an identity-dependent operation
        result = _parse(tool_post_want(
            agent_id="agent_a", auth_token=token,
            category="electronics", terms={"price": {"max": 100}},
        ))

        # (d) Assert rejection with an authentication error, not a not-found error
        assert "error" in result
        assert "Authentication required" in result["error"]
        assert "not found" not in result.get("error", "").lower()


# ---- Test 6: Relay receive rejects wrong agent ----

class TestRelayAuth:
    def test_relay_receive_rejects_wrong_agent(self):
        reg_a = _parse(tool_register_agent(agent_id="agent_a"))
        reg_b = _parse(tool_register_agent(agent_id="agent_b"))
        token_a = reg_a["auth_token"]
        token_b = reg_b["auth_token"]
        # Create a relay session as agent_a
        tool_relay_create(
            initiator_id="agent_a",
            auth_token=token_a,
            responder_id="agent_b",
        )
        # Agent_b tries to receive agent_a's messages using agent_b's token
        # but claiming to be agent_a — should fail
        result = _parse(tool_relay_receive(
            agent_id="agent_a", auth_token=token_b,
        ))
        assert "error" in result
        assert "Authentication required" in result["error"]


# ---- Test 7: open_session returns tokens ----

class TestTokenIssuance:
    def test_open_session_returns_tokens(self, session_with_tokens):
        assert "initiator_token" in session_with_tokens
        assert "responder_token" in session_with_tokens
        assert len(session_with_tokens["initiator_token"]) == 64  # 256-bit hex
        assert len(session_with_tokens["responder_token"]) == 64
        assert session_with_tokens["initiator_token"] != session_with_tokens["responder_token"]

    def test_register_agent_returns_token(self):
        result = _parse(tool_register_agent(agent_id="agent_x"))
        assert "auth_token" in result
        assert len(result["auth_token"]) == 64  # 256-bit hex


# ---- Test 9: Public tools require no token ----

class TestPublicTools:
    def test_search_agents_no_token(self):
        result = _parse(tool_search_agents())
        assert "error" not in result
        assert "count" in result

    def test_reputation_score_no_token(self):
        result = _parse(tool_reputation_score(agent_id="nobody"))
        assert "error" not in result


# ---- Test 10: Want withdraw rejects wrong agent ----

class TestWantAuth:
    def test_withdraw_want_rejects_wrong_agent(self):
        reg_a = _parse(tool_register_agent(agent_id="agent_a"))
        reg_b = _parse(tool_register_agent(agent_id="agent_b"))
        token_a = reg_a["auth_token"]
        token_b = reg_b["auth_token"]
        # Agent A posts a want
        posted = _parse(tool_post_want(
            agent_id="agent_a", auth_token=token_a,
            category="electronics", terms={"price": {"max": 100}},
        ))
        want_id = posted["want"]["id"]
        # Agent B tries to withdraw agent A's want
        result = _parse(tool_withdraw_want(
            want_id=want_id,
            agent_id="agent_b",
            auth_token=token_b,
        ))
        assert "error" in result
        # Verify the want still exists
        from concordia.mcp_server import tool_get_want
        get_result = _parse(tool_get_want(want_id=want_id))
        assert get_result["found"] is True
