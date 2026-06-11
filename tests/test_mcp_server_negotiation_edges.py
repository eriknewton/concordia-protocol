"""MCP negotiation wrapper edge coverage."""

from __future__ import annotations

import json

import pytest

from concordia.mcp_server import (
    SessionState,
    _auth,
    _store,
    tool_commit,
    tool_counter,
    tool_open_session,
    tool_propose,
    tool_reject,
)


SAMPLE_TERMS = {"price": {"type": "numeric", "label": "Price", "unit": "USD"}}
OFFER_TERMS = {"price": {"value": 1000}}


def _parse(result: str) -> dict:
    return json.loads(result)


@pytest.fixture(autouse=True)
def clean_session_state() -> None:
    _store._sessions.clear()
    _auth._session_tokens.clear()
    _auth._agent_tokens.clear()
    _auth._token_to_agent.clear()
    yield
    _store._sessions.clear()
    _auth._session_tokens.clear()
    _auth._agent_tokens.clear()
    _auth._token_to_agent.clear()


def _open_session() -> dict:
    return _parse(tool_open_session("seller", "buyer", SAMPLE_TERMS))


def test_propose_reports_missing_session_after_token_validation() -> None:
    opened = _open_session()
    session_id = opened["session_id"]
    token = opened["initiator_token"]
    _store._sessions.clear()

    result = _parse(
        tool_propose(
            session_id=session_id,
            role="initiator",
            terms=OFFER_TERMS,
            auth_token=token,
        )
    )

    assert result == {"error": f"Session '{session_id}' not found."}


def test_counter_reports_non_active_session_state() -> None:
    opened = _open_session()
    ctx = _store.get(opened["session_id"])
    assert ctx is not None
    ctx.session.state = SessionState.AGREED

    result = _parse(
        tool_counter(
            session_id=opened["session_id"],
            role="responder",
            terms={"price": {"value": 900}},
            auth_token=opened["responder_token"],
        )
    )

    assert result == {"error": "Session is in state 'agreed', not 'active'."}


def test_reject_success_shape_sanitizes_counterparty_reason() -> None:
    opened = _open_session()

    result = _parse(
        tool_reject(
            session_id=opened["session_id"],
            role="responder",
            auth_token=opened["responder_token"],
            reason="too high\u202eno thanks",
            reasoning="same\u200breason",
        )
    )

    assert result["type"] == "negotiate.reject"
    assert result["from"] == "buyer"
    assert result["state"] == "rejected"
    assert result["transcript_length"] == 3
    assert result["message"] == "Negotiation rejected by buyer. Session is now REJECTED."


def test_commit_reports_non_active_session_state() -> None:
    opened = _open_session()
    tool_reject(
        session_id=opened["session_id"],
        role="responder",
        auth_token=opened["responder_token"],
    )

    result = _parse(
        tool_commit(
            session_id=opened["session_id"],
            role="initiator",
            auth_token=opened["initiator_token"],
        )
    )

    assert result == {"error": "Session is in state 'rejected', not 'active'."}
