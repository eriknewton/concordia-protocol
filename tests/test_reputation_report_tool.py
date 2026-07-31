"""Tests for provider-parameterized reputation reporting."""

from __future__ import annotations

import json
from typing import Any

from concordia import mcp_server
from concordia.mcp_server import handle_tool_call


EXAMPLE_PROVIDER_DID = "did:web:example-scores.test"
EXAMPLE_PROVIDER_ENDPOINT = "https://example-scores.test"


def _make_agreed_session(make_agent, prefix: str) -> tuple[str, Any]:
    reporter = make_agent(f"{prefix}_reporter")
    counterparty = make_agent(f"{prefix}_counterparty")

    result = handle_tool_call("concordia_open_session", {
        "initiator_id": reporter.agent_id,
        "responder_id": counterparty.agent_id,
        "terms": {"price": {"type": "numeric"}},
    })
    session_id = result["session_id"]
    init_token = result["initiator_token"]
    resp_token = result["responder_token"]

    handle_tool_call("concordia_propose", {
        "session_id": session_id,
        "role": "initiator",
        "terms": {"price": {"value": 100}},
        "auth_token": init_token,
    })
    handle_tool_call("concordia_accept", {
        "session_id": session_id,
        "role": "responder",
        "auth_token": resp_token,
    })

    return session_id, reporter


def test_reputation_report_requires_explicit_provider() -> None:
    result = handle_tool_call("concordia_reputation_report", {
        "session_id": "session-example",
        "agent_id": "agent-example",
        "auth_token": "token-example",
    })

    assert "error" in result
    assert "Missing required parameters" in result["error"]
    assert "provider_endpoint" in result["error"]
    assert "provider_did" in result["error"]
    assert "No default reputation provider is used" in result["error"]
    assert "verascore.ai" not in result["error"].lower()


def test_reputation_report_non_verascore_provider_output_is_neutral(
    make_agent,
    monkeypatch,
) -> None:
    session_id, reporter = _make_agreed_session(
        make_agent, "neutral_report_provider"
    )
    seen_endpoints: list[str] = []

    class FakeProviderClient:
        def __init__(self, base_url: str) -> None:
            seen_endpoints.append(base_url)

        def report_concordia_receipt(
            self,
            session_data: dict[str, Any],
            **_: Any,
        ) -> dict[str, Any]:
            assert session_data["session_id"] == session_id
            return {"status": "accepted", "provider": "example-scores"}

    monkeypatch.setenv("CONCORDIA_REPUTATION_REPORTING_ENABLED", "true")
    monkeypatch.setattr(mcp_server, "VerascoreClient", FakeProviderClient)

    result = handle_tool_call("concordia_reputation_report", {
        "session_id": session_id,
        "agent_id": reporter.agent_id,
        "auth_token": reporter.auth_token,
        "provider_endpoint": EXAMPLE_PROVIDER_ENDPOINT,
        "provider_did": EXAMPLE_PROVIDER_DID,
    })

    assert seen_endpoints == [EXAMPLE_PROVIDER_ENDPOINT]
    assert result["reported"] is True
    assert result["provider"] == {
        "did": EXAMPLE_PROVIDER_DID,
        "endpoint": EXAMPLE_PROVIDER_ENDPOINT,
    }
    assert result["provider_profile"].startswith(EXAMPLE_PROVIDER_ENDPOINT)
    assert "provider_response" in result
    assert "verascore_profile" not in result
    assert "verascore_response" not in result
    assert "verascore" not in json.dumps(result, sort_keys=True).lower()
