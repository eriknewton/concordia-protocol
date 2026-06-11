"""MCP relay and Sanctuary bridge wrapper edge coverage."""

from __future__ import annotations

import json

import pytest

from concordia import mcp_server


def _parse(result: str) -> dict:
    return json.loads(result)


@pytest.fixture(autouse=True)
def clean_state() -> None:
    mcp_server._auth._agent_tokens.clear()
    mcp_server._auth._session_tokens.clear()
    mcp_server._auth._token_to_agent.clear()
    mcp_server._registry._agents.clear()
    mcp_server._relay._sessions.clear()
    mcp_server._relay._mailboxes.clear()
    mcp_server._relay._archives.clear()
    mcp_server._relay._concordia_index.clear()
    mcp_server._bridge_config.enabled = False
    mcp_server._bridge_config.default_context = "concordia_negotiation"
    mcp_server._bridge_config.commitment_on_agree = True
    mcp_server._bridge_config.reputation_on_receipt = True
    mcp_server._bridge_config.identity_map.clear()
    mcp_server._bridge_config.did_map.clear()
    yield
    mcp_server._auth._agent_tokens.clear()
    mcp_server._auth._session_tokens.clear()
    mcp_server._auth._token_to_agent.clear()
    mcp_server._registry._agents.clear()
    mcp_server._relay._sessions.clear()
    mcp_server._relay._mailboxes.clear()
    mcp_server._relay._archives.clear()
    mcp_server._relay._concordia_index.clear()


def _register(agent_id: str) -> dict:
    return _parse(mcp_server.tool_register_agent(agent_id=agent_id))


def test_relay_create_validates_responder_id_before_auth() -> None:
    result = _parse(
        mcp_server.tool_relay_create(
            initiator_id="agent_a",
            auth_token="bad-token",
            responder_id="bad id",
        )
    )

    assert result == {
        "error": "agent_id may contain only ASCII letters, digits, and the "
        "separators . _ : @ - and must start with a letter or digit"
    }


def test_relay_send_and_receive_sanitize_counterparty_fields() -> None:
    agent_a = _register("agent_a")
    agent_b = _register("agent_b")
    created = _parse(
        mcp_server.tool_relay_create(
            initiator_id="agent_a",
            auth_token=agent_a["auth_token"],
        )
    )
    relay_session_id = created["session"]["relay_session_id"]
    joined = _parse(
        mcp_server.tool_relay_join(
            relay_session_id=relay_session_id,
            agent_id="agent_b",
            auth_token=agent_b["auth_token"],
        )
    )
    assert joined["joined"] is True

    sent = _parse(
        mcp_server.tool_relay_send(
            relay_session_id=relay_session_id,
            from_agent="agent_a",
            auth_token=agent_a["auth_token"],
            message_type="offer\u202etype",
            payload={"body": "hello\u200b"},
            ttl=30,
        )
    )
    received = _parse(
        mcp_server.tool_relay_receive(
            agent_id="agent_b",
            auth_token=agent_b["auth_token"],
            relay_session_id=relay_session_id,
        )
    )

    assert sent["sent"] is True
    assert sent["message"]["message_type"] == "offertype"
    assert received["count"] == 1
    assert received["payloads"] == [{"body": "hello"}]
    assert received["_content_trust"] == "external"


def test_relay_archive_reports_not_found_or_not_concluded() -> None:
    agent = _register("agent_a")

    result = _parse(
        mcp_server.tool_relay_archive(
            relay_session_id="relay_missing",
            agent_id="agent_a",
            auth_token=agent["auth_token"],
        )
    )

    assert result == {
        "error": "Cannot archive session 'relay_missing'. Not found or not concluded."
    }


def test_bridge_configure_and_status_shape() -> None:
    agent = _register("agent_a")

    configured = _parse(
        mcp_server.tool_sanctuary_bridge_configure(
            agent_id="agent_a",
            auth_token=agent["auth_token"],
            enabled=True,
            identity_mappings=[
                {
                    "agent_id": "agent_a",
                    "sanctuary_id": "sanctuary-agent-a",
                    "did": "did:example:agent-a",
                }
            ],
            default_context="test_context",
            commitment_on_agree=False,
            reputation_on_receipt=False,
        )
    )
    status = _parse(mcp_server.tool_sanctuary_bridge_status())

    assert configured == {
        "enabled": True,
        "identity_count": 1,
        "default_context": "test_context",
        "commitment_on_agree": False,
        "reputation_on_receipt": False,
        "message": "Sanctuary bridge enabled.",
    }
    assert status == {
        "enabled": True,
        "identity_mappings": {
            "agent_a": {
                "sanctuary_id": "sanctuary-agent-a",
                "did": "did:example:agent-a",
            }
        },
        "identity_count": 1,
        "default_context": "test_context",
        "commitment_on_agree": False,
        "reputation_on_receipt": False,
    }
