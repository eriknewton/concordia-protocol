"""Relay conclusion and bridge mappings respect authenticated caller ownership.

LEGACY-HP-17
LEGACY-H-19
"""

import json
from copy import deepcopy

import pytest

from concordia import mcp_server
from concordia.relay import NegotiationRelay, RelaySessionState
from concordia.sanctuary_bridge import SanctuaryBridgeConfig


@pytest.fixture(autouse=True)
def isolated_services(monkeypatch):
    monkeypatch.setattr(mcp_server, "_relay", NegotiationRelay())
    monkeypatch.setattr(mcp_server, "_bridge_config", SanctuaryBridgeConfig())


@pytest.mark.parametrize("state", ["pending", "active", "concluded", "archived"])
def test_relay_conclude_refuses_nonparticipant_without_disclosure(make_agent, state):
    owner = make_agent("owner")
    peer = make_agent("peer")
    outsider = make_agent("outsider")
    relay = mcp_server._relay
    session = relay.create_session(owner.agent_id, peer.agent_id)
    if state != "pending":
        relay.join_session(session.relay_session_id, peer.agent_id)
    if state in ("concluded", "archived"):
        result = json.loads(mcp_server.tool_relay_conclude(
            session.relay_session_id, owner.agent_id, owner.auth_token,
        ))
        assert result["concluded"] is True
    if state == "archived":
        relay.archive_session(session.relay_session_id)
    before = deepcopy(session)

    denied = json.loads(mcp_server.tool_relay_conclude(
        session.relay_session_id, outsider.agent_id, outsider.auth_token,
    ))
    missing = json.loads(mcp_server.tool_relay_conclude(
        "missing", outsider.agent_id, outsider.auth_token,
    ))

    assert "error" in denied
    assert denied == missing
    assert session == before


@pytest.mark.parametrize("foreign_first", [False, True])
@pytest.mark.parametrize("foreign_id", ["peer", "unregistered", ""])
def test_bridge_configure_refuses_entire_foreign_mapping_request(
    make_agent, foreign_first, foreign_id,
):
    owner = make_agent("owner")
    make_agent("peer")
    config = mcp_server._bridge_config
    config.map_identity("owner", "original-owner", "did:original:owner")
    config.map_identity("peer", "original-peer", "did:original:peer")
    before = deepcopy(config)
    mappings = [
        {"agent_id": "owner", "sanctuary_id": "changed-owner", "did": "did:new:owner"},
        {"agent_id": foreign_id, "sanctuary_id": "changed-peer", "did": "did:new:peer"},
    ]
    if foreign_first:
        mappings.reverse()

    result = json.loads(mcp_server.tool_sanctuary_bridge_configure(
        owner.agent_id, owner.auth_token, enabled=True,
        identity_mappings=mappings, default_context="changed",
        commitment_on_agree=False, reputation_on_receipt=False,
    ))

    assert "error" in result
    assert config == before


@pytest.mark.parametrize("caller", ["owner", "peer"])
def test_relay_participants_can_conclude(make_agent, caller):
    owner = make_agent("owner")
    peer = make_agent("peer")
    relay = mcp_server._relay
    session = relay.create_session(owner.agent_id, peer.agent_id)
    relay.join_session(session.relay_session_id, peer.agent_id)
    agent = owner if caller == "owner" else peer

    result = json.loads(mcp_server.tool_relay_conclude(
        session.relay_session_id, agent.agent_id, agent.auth_token, reason="agreed",
    ))

    assert result["concluded"] is True
    assert session.state == RelaySessionState.CONCLUDED
    assert session.conclusion_reason == "agreed"


def test_relay_reserved_responder_must_join_before_concluding(make_agent):
    owner = make_agent("owner")
    peer = make_agent("peer")
    relay = mcp_server._relay
    session = relay.create_session(owner.agent_id, peer.agent_id)
    before = deepcopy(session)

    result = json.loads(mcp_server.tool_relay_conclude(
        session.relay_session_id, peer.agent_id, peer.auth_token,
    ))

    assert "error" in result
    assert session == before
    relay.join_session(session.relay_session_id, peer.agent_id)
    result = json.loads(mcp_server.tool_relay_conclude(
        session.relay_session_id, peer.agent_id, peer.auth_token,
    ))
    assert result["concluded"] is True


@pytest.mark.parametrize("state", ["pending", "active", "concluded", "archived"])
def test_relay_enforces_participation_at_conclusion(state):
    relay = NegotiationRelay()
    session = relay.create_session("owner", "peer")
    if state != "pending":
        relay.join_session(session.relay_session_id, "peer")
    if state in ("concluded", "archived"):
        relay.conclude_session(session.relay_session_id, agent_id="owner")
    if state == "archived":
        relay.archive_session(session.relay_session_id)
    before = deepcopy(session)

    assert relay.conclude_session(session.relay_session_id, agent_id="outsider") is None
    assert relay.conclude_session("missing", agent_id="outsider") is None
    assert session == before
    with pytest.raises(TypeError):
        relay.conclude_session(session.relay_session_id)


def test_bridge_owner_can_update_own_mapping(make_agent):
    owner = make_agent("owner")
    config = mcp_server._bridge_config
    config.map_identity("peer", "original-peer", "did:original:peer")
    for sanctuary_id in ("first", "updated"):
        result = json.loads(mcp_server.tool_sanctuary_bridge_configure(
            owner.agent_id, owner.auth_token, enabled=True,
            identity_mappings=[{
                "agent_id": owner.agent_id,
                "sanctuary_id": sanctuary_id,
                "did": f"did:{sanctuary_id}:owner",
            }],
        ))
        assert result["enabled"] is True
        assert config.identity_map == {"peer": "original-peer", "owner": sanctuary_id}
        assert config.did_map == {
            "peer": "did:original:peer", "owner": f"did:{sanctuary_id}:owner",
        }
