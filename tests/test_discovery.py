"""Tests for Discovery Registry, Graceful Degradation, and Protocol Meta-negotiation.

Covers:
    - AgentRegistry: registration, deregistration, search, heartbeat, Agent Cards
    - AgentCapabilities: category/role matching, to_dict
    - InteractionManager: protocol proposals, responses, degraded tracking, efficiency reports
    - MCP tool integration: all discovery and adoption tools via handle_tool_call
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from concordia.registry import (
    AgentCapabilities,
    AgentRegistry,
    RegisteredAgent,
)
from concordia.degradation import (
    DegradedInteraction,
    InteractionManager,
    InteractionMode,
    PeerProtocolStatus,
    ProtocolProposal,
    ProtocolResponse,
)
from concordia.mcp_server import _auth, tool_register_agent


# ===================================================================
# AgentCapabilities tests
# ===================================================================

class TestAgentCapabilities:

    def test_defaults(self):
        caps = AgentCapabilities()
        assert caps.protocol == "concordia"
        assert "buyer" in caps.roles
        assert "seller" in caps.roles
        assert "split" in caps.resolution_mechanisms

    def test_supports_category_exact(self):
        caps = AgentCapabilities(categories=["electronics"])
        assert caps.supports_category("electronics") is True

    def test_supports_category_prefix(self):
        caps = AgentCapabilities(categories=["electronics.cameras"])
        assert caps.supports_category("electronics") is True
        assert caps.supports_category("electronics.cameras.mirrorless") is True

    def test_no_categories_accepts_all(self):
        caps = AgentCapabilities(categories=[])
        assert caps.supports_category("anything") is True

    def test_rejects_unrelated_category(self):
        caps = AgentCapabilities(categories=["electronics"])
        assert caps.supports_category("furniture") is False

    def test_supports_role(self):
        caps = AgentCapabilities(roles=["seller"])
        assert caps.supports_role("seller") is True
        assert caps.supports_role("Seller") is True
        assert caps.supports_role("buyer") is False

    def test_to_dict(self):
        caps = AgentCapabilities(categories=["electronics"], max_concurrent_sessions=5)
        d = caps.to_dict()
        assert d["protocol"] == "concordia"
        assert d["categories"] == ["electronics"]
        assert d["max_concurrent_sessions"] == 5


# ===================================================================
# AgentRegistry tests
# ===================================================================

class TestAgentRegistry:

    def test_register_new_agent(self):
        reg = AgentRegistry()
        agent = reg.register("agent_1", categories=["electronics"])
        assert agent.agent_id == "agent_1"
        assert agent.capabilities.supports_category("electronics")
        assert reg.count() == 1

    def test_register_updates_existing(self):
        reg = AgentRegistry()
        reg.register("agent_1", categories=["electronics"])
        agent = reg.register("agent_1", categories=["furniture"])
        assert agent.capabilities.categories == ["furniture"]
        assert reg.count() == 1

    def test_deregister(self):
        reg = AgentRegistry()
        reg.register("agent_1")
        assert reg.deregister("agent_1") is True
        assert reg.count() == 0

    def test_deregister_missing(self):
        reg = AgentRegistry()
        assert reg.deregister("nonexistent") is False

    def test_get(self):
        reg = AgentRegistry()
        reg.register("agent_1", description="Test agent")
        agent = reg.get("agent_1")
        assert agent is not None
        assert agent.description == "Test agent"

    def test_get_missing(self):
        reg = AgentRegistry()
        assert reg.get("nonexistent") is None

    def test_heartbeat(self):
        reg = AgentRegistry()
        reg.register("agent_1")
        old_seen = reg.get("agent_1").last_seen
        assert reg.heartbeat("agent_1") is True
        # last_seen should be updated (or same if sub-second)
        assert reg.get("agent_1").last_seen >= old_seen

    def test_heartbeat_missing(self):
        reg = AgentRegistry()
        assert reg.heartbeat("nonexistent") is False

    def test_search_by_category(self):
        reg = AgentRegistry()
        reg.register("elec_seller", categories=["electronics"])
        reg.register("furn_seller", categories=["furniture"])
        reg.register("both_seller", categories=["electronics", "furniture"])

        results = reg.search(category="electronics")
        ids = {a.agent_id for a in results}
        assert "elec_seller" in ids
        assert "both_seller" in ids
        assert "furn_seller" not in ids

    def test_search_by_role(self):
        reg = AgentRegistry()
        reg.register("seller_only", roles=["seller"])
        reg.register("buyer_only", roles=["buyer"])
        reg.register("both", roles=["seller", "buyer"])

        results = reg.search(role="seller")
        ids = {a.agent_id for a in results}
        assert "seller_only" in ids
        assert "both" in ids
        assert "buyer_only" not in ids

    def test_search_by_resolution_mechanism(self):
        reg = AgentRegistry()
        reg.register("tradeoff_agent", resolution_mechanisms=["tradeoff"])
        reg.register("split_agent", resolution_mechanisms=["split"])

        results = reg.search(resolution_mechanism="tradeoff")
        ids = {a.agent_id for a in results}
        assert "tradeoff_agent" in ids
        assert "split_agent" not in ids

    def test_search_combined_filters(self):
        reg = AgentRegistry()
        reg.register("a1", categories=["electronics"], roles=["seller"])
        reg.register("a2", categories=["electronics"], roles=["buyer"])
        reg.register("a3", categories=["furniture"], roles=["seller"])

        results = reg.search(category="electronics", role="seller")
        assert len(results) == 1
        assert results[0].agent_id == "a1"

    def test_search_limit(self):
        reg = AgentRegistry()
        for i in range(20):
            reg.register(f"agent_{i}")

        results = reg.search(limit=5)
        assert len(results) == 5

    def test_list_all(self):
        reg = AgentRegistry()
        reg.register("a1")
        reg.register("a2")
        reg.register("a3")
        assert len(reg.list_all()) == 3

    def test_concordia_preferred_badge(self):
        reg = AgentRegistry()
        reg.register("agent_1")
        assert reg.is_concordia_preferred("agent_1") is True
        assert reg.is_concordia_preferred("unregistered") is False

    def test_agent_card(self):
        reg = AgentRegistry()
        reg.register("agent_1", description="My agent", categories=["electronics"])
        card = reg.get_agent_card("agent_1")
        assert card is not None
        assert card["concordia_preferred"] is True
        assert "capabilities" in card
        assert card["capabilities"][0]["protocol"] == "concordia"

    def test_agent_card_missing(self):
        reg = AgentRegistry()
        assert reg.get_agent_card("nonexistent") is None

    def test_to_dict_includes_badge(self):
        reg = AgentRegistry()
        agent = reg.register("agent_1")
        d = agent.to_dict()
        assert d["concordia_preferred"] is True
        assert d["agent_id"] == "agent_1"


# ===================================================================
# Protocol Meta-negotiation tests
# ===================================================================

class TestProtocolProposal:

    def test_proposal_structure(self):
        proposal = ProtocolProposal(
            proposer_agent_id="concordia_agent",
            target_agent_id="unknown_peer",
        )
        d = proposal.to_dict()
        assert d["type"] == "concordia.protocol_proposal"
        assert d["proposer_agent_id"] == "concordia_agent"
        assert d["target_agent_id"] == "unknown_peer"
        assert d["protocol"]["name"] == "concordia"
        assert len(d["benefits"]) > 0
        assert "without_concordia" in d["comparison"]
        assert "with_concordia" in d["comparison"]
        assert d["adoption"]["backwards_compatible"] is True

    def test_proposal_has_id(self):
        p = ProtocolProposal(proposer_agent_id="a", target_agent_id="b")
        assert p.proposal_id.startswith("proto_prop_")


class TestProtocolResponse:

    def test_accept_response(self):
        r = ProtocolResponse(
            proposal_id="prop_123",
            responder_agent_id="peer",
            accepted=True,
        )
        d = r.to_dict()
        assert d["accepted"] is True
        assert d["type"] == "concordia.protocol_response"

    def test_decline_response_with_reason(self):
        r = ProtocolResponse(
            proposal_id="prop_123",
            responder_agent_id="peer",
            accepted=False,
            reason="We use a different protocol",
        )
        d = r.to_dict()
        assert d["accepted"] is False
        assert d["reason"] == "We use a different protocol"


# ===================================================================
# InteractionManager tests
# ===================================================================

class TestInteractionManager:

    def test_propose_protocol(self):
        mgr = InteractionManager()
        proposal = mgr.propose_protocol("agent_a", "agent_b")
        assert proposal.proposer_agent_id == "agent_a"
        assert proposal.target_agent_id == "agent_b"
        assert mgr.get_proposal(proposal.proposal_id) is not None

    def test_handle_accept(self):
        mgr = InteractionManager()
        proposal = mgr.propose_protocol("a", "b")
        response, mode = mgr.handle_response(
            proposal.proposal_id, accepted=True, responder_agent_id="b"
        )
        assert response.accepted is True
        assert mode == InteractionMode.UPGRADED

    def test_handle_decline(self):
        mgr = InteractionManager()
        proposal = mgr.propose_protocol("a", "b")
        response, mode = mgr.handle_response(
            proposal.proposal_id, accepted=False, reason="No thanks"
        )
        assert response.accepted is False
        assert mode == InteractionMode.DEGRADED

    def test_start_degraded(self):
        mgr = InteractionManager()
        interaction = mgr.start_degraded("a", "b")
        assert interaction.mode == InteractionMode.DEGRADED
        assert interaction.agent_id == "a"
        assert interaction.peer_id == "b"
        assert interaction.rounds == 0

    def test_add_messages(self):
        mgr = InteractionManager()
        interaction = mgr.start_degraded("a", "b")
        msg1 = mgr.add_message(interaction.interaction_id, "a", "I'd like to buy X")
        msg2 = mgr.add_message(interaction.interaction_id, "b", "I can offer Y")
        assert msg1["round"] == 1
        assert msg2["round"] == 2
        assert interaction.rounds == 2

    def test_add_message_missing_interaction(self):
        mgr = InteractionManager()
        assert mgr.add_message("nonexistent", "a", "hello") is None

    def test_efficiency_report(self):
        mgr = InteractionManager()
        interaction = mgr.start_degraded("a", "b")
        for i in range(9):
            mgr.add_message(interaction.interaction_id, "a" if i % 2 == 0 else "b", f"Round {i+1}")

        report = mgr.get_efficiency_report(interaction.interaction_id)
        assert report is not None
        assert report["actual_rounds"] == 9
        assert report["estimated_concordia_rounds"] == 3
        assert report["rounds_saved"] == 6
        assert report["had_binding_commitment"] is False
        assert report["had_session_receipt"] is False
        assert "concordia-protocol" in report["recommendation"]

    def test_efficiency_report_missing(self):
        mgr = InteractionManager()
        assert mgr.get_efficiency_report("nonexistent") is None

    def test_upgrade_degraded_interaction(self):
        mgr = InteractionManager()
        proposal = mgr.propose_protocol("a", "b")
        interaction = mgr.start_degraded(
            "a", "b", proposal_id=proposal.proposal_id
        )
        mgr.add_message(interaction.interaction_id, "a", "Let me try something")

        response, mode = mgr.handle_response(
            proposal.proposal_id, accepted=True, responder_agent_id="b"
        )
        assert mode == InteractionMode.UPGRADED
        assert interaction.mode == InteractionMode.UPGRADED

    def test_stats(self):
        mgr = InteractionManager()
        mgr.start_degraded("a", "b1")
        mgr.start_degraded("a", "b2")
        proposal = mgr.propose_protocol("a", "b3")

        stats = mgr.stats()
        assert stats["total_interactions"] == 2
        assert stats["degraded"] == 2
        assert stats["total_proposals_sent"] == 1

    def test_degraded_with_declined_status(self):
        mgr = InteractionManager()
        interaction = mgr.start_degraded(
            "a", "b", peer_status=PeerProtocolStatus.DECLINED
        )
        assert interaction.peer_status == PeerProtocolStatus.DECLINED


# ===================================================================
# DegradedInteraction unit tests
# ===================================================================

class TestDegradedInteraction:

    def test_to_dict(self):
        di = DegradedInteraction(
            interaction_id="test_123",
            agent_id="a",
            peer_id="b",
            peer_status=PeerProtocolStatus.UNKNOWN,
        )
        d = di.to_dict()
        assert d["interaction_id"] == "test_123"
        assert d["mode"] == "degraded"
        assert d["rounds"] == 0

    def test_efficiency_report_minimum_rounds(self):
        """Concordia estimate should never go below 2."""
        di = DegradedInteraction(
            interaction_id="test",
            agent_id="a",
            peer_id="b",
            peer_status=PeerProtocolStatus.UNKNOWN,
        )
        di.add_message("a", "hello")
        di.add_message("b", "hi")
        report = di.efficiency_report()
        assert report["estimated_concordia_rounds"] == 2
        assert report["actual_rounds"] == 2


# ===================================================================
# MCP Tool integration tests
# ===================================================================

class TestDiscoveryMcpTools:

    @pytest.fixture(autouse=True)
    def reset_stores(self):
        from concordia.mcp_server import _registry, _interaction_mgr
        _registry._agents.clear()
        _interaction_mgr._interactions.clear()
        _interaction_mgr._proposals.clear()
        _auth._agent_tokens.clear()
        _auth._session_tokens.clear()
        _auth._token_to_agent.clear()
        yield

    def _parse(self, result_str: str) -> dict:
        return json.loads(result_str)

    # -- Registry tools --

    def test_register_agent(self):
        from concordia.mcp_server import tool_register_agent
        result = self._parse(tool_register_agent(
            agent_id="seller_01",
            categories=["electronics", "furniture"],
            roles=["seller"],
        ))
        assert result["registered"] is True
        assert result["concordia_preferred"] is True
        assert result["agent"]["agent_id"] == "seller_01"

    def test_search_agents(self):
        from concordia.mcp_server import tool_register_agent, tool_search_agents
        tool_register_agent(agent_id="elec_seller", categories=["electronics"], roles=["seller"])
        tool_register_agent(agent_id="furn_seller", categories=["furniture"], roles=["seller"])

        result = self._parse(tool_search_agents(category="electronics"))
        assert result["count"] == 1
        assert result["agents"][0]["agent_id"] == "elec_seller"

    def test_search_all(self):
        from concordia.mcp_server import tool_register_agent, tool_search_agents
        tool_register_agent(agent_id="a1")
        tool_register_agent(agent_id="a2")

        result = self._parse(tool_search_agents())
        assert result["count"] == 2

    def test_agent_card(self):
        from concordia.mcp_server import tool_register_agent, tool_agent_card
        tool_register_agent(agent_id="seller_01", description="Camera seller")
        result = self._parse(tool_agent_card(agent_id="seller_01"))
        assert result["found"] is True
        assert result["concordia_preferred"] is True

    def test_agent_card_not_found(self):
        from concordia.mcp_server import tool_agent_card
        result = self._parse(tool_agent_card(agent_id="nobody"))
        assert result["found"] is False
        assert result["concordia_preferred"] is False

    # -- Concordia Preferred Badge tool --

    def test_preferred_badge(self):
        from concordia.mcp_server import tool_register_agent, tool_concordia_preferred_badge
        tool_register_agent(
            agent_id="badge_agent",
            categories=["electronics"],
            roles=["seller"],
        )
        result = self._parse(tool_concordia_preferred_badge(agent_id="badge_agent"))
        assert result["found"] is True
        badge = result["badge"]
        assert badge["type"] == "concordia.preferred"
        assert badge["agent_id"] == "badge_agent"
        assert badge["verified"] is True
        assert badge["capabilities"]["roles"] == ["seller"]
        assert badge["capabilities"]["categories"] == ["electronics"]
        assert badge["features"]["structured_offers"] is True
        assert badge["features"]["binding_commitments"] is True
        assert badge["features"]["session_receipts"] is True
        assert "adopt" in badge
        assert "install" in badge["adopt"]

    def test_preferred_badge_not_found(self):
        from concordia.mcp_server import tool_concordia_preferred_badge
        result = self._parse(tool_concordia_preferred_badge(agent_id="nobody"))
        assert result["found"] is False
        assert result["concordia_preferred"] is False

    def test_preferred_badge_sanctuary_flag(self):
        from concordia.mcp_server import _registry, tool_concordia_preferred_badge
        _registry.register(
            agent_id="sanc_agent",
            metadata={"sanctuary_enabled": True},
        )
        result = self._parse(tool_concordia_preferred_badge(agent_id="sanc_agent"))
        assert result["badge"]["features"]["sanctuary_bridge"] is True

    def test_preferred_badge_via_handle_tool_call(self):
        from concordia.mcp_server import handle_tool_call
        handle_tool_call("concordia_register_agent", {
            "agent_id": "htc_agent",
            "roles": ["buyer"],
        })
        result = handle_tool_call("concordia_preferred_badge", {
            "agent_id": "htc_agent",
        })
        assert result["found"] is True
        assert result["badge"]["agent_id"] == "htc_agent"

    def test_deregister_agent(self):
        from concordia.mcp_server import tool_deregister_agent
        reg_result = self._parse(tool_register_agent(agent_id="temp_agent"))
        token = reg_result["auth_token"]
        result = self._parse(tool_deregister_agent(agent_id="temp_agent", auth_token=token))
        assert result["removed"] is True

    # -- Protocol meta-negotiation tools --

    def test_propose_protocol(self):
        from concordia.mcp_server import tool_propose_protocol
        reg_result = self._parse(tool_register_agent(agent_id="concordia_agent"))
        token = reg_result["auth_token"]
        result = self._parse(tool_propose_protocol(
            agent_id="concordia_agent",
            auth_token=token,
            peer_id="unknown_peer",
        ))
        assert "proposal" in result
        assert result["proposal"]["type"] == "concordia.protocol_proposal"
        assert len(result["proposal"]["benefits"]) > 0

    def test_respond_accept(self):
        from concordia.mcp_server import tool_propose_protocol, tool_respond_to_proposal
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]
        reg_b = self._parse(tool_register_agent(agent_id="b"))
        token_b = reg_b["auth_token"]

        prop_result = self._parse(tool_propose_protocol(agent_id="a", auth_token=token_a, peer_id="b"))
        proposal_id = prop_result["proposal"]["proposal_id"]

        resp_result = self._parse(tool_respond_to_proposal(
            proposal_id=proposal_id,
            accepted=True,
            responder_agent_id="b",
            auth_token=token_b,
        ))
        assert resp_result["resulting_mode"] == "upgraded"

    def test_respond_decline(self):
        from concordia.mcp_server import tool_propose_protocol, tool_respond_to_proposal
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]
        reg_b = self._parse(tool_register_agent(agent_id="b"))
        token_b = reg_b["auth_token"]

        prop_result = self._parse(tool_propose_protocol(agent_id="a", auth_token=token_a, peer_id="b"))
        proposal_id = prop_result["proposal"]["proposal_id"]

        resp_result = self._parse(tool_respond_to_proposal(
            proposal_id=proposal_id,
            accepted=False,
            responder_agent_id="b",
            auth_token=token_b,
            reason="Not interested",
        ))
        assert resp_result["resulting_mode"] == "degraded"

    # -- Degraded interaction tools --

    def test_start_degraded(self):
        from concordia.mcp_server import tool_start_degraded
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]
        result = self._parse(tool_start_degraded(
            agent_id="a", auth_token=token_a, peer_id="b",
        ))
        assert result["interaction"]["mode"] == "degraded"
        assert result["interaction"]["rounds"] == 0

    def test_degraded_message(self):
        from concordia.mcp_server import tool_start_degraded, tool_degraded_message
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]
        start = self._parse(tool_start_degraded(agent_id="a", auth_token=token_a, peer_id="b"))
        iid = start["interaction"]["interaction_id"]

        msg = self._parse(tool_degraded_message(
            interaction_id=iid, from_agent="a", auth_token=token_a, content="I want to buy X",
        ))
        assert msg["total_rounds"] == 1

    def test_efficiency_report(self):
        from concordia.mcp_server import (
            tool_start_degraded, tool_degraded_message, tool_efficiency_report,
        )
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]
        reg_b = self._parse(tool_register_agent(agent_id="b"))
        token_b = reg_b["auth_token"]

        start = self._parse(tool_start_degraded(agent_id="a", auth_token=token_a, peer_id="b"))
        iid = start["interaction"]["interaction_id"]

        for i in range(6):
            agent_id = "a" if i % 2 == 0 else "b"
            token = token_a if i % 2 == 0 else token_b
            tool_degraded_message(
                interaction_id=iid,
                from_agent=agent_id,
                auth_token=token,
                content=f"Round {i+1}",
            )

        report = self._parse(tool_efficiency_report(interaction_id=iid))
        assert report["actual_rounds"] == 6
        assert report["estimated_concordia_rounds"] == 2
        assert report["had_binding_commitment"] is False
        assert "concordia-protocol" in report["recommendation"]

    def test_efficiency_report_not_found(self):
        from concordia.mcp_server import tool_efficiency_report
        result = self._parse(tool_efficiency_report(interaction_id="nope"))
        assert "error" in result

    # -- Full viral loop via handle_tool_call --

    def test_full_viral_loop(self):
        """End-to-end: register → propose protocol → decline → degraded → report."""
        from concordia.mcp_server import handle_tool_call

        # Register the Concordia agent
        reg = handle_tool_call("concordia_register_agent", {
            "agent_id": "concordia_seller",
            "categories": ["electronics"],
            "roles": ["seller"],
        })
        assert reg["registered"] is True
        seller_token = reg["auth_token"]

        # Register the basic buyer (for auth token in response)
        buyer_reg = handle_tool_call("concordia_register_agent", {
            "agent_id": "basic_buyer",
        })
        buyer_token = buyer_reg["auth_token"]

        # Propose protocol to unknown peer
        prop = handle_tool_call("concordia_propose_protocol", {
            "agent_id": "concordia_seller",
            "auth_token": seller_token,
            "peer_id": "basic_buyer",
        })
        proposal_id = prop["proposal"]["proposal_id"]

        # Peer declines
        resp = handle_tool_call("concordia_respond_to_proposal", {
            "proposal_id": proposal_id,
            "accepted": False,
            "responder_agent_id": "basic_buyer",
            "auth_token": buyer_token,
            "reason": "I don't know what Concordia is",
        })
        assert resp["resulting_mode"] == "degraded"

        # Start degraded interaction
        degraded = handle_tool_call("concordia_start_degraded", {
            "agent_id": "concordia_seller",
            "auth_token": seller_token,
            "peer_id": "basic_buyer",
            "peer_status": "declined",
            "proposal_id": proposal_id,
        })
        iid = degraded["interaction"]["interaction_id"]

        # Simulate 8 rounds of unstructured back-and-forth
        messages = [
            ("concordia_seller", seller_token, "I have a Canon R5 for sale"),
            ("basic_buyer", buyer_token, "How much?"),
            ("concordia_seller", seller_token, "Asking $2200"),
            ("basic_buyer", buyer_token, "Too high, I'll do $1800"),
            ("concordia_seller", seller_token, "How about $2000?"),
            ("basic_buyer", buyer_token, "What about $1900 with shipping?"),
            ("concordia_seller", seller_token, "Fine, $1950 shipped"),
            ("basic_buyer", buyer_token, "Deal"),
        ]
        for from_agent, token, content in messages:
            handle_tool_call("concordia_degraded_message", {
                "interaction_id": iid,
                "from_agent": from_agent,
                "auth_token": token,
                "content": content,
            })

        # Generate efficiency report
        report = handle_tool_call("concordia_efficiency_report", {
            "interaction_id": iid,
        })
        assert report["actual_rounds"] == 8
        assert report["estimated_concordia_rounds"] < 8
        assert report["had_binding_commitment"] is False
        assert report["had_session_receipt"] is False
        assert report["had_reputation_attestation"] is False

        # Verify the agent is findable via search (by category + role + description)
        search = handle_tool_call("concordia_search_agents", {
            "category": "electronics",
            "role": "seller",
        })
        # Should find both agents since basic_buyer has default roles including seller
        # Filter for the specific agent we want
        agents = [a for a in search["agents"] if a["agent_id"] == "concordia_seller"]
        assert len(agents) == 1
        assert agents[0]["agent_id"] == "concordia_seller"


# ===================================================================
# Agent Capability Profile Tests (Phase 1)
# ===================================================================

class TestAgentCapabilityProfile:
    """Tests for the new discovery profile schema."""

    def test_profile_creation_minimal(self):
        from concordia.agent_profile import AgentCapabilityProfile

        profile = AgentCapabilityProfile(
            agent_id="agent_123",
            name="Test Agent",
            description="A test agent",
        )
        assert profile.agent_id == "agent_123"
        assert profile.name == "Test Agent"
        assert profile.type == "concordia.agent_profile"
        assert profile.version == "1.0"

    def test_profile_to_dict(self):
        from concordia.agent_profile import AgentCapabilityProfile, Capabilities

        profile = AgentCapabilityProfile(
            agent_id="agent_123",
            name="Test Agent",
            description="Test",
            capabilities=Capabilities(
                categories=["infrastructure.compute"],
                offer_types=["basic", "conditional"],
            ),
        )
        d = profile.to_dict()
        assert d["agent_id"] == "agent_123"
        assert d["type"] == "concordia.agent_profile"
        assert d["capabilities"]["categories"] == ["infrastructure.compute"]
        assert d["capabilities"]["offer_types"] == ["basic", "conditional"]

    def test_profile_canonical_json(self):
        from concordia.agent_profile import AgentCapabilityProfile

        profile = AgentCapabilityProfile(
            agent_id="agent_123",
            name="Test",
            description="Test",
        )
        canonical = profile.to_canonical_json_bytes()
        assert isinstance(canonical, bytes)
        assert b"agent_123" in canonical
        assert b"concordia.agent_profile" in canonical
        # Signature field should not be in canonical form
        assert b"signature" not in canonical

    def test_profile_from_dict(self):
        from concordia.agent_profile import AgentCapabilityProfile

        data = {
            "type": "concordia.agent_profile",
            "version": "1.0",
            "agent_id": "agent_xyz",
            "name": "XYZ Agent",
            "description": "Test agent",
            "capabilities": {
                "categories": ["electronics"],
                "offer_types": ["basic"],
            },
            "signature": "test_sig",
        }
        profile = AgentCapabilityProfile.from_dict(data)
        assert profile.agent_id == "agent_xyz"
        assert profile.name == "XYZ Agent"
        assert profile.signature == "test_sig"
        assert profile.capabilities.categories == ["electronics"]

    def test_profile_with_trust_signals(self):
        from concordia.agent_profile import (
            AgentCapabilityProfile,
            TrustSignals,
            Sovereignty,
        )

        profile = AgentCapabilityProfile(
            agent_id="agent_123",
            name="Agent",
            description="Test",
            trust_signals=TrustSignals(
                verascore_did="did:key:z6Mk...",
                verascore_tier="verified-sovereign",
                verascore_composite=92,
                concordia_sessions_completed=42,
                sovereignty=Sovereignty(L1="Full", L2="Full", L3="Full", L4="Full"),
            ),
        )
        d = profile.to_dict()
        assert d["trust_signals"]["verascore_composite"] == 92
        assert d["trust_signals"]["concordia_sessions_completed"] == 42
        assert d["trust_signals"]["sovereignty"]["L1"] == "Full"

    def test_profile_with_endpoints(self):
        from concordia.agent_profile import AgentCapabilityProfile, Endpoints

        profile = AgentCapabilityProfile(
            agent_id="agent_123",
            name="Agent",
            description="Test",
            endpoints=Endpoints(
                negotiate="https://agent.example.com/negotiate",
                a2a_card="https://agent.example.com/.well-known/agent.json",
            ),
        )
        d = profile.to_dict()
        assert d["endpoints"]["negotiate"] == "https://agent.example.com/negotiate"


# ===================================================================
# Agent Profile Store Tests
# ===================================================================

class TestAgentProfileStore:
    """Tests for in-memory profile storage and search."""

    def test_store_publish_and_get(self):
        from concordia.agent_profile import AgentCapabilityProfile, AgentProfileStore

        store = AgentProfileStore()
        profile = AgentCapabilityProfile(
            agent_id="agent_1",
            name="Agent 1",
            description="Test",
        )
        stored = store.publish(profile, verify_signature=False)
        assert stored.agent_id == "agent_1"

        retrieved = store.get("agent_1")
        assert retrieved is not None
        assert retrieved.agent_id == "agent_1"

    def test_store_get_missing(self):
        from concordia.agent_profile import AgentProfileStore

        store = AgentProfileStore()
        assert store.get("nonexistent") is None

    def test_store_delete(self):
        from concordia.agent_profile import AgentCapabilityProfile, AgentProfileStore

        store = AgentProfileStore()
        profile = AgentCapabilityProfile(
            agent_id="agent_1",
            name="Agent",
            description="Test",
        )
        store.publish(profile, verify_signature=False)
        assert store.get("agent_1") is not None

        deleted = store.delete("agent_1")
        assert deleted is True
        assert store.get("agent_1") is None

    def test_store_delete_missing(self):
        from concordia.agent_profile import AgentProfileStore

        store = AgentProfileStore()
        assert store.delete("nonexistent") is False

    def test_store_list_all(self):
        from concordia.agent_profile import AgentCapabilityProfile, AgentProfileStore

        store = AgentProfileStore()
        for i in range(3):
            profile = AgentCapabilityProfile(
                agent_id=f"agent_{i}",
                name=f"Agent {i}",
                description="Test",
            )
            store.publish(profile, verify_signature=False)

        all_profiles = store.list_all()
        assert len(all_profiles) == 3
        ids = {p.agent_id for p in all_profiles}
        assert ids == {"agent_0", "agent_1", "agent_2"}

    def test_store_count(self):
        from concordia.agent_profile import AgentCapabilityProfile, AgentProfileStore

        store = AgentProfileStore()
        assert store.count() == 0

        for i in range(5):
            profile = AgentCapabilityProfile(
                agent_id=f"agent_{i}",
                name=f"Agent {i}",
                description="Test",
            )
            store.publish(profile, verify_signature=False)

        assert store.count() == 5

    def test_store_search_by_category(self):
        from concordia.agent_profile import (
            AgentCapabilityProfile,
            AgentProfileStore,
            Capabilities,
        )

        store = AgentProfileStore()
        for i, cats in enumerate(
            [["infrastructure.compute"], ["electronics"], ["infrastructure.compute"]]
        ):
            profile = AgentCapabilityProfile(
                agent_id=f"agent_{i}",
                name=f"Agent {i}",
                description="Test",
                capabilities=Capabilities(categories=cats),
            )
            store.publish(profile, verify_signature=False)

        results = store.search(categories=["infrastructure.compute"])
        assert len(results) == 2
        agent_ids = {p[0].agent_id for p in results}
        assert agent_ids == {"agent_0", "agent_2"}

    def test_store_search_by_verascore_min(self):
        from concordia.agent_profile import (
            AgentCapabilityProfile,
            AgentProfileStore,
            TrustSignals,
        )

        store = AgentProfileStore()
        for i, score in enumerate([50, 75, 90]):
            profile = AgentCapabilityProfile(
                agent_id=f"agent_{i}",
                name=f"Agent {i}",
                description="Test",
                trust_signals=TrustSignals(verascore_composite=score),
            )
            store.publish(profile, verify_signature=False)

        results = store.search(min_verascore=75)
        assert len(results) == 2
        agent_ids = {p[0].agent_id for p in results}
        assert agent_ids == {"agent_1", "agent_2"}

    def test_store_search_by_offer_types_required(self):
        from concordia.agent_profile import (
            AgentCapabilityProfile,
            AgentProfileStore,
            Capabilities,
        )

        store = AgentProfileStore()
        for i, types in enumerate(
            [
                ["basic"],
                ["basic", "conditional"],
                ["basic", "conditional", "bundle"],
            ]
        ):
            profile = AgentCapabilityProfile(
                agent_id=f"agent_{i}",
                name=f"Agent {i}",
                description="Test",
                capabilities=Capabilities(offer_types=types),
            )
            store.publish(profile, verify_signature=False)

        # Require both basic and conditional
        results = store.search(offer_types_required=["basic", "conditional"])
        assert len(results) == 2
        agent_ids = {p[0].agent_id for p in results}
        assert agent_ids == {"agent_1", "agent_2"}

    def test_store_search_by_jurisdiction(self):
        from concordia.agent_profile import (
            AgentCapabilityProfile,
            AgentProfileStore,
            Location,
        )

        store = AgentProfileStore()
        for i, juris in enumerate([["US-CA"], ["EU"], ["US-CA", "EU"]]):
            profile = AgentCapabilityProfile(
                agent_id=f"agent_{i}",
                name=f"Agent {i}",
                description="Test",
                location=Location(jurisdictions=juris),
            )
            store.publish(profile, verify_signature=False)

        results = store.search(jurisdictions=["EU"])
        assert len(results) == 2
        agent_ids = {p[0].agent_id for p in results}
        assert agent_ids == {"agent_1", "agent_2"}

    def test_store_search_by_concordia_preferred(self):
        from concordia.agent_profile import (
            AgentCapabilityProfile,
            AgentProfileStore,
            TrustSignals,
        )

        store = AgentProfileStore()
        for i, pref in enumerate([True, False, True]):
            profile = AgentCapabilityProfile(
                agent_id=f"agent_{i}",
                name=f"Agent {i}",
                description="Test",
                trust_signals=TrustSignals(concordia_preferred=pref),
            )
            store.publish(profile, verify_signature=False)

        results = store.search(concordia_preferred=True)
        assert len(results) == 2
        agent_ids = {p[0].agent_id for p in results}
        assert agent_ids == {"agent_0", "agent_2"}

    def test_store_search_combined_filters(self):
        from concordia.agent_profile import (
            AgentCapabilityProfile,
            AgentProfileStore,
            Capabilities,
            TrustSignals,
        )

        store = AgentProfileStore()
        # Agent 0: electronics, score 50
        profile0 = AgentCapabilityProfile(
            agent_id="agent_0",
            name="Agent 0",
            description="Test",
            capabilities=Capabilities(categories=["electronics"]),
            trust_signals=TrustSignals(verascore_composite=50),
        )
        store.publish(profile0, verify_signature=False)

        # Agent 1: electronics, score 85
        profile1 = AgentCapabilityProfile(
            agent_id="agent_1",
            name="Agent 1",
            description="Test",
            capabilities=Capabilities(categories=["electronics"]),
            trust_signals=TrustSignals(verascore_composite=85),
        )
        store.publish(profile1, verify_signature=False)

        # Agent 2: infrastructure, score 90
        profile2 = AgentCapabilityProfile(
            agent_id="agent_2",
            name="Agent 2",
            description="Test",
            capabilities=Capabilities(categories=["infrastructure.compute"]),
            trust_signals=TrustSignals(verascore_composite=90),
        )
        store.publish(profile2, verify_signature=False)

        # Filter: electronics category AND min_verascore 75
        results = store.search(
            categories=["electronics"],
            min_verascore=75,
        )
        assert len(results) == 1
        assert results[0][0].agent_id == "agent_1"

    def test_store_search_sorting_by_verascore(self):
        from concordia.agent_profile import (
            AgentCapabilityProfile,
            AgentProfileStore,
            TrustSignals,
        )

        store = AgentProfileStore()
        for i, score in enumerate([60, 90, 75]):
            profile = AgentCapabilityProfile(
                agent_id=f"agent_{i}",
                name=f"Agent {i}",
                description="Test",
                trust_signals=TrustSignals(verascore_composite=score),
            )
            store.publish(profile, verify_signature=False)

        results = store.search(sort_by="verascore_composite")
        # Should be sorted by score descending: 90, 75, 60
        assert results[0][0].agent_id == "agent_1"  # 90
        assert results[1][0].agent_id == "agent_2"  # 75
        assert results[2][0].agent_id == "agent_0"  # 60

    def test_store_search_sorting_by_agreement_rate(self):
        from concordia.agent_profile import (
            AgentCapabilityProfile,
            AgentProfileStore,
            NegotiationProfile,
        )

        store = AgentProfileStore()
        for i, rate in enumerate([0.6, 0.95, 0.75]):
            profile = AgentCapabilityProfile(
                agent_id=f"agent_{i}",
                name=f"Agent {i}",
                description="Test",
                negotiation_profile=NegotiationProfile(agreement_rate=rate),
            )
            store.publish(profile, verify_signature=False)

        results = store.search(sort_by="agreement_rate")
        # Should be sorted by agreement_rate descending: 0.95, 0.75, 0.6
        assert results[0][0].agent_id == "agent_1"
        assert results[1][0].agent_id == "agent_2"
        assert results[2][0].agent_id == "agent_0"

    def test_store_search_limit(self):
        from concordia.agent_profile import AgentCapabilityProfile, AgentProfileStore

        store = AgentProfileStore()
        for i in range(10):
            profile = AgentCapabilityProfile(
                agent_id=f"agent_{i}",
                name=f"Agent {i}",
                description="Test",
            )
            store.publish(profile, verify_signature=False)

        results = store.search(limit=3)
        assert len(results) == 3

    def test_store_search_no_matches(self):
        from concordia.agent_profile import (
            AgentCapabilityProfile,
            AgentProfileStore,
            Capabilities,
        )

        store = AgentProfileStore()
        profile = AgentCapabilityProfile(
            agent_id="agent_1",
            name="Agent 1",
            description="Test",
            capabilities=Capabilities(categories=["electronics"]),
        )
        store.publish(profile, verify_signature=False)

        results = store.search(categories=["furniture"])
        assert len(results) == 0

    def test_store_capacity_limit(self):
        from concordia.agent_profile import AgentCapabilityProfile, AgentProfileStore

        store = AgentProfileStore()
        # Fill up to capacity
        for i in range(store.MAX_PROFILES):
            profile = AgentCapabilityProfile(
                agent_id=f"agent_{i}",
                name=f"Agent {i}",
                description="Test",
            )
            store.publish(profile, verify_signature=False)

        # Try to add one more
        overflow = AgentCapabilityProfile(
            agent_id="overflow",
            name="Overflow",
            description="Should fail",
        )
        with pytest.raises(RuntimeError):
            store.publish(overflow, verify_signature=False)

    def test_store_update_existing(self):
        from concordia.agent_profile import AgentCapabilityProfile, AgentProfileStore

        store = AgentProfileStore()
        profile = AgentCapabilityProfile(
            agent_id="agent_1",
            name="Agent 1",
            description="Original",
        )
        store.publish(profile, verify_signature=False)

        # Update with new description
        updated = AgentCapabilityProfile(
            agent_id="agent_1",
            name="Agent 1",
            description="Updated",
        )
        store.publish(updated, verify_signature=False)

        retrieved = store.get("agent_1")
        assert retrieved.description == "Updated"
        assert store.count() == 1  # Still only one agent

    def test_store_stats(self):
        from concordia.agent_profile import (
            AgentCapabilityProfile,
            AgentProfileStore,
            Capabilities,
            TrustSignals,
        )

        store = AgentProfileStore()
        for i, score in enumerate([60, 80, 100]):
            profile = AgentCapabilityProfile(
                agent_id=f"agent_{i}",
                name=f"Agent {i}",
                description="Test",
                capabilities=Capabilities(
                    categories=["electronics", "infrastructure.compute"]
                ),
                trust_signals=TrustSignals(verascore_composite=score),
            )
            store.publish(profile, verify_signature=False)

        stats = store.get_stats()
        assert stats["total_profiles"] == 3
        assert stats["average_verascore"] == 80.0
        assert stats["total_categories"] == 2  # electronics, infrastructure.compute
        assert stats["concordia_preferred_count"] == 3

    def test_store_match_score_with_categories(self):
        """Verify match_score computation for category overlap."""
        from concordia.agent_profile import (
            AgentCapabilityProfile,
            AgentProfileStore,
            Capabilities,
        )

        store = AgentProfileStore()
        profile = AgentCapabilityProfile(
            agent_id="agent_1",
            name="Agent",
            description="Test",
            capabilities=Capabilities(categories=["electronics", "furniture"]),
        )
        store.publish(profile, verify_signature=False)

        # Search for electronics only — should have partial overlap
        results = store.search(categories=["electronics"])
        assert len(results) == 1
        match_score = results[0][1]
        assert 0.5 <= match_score <= 1.0  # Between baseline and full
