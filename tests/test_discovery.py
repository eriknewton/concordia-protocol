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
        from concordia.mcp_server import tool_register_agent, tool_deregister_agent
        tool_register_agent(agent_id="temp_agent")
        result = self._parse(tool_deregister_agent(agent_id="temp_agent"))
        assert result["removed"] is True

    # -- Protocol meta-negotiation tools --

    def test_propose_protocol(self):
        from concordia.mcp_server import tool_propose_protocol
        result = self._parse(tool_propose_protocol(
            agent_id="concordia_agent",
            peer_id="unknown_peer",
        ))
        assert "proposal" in result
        assert result["proposal"]["type"] == "concordia.protocol_proposal"
        assert len(result["proposal"]["benefits"]) > 0

    def test_respond_accept(self):
        from concordia.mcp_server import tool_propose_protocol, tool_respond_to_proposal
        prop_result = self._parse(tool_propose_protocol("a", "b"))
        proposal_id = prop_result["proposal"]["proposal_id"]

        resp_result = self._parse(tool_respond_to_proposal(
            proposal_id=proposal_id,
            accepted=True,
            responder_agent_id="b",
        ))
        assert resp_result["resulting_mode"] == "upgraded"

    def test_respond_decline(self):
        from concordia.mcp_server import tool_propose_protocol, tool_respond_to_proposal
        prop_result = self._parse(tool_propose_protocol("a", "b"))
        proposal_id = prop_result["proposal"]["proposal_id"]

        resp_result = self._parse(tool_respond_to_proposal(
            proposal_id=proposal_id,
            accepted=False,
            responder_agent_id="b",
            reason="Not interested",
        ))
        assert resp_result["resulting_mode"] == "degraded"

    # -- Degraded interaction tools --

    def test_start_degraded(self):
        from concordia.mcp_server import tool_start_degraded
        result = self._parse(tool_start_degraded(
            agent_id="a", peer_id="b",
        ))
        assert result["interaction"]["mode"] == "degraded"
        assert result["interaction"]["rounds"] == 0

    def test_degraded_message(self):
        from concordia.mcp_server import tool_start_degraded, tool_degraded_message
        start = self._parse(tool_start_degraded(agent_id="a", peer_id="b"))
        iid = start["interaction"]["interaction_id"]

        msg = self._parse(tool_degraded_message(
            interaction_id=iid, from_agent="a", content="I want to buy X",
        ))
        assert msg["total_rounds"] == 1

    def test_efficiency_report(self):
        from concordia.mcp_server import (
            tool_start_degraded, tool_degraded_message, tool_efficiency_report,
        )
        start = self._parse(tool_start_degraded(agent_id="a", peer_id="b"))
        iid = start["interaction"]["interaction_id"]

        for i in range(6):
            tool_degraded_message(
                interaction_id=iid,
                from_agent="a" if i % 2 == 0 else "b",
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

        # Propose protocol to unknown peer
        prop = handle_tool_call("concordia_propose_protocol", {
            "agent_id": "concordia_seller",
            "peer_id": "basic_buyer",
        })
        proposal_id = prop["proposal"]["proposal_id"]

        # Peer declines
        resp = handle_tool_call("concordia_respond_to_proposal", {
            "proposal_id": proposal_id,
            "accepted": False,
            "responder_agent_id": "basic_buyer",
            "reason": "I don't know what Concordia is",
        })
        assert resp["resulting_mode"] == "degraded"

        # Start degraded interaction
        degraded = handle_tool_call("concordia_start_degraded", {
            "agent_id": "concordia_seller",
            "peer_id": "basic_buyer",
            "peer_status": "declined",
            "proposal_id": proposal_id,
        })
        iid = degraded["interaction"]["interaction_id"]

        # Simulate 8 rounds of unstructured back-and-forth
        messages = [
            ("concordia_seller", "I have a Canon R5 for sale"),
            ("basic_buyer", "How much?"),
            ("concordia_seller", "Asking $2200"),
            ("basic_buyer", "Too high, I'll do $1800"),
            ("concordia_seller", "How about $2000?"),
            ("basic_buyer", "What about $1900 with shipping?"),
            ("concordia_seller", "Fine, $1950 shipped"),
            ("basic_buyer", "Deal"),
        ]
        for from_agent, content in messages:
            handle_tool_call("concordia_degraded_message", {
                "interaction_id": iid,
                "from_agent": from_agent,
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

        # Verify the agent is findable via search
        search = handle_tool_call("concordia_search_agents", {
            "category": "electronics",
            "role": "seller",
        })
        assert search["count"] == 1
        assert search["agents"][0]["agent_id"] == "concordia_seller"
