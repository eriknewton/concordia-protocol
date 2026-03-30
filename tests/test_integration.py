"""End-to-end multi-agent integration tests.

Validates the full system with real multi-agent negotiation scenarios
running through the MCP tool interface.

Scenarios:
1. Full negotiation lifecycle
2. Want/Have matching -> negotiation
3. Relay-mediated negotiation
4. Graceful degradation (Concordia meets non-Concordia)
5. Reputation-informed negotiation with receipt bundles
6. Sanctuary bridge
7. Adversarial — Sybil attempt
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from concordia.mcp_server import (
    handle_tool_call,
    _store,
    _attestation_store,
    _key_registry,
)
from tests.conftest import run_negotiation, populated_reputation, SimulatedAgent


# ---------------------------------------------------------------------------
# Scenario 1: Full negotiation lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestFullNegotiationLifecycle:

    def test_discovery_to_agreement(self, make_agent):
        """Two agents discover each other, negotiate, generate receipts, and build reputation."""
        agent_a = make_agent("seller_alpha", categories=["electronics"])
        agent_b = make_agent("buyer_beta", categories=["electronics"])

        # Search for agents
        search = handle_tool_call("concordia_search_agents", {
            "category": "electronics",
        })
        agent_ids = [a["agent_id"] for a in search["agents"]]
        assert "buyer_beta" in agent_ids
        assert "seller_alpha" in agent_ids

        # Check reputation (should be empty/None)
        rep = handle_tool_call("concordia_reputation_score", {
            "agent_id": "buyer_beta",
        })
        assert rep["score"] is None

        # Run a full negotiation
        ctx = run_negotiation(agent_a, agent_b, category="electronics.cameras")

        # Both have attestations now
        rep_a = handle_tool_call("concordia_reputation_score", {
            "agent_id": "seller_alpha",
        })
        assert rep_a["score"] is not None
        assert rep_a["score"]["total_negotiations"] == 1

        rep_b = handle_tool_call("concordia_reputation_score", {
            "agent_id": "buyer_beta",
        })
        assert rep_b["score"] is not None
        assert rep_b["score"]["total_negotiations"] == 1

    def test_multi_round_negotiation(self, make_agent):
        """Multi-round negotiation with propose, counter, counter, accept."""
        a = make_agent("agent_s")
        b = make_agent("agent_b")

        result = handle_tool_call("concordia_open_session", {
            "initiator_id": "agent_s",
            "responder_id": "agent_b",
            "terms": {"price": {"type": "numeric", "label": "Price"}},
        })
        sid = result["session_id"]
        t_a = result["initiator_token"]
        t_b = result["responder_token"]

        handle_tool_call("concordia_propose", {
            "session_id": sid, "role": "initiator",
            "terms": {"price": {"value": 1000}},
            "auth_token": t_a, "reasoning": "Starting high",
        })
        handle_tool_call("concordia_counter", {
            "session_id": sid, "role": "responder",
            "terms": {"price": {"value": 700}},
            "auth_token": t_b, "reasoning": "Too expensive",
        })
        handle_tool_call("concordia_counter", {
            "session_id": sid, "role": "initiator",
            "terms": {"price": {"value": 850}},
            "auth_token": t_a, "reasoning": "Meeting halfway",
        })
        accept_result = handle_tool_call("concordia_accept", {
            "session_id": sid, "role": "responder",
            "auth_token": t_b,
        })
        assert accept_result["state"] == "agreed"

        status = handle_tool_call("concordia_session_status", {
            "session_id": sid,
            "auth_token": t_a,
        })
        assert status["state"] == "agreed"
        assert status["round_count"] >= 3

    def test_receipt_generation(self, make_agent):
        """Receipts are valid attestations with correct parties."""
        a = make_agent("rcpt_seller")
        b = make_agent("rcpt_buyer")
        ctx = run_negotiation(a, b)

        receipt = handle_tool_call("concordia_session_receipt", {
            "session_id": ctx["session_id"],
            "auth_token": ctx["init_token"],
        })
        att = receipt["receipt"]
        assert att["outcome"]["status"] == "agreed"
        party_ids = [p["agent_id"] for p in att["parties"]]
        assert "rcpt_seller" in party_ids
        assert "rcpt_buyer" in party_ids

    def test_create_receipt_bundle_after_negotiation(self, make_agent):
        """Agent creates a receipt bundle from completed negotiation."""
        a = make_agent("bundle_seller")
        b = make_agent("bundle_buyer")
        run_negotiation(a, b)

        bundle = handle_tool_call("concordia_create_receipt_bundle", {
            "agent_id": "bundle_seller",
            "auth_token": a.auth_token,
        })
        assert "error" not in bundle, f"Error: {bundle}"
        assert bundle["bundle_id"].startswith("bundle_")
        assert len(bundle["attestations"]) == 1


# ---------------------------------------------------------------------------
# Scenario 2: Want/Have matching -> negotiation
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestWantHaveMatching:

    def test_want_have_match_to_negotiation(self, make_agent):
        """Post a want, post a matching have, find match, negotiate."""
        buyer = make_agent("buyer_want")
        seller = make_agent("seller_have")

        # Buyer posts want
        want_result = handle_tool_call("concordia_post_want", {
            "agent_id": "buyer_want",
            "auth_token": buyer.auth_token,
            "category": "electronics",
            "terms": {"min_price": 500, "max_price": 1000, "currency": "USD"},
        })
        assert want_result.get("want")

        # Seller posts have
        have_result = handle_tool_call("concordia_post_have", {
            "agent_id": "seller_have",
            "auth_token": seller.auth_token,
            "category": "electronics",
            "terms": {"price": 800, "currency": "USD"},
        })
        assert have_result.get("have")

        # Find matches
        matches = handle_tool_call("concordia_find_matches", {
            "agent_id": "buyer_want",
        })
        assert matches["count"] >= 1

        # Proceed to negotiation with the matched parties
        ctx = run_negotiation(buyer, seller, category="electronics")
        assert ctx["session_id"]

    def test_want_registry_stats(self, make_agent):
        """Registry stats reflect posted wants and haves."""
        a = make_agent("stats_agent")
        handle_tool_call("concordia_post_want", {
            "agent_id": "stats_agent",
            "auth_token": a.auth_token,
            "category": "services",
            "terms": {"budget": 1000},
        })
        stats = handle_tool_call("concordia_want_registry_stats", {})
        assert stats["active_wants"] >= 1


# ---------------------------------------------------------------------------
# Scenario 3: Relay-mediated negotiation
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestRelayNegotiation:

    def test_relay_full_cycle(self, make_agent):
        """Create relay, join, exchange messages, conclude, archive."""
        a = make_agent("relay_a")
        b = make_agent("relay_b")

        # Create relay session
        create = handle_tool_call("concordia_relay_create", {
            "initiator_id": "relay_a",
            "auth_token": a.auth_token,
        })
        session_data = create["session"]
        relay_id = session_data["relay_session_id"]

        # B joins
        join = handle_tool_call("concordia_relay_join", {
            "relay_session_id": relay_id,
            "agent_id": "relay_b",
            "auth_token": b.auth_token,
        })
        assert join["joined"]

        # Exchange messages
        handle_tool_call("concordia_relay_send", {
            "relay_session_id": relay_id,
            "from_agent": "relay_a",
            "auth_token": a.auth_token,
            "message_type": "offer",
            "payload": {"type": "offer", "price": 500},
        })
        messages = handle_tool_call("concordia_relay_receive", {
            "agent_id": "relay_b",
            "auth_token": b.auth_token,
            "relay_session_id": relay_id,
        })
        assert messages["count"] >= 1

        handle_tool_call("concordia_relay_send", {
            "relay_session_id": relay_id,
            "from_agent": "relay_b",
            "auth_token": b.auth_token,
            "message_type": "counter",
            "payload": {"type": "counter", "price": 600},
        })

        # Conclude
        conclude = handle_tool_call("concordia_relay_conclude", {
            "relay_session_id": relay_id,
            "agent_id": "relay_a",
            "auth_token": a.auth_token,
        })
        assert conclude["concluded"]

        # Get transcript
        transcript = handle_tool_call("concordia_relay_transcript", {
            "relay_session_id": relay_id,
            "agent_id": "relay_a",
            "auth_token": a.auth_token,
        })
        assert transcript["count"] >= 2

        # Archive
        archive = handle_tool_call("concordia_relay_archive", {
            "relay_session_id": relay_id,
        })
        assert archive["archived"]

        # List archives
        archives = handle_tool_call("concordia_relay_list_archives", {})
        assert archives["count"] >= 1

    def test_relay_stats(self, make_agent):
        """Relay stats are updated correctly."""
        a = make_agent("rs_a")
        handle_tool_call("concordia_relay_create", {
            "initiator_id": "rs_a",
            "auth_token": a.auth_token,
        })
        stats = handle_tool_call("concordia_relay_stats", {})
        assert stats["total_sessions"] >= 1


# ---------------------------------------------------------------------------
# Scenario 4: Graceful degradation
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestGracefulDegradation:

    def test_protocol_declined_degraded_interaction(self, make_agent):
        """Agent proposes Concordia, peer declines, falls back to degraded."""
        a = make_agent("degrade_a")
        b = make_agent("degrade_b")

        # Propose protocol
        proposal = handle_tool_call("concordia_propose_protocol", {
            "agent_id": "degrade_a",
            "peer_id": "degrade_b",
            "auth_token": a.auth_token,
        })
        proposal_data = proposal["proposal"]
        proposal_id = proposal_data["proposal_id"]

        # Decline
        handle_tool_call("concordia_respond_to_proposal", {
            "proposal_id": proposal_id,
            "accepted": False,
            "responder_agent_id": "degrade_b",
            "auth_token": b.auth_token,
            "reason": "Not ready for structured protocol",
        })

        # Start degraded interaction
        degraded = handle_tool_call("concordia_start_degraded", {
            "agent_id": "degrade_a",
            "peer_id": "degrade_b",
            "auth_token": a.auth_token,
            "peer_status": "declined",
            "proposal_id": proposal_id,
        })
        interaction_data = degraded["interaction"]
        interaction_id = interaction_data["interaction_id"]

        # Exchange degraded messages
        handle_tool_call("concordia_degraded_message", {
            "interaction_id": interaction_id,
            "from_agent": "degrade_a",
            "content": "Would you sell the widget for $500?",
            "auth_token": a.auth_token,
        })
        handle_tool_call("concordia_degraded_message", {
            "interaction_id": interaction_id,
            "from_agent": "degrade_b",
            "content": "How about $600?",
            "auth_token": b.auth_token,
        })
        msg3 = handle_tool_call("concordia_degraded_message", {
            "interaction_id": interaction_id,
            "from_agent": "degrade_a",
            "content": "Deal at $550",
            "auth_token": a.auth_token,
        })
        assert msg3["total_rounds"] >= 3

        # Efficiency report
        report = handle_tool_call("concordia_efficiency_report", {
            "interaction_id": interaction_id,
        })
        assert "error" not in report


# ---------------------------------------------------------------------------
# Scenario 5: Reputation-informed negotiation with receipt bundles
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestReputationInformedNegotiation:

    def test_build_reputation_and_present_bundle(self, make_agent):
        """Run multiple negotiations, check reputation, create and verify bundle."""
        agent_a = make_agent("rep_seller")

        # Build reputation with 5 counterparties
        for i in range(5):
            cp = make_agent(f"rep_buyer_{i}")
            run_negotiation(agent_a, cp, category=f"cat_{i % 3}")

        # Check reputation
        rep = handle_tool_call("concordia_reputation_score", {
            "agent_id": "rep_seller",
        })
        assert rep["score"] is not None
        assert rep["score"]["total_negotiations"] == 5
        assert rep["score"]["overall_score"] > 0

        # Create receipt bundle
        bundle_result = handle_tool_call("concordia_create_receipt_bundle", {
            "agent_id": "rep_seller",
            "auth_token": agent_a.auth_token,
        })
        assert "error" not in bundle_result
        assert bundle_result["summary"]["total_negotiations"] == 5
        assert bundle_result["summary"]["unique_counterparties"] == 5

        # Verify the bundle
        bundle_dict = {
            k: v for k, v in bundle_result.items()
            if k in ("concordia_receipt_bundle", "bundle_id", "agent_id",
                     "created_at", "attestations", "summary", "agent_signature")
        }
        verify = handle_tool_call("concordia_verify_receipt_bundle", {
            "bundle": bundle_dict,
        })
        assert verify["valid"], f"Errors: {verify.get('errors')}"
        assert verify["summary_accurate"]
        # In-memory tests may trigger timing_anomaly (< 5s), but should not trigger diversity/self-dealing
        assert not verify["sybil_flags"]["low_counterparty_diversity"]
        assert not verify["sybil_flags"]["self_dealing"]

    def test_reputation_filtering_by_category(self, make_agent):
        """Bundle can be filtered by category."""
        a = make_agent("filter_seller")
        b = make_agent("filter_buyer_1")
        c = make_agent("filter_buyer_2")

        run_negotiation(a, b, category="electronics")
        run_negotiation(a, c, category="furniture")

        bundle = handle_tool_call("concordia_create_receipt_bundle", {
            "agent_id": "filter_seller",
            "auth_token": a.auth_token,
            "filter_category": "electronics",
        })
        assert "error" not in bundle
        assert len(bundle["attestations"]) == 1


# ---------------------------------------------------------------------------
# Scenario 6: Sanctuary bridge
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestSanctuaryBridge:

    def test_bridge_commitment_and_attestation(self, make_agent):
        """Configure bridge, negotiate, generate commitment and attestation payloads."""
        a = make_agent("bridge_seller")
        b = make_agent("bridge_buyer")

        # Configure bridge
        config = handle_tool_call("concordia_sanctuary_bridge_configure", {
            "enabled": True,
            "identity_mappings": [
                {"agent_id": "bridge_seller", "sanctuary_id": "sanc_seller", "did": "did:sanc:seller"},
                {"agent_id": "bridge_buyer", "sanctuary_id": "sanc_buyer", "did": "did:sanc:buyer"},
            ],
        })
        assert config["enabled"]

        # Negotiate to agreement
        ctx = run_negotiation(a, b)

        # Generate commitment
        commit = handle_tool_call("concordia_sanctuary_bridge_commit", {
            "session_id": ctx["session_id"],
        })
        assert "error" not in commit
        assert commit["sanctuary_enabled"]

        # Generate attestation
        attest = handle_tool_call("concordia_sanctuary_bridge_attest", {
            "attestation": ctx["attestation"],
        })
        assert "error" not in attest

        # Check bridge status
        status = handle_tool_call("concordia_sanctuary_bridge_status", {})
        assert status["enabled"]
        assert status["identity_count"] == 2


# ---------------------------------------------------------------------------
# Scenario 7: Adversarial — Sybil attempt
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestSybilDetection:

    def test_low_diversity_sybil(self, make_agent):
        """Low counterparty diversity is detected and flagged in bundles."""
        a = make_agent("sybil_agent")
        b = make_agent("sybil_sock")

        # Run several negotiations with the same counterparty
        for i in range(4):
            run_negotiation(a, b, category="widgets")

        rep = handle_tool_call("concordia_reputation_score", {
            "agent_id": "sybil_agent",
        })
        assert rep["score"] is not None
        assert rep["score"]["total_negotiations"] == 4

        # Create bundle
        bundle = handle_tool_call("concordia_create_receipt_bundle", {
            "agent_id": "sybil_agent",
            "auth_token": a.auth_token,
        })
        assert "error" not in bundle

        # Verify bundle — should flag low diversity
        bundle_dict = {
            k: v for k, v in bundle.items()
            if k in ("concordia_receipt_bundle", "bundle_id", "agent_id",
                     "created_at", "attestations", "summary", "agent_signature")
        }
        verify = handle_tool_call("concordia_verify_receipt_bundle", {
            "bundle": bundle_dict,
        })
        assert verify["sybil_flags"]["low_counterparty_diversity"]
        assert verify["sybil_flags"]["flagged"]

    def test_diverse_agent_not_flagged(self, make_agent):
        """An agent with diverse counterparties is not Sybil-flagged."""
        a = make_agent("legit_seller")
        for i in range(4):
            cp = make_agent(f"diverse_buyer_{i}")
            run_negotiation(a, cp)

        bundle = handle_tool_call("concordia_create_receipt_bundle", {
            "agent_id": "legit_seller",
            "auth_token": a.auth_token,
        })
        bundle_dict = {
            k: v for k, v in bundle.items()
            if k in ("concordia_receipt_bundle", "bundle_id", "agent_id",
                     "created_at", "attestations", "summary", "agent_signature")
        }
        verify = handle_tool_call("concordia_verify_receipt_bundle", {
            "bundle": bundle_dict,
        })
        # Diversity flag should not be set (4 unique counterparties)
        assert not verify["sybil_flags"]["low_counterparty_diversity"]
        assert not verify["sybil_flags"]["self_dealing"]
        assert not verify["sybil_flags"]["symmetric_concessions"]
        # Note: timing_anomaly may fire for in-memory tests (< 5s) — this is expected behavior

    def test_self_negotiation_blocked(self, make_agent):
        """Opening a session with yourself is rejected."""
        a = make_agent("self_dealer")
        result = handle_tool_call("concordia_open_session", {
            "initiator_id": "self_dealer",
            "responder_id": "self_dealer",
            "terms": {"price": {"type": "numeric", "label": "Price"}},
        })
        assert "error" in result


# ---------------------------------------------------------------------------
# Additional integration tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestAgentDiscovery:

    def test_register_search_deregister(self, make_agent):
        """Full agent discovery lifecycle."""
        a = make_agent("disco_agent", categories=["logistics", "shipping"])

        # Search
        results = handle_tool_call("concordia_search_agents", {
            "category": "logistics",
        })
        agent_ids = [ag["agent_id"] for ag in results["agents"]]
        assert "disco_agent" in agent_ids

        # Agent card
        card = handle_tool_call("concordia_agent_card", {
            "agent_id": "disco_agent",
        })
        assert card["found"]

        # Preferred badge
        badge = handle_tool_call("concordia_preferred_badge", {
            "agent_id": "disco_agent",
        })
        assert badge["found"]

        # Deregister
        dereg = handle_tool_call("concordia_deregister_agent", {
            "agent_id": "disco_agent",
            "auth_token": a.auth_token,
        })
        assert dereg["removed"]

    def test_reputation_query(self, make_agent):
        """Reputation query works after negotiation."""
        a = make_agent("query_seller")
        b = make_agent("query_buyer")
        run_negotiation(a, b)

        query = handle_tool_call("concordia_reputation_query", {
            "subject_agent_id": "query_seller",
            "requester_agent_id": "query_buyer",
        })
        assert "error" not in query


@pytest.mark.integration
class TestRejectionFlow:

    def test_rejection_generates_receipt(self, make_agent):
        """A rejected negotiation still generates a receipt."""
        a = make_agent("rej_seller")
        b = make_agent("rej_buyer")

        result = handle_tool_call("concordia_open_session", {
            "initiator_id": "rej_seller",
            "responder_id": "rej_buyer",
            "terms": {"price": {"type": "numeric", "label": "Price"}},
        })
        sid = result["session_id"]
        t_a = result["initiator_token"]
        t_b = result["responder_token"]

        handle_tool_call("concordia_propose", {
            "session_id": sid, "role": "initiator",
            "terms": {"price": {"value": 10000}},
            "auth_token": t_a,
        })
        handle_tool_call("concordia_reject", {
            "session_id": sid, "role": "responder",
            "auth_token": t_b,
            "reason": "Price too high",
        })

        receipt = handle_tool_call("concordia_session_receipt", {
            "session_id": sid,
            "auth_token": t_a,
        })
        assert receipt["receipt"]["outcome"]["status"] == "rejected"
