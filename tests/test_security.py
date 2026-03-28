"""Comprehensive security tests for the Concordia Protocol.

Tests cover the security fixes applied to:
  - Signing (canonical JSON validation, special float rejection)
  - Reputation Store (empty signature rejection, MAX_ATTESTATIONS)
  - Agent Registry (public_key field, MAX_AGENTS)
  - Negotiation Relay (access control, size limits, self-session prevention)
  - Want Registry (MAX_WANTS, MAX_HAVES)
  - Sanctuary Bridge (session_id and agreed_terms validation)
  - MCP Server (SessionStore self-negotiation prevention)
"""

from __future__ import annotations

import math
import pytest

from concordia.signing import canonical_json
from concordia.reputation import AttestationStore
from concordia.registry import AgentRegistry
from concordia.relay import NegotiationRelay
from concordia.want_registry import WantRegistry
from concordia.sanctuary_bridge import (
    build_commitment_payload,
    build_reputation_payload,
    bridge_on_agreement,
    bridge_on_attestation,
    SanctuaryBridgeConfig,
)
from concordia.mcp_server import SessionStore


# ===================================================================
# TestCanonicalJsonSecurity
# ===================================================================

class TestCanonicalJsonSecurity:
    """Test that canonical_json rejects special floats (NaN, Inf, -0.0)."""

    def test_nan_rejected(self):
        """Test that NaN is rejected."""
        with pytest.raises(ValueError, match="Cannot serialize special float"):
            canonical_json({"x": float("nan")})

    def test_infinity_rejected(self):
        """Test that positive infinity is rejected."""
        with pytest.raises(ValueError, match="Cannot serialize special float"):
            canonical_json({"x": float("inf")})

    def test_negative_infinity_rejected(self):
        """Test that negative infinity is rejected."""
        with pytest.raises(ValueError, match="Cannot serialize special float"):
            canonical_json({"x": float("-inf")})

    def test_negative_zero_rejected(self):
        """Test that negative zero is rejected."""
        with pytest.raises(ValueError, match="Cannot serialize negative zero"):
            canonical_json({"x": -0.0})

    def test_nested_special_float_rejected(self):
        """Test that NaN in nested dict is rejected."""
        with pytest.raises(ValueError, match="Cannot serialize special float"):
            canonical_json({"a": {"b": float("nan")}})

    def test_list_special_float_rejected(self):
        """Test that infinity in list is rejected."""
        with pytest.raises(ValueError, match="Cannot serialize special float"):
            canonical_json({"a": [1.0, float("inf")]})

    def test_normal_floats_pass(self):
        """Test that normal floats work fine."""
        result = canonical_json({"x": 1.5, "y": 0.0, "z": -3.14})
        assert isinstance(result, bytes)
        assert b"1.5" in result


# ===================================================================
# TestSignatureVerification
# ===================================================================

class TestSignatureVerification:
    """Test that empty/whitespace signatures are rejected during ingestion."""

    def test_empty_signature_rejected(self):
        """Test that an attestation with empty signature is rejected."""
        store = AttestationStore()

        attestation = {
            "concordia_attestation": "1.0.0",
            "attestation_id": "att_001",
            "session_id": "sess_001",
            "timestamp": "2026-01-01T00:00:00Z",
            "outcome": {
                "status": "agreed",
                "rounds": 3,
                "duration_seconds": 60.0,
            },
            "parties": [
                {
                    "agent_id": "agent_a",
                    "role": "initiator",
                    "behavior": {"concession_magnitude": 0.1},
                    "signature": "",  # Empty signature
                },
                {
                    "agent_id": "agent_b",
                    "role": "responder",
                    "behavior": {"concession_magnitude": 0.2},
                    "signature": "valid_sig_xyz",
                },
            ],
            "meta": {"category": "test"},
            "transcript_hash": "sha256:abc123",
        }

        accepted, result = store.ingest(attestation)
        assert not accepted
        assert any("signature must not be empty" in err for err in result.errors)

    def test_whitespace_signature_rejected(self):
        """Test that an attestation with whitespace-only signature is rejected."""
        store = AttestationStore()

        attestation = {
            "concordia_attestation": "1.0.0",
            "attestation_id": "att_002",
            "session_id": "sess_002",
            "timestamp": "2026-01-01T00:00:00Z",
            "outcome": {
                "status": "agreed",
                "rounds": 3,
                "duration_seconds": 60.0,
            },
            "parties": [
                {
                    "agent_id": "agent_a",
                    "role": "initiator",
                    "behavior": {"concession_magnitude": 0.1},
                    "signature": "   ",  # Whitespace only
                },
                {
                    "agent_id": "agent_b",
                    "role": "responder",
                    "behavior": {"concession_magnitude": 0.2},
                    "signature": "valid_sig_xyz",
                },
            ],
            "meta": {"category": "test"},
            "transcript_hash": "sha256:def456",
        }

        accepted, result = store.ingest(attestation)
        assert not accepted
        assert any("signature must not be empty" in err for err in result.errors)


# ===================================================================
# TestAttestationStoreLimits
# ===================================================================

class TestAttestationStoreLimits:
    """Test that MAX_ATTESTATIONS is enforced."""

    def test_max_attestations_enforced(self):
        """Test that the store enforces MAX_ATTESTATIONS."""
        store = AttestationStore()
        original_max = store.MAX_ATTESTATIONS
        store.MAX_ATTESTATIONS = 3

        try:
            # Ingest 3 attestations successfully
            for i in range(3):
                att = {
                    "concordia_attestation": "1.0.0",
                    "attestation_id": f"att_{i}",
                    "session_id": f"sess_{i}",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "outcome": {
                        "status": "agreed",
                        "rounds": 1,
                        "duration_seconds": 10.0,
                    },
                    "parties": [
                        {
                            "agent_id": f"agent_a_{i}",
                            "role": "initiator",
                            "behavior": {"concession_magnitude": 0.1},
                            "signature": "sig_a",
                        },
                        {
                            "agent_id": f"agent_b_{i}",
                            "role": "responder",
                            "behavior": {"concession_magnitude": 0.2},
                            "signature": "sig_b",
                        },
                    ],
                    "meta": {"category": "test"},
                    "transcript_hash": "sha256:abc",
                }
                accepted, result = store.ingest(att)
                assert accepted

            # 4th should be rejected
            att_4 = {
                "concordia_attestation": "1.0.0",
                "attestation_id": "att_4",
                "session_id": "sess_4",
                "timestamp": "2026-01-01T00:00:00Z",
                "outcome": {
                    "status": "agreed",
                    "rounds": 1,
                    "duration_seconds": 10.0,
                },
                "parties": [
                    {
                        "agent_id": "agent_a_4",
                        "role": "initiator",
                        "behavior": {"concession_magnitude": 0.1},
                        "signature": "sig_a",
                    },
                    {
                        "agent_id": "agent_b_4",
                        "role": "responder",
                        "behavior": {"concession_magnitude": 0.2},
                        "signature": "sig_b",
                    },
                ],
                "meta": {"category": "test"},
                "transcript_hash": "sha256:def",
            }
            accepted, result = store.ingest(att_4)
            assert not accepted
            assert any("capacity reached" in err for err in result.errors)
        finally:
            store.MAX_ATTESTATIONS = original_max


# ===================================================================
# TestSelfNegotiationPrevention
# ===================================================================

class TestSelfNegotiationPrevention:
    """Test that self-negotiation (same initiator/responder) is prevented."""

    def test_session_store_rejects_self_negotiation(self):
        """Test that SessionStore rejects self-negotiation."""
        store = SessionStore()

        with pytest.raises(ValueError, match="Self-negotiation is not allowed"):
            store.create(
                initiator_id="same_agent",
                responder_id="same_agent",
                terms={"price": {"type": "numeric", "label": "Price"}},
            )

    def test_relay_rejects_self_session(self):
        """Test that NegotiationRelay rejects self-sessions."""
        relay = NegotiationRelay()

        with pytest.raises(ValueError, match="Cannot create relay session with same agent"):
            relay.create_session(
                initiator_id="same_agent",
                responder_id="same_agent",
            )


# ===================================================================
# TestRelayAccessControl
# ===================================================================

class TestRelayAccessControl:
    """Test that relay enforces access control on transcripts and messages."""

    def test_transcript_access_denied_for_non_participant(self):
        """Test that non-participants cannot access transcript."""
        relay = NegotiationRelay()
        session = relay.create_session(
            initiator_id="agent_a",
            responder_id="agent_b",
        )

        # Send a message from A to B
        relay.send_message(
            relay_session_id=session.relay_session_id,
            from_agent="agent_a",
            message_type="negotiate.offer",
            payload={"terms": {"price": 100}},
        )

        # Try to get transcript as non-participant (agent_c)
        transcript = relay.get_transcript(
            relay_session_id=session.relay_session_id,
            requesting_agent="agent_c",
        )
        assert transcript is None

    def test_transcript_access_allowed_for_participant(self):
        """Test that participants can access transcript."""
        relay = NegotiationRelay()
        session = relay.create_session(
            initiator_id="agent_a",
            responder_id="agent_b",
        )

        relay.send_message(
            relay_session_id=session.relay_session_id,
            from_agent="agent_a",
            message_type="negotiate.offer",
            payload={"terms": {"price": 100}},
        )

        # Agent A (participant) can read transcript
        transcript = relay.get_transcript(
            relay_session_id=session.relay_session_id,
            requesting_agent="agent_a",
        )
        assert transcript is not None
        assert len(transcript) == 1

    def test_send_message_denied_for_non_participant(self):
        """Test that non-participants cannot send messages."""
        relay = NegotiationRelay()
        session = relay.create_session(
            initiator_id="agent_a",
            responder_id="agent_b",
        )

        # Try to send as non-participant (agent_c)
        msg = relay.send_message(
            relay_session_id=session.relay_session_id,
            from_agent="agent_c",
            message_type="negotiate.offer",
            payload={"terms": {"price": 100}},
        )
        assert msg is None

    def test_send_message_allowed_for_participant(self):
        """Test that participants can send messages."""
        relay = NegotiationRelay()
        session = relay.create_session(
            initiator_id="agent_a",
            responder_id="agent_b",
        )

        # Agent A (participant) can send
        msg = relay.send_message(
            relay_session_id=session.relay_session_id,
            from_agent="agent_a",
            message_type="negotiate.offer",
            payload={"terms": {"price": 100}},
        )
        assert msg is not None
        assert msg.from_agent == "agent_a"


# ===================================================================
# TestRelayLimits
# ===================================================================

class TestRelayLimits:
    """Test that relay enforces size and count limits."""

    def test_max_sessions_enforced(self):
        """Test that MAX_SESSIONS limit is enforced."""
        relay = NegotiationRelay()
        original_max = relay.MAX_SESSIONS
        relay.MAX_SESSIONS = 3

        try:
            # Create 3 sessions
            for i in range(3):
                session = relay.create_session(
                    initiator_id=f"agent_a_{i}",
                    responder_id=f"agent_b_{i}",
                )
                assert session is not None

            # 4th should raise
            with pytest.raises(ValueError, match="Relay session limit reached"):
                relay.create_session(
                    initiator_id="agent_a_4",
                    responder_id="agent_b_4",
                )
        finally:
            relay.MAX_SESSIONS = original_max

    def test_max_transcript_enforced(self):
        """Test that MAX_TRANSCRIPT_SIZE limit is enforced."""
        relay = NegotiationRelay()
        original_max = relay.MAX_TRANSCRIPT_SIZE
        relay.MAX_TRANSCRIPT_SIZE = 5

        try:
            session = relay.create_session(
                initiator_id="agent_a",
                responder_id="agent_b",
            )

            # Send 5 messages successfully
            for i in range(5):
                msg = relay.send_message(
                    relay_session_id=session.relay_session_id,
                    from_agent="agent_a" if i % 2 == 0 else "agent_b",
                    message_type="negotiate.offer",
                    payload={"round": i},
                )
                assert msg is not None

            # 6th should fail
            msg = relay.send_message(
                relay_session_id=session.relay_session_id,
                from_agent="agent_a",
                message_type="negotiate.offer",
                payload={"round": 5},
            )
            assert msg is None
        finally:
            relay.MAX_TRANSCRIPT_SIZE = original_max

    def test_max_mailbox_enforced(self):
        """Test that MAX_MAILBOX_SIZE limit is enforced."""
        relay = NegotiationRelay()
        original_max = relay.MAX_MAILBOX_SIZE
        relay.MAX_MAILBOX_SIZE = 3

        try:
            session = relay.create_session(
                initiator_id="agent_a",
                responder_id="agent_b",
            )

            # Send 3 messages to agent_b's mailbox (don't receive them)
            for i in range(3):
                msg = relay.send_message(
                    relay_session_id=session.relay_session_id,
                    from_agent="agent_a",
                    message_type="negotiate.offer",
                    payload={"msg": i},
                )
                assert msg is not None

            # 4th should fail (mailbox full)
            msg = relay.send_message(
                relay_session_id=session.relay_session_id,
                from_agent="agent_a",
                message_type="negotiate.offer",
                payload={"msg": 3},
            )
            assert msg is None
        finally:
            relay.MAX_MAILBOX_SIZE = original_max


# ===================================================================
# TestWantRegistryLimits
# ===================================================================

class TestWantRegistryLimits:
    """Test that Want Registry enforces MAX_WANTS and MAX_HAVES."""

    def test_max_wants_enforced(self):
        """Test that MAX_WANTS limit is enforced."""
        registry = WantRegistry()
        original_max = registry.MAX_WANTS
        registry.MAX_WANTS = 3

        try:
            # Post 3 wants
            for i in range(3):
                want, matches = registry.post_want(
                    agent_id=f"agent_{i}",
                    category="electronics",
                    terms={"price": {"min": 100, "max": 500}},
                )
                assert want is not None

            # 4th should raise
            with pytest.raises(ValueError, match="Want registry limit reached"):
                registry.post_want(
                    agent_id="agent_4",
                    category="electronics",
                    terms={"price": {"min": 100, "max": 500}},
                )
        finally:
            registry.MAX_WANTS = original_max

    def test_max_haves_enforced(self):
        """Test that MAX_HAVES limit is enforced."""
        registry = WantRegistry()
        original_max = registry.MAX_HAVES
        registry.MAX_HAVES = 3

        try:
            # Post 3 haves
            for i in range(3):
                have, matches = registry.post_have(
                    agent_id=f"agent_{i}",
                    category="electronics",
                    terms={"price": {"min": 100, "max": 500}},
                )
                assert have is not None

            # 4th should raise
            with pytest.raises(ValueError, match="Have registry limit reached"):
                registry.post_have(
                    agent_id="agent_4",
                    category="electronics",
                    terms={"price": {"min": 100, "max": 500}},
                )
        finally:
            registry.MAX_HAVES = original_max


# ===================================================================
# TestAgentRegistryLimits
# ===================================================================

class TestAgentRegistryLimits:
    """Test that Agent Registry enforces MAX_AGENTS."""

    def test_max_agents_enforced(self):
        """Test that MAX_AGENTS limit is enforced."""
        registry = AgentRegistry()
        original_max = registry.MAX_AGENTS
        registry.MAX_AGENTS = 3

        try:
            # Register 3 agents
            for i in range(3):
                agent = registry.register(
                    agent_id=f"agent_{i}",
                    roles=["buyer", "seller"],
                )
                assert agent is not None

            # 4th should raise
            with pytest.raises(ValueError, match="Agent registry limit reached"):
                registry.register(
                    agent_id="agent_4",
                    roles=["buyer", "seller"],
                )
        finally:
            registry.MAX_AGENTS = original_max

    def test_update_existing_agent_within_limit(self):
        """Test that updating an existing agent doesn't count against limit."""
        registry = AgentRegistry()
        original_max = registry.MAX_AGENTS
        registry.MAX_AGENTS = 3

        try:
            # Register 3 agents
            for i in range(3):
                agent = registry.register(
                    agent_id=f"agent_{i}",
                    roles=["buyer"],
                )
                assert agent is not None

            # Updating existing agent_0 should succeed (not a new agent)
            agent = registry.register(
                agent_id="agent_0",
                roles=["buyer", "seller"],  # Changed roles
            )
            assert agent is not None
            assert "seller" in agent.capabilities.roles
        finally:
            registry.MAX_AGENTS = original_max


# ===================================================================
# TestBridgeValidation
# ===================================================================

class TestBridgeValidation:
    """Test that Sanctuary Bridge validates session_id and terms."""

    def test_bridge_on_agreement_empty_session_id(self):
        """Test that bridge_on_agreement rejects empty session_id."""
        config = SanctuaryBridgeConfig(enabled=True)

        result = bridge_on_agreement(
            session_id="",
            agreed_terms={"price": 100},
            parties=["agent_a", "agent_b"],
            transcript_hash="sha256:abc",
            config=config,
        )

        assert result.skipped_reason is not None
        assert "Invalid session_id" in result.skipped_reason

    def test_bridge_on_attestation_empty_session_id(self):
        """Test that bridge_on_attestation rejects empty session_id."""
        config = SanctuaryBridgeConfig(enabled=True)
        attestation = {
            "session_id": "",
            "parties": [{"agent_id": "agent_a"}],
        }

        result = bridge_on_attestation(attestation, config)
        assert result.skipped_reason is not None
        assert "Invalid session_id" in result.skipped_reason

    def test_build_commitment_payload_empty_terms(self):
        """Test that build_commitment_payload rejects empty terms dict."""
        with pytest.raises(ValueError, match="agreed_terms must be a non-empty dict"):
            build_commitment_payload(
                session_id="sess_001",
                agreed_terms={},
                parties=["agent_a", "agent_b"],
            )

    def test_build_commitment_payload_empty_parties(self):
        """Test that build_commitment_payload rejects empty parties list."""
        with pytest.raises(ValueError, match="parties must be a non-empty list"):
            build_commitment_payload(
                session_id="sess_001",
                agreed_terms={"price": 100},
                parties=[],
            )


# ===================================================================
# TestRegistryPublicKey
# ===================================================================

class TestRegistryPublicKey:
    """Test that Agent Registry handles public_key field correctly."""

    def test_register_with_public_key(self):
        """Test that registering with public_key stores it."""
        registry = AgentRegistry()

        agent = registry.register(
            agent_id="agent_with_key",
            public_key="base64_encoded_key_xyz",
        )

        assert agent.public_key == "base64_encoded_key_xyz"

        # get_public_key should return it
        key = registry.get_public_key("agent_with_key")
        assert key == "base64_encoded_key_xyz"

    def test_register_without_public_key(self):
        """Test that registering without public_key returns None from get_public_key."""
        registry = AgentRegistry()

        agent = registry.register(
            agent_id="agent_no_key",
        )

        assert agent.public_key is None

        # get_public_key should return None
        key = registry.get_public_key("agent_no_key")
        assert key is None

    def test_badge_includes_public_key(self):
        """Test that badge includes public_key when present."""
        registry = AgentRegistry()

        agent = registry.register(
            agent_id="agent_with_badge_key",
            public_key="test_key_123",
        )

        badge = registry.get_badge("agent_with_badge_key")
        assert badge is not None
        assert badge["public_key"] == "test_key_123"
        assert badge["type"] == "concordia.preferred"
        assert badge["verified"] is True
