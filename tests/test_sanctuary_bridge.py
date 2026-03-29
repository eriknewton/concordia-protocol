"""Tests for the Sanctuary Bridge — optional Concordia ↔ Sanctuary integration.

Covers:
    - SanctuaryBridgeConfig: identity mapping, DID resolution
    - Commitment payload generation (L3)
    - Reveal payload generation
    - Reputation payload generation (L4) with outcome mapping
    - BridgeResult: combined output
    - bridge_on_agreement / bridge_on_attestation orchestrators
    - MCP tool integration: configure, commit, attest, status
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from concordia.sanctuary_bridge import (
    SanctuaryBridgeConfig,
    BridgeResult,
    bridge_on_agreement,
    bridge_on_attestation,
    build_commitment_payload,
    build_reveal_payload,
    build_reputation_payload,
    _map_outcome_result,
)


# ===================================================================
# Helpers
# ===================================================================

def _make_attestation(
    session_id: str = "sess_001",
    status: str = "agreed",
    agent_a: str = "seller_01",
    agent_b: str = "buyer_42",
    rounds: int = 3,
    duration: float = 45.0,
) -> dict[str, Any]:
    """Build a minimal Concordia attestation dict for bridge tests."""
    return {
        "attestation_id": f"att_{session_id}",
        "session_id": session_id,
        "outcome": {
            "status": status,
            "rounds": rounds,
            "duration_seconds": duration,
        },
        "parties": [
            {
                "agent_id": agent_a,
                "behavior": {
                    "concession_magnitude": 0.15,
                    "offers_made": 2,
                },
            },
            {
                "agent_id": agent_b,
                "behavior": {
                    "concession_magnitude": 0.10,
                    "offers_made": 1,
                },
            },
        ],
        "meta": {
            "category": "electronics.cameras",
        },
    }


def _configured_bridge(
    agent_a: str = "seller_01",
    agent_b: str = "buyer_42",
) -> SanctuaryBridgeConfig:
    """Build a configured bridge with two mapped identities."""
    config = SanctuaryBridgeConfig(enabled=True)
    config.map_identity(agent_a, "sanc_seller_01", "did:sanctuary:seller01")
    config.map_identity(agent_b, "sanc_buyer_42", "did:sanctuary:buyer42")
    return config


# ===================================================================
# SanctuaryBridgeConfig tests
# ===================================================================

class TestSanctuaryBridgeConfig:

    def test_defaults(self):
        config = SanctuaryBridgeConfig()
        assert config.enabled is False
        assert config.default_context == "concordia_negotiation"
        assert config.commitment_on_agree is True
        assert config.reputation_on_receipt is True

    def test_map_identity(self):
        config = SanctuaryBridgeConfig()
        config.map_identity("agent_1", "sanc_1", "did:sanctuary:1")
        assert config.get_sanctuary_id("agent_1") == "sanc_1"
        assert config.get_did("agent_1") == "did:sanctuary:1"

    def test_map_identity_without_did(self):
        config = SanctuaryBridgeConfig()
        config.map_identity("agent_1", "sanc_1")
        assert config.get_sanctuary_id("agent_1") == "sanc_1"
        assert config.get_did("agent_1") is None

    def test_unmapped_agent(self):
        config = SanctuaryBridgeConfig()
        assert config.get_sanctuary_id("unknown") is None
        assert config.get_did("unknown") is None


# ===================================================================
# Commitment payload tests (L3)
# ===================================================================

class TestCommitmentPayload:

    def test_basic_commitment(self):
        payload = build_commitment_payload(
            session_id="sess_001",
            agreed_terms={"price": {"value": 1000}},
            parties=["buyer_42", "seller_01"],
        )
        assert payload["tool"] == "sanctuary/proof_commitment"
        assert "value" in payload["arguments"]
        assert payload["agreement_summary"]["session_id"] == "sess_001"
        assert payload["agreement_summary"]["parties"] == ["buyer_42", "seller_01"]
        assert payload["agreement_summary"]["term_count"] == 1

    def test_parties_sorted(self):
        payload = build_commitment_payload(
            session_id="s1",
            agreed_terms={"x": 1},
            parties=["z_agent", "a_agent"],
        )
        assert payload["agreement_summary"]["parties"] == ["a_agent", "z_agent"]

    def test_commitment_with_transcript_hash(self):
        payload = build_commitment_payload(
            session_id="s1",
            agreed_terms={"x": 1},
            parties=["a", "b"],
            transcript_hash="sha256:abc123",
        )
        assert payload["agreement_summary"]["has_transcript_hash"] is True
        # The raw value should contain the hash
        raw = json.loads(payload["raw_value"])
        assert raw["transcript_hash"] == "sha256:abc123"

    def test_commitment_without_transcript_hash(self):
        payload = build_commitment_payload(
            session_id="s1",
            agreed_terms={"x": 1},
            parties=["a", "b"],
        )
        assert payload["agreement_summary"]["has_transcript_hash"] is False

    def test_commitment_value_is_canonical_json(self):
        payload = build_commitment_payload(
            session_id="s1",
            agreed_terms={"b_key": 2, "a_key": 1},
            parties=["p1"],
        )
        raw = payload["raw_value"]
        # Canonical JSON: sorted keys, no spaces
        parsed = json.loads(raw)
        assert list(parsed.keys()) == sorted(parsed.keys())

    def test_commitment_uses_canonical_json_not_vanilla_dumps(self):
        """SEC-003 regression: bridge must use canonical_json, not json.dumps.

        Verifies that non-ASCII in agreed_terms is preserved as raw UTF-8
        (not \\uXXXX escaped), matching TypeScript's stableStringify output.
        """
        payload = build_commitment_payload(
            session_id="s1",
            agreed_terms={"description": "café résumé"},
            parties=["p1"],
        )
        raw = payload["raw_value"]
        # canonical_json with ensure_ascii=False preserves Unicode
        assert "café" in raw, "Unicode should be preserved, not escaped"
        assert "\\u" not in raw, "Should not contain \\uXXXX escape sequences"

    def test_commitment_integer_valued_floats(self):
        """SEC-003 regression: integer-valued floats format without decimal point."""
        payload = build_commitment_payload(
            session_id="s1",
            agreed_terms={"price": 100, "quantity": 5},
            parties=["p1"],
        )
        raw = payload["raw_value"]
        # Should contain "100" not "100.0"
        assert '"price":100' in raw or '"price": 100' in raw


# ===================================================================
# Reveal payload tests
# ===================================================================

class TestRevealPayload:

    def test_basic_reveal(self):
        payload = build_reveal_payload(
            commitment="abc123",
            original_value="the original value",
            blinding_factor="blind_xyz",
        )
        assert payload["tool"] == "sanctuary/proof_reveal"
        assert payload["arguments"]["commitment"] == "abc123"
        assert payload["arguments"]["value"] == "the original value"
        assert payload["arguments"]["blinding_factor"] == "blind_xyz"


# ===================================================================
# Reputation payload tests (L4)
# ===================================================================

class TestReputationPayload:

    def test_basic_reputation(self):
        config = _configured_bridge()
        attestation = _make_attestation()
        payload = build_reputation_payload(attestation, config, "seller_01")
        assert payload is not None
        assert payload["tool"] == "sanctuary/reputation_record"
        args = payload["arguments"]
        assert args["identity_id"] == "sanc_seller_01"
        assert args["counterparty_did"] == "did:sanctuary:buyer42"
        assert args["outcome"]["type"] == "negotiation"
        assert args["outcome"]["result"] == "completed"
        assert args["context"] == "electronics.cameras"

    def test_reputation_unmapped_agent(self):
        config = SanctuaryBridgeConfig(enabled=True)
        attestation = _make_attestation()
        payload = build_reputation_payload(attestation, config, "seller_01")
        assert payload is None

    def test_reputation_metrics(self):
        config = _configured_bridge()
        attestation = _make_attestation()
        payload = build_reputation_payload(attestation, config, "seller_01")
        metrics = payload["arguments"]["outcome"]["metrics"]
        assert metrics["concession_magnitude"] == 0.15
        assert metrics["offers_made"] == 2.0
        assert metrics["rounds"] == 3.0
        assert metrics["duration_seconds"] == 45.0

    def test_reputation_uses_default_context(self):
        config = _configured_bridge()
        config.default_context = "custom_context"
        attestation = _make_attestation()
        attestation["meta"] = {}  # no category
        payload = build_reputation_payload(attestation, config, "seller_01")
        assert payload["arguments"]["context"] == "custom_context"

    def test_reputation_counterparty_fallback(self):
        """When counterparty has no DID, use concordia: prefix."""
        config = SanctuaryBridgeConfig(enabled=True)
        config.map_identity("seller_01", "sanc_seller")
        attestation = _make_attestation()
        payload = build_reputation_payload(attestation, config, "seller_01")
        assert payload["arguments"]["counterparty_did"] == "concordia:buyer_42"


# ===================================================================
# Outcome mapping tests
# ===================================================================

class TestOutcomeMapping:

    def test_agreed_maps_to_completed(self):
        assert _map_outcome_result("agreed") == "completed"

    def test_rejected_maps_to_failed(self):
        assert _map_outcome_result("rejected") == "failed"

    def test_expired_maps_to_failed(self):
        assert _map_outcome_result("expired") == "failed"

    def test_withdrawn_maps_to_partial(self):
        assert _map_outcome_result("withdrawn") == "partial"

    def test_unknown_maps_to_partial(self):
        assert _map_outcome_result("something_else") == "partial"


# ===================================================================
# BridgeResult tests
# ===================================================================

class TestBridgeResult:

    def test_empty_result(self):
        result = BridgeResult(session_id="s1")
        d = result.to_dict()
        assert d["session_id"] == "s1"
        assert d["sanctuary_enabled"] is False
        assert d["commitment_payload"] is None
        assert d["reputation_payloads"] == []
        assert d["reputation_payload_count"] == 0

    def test_result_with_commitment(self):
        result = BridgeResult(
            session_id="s1",
            commitment_payload={"tool": "sanctuary/proof_commitment"},
        )
        d = result.to_dict()
        assert d["sanctuary_enabled"] is True

    def test_result_with_skip_reason(self):
        result = BridgeResult(session_id="s1", skipped_reason="Bridge disabled")
        d = result.to_dict()
        assert d["skipped_reason"] == "Bridge disabled"


# ===================================================================
# Orchestrator tests: bridge_on_agreement
# ===================================================================

class TestBridgeOnAgreement:

    def test_disabled_bridge(self):
        config = SanctuaryBridgeConfig(enabled=False)
        result = bridge_on_agreement("s1", {"x": 1}, ["a", "b"], None, config)
        assert result.commitment_payload is None
        assert result.skipped_reason is not None

    def test_enabled_bridge(self):
        config = _configured_bridge()
        result = bridge_on_agreement(
            session_id="sess_001",
            agreed_terms={"price": {"value": 1000}},
            parties=["seller_01", "buyer_42"],
            transcript_hash="sha256:abc",
            config=config,
        )
        assert result.commitment_payload is not None
        assert result.commitment_payload["tool"] == "sanctuary/proof_commitment"

    def test_commitment_disabled(self):
        config = _configured_bridge()
        config.commitment_on_agree = False
        result = bridge_on_agreement("s1", {"x": 1}, ["a", "b"], None, config)
        assert result.commitment_payload is None


# ===================================================================
# Orchestrator tests: bridge_on_attestation
# ===================================================================

class TestBridgeOnAttestation:

    def test_disabled_bridge(self):
        config = SanctuaryBridgeConfig(enabled=False)
        attestation = _make_attestation()
        result = bridge_on_attestation(attestation, config)
        assert result.reputation_payloads == []
        assert result.skipped_reason is not None

    def test_enabled_bridge_both_mapped(self):
        config = _configured_bridge()
        attestation = _make_attestation()
        result = bridge_on_attestation(attestation, config)
        assert len(result.reputation_payloads) == 2
        tools = {p["tool"] for p in result.reputation_payloads}
        assert tools == {"sanctuary/reputation_record"}

    def test_enabled_bridge_one_mapped(self):
        config = SanctuaryBridgeConfig(enabled=True)
        config.map_identity("seller_01", "sanc_seller")
        attestation = _make_attestation()
        result = bridge_on_attestation(attestation, config)
        assert len(result.reputation_payloads) == 1

    def test_reputation_disabled(self):
        config = _configured_bridge()
        config.reputation_on_receipt = False
        attestation = _make_attestation()
        result = bridge_on_attestation(attestation, config)
        assert result.reputation_payloads == []


# ===================================================================
# MCP Tool integration tests
# ===================================================================

class TestSanctuaryBridgeMcpTools:

    @pytest.fixture(autouse=True)
    def reset_bridge(self):
        from concordia.mcp_server import _bridge_config, _store, _registry, _auth
        _bridge_config.enabled = False
        _bridge_config.identity_map.clear()
        _bridge_config.did_map.clear()
        _bridge_config.default_context = "concordia_negotiation"
        _bridge_config.commitment_on_agree = True
        _bridge_config.reputation_on_receipt = True
        _store._sessions.clear()
        _registry._agents.clear()
        _auth._agent_tokens.clear()
        _auth._session_tokens.clear()
        _auth._token_to_agent.clear()
        yield

    def _parse(self, result_str: str) -> dict:
        return json.loads(result_str)

    def test_bridge_status_disabled(self):
        from concordia.mcp_server import tool_sanctuary_bridge_status
        result = self._parse(tool_sanctuary_bridge_status())
        assert result["enabled"] is False
        assert result["identity_count"] == 0

    def test_bridge_configure(self):
        from concordia.mcp_server import tool_sanctuary_bridge_configure
        result = self._parse(tool_sanctuary_bridge_configure(
            enabled=True,
            identity_mappings=[
                {"agent_id": "seller_01", "sanctuary_id": "sanc_s", "did": "did:sanctuary:s"},
                {"agent_id": "buyer_42", "sanctuary_id": "sanc_b"},
            ],
            default_context="test_context",
        ))
        assert result["enabled"] is True
        assert result["identity_count"] == 2
        assert result["default_context"] == "test_context"

    def test_bridge_status_after_configure(self):
        from concordia.mcp_server import (
            tool_sanctuary_bridge_configure,
            tool_sanctuary_bridge_status,
        )
        tool_sanctuary_bridge_configure(
            enabled=True,
            identity_mappings=[
                {"agent_id": "a1", "sanctuary_id": "s1", "did": "did:sanctuary:1"},
            ],
        )
        result = self._parse(tool_sanctuary_bridge_status())
        assert result["enabled"] is True
        assert result["identity_count"] == 1
        assert "a1" in result["identity_mappings"]
        assert result["identity_mappings"]["a1"]["sanctuary_id"] == "s1"
        assert result["identity_mappings"]["a1"]["did"] == "did:sanctuary:1"

    def test_bridge_commit_requires_enabled(self):
        from concordia.mcp_server import tool_sanctuary_bridge_commit
        result = self._parse(tool_sanctuary_bridge_commit(session_id="fake"))
        assert "error" in result

    def test_bridge_commit_requires_agreed_session(self):
        from concordia.mcp_server import (
            tool_sanctuary_bridge_configure,
            tool_sanctuary_bridge_commit,
            tool_open_session,
        )
        tool_sanctuary_bridge_configure(enabled=True)
        # Create an active (not agreed) session
        session = self._parse(tool_open_session(
            initiator_id="seller_01",
            responder_id="buyer_42",
            terms={"price": {"type": "numeric"}},
        ))
        result = self._parse(tool_sanctuary_bridge_commit(
            session_id=session["session_id"],
        ))
        assert "error" in result
        assert "agreed" in result["error"].lower()

    def test_bridge_commit_on_agreed_session(self):
        from concordia.mcp_server import (
            tool_sanctuary_bridge_configure,
            tool_sanctuary_bridge_commit,
            tool_open_session,
            tool_propose,
            tool_accept,
        )
        tool_sanctuary_bridge_configure(
            enabled=True,
            identity_mappings=[
                {"agent_id": "seller_01", "sanctuary_id": "sanc_s"},
            ],
        )
        session = self._parse(tool_open_session(
            initiator_id="seller_01",
            responder_id="buyer_42",
            terms={"price": {"type": "numeric"}},
        ))
        sid = session["session_id"]
        initiator_token = session["initiator_token"]
        responder_token = session["responder_token"]
        tool_propose(session_id=sid, auth_token=initiator_token, role="initiator", terms={"price": {"value": 100}})
        tool_accept(session_id=sid, auth_token=responder_token, role="responder")

        result = self._parse(tool_sanctuary_bridge_commit(session_id=sid))
        assert result["sanctuary_enabled"] is True
        assert result["commitment_payload"] is not None
        assert result["commitment_payload"]["tool"] == "sanctuary/proof_commitment"

    def test_bridge_attest_requires_enabled(self):
        from concordia.mcp_server import tool_sanctuary_bridge_attest
        result = self._parse(tool_sanctuary_bridge_attest(attestation={}))
        assert "error" in result

    def test_bridge_attest_with_mapped_parties(self):
        from concordia.mcp_server import (
            tool_sanctuary_bridge_configure,
            tool_sanctuary_bridge_attest,
        )
        tool_sanctuary_bridge_configure(
            enabled=True,
            identity_mappings=[
                {"agent_id": "seller_01", "sanctuary_id": "sanc_s", "did": "did:s:1"},
                {"agent_id": "buyer_42", "sanctuary_id": "sanc_b", "did": "did:b:1"},
            ],
        )
        attestation = _make_attestation()
        result = self._parse(tool_sanctuary_bridge_attest(attestation=attestation))
        assert result["sanctuary_enabled"] is True
        assert result["reputation_payload_count"] == 2

    # -- Full lifecycle via handle_tool_call --

    def test_full_bridge_lifecycle(self):
        """End-to-end: configure → negotiate → commit → attest."""
        from concordia.mcp_server import handle_tool_call

        # Configure bridge
        config_result = handle_tool_call("concordia_sanctuary_bridge_configure", {
            "enabled": True,
            "identity_mappings": [
                {"agent_id": "seller_01", "sanctuary_id": "sanc_s", "did": "did:s:1"},
                {"agent_id": "buyer_42", "sanctuary_id": "sanc_b", "did": "did:b:1"},
            ],
        })
        assert config_result["enabled"] is True

        # Run a Concordia negotiation to agreement
        session = handle_tool_call("concordia_open_session", {
            "initiator_id": "seller_01",
            "responder_id": "buyer_42",
            "terms": {"price": {"type": "numeric", "label": "Price"}},
        })
        sid = session["session_id"]
        initiator_token = session["initiator_token"]
        responder_token = session["responder_token"]

        handle_tool_call("concordia_propose", {
            "session_id": sid,
            "auth_token": initiator_token,
            "role": "initiator",
            "terms": {"price": {"value": 1000}},
        })
        handle_tool_call("concordia_accept", {
            "session_id": sid,
            "auth_token": responder_token,
            "role": "responder",
        })

        # Generate Sanctuary commitment
        commit_result = handle_tool_call("concordia_sanctuary_bridge_commit", {
            "session_id": sid,
        })
        assert commit_result["sanctuary_enabled"] is True
        assert commit_result["commitment_payload"]["tool"] == "sanctuary/proof_commitment"

        # Generate receipt, then bridge to Sanctuary reputation
        receipt = handle_tool_call("concordia_session_receipt", {
            "session_id": sid,
            "auth_token": initiator_token,
        })
        assert "receipt" in receipt

        attest_result = handle_tool_call("concordia_sanctuary_bridge_attest", {
            "attestation": receipt["receipt"],
        })
        assert attest_result["sanctuary_enabled"] is True
        assert attest_result["reputation_payload_count"] == 2

        # Verify status
        status = handle_tool_call("concordia_sanctuary_bridge_status", {})
        assert status["enabled"] is True
        assert status["identity_count"] == 2
