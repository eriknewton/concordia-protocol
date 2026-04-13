"""Tests for trust-evidence-format v1.0.0 envelope generation."""

from __future__ import annotations

import json
from typing import Any

import pytest

from concordia import (
    Agent,
    BasicOffer,
    KeyPair,
    ES256KeyPair,
    generate_attestation,
    build_trust_evidence_envelope,
    verify_envelope_signature,
)
from concordia.envelope import ENVELOPE_VERSION, _OUTCOME_MAP
from concordia.mcp_server import handle_tool_call
from concordia.types import ResolutionMechanism, SessionState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agreed_session():
    """Create a simple agreed session with attestation."""
    seller = Agent("did:test:seller")
    buyer = Agent("did:test:buyer")
    session = seller.open_session(
        counterparty=buyer.identity, terms={"price": {"value": 100}}
    )
    buyer.join_session(session)
    buyer.accept_session()
    offer = BasicOffer(terms={"price": {"value": 90}})
    buyer.send_offer(offer)
    seller.accept_offer()

    keys = {
        "did:test:seller": KeyPair.generate(),
        "did:test:buyer": KeyPair.generate(),
    }
    attestation = generate_attestation(session, keys)
    return session, attestation, keys


def _make_rejected_session():
    """Create a rejected session with attestation."""
    seller = Agent("did:test:seller")
    buyer = Agent("did:test:buyer")
    session = seller.open_session(
        counterparty=buyer.identity, terms={"price": {"value": 100}}
    )
    buyer.join_session(session)
    buyer.accept_session()
    offer = BasicOffer(terms={"price": {"value": 90}})
    buyer.send_offer(offer)
    seller.reject_offer()

    keys = {
        "did:test:seller": KeyPair.generate(),
        "did:test:buyer": KeyPair.generate(),
    }
    attestation = generate_attestation(
        session, keys, resolution_mechanism=ResolutionMechanism.NONE
    )
    return session, attestation, keys


def _make_expired_session():
    """Create an expired session with attestation."""
    seller = Agent("did:test:seller")
    buyer = Agent("did:test:buyer")
    session = seller.open_session(
        counterparty=buyer.identity, terms={"price": {"value": 100}}
    )
    buyer.join_session(session)
    buyer.accept_session()
    # Force expire via the state property
    session.state = SessionState.EXPIRED

    keys = {
        "did:test:seller": KeyPair.generate(),
        "did:test:buyer": KeyPair.generate(),
    }
    attestation = generate_attestation(
        session, keys, resolution_mechanism=ResolutionMechanism.NONE
    )
    return session, attestation, keys


# ---------------------------------------------------------------------------
# Envelope generation tests
# ---------------------------------------------------------------------------


class TestEnvelopeGeneration:
    def test_agreed_session_envelope(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "test-key-1", "did:test:seller"
        )
        assert envelope["envelope_version"] == ENVELOPE_VERSION
        assert envelope["envelope_id"].startswith("urn:uuid:")
        assert envelope["category"] == "transactional"
        assert envelope["visibility"] == "public"
        assert "signature" in envelope
        assert envelope["signature"]["alg"] == "EdDSA"

    def test_rejected_session_envelope(self):
        _, attestation, _ = _make_rejected_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "test-key-1", "did:test:seller"
        )
        assert envelope["payload"]["outcome"] == "REJECTED"
        assert envelope["payload"]["commitment"]["committed"] is False

    def test_expired_session_envelope(self):
        _, attestation, _ = _make_expired_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "test-key-1", "did:test:seller"
        )
        assert envelope["payload"]["outcome"] == "EXPIRED"
        assert envelope["payload"]["commitment"]["committed"] is False


# ---------------------------------------------------------------------------
# Signature verification round-trip
# ---------------------------------------------------------------------------


class TestSignatureVerification:
    def test_eddsa_roundtrip(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller"
        )
        assert verify_envelope_signature(envelope, kp.public_key, "EdDSA")

    def test_es256_roundtrip(self):
        _, attestation, _ = _make_agreed_session()
        kp = ES256KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller"
        )
        assert envelope["signature"]["alg"] == "ES256"
        assert verify_envelope_signature(envelope, kp.public_key, "ES256")

    def test_tampered_envelope_fails(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller"
        )
        envelope["visibility"] = "private"  # tamper
        assert not verify_envelope_signature(envelope, kp.public_key, "EdDSA")

    def test_wrong_key_fails(self):
        _, attestation, _ = _make_agreed_session()
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp1, "did:web:test.ai", "key-1", "did:test:seller"
        )
        assert not verify_envelope_signature(envelope, kp2.public_key, "EdDSA")


# ---------------------------------------------------------------------------
# Field mapping accuracy
# ---------------------------------------------------------------------------


class TestFieldMapping:
    def test_payload_fields(self):
        session, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller"
        )
        payload = envelope["payload"]

        assert payload["session_id"] == attestation["session_id"]
        assert payload["session_protocol"] == "concordia"
        assert payload["session_protocol_version"] is not None
        assert payload["outcome"] == "ACCEPTED"
        assert payload["counterparty_did"] == "did:test:buyer"
        assert payload["completion_timestamp"] == attestation["timestamp"]
        assert payload["rounds_to_completion"] == attestation["outcome"]["rounds"]

    def test_quality_signals(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller"
        )
        qs = envelope["payload"]["quality_signals"]
        # Quality signals should be present (values depend on session)
        assert isinstance(qs, dict)

    def test_commitment_block_agreed(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller"
        )
        commit = envelope["payload"]["commitment"]
        assert commit["committed"] is True
        assert commit["commitment_hash"] == attestation["transcript_hash"]
        assert commit["honored"] is None  # no fulfillment yet
        assert commit["honored_verified_at"] is None

    def test_privacy_guarantees(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller"
        )
        pg = envelope["payload"]["privacy_guarantees"]
        assert pg["deal_terms_disclosed"] is False
        assert pg["counterparty_identity_disclosed"] is True
        assert pg["zk_proof_available"] is False

    def test_provider_block(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:provider.ai", "my-kid", "did:test:seller"
        )
        assert envelope["provider"]["did"] == "did:web:provider.ai"
        assert envelope["provider"]["kid"] == "my-kid"
        assert envelope["provider"]["name"] == "Concordia"
        assert envelope["provider"]["category"] == "transactional"

    def test_subject_block(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:subject"
        )
        assert envelope["subject"]["did"] == "did:test:subject"


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------


class TestReferences:
    def test_auto_populated_source_session(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller"
        )
        refs = envelope["references"]
        assert len(refs) >= 1
        auto_ref = refs[0]
        assert auto_ref["kind"] == "source_session"
        assert auto_ref["urn"] == f"urn:concordia:session:{attestation['session_id']}"
        assert auto_ref["verified_at"] == envelope["issued_at"]
        assert auto_ref["verifier_did"] == "did:web:test.ai"
        assert auto_ref["hash"] == attestation["transcript_hash"]

    def test_auto_ref_matches_envelope_fields(self):
        """verified_at must equal issued_at and verifier_did must equal provider_did."""
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        provider = "did:web:custom-provider.ai"
        envelope = build_trust_evidence_envelope(
            attestation, kp, provider, "key-1", "did:test:seller"
        )
        auto_ref = envelope["references"][0]
        assert auto_ref["verified_at"] == envelope["issued_at"]
        assert auto_ref["verifier_did"] == provider

    def test_additional_references_merged(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        extra = [
            {"kind": "upstream_envelope", "urn": "urn:example:envelope:123"},
            {"kind": "mandate_proof", "urn": "urn:example:mandate:456"},
        ]
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller",
            references=extra,
        )
        refs = envelope["references"]
        assert len(refs) == 3
        assert refs[1]["kind"] == "upstream_envelope"
        assert refs[2]["kind"] == "mandate_proof"

    def test_invalid_reference_rejected(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        with pytest.raises(ValueError, match="kind"):
            build_trust_evidence_envelope(
                attestation, kp, "did:web:test.ai", "key-1", "did:test:seller",
                references=[{"missing": "fields"}],
            )


# ---------------------------------------------------------------------------
# Validity temporal
# ---------------------------------------------------------------------------


class TestValidityTemporal:
    def test_validity_temporal_present(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller"
        )
        vt = envelope["validity_temporal"]
        assert vt["mode"] == "sequence"
        assert vt["sequence_key"] == attestation["session_id"]
        assert vt["baseline"] is None
        assert vt["aliasing_risk"] is None


# ---------------------------------------------------------------------------
# Envelope without optional fields
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_no_additional_refs_no_subject_override(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller"
        )
        # Should still have auto-populated reference
        assert len(envelope["references"]) == 1
        assert envelope["subject"]["did"] == "did:test:seller"
        assert envelope["visibility"] == "public"

    def test_custom_expiry(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller",
            expires_at="2099-12-31T23:59:59Z",
        )
        assert envelope["expires_at"] == "2099-12-31T23:59:59Z"

    def test_restricted_visibility(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller",
            visibility="restricted",
        )
        assert envelope["visibility"] == "restricted"


# ---------------------------------------------------------------------------
# Non-terminal session rejection
# ---------------------------------------------------------------------------


class TestNonTerminalRejection:
    def test_cannot_envelope_active_session(self, make_agent):
        """Envelope tool rejects non-terminal sessions (same as receipt tool)."""
        a = make_agent("agent-env-a")
        b = make_agent("agent-env-b")

        result = handle_tool_call("concordia_open_session", {
            "initiator_id": a.agent_id,
            "responder_id": b.agent_id,
            "terms": {"price": {"type": "numeric"}},
        })
        session_id = result["session_id"]
        init_token = result["initiator_token"]

        raw = handle_tool_call("concordia_session_receipt_envelope", {
            "session_id": session_id,
            "auth_token": init_token,
        })
        # raw is a JSON string from the tool
        if isinstance(raw, str):
            raw = json.loads(raw)
        assert "error" in raw


# ---------------------------------------------------------------------------
# Private key never in output
# ---------------------------------------------------------------------------


class TestPrivateKeyNeverInOutput:
    def test_no_private_key_in_envelope_eddsa(self):
        _, attestation, _ = _make_agreed_session()
        kp = KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller"
        )
        envelope_str = json.dumps(envelope, default=str)
        # Private key bytes should not appear in the output
        import base64
        priv_b64 = base64.urlsafe_b64encode(kp.private_key_bytes()).decode()
        assert priv_b64 not in envelope_str

    def test_no_private_key_in_envelope_es256(self):
        _, attestation, _ = _make_agreed_session()
        kp = ES256KeyPair.generate()
        envelope = build_trust_evidence_envelope(
            attestation, kp, "did:web:test.ai", "key-1", "did:test:seller"
        )
        envelope_str = json.dumps(envelope, default=str)
        import base64
        priv_b64 = base64.urlsafe_b64encode(kp.private_key_bytes()).decode()
        assert priv_b64 not in envelope_str


# ---------------------------------------------------------------------------
# MCP tool integration test
# ---------------------------------------------------------------------------


class TestMcpEnvelopeTool:
    def test_agreed_session_via_tool(self, make_agent):
        a = make_agent("agent-mcp-a")
        b = make_agent("agent-mcp-b")

        result = handle_tool_call("concordia_open_session", {
            "initiator_id": a.agent_id,
            "responder_id": b.agent_id,
            "terms": {"price": {"type": "numeric"}},
        })
        session_id = result["session_id"]
        init_token = result["initiator_token"]
        resp_token = result["responder_token"]

        # Propose and accept
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

        raw = handle_tool_call("concordia_session_receipt_envelope", {
            "session_id": session_id,
            "auth_token": init_token,
        })
        if isinstance(raw, str):
            envelope = json.loads(raw)
        else:
            envelope = raw

        assert envelope["envelope_version"] == ENVELOPE_VERSION
        assert envelope["payload"]["outcome"] == "ACCEPTED"
        assert envelope["signature"]["alg"] == "EdDSA"

    def test_es256_via_tool(self, make_agent):
        a = make_agent("agent-es256-a")
        b = make_agent("agent-es256-b")

        result = handle_tool_call("concordia_open_session", {
            "initiator_id": a.agent_id,
            "responder_id": b.agent_id,
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

        raw = handle_tool_call("concordia_session_receipt_envelope", {
            "session_id": session_id,
            "auth_token": init_token,
            "algorithm": "ES256",
        })
        if isinstance(raw, str):
            envelope = json.loads(raw)
        else:
            envelope = raw

        assert envelope["signature"]["alg"] == "ES256"

    def test_additional_references_via_tool(self, make_agent):
        a = make_agent("agent-ref-a")
        b = make_agent("agent-ref-b")

        result = handle_tool_call("concordia_open_session", {
            "initiator_id": a.agent_id,
            "responder_id": b.agent_id,
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

        extra_refs = json.dumps([{"kind": "chain_state", "urn": "urn:example:chain:1"}])
        raw = handle_tool_call("concordia_session_receipt_envelope", {
            "session_id": session_id,
            "auth_token": init_token,
            "additional_references": extra_refs,
        })
        if isinstance(raw, str):
            envelope = json.loads(raw)
        else:
            envelope = raw

        assert len(envelope["references"]) == 2
        assert envelope["references"][1]["kind"] == "chain_state"
