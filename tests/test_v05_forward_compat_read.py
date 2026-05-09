"""v0.5 hard gate: forward-compat. v0.4-shaped artifacts validate.

Per SPEC §11.5: v0.5 ratifies the references[] shape introduced in
v0.4.0. Existing v0.4-shaped attestations and envelopes MUST validate
cleanly against the v0.5 JSON Schema.

This test feeds explicitly-v0.4-shaped artifacts (no v0.5 optional
fields, no v0.5 extension keys) to the validator and asserts they pass.
"""

from __future__ import annotations

import pytest

from concordia import (
    Agent,
    BasicOffer,
    SessionState,
    generate_attestation,
    is_valid_attestation,
)


@pytest.fixture
def agreed_session():
    seller = Agent("seller_v04_compat")
    buyer = Agent("buyer_v04_compat")
    terms = {"price": {"value": 100.0, "currency": "USD"}, "qty": {"value": 1}}
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    buyer.accept_session()
    seller.send_offer(BasicOffer(terms={
        "price": {"value": 100.0, "currency": "USD"},
        "qty": {"value": 1},
    }))
    buyer.accept_offer()
    assert session.state == SessionState.AGREED
    return session, seller, buyer


def _key_pairs(seller, buyer):
    return {
        seller.identity.agent_id: seller.key_pair,
        buyer.identity.agent_id: buyer.key_pair,
    }


class TestV04ReferencesValidateUnderV05Schema:
    """v0.4-shaped attestation references parse cleanly under v0.5 schema."""

    def test_v04_minimal_reference_validates(self, agreed_session):
        """The v0.4 baseline shape: only {type, id, relationship}."""
        session, seller, buyer = agreed_session
        v04_refs = [
            {"type": "receipt", "id": "att_v04_1", "relationship": "supersedes"},
            {"type": "receipt", "id": "att_v04_2", "relationship": "extends"},
        ]
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=v04_refs
        )
        assert is_valid_attestation(att)
        for ref in att["references"]:
            assert set(ref.keys()) == {"type", "id", "relationship"}

    def test_v04_attestation_without_references_validates(self, agreed_session):
        """v0.4 attestations without references[] still validate."""
        session, seller, buyer = agreed_session
        att = generate_attestation(session, _key_pairs(seller, buyer))
        assert is_valid_attestation(att)


class TestV05ReferencesValidateUnderV05Schema:
    """v0.5-shaped attestation references with optional fields validate."""

    def test_v05_full_reference_validates(self, agreed_session):
        """v0.5 adds optional version, signed_at, signer_did, extensions."""
        session, seller, buyer = agreed_session
        v05_refs = [
            {
                "type": "receipt",
                "id": "att_v05_1",
                "relationship": "extends",
                "version": "0.5.0",
                "signed_at": "2026-05-11T00:00:00Z",
                "signer_did": "did:web:example.org:signer-1",
                "extensions": {"custom_key": "custom_value"},
            },
        ]
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=v05_refs
        )
        assert is_valid_attestation(att)


class TestUnknownTypeAndRelationshipPreserved:
    """Per SPEC §11.5.8 MUST: unknown values preserved as opaque strings."""

    def test_unknown_type_roundtrips(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [
            {"type": "future_v07_primitive", "id": "x",
             "relationship": "references"}
        ]
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=refs
        )
        assert att["references"][0]["type"] == "future_v07_primitive"

    def test_unknown_relationship_roundtrips(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [
            {"type": "receipt", "id": "x", "relationship": "v07_new_relation"}
        ]
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=refs
        )
        assert att["references"][0]["relationship"] == "v07_new_relation"


class TestEnvelopeForwardCompat:
    """Envelope-level v0.4 references parse cleanly per SPEC §11.5.2."""

    def test_v04_envelope_reference_with_full_verification_triple(self, agreed_session):
        from concordia.envelope import build_trust_evidence_envelope
        from concordia.signing import KeyPair

        session, seller, buyer = agreed_session
        att = generate_attestation(session, _key_pairs(seller, buyer))
        provider_kp = KeyPair.generate()
        v04_envelope_refs = [
            {
                "kind": "chain_state",
                "urn": "urn:concordia:chain:abc123",
                "verified_at": "2026-04-20T12:00:00Z",
                "verifier_did": "did:web:example.org:verifier",
                "hash": "sha256:" + "0" * 64,
            },
        ]
        envelope = build_trust_evidence_envelope(
            att,
            provider_kp,
            provider_did="did:web:example.org:provider",
            provider_kid="key-1",
            subject_did="did:web:example.org:subject",
            references=v04_envelope_refs,
        )
        assert envelope["envelope_version"] == "1.0.0"
        assert any(r.get("kind") == "chain_state" for r in envelope["references"])

    def test_v04_envelope_reference_without_verification_triple(self, agreed_session):
        """Per SPEC §11.5.2: kind+urn required, verification triple optional."""
        from concordia.envelope import build_trust_evidence_envelope
        from concordia.signing import KeyPair

        session, seller, buyer = agreed_session
        att = generate_attestation(session, _key_pairs(seller, buyer))
        provider_kp = KeyPair.generate()
        minimal_refs = [
            {"kind": "mandate_proof", "urn": "urn:ap2:mandate:abc"},
        ]
        envelope = build_trust_evidence_envelope(
            att,
            provider_kp,
            provider_did="did:web:example.org:provider",
            provider_kid="key-1",
            subject_did="did:web:example.org:subject",
            references=minimal_refs,
        )
        assert any(
            r.get("urn") == "urn:ap2:mandate:abc" for r in envelope["references"]
        )
