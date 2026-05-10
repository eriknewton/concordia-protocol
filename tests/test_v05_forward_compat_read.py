"""Tests that validators accept both v0.4 and v0.5 shaped attestations."""

import pytest

from concordia import (
    Agent,
    BasicOffer,
    generate_attestation,
)
from concordia.attestation import _validate_reference, REFERENCE_TYPES, REFERENCE_RELATIONSHIPS
from concordia.schema_validator import validate_attestation


@pytest.fixture
def agreed_session():
    """A session that has reached AGREED state."""
    seller = Agent("seller_01")
    buyer = Agent("buyer_42")
    terms = {"price": {"value": 100.00, "currency": "USD"}}
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    buyer.accept_session()
    offer = BasicOffer(terms={"price": {"value": 95.00, "currency": "USD"}})
    seller.send_offer(offer, reasoning="Fair")
    buyer.accept_offer(reasoning="OK")
    return session, seller, buyer


class TestForwardCompatRead:
    """v0.4 and v0.5 shaped references both validate cleanly."""

    def test_v04_shaped_reference_validates(self):
        """A reference with only {type, id, relationship} (v0.4 shape) passes."""
        ref = {"type": "receipt", "id": "att_abc123", "relationship": "references"}
        result = _validate_reference(ref, 0)
        assert result["type"] == "receipt"
        assert result["id"] == "att_abc123"
        assert result["relationship"] == "references"

    def test_v05_shaped_reference_with_optional_fields_validates(self):
        """A reference with optional v0.5 fields passes (extra keys are ignored by validator)."""
        ref = {
            "type": "receipt",
            "id": "att_abc123",
            "relationship": "supersedes",
            "version": "0.5.0",
            "signed_at": "2026-05-11T00:00:00Z",
            "signer_did": "did:example:signer",
        }
        result = _validate_reference(ref, 0)
        assert result["type"] == "receipt"
        assert result["relationship"] == "supersedes"

    def test_v04_attestation_schema_validates(self, agreed_session):
        """A v0.4-style attestation (no optional v0.5 fields) validates against schema."""
        session, seller, buyer = agreed_session
        key_pairs = {"seller_01": seller.key_pair, "buyer_42": buyer.key_pair}
        att = generate_attestation(session, key_pairs)
        # v0.4-style: no validity_temporal, basic references
        errors = validate_attestation(att)
        assert errors == [], f"v0.4-style attestation failed validation: {errors}"

    def test_v05_attestation_with_references_validates(self, agreed_session):
        """An attestation with v0.5 references validates against schema."""
        session, seller, buyer = agreed_session
        key_pairs = {"seller_01": seller.key_pair, "buyer_42": buyer.key_pair}
        att = generate_attestation(
            session,
            key_pairs,
            references=[
                {"type": "receipt", "id": "att_prior", "relationship": "supersedes"},
            ],
        )
        errors = validate_attestation(att)
        assert errors == [], f"v0.5 attestation with references failed: {errors}"

    def test_all_reference_types_accepted(self):
        """Every reference type in REFERENCE_TYPES passes validation."""
        for ref_type in REFERENCE_TYPES:
            ref = {"type": ref_type, "id": f"id_{ref_type}", "relationship": "references"}
            result = _validate_reference(ref, 0)
            assert result["type"] == ref_type

    def test_all_relationships_accepted(self):
        """Every relationship in REFERENCE_RELATIONSHIPS passes validation."""
        for rel in REFERENCE_RELATIONSHIPS:
            ref = {"type": "receipt", "id": "test_id", "relationship": rel}
            result = _validate_reference(ref, 0)
            assert result["relationship"] == rel
