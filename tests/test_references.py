"""Tests for generalized attestation references (WP2, v0.4.0).

Covers the {type, id, relationship} reference shape on Concordia attestations.
Shape is forward-compatible with CMPC v0.5 primitive types.
"""

import pytest

from concordia import (
    Agent,
    BasicOffer,
    SessionState,
    generate_attestation,
)


@pytest.fixture
def agreed_session():
    seller = Agent("seller_ref")
    buyer = Agent("buyer_ref")
    terms = {
        "price": {"value": 100.0, "currency": "USD"},
        "qty": {"value": 1},
    }
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    buyer.accept_session()
    seller.send_offer(BasicOffer(terms={
        "price": {"value": 100.0, "currency": "USD"},
        "qty": {"value": 1},
    }), reasoning="firm price")
    buyer.accept_offer()
    assert session.state == SessionState.AGREED
    return session, seller, buyer


def _key_pairs(seller, buyer):
    return {seller.identity.agent_id: seller.key_pair,
            buyer.identity.agent_id: buyer.key_pair}


class TestReferencesEmpty:
    def test_default_references_is_empty_list(self, agreed_session):
        session, seller, buyer = agreed_session
        att = generate_attestation(session, _key_pairs(seller, buyer))
        assert "references" in att
        assert att["references"] == []

    def test_explicit_none_references_is_empty_list(self, agreed_session):
        session, seller, buyer = agreed_session
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=None
        )
        assert att["references"] == []


class TestReferencesReceiptType:
    def test_single_receipt_reference(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [{"type": "receipt", "id": "att_deadbeef",
                 "relationship": "supersedes"}]
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=refs
        )
        assert len(att["references"]) == 1
        assert att["references"][0] == refs[0]

    def test_multiple_references_preserve_order(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [
            {"type": "receipt", "id": "att_1", "relationship": "extends"},
            {"type": "receipt", "id": "att_2", "relationship": "fulfills"},
            {"type": "receipt", "id": "att_3", "relationship": "references"},
        ]
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=refs
        )
        assert att["references"] == refs

    @pytest.mark.parametrize("rel", ["supersedes", "extends", "fulfills", "references"])
    def test_every_relationship_accepted(self, agreed_session, rel):
        session, seller, buyer = agreed_session
        refs = [{"type": "receipt", "id": "att_x", "relationship": rel}]
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=refs
        )
        assert att["references"][0]["relationship"] == rel


class TestReferencesCMPCForwardCompat:
    """CMPC v0.5 primitive types are accepted today as opaque refs."""

    @pytest.mark.parametrize("ref_type", ["chain_session", "predicate", "mandate"])
    def test_cmpc_primitive_type_accepted(self, agreed_session, ref_type):
        session, seller, buyer = agreed_session
        refs = [{"type": ref_type, "id": f"cmpc_{ref_type}_1",
                 "relationship": "references"}]
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=refs
        )
        assert att["references"][0]["type"] == ref_type


class TestReferencesValidation:
    def test_unknown_type_rejected(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [{"type": "bogus", "id": "x", "relationship": "references"}]
        with pytest.raises(ValueError, match="type"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=refs
            )

    def test_unknown_relationship_rejected(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [{"type": "receipt", "id": "x", "relationship": "cancels"}]
        with pytest.raises(ValueError, match="relationship"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=refs
            )

    def test_missing_id_rejected(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [{"type": "receipt", "relationship": "references"}]
        with pytest.raises(ValueError, match="missing required"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=refs
            )

    def test_empty_id_rejected(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [{"type": "receipt", "id": "", "relationship": "references"}]
        with pytest.raises(ValueError, match="non-empty string"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=refs
            )

    def test_non_dict_reference_rejected(self, agreed_session):
        session, seller, buyer = agreed_session
        with pytest.raises(ValueError, match="must be a dict"):
            generate_attestation(
                session, _key_pairs(seller, buyer),
                references=["not a dict"],
            )

    def test_reference_index_in_error(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [
            {"type": "receipt", "id": "ok", "relationship": "references"},
            {"type": "receipt", "id": "x", "relationship": "bogus"},
        ]
        with pytest.raises(ValueError, match=r"references\[1\]"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=refs
            )


class TestReferencesSchemaValidation:
    """Confirm the attestation JSON schema accepts the new shape."""

    def test_schema_accepts_attestation_with_references(self, agreed_session):
        from concordia import is_valid_attestation
        session, seller, buyer = agreed_session
        refs = [{"type": "receipt", "id": "att_prior",
                 "relationship": "supersedes"}]
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=refs
        )
        assert is_valid_attestation(att)

    def test_schema_accepts_attestation_with_empty_references(self, agreed_session):
        from concordia import is_valid_attestation
        session, seller, buyer = agreed_session
        att = generate_attestation(session, _key_pairs(seller, buyer))
        assert is_valid_attestation(att)
