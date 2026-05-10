"""Tests for v0.5 error text alignment with SPEC SS11.5 section references."""

import pytest

from concordia import Agent, BasicOffer, KeyPair, generate_attestation
from concordia.attestation import _validate_reference
from concordia.envelope import build_trust_evidence_envelope


@pytest.fixture
def agreed_session():
    """A session that has reached AGREED state."""
    seller = Agent("seller_01")
    buyer = Agent("buyer_42")
    terms = {
        "price": {"value": 150.00, "currency": "USD"},
        "condition": {"value": "good"},
    }
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    buyer.accept_session()
    offer = BasicOffer(terms={
        "price": {"value": 135.00, "currency": "USD"},
        "condition": {"value": "good"},
    })
    seller.send_offer(offer, reasoning="Fair price")
    buyer.accept_offer(reasoning="Looks good")
    return session, seller, buyer


class TestAttestationValidatorErrorTextAlignment:
    """Each attestation-level _validate_reference error cites SPEC SS11.5."""

    def test_missing_required_keys_cites_spec(self):
        with pytest.raises(ValueError, match=r"SPEC §11\.5\.6"):
            _validate_reference({"type": "receipt"}, 0)

    def test_invalid_type_cites_spec(self):
        ref = {"type": "bogus", "id": "abc", "relationship": "references"}
        with pytest.raises(ValueError, match=r"SPEC §11\.5\.6"):
            _validate_reference(ref, 0)

    def test_invalid_relationship_cites_spec(self):
        ref = {"type": "receipt", "id": "abc", "relationship": "destroys"}
        with pytest.raises(ValueError, match=r"SPEC §11\.5\.5"):
            _validate_reference(ref, 0)

    def test_empty_id_cites_spec(self):
        ref = {"type": "receipt", "id": "", "relationship": "references"}
        with pytest.raises(ValueError, match=r"SPEC §11\.5\.6"):
            _validate_reference(ref, 0)

    def test_non_dict_ref_raises(self):
        with pytest.raises(ValueError, match="must be a dict"):
            _validate_reference("not a dict", 0)


class TestEnvelopeValidatorErrorTextAlignment:
    """Envelope-level reference errors cite SPEC SS11.5.4."""

    def test_missing_kind_urn_cites_spec(self, agreed_session):
        session, seller, buyer = agreed_session
        key_pairs = {"seller_01": seller.key_pair, "buyer_42": buyer.key_pair}
        att = generate_attestation(session, key_pairs)
        with pytest.raises(ValueError, match=r"SPEC §11\.5\.4"):
            build_trust_evidence_envelope(
                att,
                seller.key_pair,
                provider_did="did:example:provider",
                provider_kid="key-1",
                subject_did="did:example:subject",
                references=[{"missing": "keys"}],
            )
