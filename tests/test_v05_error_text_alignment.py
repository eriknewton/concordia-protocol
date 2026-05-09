"""v0.5 hard gate: validator error text cites SPEC §11.5 sections.

Per SPEC §11.5.8: implementations MUST emit clear error text for
malformed entries that maps to the specific 11.5.x section that defines
the violated invariant. This test provokes each path of
``concordia.attestation._validate_reference()`` and asserts the resulting
message contains a SPEC §11.5 citation.
"""

from __future__ import annotations

import pytest

from concordia import Agent, BasicOffer, SessionState, generate_attestation


@pytest.fixture
def agreed_session():
    seller = Agent("seller_v05_text")
    buyer = Agent("buyer_v05_text")
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


class TestErrorTextCitesSpec:
    """Every validator error message must cite SPEC §11.5."""

    def test_non_dict_reference_cites_11_5_6(self, agreed_session):
        session, seller, buyer = agreed_session
        with pytest.raises(ValueError, match=r"SPEC §11\.5\.6"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=["not a dict"]
            )

    def test_missing_required_keys_cites_11_5_6(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [{"type": "receipt", "relationship": "references"}]
        with pytest.raises(ValueError, match=r"SPEC §11\.5\.6"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=refs
            )

    def test_empty_id_cites_11_5_6(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [{"type": "receipt", "id": "", "relationship": "references"}]
        with pytest.raises(ValueError, match=r"SPEC §11\.5\.6"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=refs
            )

    def test_empty_type_cites_11_5_6(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [{"type": "", "id": "x", "relationship": "references"}]
        with pytest.raises(ValueError, match=r"SPEC §11\.5\.6"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=refs
            )

    def test_empty_relationship_cites_11_5_6(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [{"type": "receipt", "id": "x", "relationship": ""}]
        with pytest.raises(ValueError, match=r"SPEC §11\.5\.6"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=refs
            )

    def test_envelope_missing_kind_or_urn_cites_11_5_2(self, agreed_session):
        """Envelope-level references cite SPEC §11.5.2 per the layering boundary."""
        from concordia.envelope import build_trust_evidence_envelope
        from concordia.signing import KeyPair

        session, seller, buyer = agreed_session
        att = generate_attestation(session, _key_pairs(seller, buyer))
        provider_kp = KeyPair.generate()
        bad_refs = [{"kind": "source_session"}]
        with pytest.raises(ValueError, match=r"SPEC §11\.5\.2"):
            build_trust_evidence_envelope(
                att,
                provider_kp,
                provider_did="did:web:example.org:provider",
                provider_kid="key-1",
                subject_did="did:web:example.org:subject",
                references=bad_refs,
            )
