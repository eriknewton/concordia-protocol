"""Tests for attestation generation (§9.6)."""

import pytest

from concordia import (
    Agent,
    BasicOffer,
    KeyPair,
    ResolutionMechanism,
    SessionState,
    generate_attestation,
    verify_signature,
)


@pytest.fixture
def agreed_session():
    """A session that has reached AGREED state."""
    seller = Agent("seller_01")
    buyer = Agent("buyer_42")
    terms = {
        "price": {"value": 150.00, "currency": "USD"},
        "condition": {"value": "good"},
        "delivery": {"value": "shipping"},
    }
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    buyer.accept_session()

    offer = BasicOffer(terms={
        "price": {"value": 135.00, "currency": "USD"},
        "condition": {"value": "good"},
        "delivery": {"value": "shipping"},
    })
    seller.send_offer(offer, reasoning="Fair price for the condition")

    buyer.accept_offer(reasoning="Looks good")
    return session, seller, buyer


class TestAttestationGeneration:
    def test_generates_for_agreed(self, agreed_session):
        session, seller, buyer = agreed_session
        assert session.state == SessionState.AGREED
        key_pairs = {
            "seller_01": seller.key_pair,
            "buyer_42": buyer.key_pair,
        }
        att = generate_attestation(
            session, key_pairs,
            category="electronics.cameras",
            value_range="100-500_USD",
        )
        assert att["concordia_attestation"] == "0.1.0"
        assert att["outcome"]["status"] == "agreed"
        assert att["outcome"]["rounds"] >= 1
        assert att["outcome"]["resolution_mechanism"] == "direct"
        assert len(att["parties"]) == 2
        assert att["transcript_hash"].startswith("sha256:")
        assert att["fulfillment"] is None

    def test_party_signatures_valid(self, agreed_session):
        session, seller, buyer = agreed_session
        key_pairs = {
            "seller_01": seller.key_pair,
            "buyer_42": buyer.key_pair,
        }
        att = generate_attestation(session, key_pairs)
        for party in att["parties"]:
            agent_id = party["agent_id"]
            kp = key_pairs[agent_id]
            sig = party["signature"]
            assert verify_signature(party, sig, kp.public_key)

    def test_behavior_fields(self, agreed_session):
        session, seller, buyer = agreed_session
        key_pairs = {"seller_01": seller.key_pair, "buyer_42": buyer.key_pair}
        att = generate_attestation(session, key_pairs)
        seller_party = next(p for p in att["parties"] if p["agent_id"] == "seller_01")
        assert seller_party["behavior"]["offers_made"] >= 1
        assert seller_party["behavior"]["reasoning_provided"] is True
        assert seller_party["role"] == "initiator"

    def test_meta_fields(self, agreed_session):
        session, seller, buyer = agreed_session
        key_pairs = {"seller_01": seller.key_pair, "buyer_42": buyer.key_pair}
        att = generate_attestation(
            session, key_pairs,
            category="electronics.cameras.mirrorless",
            value_range="1000-5000_USD",
        )
        assert att["meta"]["category"] == "electronics.cameras.mirrorless"
        assert att["meta"]["value_range"] == "1000-5000_USD"

    def test_rejected_session_attestation(self):
        seller = Agent("s")
        buyer = Agent("b")
        session = seller.open_session(
            counterparty=buyer.identity,
            terms={"price": {"value": 100}},
        )
        buyer.join_session(session)
        buyer.decline_session()
        key_pairs = {"s": seller.key_pair, "b": buyer.key_pair}
        att = generate_attestation(session, key_pairs)
        assert att["outcome"]["status"] == "rejected"

    def test_expired_session_attestation(self):
        seller = Agent("s")
        buyer = Agent("b")
        session = seller.open_session(
            counterparty=buyer.identity,
            terms={"price": {"value": 100}},
        )
        buyer.join_session(session)
        session.expire()
        key_pairs = {"s": seller.key_pair, "b": buyer.key_pair}
        att = generate_attestation(session, key_pairs)
        assert att["outcome"]["status"] == "expired"

    def test_cannot_attest_active_session(self):
        seller = Agent("s")
        buyer = Agent("b")
        session = seller.open_session(
            counterparty=buyer.identity,
            terms={"price": {"value": 100}},
        )
        buyer.join_session(session)
        buyer.accept_session()
        with pytest.raises(ValueError):
            generate_attestation(session, {})
