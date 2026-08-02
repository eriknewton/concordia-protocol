"""Tests for attestation generation (§9.6)."""

from copy import deepcopy

import pytest

from concordia import (
    Agent,
    BasicOffer,
    SessionState,
    generate_attestation,
    verify_attestation,
    verify_signature,
)
from concordia.message import compute_hash, validate_chain
from concordia.signing import sign_message


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
        assert att["concordia_attestation"] == "0.3.0"
        assert att["outcome"]["status"] == "agreed"
        assert att["outcome"]["rounds"] >= 1
        assert att["outcome"]["resolution_mechanism"] == "direct"
        assert len(att["parties"]) == 2
        assert att["transcript_hash"].startswith("sha256:")
        assert att["chain_head"] == compute_hash(session.transcript[-1])
        assert att["message_count"] == len(session.transcript)
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


class TestAttestationVerification:
    def test_verify_attestation_checks_schema_and_party_signatures(self, agreed_session):
        session, seller, buyer = agreed_session
        key_pairs = {"seller_01": seller.key_pair, "buyer_42": buyer.key_pair}
        att = generate_attestation(
            session,
            key_pairs,
            category="electronics.cameras",
            value_range="100-500_USD",
        )
        public_keys = {
            agent_id: kp.public_key for agent_id, kp in key_pairs.items()
        }

        result = verify_attestation(att, public_keys)

        assert result.valid is True
        assert result.errors == []
        assert sorted(result.verified_parties) == ["buyer_42", "seller_01"]

    def test_verify_attestation_rejects_party_tamper(self, agreed_session):
        session, seller, buyer = agreed_session
        key_pairs = {"seller_01": seller.key_pair, "buyer_42": buyer.key_pair}
        att = generate_attestation(session, key_pairs)
        public_keys = {
            agent_id: kp.public_key for agent_id, kp in key_pairs.items()
        }

        assert verify_attestation(att, public_keys).valid is True
        att["parties"][0]["behavior"]["offers_made"] += 1
        result = verify_attestation(att, public_keys)

        assert result.valid is False
        assert any("invalid signature" in e for e in result.signature_errors)

    def test_verify_attestation_fails_closed_on_malformed_input(self):
        result = verify_attestation({"parties": "not-a-list"}, {})

        assert result.valid is False
        assert result.errors

    def test_verify_attestation_rejects_resigned_splice_transcript(self):
        session, spliced, seller, buyer = _same_signer_splice_fixture()
        key_pairs = {seller.agent_id: seller.key_pair, buyer.agent_id: buyer.key_pair}
        public_keys = {agent_id: kp.public_key for agent_id, kp in key_pairs.items()}
        att = generate_attestation(session, key_pairs)

        assert validate_chain(spliced) is True
        assert compute_hash(spliced[-1]) != att["chain_head"]
        result = verify_attestation(att, public_keys, transcript=spliced)

        assert result.valid is False
        assert result.set_binding_state == "error"
        assert any("chain_head mismatch" in e for e in result.set_binding_errors)
        assert any("message_count mismatch" in e for e in result.set_binding_errors)

    def test_verify_attestation_rejects_truncated_transcript(self, agreed_session):
        session, seller, buyer = agreed_session
        key_pairs = {"seller_01": seller.key_pair, "buyer_42": buyer.key_pair}
        public_keys = {agent_id: kp.public_key for agent_id, kp in key_pairs.items()}
        att = generate_attestation(session, key_pairs)
        truncated = session.transcript[:-1]

        assert validate_chain(truncated) is True
        result = verify_attestation(att, public_keys, transcript=truncated)

        assert result.valid is False
        assert result.set_binding_state == "error"
        assert any("message_count mismatch" in e for e in result.set_binding_errors)

    def test_verify_attestation_v03_missing_set_field_fails_closed(self, agreed_session):
        session, seller, buyer = agreed_session
        key_pairs = {"seller_01": seller.key_pair, "buyer_42": buyer.key_pair}
        public_keys = {agent_id: kp.public_key for agent_id, kp in key_pairs.items()}
        att = generate_attestation(session, key_pairs)
        del att["chain_head"]

        result = verify_attestation(att, public_keys)

        assert result.valid is False
        assert result.set_binding_state == "error"
        assert any("requires chain_head" in e for e in result.set_binding_errors)

    def test_verify_attestation_v03_malformed_set_fields_fail_closed(self, agreed_session):
        session, seller, buyer = agreed_session
        key_pairs = {"seller_01": seller.key_pair, "buyer_42": buyer.key_pair}
        public_keys = {agent_id: kp.public_key for agent_id, kp in key_pairs.items()}
        att = generate_attestation(session, key_pairs)
        att["chain_head"] = "sha256:NOTLOWERHEX"
        att["message_count"] = 0

        result = verify_attestation(att, public_keys)

        assert result.valid is False
        assert any("requires chain_head" in e for e in result.set_binding_errors)
        assert any("requires message_count" in e for e in result.set_binding_errors)

    def test_verify_attestation_legacy_set_unbound_is_reported(self, agreed_session):
        session, seller, buyer = agreed_session
        key_pairs = {"seller_01": seller.key_pair, "buyer_42": buyer.key_pair}
        public_keys = {agent_id: kp.public_key for agent_id, kp in key_pairs.items()}
        att = generate_attestation(session, key_pairs)
        att["concordia_attestation"] = "0.2.0"
        del att["chain_head"]
        del att["message_count"]

        result = verify_attestation(att, public_keys, transcript=session.transcript)

        assert result.valid is True
        assert result.set_binding_state == "legacy_set_unbound"
        assert any("legacy set-unbound" in w for w in result.warnings)


def _same_signer_splice_fixture():
    seller = Agent("seller_splice_test")
    buyer = Agent("buyer_splice_test")
    terms = {"price": {"value": 500, "currency": "USD"}}
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    buyer.accept_session()
    seller.send_offer(BasicOffer(terms=terms), reasoning="message to remove")
    seller.inquire(["price"], reasoning="downstream same-signer message 1")
    seller.accept_offer(reasoning="downstream same-signer message 2")

    original = deepcopy(session.transcript)
    spliced = [
        deepcopy(original[0]),
        deepcopy(original[1]),
        deepcopy(original[3]),
        deepcopy(original[4]),
    ]
    prev_hash = compute_hash(spliced[1])
    for msg in spliced[2:]:
        assert msg["from"]["agent_id"] == seller.agent_id
        msg["prev_hash"] = prev_hash
        msg.pop("signature", None)
        msg["signature"] = sign_message(msg, seller.key_pair)
        prev_hash = compute_hash(msg)

    assert len(original) == 5
    assert validate_chain(original) is True
    assert validate_chain(spliced) is True
    return session, spliced, seller, buyer
