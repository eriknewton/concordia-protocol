"""Tests for JSON Schema validation of messages and attestations."""

from __future__ import annotations

import copy

from concordia import (
    Agent,
    BasicOffer,
    KeyPair,
    generate_attestation,
    is_valid_attestation,
    is_valid_message,
    validate_attestation,
    validate_message,
)


class TestMessageValidation:
    def test_valid_open_message(self):
        seller = Agent("seller_01")
        buyer = Agent("buyer_42")
        session = seller.open_session(
            counterparty=buyer.identity,
            terms={"price": {"value": 150.00, "currency": "USD"}},
        )
        # First message in transcript is the open message
        msg = session.transcript[0]
        assert is_valid_message(msg), validate_message(msg)

    def test_valid_offer_message(self):
        seller = Agent("seller_01")
        buyer = Agent("buyer_42")
        session = seller.open_session(
            counterparty=buyer.identity,
            terms={"price": {"value": 150.00}},
        )
        buyer.join_session(session)
        buyer.accept_session()
        offer = BasicOffer(terms={"price": {"value": 120.00}})
        buyer.send_offer(offer)
        # The offer message is the last in transcript
        msg = session.transcript[-1]
        assert is_valid_message(msg), validate_message(msg)

    def test_all_messages_in_session_valid(self):
        seller = Agent("seller_01")
        buyer = Agent("buyer_42")
        session = seller.open_session(
            counterparty=buyer.identity,
            terms={"price": {"value": 150.00, "currency": "USD"}},
        )
        buyer.join_session(session)
        buyer.accept_session()
        offer = BasicOffer(terms={"price": {"value": 120.00, "currency": "USD"}})
        buyer.send_offer(offer)
        counter = BasicOffer(terms={"price": {"value": 135.00, "currency": "USD"}})
        seller.send_counter(counter, reasoning="Meeting in the middle")
        buyer.accept_offer()

        for i, msg in enumerate(session.transcript):
            errors = validate_message(msg)
            assert not errors, f"Message {i} ({msg['type']}) invalid: {errors}"

    def test_invalid_message_missing_fields(self):
        msg = {"concordia": "0.1.0", "type": "negotiate.open"}
        errors = validate_message(msg)
        assert len(errors) > 0

    def test_invalid_message_bad_type(self):
        msg = {
            "concordia": "0.1.0",
            "type": "negotiate.invalid_type",
            "id": "msg_1",
            "session_id": "ses_1",
            "timestamp": "2026-03-21T00:00:00Z",
            "from": {"agent_id": "a"},
            "body": {},
            "signature": "sig",
        }
        errors = validate_message(msg)
        assert len(errors) > 0


class TestAttestationValidation:
    def _valid_attestation(self):
        behavior = {
            "offers_made": 1,
            "concessions": 0,
            "concession_magnitude": 0,
            "signals_shared": 0,
            "constraints_declared": 0,
            "constraints_violated": 0,
            "reasoning_provided": True,
            "withdrawal": False,
        }
        return {
            "concordia_attestation": "0.1.0",
            "attestation_id": "att_valid",
            "session_id": "ses_valid",
            "timestamp": "2026-05-10T14:22:08Z",
            "outcome": {
                "status": "agreed",
                "rounds": 2,
                "duration_seconds": 60,
                "terms_count": 3,
                "resolution_mechanism": "direct",
            },
            "parties": [
                {
                    "agent_id": "agent_a",
                    "role": "initiator",
                    "behavior": copy.deepcopy(behavior),
                    "signature": "sig_a",
                },
                {
                    "agent_id": "agent_b",
                    "role": "responder",
                    "behavior": copy.deepcopy(behavior),
                    "signature": "sig_b",
                },
            ],
            "meta": {
                "category": "electronics.cameras",
                "value_range": "1000-5000_USD",
                "extensions_used": [],
                "mediator_invoked": False,
            },
            "transcript_hash": "sha256:" + "a" * 64,
            "fulfillment": None,
        }

    def test_valid_attestation(self):
        seller = Agent("seller_01")
        buyer = Agent("buyer_42")
        session = seller.open_session(
            counterparty=buyer.identity,
            terms={
                "price": {"value": 150.00, "currency": "USD"},
                "condition": {"value": "good"},
            },
        )
        buyer.join_session(session)
        buyer.accept_session()
        offer = BasicOffer(terms={
            "price": {"value": 135.00, "currency": "USD"},
            "condition": {"value": "good"},
        })
        seller.send_offer(offer)
        buyer.accept_offer()

        key_pairs = {"seller_01": seller.key_pair, "buyer_42": buyer.key_pair}
        att = generate_attestation(
            session, key_pairs,
            category="electronics.cameras",
            value_range="100-500_USD",
        )
        errors = validate_attestation(att)
        assert not errors, f"Attestation invalid: {errors}"

    def test_invalid_attestation_missing_fields(self):
        att = {"concordia_attestation": "0.1.0"}
        errors = validate_attestation(att)
        assert len(errors) > 0

    def test_rejects_top_level_raw_term_extra_field(self):
        att = self._valid_attestation()
        att["price"] = {"value": 1900, "currency": "USD"}
        errors = validate_attestation(att)
        assert "$: Additional properties are not allowed ('price' was unexpected)" in errors

    def test_rejects_outcome_agreed_terms(self):
        att = self._valid_attestation()
        att["outcome"]["agreed_terms"] = {
            "price": {"value": 1900, "currency": "USD"},
            "quantity": 2,
        }
        errors = validate_attestation(att)
        assert (
            "$.outcome: Additional properties are not allowed "
            "('agreed_terms' was unexpected)"
        ) in errors

    def test_rejects_per_party_raw_price(self):
        att = self._valid_attestation()
        att["parties"][0]["behavior"]["price_floor"] = 1750
        att["parties"][0]["behavior"]["accepted_price"] = 1900
        errors = validate_attestation(att)
        assert (
            "$.parties[0].behavior: Additional properties are not allowed "
            "('accepted_price', 'price_floor' were unexpected)"
        ) in errors

    def test_rejects_reference_extensions_term_payload(self):
        att = self._valid_attestation()
        att["references"] = [
            {
                "id": "urn:concordia:predicate:privacy",
                "type": "predicate",
                "relationship": "references",
                "extensions": {
                    "price": 1900,
                    "quantity": 2,
                },
            }
        ]
        errors = validate_attestation(att)
        assert (
            "$.references[0].extensions: Additional properties are not allowed "
            "('price', 'quantity' were unexpected)"
        ) in errors
