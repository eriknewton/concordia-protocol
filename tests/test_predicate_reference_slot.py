"""Predicate is an opaque attestation reference slot in v0.5.2."""

from __future__ import annotations

import warnings

import pytest

from concordia import (
    Agent,
    BasicOffer,
    SessionState,
    generate_attestation,
    is_valid_attestation,
    validate_attestation,
)


@pytest.fixture
def agreed_session():
    seller = Agent("seller_predicate_ref")
    buyer = Agent("buyer_predicate_ref")
    terms = {"price": {"value": 100.0, "currency": "USD"}, "qty": {"value": 1}}
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    buyer.accept_session()
    seller.send_offer(
        BasicOffer(
            terms={
                "price": {"value": 100.0, "currency": "USD"},
                "qty": {"value": 1},
            }
        )
    )
    buyer.accept_offer()
    assert session.state == SessionState.AGREED
    return session, seller, buyer


def _key_pairs(seller, buyer):
    return {
        seller.identity.agent_id: seller.key_pair,
        buyer.identity.agent_id: buyer.key_pair,
    }


def test_predicate_reference_preserved_by_emit_and_schema(agreed_session):
    session, seller, buyer = agreed_session
    predicate_ref = {
        "type": "predicate",
        "id": "urn:concordia:predicate:age_gate:v0",
        "relationship": "references",
        "extensions": {"profile": "opaque-authority-gate"},
    }
    att = generate_attestation(
        session,
        _key_pairs(seller, buyer),
        references=[predicate_ref],
    )
    assert att["references"] == [predicate_ref]
    assert is_valid_attestation(att)


def test_predicate_reference_validation_does_not_warn_or_resolve(agreed_session):
    session, seller, buyer = agreed_session
    att = generate_attestation(
        session,
        _key_pairs(seller, buyer),
        references=[
            {
                "type": "predicate",
                "id": "urn:concordia:predicate:unresolvable-local-test",
                "relationship": "references",
            }
        ],
    )
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        assert validate_attestation(att) == []
    assert seen == []


def test_predicate_reference_survives_schema_validation_unchanged(agreed_session):
    session, seller, buyer = agreed_session
    att = generate_attestation(
        session,
        _key_pairs(seller, buyer),
        references=[
            {
                "type": "predicate",
                "id": "predicate:opaque-slot-only",
                "relationship": "advisory_gate",
            }
        ],
    )
    with pytest.warns(UserWarning, match="non-canonical"):
        assert is_valid_attestation(att)
    assert att["references"][0] == {
        "type": "predicate",
        "id": "predicate:opaque-slot-only",
        "relationship": "advisory_gate",
    }
