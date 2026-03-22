"""Tests for the Session state machine (§5).

Covers all valid state transitions and verifies that invalid
transitions raise InvalidTransitionError.
"""

import pytest

from concordia import (
    Agent,
    BasicOffer,
    InvalidTransitionError,
    Session,
    SessionState,
)


@pytest.fixture
def negotiation():
    """Set up a seller/buyer pair with an open session."""
    seller = Agent("seller")
    buyer = Agent("buyer")
    terms = {
        "price": {"value": 150.00, "currency": "USD"},
        "condition": {"value": "good"},
    }
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    return seller, buyer, session


class TestValidTransitions:
    """All valid transitions per §5.2 must succeed."""

    def test_proposed_to_active(self, negotiation):
        seller, buyer, session = negotiation
        assert session.state == SessionState.PROPOSED
        buyer.accept_session()
        assert session.state == SessionState.ACTIVE

    def test_proposed_to_rejected(self, negotiation):
        seller, buyer, session = negotiation
        buyer.decline_session(reason="Not interested")
        assert session.state == SessionState.REJECTED

    def test_proposed_to_expired(self, negotiation):
        _, _, session = negotiation
        session.expire()
        assert session.state == SessionState.EXPIRED

    def test_active_stays_active_on_offer(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        offer = BasicOffer(terms={"price": {"value": 120.00, "currency": "USD"}})
        buyer.send_offer(offer)
        assert session.state == SessionState.ACTIVE

    def test_active_stays_active_on_counter(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        offer = BasicOffer(terms={"price": {"value": 120.00, "currency": "USD"}})
        buyer.send_offer(offer)
        counter = BasicOffer(terms={"price": {"value": 140.00, "currency": "USD"}})
        seller.send_counter(counter)
        assert session.state == SessionState.ACTIVE

    def test_active_to_agreed(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        offer = BasicOffer(terms={"price": {"value": 135.00, "currency": "USD"}})
        seller.send_offer(offer)
        buyer.accept_offer()
        assert session.state == SessionState.AGREED

    def test_active_to_rejected_on_reject(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        offer = BasicOffer(terms={"price": {"value": 200.00, "currency": "USD"}})
        seller.send_offer(offer)
        buyer.reject_offer(reason="Too expensive")
        assert session.state == SessionState.REJECTED

    def test_active_to_rejected_on_withdraw(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        buyer.withdraw(reason="Changed my mind")
        assert session.state == SessionState.REJECTED

    def test_active_to_expired(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        session.expire()
        assert session.state == SessionState.EXPIRED

    def test_rejected_to_dormant(self, negotiation):
        seller, buyer, session = negotiation
        buyer.decline_session()
        session.make_dormant()
        assert session.state == SessionState.DORMANT
        assert session.reactivatable is True

    def test_expired_to_dormant(self, negotiation):
        _, _, session = negotiation
        session.expire()
        session.make_dormant()
        assert session.state == SessionState.DORMANT

    def test_dormant_to_active(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        buyer.withdraw()
        session.make_dormant()
        assert session.state == SessionState.DORMANT
        # Reactivate with a new offer
        offer = BasicOffer(terms={"price": {"value": 130.00, "currency": "USD"}})
        seller.send_offer(offer)
        assert session.state == SessionState.ACTIVE

    def test_active_stays_active_on_signal(self, negotiation):
        from concordia import PreferenceSignal, Flexibility

        seller, buyer, session = negotiation
        buyer.accept_session()
        signal = PreferenceSignal(
            priority_ranking=["price", "condition"],
            flexibility={"price": Flexibility.SOMEWHAT_FLEXIBLE},
        )
        buyer.signal(signal)
        assert session.state == SessionState.ACTIVE

    def test_active_stays_active_on_inquire(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        buyer.inquire(term_ids=["price"])
        assert session.state == SessionState.ACTIVE

    def test_active_stays_active_on_constrain(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        buyer.constrain(constraints={"price": {"max": 160.00}})
        assert session.state == SessionState.ACTIVE

    def test_commit_leads_to_agreed(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        offer = BasicOffer(terms={"price": {"value": 135.00, "currency": "USD"}})
        seller.send_offer(offer)
        buyer.accept_offer()
        assert session.state == SessionState.AGREED


class TestInvalidTransitions:
    """Invalid transitions must raise InvalidTransitionError."""

    def test_cannot_offer_in_proposed(self, negotiation):
        seller, buyer, session = negotiation
        offer = BasicOffer(terms={"price": {"value": 100.00, "currency": "USD"}})
        with pytest.raises(InvalidTransitionError):
            buyer.send_offer(offer)

    def test_cannot_accept_in_proposed(self, negotiation):
        seller, buyer, session = negotiation
        with pytest.raises(InvalidTransitionError):
            buyer.accept_offer()

    def test_cannot_accept_session_when_active(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        with pytest.raises(InvalidTransitionError):
            buyer.accept_session()

    def test_cannot_expire_when_agreed(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        offer = BasicOffer(terms={"price": {"value": 135.00, "currency": "USD"}})
        seller.send_offer(offer)
        buyer.accept_offer()
        with pytest.raises(InvalidTransitionError):
            session.expire()

    def test_cannot_make_dormant_from_active(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        with pytest.raises(InvalidTransitionError):
            session.make_dormant()

    def test_cannot_offer_in_agreed(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        offer = BasicOffer(terms={"price": {"value": 135.00, "currency": "USD"}})
        seller.send_offer(offer)
        buyer.accept_offer()
        offer2 = BasicOffer(terms={"price": {"value": 100.00, "currency": "USD"}})
        with pytest.raises(InvalidTransitionError):
            seller.send_offer(offer2)


class TestTranscriptAndBehavior:
    """Transcript recording and behavioral tracking."""

    def test_transcript_grows(self, negotiation):
        seller, buyer, session = negotiation
        assert len(session.transcript) == 1  # open message
        buyer.accept_session()
        assert len(session.transcript) == 2

    def test_round_count(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        offer1 = BasicOffer(terms={"price": {"value": 120.00, "currency": "USD"}})
        buyer.send_offer(offer1)
        counter1 = BasicOffer(terms={"price": {"value": 140.00, "currency": "USD"}})
        seller.send_counter(counter1)
        # round_count increments on OFFER and COUNTER only
        # open → 0, accept_session → 0, offer → 1, counter → 2
        assert session.round_count == 2

    def test_behavior_tracks_offers(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        offer = BasicOffer(terms={"price": {"value": 120.00, "currency": "USD"}})
        buyer.send_offer(offer)
        behavior = session.get_behavior("buyer")
        assert behavior.offers_made == 1

    def test_concluded_at_set(self, negotiation):
        seller, buyer, session = negotiation
        buyer.accept_session()
        assert session.concluded_at is None
        offer = BasicOffer(terms={"price": {"value": 135.00, "currency": "USD"}})
        seller.send_offer(offer)
        buyer.accept_offer()
        assert session.concluded_at is not None

    def test_terms_captured_from_open(self, negotiation):
        _, _, session = negotiation
        assert session.terms is not None
        assert "price" in session.terms
