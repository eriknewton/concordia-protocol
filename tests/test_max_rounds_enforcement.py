"""Round-cap enforcement (SPEC §9.5 offer-spam rate limit).

`max_rounds` was advertised in the spec and echoed in session metadata but never
enforced: `round_count` incremented without bound, so a peer could drive
unlimited offer/counter rounds and grow the transcript without limit. These
tests prove the cap is now load-bearing: the offer/counter that would exceed it
is rejected before it is appended or counted, while non-offer messages
(accept/reject/commit) still work so a session can always be concluded.
"""

import pytest

from concordia import (
    Agent,
    BasicOffer,
    MaxRoundsExceededError,
    InvalidTransitionError,
    SessionState,
    TimingConfig,
)


def _capped_negotiation(max_rounds: int):
    """Seller/buyer pair on an ACTIVE session with a small max_rounds cap."""
    seller = Agent("seller")
    buyer = Agent("buyer")
    terms = {"price": {"value": 150.00, "currency": "USD"}}
    session = seller.open_session(
        counterparty=buyer.identity,
        terms=terms,
        timing=TimingConfig(max_rounds=max_rounds),
    )
    buyer.join_session(session)
    buyer.accept_session()
    return seller, buyer, session


def test_offer_counter_rounds_allowed_up_to_cap():
    seller, buyer, session = _capped_negotiation(max_rounds=2)
    buyer.send_offer(BasicOffer(terms={"price": {"value": 120.0, "currency": "USD"}}))   # round 1
    seller.send_counter(BasicOffer(terms={"price": {"value": 140.0, "currency": "USD"}}))  # round 2
    assert session.round_count == 2


def test_offer_beyond_cap_is_rejected_and_not_recorded():
    seller, buyer, session = _capped_negotiation(max_rounds=2)
    buyer.send_offer(BasicOffer(terms={"price": {"value": 120.0, "currency": "USD"}}))
    seller.send_counter(BasicOffer(terms={"price": {"value": 140.0, "currency": "USD"}}))

    transcript_len_before = len(session.transcript)
    with pytest.raises(MaxRoundsExceededError):
        buyer.send_offer(BasicOffer(terms={"price": {"value": 130.0, "currency": "USD"}}))

    # Fail closed: the rejected offer was neither counted nor appended.
    assert session.round_count == 2
    assert len(session.transcript) == transcript_len_before


def test_max_rounds_error_is_an_invalid_transition_error():
    # The MCP propose/counter tools catch (InvalidTransitionError, ValueError),
    # so the subclass relationship is what makes this surface as a clean error.
    assert issubclass(MaxRoundsExceededError, InvalidTransitionError)


def test_session_can_still_be_accepted_at_the_cap():
    """Non-offer transitions are unaffected: a capped session can conclude."""
    seller, buyer, session = _capped_negotiation(max_rounds=1)
    buyer.send_offer(BasicOffer(terms={"price": {"value": 120.0, "currency": "USD"}}))  # round 1 (at cap)

    # A further counter is blocked...
    with pytest.raises(MaxRoundsExceededError):
        seller.send_counter(BasicOffer(terms={"price": {"value": 140.0, "currency": "USD"}}))

    # ...but accepting the standing offer still works (not an offer/counter).
    seller.accept_offer()
    assert session.state == SessionState.AGREED
