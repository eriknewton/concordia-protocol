"""Focused tests for the discovery matching primitives."""

from __future__ import annotations

from concordia.discovery import (
    Have,
    Match,
    Want,
    _categories_compatible,
    _compute_overlap,
    find_matches,
)


def test_want_to_dict_includes_location_when_present() -> None:
    want = Want(
        id="want_123",
        agent_id="buyer_1",
        category="compute.gpu",
        terms={"price": {"max": 100, "currency": "USD"}},
        location={"country": "US", "region": "CA"},
        ttl=60,
        notify=False,
    )

    assert want.to_dict() == {
        "type": "concordia.want",
        "id": "want_123",
        "agent_id": "buyer_1",
        "category": "compute.gpu",
        "terms": {"price": {"max": 100, "currency": "USD"}},
        "ttl": 60,
        "notify": False,
        "location": {"country": "US", "region": "CA"},
    }


def test_want_to_dict_omits_location_when_absent() -> None:
    want = Want(
        id="want_456",
        agent_id="buyer_2",
        category="compute",
        terms={"tier": {"value": "a100"}},
    )

    assert want.to_dict() == {
        "type": "concordia.want",
        "id": "want_456",
        "agent_id": "buyer_2",
        "category": "compute",
        "terms": {"tier": {"value": "a100"}},
        "ttl": 604800,
        "notify": True,
    }


def test_have_to_dict_includes_location_when_present() -> None:
    have = Have(
        id="have_123",
        agent_id="seller_1",
        category="compute.gpu",
        terms={"price": {"min": 80, "currency": "USD"}},
        location={"country": "US", "region": "WA"},
        ttl=120,
    )

    assert have.to_dict() == {
        "type": "concordia.have",
        "id": "have_123",
        "agent_id": "seller_1",
        "category": "compute.gpu",
        "terms": {"price": {"min": 80, "currency": "USD"}},
        "ttl": 120,
        "location": {"country": "US", "region": "WA"},
    }


def test_have_to_dict_omits_location_when_absent() -> None:
    have = Have(
        id="have_456",
        agent_id="seller_2",
        category="compute",
        terms={"tier": {"value": "h100"}},
    )

    assert have.to_dict() == {
        "type": "concordia.have",
        "id": "have_456",
        "agent_id": "seller_2",
        "category": "compute",
        "terms": {"tier": {"value": "h100"}},
        "ttl": 2592000,
    }


def test_match_to_dict_shape_includes_negotiate_open_suggestion() -> None:
    match = Match(
        match_id="match_123",
        want_id="want_123",
        have_id="have_123",
        overlap={"price": {"range": [80, 100], "currency": "USD"}},
        score=1.0,
    )

    assert match.to_dict() == {
        "type": "concordia.match",
        "match_id": "match_123",
        "want_id": "want_123",
        "have_id": "have_123",
        "overlap": {"price": {"range": [80, 100], "currency": "USD"}},
        "score": 1.0,
        "suggestion": "negotiate.open",
    }


def test_categories_compatible_prefix_match_both_directions() -> None:
    assert _categories_compatible("compute", "compute.gpu") is True
    assert _categories_compatible("compute.gpu", "compute") is True


def test_categories_compatible_rejects_incompatible_categories() -> None:
    assert _categories_compatible("compute.gpu", "storage.ssd") is False


def test_compute_overlap_numeric_range_overlap_and_currency_propagation() -> None:
    # Same currency on both sides: the only clearly-correct overlap case.
    # (The reference matcher does NOT compare currencies — see the
    # "needs-design" note in the evidence packet — so this test deliberately
    # keeps both sides on USD rather than asserting a cross-currency match.)
    overlap, score = _compute_overlap(
        {"price": {"max": 100, "currency": "USD"}},
        {"price": {"min": 80, "currency": "USD"}},
    )

    assert overlap == {"price": {"range": [80, 100], "currency": "USD"}}
    assert score == 1.0


def test_compute_overlap_numeric_range_uses_have_currency_when_want_has_none() -> None:
    overlap, score = _compute_overlap(
        {"price": {"max": 100}},
        {"price": {"min": 80, "currency": "EUR"}},
    )

    assert overlap == {"price": {"range": [80, 100], "currency": "EUR"}}
    assert score == 1.0


def test_compute_overlap_numeric_range_without_overlap_scores_zero() -> None:
    overlap, score = _compute_overlap(
        {"price": {"max": 75, "currency": "USD"}},
        {"price": {"min": 80, "currency": "USD"}},
    )

    assert overlap == {}
    assert score == 0.0


def test_compute_overlap_categorical_value_match_and_score_rounding() -> None:
    # Equal categorical values on the two matched terms (the clearly-correct
    # case); the third term is a numeric pair that cannot overlap, so the
    # score is 2/3 == 0.67. (The reference matcher only checks that both
    # values are truthy, not that they are equal — see the "needs-design"
    # note in the evidence packet — so this test uses equal values rather
    # than asserting that mismatched values match.)
    overlap, score = _compute_overlap(
        {
            "gpu": {"value": "a100"},
            "region": {"value": "us-west"},
            "memory": {"min": 80},
        },
        {
            "gpu": {"value": "a100"},
            "region": {"value": "us-west"},
            "memory": {"max": 40},
        },
    )

    assert overlap == {
        "gpu": {"value": "a100"},
        "region": {"value": "us-west"},
    }
    assert score == 0.67


def test_compute_overlap_empty_want_terms_scores_zero() -> None:
    overlap, score = _compute_overlap({}, {"price": {"min": 80}})

    assert overlap == {}
    assert score == 0.0


def test_find_matches_end_to_end_filters_and_emits_one_match_per_overlap() -> None:
    wants = [
        Want(
            id="want_skip_same_agent",
            agent_id="agent_1",
            category="same-agent-only",
            terms={"price": {"max": 100, "currency": "USD"}},
        ),
        Want(
            id="want_skip_incompatible_category",
            agent_id="buyer_2",
            category="storage",
            terms={"price": {"max": 100, "currency": "USD"}},
        ),
        Want(
            id="want_skip_zero_score",
            agent_id="buyer_3",
            category="zero-score-only",
            terms={"price": {"max": 50, "currency": "USD"}},
        ),
        Want(
            id="want_overlap_one",
            agent_id="buyer_4",
            category="price-match",
            terms={"price": {"max": 100, "currency": "USD"}},
        ),
        Want(
            id="want_overlap_two",
            agent_id="buyer_5",
            category="model-match.gpu",
            terms={"model": {"value": "a100"}},
        ),
    ]
    haves = [
        Have(
            id="have_skip_same_agent",
            agent_id="agent_1",
            category="same-agent-only",
            terms={"price": {"min": 80, "currency": "USD"}},
        ),
        Have(
            id="have_skip_incompatible_category",
            agent_id="seller_2",
            category="compute",
            terms={"price": {"min": 80, "currency": "USD"}},
        ),
        Have(
            id="have_skip_zero_score",
            agent_id="seller_3",
            category="zero-score-only",
            terms={"price": {"min": 80, "currency": "USD"}},
        ),
        Have(
            id="have_overlap_price",
            agent_id="seller_4",
            category="price-match.gpu",
            terms={"price": {"min": 80, "currency": "USD"}},
        ),
        Have(
            id="have_overlap_model",
            agent_id="seller_5",
            category="model-match",
            terms={"model": {"value": "a100"}},
        ),
    ]

    matches = find_matches(wants, haves)

    assert [match.to_dict() for match in matches] == [
        {
            "type": "concordia.match",
            "match_id": matches[0].match_id,
            "want_id": "want_overlap_one",
            "have_id": "have_overlap_price",
            "overlap": {"price": {"range": [80, 100], "currency": "USD"}},
            "score": 1.0,
            "suggestion": "negotiate.open",
        },
        {
            "type": "concordia.match",
            "match_id": matches[1].match_id,
            "want_id": "want_overlap_two",
            "have_id": "have_overlap_model",
            "overlap": {"model": {"value": "a100"}},
            "score": 1.0,
            "suggestion": "negotiate.open",
        },
    ]
