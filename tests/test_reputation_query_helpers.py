from types import SimpleNamespace

from concordia.reputation.query import (
    _attestation_time_range,
    _compute_flags,
    _context_specific,
    validate_query,
)


def _score(**overrides):
    values = {
        "overall_score": 0.91,
        "confidence": 0.9,
        "total_negotiations": 12,
        "total_agreements": 10,
        "agreement_rate": 0.83,
        "fulfillment_rate": 0.95,
        "sybil_flagged_count": 0,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_validate_query_accepts_valid_query():
    query = {
        "type": "concordia.reputation.query",
        "subject_agent_id": "agent-subject",
        "requester_agent_id": "agent-requester",
        "context": {"category": "electronics"},
    }

    assert validate_query(query) == []


def test_validate_query_reports_wrong_query_type():
    errors = validate_query({
        "type": "not.concordia.reputation.query",
        "subject_agent_id": "agent-subject",
        "requester_agent_id": "agent-requester",
    })

    assert errors == [
        "Invalid query type: expected 'concordia.reputation.query', "
        "got 'not.concordia.reputation.query'"
    ]


def test_validate_query_reports_missing_subject_agent_id():
    errors = validate_query({
        "type": "concordia.reputation.query",
        "requester_agent_id": "agent-requester",
    })

    assert errors == ["Missing required field: 'subject_agent_id'"]


def test_validate_query_reports_missing_requester_agent_id():
    errors = validate_query({
        "type": "concordia.reputation.query",
        "subject_agent_id": "agent-subject",
    })

    assert errors == ["Missing required field: 'requester_agent_id'"]


def test_validate_query_reports_context_that_is_not_a_dict():
    errors = validate_query({
        "type": "concordia.reputation.query",
        "subject_agent_id": "agent-subject",
        "requester_agent_id": "agent-requester",
        "context": "electronics",
    })

    assert errors == ["'context' must be a dict if provided"]


def test_compute_flags_returns_no_flags_for_healthy_score():
    assert _compute_flags(_score(), store=object(), agent_id="agent") == []


def test_compute_flags_detects_each_flag_independently():
    cases = [
        (_score(total_negotiations=4), ["new_agent"]),
        (_score(confidence=0.29), ["low_confidence"]),
        (_score(sybil_flagged_count=1), ["sybil_signals_detected"]),
        (_score(fulfillment_rate=0.79), ["low_fulfillment"]),
        (_score(agreement_rate=0.29), ["low_agreement_rate"]),
    ]

    for score, expected_flags in cases:
        assert _compute_flags(score, store=object(), agent_id="agent") == expected_flags


def test_compute_flags_combines_all_applicable_flags_in_order():
    score = _score(
        total_negotiations=5,
        confidence=0.2,
        sybil_flagged_count=2,
        fulfillment_rate=0.7,
        agreement_rate=0.2,
    )

    assert _compute_flags(score, store=object(), agent_id="agent") == [
        "low_confidence",
        "sybil_signals_detected",
        "low_fulfillment",
        "low_agreement_rate",
    ]


def test_compute_flags_combines_new_agent_without_low_agreement_rate():
    score = _score(
        total_negotiations=4,
        confidence=0.2,
        sybil_flagged_count=2,
        fulfillment_rate=0.7,
        agreement_rate=0.2,
    )

    assert _compute_flags(score, store=object(), agent_id="agent") == [
        "new_agent",
        "low_confidence",
        "sybil_signals_detected",
        "low_fulfillment",
    ]


class FakeScorer:
    def __init__(self, scores):
        self.scores = scores
        self.calls = []

    def score(self, agent_id, *, category=None, value_range=None, role=None):
        self.calls.append({
            "agent_id": agent_id,
            "category": category,
            "value_range": value_range,
            "role": role,
        })
        return self.scores[(category, value_range, role)]


def test_context_specific_returns_empty_dict_without_context():
    scorer = FakeScorer({})

    assert _context_specific(scorer, "agent", None) == {}
    assert _context_specific(scorer, "agent", {}) == {}
    assert scorer.calls == []


def test_context_specific_populates_rounded_scores_and_counts():
    scorer = FakeScorer({
        ("electronics", None, None): SimpleNamespace(
            overall_score=0.87654,
            total_negotiations=7,
        ),
        (None, "1000-5000_USD", None): SimpleNamespace(
            overall_score=0.65432,
            total_negotiations=3,
        ),
        (None, None, "seller"): SimpleNamespace(
            overall_score=0.98765,
            total_negotiations=4,
        ),
    })

    result = _context_specific(
        scorer,
        "agent",
        {
            "category": "electronics",
            "value_range": "1000-5000_USD",
            "role": "seller",
        },
    )

    assert result == {
        "category_score": 0.8765,
        "category_negotiations": 7,
        "value_range_score": 0.6543,
        "role_score": 0.9877,
    }
    assert scorer.calls == [
        {
            "agent_id": "agent",
            "category": "electronics",
            "value_range": None,
            "role": None,
        },
        {
            "agent_id": "agent",
            "category": None,
            "value_range": "1000-5000_USD",
            "role": None,
        },
        {
            "agent_id": "agent",
            "category": None,
            "value_range": None,
            "role": "seller",
        },
    ]


def test_context_specific_uses_none_and_zero_fallbacks():
    scorer = FakeScorer({
        ("electronics", None, None): None,
        (None, "1000-5000_USD", None): None,
        (None, None, "seller"): None,
    })

    result = _context_specific(
        scorer,
        "agent",
        {
            "category": "electronics",
            "value_range": "1000-5000_USD",
            "role": "seller",
        },
    )

    assert result == {
        "category_score": None,
        "category_negotiations": 0,
        "value_range_score": None,
        "role_score": None,
    }


class FakeStore:
    def __init__(self, records):
        self.records = records
        self.agent_ids = []

    def get_by_agent(self, agent_id):
        self.agent_ids.append(agent_id)
        return self.records


def test_attestation_time_range_returns_sorted_earliest_and_latest():
    store = FakeStore([
        SimpleNamespace(attestation={"timestamp": "2026-02-03T00:00:00Z"}),
        SimpleNamespace(attestation={"timestamp": "2024-12-31T23:59:59Z"}),
        SimpleNamespace(attestation={"timestamp": "2025-06-01T12:30:00Z"}),
    ])

    assert _attestation_time_range(store, "agent") == (
        "2024-12-31T23:59:59Z",
        "2026-02-03T00:00:00Z",
    )
    assert store.agent_ids == ["agent"]


def test_attestation_time_range_returns_none_pair_without_records():
    assert _attestation_time_range(FakeStore([]), "agent") == (None, None)


def test_attestation_time_range_returns_none_pair_without_timestamps():
    store = FakeStore([
        SimpleNamespace(attestation={}),
        SimpleNamespace(attestation={"timestamp": None}),
        SimpleNamespace(attestation={"timestamp": ""}),
    ])

    assert _attestation_time_range(store, "agent") == (None, None)
