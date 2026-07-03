"""CMPC closure-predicate evaluator tests.

Covers the bilateral chain-closure profile and the closure-language expression
tree, with explicit satisfied / unsatisfied / malformed coverage. The
fail-closed contract is asserted directly: unknown types and malformed input
must resolve to ``unsatisfied`` and must never raise or default to
``satisfied``.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from concordia.cmpc import (
    BILATERAL_CHAIN_CLOSURE_V1,
    CLOSURE_LANGUAGE_V1,
    ChainSession,
    ChainSessionState,
    EvaluablePredicate,
    PredicateResult,
    evaluate_predicate,
)

RETAILER = "did:web:retailer.example"
WHOLESALER = "did:web:wholesaler.example"

# A fixed reference clock so deadline checks are deterministic.
NOW = "2026-05-16T12:00:00Z"
BEFORE_DEADLINE = "2026-05-16T14:00:00Z"
PAST_DEADLINE = "2026-05-16T10:00:00Z"


def _chain_session() -> ChainSession:
    created = datetime(2026, 5, 16, 11, 0, tzinfo=timezone.utc)
    return ChainSession(
        chain_session_id="urn:concordia:chain-session:beer-1",
        participants=[RETAILER, WHOLESALER],
        closure_predicate_ref="urn:concordia:predicate:closure-1",
        state=ChainSessionState.OPEN,
        created_at=created,
        activation_deadline=created + timedelta(hours=3),
    )


def _commitment(did: str, quantity: Any, mandate: str | None = "urn:concordia:mandate:m1") -> dict[str, Any]:
    return {
        "commitment_id": f"urn:concordia:commitment:{did.split(':')[-1]}",
        "committer_did": did,
        "commitment_terms": {"quantity": quantity, "price": 10},
        "mandate_proof_id": mandate,
    }


def _bilateral_predicate(**overrides: Any) -> EvaluablePredicate:
    params: dict[str, Any] = {
        "expected_participants": [RETAILER, WHOLESALER],
        "aggregate_quantity_required": 100,
        "match_tolerance": 0.0,
        "activation_deadline_iso": BEFORE_DEADLINE,
        "mandate_check_required": True,
        "_now": NOW,
    }
    params.update(overrides)
    return EvaluablePredicate(
        predicate_id="urn:concordia:predicate:closure-1",
        type_urn=BILATERAL_CHAIN_CLOSURE_V1,
        parameters=params,
    )


def _closure_language_predicate(expression: Any) -> EvaluablePredicate:
    return EvaluablePredicate(
        predicate_id="urn:concordia:predicate:closure-lang-1",
        type_urn=CLOSURE_LANGUAGE_V1,
        parameters={"expression": expression},
    )


# --------------------------------------------------------------------------
# Bilateral profile: satisfied
# --------------------------------------------------------------------------


def test_bilateral_satisfied_happy_path() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    assert result.result == "satisfied"
    assert result.satisfied is True
    assert result.evidence["total_quantity"] == 100.0


def test_bilateral_satisfied_within_tolerance() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 41)]
    result = evaluate_predicate(
        _bilateral_predicate(match_tolerance=1.0), _chain_session(), commitments
    )
    assert result.result == "satisfied"


def test_bilateral_satisfied_mandate_check_off_allows_missing_mandate() -> None:
    commitments = [
        _commitment(RETAILER, 60, mandate=None),
        _commitment(WHOLESALER, 40, mandate=None),
    ]
    result = evaluate_predicate(
        _bilateral_predicate(mandate_check_required=False), _chain_session(), commitments
    )
    assert result.result == "satisfied"


# --------------------------------------------------------------------------
# Bilateral profile: unsatisfied (each declared check)
# --------------------------------------------------------------------------


def test_bilateral_unsatisfied_quantity_mismatch() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 30)]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "aggregate_quantity_mismatch"


def test_bilateral_unsatisfied_unexpected_participant() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment("did:web:intruder.example", 40)]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "unexpected_participant"


def test_bilateral_unsatisfied_past_deadline() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(
        _bilateral_predicate(activation_deadline_iso=PAST_DEADLINE),
        _chain_session(),
        commitments,
    )
    assert result.result == "unsatisfied"
    assert result.reason == "past_activation_deadline"


def test_bilateral_unsatisfied_missing_mandate_when_required() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40, mandate=None)]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "missing_mandate_proof"


def test_bilateral_unsatisfied_no_commitments() -> None:
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), [])
    assert result.result == "unsatisfied"
    assert result.reason == "no_commitments"


# --------------------------------------------------------------------------
# Bilateral profile: malformed parameters and records (fail closed)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides,expected_reason",
    [
        ({"expected_participants": "not-a-list"}, "malformed_expected_participants"),
        ({"expected_participants": []}, "malformed_expected_participants"),
        ({"aggregate_quantity_required": "100"}, "malformed_aggregate_quantity_required"),
        ({"aggregate_quantity_required": True}, "malformed_aggregate_quantity_required"),
        ({"match_tolerance": "wide"}, "malformed_match_tolerance"),
        ({"match_tolerance": -1.0}, "negative_match_tolerance"),
        ({"activation_deadline_iso": "not-a-date"}, "malformed_activation_deadline"),
        ({"activation_deadline_iso": 42}, "malformed_activation_deadline"),
        ({"_now": "not-a-date"}, "malformed_now"),
    ],
)
def test_bilateral_malformed_parameters_fail_closed(
    overrides: dict[str, Any], expected_reason: str
) -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(_bilateral_predicate(**overrides), _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == expected_reason


def test_bilateral_missing_aggregate_quantity_required() -> None:
    predicate = _bilateral_predicate()
    del predicate.parameters["aggregate_quantity_required"]
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "missing_aggregate_quantity_required"


def test_bilateral_malformed_commitment_terms() -> None:
    commitments = [
        {"committer_did": RETAILER, "commitment_terms": "oops", "mandate_proof_id": "m"},
        _commitment(WHOLESALER, 40),
    ]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_commitment_terms"


def test_bilateral_non_numeric_quantity() -> None:
    commitments = [_commitment(RETAILER, "sixty"), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "non_numeric_quantity"


def test_bilateral_boolean_quantity_rejected() -> None:
    commitments = [_commitment(RETAILER, True), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "non_numeric_quantity"


def test_bilateral_missing_committer_did() -> None:
    commitments = [{"commitment_terms": {"quantity": 60}, "mandate_proof_id": "m"}]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "missing_committer_did"


# --------------------------------------------------------------------------
# Fail-closed: unknown predicate type never satisfies, never raises
# --------------------------------------------------------------------------


def test_unknown_predicate_type_fails_closed() -> None:
    predicate = EvaluablePredicate(
        predicate_id="urn:concordia:predicate:x",
        type_urn="urn:concordia:predicate-type:unknown:v9",
        parameters={},
    )
    result = evaluate_predicate(predicate, _chain_session(), [])
    assert result.result == "unsatisfied"
    assert result.reason == "unknown_predicate_type"


def test_empty_type_urn_fails_closed() -> None:
    predicate = EvaluablePredicate(predicate_id="p", type_urn="", parameters={})
    result = evaluate_predicate(predicate, _chain_session(), None)
    assert result.result == "unsatisfied"
    assert result.reason == "unknown_predicate_type"


# --------------------------------------------------------------------------
# Closure language: comparison operators
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "op,value,expected",
    [
        ("==", 60, "satisfied"),
        ("!=", 99, "satisfied"),
        (">=", 60, "satisfied"),
        ("<=", 60, "satisfied"),
        (">", 59, "satisfied"),
        ("<", 61, "satisfied"),
        ("==", 61, "unsatisfied"),
        (">", 60, "unsatisfied"),
    ],
)
def test_closure_language_comparison_field(op: str, value: int, expected: str) -> None:
    commitments = [_commitment(RETAILER, 60)]
    predicate = _closure_language_predicate(
        {"op": op, "field": "commitment_terms.quantity", "value": value}
    )
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == expected


# --------------------------------------------------------------------------
# Closure language: aggregation
# --------------------------------------------------------------------------


def test_closure_language_sum_satisfied() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    predicate = _closure_language_predicate(
        {
            "op": "==",
            "left": {"op": "sum", "field": "commitment_terms.quantity"},
            "value": 100,
        }
    )
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "satisfied"


def test_closure_language_count() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    predicate = _closure_language_predicate(
        {"op": "==", "left": {"op": "count"}, "value": 2}
    )
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "satisfied"


def test_closure_language_min_max() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    min_pred = _closure_language_predicate(
        {"op": "==", "left": {"op": "min", "field": "commitment_terms.quantity"}, "value": 40}
    )
    max_pred = _closure_language_predicate(
        {"op": "==", "left": {"op": "max", "field": "commitment_terms.quantity"}, "value": 60}
    )
    assert evaluate_predicate(min_pred, _chain_session(), commitments).result == "satisfied"
    assert evaluate_predicate(max_pred, _chain_session(), commitments).result == "satisfied"


# --------------------------------------------------------------------------
# Closure language: boolean composition, membership, time
# --------------------------------------------------------------------------


def test_closure_language_and_or_not() -> None:
    commitments = [_commitment(RETAILER, 60)]
    field_eq = {"op": "==", "field": "commitment_terms.quantity", "value": 60}
    field_ne = {"op": "==", "field": "commitment_terms.quantity", "value": 99}
    session = _chain_session()

    assert evaluate_predicate(
        _closure_language_predicate({"op": "and", "args": [field_eq, field_eq]}),
        session,
        commitments,
    ).result == "satisfied"
    assert evaluate_predicate(
        _closure_language_predicate({"op": "and", "args": [field_eq, field_ne]}),
        session,
        commitments,
    ).result == "unsatisfied"
    assert evaluate_predicate(
        _closure_language_predicate({"op": "or", "args": [field_eq, field_ne]}),
        session,
        commitments,
    ).result == "satisfied"
    assert evaluate_predicate(
        _closure_language_predicate({"op": "not", "arg": field_ne}),
        session,
        commitments,
    ).result == "satisfied"


def test_closure_language_membership() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    predicate = _closure_language_predicate(
        {"op": "in", "field": "committer_did", "values": [RETAILER, WHOLESALER]}
    )
    assert evaluate_predicate(predicate, _chain_session(), commitments).result == "satisfied"

    reject = _closure_language_predicate(
        {"op": "in", "field": "committer_did", "values": [RETAILER]}
    )
    assert evaluate_predicate(reject, _chain_session(), commitments).result == "unsatisfied"


def test_closure_language_time_before_after() -> None:
    commitments = [
        {"committer_did": RETAILER, "commitment_terms": {"delivery": "2026-05-16T09:00:00Z"}},
    ]
    before = _closure_language_predicate(
        {"op": "before", "field": "commitment_terms.delivery", "value": "2026-05-16T12:00:00Z"}
    )
    after = _closure_language_predicate(
        {"op": "after", "field": "commitment_terms.delivery", "value": "2026-05-16T12:00:00Z"}
    )
    assert evaluate_predicate(before, _chain_session(), commitments).result == "satisfied"
    assert evaluate_predicate(after, _chain_session(), commitments).result == "unsatisfied"


# --------------------------------------------------------------------------
# Closure language: malformed trees fail closed (never raise, never satisfy)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expression",
    [
        {"op": "bogus"},
        {"op": "and"},
        {"op": "and", "args": []},
        {"op": "and", "args": ["not-a-node"]},
        {"op": "not"},
        {"op": "=="},
        {"op": "==", "field": "commitment_terms.quantity"},
        {"op": "==", "field": "missing.path", "value": 1},
        {"op": "in", "field": "committer_did"},
        {"op": "in", "values": [RETAILER]},
        {"op": "before", "field": "commitment_terms.delivery"},
        {"op": "sum", "field": "commitment_terms.price_str"},
    ],
)
def test_closure_language_malformed_fails_closed(expression: dict[str, Any]) -> None:
    commitments = [
        {
            "committer_did": RETAILER,
            "commitment_terms": {"quantity": 60, "price_str": "ten"},
        }
    ]
    result = evaluate_predicate(
        _closure_language_predicate(expression), _chain_session(), commitments
    )
    assert isinstance(result, PredicateResult)
    assert result.result == "unsatisfied"


def test_closure_language_missing_expression() -> None:
    predicate = EvaluablePredicate(
        predicate_id="p", type_urn=CLOSURE_LANGUAGE_V1, parameters={}
    )
    result = evaluate_predicate(predicate, _chain_session(), [])
    assert result.result == "unsatisfied"
    assert result.reason == "missing_expression"


# --------------------------------------------------------------------------
# Result shape and adapter
# --------------------------------------------------------------------------


def test_predicate_result_to_dict_shape() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    payload = result.to_dict()
    assert payload["result"] == "satisfied"
    assert "evidence" in payload
    assert "reason" not in payload


# --------------------------------------------------------------------------
# Fail-closed: non-finite numeric inputs (NaN / inf) never satisfy
#
# json.loads accepts the bare tokens NaN, Infinity, and -Infinity as float
# values, so an attacker-controlled commitment or condition payload can carry a
# non-finite quantity. These must resolve to unsatisfied: a non-finite required
# quantity, tolerance, or aggregand poisons the abs(...) > tolerance mismatch
# guard (every comparison against NaN is False), which would otherwise report a
# deal closed when it is not.
# --------------------------------------------------------------------------


def test_bilateral_nan_quantity_fails_closed() -> None:
    commitments = [
        _commitment(RETAILER, float("nan")),
        _commitment(WHOLESALER, 5),
    ]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "non_numeric_quantity"


def test_bilateral_inf_quantity_fails_closed() -> None:
    commitments = [
        _commitment(RETAILER, float("inf")),
        _commitment(WHOLESALER, 5),
    ]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "non_numeric_quantity"


def test_bilateral_nan_required_quantity_fails_closed() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    predicate = _bilateral_predicate(aggregate_quantity_required=float("nan"))
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_aggregate_quantity_required"


def test_bilateral_nan_tolerance_fails_closed() -> None:
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    predicate = _bilateral_predicate(match_tolerance=float("nan"))
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_match_tolerance"


def test_closure_language_nan_aggregand_fails_closed() -> None:
    # not(sum > threshold) must not report satisfied when a NaN aggregand is
    # present: rejecting the aggregand keeps the expression unsatisfied.
    commitments = [_commitment(RETAILER, float("nan")), _commitment(WHOLESALER, 40)]
    predicate = _closure_language_predicate(
        {
            "op": "not",
            "arg": {
                "op": ">",
                "left": {"op": "sum", "field": "commitment_terms.quantity"},
                "value": 1000,
            },
        }
    )
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"


def test_closure_language_direct_comparison_nan_cap_fails_closed() -> None:
    # not(qty > 1000) is a hard quantity cap. A NaN quantity makes
    # operator.gt(nan, 1000) False, so not(False) would report satisfied and
    # bypass the cap. The direct field-comparison path must reject the
    # non-finite comparand and fail closed instead.
    cap = {
        "op": "not",
        "arg": {"op": ">", "field": "commitment_terms.quantity", "value": 1000},
    }
    predicate = _closure_language_predicate(cap)

    # Honest over-cap quantity is correctly blocked.
    over = evaluate_predicate(predicate, _chain_session(), [_commitment(RETAILER, 2000)])
    assert over.result == "unsatisfied"

    # NaN quantity must not slip through as satisfied.
    nan_result = evaluate_predicate(
        predicate, _chain_session(), [_commitment(RETAILER, float("nan"))]
    )
    assert nan_result.result == "unsatisfied"

    # Honest within-cap quantity still satisfies.
    within = evaluate_predicate(predicate, _chain_session(), [_commitment(RETAILER, 500)])
    assert within.result == "satisfied"


def test_closure_language_direct_inequality_nan_fails_closed() -> None:
    # qty != 0 with a NaN quantity: operator.ne(nan, 0) is True, which would
    # report satisfied. The direct comparison path must reject NaN and fail
    # closed.
    predicate = _closure_language_predicate(
        {"op": "!=", "field": "commitment_terms.quantity", "value": 0}
    )
    nan_result = evaluate_predicate(
        predicate, _chain_session(), [_commitment(RETAILER, float("nan"))]
    )
    assert nan_result.result == "unsatisfied"

    # A finite non-zero quantity still satisfies qty != 0.
    finite = evaluate_predicate(predicate, _chain_session(), [_commitment(RETAILER, 5)])
    assert finite.result == "satisfied"


def test_closure_language_direct_comparison_nan_cap_fails_closed_benign_first() -> None:
    # Order-dependent short-circuit leak: a benign in-cap commitment ordered
    # BEFORE a NaN commitment must not let all()'s short-circuit skip the
    # finiteness guard on the NaN. The cap not(qty > 1000) must fail closed
    # regardless of commitment order.
    cap = {
        "op": "not",
        "arg": {"op": ">", "field": "commitment_terms.quantity", "value": 1000},
    }
    predicate = _closure_language_predicate(cap)

    benign_then_nan = evaluate_predicate(
        predicate,
        _chain_session(),
        [_commitment(RETAILER, 500), _commitment(WHOLESALER, float("nan"))],
    )
    assert benign_then_nan.result == "unsatisfied"

    # An infinite quantity in a non-first commitment must also fail closed.
    benign_then_inf = evaluate_predicate(
        predicate,
        _chain_session(),
        [_commitment(RETAILER, 500), _commitment(WHOLESALER, float("inf"))],
    )
    assert benign_then_inf.result == "unsatisfied"

    # Two honest within-cap commitments still satisfy the cap.
    both_within = evaluate_predicate(
        predicate,
        _chain_session(),
        [_commitment(RETAILER, 500), _commitment(WHOLESALER, 600)],
    )
    assert both_within.result == "satisfied"


def test_closure_language_membership_missing_field_later_commitment_fails_closed() -> None:
    # Order-dependent short-circuit leak in the membership path: a first
    # commitment that is legitimately not-in-set must not let all()'s
    # short-circuit skip field resolution on a later commitment whose field is
    # missing. not(in{committer_did in [a]}) over [not-in-set, missing-field]
    # must fail closed rather than invert to satisfied.
    predicate = _closure_language_predicate(
        {
            "op": "not",
            "arg": {"op": "in", "field": "committer_did", "values": [RETAILER]},
        }
    )
    commitments = [
        {"committer_did": WHOLESALER, "commitment_terms": {}},
        {"commitment_terms": {}},
    ]
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"


def test_closure_language_time_unparsable_later_commitment_fails_closed() -> None:
    # Order-dependent short-circuit leak in the time path: a first commitment
    # that is legitimately not-before must not let all()'s short-circuit skip
    # parsing a later commitment whose timestamp is unparsable.
    # not(before) over [late-parsable, unparsable] must fail closed.
    predicate = _closure_language_predicate(
        {
            "op": "not",
            "arg": {
                "op": "before",
                "field": "commitment_terms.delivery",
                "value": "2026-05-16T12:00:00Z",
            },
        }
    )
    commitments = [
        {
            "committer_did": RETAILER,
            "commitment_terms": {"delivery": "2026-05-16T18:00:00Z"},
        },
        {
            "committer_did": WHOLESALER,
            "commitment_terms": {"delivery": "not-a-time"},
        },
    ]
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"


# --------------------------------------------------------------------------
# Fail-closed (finding C1-1): boolean and/or must evaluate every branch, not
# short-circuit. A malformed branch reached only after an earlier true (OR) or
# false (AND) branch must fail closed rather than let all()/any() skip it.
# --------------------------------------------------------------------------


def test_closure_language_or_true_then_malformed_fails_closed() -> None:
    # any()'s short-circuit would evaluate only the first (true) OR branch and
    # skip the malformed {"op": "bogus"} branch, reporting satisfied on a
    # malformed expression tree. Every branch must be evaluated so the malformed
    # branch's PredicateEvaluationError fails closed.
    predicate = _closure_language_predicate(
        {
            "op": "or",
            "args": [
                {"op": "==", "field": "commitment_terms.quantity", "value": 60},
                {"op": "bogus"},
            ],
        }
    )
    result = evaluate_predicate(predicate, _chain_session(), [_commitment(RETAILER, 60)])
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_predicate"

    # A well-formed OR whose first branch is true still satisfies (the fix does
    # not over-reject legitimate short-circuit-eligible trees).
    legit = _closure_language_predicate(
        {
            "op": "or",
            "args": [
                {"op": "==", "field": "commitment_terms.quantity", "value": 60},
                {"op": "==", "field": "commitment_terms.quantity", "value": 999},
            ],
        }
    )
    legit_result = evaluate_predicate(legit, _chain_session(), [_commitment(RETAILER, 60)])
    assert legit_result.result == "satisfied"


def test_closure_language_and_false_then_malformed_fails_closed() -> None:
    # all()'s short-circuit would evaluate only the first (false) AND branch and
    # skip the malformed branch, returning False (unsatisfied) by luck. The
    # contract is that a malformed tree fails closed with a malformed reason, not
    # that it happens to be unsatisfied; every branch must be evaluated.
    predicate = _closure_language_predicate(
        {
            "op": "and",
            "args": [
                {"op": "==", "field": "commitment_terms.quantity", "value": 99},
                {"op": "bogus"},
            ],
        }
    )
    result = evaluate_predicate(predicate, _chain_session(), [_commitment(RETAILER, 60)])
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_predicate"


# --------------------------------------------------------------------------
# Fail-closed (finding C1-2): a non-finite EXPECTED comparison literal (NaN /
# Infinity / -Infinity carried in the predicate's `value`) must be rejected
# before comparison. Every comparison against NaN returns False, so a cap
# written as not(field <op> NaN) would otherwise invert to satisfied.
# --------------------------------------------------------------------------


def test_closure_language_not_equal_nan_expected_fails_closed() -> None:
    # not(qty == NaN): operator.eq(60, nan) is False, so not(False) would report
    # satisfied. The expected literal must be rejected as non-finite so the tree
    # fails closed.
    predicate = _closure_language_predicate(
        {
            "op": "not",
            "arg": {"op": "==", "field": "commitment_terms.quantity", "value": float("nan")},
        }
    )
    result = evaluate_predicate(predicate, _chain_session(), [_commitment(RETAILER, 60)])
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_predicate"


def test_closure_language_infinite_expected_fails_closed() -> None:
    # not(qty >= Infinity): operator.ge(60, inf) is False, so not(False) would
    # report satisfied. An infinite expected literal must fail closed too.
    predicate = _closure_language_predicate(
        {
            "op": "not",
            "arg": {"op": ">=", "field": "commitment_terms.quantity", "value": float("inf")},
        }
    )
    result = evaluate_predicate(predicate, _chain_session(), [_commitment(RETAILER, 60)])
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_predicate"


def test_closure_language_left_node_nan_expected_fails_closed() -> None:
    # The `left`-node comparison path (an aggregation result compared to an
    # expected literal) must also reject a non-finite expected literal.
    # not(sum(qty) == NaN) would otherwise invert to satisfied.
    predicate = _closure_language_predicate(
        {
            "op": "not",
            "arg": {
                "op": "==",
                "left": {"op": "sum", "field": "commitment_terms.quantity"},
                "value": float("nan"),
            },
        }
    )
    result = evaluate_predicate(predicate, _chain_session(), [_commitment(RETAILER, 60)])
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_predicate"


# --------------------------------------------------------------------------
# Fail-closed: a deeply nested closure-language tree yields unsatisfied, not a
# raised RecursionError out of evaluate_predicate.
# --------------------------------------------------------------------------


def test_closure_language_deeply_nested_tree_fails_closed() -> None:
    depth = sys.getrecursionlimit() * 4
    expression: dict[str, Any] = {"op": "count"}
    for _ in range(depth):
        expression = {"op": "not", "arg": expression}
    predicate = _closure_language_predicate(expression)
    result = evaluate_predicate(predicate, _chain_session(), [_commitment(RETAILER, 60)])
    assert isinstance(result, PredicateResult)
    assert result.result == "unsatisfied"


# --------------------------------------------------------------------------
# Fail-closed (finding C1-1): evaluate_predicate is total even for a malformed
# predicate object. Reading the type URN or hashing the parameter payload must
# not raise out of evaluate_predicate; a non-EvaluablePredicate or a predicate
# with a non-string type URN must resolve to unsatisfied.
# --------------------------------------------------------------------------


def test_non_evaluable_predicate_object_fails_closed() -> None:
    # A bare object() has no type_urn attribute. Reading it eagerly would raise
    # AttributeError out of evaluate_predicate; it must fail closed instead.
    result = evaluate_predicate(object(), _chain_session(), [])  # type: ignore[arg-type]
    assert isinstance(result, PredicateResult)
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_predicate"


def test_unhashable_type_urn_fails_closed() -> None:
    # A predicate whose type_urn is a list is unhashable; a dict lookup keyed on
    # it would raise TypeError. It must fail closed as a malformed type payload.
    predicate = EvaluablePredicate(
        predicate_id="p",
        type_urn=["x"],  # type: ignore[arg-type]
        parameters={},
    )
    result = evaluate_predicate(predicate, _chain_session(), [])
    assert isinstance(result, PredicateResult)
    assert result.result == "unsatisfied"
    assert result.reason in ("malformed_predicate", "unknown_predicate_type")


def test_non_string_type_urn_fails_closed() -> None:
    predicate = EvaluablePredicate(
        predicate_id="p",
        type_urn=42,  # type: ignore[arg-type]
        parameters={},
    )
    result = evaluate_predicate(predicate, _chain_session(), [])
    assert isinstance(result, PredicateResult)
    assert result.result == "unsatisfied"
    assert result.reason in ("malformed_predicate", "unknown_predicate_type")


# --------------------------------------------------------------------------
# Fail-closed (finding C1-2): the closure language must not satisfy on an EMPTY
# commitment list. count()==0 and sum()==0 over an empty chain would otherwise
# report a deal closed against zero commitments.
# --------------------------------------------------------------------------


def test_closure_language_count_zero_on_empty_fails_closed() -> None:
    predicate = _closure_language_predicate(
        {"op": "==", "left": {"op": "count"}, "value": 0}
    )
    result = evaluate_predicate(predicate, _chain_session(), [])
    assert result.result == "unsatisfied"


def test_closure_language_sum_zero_on_empty_fails_closed() -> None:
    predicate = _closure_language_predicate(
        {
            "op": "==",
            "left": {"op": "sum", "field": "commitment_terms.quantity"},
            "value": 0,
        }
    )
    result = evaluate_predicate(predicate, _chain_session(), [])
    assert result.result == "unsatisfied"


def test_closure_language_root_aggregation_empty_fails_closed() -> None:
    # A bare count root over an empty list must not satisfy either.
    predicate = _closure_language_predicate({"op": "count"})
    result = evaluate_predicate(predicate, _chain_session(), [])
    assert result.result == "unsatisfied"


# --------------------------------------------------------------------------
# Fail-closed (finding C1-3): the bilateral profile must require EVERY expected
# participant to be present. A partial commitment set (subset of expected) must
# not close.
# --------------------------------------------------------------------------


def test_bilateral_partial_participants_fails_closed() -> None:
    # Only the retailer commits (qty 100, future deadline). The wholesaler is an
    # expected participant with no commitment, so the chain must not close.
    commitments = [_commitment(RETAILER, 100)]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "missing_expected_participant"


def test_bilateral_duplicate_participant_fails_closed() -> None:
    # Two commitments from the same expected participant, with the other expected
    # participant absent, must not close even if the quantities sum correctly.
    commitments = [_commitment(RETAILER, 60), _commitment(RETAILER, 40)]
    result = evaluate_predicate(_bilateral_predicate(), _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "duplicate_participant_commitment"


# --------------------------------------------------------------------------
# Fail-closed (finding C1-4): an unverified signed ClosurePredicate primitive
# must NOT become a trusted policy tree. The unsafe from_closure_predicate
# adapter, which converted a signed primitive without verifying its signature,
# status, expiry, or revocation, has been removed. There is no path from an
# unverified signed primitive to a satisfied evaluation.
# --------------------------------------------------------------------------


def test_unsafe_closure_predicate_adapter_removed() -> None:
    # The adapter that turned an unverified signed primitive into trusted policy
    # is gone. Its removal is the fix: an unverified signed primitive cannot be
    # adapted at all, so a dummy or expired signature can never evaluate.
    assert not hasattr(EvaluablePredicate, "from_closure_predicate")


# --------------------------------------------------------------------------
# Fail-closed (finding C1-round-N-1): the non-finite guard must cover the
# membership `in` operator, not only comparison. Field-value resolution now
# routes through a single chokepoint (_get_field) that rejects a NaN / Infinity
# commitment field, so a blocklist written as not(field in {...}) cannot invert
# to satisfied because NaN is not a member of any set. Before the chokepoint the
# guard was applied on comparison but missed on `in`; these fail before / pass
# after that fix.
# --------------------------------------------------------------------------


def test_closure_language_membership_nan_field_fails_closed() -> None:
    # not(in{quantity in [1,2,3]}) with a NaN quantity: NaN is not in the set,
    # so before the chokepoint not(False) inverted to satisfied and bypassed the
    # blocklist. The finiteness guard at field resolution now rejects the NaN.
    predicate = _closure_language_predicate(
        {
            "op": "not",
            "arg": {
                "op": "in",
                "field": "commitment_terms.quantity",
                "values": [1, 2, 3],
            },
        }
    )
    result = evaluate_predicate(
        predicate, _chain_session(), [_commitment(RETAILER, float("nan"))]
    )
    assert isinstance(result, PredicateResult)
    assert result.result == "unsatisfied"


def test_closure_language_membership_inf_field_fails_closed() -> None:
    # An infinite membership comparand must fail closed the same way as NaN.
    predicate = _closure_language_predicate(
        {
            "op": "not",
            "arg": {
                "op": "in",
                "field": "commitment_terms.quantity",
                "values": [1, 2, 3],
            },
        }
    )
    result = evaluate_predicate(
        predicate, _chain_session(), [_commitment(RETAILER, float("inf"))]
    )
    assert result.result == "unsatisfied"


def test_closure_language_membership_nan_field_later_commitment_fails_closed() -> None:
    # The finiteness guard must fire on a NaN in a NON-first commitment too: a
    # first in-set commitment must not let all()'s short-circuit skip the guard
    # on a later NaN. not(in{quantity in [60]}) over [60, NaN] must fail closed.
    predicate = _closure_language_predicate(
        {
            "op": "not",
            "arg": {
                "op": "in",
                "field": "commitment_terms.quantity",
                "values": [60],
            },
        }
    )
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, float("nan"))]
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"


# --------------------------------------------------------------------------
# Fail-closed (finding C1-round-N-2): a bare aggregation (sum/min/max/count) or
# not(aggregation) in a boolean position (root, and/or/not) must be rejected,
# not coerced by numeric truthiness. A boolean position requires a declared
# boolean check; _evaluate_boolean is the single chokepoint that rejects a
# non-boolean node. These fail before / pass after that guard.
# --------------------------------------------------------------------------


def test_closure_language_root_count_bare_fails_closed() -> None:
    # A bare count root over a non-empty chain returned 2.0, which bool()
    # coerced to satisfied. A boolean position must not accept a raw aggregation.
    predicate = _closure_language_predicate({"op": "count"})
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert isinstance(result, PredicateResult)
    assert result.result == "unsatisfied"


def test_closure_language_root_sum_bare_fails_closed() -> None:
    # A bare sum root likewise must not be coerced by truthiness.
    predicate = _closure_language_predicate(
        {"op": "sum", "field": "commitment_terms.quantity"}
    )
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"


def test_closure_language_not_sum_nets_to_zero_fails_closed() -> None:
    # not(sum) with quantities +5 and -5 nets to sum=0; not(0.0) is True, so
    # before the guard this reported satisfied by numeric truthiness. A boolean
    # position must reject the raw aggregation under not().
    predicate = _closure_language_predicate(
        {"op": "not", "arg": {"op": "sum", "field": "commitment_terms.quantity"}}
    )
    commitments = [_commitment(RETAILER, 5), _commitment(WHOLESALER, -5)]
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert isinstance(result, PredicateResult)
    assert result.result == "unsatisfied"


def test_closure_language_and_with_bare_aggregation_child_fails_closed() -> None:
    # A bare aggregation as an and/or child must be rejected too, not coerced.
    predicate = _closure_language_predicate(
        {
            "op": "and",
            "args": [
                {"op": "==", "left": {"op": "count"}, "value": 2},
                {"op": "count"},
            ],
        }
    )
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"


# --------------------------------------------------------------------------
# Fail-closed (finding C1-round-N-P1): the shared field-resolution chokepoint
# must reject a WRONG-TYPE scalar field, not only a non-finite number. A string
# quantity must not satisfy a numeric != by Python cross-type inequality, and a
# boolean field must not satisfy numeric membership by True-aliases-1. The guard
# is keyed on the operator's reference literal(s) at the single _get_field
# boundary, so comparison, membership, and (by construction) every other field
# consumer inherit it. These fail before / pass after the type guard.
# --------------------------------------------------------------------------


def test_closure_language_comparison_string_field_type_mismatch_fails_closed() -> None:
    # quantity != 0 over a string quantity "sixty": operator.ne("sixty", 0) is
    # True, so before the type guard this reported satisfied and let a malformed
    # commitment close a numeric inequality. The chokepoint rejects the string
    # field because its scalar type-class does not match the numeric literal 0.
    predicate = _closure_language_predicate(
        {"op": "!=", "field": "commitment_terms.quantity", "value": 0}
    )
    result = evaluate_predicate(predicate, _chain_session(), [_commitment(RETAILER, "sixty")])
    assert isinstance(result, PredicateResult)
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_predicate"

    # A finite numeric quantity still satisfies quantity != 0.
    finite = evaluate_predicate(
        predicate, _chain_session(), [_commitment(RETAILER, 60)]
    )
    assert finite.result == "satisfied"


def test_closure_language_membership_boolean_field_numeric_alias_fails_closed() -> None:
    # quantity in [1] over a boolean quantity True: True in {1} is True in
    # Python, so before the type guard this reported satisfied by numeric
    # aliasing. The chokepoint rejects the boolean field because bool is its own
    # type-class, distinct from the numeric member 1.
    predicate = _closure_language_predicate(
        {"op": "in", "field": "commitment_terms.quantity", "values": [1]}
    )
    result = evaluate_predicate(predicate, _chain_session(), [_commitment(RETAILER, True)])
    assert isinstance(result, PredicateResult)
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_predicate"

    # A genuine numeric member still matches.
    numeric = evaluate_predicate(
        _closure_language_predicate(
            {"op": "in", "field": "commitment_terms.quantity", "values": [1, 60]}
        ),
        _chain_session(),
        [_commitment(RETAILER, 60)],
    )
    assert numeric.result == "satisfied"

    # String membership on a string field is unaffected by the numeric guard.
    string_member = evaluate_predicate(
        _closure_language_predicate(
            {"op": "in", "field": "committer_did", "values": [RETAILER]}
        ),
        _chain_session(),
        [_commitment(RETAILER, 60)],
    )
    assert string_member.result == "satisfied"


def test_closure_language_membership_string_field_numeric_values_type_mismatch() -> None:
    # A string field checked against a numeric value set must fail closed rather
    # than silently never-match: the type-class mismatch is a malformed pairing.
    predicate = _closure_language_predicate(
        {"op": "in", "field": "committer_did", "values": [1, 2, 3]}
    )
    result = evaluate_predicate(predicate, _chain_session(), [_commitment(RETAILER, 60)])
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_predicate"


# --------------------------------------------------------------------------
# Fail-closed (finding C1-round-N-MED): bilateral parameters must be
# type-checked WITHOUT coercion. A non-string expected participant (str() would
# have coerced it into a matching DID) and a non-bool mandate_check_required
# (bool() would have read "" / 0 / None as False and skipped the mandate check)
# must fail closed. These fail before / pass after the type checks.
# --------------------------------------------------------------------------


def test_bilateral_non_string_expected_participant_fails_closed() -> None:
    # expected_participants=[123] with a committer_did="123" would satisfy the
    # exact-set participant check once str(123) coerces to "123". Requiring a
    # non-empty string without coercion fails closed on the malformed list.
    predicate = _bilateral_predicate(expected_participants=[123, WHOLESALER])
    commitments = [_commitment("123", 60), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_expected_participants"


def test_bilateral_empty_string_expected_participant_fails_closed() -> None:
    # An empty-string participant is malformed too (it can never legitimately
    # match a committer_did, which is itself required non-empty).
    predicate = _bilateral_predicate(expected_participants=["", WHOLESALER])
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_expected_participants"


def test_bilateral_non_bool_mandate_check_required_fails_closed() -> None:
    # mandate_check_required="" is a malformed flag. bool("") is False, which
    # would skip the mandate check and let commitments with NO mandate proof
    # close. A present non-bool value must fail closed instead.
    predicate = _bilateral_predicate(mandate_check_required="")
    commitments = [
        _commitment(RETAILER, 60, mandate=None),
        _commitment(WHOLESALER, 40, mandate=None),
    ]
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_mandate_check_required"


def test_bilateral_truthy_non_bool_mandate_check_required_fails_closed() -> None:
    # A truthy non-bool (the string "yes") must also fail closed: the type is
    # wrong regardless of truthiness, so the parameter payload is malformed.
    predicate = _bilateral_predicate(mandate_check_required="yes")
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(predicate, _chain_session(), commitments)
    assert result.result == "unsatisfied"
    assert result.reason == "malformed_mandate_check_required"
