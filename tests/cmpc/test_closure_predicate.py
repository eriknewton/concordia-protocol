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


def test_evaluable_predicate_from_signed_closure_predicate() -> None:
    from concordia.cmpc import ClosurePredicate

    signed = ClosurePredicate(
        predicate_id="urn:concordia:predicate:closure-1",
        type=BILATERAL_CHAIN_CLOSURE_V1,
        authority="did:web:authority.example",
        issuer="did:web:issuer.example",
        subject="urn:concordia:chain-session:beer-1",
        condition={
            "expected_participants": [RETAILER, WHOLESALER],
            "aggregate_quantity_required": 100,
            "activation_deadline_iso": BEFORE_DEADLINE,
            "mandate_check_required": False,
            "_now": NOW,
        },
        issued_at="2026-05-16T11:00:00Z",
        expires_at="2026-05-16T15:00:00Z",
        references=[],
        algorithm="EdDSA",
        status="active",
        signature="sig",
    )
    evaluable = EvaluablePredicate.from_closure_predicate(signed)
    assert evaluable.type_urn == BILATERAL_CHAIN_CLOSURE_V1
    commitments = [_commitment(RETAILER, 60), _commitment(WHOLESALER, 40)]
    result = evaluate_predicate(evaluable, _chain_session(), commitments)
    assert result.result == "satisfied"


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
