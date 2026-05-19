"""CMPC closure-predicate evaluation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import operator
from typing import Any, Literal

from concordia.cmpc.chain_session import ChainSession


PredicateOutcome = Literal["satisfied", "unsatisfied"]

BILATERAL_CHAIN_CLOSURE_V1 = (
    "urn:concordia:predicate-type:bilateral_chain_closure:v1"
)
CLOSURE_LANGUAGE_V1 = "urn:concordia:predicate-type:closure_language:v1"


@dataclass
class PredicateResult:
    result: PredicateOutcome
    reason: str | None = None
    evidence: dict[str, Any] | None = None


@dataclass
class ClosurePredicate:
    predicate_id: str
    type_urn: str
    parameters: dict[str, Any]
    version: str = "1"


def evaluate_predicate(
    predicate: ClosurePredicate,
    chain_session: ChainSession,
    commitments_list: list[dict[str, Any]] | None = None,
) -> PredicateResult:
    commitments = commitments_list if commitments_list is not None else []
    evaluator = PROFILES.get(predicate.type_urn)
    if not evaluator:
        return PredicateResult(
            "unsatisfied",
            reason=f"unknown_predicate_type:{predicate.type_urn}",
        )
    return evaluator(predicate, chain_session, commitments)


def evaluate_closure_language_v1(
    predicate: ClosurePredicate,
    chain_session: ChainSession,
    commitments_list: list[dict[str, Any]],
) -> PredicateResult:
    node = predicate.parameters.get("expression")
    if not isinstance(node, dict):
        return PredicateResult("unsatisfied", reason="missing_expression")
    try:
        value = evaluate_node(node, chain_session, commitments_list)
    except (KeyError, TypeError, ValueError) as exc:
        return PredicateResult("unsatisfied", reason=str(exc))
    if bool(value):
        return PredicateResult("satisfied", evidence={"value": value})
    return PredicateResult("unsatisfied", reason="predicate_not_satisfied")


def evaluate_node(
    node: dict[str, Any],
    chain_session: ChainSession,
    commitments: list[dict[str, Any]],
) -> Any:
    op = node.get("op")
    if op == "and":
        return all(evaluate_node(arg, chain_session, commitments) for arg in node["args"])
    if op == "or":
        return any(evaluate_node(arg, chain_session, commitments) for arg in node["args"])
    if op == "not":
        return not evaluate_node(node["arg"], chain_session, commitments)
    if op in ("==", "!=", ">=", "<=", ">", "<"):
        return evaluate_comparison(node, chain_session, commitments)
    if op == "in":
        return evaluate_membership(node, commitments)
    if op in ("before", "after"):
        return evaluate_time(node, commitments)
    if op in ("sum", "min", "max", "count"):
        return evaluate_aggregation(node, commitments)
    raise ValueError(f"Unknown predicate op: {op}")


def evaluate_comparison(
    node: dict[str, Any],
    chain_session: ChainSession,
    commitments: list[dict[str, Any]],
) -> bool:
    op = node["op"]
    comparator = _COMPARATORS[op]
    expected = node["value"]

    if "left" in node:
        actual = evaluate_node(node["left"], chain_session, commitments)
        return bool(comparator(actual, expected))

    field = node["field"]
    return all(comparator(_get_field(commitment, field), expected) for commitment in commitments)


def evaluate_membership(node: dict[str, Any], commitments: list[dict[str, Any]]) -> bool:
    accepted_values = set(node["values"])
    field = node["field"]
    return all(_get_field(commitment, field) in accepted_values for commitment in commitments)


def evaluate_time(node: dict[str, Any], commitments: list[dict[str, Any]]) -> bool:
    op = node["op"]
    expected = _parse_iso_datetime(node["value"])
    field = node["field"]
    if op == "before":
        return all(_parse_iso_datetime(_get_field(c, field)) < expected for c in commitments)
    if op == "after":
        return all(_parse_iso_datetime(_get_field(c, field)) > expected for c in commitments)
    raise ValueError(f"Unknown time op: {op}")


def evaluate_aggregation(node: dict[str, Any], commitments: list[dict[str, Any]]) -> int | float:
    op = node["op"]
    if op == "count":
        return len(commitments)

    field = node["field"]
    values = [_get_field(commitment, field) for commitment in commitments]
    if not all(isinstance(value, int | float) for value in values):
        raise TypeError(f"Aggregation field is not numeric: {field}")
    numeric_values = [float(value) if isinstance(value, int) else value for value in values]

    if op == "sum":
        return sum(numeric_values)
    if op == "min":
        return min(numeric_values)
    if op == "max":
        return max(numeric_values)
    raise ValueError(f"Unknown aggregation op: {op}")


def evaluate_bilateral_chain_closure_v1(
    predicate: ClosurePredicate,
    chain_session: ChainSession,
    commitments_list: list[dict[str, Any]],
) -> PredicateResult:
    params = predicate.parameters
    expected = set(params["expected_participants"])
    required_qty = params["aggregate_quantity_required"]
    tolerance = params.get("match_tolerance", 0.0)
    deadline = _parse_iso_datetime(params["activation_deadline_iso"])
    mandate_check = params.get("mandate_check_required", False)

    actual_participants = {commitment["committer_did"] for commitment in commitments_list}
    if not actual_participants.issubset(expected):
        return PredicateResult(
            "unsatisfied",
            reason="unexpected_participants",
            evidence={
                "actual": sorted(actual_participants),
                "expected": sorted(expected),
            },
        )

    total_qty = sum(
        commitment["commitment_terms"].get("quantity", 0)
        for commitment in commitments_list
    )
    if abs(total_qty - required_qty) > tolerance:
        return PredicateResult(
            "unsatisfied",
            reason="aggregate_quantity_mismatch",
            evidence={"actual": total_qty, "required": required_qty},
        )

    now = datetime.now(timezone.utc)
    if now >= deadline:
        return PredicateResult(
            "unsatisfied",
            reason="past_activation_deadline",
            evidence={"now": now.isoformat(), "deadline": deadline.isoformat()},
        )

    if mandate_check:
        for commitment in commitments_list:
            if not commitment.get("mandate_proof_id"):
                return PredicateResult(
                    "unsatisfied",
                    reason="missing_mandate_proof",
                    evidence={"commitment_id": commitment.get("commitment_id")},
                )

    return PredicateResult(
        "satisfied",
        evidence={
            "total_qty": total_qty,
            "expected_qty": required_qty,
            "chain_session_id": chain_session.chain_session_id,
        },
    )


def _get_field(commitment: dict[str, Any], field_path: str) -> Any:
    current: Any = commitment
    for segment in field_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            raise KeyError(f"Missing field: {field_path}")
        current = current[segment]
    return current


def _parse_iso_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise TypeError(f"Expected ISO 8601 datetime string, got {type(value).__name__}")
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


_COMPARATORS: dict[str, Callable[[Any, Any], bool]] = {
    "==": operator.eq,
    "!=": operator.ne,
    ">=": operator.ge,
    "<=": operator.le,
    ">": operator.gt,
    "<": operator.lt,
}


PROFILES: dict[
    str,
    Callable[[ClosurePredicate, ChainSession, list[dict[str, Any]]], PredicateResult],
] = {
    BILATERAL_CHAIN_CLOSURE_V1: evaluate_bilateral_chain_closure_v1,
    CLOSURE_LANGUAGE_V1: evaluate_closure_language_v1,
}
