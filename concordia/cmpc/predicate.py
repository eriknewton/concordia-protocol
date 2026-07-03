"""CMPC closure-predicate evaluation.

Re-derived for Concordia v0.7-alpha from the CMPC Stage 3 bilateral design
intent: a closure predicate evaluates over the commitments on a bilateral chain
session and returns a structured, machine-readable result of either
``satisfied`` or ``unsatisfied``.

Two evaluation surfaces ship in Stage 3:

* The bilateral type profile ``urn:concordia:predicate-type:bilateral_chain_closure:v1``,
  which checks that every committer is an expected participant, that the
  aggregate committed quantity matches the required quantity within tolerance,
  that the activation deadline has not lapsed, and (optionally) that every
  commitment carries a mandate proof.
* A small JSON-tree closure language ``urn:concordia:predicate-type:closure_language:v1``
  supporting Boolean composition (and/or/not), numeric comparison, set
  membership, ISO 8601 time comparison, and aggregation (sum/min/max/count)
  across the chain's commitments.

Fail-closed contract: evaluation is total. Any unknown predicate type, unknown
operator, malformed node, missing field, non-numeric aggregand, unparsable
timestamp, or otherwise malformed input yields ``unsatisfied`` with a
machine-readable reason. It NEVER defaults to ``satisfied`` and NEVER raises out
of :func:`evaluate_predicate`. Satisfaction requires every declared check to
pass explicitly.
"""

from __future__ import annotations

import math
import operator
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from concordia.cmpc.chain_session import ChainSession

PredicateOutcome = Literal["satisfied", "unsatisfied"]

BILATERAL_CHAIN_CLOSURE_V1 = "urn:concordia:predicate-type:bilateral_chain_closure:v1"
CLOSURE_LANGUAGE_V1 = "urn:concordia:predicate-type:closure_language:v1"


class PredicateEvaluationError(Exception):
    """Internal signal used while walking a closure-language expression tree.

    Raised by node evaluators on a malformed or unevaluable node and always
    caught at the closure-language boundary, where it is converted into an
    ``unsatisfied`` result. It never escapes :func:`evaluate_predicate`.
    """


@dataclass
class PredicateResult:
    """Outcome of a closure-predicate evaluation.

    ``result`` is the machine-readable outcome; ``reason`` names the specific
    check that failed on an ``unsatisfied`` result; ``evidence`` carries the
    supporting values used to reach the outcome.
    """

    result: PredicateOutcome
    reason: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def satisfied(self) -> bool:
        return self.result == "satisfied"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"result": self.result}
        if self.reason is not None:
            data["reason"] = self.reason
        if self.evidence:
            data["evidence"] = self.evidence
        return data


@dataclass
class EvaluablePredicate:
    """The evaluable view of a closure predicate.

    Distinct from :class:`concordia.cmpc.types.ClosurePredicate`, which is the
    signed, at-rest primitive. This is the minimal shape the evaluator needs:
    the predicate identifier, the type URN that selects a profile, and the
    parameter payload the selected profile reads.
    """

    predicate_id: str
    type_urn: str
    parameters: dict[str, Any]
    version: str = "1"

    @classmethod
    def from_closure_predicate(cls, predicate: Any) -> "EvaluablePredicate":
        """Adapt a signed ClosurePredicate primitive into an evaluable view.

        The signed primitive stores the profile parameters under its
        ``condition`` field and the type URN under ``type``.
        """
        condition = getattr(predicate, "condition", None)
        parameters: dict[str, Any] = condition if isinstance(condition, dict) else {}
        return cls(
            predicate_id=getattr(predicate, "predicate_id", ""),
            type_urn=getattr(predicate, "type", ""),
            parameters=parameters,
        )


def _satisfied(evidence: dict[str, Any] | None = None) -> PredicateResult:
    return PredicateResult("satisfied", evidence=evidence or {})


def _unsatisfied(reason: str, evidence: dict[str, Any] | None = None) -> PredicateResult:
    return PredicateResult("unsatisfied", reason=reason, evidence=evidence or {})


def evaluate_predicate(
    predicate: EvaluablePredicate,
    chain_session: ChainSession,
    commitments: list[dict[str, Any]] | None = None,
) -> PredicateResult:
    """Evaluate a closure predicate over a chain session's commitments.

    Total and fail-closed: selects the profile evaluator by the predicate's
    type URN and always returns a :class:`PredicateResult`. An unknown type,
    or any error raised inside a profile evaluator, yields ``unsatisfied``
    rather than propagating. Never returns ``satisfied`` by default.
    """
    commitment_list = commitments if commitments is not None else []
    evaluator = _PROFILES.get(predicate.type_urn)
    if evaluator is None:
        return _unsatisfied(
            "unknown_predicate_type",
            {"type_urn": predicate.type_urn},
        )
    try:
        return evaluator(predicate, chain_session, commitment_list)
    except PredicateEvaluationError as exc:
        return _unsatisfied("malformed_predicate", {"detail": str(exc)})
    except Exception as exc:
        # Total fail-closed backstop: any error inside a profile evaluator,
        # including RecursionError from a deeply nested closure-language tree or
        # a malformed parameter payload, must surface as an unsatisfied result
        # rather than crash the evaluator or leak through as satisfaction. This
        # upholds the module contract that evaluation is total and never raises
        # out of evaluate_predicate.
        return _unsatisfied("malformed_predicate", {"detail": str(exc)})


def evaluate_bilateral_chain_closure_v1(
    predicate: EvaluablePredicate,
    chain_session: ChainSession,
    commitments: list[dict[str, Any]],
) -> PredicateResult:
    """Evaluate the bilateral chain-closure profile.

    Satisfied iff every committer is an expected participant, the aggregate
    committed quantity matches the required quantity within tolerance, the
    activation deadline has not lapsed, and (when required) every commitment
    carries a mandate proof. Any missing or malformed parameter fails closed.
    """
    params = predicate.parameters
    if not isinstance(params, dict):
        return _unsatisfied("malformed_parameters")

    expected_raw = params.get("expected_participants")
    if not isinstance(expected_raw, list) or not expected_raw:
        return _unsatisfied("malformed_expected_participants")
    expected = {str(did) for did in expected_raw}

    if "aggregate_quantity_required" not in params:
        return _unsatisfied("missing_aggregate_quantity_required")
    required_qty = params["aggregate_quantity_required"]
    if (
        not isinstance(required_qty, (int, float))
        or isinstance(required_qty, bool)
        or not math.isfinite(required_qty)
    ):
        return _unsatisfied("malformed_aggregate_quantity_required")

    tolerance = params.get("match_tolerance", 0.0)
    if (
        not isinstance(tolerance, (int, float))
        or isinstance(tolerance, bool)
        or not math.isfinite(tolerance)
    ):
        return _unsatisfied("malformed_match_tolerance")
    if tolerance < 0:
        return _unsatisfied("negative_match_tolerance")

    deadline_raw = params.get("activation_deadline_iso")
    try:
        deadline = _parse_iso_datetime(deadline_raw)
    except (TypeError, ValueError):
        return _unsatisfied("malformed_activation_deadline")

    mandate_check = bool(params.get("mandate_check_required", False))
    now = params.get("_now")
    try:
        now_dt = _parse_iso_datetime(now) if now is not None else datetime.now(timezone.utc)
    except (TypeError, ValueError):
        return _unsatisfied("malformed_now")

    if not commitments:
        return _unsatisfied("no_commitments")

    actual_participants: set[str] = set()
    for commitment in commitments:
        if not isinstance(commitment, dict):
            return _unsatisfied("malformed_commitment")
        did = commitment.get("committer_did")
        if not isinstance(did, str) or not did:
            return _unsatisfied("missing_committer_did")
        actual_participants.add(did)

    if not actual_participants.issubset(expected):
        return _unsatisfied(
            "unexpected_participant",
            {
                "actual": sorted(actual_participants),
                "expected": sorted(expected),
            },
        )

    total_qty = 0.0
    for commitment in commitments:
        terms = commitment.get("commitment_terms")
        if not isinstance(terms, dict):
            return _unsatisfied("malformed_commitment_terms")
        quantity = terms.get("quantity")
        if (
            not isinstance(quantity, (int, float))
            or isinstance(quantity, bool)
            or not math.isfinite(quantity)
        ):
            return _unsatisfied("non_numeric_quantity")
        total_qty += float(quantity)

    if abs(total_qty - float(required_qty)) > float(tolerance):
        return _unsatisfied(
            "aggregate_quantity_mismatch",
            {"actual": total_qty, "required": required_qty, "tolerance": tolerance},
        )

    if now_dt >= deadline:
        return _unsatisfied(
            "past_activation_deadline",
            {"now": now_dt.isoformat(), "deadline": deadline.isoformat()},
        )

    if mandate_check:
        for commitment in commitments:
            mandate_proof_id = commitment.get("mandate_proof_id")
            if not mandate_proof_id:
                return _unsatisfied(
                    "missing_mandate_proof",
                    {"commitment_id": commitment.get("commitment_id")},
                )

    return _satisfied(
        {
            "total_quantity": total_qty,
            "required_quantity": required_qty,
            "chain_session_id": chain_session.chain_session_id,
            "participants": sorted(actual_participants),
        }
    )


def evaluate_closure_language_v1(
    predicate: EvaluablePredicate,
    chain_session: ChainSession,
    commitments: list[dict[str, Any]],
) -> PredicateResult:
    """Evaluate a closure-language expression tree over the commitments.

    The tree lives under ``parameters.expression`` as a JSON object. Satisfied
    iff the root node evaluates truthy. A missing or malformed tree fails
    closed.
    """
    node = predicate.parameters.get("expression")
    if not isinstance(node, dict):
        return _unsatisfied("missing_expression")
    value = _evaluate_node(node, chain_session, commitments)
    if bool(value):
        return _satisfied({"value": value})
    return _unsatisfied("expression_not_satisfied", {"value": value})


def _evaluate_node(
    node: dict[str, Any],
    chain_session: ChainSession,
    commitments: list[dict[str, Any]],
) -> Any:
    op = node.get("op")
    if op == "and":
        return all(
            bool(_evaluate_node(_require_node(arg), chain_session, commitments))
            for arg in _require_args(node)
        )
    if op == "or":
        return any(
            bool(_evaluate_node(_require_node(arg), chain_session, commitments))
            for arg in _require_args(node)
        )
    if op == "not":
        return not bool(_evaluate_node(_require_node(node.get("arg")), chain_session, commitments))
    if op in _COMPARATORS:
        return _evaluate_comparison(node, chain_session, commitments)
    if op == "in":
        return _evaluate_membership(node, commitments)
    if op in ("before", "after"):
        return _evaluate_time(node, commitments)
    if op in ("sum", "min", "max", "count"):
        return _evaluate_aggregation(node, commitments)
    raise PredicateEvaluationError(f"unknown_op:{op}")


def _require_args(node: dict[str, Any]) -> list[Any]:
    args = node.get("args")
    if not isinstance(args, list) or not args:
        raise PredicateEvaluationError("missing_args")
    return args


def _require_node(candidate: Any) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        raise PredicateEvaluationError("malformed_node")
    return candidate


def _evaluate_comparison(
    node: dict[str, Any],
    chain_session: ChainSession,
    commitments: list[dict[str, Any]],
) -> bool:
    op = node["op"]
    comparator = _COMPARATORS[op]
    if "value" not in node:
        raise PredicateEvaluationError("missing_value")
    expected = node["value"]

    if "left" in node:
        actual = _evaluate_node(_require_node(node["left"]), chain_session, commitments)
        return bool(comparator(actual, expected))

    field_path = node.get("field")
    if not isinstance(field_path, str):
        raise PredicateEvaluationError("missing_field")
    if not commitments:
        raise PredicateEvaluationError("no_commitments_for_comparison")
    return all(
        bool(comparator(_finite_comparand(_get_field(commitment, field_path), field_path), expected))
        for commitment in commitments
    )


def _finite_comparand(value: Any, field_path: str) -> Any:
    """Reject a non-finite numeric comparand so comparisons fail closed.

    Non-numeric values pass through unchanged (string/set/time comparisons are
    handled by their own operators). A numeric value that is NaN or infinite is
    rejected: every ordering/inequality comparison against NaN returns False, so
    a cap guard written as not(field <op> bound) would otherwise invert to
    satisfied. json.loads accepts the bare NaN/Infinity/-Infinity tokens, so an
    attacker-controlled commitment can carry one; this guard mirrors the
    finiteness checks on the aggregation and bilateral quantity paths.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not math.isfinite(value):
        raise PredicateEvaluationError(f"non_finite_comparand:{field_path}")
    return value


def _evaluate_membership(node: dict[str, Any], commitments: list[dict[str, Any]]) -> bool:
    values = node.get("values")
    if not isinstance(values, list):
        raise PredicateEvaluationError("missing_values")
    accepted = set(values)
    field_path = node.get("field")
    if not isinstance(field_path, str):
        raise PredicateEvaluationError("missing_field")
    if not commitments:
        raise PredicateEvaluationError("no_commitments_for_membership")
    return all(_get_field(commitment, field_path) in accepted for commitment in commitments)


def _evaluate_time(node: dict[str, Any], commitments: list[dict[str, Any]]) -> bool:
    op = node["op"]
    if "value" not in node:
        raise PredicateEvaluationError("missing_value")
    expected = _parse_iso_datetime(node["value"])
    field_path = node.get("field")
    if not isinstance(field_path, str):
        raise PredicateEvaluationError("missing_field")
    if not commitments:
        raise PredicateEvaluationError("no_commitments_for_time")
    if op == "before":
        return all(
            _parse_iso_datetime(_get_field(c, field_path)) < expected for c in commitments
        )
    return all(_parse_iso_datetime(_get_field(c, field_path)) > expected for c in commitments)


def _evaluate_aggregation(node: dict[str, Any], commitments: list[dict[str, Any]]) -> float:
    op = node["op"]
    if op == "count":
        return float(len(commitments))

    field_path = node.get("field")
    if not isinstance(field_path, str):
        raise PredicateEvaluationError("missing_field")
    numeric_values: list[float] = []
    for commitment in commitments:
        value = _get_field(commitment, field_path)
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
        ):
            raise PredicateEvaluationError(f"non_numeric_aggregand:{field_path}")
        numeric_values.append(float(value))

    if op == "sum":
        return float(sum(numeric_values))
    if not numeric_values:
        raise PredicateEvaluationError(f"empty_aggregation:{op}")
    if op == "min":
        return float(min(numeric_values))
    return float(max(numeric_values))


def _get_field(commitment: dict[str, Any], field_path: str) -> Any:
    current: Any = commitment
    for segment in field_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            raise PredicateEvaluationError(f"missing_field:{field_path}")
        current = current[segment]
    return current


def _parse_iso_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise TypeError(f"expected ISO 8601 datetime string, got {type(value).__name__}")
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


_ProfileEvaluator = Callable[
    [EvaluablePredicate, ChainSession, list[dict[str, Any]]], PredicateResult
]

_PROFILES: dict[str, _ProfileEvaluator] = {
    BILATERAL_CHAIN_CLOSURE_V1: evaluate_bilateral_chain_closure_v1,
    CLOSURE_LANGUAGE_V1: evaluate_closure_language_v1,
}
