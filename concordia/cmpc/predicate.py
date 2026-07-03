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

Fail-closed contract: evaluation is total. A malformed predicate object, an
unknown predicate type, an unknown operator, a malformed node, a missing field,
a non-numeric aggregand, an unparsable timestamp, an EMPTY commitment list at an
aggregation/comparison/membership/time boundary, or otherwise malformed input
yields ``unsatisfied`` with a machine-readable reason. It NEVER defaults to
``satisfied`` and NEVER raises out of :func:`evaluate_predicate`. Satisfaction
requires every declared check to pass explicitly over at least one commitment.
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

    # NOTE (security, fail-closed): there is deliberately NO adapter from a
    # signed :class:`concordia.cmpc.types.ClosurePredicate` to this evaluable
    # view. A prior ``from_closure_predicate`` classmethod copied a signed
    # primitive's ``condition``/``type`` into trusted policy WITHOUT verifying
    # its signature, status, expiry, or revocation, so a primitive carrying a
    # dummy or expired signature evaluated as satisfied. Constructing an
    # EvaluablePredicate is an assertion that the parameters are already
    # trusted; an unverified signed primitive must first pass a real
    # signature + status + expiry + revocation check (which requires the
    # issuer public key and the revocation store, neither of which this module
    # holds) before its parameters may be trusted here.


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
    try:
        # Read the type URN INSIDE the guarded path. A malformed predicate
        # object (no type_urn attribute) or a non-string / unhashable type URN
        # must resolve to unsatisfied, not raise out of evaluate_predicate. The
        # dict lookup below would raise TypeError on an unhashable key, so the
        # string check is a precondition, not a nicety.
        type_urn = getattr(predicate, "type_urn", None)
        if not isinstance(type_urn, str):
            return _unsatisfied("malformed_predicate", {"detail": "type_urn_not_a_string"})
        evaluator = _PROFILES.get(type_urn)
        if evaluator is None:
            return _unsatisfied(
                "unknown_predicate_type",
                {"type_urn": type_urn},
            )
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
    # Require every expected participant to be a non-empty string WITHOUT
    # coercion. str(did) would have silently turned a malformed entry (an int
    # 123, None, a dict) into a string DID, letting a commitment whose
    # committer_did happens to stringify-match (committer_did="123" against
    # expected_participants=[123]) satisfy the exact-set participant check on a
    # malformed parameter payload. A malformed participant list must fail closed.
    if any(not isinstance(did, str) or not did for did in expected_raw):
        return _unsatisfied("malformed_expected_participants")
    expected = set(expected_raw)

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

    # mandate_check_required must be absent or an ACTUAL bool. bool(...) coercion
    # would have read a malformed payload's mandate_check_required="" (or 0, or
    # None) as False and skipped the mandate check entirely, letting a deal with
    # missing mandate proofs close despite a malformed parameter. A present
    # non-bool value fails closed.
    mandate_check_raw = params.get("mandate_check_required", False)
    if not isinstance(mandate_check_raw, bool):
        return _unsatisfied("malformed_mandate_check_required")
    mandate_check = mandate_check_raw
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
        # Reject a duplicate committer up front. A second commitment from an
        # already-committed participant, paired with another expected
        # participant being absent, could otherwise let a partial set reach the
        # expected quantity and close. One commitment per expected participant.
        if did in actual_participants:
            return _unsatisfied(
                "duplicate_participant_commitment",
                {"committer_did": did},
            )
        actual_participants.add(did)

    # Require EVERY expected participant to be present (exact set match), not
    # merely a subset. A subset check let a partial commitment set close without
    # every bilateral participant having committed.
    if actual_participants != expected:
        missing = sorted(expected - actual_participants)
        unexpected = sorted(actual_participants - expected)
        if unexpected:
            return _unsatisfied(
                "unexpected_participant",
                {
                    "actual": sorted(actual_participants),
                    "expected": sorted(expected),
                },
            )
        return _unsatisfied(
            "missing_expected_participant",
            {
                "missing": missing,
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
    # The root is a boolean position: it must evaluate to a declared boolean
    # check, not a numeric aggregation coerced by truthiness. _evaluate_boolean
    # is the single chokepoint that rejects a non-boolean node in any boolean
    # position (root, and/or/not).
    value = _evaluate_boolean(node, chain_session, commitments)
    if value:
        return _satisfied({"value": value})
    return _unsatisfied("expression_not_satisfied", {"value": value})


def _evaluate_node(
    node: dict[str, Any],
    chain_session: ChainSession,
    commitments: list[dict[str, Any]],
) -> Any:
    op = node.get("op")
    if op == "and":
        # Materialize EVERY child result before applying truth semantics. all()'s
        # short-circuit on the first False child would otherwise skip evaluation
        # of later children, so a malformed later branch (which raises
        # PredicateEvaluationError) would be silently skipped and the AND could
        # report the tree satisfied on a malformed expression. Evaluating every
        # branch first makes any branch's failure fail closed. Each child is a
        # boolean position, so _evaluate_boolean rejects a non-boolean child
        # (bare aggregation) rather than coercing it by truthiness.
        child_values = [
            _evaluate_boolean(_require_node(arg), chain_session, commitments)
            for arg in _require_args(node)
        ]
        return all(child_values)
    if op == "or":
        # Materialize EVERY child result before applying truth semantics. any()'s
        # short-circuit on the first True child would otherwise skip evaluation
        # of later children, so a true-then-malformed OR (a valid true branch
        # followed by a malformed branch that raises PredicateEvaluationError)
        # would report the tree satisfied instead of failing closed. Evaluating
        # every branch first makes any branch's failure fail closed. Each child
        # is a boolean position (see the and branch).
        child_values = [
            _evaluate_boolean(_require_node(arg), chain_session, commitments)
            for arg in _require_args(node)
        ]
        return any(child_values)
    if op == "not":
        # not's operand is a boolean position: reject a non-boolean node (bare
        # aggregation) rather than inverting its numeric truthiness, so
        # not(sum-nets-to-zero) fails closed instead of reporting satisfied.
        return not _evaluate_boolean(_require_node(node.get("arg")), chain_session, commitments)
    if op in _COMPARATORS:
        return _evaluate_comparison(node, chain_session, commitments)
    if op == "in":
        return _evaluate_membership(node, commitments)
    if op in ("before", "after"):
        return _evaluate_time(node, commitments)
    if op in ("sum", "min", "max", "count"):
        return _evaluate_aggregation(node, commitments)
    raise PredicateEvaluationError(f"unknown_op:{op}")


def _evaluate_boolean(
    node: dict[str, Any],
    chain_session: ChainSession,
    commitments: list[dict[str, Any]],
) -> bool:
    """Evaluate a node that sits in a boolean position and require a bool result.

    Single chokepoint for every boolean position in the tree (the root and the
    operands of and/or/not). A boolean position must resolve to a declared
    boolean check (comparison, membership, time, or a boolean composition), not
    to a numeric aggregation (sum/min/max/count) coerced by truthiness. Coercing
    an aggregation with bool() contradicts the fail-closed contract: a bare
    ``count`` root reports satisfied on any non-zero count, and
    ``not(sum-of-quantities)`` reports satisfied whenever the quantities net to
    zero. Rejecting a non-boolean node here closes that class at one boundary for
    every boolean position rather than per-site.
    """
    value = _evaluate_node(node, chain_session, commitments)
    if not isinstance(value, bool):
        raise PredicateEvaluationError(f"non_boolean_in_boolean_position:{node.get('op')}")
    return value


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
    # Reject a non-finite EXPECTED literal (NaN / Infinity / -Infinity) before
    # comparing. json.loads accepts the bare NaN/Infinity/-Infinity tokens, so a
    # predicate can carry one as its `value`. Every ordering/equality comparison
    # against NaN returns False, so a cap guard written as not(field <op> NaN)
    # would otherwise invert to satisfied. This mirrors the comparand-side
    # finiteness guard so both sides of the comparison fail closed.
    expected = _finite_comparand(node["value"], "value")

    if "left" in node:
        # The `left` value (an aggregation result, always a finite float) meets
        # the expected literal through the SAME type/finiteness chokepoint as a
        # resolved commitment field, keyed on the expected literal. Without the
        # type-class match, a malformed non-numeric expected literal fails open:
        # operator.eq(1.0, "two") is False, so not(count == "two") would invert
        # to satisfied on a cross-type comparison. Keying the guard on
        # [expected] rejects a number-vs-str (or any mismatched-class) pairing
        # before the comparator runs, so the whole comparison fails closed.
        actual = _guard_field_scalar(
            _evaluate_node(_require_node(node["left"]), chain_session, commitments),
            [expected],
            "left",
        )
        return bool(comparator(actual, expected))

    field_path = node.get("field")
    if not isinstance(field_path, str):
        raise PredicateEvaluationError("missing_field")
    if not commitments:
        raise PredicateEvaluationError("no_commitments_for_comparison")
    # Materialize EVERY comparand before applying the truth test. Folding the
    # resolution into the all(...) generator would let all()'s short-circuit on
    # the first legitimately-False comparator skip resolution on every later
    # commitment, so a malformed comparand in a non-first commitment would evade
    # the type/finiteness guard. Resolve all comparands first (the guard is
    # applied inside _get_field, the single field-resolution chokepoint, keyed on
    # the expected literal so a type-mismatched commitment field fails closed),
    # then run the comparison over the materialized list.
    comparands = [
        _get_field(commitment, field_path, expected=[expected]) for commitment in commitments
    ]
    return all(bool(comparator(comparand, expected)) for comparand in comparands)


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


def _scalar_type_class(value: Any) -> str:
    """Classify a scalar into a comparison type-class.

    ``bool`` is deliberately its OWN class, distinct from ``number``, so a
    commitment field ``True`` never aliases to the numeric literal ``1`` (in
    Python ``True == 1`` and ``True in {1}``). ``int``/``float`` collapse into
    one ``number`` class so ``60`` and ``60.0`` compare equal. Everything else
    that is not a recognised scalar is keyed by its concrete Python type name
    (``other:NoneType``, ``other:dict``, ``other:list``, ...) so it can only
    type-match another value of the SAME Python type. Collapsing every
    non-scalar into a single ``other`` class would let a dict field type-match a
    ``None`` / ``list`` / ``dict`` literal of a different type, re-opening the
    wrong-type fail-open: ``operator.ne({"nested": 1}, None)`` is True, so a
    ``field != None`` guard would be satisfied by an arbitrary structured field.
    """
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "str"
    return f"other:{type(value).__name__}"


def _guard_field_scalar(value: Any, expected: list[Any] | None, field_path: str) -> Any:
    """Single type/finiteness guard for a resolved commitment field value.

    This is the one boundary every operator's field resolution passes through
    (comparison, membership ``in``, aggregation, before/after), so a malformed
    commitment field fails closed once here instead of per operator.

    Two classes are closed:

    * Non-finite numbers (NaN / Infinity / -Infinity, which json.loads accepts
      as bare tokens) are rejected outright. Every ordering/inequality
      comparison against NaN is False and NaN is not a member of any set, so a
      cap ``not(field <op> bound)`` or blocklist ``not(field in {...})`` would
      otherwise invert to satisfied.
    * A field whose scalar type-class does not match ANY expected literal is
      rejected. Without this, a string field ``"sixty"`` satisfies
      ``quantity != 0`` (``operator.ne("sixty", 0)`` is True) and a boolean
      field ``True`` satisfies ``quantity in [1]`` (``True in {1}`` is True) by
      Python cross-type equality / numeric aliasing. ``bool`` is its own class
      so it never aliases to ``number``.

    ``expected`` is the operator's reference literal(s): the comparison ``value``
    or the membership ``values``. When ``expected`` is ``None`` (an aggregation,
    where the numeric requirement is enforced by the caller) only the finiteness
    guard applies.
    """
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            raise PredicateEvaluationError(f"non_finite_comparand:{field_path}")
    if not expected:
        return value
    value_class = _scalar_type_class(value)
    expected_classes = {_scalar_type_class(ref) for ref in expected}
    if value_class not in expected_classes:
        raise PredicateEvaluationError(
            f"type_mismatch:{field_path}:{value_class}!={sorted(expected_classes)}"
        )
    return value


def _evaluate_membership(node: dict[str, Any], commitments: list[dict[str, Any]]) -> bool:
    values = node.get("values")
    if not isinstance(values, list):
        raise PredicateEvaluationError("missing_values")
    # Reject a non-finite membership LITERAL (NaN / Infinity / -Infinity, which
    # json.loads accepts as bare tokens) before building the accepted set. A NaN
    # left in the set is never a member of itself, so a blocklist written as
    # not(field in {..., NaN}) would leave the NaN inert and invert to satisfied
    # on a finite field. This mirrors the comparison-side literal guard so both
    # the comparison `value` and the membership `values` literals fail closed.
    for reference in values:
        _finite_comparand(reference, "values")
    accepted = set(values)
    field_path = node.get("field")
    if not isinstance(field_path, str):
        raise PredicateEvaluationError("missing_field")
    if not commitments:
        raise PredicateEvaluationError("no_commitments_for_membership")
    # Resolve the field on EVERY commitment before applying the membership
    # test. Folding _get_field into the all(...) generator would let the
    # short-circuit on a first not-in-set commitment skip field resolution on
    # later commitments, so a later commitment with a missing / non-finite /
    # type-mismatched field would evade the fail-closed PredicateEvaluationError
    # _get_field raises. _get_field is the single field-resolution chokepoint,
    # keyed here on the declared membership set: a NaN / Infinity field is
    # rejected (NaN is not a member of any set, so not(field in {...}) would
    # otherwise invert to satisfied) and a type-mismatched field is rejected
    # before the set lookup (a boolean True must not alias to the numeric member
    # 1, since True in {1} is True in Python). This closes the same class the
    # comparison, aggregation, and before/after paths close.
    field_values = [
        _get_field(commitment, field_path, expected=values) for commitment in commitments
    ]
    return all(value in accepted for value in field_values)


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
    # Parse EVERY commitment's timestamp before applying the time test. Folding
    # the parse into the all(...) generator would let the short-circuit on a
    # first time-not-before/after commitment skip parsing on later commitments,
    # so a later commitment with a missing or unparsable timestamp would evade
    # the fail-closed error _parse_iso_datetime / _get_field raise.
    actual_times = [_parse_iso_datetime(_get_field(c, field_path)) for c in commitments]
    if op == "before":
        return all(actual < expected for actual in actual_times)
    return all(actual > expected for actual in actual_times)


def _evaluate_aggregation(node: dict[str, Any], commitments: list[dict[str, Any]]) -> float:
    op = node["op"]
    # Fail closed on an empty commitment list. count()==0 or sum()==0 over zero
    # commitments would otherwise let a closure expression report a deal closed
    # against no commitments at all. Aggregation over an empty chain is
    # meaningless in the closure context, so every aggregation op requires at
    # least one commitment. (min/max already reject emptiness below; this makes
    # count and sum consistent and closes the empty-list satisfaction hole.)
    if not commitments:
        raise PredicateEvaluationError(f"empty_commitments_for_aggregation:{op}")
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


def _get_field(
    commitment: dict[str, Any], field_path: str, expected: list[Any] | None = None
) -> Any:
    current: Any = commitment
    for segment in field_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            raise PredicateEvaluationError(f"missing_field:{field_path}")
        current = current[segment]
    # Single chokepoint for commitment field-value resolution: every consumer
    # (comparison, membership `in`, aggregation, before/after) reads its
    # comparand through here, so applying one type/finiteness guard at this one
    # boundary makes the whole class fail closed instead of patching each
    # operator. A NaN / Infinity / -Infinity numeric field (json.loads accepts
    # the bare tokens, so an attacker-controlled commitment can carry one) is
    # rejected on every path: NaN is not a member of any value set and every
    # ordering / inequality comparison against NaN returns False, so a blocklist
    # written as not(field in {...}) or a cap written as not(field <op> bound)
    # would otherwise invert to satisfied. When the caller passes the operator's
    # reference literal(s) (`expected`), a field whose scalar type-class does not
    # match any reference is also rejected here, so a string field cannot satisfy
    # a numeric != by Python cross-type inequality and a boolean field cannot
    # satisfy numeric membership by True-aliases-1. Booleans stay their own class
    # and pass through unchanged only where a boolean reference is expected.
    return _guard_field_scalar(current, expected, field_path)


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
