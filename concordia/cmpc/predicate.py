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


_ORDERING_OPS = frozenset((">", ">=", "<", "<="))


def _evaluate_comparison(
    node: dict[str, Any],
    chain_session: ChainSession,
    commitments: list[dict[str, Any]],
) -> bool:
    op = node["op"]
    comparator = _COMPARATORS[op]
    if "value" not in node:
        raise PredicateEvaluationError("missing_value")
    # Resolve the EXPECTED literal to a discriminated typed value through the one
    # chokepoint. This rejects a non-finite numeric literal (json.loads accepts
    # bare NaN/Infinity/-Infinity tokens) and anything that is not a recognised
    # comparand type (finite non-bool number, str, or datetime), so both sides of
    # the comparison pass through identical type discipline and fail closed.
    expected = _typed_comparand(node["value"], "value")

    if "left" in node:
        # The `left` value is an aggregation result (always a finite float). It
        # meets the expected literal through the SAME typed chokepoint as a
        # resolved commitment field, so a malformed non-numeric expected literal
        # cannot fail open: operator.eq(1.0, "two") is False, so not(count ==
        # "two") would otherwise invert to satisfied on a cross-type comparison.
        actual = _typed_comparand(
            _evaluate_node(_require_node(node["left"]), chain_session, commitments),
            "left",
        )
        return _typed_compare(op, comparator, actual, expected, "left")

    field_path = node.get("field")
    if not isinstance(field_path, str):
        raise PredicateEvaluationError("missing_field")
    if not commitments:
        raise PredicateEvaluationError("no_commitments_for_comparison")
    # Materialize EVERY comparand before applying the truth test. Folding the
    # resolution into the all(...) generator would let all()'s short-circuit on
    # the first legitimately-False comparator skip resolution on every later
    # commitment, so a malformed comparand in a non-first commitment would evade
    # the typed chokepoint. Resolve all comparands first (each through _get_field,
    # the single field-resolution chokepoint, which discriminates the value's
    # type), then run the typed comparison over the materialized list.
    comparands = [_get_field(commitment, field_path) for commitment in commitments]
    return all(
        _typed_compare(op, comparator, comparand, expected, field_path)
        for comparand in comparands
    )


@dataclass(frozen=True)
class _TypedComparand:
    """A commitment/literal value discriminated into a comparison type-class.

    ``type_class`` is one of ``"number"``, ``"str"``, or ``"datetime"``; ``value``
    is the underlying comparand. Two typed comparands are equal iff BOTH their
    type-class and value are equal, which is exactly the cross-type-strict,
    bool-de-aliased semantics the closure language requires: ``True`` (rejected
    outright, never a comparand) can never reach a ``number`` key, ``"60"`` and
    ``60`` land in different classes so they never match, and ``60`` and ``60.0``
    share the ``number`` class and value so they do match.
    """

    type_class: str
    value: Any

    def key(self) -> tuple[str, Any]:
        return (self.type_class, self.value)


def _typed_comparand(raw: Any, field_path: str) -> _TypedComparand:
    """Resolve a raw value to a discriminated typed comparand or fail closed.

    THE strict chokepoint for every comparand in the closure language (both sides
    of a comparison, every membership literal, and every resolved commitment
    field). A value is accepted only if it is exactly one of:

    * a finite ``int``/``float`` that is NOT a ``bool`` -> ``number``;
    * a ``str`` -> ``str``;
    * a ``datetime`` -> ``datetime``.

    Everything else fails closed with ``PredicateEvaluationError``. This single
    boundary closes three fail-open classes at once:

    * finiteness: NaN / Infinity / -Infinity (json.loads accepts the bare tokens)
      are rejected, so a cap ``not(field <op> bound)`` or blocklist
      ``not(field in {...})`` cannot invert to satisfied;
    * type-strictness: a wrong-type scalar (a string ``"60"`` where a number is
      declared, or vice versa) never silently compares via Python's lexicographic
      or cross-type equality, because comparands only ever match on
      ``(type_class, value)`` keys and ordering requires both sides ``number``;
    * bool-aliasing: ``bool`` is not a ``number`` (nor any accepted class), so
      ``True`` is rejected outright and can never alias to the numeric ``1``
      (``True == 1`` and ``True in {1}`` are both True in raw Python).
    """
    if isinstance(raw, bool):
        raise PredicateEvaluationError(f"boolean_comparand:{field_path}")
    if isinstance(raw, (int, float)):
        if not math.isfinite(raw):
            raise PredicateEvaluationError(f"non_finite_comparand:{field_path}")
        return _TypedComparand("number", raw)
    if isinstance(raw, str):
        return _TypedComparand("str", raw)
    if isinstance(raw, datetime):
        return _TypedComparand("datetime", raw)
    raise PredicateEvaluationError(f"unsupported_comparand_type:{field_path}:{type(raw).__name__}")


def _typed_compare(
    op: str,
    comparator: Callable[[Any, Any], bool],
    actual: _TypedComparand,
    expected: _TypedComparand,
    field_path: str,
) -> bool:
    """Apply a comparison operator over two typed comparands, fail-closed.

    Ordering operators (>, >=, <, <=) require BOTH operands to be ``number``:
    lexicographic string ordering ("60" > "100") and any cross-type ordering are
    rejected rather than silently evaluated, so a wrong-type commitment value can
    never reach operator.gt/ge/lt/le.

    Equality operators (==, !=) require BOTH operands to share a type-class. A
    cross-type pairing is a malformed predicate, not a validly-unequal one: a
    predicate author who writes ``count == "two"`` or ``field != None`` made a
    type error, and returning ``!=`` -> True for it would let a cap written as
    ``not(count == "two")`` or a guard written as ``field != None`` invert to
    satisfied by cross-type inequality. Rejecting the mismatched pairing fails
    closed; a same-class pairing then compares on value so "60" never equals 60
    and 60 equals 60.0.
    """
    if op in _ORDERING_OPS:
        if actual.type_class != "number" or expected.type_class != "number":
            raise PredicateEvaluationError(
                f"non_numeric_ordering:{field_path}:{actual.type_class}<{op}>{expected.type_class}"
            )
        return bool(comparator(actual.value, expected.value))
    if actual.type_class != expected.type_class:
        raise PredicateEvaluationError(
            f"cross_type_equality:{field_path}:{actual.type_class}{op}{expected.type_class}"
        )
    return bool(comparator(actual.value, expected.value))


def _evaluate_membership(node: dict[str, Any], commitments: list[dict[str, Any]]) -> bool:
    values = node.get("values")
    if not isinstance(values, list):
        raise PredicateEvaluationError("missing_values")
    # Resolve every membership LITERAL through the strict typed chokepoint, then
    # key the accepted set on the discriminated (type_class, value) keys. Raw
    # set(values) semantics reintroduce Python's numeric/bool aliasing: with a
    # declared set [1, False], set([1, False]) keeps 1 and False as distinct
    # members, but a field True still matches member 1 because True == 1, and a
    # field "60" cannot be excluded from a numeric set by type. Keying on the
    # typed comparand closes both: the literal set and the resolved field are
    # compared on identical (type_class, value) keys.
    typed_literals = [_typed_comparand(reference, "values") for reference in values]
    if not typed_literals:
        raise PredicateEvaluationError("missing_values")
    accepted = {literal.key() for literal in typed_literals}
    accepted_classes = {literal.type_class for literal in typed_literals}
    field_path = node.get("field")
    if not isinstance(field_path, str):
        raise PredicateEvaluationError("missing_field")
    if not commitments:
        raise PredicateEvaluationError("no_commitments_for_membership")
    # Resolve the field on EVERY commitment before applying the membership test.
    # Folding _get_field into the all(...) generator would let the short-circuit
    # on a first not-in-set commitment skip field resolution on later
    # commitments, so a later commitment with a missing / non-finite / wrong-type
    # field would evade the fail-closed PredicateEvaluationError _get_field
    # raises. _get_field routes through the same typed chokepoint, so the field
    # is discriminated identically to the literals before the keyed set lookup: a
    # boolean True is rejected outright (never aliases to member 1) and a NaN
    # field is rejected (never a member of any set).
    field_comparands = [_get_field(commitment, field_path) for commitment in commitments]
    for comparand in field_comparands:
        # A field whose type-class matches NONE of the declared literal classes is
        # a malformed pairing, not a validly-absent member: a string field against
        # a numeric-only value set (or vice versa) must fail closed, mirroring the
        # cross-type equality rule, so a blocklist `not(field in {...})` cannot
        # invert to satisfied merely because the field is the wrong type to ever
        # match.
        if comparand.type_class not in accepted_classes:
            raise PredicateEvaluationError(
                f"cross_type_membership:{field_path}:"
                f"{comparand.type_class}!={sorted(accepted_classes)}"
            )
    return all(comparand.key() in accepted for comparand in field_comparands)


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
    actual_times = [_parse_iso_datetime(_resolve_field(c, field_path)) for c in commitments]
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
        # Route the aggregand through the SAME strict typed chokepoint as every
        # other comparand, then require the discriminated class be `number`. This
        # rejects a bool (True is not a number), a NaN/Infinity, a string, and any
        # non-scalar in one place, keeping the aggregation operand under identical
        # type discipline to comparison and membership.
        typed = _typed_comparand(_resolve_field(commitment, field_path), field_path)
        if typed.type_class != "number":
            raise PredicateEvaluationError(f"non_numeric_aggregand:{field_path}")
        numeric_values.append(float(typed.value))

    if op == "sum":
        return float(sum(numeric_values))
    if not numeric_values:
        raise PredicateEvaluationError(f"empty_aggregation:{op}")
    if op == "min":
        return float(min(numeric_values))
    return float(max(numeric_values))


def _resolve_field(commitment: dict[str, Any], field_path: str) -> Any:
    """Walk a dotted field path to its raw value or fail closed on a miss.

    Resolution ONLY: every consumer that needs a discriminated, type-checked
    comparand wraps this in :func:`_typed_comparand` (comparison, membership `in`
    -> :func:`_get_field`); aggregation applies its own numeric-non-bool check and
    before/after parses the raw value as a datetime. Keeping the walk separate
    from the typed guard lets each operator apply exactly the type discipline it
    requires while sharing one path-resolution + missing-field chokepoint.
    """
    current: Any = commitment
    for segment in field_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            raise PredicateEvaluationError(f"missing_field:{field_path}")
        current = current[segment]
    return current


def _get_field(commitment: dict[str, Any], field_path: str) -> _TypedComparand:
    """Resolve a commitment field to a strict, discriminated typed comparand.

    THE single field-resolution chokepoint for the comparison and membership
    operators: it walks the dotted path and then routes the raw value through
    :func:`_typed_comparand`, so every comparand a comparison or membership test
    sees is a finite non-bool number, a str, or a datetime, keyed by type-class.
    A NaN / Infinity field, a boolean field (which would alias to numeric 1), and
    any unsupported-type field all fail closed here on every path.
    """
    return _typed_comparand(_resolve_field(commitment, field_path), field_path)


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
