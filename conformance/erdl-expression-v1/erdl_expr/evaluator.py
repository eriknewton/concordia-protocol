"""The ERDL 34-node expression kernel.

Implemented from the ERDL v2.1 specification (sections 5.2, 5.3, 7.0, 7.2, 7.3)
and the expression-runner contract (ER1 to ER9). No ERDL engine, verifier
script, or answer file was consulted; see the package README for the recorded
independence boundary.

Two structural decisions govern the whole file and are stated once here rather
than repeated at every node:

* **Errors fold once, at the top.** A node that cannot evaluate raises
  `EvalError`. `evaluate_tree` catches it and folds the whole result to false
  per E12 (tier 3 to 5). Folding at the erroring node instead would make
  `not(<error>)` come out true, the fail-open shape section 5.2 warns about.
* **A missing field is not an error.** E11 collapses it to false at a predicate
  leaf with no warning. Arithmetic, time and aggregate nodes are the stated
  exceptions: section 7.3(a) calls arithmetic on a missing field an evaluation
  error, and section 7.3(e) calls a missing aggregate `over` a type mismatch.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from decimal import Decimal
from fractions import Fraction
from typing import Any, Final

from . import times
from .errors import (
    ARITY,
    DIVISION_BY_ZERO,
    NOT_AN_ARRAY,
    RESOURCE_LIMIT,
    SAFE_FOLD_EMPTY,
    SCHEMA_VIOLATION,
    TYPE_MISMATCH,
    UNKNOWN_NODE,
    EvalError,
)
from .limits import MAX_REGEX_SUBJECT, check_array_bound, check_regex_safety, check_tree
from .values import (
    ROUND_HALF_EVEN,
    UNDEFINED,
    Undefined,
    Value,
    is_number,
    nfc,
    round_to_int,
    to_fraction,
)

COMPARISON_OPS: Final[frozenset[str]] = frozenset({"eq", "ne", "gt", "gte", "lt", "lte"})
STRING_OPS: Final[frozenset[str]] = frozenset({"contains", "match", "starts_with", "ends_with"})
QUANTIFIERS: Final[frozenset[str]] = frozenset({"all", "any", "none"})
AGGREGATES: Final[frozenset[str]] = frozenset({"count", "sum", "avg", "min", "max"})
ARITHMETIC_BINARY: Final[frozenset[str]] = frozenset({"add", "sub", "mul", "div"})


@dataclass(frozen=True)
class Semantics:
    """Switchable semantics, defaulted to the specification's mandate.

    Every field defaults to what ERDL requires. The alternatives exist so the
    test suite can plant a wrong semantics and demonstrate that the E2, E8 and
    E11 sentinels catch it; a guard that has never been shown to fail is not
    evidence that it works. Nothing in the shipped path or the CLI selects a
    non-default value, and `evaluate_corpus` asserts the defaults before it
    writes a submission.
    """

    #: E2 mandates half-even at the reporting scale.
    rounding: str = ROUND_HALF_EVEN
    #: E8 mandates that all/any/none over an empty array fold to false.
    empty_quantifier_folds_false: bool = True
    #: E11 mandates that a missing field collapses to false at a leaf rather
    #: than propagating a third truth value.
    leaf_collapse: bool = True


DEFAULT_SEMANTICS: Final[Semantics] = Semantics()


def _wrap(raw: Any) -> Value:
    """Lift a JSON-parsed fact value into the kernel value domain."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, float):
        raise EvalError(TYPE_MISMATCH, "binary float is not an ERDL fact value")
    if isinstance(raw, (int, Decimal, Fraction)):
        return to_fraction(raw)
    if isinstance(raw, str):
        return nfc(raw)
    if isinstance(raw, list):
        # The chokepoint for the E4 array ceiling on fact-borne arrays: every
        # array in the fact passes through here on its way into the value
        # domain, nested ones included, so the ceiling is enforced once rather
        # than at each of the four sites that later consume an array. Those
        # sites keep their own check because a list can also be produced by the
        # tree itself, which never reaches this function.
        check_array_bound(len(raw), "fact")
        return [_wrap(item) for item in raw]
    if isinstance(raw, dict):
        # Fact keys are NFC-normalized on the way in so a decomposed key in the
        # fact object and a precomposed path segment in the tree still meet.
        return {nfc(str(key)): _wrap(value) for key, value in raw.items()}
    if raw is None:
        return None
    raise EvalError(TYPE_MISMATCH, f"unsupported fact value: {type(raw).__name__}")


def _same_kind(left: Value, right: Value) -> bool:
    """True when two present values are comparable without conversion.

    ERDL forbids implicit conversion, so `"100"` and `100` are not comparable
    and `false` and `0` are not comparable.
    """
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool)
    if is_number(left) or is_number(right):
        return is_number(left) and is_number(right)
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str)
    if isinstance(left, list) or isinstance(right, list):
        return isinstance(left, list) and isinstance(right, list)
    return False


def _equal(left: Value, right: Value) -> bool:
    """Strict same-kind equality, used by `eq`, `ne` and `in` membership."""
    if not _same_kind(left, right):
        return False
    return bool(left == right)


@dataclass
class Evaluator:
    """Evaluates one expression tree against one fact object."""

    fact: dict[str, Any]
    semantics: Semantics = DEFAULT_SEMANTICS
    bindings: dict[str, Value] = field(default_factory=dict)
    #: Non-error records the audit trail carries. Section 7.3(b) requires the
    #: empty-array quantifier fold to be recorded, and a fold that leaves no
    #: trace is indistinguishable from a predicate that genuinely came out
    #: false. The list is SHARED with the per-item evaluators a quantifier
    #: builds, so a fold inside a nested evaluation still reaches the outcome.
    notes: list[str] = field(default_factory=list)

    def _record(self, code: str) -> None:
        """Record a non-error fold once per evaluation."""
        if code not in self.notes:
            self.notes.append(code)

    # -- entry ------------------------------------------------------------

    def evaluate(self, node: Any) -> Value:
        if isinstance(node, dict):
            return self._dispatch(node)
        if isinstance(node, list):
            # A list in an operand position is an array literal; its members are
            # themselves nodes, so a literal array of objects still evaluates.
            return [self.evaluate(item) for item in node]
        if isinstance(node, bool):
            return node
        if isinstance(node, float):
            # E2 puts the kernel on exact decimals. A binary float has already
            # lost the literal it came from, so accepting one here would let an
            # inexact value in through a side door that the JSON loader is
            # careful to keep shut.
            raise EvalError(TYPE_MISMATCH, "binary float is not an ERDL literal")
        if isinstance(node, (int, Decimal, Fraction)):
            return to_fraction(node)
        if isinstance(node, str):
            return nfc(node)
        if node is None:
            return None
        raise EvalError(UNKNOWN_NODE, f"unsupported literal: {type(node).__name__}")

    # -- dispatch ---------------------------------------------------------

    def _dispatch(self, node: dict[str, Any]) -> Value:
        keys = set(node)
        if "expr" in keys:
            # E5: `expr` and the Simple triple must not coexist.
            if keys & {"field", "operator", "value"}:
                raise EvalError(SCHEMA_VIOLATION, "expr coexists with field/operator/value")
            return self.evaluate(node["expr"])
        if "operator" in keys:
            # A Simple condition, not a bare field node. Compiling it here keeps
            # E7 true: one evaluation core, reached by both projections.
            from .simple import compile_simple

            return self.evaluate(compile_simple(node))
        if "field" in keys:
            return self._field(node["field"])
        if "var" in keys:
            return self._var(node["var"])
        if len(keys) != 1:
            raise EvalError(UNKNOWN_NODE, f"ambiguous node keys: {sorted(keys)}")
        (name,) = keys
        payload = node[name]
        if name == "and":
            return self._and(payload)
        if name == "or":
            return self._or(payload)
        if name == "not":
            return not self._boolean(self.evaluate(payload))
        if name in COMPARISON_OPS:
            return self._compare(name, payload)
        if name == "in":
            return self._in(payload)
        if name in STRING_OPS:
            return self._string(name, payload)
        if name == "exists":
            return self._exists(payload)
        if name == "length":
            return self._length(payload)
        if name == "between":
            return self._between(payload)
        if name in QUANTIFIERS:
            return self._quantifier(name, payload)
        if name in ARITHMETIC_BINARY:
            return self._arithmetic(name, payload)
        if name == "round":
            return self._round(payload)
        if name == "days_between":
            return self._days_between(payload)
        if name == "epoch_ms":
            return Fraction(times.epoch_ms(self._moment(payload)))
        if name == "date_add":
            return self._date_add(payload)
        if name == "date_part":
            return self._date_part(payload)
        if name == "month_last_day":
            return times.to_iso(times.month_last_day(self._moment(payload)))
        if name in AGGREGATES:
            return self._aggregate(name, payload)
        if name == "aggregate":
            return self._aggregate_object(payload)
        raise EvalError(UNKNOWN_NODE, name)

    # -- value nodes ------------------------------------------------------

    def _field(self, path: Any) -> Value:
        if not isinstance(path, str):
            raise EvalError(SCHEMA_VIOLATION, "field path must be a string")
        return self._resolve(_wrap(self.fact), nfc(path).split("."))

    def _var(self, name: Any) -> Value:
        if not isinstance(name, str):
            raise EvalError(SCHEMA_VIOLATION, "var name must be a string")
        # Section 5.3 restricts `var` to `$` and `$.path`; a bare name is the
        # quantifier binding introduced by all/any/none.
        if name == "$":
            return _wrap(self.fact)
        if name.startswith("$."):
            return self._resolve(_wrap(self.fact), nfc(name[2:]).split("."))
        if name.startswith("$"):
            raise EvalError(SCHEMA_VIOLATION, f"malformed var reference: {name}")
        if name in self.bindings:
            return self.bindings[name]
        return UNDEFINED

    def _resolve(self, root: Value, segments: list[str]) -> Value:
        current: Value = root
        for segment in segments:
            if isinstance(current, dict) and segment in current:
                current = current[segment]
                continue
            # Traversing into a scalar, or past a key that is not there, is a
            # missing field (E11), not an error: only `exists` may sense it.
            return UNDEFINED
        return current

    # -- logic ------------------------------------------------------------

    def _missing(self) -> bool:
        """The E11 leaf collapse: a missing operand makes its leaf false.

        Every predicate leaf routes its missing-operand case through here, so
        the constraint has one implementation rather than seven copies, and the
        sentinel test can disable it in one place and watch every leaf change.
        """
        if not self.semantics.leaf_collapse:
            raise EvalError(TYPE_MISMATCH, "missing operand with leaf collapse disabled")
        return False

    def _boolean(self, value: Value) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, Undefined) or value is None:
            return self._missing()
        raise EvalError(TYPE_MISMATCH, "logical operand is not a boolean")

    def _operands(self, payload: Any, expected: int, node: str) -> list[Any]:
        if not isinstance(payload, list) or len(payload) != expected:
            raise EvalError(ARITY, f"{node} takes exactly {expected} operands")
        return payload

    def _and(self, payload: Any) -> bool:
        if not isinstance(payload, list):
            raise EvalError(ARITY, "and takes a list")
        for operand in payload:
            # Short-circuit: the Simple compiler's `exists(f) AND ...` guard is
            # only protective if a false guard stops the derived expression.
            if not self._boolean(self.evaluate(operand)):
                return False
        return True

    def _or(self, payload: Any) -> bool:
        if not isinstance(payload, list):
            raise EvalError(ARITY, "or takes a list")
        for operand in payload:
            if self._boolean(self.evaluate(operand)):
                return True
        return False

    # -- comparison -------------------------------------------------------

    def _compare(self, op: str, payload: Any) -> bool:
        left_node, right_node = self._operands(payload, 2, op)
        left = self.evaluate(left_node)
        right = self.evaluate(right_node)
        if op == "eq":
            return self._eq(left, right)
        if op == "ne":
            return self._ne(left, right)
        return self._ordered(op, left, right)

    def _eq(self, left: Value, right: Value) -> bool:
        if right is None:
            # The `== null` idiom (section 7.3(a)): a null on the RIGHT asks
            # whether the left side is absent. A null on the left is an ordinary
            # operand and takes the strict path below, which is why
            # eq(null, <present>) is false.
            return isinstance(left, Undefined) or left is None
        if isinstance(left, Undefined) or isinstance(right, Undefined):
            return self._missing()
        if left is None:
            return False
        return _equal(left, right)

    def _ne(self, left: Value, right: Value) -> bool:
        if right is None:
            return not (isinstance(left, Undefined) or left is None)
        if isinstance(left, Undefined) or isinstance(right, Undefined):
            return self._missing()
        if left is None:
            return False
        if not _same_kind(left, right):
            # E11: a cross-type `ne` is false, not true. Returning true here is
            # the fail-open the constraint text calls out by name.
            return False
        return not _equal(left, right)

    def _ordered(self, op: str, left: Value, right: Value) -> bool:
        if isinstance(left, Undefined) or isinstance(right, Undefined):
            return self._missing()
        if left is None or right is None:
            return False
        if not _same_kind(left, right) or isinstance(left, (bool, list)):
            # A14 is settled: silent false, not an E3 EvaluationError. Section
            # 5.2's worked example ("100" gt 50 "is always false"), the
            # "cross-type returns false" bullet, and the section 7.3(a) table
            # row "returns false (no implicit conversion)" all fix
            # `errored: false` with no `type_mismatch` warning for a
            # type-mismatched ORDERED comparison, the same silent-false path
            # `_eq`/`_ne` already take. The contrasted table row that DOES
            # mean EvaluationError says so explicitly; this one does not.
            # Must match the same silent-false split in `_between`, which is
            # a closed interval written as two ordered comparisons.
            # RESULTS.md A14 / A9.
            return False
        if op == "gt":
            return bool(left > right)  # type: ignore[operator]
        if op == "gte":
            return bool(left >= right)  # type: ignore[operator]
        if op == "lt":
            return bool(left < right)  # type: ignore[operator]
        return bool(left <= right)  # type: ignore[operator]

    # -- set --------------------------------------------------------------

    def _in(self, payload: Any) -> bool:
        member_node, set_node = self._operands(payload, 2, "in")
        member = self.evaluate(member_node)
        candidates = self.evaluate(set_node)
        if not isinstance(candidates, list):
            raise EvalError(NOT_AN_ARRAY, "in takes an array on the right")
        check_array_bound(len(candidates), "in")
        if isinstance(member, Undefined):
            return self._missing()
        return any(_equal(member, candidate) for candidate in candidates)

    # -- string -----------------------------------------------------------

    def _string(self, op: str, payload: Any) -> bool:
        subject_node, pattern_node = self._operands(payload, 2, op)
        subject = self.evaluate(subject_node)
        pattern = self.evaluate(pattern_node)
        if isinstance(subject, Undefined):
            return self._missing()
        if not isinstance(subject, str) or not isinstance(pattern, str):
            raise EvalError(TYPE_MISMATCH, f"{op} takes two strings")
        if op == "contains":
            return pattern in subject
        if op == "starts_with":
            return subject.startswith(pattern)
        if op == "ends_with":
            return subject.endswith(pattern)
        if len(subject) > MAX_REGEX_SUBJECT:
            # Section 7.3(d)(2), the input-length limit. It is a resource limit
            # rather than a type mismatch: the subject is a perfectly good
            # string, it is only too long to match under the E4 step ceiling.
            raise EvalError(RESOURCE_LIMIT, "regex subject exceeds the input-length limit")
        check_regex_safety(pattern)
        # Case-sensitive with no inline flags (section 5.2), search rather than
        # full match: the corpus anchors its patterns explicitly with ^ and $,
        # which is only meaningful under search semantics.
        return re.search(pattern, subject) is not None

    # -- existence and measure --------------------------------------------

    def _exists(self, payload: Any) -> bool:
        value = self.evaluate(payload)
        # Section 5.2: "" , 0 and false all count as existing; only absent and
        # null do not.
        return not (isinstance(value, Undefined) or value is None)

    def _length(self, payload: Any) -> Fraction:
        value = self.evaluate(payload)
        if isinstance(value, Undefined):
            # Section 5.2 states length(missing) = 0 explicitly, and names it as
            # the reason the Simple compiler wraps length_* in an exists guard.
            return Fraction(0)
        if isinstance(value, str):
            return Fraction(len(value))  # Python str length is code points
        if isinstance(value, list):
            check_array_bound(len(value), "length")
            return Fraction(len(value))
        raise EvalError(TYPE_MISMATCH, "length takes a string or an array")

    def _between(self, payload: Any) -> bool:
        subject_node, low_node, high_node = self._operands(payload, 3, "between")
        subject = self.evaluate(subject_node)
        low = self.evaluate(low_node)
        high = self.evaluate(high_node)
        if isinstance(subject, Undefined) or subject is None:
            return self._missing()
        if not (is_number(subject) and is_number(low) and is_number(high)):
            # A14 is settled: silent false. Section 5.2 states "between is
            # numeric-only ... non-numeric returns false" with no mention of
            # an EvaluationError, so this takes the same silent-false path as
            # `_ordered` (which it matches deliberately: between is a closed
            # interval written as two ordered comparisons) and `_eq`/`_ne`:
            # `errored: false`, no `type_mismatch` warning. RESULTS.md A14/A9.
            return False
        return bool(low <= subject <= high)  # type: ignore[operator]

    # -- quantifiers ------------------------------------------------------

    def _quantifier(self, kind: str, payload: Any) -> bool:
        if not isinstance(payload, dict):
            raise EvalError(SCHEMA_VIOLATION, f"{kind} takes a binding object")
        binding = payload.get("binding")
        if not isinstance(binding, str):
            raise EvalError(SCHEMA_VIOLATION, f"{kind} needs a binding name")
        items = self.evaluate(payload.get("over"))
        if isinstance(items, Undefined):
            # A missing array is E11 leaf collapse, not the section 7.3(e)
            # aggregate rule: that rule names `aggregate`, and only aggregate.
            return self._missing()
        if not isinstance(items, list):
            raise EvalError(NOT_AN_ARRAY, f"{kind} takes an array")
        check_array_bound(len(items), kind)
        if not items:
            if self.semantics.empty_quantifier_folds_false:
                # E8 anti-vacuous-truth fold. Section 7.3(b) does not stop at
                # the value: "all/any/none(empty) all fold to false ... and
                # record the safe fold in the audit record". Without the
                # record, this false is indistinguishable in the result object
                # from a predicate that every element failed, which is the one
                # thing a reader of the audit trail needs to tell apart.
                self._record(SAFE_FOLD_EMPTY)
                return False
            return kind != "any"  # standard vacuous truth, for the E8 sentinel
        predicate = payload.get("predicate")
        results: list[bool] = []
        for item in items:
            nested = Evaluator(
                fact=self.fact,
                semantics=self.semantics,
                bindings={**self.bindings, binding: item},
                notes=self.notes,
            )
            results.append(self._boolean(nested.evaluate(predicate)))
        if kind == "all":
            return all(results)
        if kind == "any":
            return any(results)
        return not any(results)

    # -- arithmetic -------------------------------------------------------

    def _number(self, node: Any) -> Fraction:
        value = self.evaluate(node)
        if is_number(value):
            assert isinstance(value, Fraction)
            return value
        # Section 7.3(a): arithmetic on a missing field is an evaluation error,
        # not a silent false. E11-004 pins this.
        raise EvalError(TYPE_MISMATCH, "arithmetic operand is not a number")

    def _arithmetic(self, op: str, payload: Any) -> Fraction:
        left_node, right_node = self._operands(payload, 2, op)
        left = self._number(left_node)
        right = self._number(right_node)
        if op == "add":
            return left + right
        if op == "sub":
            return left - right
        if op == "mul":
            return left * right
        if right == 0:
            raise EvalError(DIVISION_BY_ZERO, "div by zero")
        # Exact rational division: no scale is imposed here, because E2 forbids
        # rounding anywhere but an output node.
        return left / right

    def _round(self, payload: Any) -> Fraction:
        if not isinstance(payload, list) or not 1 <= len(payload) <= 2:
            raise EvalError(ARITY, "round takes one operand and an optional digit count")
        value = self._number(payload[0])
        digits = 0
        if len(payload) == 2:
            requested = self._number(payload[1])
            if requested.denominator != 1:
                raise EvalError(TYPE_MISMATCH, "round digits must be an integer")
            digits = int(requested)
        factor = Fraction(10) ** digits
        return Fraction(round_to_int(value * factor, self.semantics.rounding)) / factor

    # -- time -------------------------------------------------------------

    def _moment(self, node: Any) -> dt.datetime:
        return times.parse_utc(self.evaluate(node))

    def _days_between(self, payload: Any) -> Fraction:
        start_node, end_node = self._operands(payload, 2, "days_between")
        start = times.epoch_ms(self._moment(start_node))
        end = times.epoch_ms(self._moment(end_node))
        # Section 7.3(f): UTC millisecond difference divided by 86400000, floored.
        return Fraction((end - start) // times.MS_PER_DAY)

    def _date_add(self, payload: Any) -> str:
        if not isinstance(payload, dict):
            raise EvalError(SCHEMA_VIOLATION, "date_add takes an object")
        unit = payload.get("unit")
        if not isinstance(unit, str) or unit not in times.ADD_UNITS:
            raise EvalError(TYPE_MISMATCH, f"date_add unit: {unit!r}")
        amount = self.evaluate(payload.get("amount"))
        if not is_number(amount):
            raise EvalError(TYPE_MISMATCH, "date_add amount is not a number")
        assert isinstance(amount, Fraction)
        if amount.denominator != 1:
            # Section 7.3(f) forbids implicit rounding of a duration: "add 1.5
            # months" has no business meaning, so it is rejected rather than
            # silently rounded to 2.
            raise EvalError(TYPE_MISMATCH, "date_add amount must be an integer")
        base = self._moment(payload.get("base"))
        return times.to_iso(times.add_units(base, unit, int(amount)))

    def _date_part(self, payload: Any) -> Fraction:
        if not isinstance(payload, dict):
            raise EvalError(SCHEMA_VIOLATION, "date_part takes an object")
        unit = payload.get("unit")
        if not isinstance(unit, str) or unit not in times.PART_UNITS:
            raise EvalError(TYPE_MISMATCH, f"date_part unit: {unit!r}")
        base = self._moment(payload.get("arg"))
        return Fraction(times.date_part(base, unit))

    # -- aggregate --------------------------------------------------------

    def _aggregate_object(self, payload: Any) -> Value:
        if not isinstance(payload, dict):
            raise EvalError(SCHEMA_VIOLATION, "aggregate takes an object")
        function = payload.get("fn")
        if not isinstance(function, str) or function not in AGGREGATES:
            raise EvalError(TYPE_MISMATCH, f"aggregate fn: {function!r}")
        return self._aggregate(function, payload.get("over"))

    def _aggregate(self, function: str, payload: Any) -> Value:
        items = self.evaluate(payload)
        if not isinstance(items, list):
            # Section 7.3(e) names missing, scalar and object alike as a
            # type mismatch here, which is why a missing `over` is an error for
            # aggregate while a missing quantifier `over` is a silent false.
            raise EvalError(TYPE_MISMATCH, f"{function} takes an array")
        check_array_bound(len(items), function)
        if function == "count":
            return Fraction(len(items))
        if not items:
            # Section 7.3(e): sum folds to the empty-sum identity; avg, min and
            # max fold to false rather than to an infinity or a zero-divide.
            # The safe-failure folds are recorded for the same reason the E8
            # fold is (section 7.3(b)); the empty-sum identity is an ordinary
            # result, not a fold, so it records nothing.
            if function == "sum":
                return Fraction(0)
            self._record(SAFE_FOLD_EMPTY)
            return False
        numbers: list[Fraction] = []
        for item in items:
            if not is_number(item):
                raise EvalError(TYPE_MISMATCH, f"{function} over a non-numeric element")
            assert isinstance(item, Fraction)
            numbers.append(item)
        if function == "sum":
            return sum(numbers, Fraction(0))
        if function == "avg":
            return sum(numbers, Fraction(0)) / Fraction(len(numbers))
        if function == "min":
            return min(numbers)
        return max(numbers)


@dataclass(frozen=True)
class Outcome:
    """The folded outcome of one evaluation."""

    value: Value
    errored: bool
    warnings: tuple[str, ...]


def evaluate_tree(
    tree: Any,
    fact: dict[str, Any] | None = None,
    semantics: Semantics = DEFAULT_SEMANTICS,
) -> Outcome:
    """Evaluate a tree and apply the single E12 fold.

    Failure mode to watch for: the static limit check must stay ahead of the
    evaluation. Run it afterwards and an over-limit tree has already been
    evaluated, so the limit reports a violation the runner already ignored.
    """
    evaluator = Evaluator(fact=fact or {}, semantics=semantics)
    try:
        check_tree(tree)
        value = evaluator.evaluate(tree)
    except EvalError as exc:
        # An error supersedes any fold recorded on the way to it: the result
        # object reports one outcome, and E12's fold is that outcome.
        return Outcome(value=False, errored=True, warnings=(exc.code,))
    except RecursionError:
        return Outcome(value=False, errored=True, warnings=(RESOURCE_LIMIT,))
    return Outcome(value=value, errored=False, warnings=tuple(evaluator.notes))


__all__ = [
    "DEFAULT_SEMANTICS",
    "Evaluator",
    "Outcome",
    "Semantics",
    "evaluate_tree",
]
