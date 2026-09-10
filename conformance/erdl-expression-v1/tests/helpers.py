"""Shared assertions for the node-group suites.

Every case below is derived from the specification text, not from the corpus:
the corpus ships no expected values, and reading an oracle would forfeit ER9.
"""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
from typing import Any

from erdl_expr.evaluator import DEFAULT_SEMANTICS, Outcome, Semantics, evaluate_tree
from erdl_expr.values import decimal_string


def dec(text: str) -> Decimal:
    """An exact decimal literal for a hand-built tree.

    Python source cannot write one: `0.1` in a test file is a binary float and
    is already the wrong value before the kernel sees it. The corpus loader has
    the same problem and solves it the same way, with `parse_float=Decimal`.
    """
    return Decimal(text)


def run(tree: Any, fact: dict[str, Any] | None = None,
        semantics: Semantics = DEFAULT_SEMANTICS) -> Outcome:
    return evaluate_tree(tree, fact, semantics)


def assert_true(tree: Any, fact: dict[str, Any] | None = None) -> None:
    outcome = run(tree, fact)
    assert outcome.errored is False, outcome.warnings
    assert outcome.value is True


def assert_false(tree: Any, fact: dict[str, Any] | None = None) -> None:
    outcome = run(tree, fact)
    assert outcome.errored is False, outcome.warnings
    assert outcome.value is False


def assert_errored(tree: Any, fact: dict[str, Any] | None = None, code: str | None = None) -> None:
    """An evaluation error folds to false and reports `errored`.

    Both halves are asserted. Checking only the value would pass for an
    implementation that quietly returned false without recording the error,
    which is the difference E3 exists to make visible.
    """
    outcome = run(tree, fact)
    assert outcome.errored is True, outcome.value
    assert outcome.value is False
    if code is not None:
        assert code in outcome.warnings, outcome.warnings


def assert_constraint_violated(tree: Any, fact: dict[str, Any] | None, code: str) -> None:
    """RESULTS.md A21 / EXPRESSION-RUNNER-CONTRACT.md (b56c1c2), "Constraint
    vectors (E4/E5)": an E4 resource-limit violation is a
    constraint-verification vector, not an evaluation vector, so it is
    reported as `errored: false` with a literal `null` value -- not
    `assert_errored`'s evaluated-and-folded `false`, and not
    `assert_warned_not_errored`'s evaluated-and-warned `false` either. All
    three are asserted so a runner that quietly reused one of those two
    shapes for an E4 rejection is caught here.
    """
    outcome = run(tree, fact)
    assert outcome.errored is False, outcome.warnings
    assert outcome.value is None, outcome.value
    assert outcome.not_evaluated is True
    assert code in outcome.warnings, outcome.warnings


def assert_warned_not_errored(tree: Any, fact: dict[str, Any] | None, code: str) -> None:
    """A17 (erdl-vectors discussion #2031, spec §7.3(a) fixed at fb428b7): a
    string-family, `length`, or `aggregate` type mismatch folds to false and
    records the warning, but is NOT an evaluation error.

    All three are asserted, the same way `assert_errored` asserts both halves
    of its own predicate: `errored` distinguishes this from `assert_errored`'s
    class (a raised `EvalError`), `value` distinguishes it from a plain
    `assert_false` (a false that happens to record nothing), and the warning
    distinguishes it from every other silent-false fold (comparison, `between`)
    that A17 explicitly leaves alone.
    """
    outcome = run(tree, fact)
    assert outcome.errored is False, outcome.warnings
    assert outcome.value is False
    assert code in outcome.warnings, outcome.warnings


def assert_number(tree: Any, expected: str, fact: dict[str, Any] | None = None) -> None:
    outcome = run(tree, fact)
    assert outcome.errored is False, outcome.warnings
    assert isinstance(outcome.value, Fraction), outcome.value
    assert decimal_string(outcome.value) == expected


def assert_string(tree: Any, expected: str, fact: dict[str, Any] | None = None) -> None:
    outcome = run(tree, fact)
    assert outcome.errored is False, outcome.warnings
    assert outcome.value == expected
