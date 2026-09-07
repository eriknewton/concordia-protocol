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


def assert_number(tree: Any, expected: str, fact: dict[str, Any] | None = None) -> None:
    outcome = run(tree, fact)
    assert outcome.errored is False, outcome.warnings
    assert isinstance(outcome.value, Fraction), outcome.value
    assert decimal_string(outcome.value) == expected


def assert_string(tree: Any, expected: str, fact: dict[str, Any] | None = None) -> None:
    outcome = run(tree, fact)
    assert outcome.errored is False, outcome.warnings
    assert outcome.value == expected
