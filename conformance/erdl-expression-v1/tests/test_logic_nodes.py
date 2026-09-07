"""Logic group: and, or, not (spec sections 5.3, 7.3(a))."""

from __future__ import annotations

from .helpers import assert_errored, assert_false, assert_true


def test_and_is_true_only_when_every_operand_holds() -> None:
    assert_true({"and": [True, True]})
    assert_false({"and": [True, False]})
    assert_false({"and": [False, True]})


def test_or_is_true_when_any_operand_holds() -> None:
    assert_true({"or": [False, True]})
    assert_false({"or": [False, False]})


def test_not_inverts_a_boolean() -> None:
    assert_true({"not": False})
    assert_false({"not": True})


def test_a_non_boolean_operand_is_a_type_mismatch_not_truthiness() -> None:
    # ERDL forbids implicit conversion, so 1 is not true and 0 is not false.
    # An implementation that borrowed the host language's truthiness would
    # return true here and false for the `or` case, and both would be wrong for
    # the same reason.
    assert_errored({"and": [1, True]}, code="type_mismatch")
    assert_errored({"or": [0, False]}, code="type_mismatch")


def test_not_of_a_missing_field_is_true_which_is_why_the_guard_exists() -> None:
    # E11 collapses the missing field to false at the leaf, and `not` flips it.
    # Section 5.2 names this exact shape as the reason every compiled `not_*`
    # operator carries an exists guard, so the kernel behaviour is correct and
    # the compiler is where the fail-open is prevented.
    assert_true({"not": {"field": "missing"}})


def test_an_error_under_not_does_not_become_true() -> None:
    # The E12 fold is taken once, at the top. A node-local fold would turn this
    # into `not(false)` and report true, which is the fail-open an error must
    # never produce.
    assert_errored({"not": {"div": [1, 0]}}, code="division_by_zero")


def test_and_short_circuits_so_a_false_guard_protects_its_branch() -> None:
    # The compiled `exists(f) AND <derived>` guard is only protective if a false
    # guard stops the derived expression from evaluating.
    assert_false({"and": [{"exists": {"field": "missing"}}, {"div": [1, 0]}]}, {})
