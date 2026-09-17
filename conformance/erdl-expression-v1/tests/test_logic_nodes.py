"""Logic group: and, or, not (spec sections 5.3, 7.3(a))."""

from __future__ import annotations

from .helpers import assert_errored, assert_false, assert_true, run


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


def test_a_non_boolean_operand_folds_to_false_silently() -> None:
    # ERDL forbids implicit conversion, so 1 is not true and 0 is not false.
    # An implementation that borrowed the host language's truthiness would
    # return true here and false for the `or` case, and both would be wrong
    # for the same reason (A13's already-settled VALUE reading). spec v2.1
    # (erdl-landing 79dd76a, section 7.3(a)) settles the `errored` question
    # A13/A20 had left open: "logic nodes (`and`/`or`) over a non-boolean
    # operand fold type mismatches to false **silently** (no warning)" --
    # the SAME silent family as comparison/`between`, not the WARNED family
    # (`in`/string/`length`/`aggregate`/quantifier). Before this fix,
    # `_boolean` raised `TYPE_MISMATCH` for a non-boolean operand and the
    # generic EvalError fold reported `errored=True`; RESULTS.md A20
    # (V-ENGINE-and-004/-or-004).
    for tree in ({"and": [1, True]}, {"or": [0, False]}):
        outcome = run(tree)
        assert outcome.errored is False, outcome.warnings
        assert outcome.value is False
        assert outcome.warnings == (), outcome.warnings


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
