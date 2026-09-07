"""Quantifier group: all, any, none (sections 5.3, 7.3(b), E8)."""

from __future__ import annotations

from .helpers import assert_errored, assert_false, assert_true, run

POSITIVE = {"binding": "x", "over": {"field": "items"}, "predicate": {"gt": [{"var": "x"}, 0]}}


def test_all_holds_when_every_member_satisfies_the_predicate() -> None:
    assert_true({"all": POSITIVE}, {"items": [1, 2, 3]})
    assert_false({"all": POSITIVE}, {"items": [1, -2, 3]})


def test_any_holds_when_one_member_satisfies_the_predicate() -> None:
    assert_true({"any": POSITIVE}, {"items": [-1, 2]})
    assert_false({"any": POSITIVE}, {"items": [-1, -2]})


def test_none_holds_when_no_member_satisfies_the_predicate() -> None:
    assert_true({"none": POSITIVE}, {"items": [-1, -2]})
    assert_false({"none": POSITIVE}, {"items": [-1, 2]})


def test_the_binding_is_scoped_to_its_own_predicate() -> None:
    # The binding must not leak into the enclosing scope, or a later `var`
    # reference would silently read the last loop iteration.
    assert_false({"eq": [{"var": "x"}, 1]}, {"items": [1]})


def test_a_missing_array_is_false_and_a_non_array_is_an_error() -> None:
    # E11 governs the missing case (silent false); section 7.3(e)'s type
    # mismatch rule names `aggregate`, not the quantifiers, so a present
    # non-array is the error and an absent one is not.
    assert_false({"all": POSITIVE}, {})
    assert_errored({"all": POSITIVE}, {"items": "not-array"}, "not_an_array")
    assert_errored({"any": POSITIVE}, {"items": 5}, "not_an_array")


def test_the_empty_array_fold_is_recorded_not_only_taken() -> None:
    # Section 7.3(b) asks for two things: fold all/any/none over an empty array
    # to false, "and record the safe fold in the audit record". Without the
    # record, this false is indistinguishable in the result object from a
    # predicate every element failed.
    for kind in ("all", "any", "none"):
        outcome = run({kind: POSITIVE}, {"items": []})
        assert outcome.value is False
        assert outcome.errored is False  # a safe fold is not an evaluation error
        assert "safe_fold_empty_array" in outcome.warnings
    # A non-empty array that simply fails the predicate records nothing, which
    # is what makes the record informative.
    assert run({"all": POSITIVE}, {"items": [-1]}).warnings == ()


def test_the_aggregate_safe_failure_folds_are_recorded_too() -> None:
    # Section 7.3(e): avg, min and max over an empty array fold to false. The
    # empty-sum identity is an ordinary result rather than a fold, so `sum`
    # and `count` record nothing.
    for function in ("avg", "min", "max"):
        outcome = run({function: {"field": "nums"}}, {"nums": []})
        assert outcome.value is False
        assert "safe_fold_empty_array" in outcome.warnings
    assert run({"sum": {"field": "nums"}}, {"nums": []}).warnings == ()
    assert run({"count": {"field": "nums"}}, {"nums": []}).warnings == ()
