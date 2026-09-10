"""Quantifier group: all, any, none (sections 5.3, 7.3(b), E8)."""

from __future__ import annotations

from .helpers import assert_false, assert_true, assert_warned_not_errored, run

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


def test_a_missing_or_non_array_over_is_warned_not_errored() -> None:
    # spec v2.1 (erdl-landing 79dd76a, section 7.3(b)) names the missing case
    # with scalar and object, so a missing `over` is the quantifier's own
    # `type_mismatch` warning, not E11's silent leaf collapse. It settles
    # the case A20 had left open: "an `over` that is not an array
    # (missing/scalar/object) is a `type_mismatch` warning: `all/any/none`
    # fold to `false` with `errored: false`." Before this fix, `_quantifier`
    # raised `NOT_AN_ARRAY` for this branch and the generic EvalError fold
    # reported `errored=True`; RESULTS.md A20 (V-ENGINE-all-003/-any-003/
    # -none-003).
    assert_warned_not_errored({"all": POSITIVE}, {}, "type_mismatch")
    assert_warned_not_errored({"all": POSITIVE}, {"items": "not-array"}, "type_mismatch")
    assert_warned_not_errored({"any": POSITIVE}, {"items": 5}, "type_mismatch")


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
