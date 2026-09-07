"""Aggregate group: count, sum, avg, min, max (sections 5.3, 7.3(e))."""

from __future__ import annotations

from .helpers import assert_errored, assert_false, assert_number, dec


def test_the_five_aggregate_functions() -> None:
    assert_number({"count": {"field": "nums"}}, "3", {"nums": [1, 2, 3]})
    assert_number({"sum": {"field": "nums"}}, "0.6", {"nums": [dec("0.1"), dec("0.2"), dec("0.3")]})
    assert_number({"avg": {"field": "nums"}}, "2", {"nums": [1, 2, 3]})
    assert_number({"min": {"field": "nums"}}, "1", {"nums": [3, 1, 2]})
    assert_number({"max": {"field": "nums"}}, "3", {"nums": [3, 1, 2]})


def test_the_object_form_reaches_the_same_functions() -> None:
    assert_number({"aggregate": {"fn": "sum", "over": {"field": "n"}}}, "6", {"n": [1, 2, 3]})


def test_an_average_keeps_full_precision_until_the_reported_value() -> None:
    # 1/3 rounded once at the end, not three thirds each rounded and summed.
    assert_number({"avg": {"field": "n"}}, "0.33333333333333", {"n": [0, 0, 1]})


def test_the_empty_array_folds_per_the_table() -> None:
    # Section 7.3(e): count and sum have identities; avg, min and max fold to
    # false rather than to a zero-divide or an infinity.
    assert_number({"count": {"field": "n"}}, "0", {"n": []})
    assert_number({"sum": {"field": "n"}}, "0", {"n": []})
    assert_false({"avg": {"field": "n"}}, {"n": []})
    assert_false({"min": {"field": "n"}}, {"n": []})
    assert_false({"max": {"field": "n"}}, {"n": []})


def test_a_missing_over_is_a_type_mismatch_and_differs_from_an_empty_array() -> None:
    # Section 7.3(e) states the distinction outright: count(missing) is a type
    # mismatch, count(empty) is 0. An implementation that folded both to 0
    # would report a rule as satisfied on a fact object that never carried the
    # field at all.
    assert_errored({"count": {"field": "missing"}}, {}, "type_mismatch")
    assert_errored({"sum": {"field": "n"}}, {"n": 5}, "type_mismatch")


def test_a_non_numeric_member_is_a_type_mismatch() -> None:
    assert_errored({"min": {"field": "n"}}, {"n": [1, "x", 3]}, "type_mismatch")
