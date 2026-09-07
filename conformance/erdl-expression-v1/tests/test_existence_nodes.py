"""Existence and measure group: exists, length, between (sections 5.2, 5.3)."""

from __future__ import annotations

from .helpers import assert_errored, assert_false, assert_number, assert_true


def test_exists_is_present_and_not_null() -> None:
    assert_true({"exists": {"field": "x"}}, {"x": 1})
    assert_false({"exists": {"field": "x"}}, {})
    assert_false({"exists": {"field": "x"}}, {"x": None})


def test_exists_counts_empty_string_zero_and_false_as_existing() -> None:
    # Section 5.2 is explicit: existing is not the same as non-empty, so an
    # implementation that reused a truthiness test would report false here and
    # would silently disable every exists guard on a zero-valued field.
    assert_true({"exists": {"field": "x"}}, {"x": ""})
    assert_true({"exists": {"field": "x"}}, {"x": 0})
    assert_true({"exists": {"field": "x"}}, {"x": False})


def test_length_counts_code_points_and_array_members() -> None:
    assert_number({"length": {"field": "s"}}, "3", {"s": "abc"})
    assert_number({"length": {"field": "arr"}}, "4", {"arr": [1, 2, 3, 4]})
    # Code points, not UTF-16 units: an astral character is one.
    assert_number({"length": {"field": "s"}}, "1", {"s": "\U0001F600"})


def test_length_of_a_missing_field_is_zero() -> None:
    # Section 5.2 states this and then names it as the reason the Simple
    # compiler wraps every length_* composition in an exists guard: without the
    # guard, `length_lt 5` would hold for a field that is not there.
    assert_number({"length": {"field": "missing"}}, "0", {})


def test_length_of_a_number_is_a_type_mismatch() -> None:
    assert_errored({"length": {"field": "n"}}, {"n": 42}, "type_mismatch")


def test_between_is_a_closed_numeric_interval() -> None:
    assert_true({"between": [{"field": "age"}, 16, 60]}, {"age": 30})
    assert_true({"between": [{"field": "age"}, 16, 60]}, {"age": 16})
    assert_true({"between": [{"field": "age"}, 16, 60]}, {"age": 60})
    assert_false({"between": [{"field": "age"}, 16, 60]}, {"age": 61})


def test_between_over_a_missing_field_or_a_string_is_a_silent_false() -> None:
    # A14/A9, settled: a non-numeric `between` operand is a silent false,
    # `errored: false`, on the same path as a cross-type ordered comparison.
    assert_false({"between": [{"field": "missing"}, 1, 10]}, {})
    assert_false({"between": [{"field": "age"}, 16, 60]}, {"age": "30"})
