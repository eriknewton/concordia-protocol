"""Arithmetic group: add, sub, mul, div, round (sections 5.3, 7.3(a), E2)."""

from __future__ import annotations

from .helpers import assert_errored, assert_number, dec


def test_binary_arithmetic_on_exact_decimals() -> None:
    assert_number({"add": [1, 2]}, "3")
    assert_number({"sub": [5, 3]}, "2")
    assert_number({"mul": [3, 4]}, "12")


def test_decimal_literals_are_exact_not_binary_approximations() -> None:
    # The failure this catches is a float parse: 0.1 + 0.2 would come out as
    # 0.30000000000000004 and 0.3 - 0.1 as 0.19999999999999998.
    assert_number({"add": [dec("0.1"), dec("0.2")]}, "0.3")
    assert_number({"sub": [dec("0.3"), dec("0.1")]}, "0.2")
    assert_number({"mul": [dec("0.1"), dec("0.2")]}, "0.02")
    assert_number({"mul": [dec("0.1"), 3]}, "0.3")


def test_division_reports_at_scale_fourteen() -> None:
    assert_number({"div": [1, 3]}, "0.33333333333333")
    assert_number({"div": [4, 3]}, "1.33333333333333")
    assert_number({"div": [2, 3]}, "0.66666666666667")


def test_a_large_integer_survives_intact() -> None:
    # 1e21 + 1 is outside the exactly representable range of a double, so an
    # implementation that reported through a float would print 1e21 and lose
    # the increment entirely.
    assert_number({"add": [dec("1e21"), 1]}, "1000000000000000000001")


def test_round_is_half_even_at_the_reporting_scale() -> None:
    assert_number({"round": [dec("0.5")]}, "0")
    assert_number({"round": [dec("1.5")]}, "2")
    assert_number({"round": [dec("2.5")]}, "2")
    assert_number({"round": [dec("3.5")]}, "4")
    assert_number({"round": [dec("-2.5")]}, "-2")


def test_division_by_zero_and_bad_arity_are_evaluation_errors() -> None:
    assert_errored({"div": [10, 0]}, code="division_by_zero")
    assert_errored({"sub": [5]}, code="arity")
    assert_errored({"div": [10, 2, 5]}, code="arity")


def test_a_binary_float_is_refused_rather_than_silently_accepted() -> None:
    # A float has already lost the decimal it came from, so the kernel refuses
    # it at the door instead of converting and pretending the value is exact.
    assert_errored({"add": [0.1, 0.2]}, code="type_mismatch")


def test_arithmetic_on_a_missing_field_is_a_type_mismatch() -> None:
    # Section 7.3(a) separates the two readings of a missing field: false when
    # it lands at a condition leaf, an evaluation error inside an arithmetic
    # expression. E11 pins the arithmetic half.
    assert_errored({"add": [{"field": "missing"}, 1]}, {}, "type_mismatch")
    assert_errored({"add": [1, "x"]}, code="type_mismatch")
    assert_errored({"round": ["x"]}, code="type_mismatch")
