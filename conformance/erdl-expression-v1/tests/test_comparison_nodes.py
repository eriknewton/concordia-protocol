"""Comparison group: eq, ne, gt, gte, lt, lte (sections 5.2, 7.3(a), E11)."""

from __future__ import annotations

from .helpers import assert_errored, assert_false, assert_true


def test_equality_on_matching_values() -> None:
    assert_true({"eq": [{"field": "age"}, 35]}, {"age": 35})
    assert_false({"eq": [{"field": "age"}, 34]}, {"age": 35})
    assert_true({"ne": [{"field": "age"}, 34]}, {"age": 35})
    assert_false({"ne": [{"field": "age"}, 35]}, {"age": 35})


def test_ordered_comparison_on_numbers() -> None:
    assert_true({"gt": [{"field": "age"}, 60]}, {"age": 61})
    assert_false({"gt": [{"field": "age"}, 60]}, {"age": 60})
    assert_true({"gte": [{"field": "age"}, 60]}, {"age": 60})
    assert_true({"lt": [{"field": "age"}, 60]}, {"age": 59})
    assert_true({"lte": [{"field": "age"}, 60]}, {"age": 60})


def test_strings_order_by_code_point_not_by_numeric_reading() -> None:
    # Section 5.2 states this outright: "2" is greater than "10" because the
    # comparison is lexicographic, and an implementation that coerced would
    # report false.
    assert_true({"gt": ["2", "10"]})


def test_a_missing_field_collapses_to_false_without_an_error() -> None:
    # E11 leaf collapse. This is NOT an evaluation error: a missing field is
    # the norm in agent context, so it must not raise a warning that a Guard
    # would fail closed on.
    for operator in ("eq", "ne", "gt", "gte", "lt", "lte"):
        assert_false({operator: [{"field": "missing"}, 1]}, {})


def test_a_cross_type_ordered_comparison_is_a_silent_false() -> None:
    # A14, settled: silent false. Section 5.2's worked example ("100" gt 50
    # "is always false") and section 7.3(a)'s table row ("Type-mismatched
    # comparison | returns false (no implicit conversion)") both fix
    # `errored: false` with no `type_mismatch` warning; the string "100" is
    # never coerced to the number 100, but that is a value fact, not a record.
    assert_false({"gt": [{"field": "amount"}, 50]}, {"amount": "100"})
    assert_false({"lte": [{"field": "amount"}, 50]}, {"amount": "100"})


def test_cross_type_equality_is_false_in_both_directions() -> None:
    # E11: `ne` across types is false, not true. Returning true would be a
    # fail-open, since "these are different" would then satisfy a deny rule.
    assert_false({"eq": [False, 100]})
    assert_false({"ne": [False, 100]})
    assert_false({"ne": ["x", 100]})


def test_the_null_check_idiom_reads_the_right_hand_operand() -> None:
    # Section 7.3(a) keeps `== null` and `!= null` working normally. The idiom
    # is recognised when null is the RIGHT operand, which is how the check is
    # written; a null on the left is an ordinary operand and takes the strict
    # cross-type path, so it is false for both operators.
    assert_true({"eq": [{"field": "missing"}, None]}, {})
    assert_false({"ne": [{"field": "missing"}, None]}, {})
    assert_false({"eq": [{"field": "age"}, None]}, {"age": 35})
    assert_true({"ne": [{"field": "age"}, None]}, {"age": 35})
    assert_false({"eq": [None, {"field": "age"}]}, {"age": 35})
    assert_false({"ne": [None, {"field": "age"}]}, {"age": 35})


def test_a_comparison_needs_exactly_two_operands() -> None:
    assert_errored({"eq": [1]}, code="arity")


def test_every_ordered_comparison_treats_a_cross_type_pair_the_same_way() -> None:
    # A14, settled: the silent-false reading, applied across the whole group
    # rather than at one node, the same path `eq`/`ne` already take. An
    # ordered comparison of two different types has no order to report, and
    # section 5.2's worked example and section 7.3(a)'s table row fix
    # `errored: false` with no warning; the row that DOES mean an
    # EvaluationError (arithmetic on a missing field) says so explicitly on
    # the very next table row, and this one does not.
    for operator in ("gt", "gte", "lt", "lte"):
        assert_false({operator: [{"field": "amount"}, 50]}, {"amount": "100"})
        assert_false({operator: [{"field": "flag"}, 1]}, {"flag": True})
    # between is the same comparison written as a closed interval, so it takes
    # the same path (section 5.2, "between is numeric-only ... non-numeric
    # returns false").
    assert_false({"between": [{"field": "age"}, 16, 60]}, {"age": "30"})


def test_equality_across_types_is_a_silent_false_not_an_error() -> None:
    # Section 7.3(a) and the E11 vectors: false, and no fail-open on `ne`. The
    # value matches the ordered case above; only `errored` differs, which is
    # the whole content of the distinction.
    assert_false({"eq": [False, 100]})
    assert_false({"ne": [False, 100]})
    assert_false({"ne": ["x", 100]})
    assert_false({"eq": [{"field": "amount"}, 50]}, {"amount": "100"})
