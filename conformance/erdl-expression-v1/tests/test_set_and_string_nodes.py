"""Set group (in) and string group (contains, match, starts_with, ends_with)."""

from __future__ import annotations

from .helpers import assert_errored, assert_false, assert_true, assert_warned_not_errored


def test_in_tests_membership_with_strict_equality() -> None:
    assert_true({"in": [{"field": "cat"}, ["rare", "common"]]}, {"cat": "rare"})
    assert_false({"in": [{"field": "cat"}, ["a", "b"]]}, {"cat": "c"})
    # No coercion: the string "1" is not the number 1.
    assert_false({"in": [{"field": "n"}, [1, 2]]}, {"n": "1"})


def test_in_over_a_missing_field_is_false_and_over_a_non_array_is_an_error() -> None:
    assert_false({"in": [{"field": "missing"}, ["a"]]}, {})
    assert_errored({"in": [{"field": "cat"}, "not-array"]}, {"cat": "a"}, "not_an_array")


def test_string_operators_on_present_strings() -> None:
    assert_true({"contains": [{"field": "cmd"}, "rm"]}, {"cmd": "rm -rf /"})
    assert_false({"contains": [{"field": "cmd"}, "ls"]}, {"cmd": "rm -rf /"})
    assert_true({"starts_with": [{"field": "n"}, "safe_"]}, {"n": "safe_read"})
    assert_false({"starts_with": [{"field": "n"}, "safe_"]}, {"n": "unsafe_read"})
    assert_true({"ends_with": [{"field": "n"}, ".log"]}, {"n": "sys.log"})
    assert_false({"ends_with": [{"field": "n"}, ".log"]}, {"n": "sys.txt"})


def test_match_is_case_sensitive_and_anchors_apply() -> None:
    assert_true({"match": [{"field": "cmd"}, "^(rm|sudo)$"]}, {"cmd": "rm"})
    assert_false({"match": [{"field": "cmd"}, "^rm$"]}, {"cmd": "sudo"})
    # Section 5.2: matching is always case-sensitive and there is no inline
    # case-insensitivity flag, so an upper-case subject does not match.
    assert_false({"match": [{"field": "cmd"}, "^rm$"]}, {"cmd": "RM"})


def test_a_string_operator_on_a_missing_field_is_false() -> None:
    for operator in ("contains", "starts_with", "ends_with", "match"):
        assert_false({operator: [{"field": "missing"}, "x"]}, {})


def test_a_non_string_operand_on_contains_or_starts_with_or_ends_with_is_warned_not_errored() -> None:
    # A17 settled these three (RESULTS.md, spec section 7.3(a)); `match` is
    # untouched below because A17 does not name it and no vector exercises a
    # regex-pattern type mismatch.
    assert_warned_not_errored({"contains": [{"field": "cmd"}, 123]}, {"cmd": "rm"}, "type_mismatch")
    assert_warned_not_errored({"starts_with": [{"field": "n"}, 1]}, {"n": "safe"}, "type_mismatch")
    assert_warned_not_errored({"ends_with": [{"field": "n"}, 1]}, {"n": "x"}, "type_mismatch")
