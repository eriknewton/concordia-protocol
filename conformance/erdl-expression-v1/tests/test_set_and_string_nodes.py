"""Set group (in) and string group (contains, match, starts_with, ends_with)."""

from __future__ import annotations

from .helpers import assert_false, assert_true, assert_warned_not_errored


def test_in_tests_membership_with_strict_equality() -> None:
    assert_true({"in": [{"field": "cat"}, ["rare", "common"]]}, {"cat": "rare"})
    assert_false({"in": [{"field": "cat"}, ["a", "b"]]}, {"cat": "c"})
    # No coercion: the string "1" is not the number 1.
    assert_false({"in": [{"field": "n"}, [1, 2]]}, {"n": "1"})


def test_in_over_a_missing_field_is_false_and_over_a_non_array_is_warned_not_errored() -> None:
    # Spec §7.3(a) (upstream fb428b7) names `in` (non-array right operand)
    # explicitly among the four warned-not-errored families alongside string
    # nodes/length/aggregate: "record a type_mismatch warning — these four set
    # errored: false". This vector (V-ENGINE-in-003 in the upstream corpus) was
    # left raising `not_an_array` (errored=true) when A17 fixed the other three
    # families; the erdl-vectors PR#3 CI cross-verification flagged the miss
    # (errored=true≠false against the oracle). RESULTS.md A17 addendum.
    assert_false({"in": [{"field": "missing"}, ["a"]]}, {})
    assert_warned_not_errored({"in": [{"field": "cat"}, "not-array"]}, {"cat": "a"}, "type_mismatch")


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
    # A17 settled these three (RESULTS.md, spec section 7.3(a)).
    assert_warned_not_errored({"contains": [{"field": "cmd"}, 123]}, {"cmd": "rm"}, "type_mismatch")
    assert_warned_not_errored({"starts_with": [{"field": "n"}, 1]}, {"n": "safe"}, "type_mismatch")
    assert_warned_not_errored({"ends_with": [{"field": "n"}, 1]}, {"n": "x"}, "type_mismatch")


def test_a_non_string_operand_on_match_is_also_warned_not_errored() -> None:
    # Fix round found this as a gap in A17, not a new ambiguity: fb428b7's
    # warning-asymmetry clause names its "string nodes" family as exactly
    # "contains/match/starts_with/ends_with" (spec §7.3(a)) -- `match` is
    # already named in the settled text, alongside the three above, not an
    # unsettled fourth case. Before this fix, `_string` carved `match` out of
    # the shared branch and raised `EvalError(TYPE_MISMATCH, ...)` here
    # (errored=true), on the theory that no corpus vector exercises this
    # exact shape; that reasoning does not survive contact with the clause's
    # own unconditional wording. This is a plain operand-type mismatch (the
    # pattern is a number, not a regex string), distinct from
    # `V-ENGINE-match-003`'s regex-*safety* rejection on a correctly-typed
    # string pattern (RESULTS.md A20/A21, `test_an_unsafe_pattern_is_caught_
    # statically_not_only_when_it_is_reached` in test_limits.py), which stays
    # an EvaluationError because §7.3(d) states no `errored` value for it.
    assert_warned_not_errored({"match": [{"field": "cmd"}, 123]}, {"cmd": "rm"}, "type_mismatch")
