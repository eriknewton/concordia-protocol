"""E4 Grade A resource limits and the section 7.3(d) regex safe subset."""

from __future__ import annotations

import time

import pytest
from erdl_expr.errors import EvalError
from erdl_expr.limits import _longest_array, check_regex_safety, check_tree, measure

from .helpers import assert_errored, assert_true


def test_an_ordinary_guarded_composition_is_well_inside_every_limit() -> None:
    # The failure this catches: counting an operand list as a level of the tree
    # makes this compiled `length_gt` look seven deep and trips the depth
    # ceiling on a tree the specification's own compile table produces.
    tree = {
        "and": [
            {"exists": {"field": "s"}},
            {"gt": [{"length": {"field": "s"}}, 2]},
        ]
    }
    check_tree(tree)
    count, depth = measure(tree)
    assert count <= 16
    assert depth <= 6
    assert_true(tree, {"s": "abc"})


def test_the_node_ceiling_counts_literals() -> None:
    # 65 = the Grade A ceiling of 64 plus one, reached only by counting the
    # boolean literals; counting operator nodes alone would score this at 1.
    over = {"and": [True] * 65}
    under = {"and": [True] * 63}
    assert_errored(over, code="resource_limit")
    check_tree(under)


def test_the_depth_arithmetic_and_quantifier_ceilings() -> None:
    deep = {"not": {"not": {"not": {"not": {"not": {"not": {"not": True}}}}}}}
    assert_errored(deep, code="resource_limit")
    assert_errored({"add": [1, {"add": [1, {"add": [1, 2]}]}]}, code="resource_limit")
    nested = {
        "all": {
            "binding": "x",
            "over": {"field": "items"},
            "predicate": {
                "all": {"binding": "y", "over": {"field": "items"}, "predicate": True}
            },
        }
    }
    assert_errored(nested, {"items": [1]}, "resource_limit")


def test_the_array_ceiling_covers_a_literal_operand_list() -> None:
    assert_errored({"in": [{"field": "x"}, list(range(10_001))]}, {"x": 1}, "resource_limit")
    # An operand list is flattened away by the depth walker, so the array
    # ceiling has to measure it separately or an over-long `and` is capped only
    # by the node count, which a different tree shape can stay under.
    assert _longest_array({"and": [True] * 10_001}) == 10_001


def test_the_array_ceiling_covers_an_array_that_arrives_in_the_fact() -> None:
    # The static tree here is three nodes. Without a runtime cap, a two-node
    # rule walks a fact array of any size, which is the half of E4 a
    # tree-shaped check cannot reach.
    oversized = list(range(10_001))
    quantifier = {
        "any": {"binding": "x", "over": {"field": "items"}, "predicate": {"gt": [{"var": "x"}, 0]}}
    }
    assert_errored(quantifier, {"items": oversized}, "resource_limit")
    assert_errored({"count": {"field": "items"}}, {"items": oversized}, "resource_limit")
    assert_errored({"in": [{"field": "x"}, {"field": "items"}]}, {"items": oversized, "x": 1},
                   "resource_limit")
    assert_errored({"length": {"field": "items"}}, {"items": oversized}, "resource_limit")
    # One under the ceiling still evaluates, so the cap is a boundary and not a
    # blanket refusal of large arrays.
    assert_true(
        {"gt": [{"count": {"field": "items"}}, 1]},
        {"items": list(range(10_000))},
    )


def test_the_regex_safe_subset_rejects_the_three_forbidden_families() -> None:
    # Nested quantifier: the canonical catastrophic-backtracking shape.
    with pytest.raises(EvalError):
        check_regex_safety("(a+)+$")
    # Backreference and lookaround are non-regular and forbidden outright.
    with pytest.raises(EvalError):
        check_regex_safety(r"(a)\1")
    with pytest.raises(EvalError):
        check_regex_safety("(?=a)b")
    with pytest.raises(EvalError):
        check_regex_safety("(?<!a)b")


def test_ambiguous_quantified_alternation_is_refused() -> None:
    # Every one of these gives a backtracking engine two ways to consume the
    # same character inside a repetition, which is the second exponential
    # family after the nested quantifier.
    for pattern in ("(ab|a)*$", "(a|a)*$", "(a|ab)+c", "(a|)*b", "([a-z]|b)*"):
        with pytest.raises(EvalError) as caught:
            check_regex_safety(pattern)
        assert caught.value.code == "regex_unsafe"


def test_a_catastrophic_pattern_is_refused_rather_than_run() -> None:
    # The adversarial case, stated as the property that matters: a pattern
    # whose match would take exponential time never reaches the matcher, so the
    # refusal is fast. Without the guard, `(a|a)*$` against this subject runs
    # 2**34 paths, which does not finish; a wall-clock bound is therefore the
    # honest assertion, and it is loose enough not to be a flake on a busy
    # machine.
    subject = "a" * 34 + "b"
    tree = {"match": [{"field": "cmd"}, "(a|a)*$"]}
    started = time.monotonic()
    assert_errored(tree, {"cmd": subject}, "regex_unsafe")
    assert time.monotonic() - started < 1.0


def test_the_input_length_limit_backs_the_syntactic_guard() -> None:
    # Section 7.3(d) asks for an input-length limit as well as the safe subset,
    # so a pattern the guard admits still cannot be run against an unbounded
    # subject.
    tree = {"match": [{"field": "cmd"}, "^a+$"]}
    assert_errored(tree, {"cmd": "a" * 10_001}, "resource_limit")


def test_the_safe_subset_still_accepts_ordinary_patterns() -> None:
    # A guard that rejected everything would be indistinguishable from a broken
    # one on the corpus, so the accepting half is asserted too.
    for pattern in ("^rm$", "^(rm|sudo)$", "[a-z]+", "a{2,4}", r"\d+\.\d+", "(abc)+"):
        check_regex_safety(pattern)


def test_an_unsafe_pattern_is_caught_statically_not_only_when_it_is_reached() -> None:
    # The pattern sits on a branch a false guard short-circuits away, so a
    # lazy check would never see it.
    tree = {"and": [False, {"match": [{"field": "cmd"}, "(a+)+$"]}]}
    assert_errored(tree, {"cmd": "aaaa"}, "regex_unsafe")
