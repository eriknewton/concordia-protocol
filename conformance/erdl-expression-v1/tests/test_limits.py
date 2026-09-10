"""E4 Grade A resource limits and the section 7.3(d) regex safe subset."""

from __future__ import annotations

import time

import pytest
from erdl_expr.errors import EvalError
from erdl_expr.limits import _longest_array, check_regex_safety, check_tree, measure

from .helpers import assert_constraint_violated, assert_errored, assert_false, assert_true, run


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
    # V-ENGINE-E4-001 is exactly this tree (RESULTS.md A21: a constraint
    # vector, not an evaluation vector, so `errored` stays false).
    over = {"and": [True] * 65}
    under = {"and": [True] * 63}
    assert_constraint_violated(over, None, "resource_limit")
    check_tree(under)


def test_the_depth_arithmetic_and_quantifier_ceilings() -> None:
    # V-ENGINE-E4-002, -003 and -005 are exactly these three trees
    # (RESULTS.md A21).
    deep = {"not": {"not": {"not": {"not": {"not": {"not": {"not": True}}}}}}}
    assert_constraint_violated(deep, None, "resource_limit")
    assert_constraint_violated(
        {"add": [1, {"add": [1, {"add": [1, 2]}]}]}, None, "resource_limit"
    )
    nested = {
        "all": {
            "binding": "x",
            "over": {"field": "items"},
            "predicate": {
                "all": {"binding": "y", "over": {"field": "items"}, "predicate": True}
            },
        }
    }
    assert_constraint_violated(nested, {"items": [1]}, "resource_limit")


def test_the_array_ceiling_covers_a_literal_operand_list() -> None:
    # V-ENGINE-E4-004 is this tree (RESULTS.md A21).
    assert_constraint_violated(
        {"in": [{"field": "x"}, list(range(10_001))]}, {"x": 1}, "resource_limit"
    )
    # An operand list is flattened away by the depth walker, so the array
    # ceiling has to measure it separately or an over-long `and` is capped only
    # by the node count, which a different tree shape can stay under.
    assert _longest_array({"and": [True] * 10_001}) == 10_001


def test_the_array_ceiling_covers_an_array_that_arrives_in_the_fact() -> None:
    # The static tree here is three nodes. Without a runtime cap, a two-node
    # rule walks a fact array of any size, which is the half of E4 a
    # tree-shaped check cannot reach. RESULTS.md A21: this is the same
    # `resource_limit` code as the static E4 vectors, raised at evaluation
    # time instead of the static gate, and folds the same way -- no vector in
    # the corpus reaches this path, but the fold shape must not depend on
    # which of E4's two enforcement points caught the breach.
    oversized = list(range(10_001))
    quantifier = {
        "any": {"binding": "x", "over": {"field": "items"}, "predicate": {"gt": [{"var": "x"}, 0]}}
    }
    assert_constraint_violated(quantifier, {"items": oversized}, "resource_limit")
    assert_constraint_violated({"count": {"field": "items"}}, {"items": oversized}, "resource_limit")
    assert_constraint_violated(
        {"in": [{"field": "x"}, {"field": "items"}]}, {"items": oversized, "x": 1},
        "resource_limit",
    )
    assert_constraint_violated({"length": {"field": "items"}}, {"items": oversized}, "resource_limit")
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
    # subject. Same `resource_limit` code and fold as the rest of E4
    # (RESULTS.md A21); no corpus vector reaches this path.
    tree = {"match": [{"field": "cmd"}, "^a+$"]}
    assert_constraint_violated(tree, {"cmd": "a" * 10_001}, "resource_limit")


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


def test_the_five_structural_e4_ceilings_report_no_evaluated_value() -> None:
    """RESULTS.md A21. Before this test's fix, every one of these five trees
    (V-ENGINE-E4-001 through -005) reported `errored=True, value=False`,
    because `evaluate_tree` folded every `EvalError` through one path
    regardless of its code. EXPRESSION-RUNNER-CONTRACT.md (b56c1c2)
    "Constraint vectors (E4/E5)" says the E4 resource-limit vectors are
    "constraint-verification vectors, not evaluation vectors" and that "the
    E12 fold and `errored` rules ... apply to evaluation vectors only", so the
    correct report for a rejected tree is `errored=False` with no evaluated
    value at all, not a folded `false`.

    V-ENGINE-E4-006 (the sixth E4 vector, a regex-safety rejection) is
    deliberately NOT one of these five: RESULTS.md A10/A20 already settled
    that reading as `errored=True` on separate spec grounds (section 7.3(d)
    has no stated `errored` value for a regex-safety rejection, unlike the
    explicit "not an evaluation vector" text E4's other five ceilings have),
    and this fix must not silently change it. See
    `test_a_catastrophic_pattern_is_refused_rather_than_run` and
    `test_an_unsafe_pattern_is_caught_statically_not_only_when_it_is_reached`
    above, both still asserting `errored=True` for a regex-unsafe fold.
    """
    node_ceiling = {"and": [True] * 65}  # V-ENGINE-E4-001
    depth_ceiling = {"not": {"not": {"not": {"not": {"not": {"not": {"not": True}}}}}}}  # E4-002
    arithmetic_ceiling = {"add": [1, {"add": [1, {"add": [1, 2]}]}]}  # E4-003
    array_ceiling = {"in": [{"field": "x"}, list(range(10_001))]}  # E4-004
    quantifier_ceiling = {
        "all": {
            "binding": "x",
            "over": {"field": "items"},
            "predicate": {
                "all": {"binding": "y", "over": {"field": "items"}, "predicate": True}
            },
        }
    }  # E4-005
    for tree, fact in (
        (node_ceiling, None),
        (depth_ceiling, None),
        (arithmetic_ceiling, None),
        (array_ceiling, {"x": 1}),
        (quantifier_ceiling, {"items": [1]}),
    ):
        outcome = run(tree, fact)
        assert outcome.not_evaluated is True, (tree, outcome)
        assert outcome.errored is False, (tree, outcome)
        assert outcome.value is None, (tree, outcome)
        assert "resource_limit" in outcome.warnings, (tree, outcome)


def test_an_e5_load_time_exclusivity_violation_reports_true_not_an_error() -> None:
    """RESULTS.md A22 (`V-ENGINE-E5-001`). Before this fix, `expr` coexisting
    with the Simple triple (`field`/`operator`/`value`) raised a plain
    `SCHEMA_VIOLATION` `EvalError`, which `evaluate_tree` folded through the
    ordinary EvalError path to `errored=True, value=False`. But
    EXPRESSION-RUNNER-CONTRACT.md (b56c1c2) "Constraint vectors (E4/E5)" says
    E5, like E4, is a constraint-verification vector, not an evaluation
    vector -- and unlike E4 it gives E5 a definite reportable answer: "E5
    `value: true` = violation detected". This tree is exactly
    `V-ENGINE-E5-001` ("expr vs field/operator/value exclusive (violation)"):
    reporting `errored=True` for it was folding a constraint-detection result
    through the evaluation-error path the contract explicitly carves it out
    of, the same category error A21 already found and fixed for E4.
    """
    tree = {
        "expr": {"eq": [{"field": "x"}, 1]},
        "field": "x",
        "operator": "eq",
        "value": 1,
    }
    outcome = run(tree, {})
    assert outcome.not_evaluated is False, outcome
    assert outcome.errored is False, outcome
    assert outcome.value is True, outcome
    assert "expr_load_exclusivity_violation" in outcome.warnings, outcome


def test_an_expr_only_node_has_no_exclusivity_violation_and_evaluates_normally() -> None:
    # V-ENGINE-E5-002 ("expr-only valid"): no field/operator/value alongside
    # `expr`, so this is not a violation at all -- it evaluates the inner
    # tree, which is E11's ordinary missing-field leaf collapse here.
    assert_false({"expr": {"eq": [{"field": "x"}, 1]}}, {})
