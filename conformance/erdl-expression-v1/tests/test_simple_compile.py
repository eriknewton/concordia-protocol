"""Projection A and C: the Simple compiler, decision tables, and the modifiers.

E7 requires one evaluation core reached by every projection, so these tests
check the compile targets the specification's section 5.2 table names and then
evaluate the compiled tree through the same kernel the Expression tests use.
"""

from __future__ import annotations

import pytest
from erdl_expr.errors import EvalError
from erdl_expr.simple import (
    ALIASES,
    CONDITION_OPERATORS,
    DECISION_TYPES,
    MODIFIER_OPERATORS,
    SIMPLE_OPERATORS,
    compile_decision_table,
    compile_simple,
)
from erdl_expr.temporal import TemporalState, run_state_ops

from .helpers import assert_false, assert_true


def test_the_operator_set_is_thirty() -> None:
    assert len(CONDITION_OPERATORS) == 28
    assert len(MODIFIER_OPERATORS) == 2
    assert len(set(SIMPLE_OPERATORS)) == 30


def test_direct_operators_compile_to_the_bare_node() -> None:
    assert compile_simple({"operator": "eq", "field": "age", "value": 35}) == {
        "eq": [{"field": "age"}, 35]
    }
    assert compile_simple({"operator": "in", "field": "cat", "value": ["a", "b"]}) == {
        "in": [{"field": "cat"}, ["a", "b"]]
    }
    assert compile_simple({"operator": "between", "field": "age", "value": [16, 60]}) == {
        "between": [{"field": "age"}, 16, 60]
    }
    assert compile_simple({"operator": "exists", "field": "x"}) == {"exists": {"field": "x"}}


def test_negated_operators_carry_the_exists_guard() -> None:
    assert compile_simple({"operator": "not_in", "field": "cat", "value": ["a"]}) == {
        "and": [{"exists": {"field": "cat"}}, {"not": {"in": [{"field": "cat"}, ["a"]]}}]
    }
    assert compile_simple({"operator": "not_contains", "field": "c", "value": "rm"}) == {
        "and": [{"exists": {"field": "c"}}, {"not": {"contains": [{"field": "c"}, "rm"]}}]
    }


def test_not_exists_is_the_one_operator_without_the_guard() -> None:
    # Guarding it would defeat it: `exists(x) AND not(exists(x))` is false for
    # every fact object, so the operator would never fire.
    assert compile_simple({"operator": "not_exists", "field": "x"}) == {
        "not": {"exists": {"field": "x"}}
    }
    assert_true(compile_simple({"operator": "not_exists", "field": "x"}), {})
    assert_false(compile_simple({"operator": "not_exists", "field": "x"}), {"x": 1})


def test_length_and_count_compositions_carry_the_guard() -> None:
    assert compile_simple({"operator": "length_gt", "field": "s", "value": 2}) == {
        "and": [{"exists": {"field": "s"}}, {"gt": [{"length": {"field": "s"}}, 2]}]
    }
    assert compile_simple({"operator": "count_lte", "field": "i", "value": 2}) == {
        "and": [{"exists": {"field": "i"}}, {"lte": [{"count": {"field": "i"}}, 2]}]
    }


def test_the_guard_is_what_stops_a_missing_field_from_satisfying_a_negation() -> None:
    # Without the guard each of these would hold on a fact object that never
    # carried the field: the positive operator is false for a missing field and
    # a bare `not` flips it, and length(missing) is 0 which is less than 5.
    for condition in (
        {"operator": "not_contains", "field": "cmd", "value": "rm"},
        {"operator": "not_between", "field": "age", "value": [16, 60]},
        {"operator": "length_lt", "field": "s", "value": 5},
        {"operator": "count_lt", "field": "items", "value": 5},
    ):
        tree = compile_simple(condition)
        assert_false(tree, {})


def test_compiled_conditions_evaluate_through_the_same_kernel() -> None:
    assert_true(compile_simple({"operator": "gt", "field": "age", "value": 60}), {"age": 61})
    assert_true(
        compile_simple({"operator": "length_eq", "field": "s", "value": 3}), {"s": "abc"}
    )
    assert_true(
        compile_simple({"operator": "not_in", "field": "cat", "value": ["a", "b"]}),
        {"cat": "c"},
    )


def test_the_two_historical_aliases_normalize_to_the_canonical_name() -> None:
    assert ALIASES == {"matches": "match", "neq": "ne"}
    assert compile_simple({"operator": "matches", "field": "c", "value": "^r$"}) == {
        "match": [{"field": "c"}, "^r$"]
    }
    assert compile_simple({"operator": "neq", "field": "a", "value": 1}) == {
        "ne": [{"field": "a"}, 1]
    }


def test_a_stateful_modifier_is_not_a_tree_node() -> None:
    with pytest.raises(EvalError):
        compile_simple({"operator": "rate", "field": "x", "value": "3/60s"})


def test_a_decision_table_compiles_to_the_same_tree_as_the_simple_form() -> None:
    table = {"columns": ["age"], "rows": [{"conditions": {"age": 35}, "decision": "ALLOW"}]}
    assert compile_decision_table(table) == compile_simple(
        {"operator": "eq", "field": "age", "value": 35}
    )


def test_a_multi_column_row_compiles_to_an_and_in_column_order() -> None:
    table = {
        "columns": ["country", "amount"],
        "rows": [{"conditions": {"amount": 10, "country": "CN"}, "decision": "ALLOW"}],
    }
    # Column order, not the order the row's keys happen to be written in: E7
    # rule 1 makes the column list the canonical order, so two authors writing
    # the same row differently still produce the same tree and the same hash.
    assert compile_decision_table(table) == {
        "and": [{"eq": [{"field": "country"}, "CN"]}, {"eq": [{"field": "amount"}, 10]}]
    }


def test_the_default_row_compiles_to_literal_true() -> None:
    table = {"columns": ["a"], "rows": [{"conditions": {}, "decision": "ALLOW"}]}
    assert compile_decision_table(table) is True


def test_rate_is_false_under_the_limit_and_true_once_it_is_reached() -> None:
    # Section 5.2: the first N events record and return false; the threshold
    # holds from the point the window contains N.
    state = TemporalState()
    assert state.check_rate("k", 3, 60_000) is False
    state.record("k")
    state.record("k")
    assert state.check_rate("k", 3, 60_000) is False
    state.record("k")
    assert state.check_rate("k", 3, 60_000) is True


def test_within_is_a_deduplication_window() -> None:
    state = TemporalState()
    assert state.check_within("k", 60_000) is False
    state.record("k")
    assert state.check_within("k", 60_000) is True


def test_events_outside_the_window_do_not_count() -> None:
    state = TemporalState(now_ms=1_000_000)
    state.events["k"] = [1_000_000 - 90_000]
    assert state.check_within("k", 60_000) is False


def test_the_isolation_key_separates_two_operators() -> None:
    state = TemporalState()
    state.record("field|within|value")
    assert state.check_within("field|rate|value|3/60s", 60_000) is False


def test_replaying_a_state_op_sequence_returns_the_last_check() -> None:
    assert run_state_ops(
        [
            {"op": "recordRate", "key": "k", "windowMs": 60_000},
            {"op": "recordRate", "key": "k", "windowMs": 60_000},
            {"op": "recordRate", "key": "k", "windowMs": 60_000},
            {"op": "checkRate", "key": "k", "maxCount": 3, "windowMs": 60_000},
        ]
    ) is True
    assert run_state_ops(
        [
            {"op": "recordWithin", "key": "k"},
            {"op": "checkWithin", "key": "k", "windowMs": 60_000},
        ]
    ) is True


def test_a_sequence_with_no_check_is_a_malformed_vector() -> None:
    with pytest.raises(ValueError):
        run_state_ops([{"op": "recordRate", "key": "k", "windowMs": 60_000}])


def test_a_cell_may_name_any_of_the_six_comparison_operators() -> None:
    # Section 5.4's own example row is `when: [["gte", 10000]]`, so a table
    # whose cells only ever mean equality implements a fraction of the
    # projection. One column, one cell, one comparison node each.
    for operator in ("eq", "ne", "gt", "gte", "lt", "lte"):
        table = {
            "columns": [{"field": "context.amount", "label": "application amount"}],
            "rows": [{"when": [[operator, 10000]], "then": "REQUEST_HUMAN", "priority": 100}],
        }
        assert compile_decision_table(table) == {
            operator: [{"field": "context.amount"}, 10000]
        }


def test_a_cell_row_compiles_to_the_same_tree_as_the_hand_written_simple_form() -> None:
    # E7 rule 5: the compiled tree is identical to the hand-written Simple
    # tree, which is the property that makes the projection a projection.
    table = {"columns": [{"field": "age"}], "rows": [{"when": [["gte", 60]], "then": "ALLOW"}]}
    assert compile_decision_table(table) == compile_simple(
        {"operator": "gte", "field": "age", "value": 60}
    )


def test_the_spec_shaped_table_orders_rows_by_precedence() -> None:
    # Section 5.4's worked example, cells and default row included. Row order
    # is precedence (E7 rule 2), so the first matching row wins.
    table = {
        "columns": [{"field": "context.amount", "label": "application amount"}],
        "rows": [
            {"when": [["gte", 10000]], "then": "REQUEST_HUMAN", "priority": 100},
            {"when": [["gte", 5000]], "then": "ESCALATE", "priority": 90},
            {"when": [], "then": "ALLOW", "priority": 1},
        ],
    }
    tree = compile_decision_table(table)
    assert_true(tree, {"context": {"amount": 12000}})
    assert_true(tree, {"context": {"amount": 1}})  # the default row fires
    assert tree == {
        "or": [
            {"gte": [{"field": "context.amount"}, 10000]},
            {"or": [{"gte": [{"field": "context.amount"}, 5000]}, True]},
        ]
    }


def test_an_empty_when_is_the_default_row() -> None:
    table = {"columns": [{"field": "a"}], "rows": [{"when": [], "then": "ALLOW"}]}
    assert compile_decision_table(table) is True


def test_a_cell_outside_the_comparison_group_is_refused() -> None:
    for cell in (["in", ["a"]], ["contains", "x"], ["gte"], "gte"):
        table = {"columns": [{"field": "a"}], "rows": [{"when": [cell], "then": "ALLOW"}]}
        with pytest.raises(EvalError):
            compile_decision_table(table)


def test_a_row_decision_outside_the_section_6_enumeration_is_refused() -> None:
    # E7 rule 4. A misspelled decision that compiled cleanly would produce a
    # rule that evaluates and then names a decision nothing can act on.
    table = {"columns": [{"field": "a"}], "rows": [{"when": [], "then": "APPROVE"}]}
    with pytest.raises(EvalError):
        compile_decision_table(table)


def test_decision_types_is_exactly_the_section_6_thirteen() -> None:
    assert len(DECISION_TYPES) == 13


def test_a_workflow_substate_in_then_is_refused() -> None:
    # WORKFLOW_WAITING and WORKFLOW_PROGRESS are substates of WORKFLOW (a
    # running workflow's own status), not values a row's `then` can name.
    for substate in ("WORKFLOW_WAITING", "WORKFLOW_PROGRESS"):
        table = {"columns": [{"field": "a"}], "rows": [{"when": [], "then": substate}]}
        with pytest.raises(EvalError):
            compile_decision_table(table)


def test_a_row_with_more_cells_than_columns_is_refused() -> None:
    table = {"columns": [{"field": "a"}], "rows": [{"when": [["eq", 1], ["eq", 2]]}]}
    with pytest.raises(EvalError):
        compile_decision_table(table)


def test_rate_fires_on_the_invocation_after_the_threshold_is_reached() -> None:
    # The section 5.2 truth table read as the operator's own invocation loop:
    # "first N times: record + false", "from the (N+1)-th time: true", with
    # post-counting (supporting constraint 1) and the record taken in the
    # under-limit branch (constraint 3). Under those two, the window holds
    # exactly N events when the (N+1)-th invocation checks, so the check is
    # "count >= N" and the first true is the (N+1)-th call.
    state = TemporalState()
    threshold = 3
    verdicts = []
    for _ in range(threshold + 1):
        fired = state.check_rate("k", threshold, 60_000)
        verdicts.append(fired)
        if not fired:
            state.record("k")
    assert verdicts == [False, False, False, True]
