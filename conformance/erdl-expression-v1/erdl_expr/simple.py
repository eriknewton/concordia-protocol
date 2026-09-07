"""Projection A: the Simple 30-operator compiler, and the decision-table compiler.

E7 requires Simple and Expression to compile to the same evaluation core, so
this module produces trees and never evaluates anything. The compile targets are
the ones the spec's section 5.2 mapping table states, including the exists
guard.

The exists guard is the part a reimplementation gets wrong. Every `not_*`
operator except `not_exists`, and every `length_*` and `count_*` composition,
compiles to `exists(field) AND <derived>`. Without it a missing field would make
`not_contains` true (a positive operator returns false for a missing field, and
a bare `not` flips that to true) and `length_lt` true (length of a missing field
is 0, which is less than any positive bound). Both are fail-open. `not_exists`
is the sole exception, because sensing absence is its entire purpose.
"""

from __future__ import annotations

from typing import Any, Final

from .errors import SCHEMA_VIOLATION, EvalError

#: The 30 Simple operators: 28 conditions plus the 2 modifiers.
CONDITION_OPERATORS: Final[tuple[str, ...]] = (
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "match",
    "starts_with",
    "ends_with",
    "not_starts_with",
    "not_ends_with",
    "exists",
    "not_exists",
    "length_gt",
    "length_gte",
    "length_lt",
    "length_lte",
    "length_eq",
    "between",
    "not_between",
    "count_gt",
    "count_gte",
    "count_lt",
    "count_lte",
)
MODIFIER_OPERATORS: Final[tuple[str, ...]] = ("within", "rate")
SIMPLE_OPERATORS: Final[tuple[str, ...]] = CONDITION_OPERATORS + MODIFIER_OPERATORS

#: Historical aliases section 5.2 permits an implementation to normalize. They
#: are not new operators, and the canonical name is what enters the tree.
ALIASES: Final[dict[str, str]] = {"matches": "match", "neq": "ne"}

_DIRECT_COMPARISON: Final[frozenset[str]] = frozenset({"eq", "ne", "gt", "gte", "lt", "lte"})
_DIRECT_STRING: Final[frozenset[str]] = frozenset(
    {"contains", "match", "starts_with", "ends_with"}
)
_NEGATED_STRING: Final[dict[str, str]] = {
    "not_contains": "contains",
    "not_starts_with": "starts_with",
    "not_ends_with": "ends_with",
}
_LENGTH_COMPARISON: Final[dict[str, str]] = {
    "length_gt": "gt",
    "length_gte": "gte",
    "length_lt": "lt",
    "length_lte": "lte",
    "length_eq": "eq",
}
_COUNT_COMPARISON: Final[dict[str, str]] = {
    "count_gt": "gt",
    "count_gte": "gte",
    "count_lt": "lt",
    "count_lte": "lte",
}


def _guarded(path: str, derived: dict[str, Any]) -> dict[str, Any]:
    """`exists(field) AND derived`, the E11 compile-layer guarantee."""
    return {"and": [{"exists": {"field": path}}, derived]}


def compile_simple(condition: dict[str, Any]) -> Any:
    """Compile one Simple condition into an expression tree.

    Accepts the `{field, operator, value}` shape the corpus uses.
    """
    operator = condition.get("operator")
    if not isinstance(operator, str):
        raise EvalError(SCHEMA_VIOLATION, "Simple condition needs an operator")
    operator = ALIASES.get(operator, operator)
    path = condition.get("field")
    if not isinstance(path, str):
        raise EvalError(SCHEMA_VIOLATION, "Simple condition needs a field")
    value = condition.get("value")
    reference = {"field": path}

    if operator in _DIRECT_COMPARISON:
        return {operator: [reference, value]}
    if operator == "in":
        return {"in": [reference, value]}
    if operator == "not_in":
        return _guarded(path, {"not": {"in": [reference, value]}})
    if operator in _DIRECT_STRING:
        return {operator: [reference, value]}
    if operator in _NEGATED_STRING:
        return _guarded(path, {"not": {_NEGATED_STRING[operator]: [reference, value]}})
    if operator == "exists":
        return {"exists": reference}
    if operator == "not_exists":
        # The one operator that must NOT carry the guard: its meaning is
        # "sense that the field is absent", which the guard would defeat.
        return {"not": {"exists": reference}}
    if operator in _LENGTH_COMPARISON:
        return _guarded(path, {_LENGTH_COMPARISON[operator]: [{"length": reference}, value]})
    if operator in _COUNT_COMPARISON:
        return _guarded(path, {_COUNT_COMPARISON[operator]: [{"count": reference}, value]})
    if operator == "between":
        bounds = _bounds(value)
        return {"between": [reference, bounds[0], bounds[1]]}
    if operator == "not_between":
        bounds = _bounds(value)
        return _guarded(path, {"not": {"between": [reference, bounds[0], bounds[1]]}})
    if operator in MODIFIER_OPERATORS:
        # within and rate are stateful modifiers. Section 5.2 keeps their state
        # out of the tree (the tree stays a pure function, E1) and hands it to
        # the Guard state manager in temporal.py.
        raise EvalError(SCHEMA_VIOLATION, f"{operator} is a stateful modifier, not a tree node")
    raise EvalError(SCHEMA_VIOLATION, f"unknown Simple operator: {operator}")


def _bounds(value: Any) -> tuple[Any, Any]:
    if not isinstance(value, list) or len(value) != 2:
        raise EvalError(SCHEMA_VIOLATION, "between takes a [min, max] pair")
    return value[0], value[1]


#: The 13 decision types section 6 enumerates. E7 rule 4 makes a row's `then`
#: a member of this set, so a table naming anything else is a load-time defect
#: rather than a row that never fires. WORKFLOW_WAITING and WORKFLOW_PROGRESS
#: are substates of WORKFLOW (a running workflow's own internal status), not
#: `then` values a row can name; a row that names one is rejected below with
#: the same schema_violation as any other unrecognized decision. RESULTS.md.
DECISION_TYPES: Final[frozenset[str]] = frozenset(
    {
        "ALLOW",
        "DENY",
        "CORRECT",
        "NOTIFY",
        "REQUEST_HUMAN",
        "ESCALATE",
        "DELEGATE",
        "DEFER",
        "EMERGENCY_HALT",
        "ROLLBACK",
        "QUARANTINE",
        "WORKFLOW",
        "GUIDE",
    }
)

#: The comparison operators a decision-table cell may name. Section 5.4 states
#: that "each condition unit compiles to a comparison node", and section 5.3
#: fixes the comparison group at these six; the section's own example cell is
#: `["gte", 10000]`, so eq is not the only cell form.
#: Must match COMPARISON_OPS in evaluator.py.
CELL_OPERATORS: Final[frozenset[str]] = frozenset({"eq", "ne", "gt", "gte", "lt", "lte"})


def compile_decision_table(table: dict[str, Any]) -> Any:
    """Compile projection C (a decision table) to the same kernel.

    E7 rule 1: a row's conditions compile to a logical AND in field-column
    order. Rule 3: an empty row is the default row and compiles to literal true.
    A single condition compiles to the bare comparison rather than a one-element
    `and`, so that the tree is identical to the hand-written Simple tree, which
    is what rule 5 requires.

    Two row shapes are accepted, because the specification and the vector
    corpus write a table differently and rule 5 says both must reach the same
    tree:

    * section 5.4's own shape, `when: [["gte", 10000], ...]`, where a cell
      names its comparison operator and its operand, positionally against the
      column list, and `when: []` is the default row;
    * the corpus shape, `conditions: {<column>: <value>}`, where a bare value
      is the equality cell.

    Failure mode a reader should know about: a table that only ever fires
    equality looks correct against an equality-only corpus, so the operator
    cell is exercised by the unit tests rather than by the vectors.
    """
    columns = table.get("columns")
    if not isinstance(columns, list):
        raise EvalError(SCHEMA_VIOLATION, "decision table needs columns")
    rows = table.get("rows")
    if not isinstance(rows, list) or not rows:
        raise EvalError(SCHEMA_VIOLATION, "decision table needs rows")
    compiled = [_compile_row(columns, row) for row in rows]
    if len(compiled) == 1:
        return compiled[0]
    # This tree answers one boolean question, "does some row in the table
    # match," never which row's `then` fires; row-to-decision selection is
    # outside the expression kernel's scope. §5.4's own compile rule ⑤ is
    # that the compiled tree must equal the hand-written Simple/Expression
    # tree, and "some row matches" over an ordered row list is exactly
    # `or(row0, or(row1, or(row2, ...)))`, so the fold below builds that OR
    # right-associated over the rows, not an if-then-else: an if-then-else
    # would need to carry each row's `then` value through the tree, which the
    # single shared boolean kernel (E7) has no node for. A default row's
    # compiled term is literal `true`, so this OR degenerates to `true`
    # whenever one is present, matching the fact that a default row always
    # matches something.
    result: Any = compiled[-1]
    for branch in reversed(compiled[:-1]):
        result = {"or": [branch, result]}
    return result


def _column_field(column: Any) -> str:
    """The field a column names, in either of the two column shapes.

    Section 5.4 writes a column as `{field, label}`; the corpus writes it as a
    bare field name. The label is presentation and never enters the tree.
    """
    if isinstance(column, str):
        return column
    if isinstance(column, dict) and isinstance(column.get("field"), str):
        return str(column["field"])
    raise EvalError(SCHEMA_VIOLATION, "decision-table column must name a field")


def _compile_row(columns: list[Any], row: Any) -> Any:
    if not isinstance(row, dict):
        raise EvalError(SCHEMA_VIOLATION, "decision-table row must be an object")
    _check_decision(row)
    fields = [_column_field(column) for column in columns]
    terms = _row_terms(fields, row)
    if not terms:
        # E7 rule 3: the default row is unconditional and compiles to literal
        # true. An empty `when` and an absent `conditions` are the same row.
        return True
    if len(terms) == 1:
        return terms[0]
    return {"and": terms}


def _check_decision(row: dict[str, Any]) -> None:
    """E7 rule 4: a row's decision belongs to the section 6 enumeration."""
    decision = row.get("then", row.get("decision"))
    if decision is None:
        return
    if not isinstance(decision, str) or decision not in DECISION_TYPES:
        raise EvalError(SCHEMA_VIOLATION, f"decision-table row decision: {decision!r}")


def _row_terms(fields: list[str], row: dict[str, Any]) -> list[Any]:
    cells = row.get("when")
    if isinstance(cells, list):
        # Section 5.4's shape. Cells are positional against the column list, so
        # a table with more cells than columns has no field to attach the extra
        # cell to and is malformed rather than silently truncated.
        if len(cells) > len(fields):
            raise EvalError(SCHEMA_VIOLATION, "decision-table row has more cells than columns")
        return [_cell_term(fields[index], cell) for index, cell in enumerate(cells)]
    conditions = row.get("conditions")
    if not isinstance(conditions, dict) or not conditions:
        return []
    # The corpus shape. A bare value is the equality cell, which is the same
    # comparison node the `["eq", value]` cell produces.
    return [
        {"eq": [{"field": field}, conditions[field]]} for field in fields if field in conditions
    ]


def _cell_term(field: str, cell: Any) -> Any:
    """Compile one section 5.4 condition unit into a comparison node."""
    if not isinstance(cell, list) or len(cell) != 2:
        raise EvalError(SCHEMA_VIOLATION, "decision-table cell must be [operator, value]")
    operator, operand = cell
    if not isinstance(operator, str):
        raise EvalError(SCHEMA_VIOLATION, "decision-table cell operator must be a string")
    operator = ALIASES.get(operator, operator)
    if operator not in CELL_OPERATORS:
        # Deliberately narrow: section 5.4 says a condition unit compiles to a
        # comparison node, and the comparison group is exactly these six. A
        # cell naming `in` or `contains` is refused rather than quietly
        # compiled to a node the section does not authorize here.
        raise EvalError(SCHEMA_VIOLATION, f"decision-table cell operator: {operator!r}")
    return {operator: [{"field": field}, operand]}
