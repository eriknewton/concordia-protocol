"""Projection D: the deterministic gloss renderer (section 5.5, G1 to G5)."""

from __future__ import annotations

from decimal import Decimal

import pytest
from erdl_expr.gloss import _TEMPLATES, GlossError, render
from erdl_expr.simple import compile_simple


def test_the_frozen_templates_render_each_node_group() -> None:
    assert render({"eq": [{"field": "age"}, 35]}) == "age equals 35"
    assert render({"and": [{"eq": [{"field": "a"}, 1]}, {"eq": [{"field": "b"}, 2]}]}) == (
        "a equals 1 and b equals 2"
    )
    assert render({"not": {"eq": [{"field": "age"}, 35]}}) == "not (age equals 35)"
    assert render({"in": [{"field": "cat"}, ["a", "b"]]}) == "cat in [a, b]"
    assert render({"contains": [{"field": "cmd"}, "rm"]}) == "cmd contains rm"
    assert render({"between": [{"field": "age"}, 16, 60]}) == (
        "age is in the inclusive range 16 to 60"
    )
    assert render({"add": [{"field": "a"}, {"field": "b"}]}) == "a plus b"
    assert render({"sum": {"field": "nums"}}) == "sum of nums"
    assert render({"length": {"field": "s"}}) == "length of s"
    assert render({"match": [{"field": "s"}, "^a"]}) == "s matches ^a"
    assert render({"month_last_day": {"field": "d"}}) == "the last day of the month of d"


def test_a_quantifier_renders_its_binding_and_predicate() -> None:
    tree = {
        "all": {"binding": "x", "over": {"field": "items"}, "predicate": {"gt": [{"var": "x"}, 0]}}
    }
    assert render(tree) == 'all elements in items satisfy "x is greater than 0"'


def test_a_date_add_renders_its_amount_and_unit_in_separate_slots() -> None:
    # Section 5.5's template is `{A} plus {B} {unit}`: two slots, so the
    # template owns the spacing between the amount and the unit.
    tree = {"date_add": {"unit": "years", "base": {"field": "date"}, "amount": 2}}
    assert render(tree) == "date plus 2 years"


def test_a_boolean_field_takes_the_exists_special_case() -> None:
    # Section 5.5's note: "is_active exists" reads badly, so a field named with
    # the boolean convention renders as a truth statement instead.
    assert render({"exists": {"field": "is_active"}}) == "is_active is true"
    assert render({"exists": {"field": "has_paid"}}) == "has_paid is true"
    assert render({"exists": {"field": "email"}}) == "email exists"


def test_a_number_renders_at_its_own_magnitude_not_padded_to_the_scale() -> None:
    # The gloss is the reading layer and does not enter the hash (G4), so
    # "age equals 35.00000000000000" would be noise, not fidelity.
    assert render({"eq": [{"field": "age"}, 35]}).endswith("35")
    assert render({"lt": [{"field": "r"}, Decimal("0.15")]}) == "r is less than 0.15"


def test_rendering_is_deterministic_and_a_function_of_the_tree_alone() -> None:
    tree = {"or": [{"eq": [{"field": "a"}, 1]}, {"eq": [{"field": "b"}, 2]}]}
    assert render(tree) == render(dict(tree))


def test_tampering_with_the_tree_changes_the_gloss() -> None:
    # G2 binds a stored gloss to its tree by re-rendering. These are the four
    # tamper shapes: a literal, an operator, a removed child, and a set member.
    base = {"eq": [{"field": "age"}, 35]}
    assert render(base) != render({"eq": [{"field": "age"}, 36]})
    assert render(base) != render({"ne": [{"field": "age"}, 35]})
    pair = {"and": [{"eq": [{"field": "a"}, 1]}, {"eq": [{"field": "b"}, 2]}]}
    assert render(pair) != render({"and": [{"eq": [{"field": "a"}, 1]}]})
    members = {"in": [{"field": "cat"}, ["a", "b"]]}
    assert render(members) != render({"in": [{"field": "cat"}, ["a", "c"]]})


def test_a_simple_rule_glosses_after_compilation() -> None:
    # G5: the reading layer does not distinguish the projections, so a Simple
    # condition renders through its compiled tree.
    tree = compile_simple({"operator": "not_exists", "field": "x"})
    assert render(tree) == "not (x exists)"


def test_the_chinese_templates_are_available_and_differ() -> None:
    # Spec v2.1 pins section 5.5 to English as canonical; the Chinese forms
    # survive as a presentation-only projection, never as a reported value.
    # See RESULTS.md A4.
    assert render({"eq": [{"field": "age"}, 35]}, "zh") == "age 等于 35"
    assert render({"exists": {"field": "is_active"}}, "zh") == "is_active 为“是”"


def test_an_unknown_node_has_no_frozen_template() -> None:
    with pytest.raises(GlossError):
        render({"nonesuch": [1, 2]})
    with pytest.raises(GlossError):
        render({"eq": [{"field": "a"}, 1]}, "fr")


def test_the_english_templates_are_the_frozen_section_5_5_table() -> None:
    # G1 makes gloss a render product of a FROZEN template, so the wording is a
    # cross-implementation contract rather than a style choice: a reported gloss
    # string is compared byte for byte (after NFC). This table is transcribed
    # from erdl-spec v2.1 section 5.5 (erdl-landing commit dcb7a55), which
    # reworded fifteen rows on 2026-09-09. Pinning it here means a future edit
    # that drifts from the spec fails a test instead of silently changing
    # sixteen reported strings.
    expected = {
        "and": "{A} and {B}",
        "or": "{A} or {B}",
        "not": "not ({A})",
        "eq": "{A} equals {B}",
        "ne": "{A} does not equal {B}",
        "gt": "{A} is greater than {B}",
        "gte": "{A} is greater than or equal to {B}",
        "lt": "{A} is less than {B}",
        "lte": "{A} is less than or equal to {B}",
        "in": "{A} in {B}",
        "contains": "{A} contains {B}",
        "match": "{A} matches {B}",
        "starts_with": "{A} starts with {B}",
        "ends_with": "{A} ends with {B}",
        "exists": "{A} exists",
        "exists_boolean": "{A} is true",
        "length": "length of {A}",
        "between": "{A} is in the inclusive range {B} to {C}",
        "all": 'all elements in {A} satisfy "{B}"',
        "any": 'at least one element in {A} satisfy "{B}"',
        "none": 'no elements in {A} satisfy "{B}"',
        "add": "{A} plus {B}",
        "sub": "{A} minus {B}",
        "mul": "{A} times {B}",
        "div": "{A} divided by {B}",
        "round": "{A} rounded",
        "days_between": "days between {A} and {B}",
        "epoch_ms": "epoch ms of {A}",
        "date_add": "{A} plus {B} {unit}",
        "date_part": "{part} of {A}",
        "month_last_day": "the last day of the month of {A}",
        "count": "count of {A}",
        "sum": "sum of {A}",
        "avg": "average of {A}",
        "min": "minimum of {A}",
        "max": "maximum of {A}",
    }
    actual = {name: entry["en"] for name, entry in _TEMPLATES.items()}
    # Full-set equality, not a spot check: a parity test that compares only the
    # rows it happens to name cannot detect a row that went missing.
    assert actual == expected
