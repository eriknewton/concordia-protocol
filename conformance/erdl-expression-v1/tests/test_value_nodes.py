"""Value group: field, var, literal (spec section 5.3, appendix A)."""

from __future__ import annotations

from erdl_expr.evaluator import evaluate_tree
from erdl_expr.values import UNDEFINED

from .helpers import assert_number, assert_string, run


def test_field_reads_a_top_level_key() -> None:
    assert_number({"field": "age"}, "35", {"age": 35})


def test_field_reads_a_dotted_path() -> None:
    assert_string({"field": "user.name"}, "John Doe", {"user": {"name": "John Doe"}})


def test_missing_field_is_the_undefined_sentinel() -> None:
    outcome = evaluate_tree({"field": "missing"}, {})
    assert outcome.errored is False
    assert outcome.value is UNDEFINED


def test_traversing_into_a_scalar_is_missing_not_an_error() -> None:
    # `a` is a number, so `a.b` has no key to follow. E11 makes that a missing
    # field; only `exists` may sense the difference, and nothing raises.
    outcome = evaluate_tree({"field": "a.b"}, {"a": 1})
    assert outcome.errored is False
    assert outcome.value is UNDEFINED


def test_var_root_returns_the_fact_object() -> None:
    outcome = evaluate_tree({"var": "$"}, {"a": 1})
    assert outcome.errored is False
    assert outcome.value == {"a": 1}


def test_var_path_reads_into_the_fact_object() -> None:
    assert_string({"var": "$.user.name"}, "x", {"user": {"name": "x"}})


def test_var_missing_path_is_undefined() -> None:
    outcome = evaluate_tree({"var": "$.missing"}, {})
    assert outcome.value is UNDEFINED


def test_literal_number_string_and_zero() -> None:
    assert_number(42, "42")
    assert_number(0, "0")
    assert_string("hello", "hello")


def test_literal_null_is_not_reportable_and_stays_a_value() -> None:
    outcome = evaluate_tree(None, {})
    assert outcome.errored is False
    assert outcome.value is None


def test_string_values_are_nfc_normalized_on_the_way_in() -> None:
    # A decomposed literal (e + U+0301 combining acute) becomes the precomposed
    # U+00E9 form, so a byte comparison against a precomposed string succeeds
    # (E10). Written as escapes because the two forms are indistinguishable on
    # screen, which is exactly why the constraint needs a test at all.
    decomposed = "cafe\u0301"
    precomposed = "caf\u00e9"
    assert decomposed != precomposed
    assert run(decomposed).value == precomposed
    assert run({"field": "s"}, {"s": decomposed}).value == precomposed
