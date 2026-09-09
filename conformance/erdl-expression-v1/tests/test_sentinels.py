"""The semantic sentinels, each shown failing before it passes.

Contract section 3 makes the E2, E8, E10, E9 and E11 edge cases the honesty
sentinel of the expression layer: an implementation with subtly wrong semantics
necessarily mismatches on them. A guard nobody has watched fail is not evidence
that it works, so every sentinel here is asserted twice: once against a
deliberately wrong semantics, where it must fail, and once against the
specification's semantics, where it must hold.

The wrong semantics come from `Semantics`, whose fields default to the
specification's mandate. `evaluate_corpus` refuses to run with a non-default
value, so nothing here can leak into a published artifact.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Any

import pytest
from erdl_expr.evaluator import DEFAULT_SEMANTICS, Semantics, evaluate_tree
from erdl_expr.values import ROUND_HALF_EVEN, ROUND_HALF_UP, decimal_string, round_to_int

from .helpers import assert_false, assert_number, assert_true, dec, run

HALF_UP = Semantics(rounding=ROUND_HALF_UP)
VACUOUS = Semantics(empty_quantifier_folds_false=False)
NO_COLLAPSE = Semantics(leaf_collapse=False)


def _rounded(tree: object, semantics: Semantics) -> str:
    outcome = evaluate_tree(tree, {}, semantics)
    assert isinstance(outcome.value, Fraction), outcome
    return decimal_string(outcome.value)


def test_e2_half_even_sentinel_fails_under_a_planted_half_up_mode() -> None:
    # Plant the wrong mode. Half-up rounds every tie away from zero, so the two
    # even-tie cases move and the sentinel catches it.
    assert _rounded({"round": [dec("0.5")]}, HALF_UP) == "1"
    assert _rounded({"round": [dec("2.5")]}, HALF_UP) == "3"
    # The specification's mode: ties go to the even neighbour.
    assert _rounded({"round": [dec("0.5")]}, DEFAULT_SEMANTICS) == "0"
    assert _rounded({"round": [dec("2.5")]}, DEFAULT_SEMANTICS) == "2"
    assert _rounded({"round": [dec("1.5")]}, DEFAULT_SEMANTICS) == "2"
    assert _rounded({"round": [dec("3.5")]}, DEFAULT_SEMANTICS) == "4"


def test_e2_half_even_also_governs_the_reported_scale_not_only_the_round_node() -> None:
    # A value whose fifteenth decimal digit is an exact tie. Half-up would keep
    # the fourteenth digit at 4 and round it to 5.
    tie = Fraction(45, 10**15)
    assert round_to_int(tie * 10**14, ROUND_HALF_UP) == 5
    assert round_to_int(tie * 10**14, ROUND_HALF_EVEN) == 4
    assert decimal_string(tie) == "0.00000000000004"


def test_e8_empty_array_folding_fails_under_vacuous_truth() -> None:
    empty = {"binding": "x", "over": {"field": "items"}, "predicate": {"gt": [{"var": "x"}, 0]}}
    fact: dict[str, Any] = {"items": []}
    # Standard quantifier semantics: `all` over an empty array is vacuously
    # true, which is the "nothing to check, therefore allowed" reading E8
    # exists to forbid.
    assert evaluate_tree({"all": empty}, fact, VACUOUS).value is True
    assert evaluate_tree({"none": empty}, fact, VACUOUS).value is True
    # The ERDL fold: all three are false.
    assert_false({"all": empty}, fact)
    assert_false({"any": empty}, fact)
    assert_false({"none": empty}, fact)


def test_e11_leaf_collapse_fails_when_the_collapse_is_disabled() -> None:
    missing = {"eq": [{"field": "missing"}, 1]}
    # With the collapse disabled, a missing operand propagates instead of
    # settling the leaf, so the whole evaluation reports errored and a Guard
    # reading it would fail closed on an absent field, which E11 calls out as
    # the wrong behaviour for a context where absence is the norm.
    assert evaluate_tree(missing, {}, NO_COLLAPSE).errored is True
    assert evaluate_tree({"not": missing}, {}, NO_COLLAPSE).value is False
    assert evaluate_tree({"contains": [{"field": "m"}, "x"]}, {}, NO_COLLAPSE).errored is True
    # The ERDL semantics: the collapse happens at the leaf, silently, and only
    # `exists` senses the absence.
    assert_false(missing, {})
    assert run(missing, {}).errored is False
    assert run({"not": missing}, {}).value is True
    assert_false({"exists": {"field": "missing"}}, {})


def test_e10_nfc_normalization_makes_the_two_encodings_meet() -> None:
    # Escapes, not literal characters: the decomposed and precomposed forms
    # look identical in an editor, which is the reason E10 exists and the
    # reason a reviewer cannot check this case by eye.
    decomposed = "cafe\u0301"
    precomposed = "caf\u00e9"
    assert decomposed != precomposed
    assert_true({"eq": [{"field": "s"}, precomposed]}, {"s": decomposed})
    assert_true({"contains": [{"field": "s"}, precomposed]}, {"s": decomposed + " au lait"})
    # And the reverse direction, so the normalization is not one-sided.
    assert_true({"eq": [{"field": "s"}, decomposed]}, {"s": precomposed})
    # `in` goes through the same _equal comparison as eq on each candidate
    # (evaluator.py:94,176), so both sides of the membership check must
    # NFC-normalize for the two encodings to meet here too.
    assert_true({"in": [{"field": "s"}, [precomposed]]}, {"s": decomposed})
    assert_true({"in": [{"field": "s"}, [decomposed]]}, {"s": precomposed})


def test_e12_folds_an_error_to_false_and_never_to_true() -> None:
    # The fold direction is the whole point: an error must not satisfy a rule.
    for tree in (
        {"div": [1, 0]},
        {"not": {"div": [1, 0]}},
        {"exists": {"div": [1, 0]}},
        {"or": [{"div": [1, 0]}, True]},
    ):
        outcome = run(tree)
        assert outcome.errored is True, tree
        assert outcome.value is False, tree


def test_the_corpus_runner_refuses_a_planted_semantics() -> None:
    # The switches above are test instruments. This is the structural guard
    # that keeps one out of a published submission.
    from erdl_expr.results import evaluate_corpus

    with pytest.raises(ValueError, match="specification's semantics"):
        evaluate_corpus({"vectors": []}, HALF_UP)


def test_scale_fourteen_is_where_a_quotient_is_reported() -> None:
    assert_number({"div": [1, 3]}, "0.33333333333333")
    assert_number({"div": [1, 7]}, "0.14285714285714")
    assert_number({"div": [2, 7]}, "0.28571428571429")
