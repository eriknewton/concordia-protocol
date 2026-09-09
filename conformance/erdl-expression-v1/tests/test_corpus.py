"""The whole published corpus: every vector produces an ER3 result object.

The vector file is OpenOBA's artifact, not this repository's, so it is
referenced rather than vendored. Point `ERDL_V_ENGINE_VECTORS` at a local copy
to run this module; without it the corpus half of the suite skips and the
synthetic half above still runs.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from erdl_expr.results import (
    _canonical,
    corpus_sha256,
    evaluate_corpus,
    load_corpus,
)
from erdl_expr.simple import compile_decision_table, compile_simple

#: SHA-256 of the exact corpus every number in `output/` and `RESULTS.md` was
#: measured against. A different digest means the numbers describe a different
#: input, so the test says so rather than quietly re-measuring.
CORPUS_SHA256 = "3ee30466cc6d95ddd99bc412cfc88b2f2dd3f890b8687b8f12043cc40074c902"
EXPECTED_TOTAL = 240

_PATH = os.environ.get("ERDL_V_ENGINE_VECTORS", "")
pytestmark = pytest.mark.skipif(
    not (_PATH and Path(_PATH).is_file()),
    reason="set ERDL_V_ENGINE_VECTORS to the published v-engine-vectors.json",
)


@pytest.fixture(scope="module")
def document() -> dict[str, Any]:
    return load_corpus(_PATH)


def test_the_corpus_is_the_one_the_recorded_numbers_describe(document: dict[str, Any]) -> None:
    assert corpus_sha256(_PATH) == CORPUS_SHA256
    assert len(document["vectors"]) == EXPECTED_TOTAL


def test_every_vector_produces_a_well_formed_er3_result(document: dict[str, Any]) -> None:
    results = evaluate_corpus(document)
    assert len(results) == EXPECTED_TOTAL
    for result in results:
        payload = result.as_object()
        assert set(payload) == {"value", "value_type", "errored", "warnings"}
        assert payload["value_type"] in {"number", "string", "boolean"}
        assert isinstance(payload["errored"], bool)
        assert isinstance(payload["warnings"], list)
        if payload["value_type"] == "boolean":
            assert isinstance(payload["value"], bool)
        if payload["errored"]:
            # E12 folds every error to false; an errored result reporting any
            # other value would mean the fold was skipped somewhere.
            assert payload["value"] is False


def test_the_vector_ids_are_unique_and_all_present(document: dict[str, Any]) -> None:
    results = evaluate_corpus(document)
    ids = [result.vector_id for result in results]
    assert len(set(ids)) == EXPECTED_TOTAL
    assert set(ids) == {str(vector["id"]) for vector in document["vectors"]}


def test_the_group_counts_match_the_corpus_breakdown(document: dict[str, Any]) -> None:
    results = evaluate_corpus(document)
    groups = Counter(result.group for result in results)
    breakdown = document["breakdown"]
    constraints = sum(count for name, count in groups.items() if name.startswith("constraint:"))
    assert constraints == breakdown["constraint"]
    assert groups["simple_compile"] == breakdown["simple_compile"]
    assert groups["gloss"] == breakdown["gloss"]
    assert groups["gloss_integrity"] == breakdown["gloss_integrity"]
    assert groups["projection"] == breakdown["projection"]
    node_groups = sum(
        count
        for name, count in groups.items()
        if not name.startswith("constraint:")
        and name not in {"simple_compile", "gloss", "gloss_integrity", "projection"}
    )
    assert node_groups == breakdown["node"]


def test_this_runner_compiles_every_simple_vector_to_the_published_tree(
    document: dict[str, Any],
) -> None:
    # The corpus publishes the compiled tree for each Simple operator, so the
    # compiler can be checked against it without touching an answer file: the
    # tree is an input, not an expected evaluation result.
    checked = 0
    for vector in document["vectors"]:
        if vector.get("subcategory") == "simple-compile":
            checked += 1
            assert _canonical(compile_simple(vector)) == _canonical(vector["compiled_tree"])
        if "decision_table" in vector:
            compiled = compile_decision_table(vector["decision_table"])
            published = vector["decision_table_compiled_tree"]
            assert _canonical(compiled) == _canonical(published)
    assert checked == 28


def test_evaluation_is_a_pure_function_of_the_tree_and_the_fact(document: dict[str, Any]) -> None:
    # E1. Two runs over the same corpus must agree exactly, and neither may
    # mutate the loaded document.
    before = _canonical(document)
    first = [result.as_object() for result in evaluate_corpus(document)]
    second = [result.as_object() for result in evaluate_corpus(document)]
    assert first == second
    assert _canonical(document) == before
