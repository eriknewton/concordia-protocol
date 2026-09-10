"""The ER3 result object and the submission file's numeric encoding."""

from __future__ import annotations

import json
from fractions import Fraction

import pytest
from erdl_expr.results import (
    VectorResult,
    dumps,
    evaluate_vector,
    submission_payload,
)


def _envelope(results: list[VectorResult], number_format: str = "decimal-string") -> str:
    return dumps(
        submission_payload(
            results,
            runner="test",
            method="test",
            date="2026-09-07",
            artifact="https://example.invalid",
            number_format=number_format,
        )
    )


def test_each_result_carries_the_four_er3_fields() -> None:
    result = evaluate_vector(
        {"id": "T1", "category": "V-ENGINE", "node_group": "comparison",
         "expr_tree": {"eq": [{"field": "a"}, 1]}, "context": {"a": 1}}
    )
    assert set(result.as_object()) == {"value", "value_type", "errored", "warnings"}
    assert result.value_type == "boolean"
    assert result.errored is False


def test_the_default_encoding_is_a_decimal_string() -> None:
    # A1 settled 2026-09-10 (upstream b56c1c2): contract ER3 corrected itself
    # to "a decimal string ... not a JSON number", reversing the prior
    # contract text this runner had been reading as authoritative. The
    # submission the CI cross-verify job consumes must therefore default to
    # decimal-string without a caller having to opt in, or the omission alone
    # reproduces the 37-vector number-family mismatch class the erdl-vectors
    # PR#3 CI run reported (`value=35≠"35" type=number≠number`).
    results = [VectorResult("T1", "V-ENGINE", "arithmetic",
                            Fraction(1, 3), "number", False, ())]
    payload = json.loads(_envelope(results))
    assert payload["number_format"] == "decimal-string"
    assert payload["results"]["T1"]["value"] == "0.33333333333333"
    assert payload["results"]["T1"]["value_type"] == "number"


def test_the_decimal_string_encoding_regenerates_the_same_values_quoted() -> None:
    results = [VectorResult("T1", "V-ENGINE", "arithmetic",
                            Fraction(1, 3), "number", False, ())]
    payload = json.loads(_envelope(results, "decimal-string"))
    assert payload["results"]["T1"]["value"] == "0.33333333333333"
    assert payload["number_format"] == "decimal-string"


def test_the_json_number_encoding_is_kept_as_the_superseded_alternate() -> None:
    # Pre-A1-settlement behavior, retained only for comparison (README.md);
    # it is no longer what the submission ships by default.
    results = [VectorResult("T1", "V-ENGINE", "arithmetic",
                            Fraction(1, 3), "number", False, ())]
    text = _envelope(results, "json-number")
    assert '"value": 0.33333333333333' in text
    assert json.loads(text)["results"]["T1"]["value_type"] == "number"


def test_a_large_integer_survives_the_round_trip_in_either_encoding() -> None:
    # The reason numbers do not go through the JSON encoder's float path: this
    # value is not representable as a double, and a float round trip would
    # write 1e+21 and drop the increment. True whichever encoding is chosen.
    big = Fraction(10**21 + 1)
    json_number_text = _envelope(
        [VectorResult("T1", "V-ENGINE", "arithmetic", big, "number", False, ())], "json-number"
    )
    assert '"value": 1000000000000000000001' in json_number_text
    assert json.loads(json_number_text)["results"]["T1"]["value"] == 10**21 + 1
    decimal_string_payload = json.loads(_envelope(
        [VectorResult("T1", "V-ENGINE", "arithmetic", big, "number", False, ())], "decimal-string"
    ))
    assert decimal_string_payload["results"]["T1"]["value"] == "1000000000000000000001"


def test_a_string_value_containing_the_sentinel_is_refused_not_corrupted() -> None:
    # The number encoding works by substituting a marker out of the serialized
    # text. If a real string ever carried the marker the substitution would
    # corrupt it, so the writer fails instead of publishing.
    poisoned = [VectorResult("T1", "V-GLOSS", "gloss",
                             "@@ERDL-NUM:1@@", "string", False, ())]
    with pytest.raises(ValueError, match="sentinel"):
        _envelope(poisoned)


def test_an_unknown_number_format_is_refused() -> None:
    with pytest.raises(ValueError):
        submission_payload([], runner="r", method="m", date="d",
                           artifact="a", number_format="binary")


def test_an_exact_integer_beyond_the_double_range_is_a_reader_side_bound() -> None:
    # What the file carries and what a double-typed reader recovers are two
    # different questions, and conflating them is what makes `1e+21` look like a
    # runner defect. The envelope's bytes for `add(1e21, 1)` are the exact
    # digits; a reader that parses JSON numbers into IEEE 754 doubles (any
    # JavaScript one, `JSON.parse` included) collapses them, because the value
    # is above 2**53 - 1 and is not representable. Python's int parse is exact,
    # so the bound belongs to the consumer, never to the encoder here.
    big = 10**21 + 1
    text = _envelope([VectorResult("T1", "V-ENGINE", "arithmetic",
                                   Fraction(big), "number", False, ())], "json-number")
    assert '"value": 1000000000000000000001' in text
    assert json.loads(text)["results"]["T1"]["value"] == big
    # 9007199254740991 = 2**53 - 1, the largest integer a double represents
    # exactly; every ER4 number vector in the corpus except this one is under it.
    assert big > 2**53 - 1
    assert float(big) == float(10**21)
    # The decimal-string encoding is the form that survives a double-typed
    # reader, which is the whole of RFC 8785 section 3.1's recommendation and
    # the whole of ambiguity A1.
    quoted = json.loads(_envelope(
        [VectorResult("T1", "V-ENGINE", "arithmetic", Fraction(big), "number", False, ())],
        "decimal-string"))
    assert quoted["results"]["T1"]["value"] == "1000000000000000000001"


def test_a_not_evaluated_e4_constraint_vector_reports_json_null_not_the_oracles_string() -> None:
    """RESULTS.md A21: this stays the JSON literal `null` for both `value`
    and `value_type` on an E4 constraint-verification vector that was never
    evaluated, even though reading `v-engine-answers.json` directly (a prior
    fix round did, then reverted the read's effect) shows the oracle reports
    `value_type` as the quoted *string* `"null"`. The contract's ER3 schema
    line names only number/string/boolean for an evaluated result and states
    no shape at all for a constraint vector, so there is no contract text
    that would make the string the correct tag; the only source for it was
    the oracle file itself, and ER9 ("a runner MUST NOT read the answer
    oracle to pass") forbids shaping a reported field to match what that read
    showed, whatever it showed. This pins the contract-blind reading (JSON
    `null`) rather than the read-aligned one, and leaves what the E4 tag
    should be an open question for upstream, not something this runner
    infers from the oracle.
    """
    vector = {
        "id": "T1", "category": "V-ENGINE", "node_group": "logic",
        "expr_tree": {"and": [True] * 65},
    }
    result = evaluate_vector(vector)
    assert result.value is None
    assert result.value_type is None
    payload = json.loads(_envelope([result]))
    assert payload["results"]["T1"]["value"] is None
    assert payload["results"]["T1"]["value_type"] is None
