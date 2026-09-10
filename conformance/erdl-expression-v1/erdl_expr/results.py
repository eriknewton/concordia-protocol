"""Turn each corpus vector into the ER3 result object, and serialize the file.

ER3 fixes the shape: `{value, value_type, errored, warnings}` with `value_type`
one of number, string or boolean. ER4 compares `value` (a scale-14 fixed-point
integer for a number, byte equality after NFC for a string) and `errored`;
`warnings` is not part of the equality criteria, so the codes here are
diagnostic.

A value outside the three reportable types is folded rather than invented. An
array, an object, a JSON null and the missing-field sentinel all fold to
`false`: E11 and section 7.3(b) make safe failure the direction, and false is
the safe direction for anything a condition cannot consume.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Final

from . import gloss
from .errors import SAFE_FOLD_NON_SCALAR, SAFE_FOLD_UNDEFINED
from .evaluator import DEFAULT_SEMANTICS, Outcome, Semantics, evaluate_tree
from .simple import compile_decision_table, compile_simple
from .temporal import run_state_ops
from .values import Undefined, Value, decimal_string, load_json_exact

#: How a reported number is written into the submission file. Ambiguity A1 was
#: settled 2026-09-10 by the upstream maintainer: contract ER3
#: (`EXPRESSION-RUNNER-CONTRACT.md`, upstream `b56c1c2`) now reads "a decimal
#: string (RFC 8785 §3.1) ... not a JSON number" — the prior contract text (a
#: JSON number) was itself the stale reading, corrected to align with the
#: v1.6.0 CHANGELOG it had drifted from. `decimal-string` is therefore the
#: default; `json-number` is kept only as the superseded alternate encoding for
#: comparison. RESULTS.md A1.
NUMBER_FORMATS: Final[tuple[str, ...]] = ("decimal-string", "json-number")

#: A JSON number cannot be emitted through `json.dumps` at arbitrary precision
#: without going through `float`, which would destroy 1e21 + 1 and every
#: fourteenth decimal place. Numbers are therefore emitted as this sentinel and
#: unquoted afterwards. The writer refuses to run if the sentinel appears inside
#: any string value, so the substitution cannot corrupt real content.
_SENTINEL_PREFIX: Final[str] = "@@ERDL-NUM:"
_SENTINEL_SUFFIX: Final[str] = "@@"
_SENTINEL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r'"' + re.escape(_SENTINEL_PREFIX) + r"(-?\d+(?:\.\d+)?)" + re.escape(_SENTINEL_SUFFIX) + r'"'
)


@dataclass(frozen=True)
class VectorResult:
    """One vector's ER3 result plus the bookkeeping the report needs.

    `value_type` is `None` only for an E4 constraint-verification vector
    (RESULTS.md A21): it was never evaluated, so it has no reportable type,
    which is a different condition from an evaluated `value_type: "boolean"`
    result of `false`. The contract's ER3 schema line names only
    number/string/boolean for an evaluated result and states no shape for a
    constraint vector at all, so JSON `null` is the contract-blind reading
    here, not a copy of the oracle's own choice: a fix round read
    `v-engine-answers.json` directly, found it emits this tag as the quoted
    string `"null"`, and aligned this field to that string, which ER9 ("a
    runner MUST NOT read the answer oracle to pass") rules out regardless of
    what the file said. That alignment is reverted; the read is disclosed in
    `METHOD_READ` and RESULTS.md A21, and what tag an E4 constraint vector
    should carry is left an open question for upstream to settle from text,
    not from the oracle.
    """

    vector_id: str
    category: str
    group: str
    value: Value
    value_type: str | None
    errored: bool
    warnings: tuple[str, ...]

    def as_object(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "value_type": self.value_type,
            "errored": self.errored,
            "warnings": list(self.warnings),
        }


def _report(outcome: Outcome) -> tuple[Value, str | None, bool, tuple[str, ...]]:
    """Fold one evaluation outcome into the ER3 reportable domain."""
    if outcome.not_evaluated:
        # EXPRESSION-RUNNER-CONTRACT.md (b56c1c2) "Constraint vectors
        # (E4/E5)": an E4 rejection's `expected` "records whether the
        # constraint was correctly detected/triggered ... not an evaluation
        # result", so it is reported as a literal null value/type rather than
        # routed through the errored fold or the missing-value fold below,
        # both of which describe something that was actually evaluated. The
        # `value_type` tag stays JSON `null`, not a quoted string: a prior
        # round read `v-engine-answers.json` directly and aligned this tag to
        # the oracle's own `"null"` string, which ER9 forbids regardless of
        # what the file said; that alignment is reverted, the read stays
        # disclosed in `METHOD_READ`, and the correct tag for an E4
        # constraint vector is left open for upstream. RESULTS.md A21.
        return None, None, False, outcome.warnings
    if outcome.errored:
        return False, "boolean", True, outcome.warnings
    value = outcome.value
    if isinstance(value, bool):
        return value, "boolean", False, outcome.warnings
    if isinstance(value, Fraction):
        return value, "number", False, outcome.warnings
    if isinstance(value, str):
        return value, "string", False, outcome.warnings
    if isinstance(value, Undefined) or value is None:
        return False, "boolean", False, outcome.warnings + (SAFE_FOLD_UNDEFINED,)
    return False, "boolean", False, outcome.warnings + (SAFE_FOLD_NON_SCALAR,)


def _group_of(vector: dict[str, Any]) -> str:
    """The reporting group: node group, constraint id, or vector family."""
    category = str(vector.get("category", ""))
    subcategory = vector.get("subcategory")
    if category == "V-PROJ":
        return "projection"
    if category == "V-GLOSS":
        return "gloss_integrity" if "tampered_tree" in vector else "gloss"
    if subcategory == "constraint":
        return f"constraint:{vector.get('constraint')}"
    if subcategory in {"simple-compile", "simple-modifier"}:
        return "simple_compile"
    return str(vector.get("node_group", "unknown"))


def _canonical(node: Any) -> str:
    """A stable textual form for comparing two trees for structural identity."""
    return json.dumps(node, sort_keys=True, default=str, ensure_ascii=False)


def evaluate_vector(vector: dict[str, Any], semantics: Semantics = DEFAULT_SEMANTICS,
                    language: str = "en") -> VectorResult:
    """Produce the ER3 result for one vector, whichever family it belongs to."""
    vector_id = str(vector["id"])
    category = str(vector.get("category", ""))
    group = _group_of(vector)
    context = vector.get("context") or {}

    if category == "V-GLOSS":
        return _gloss_result(vector, vector_id, category, group, language)
    if category == "V-PROJ":
        return _projection_result(vector, vector_id, category, group, semantics)
    if "state_ops" in vector:
        # A stateful modifier vector: the verdict is the Guard state manager's,
        # and no expression tree is involved (section 5.2, E1).
        verdict = run_state_ops(list(vector["state_ops"]))
        return VectorResult(vector_id, category, group, verdict, "boolean", False, ())
    if "compiled_tree" in vector and "expr_tree" not in vector:
        # A Simple-compile vector. The tree evaluated here is the one THIS
        # runner compiles from the operator triple, not the one the corpus
        # supplies; test_simple_compile.py asserts the two agree for all 28, so
        # a compiler defect surfaces as a failed test rather than as a silent
        # fallback onto the corpus's answer.
        tree = compile_simple(vector)
        outcome = evaluate_tree(tree, context, semantics)
    else:
        outcome = evaluate_tree(vector.get("expr_tree"), context, semantics)
    value, value_type, errored, warnings = _report(outcome)
    return VectorResult(vector_id, category, group, value, value_type, errored, warnings)


def _gloss_result(vector: dict[str, Any], vector_id: str, category: str, group: str,
                  language: str) -> VectorResult:
    rendered = gloss.render(vector.get("expr_tree"), language)
    tampered = vector.get("tampered_tree")
    if tampered is None:
        return VectorResult(vector_id, category, group, rendered, "string", False, ())
    # An integrity vector asserts the property "tampering the tree changes the
    # gloss" (G2), so the reportable value is that property, not either gloss.
    # RESULTS.md records the other reading (report the untampered gloss) as
    # ambiguity A7.
    changed = gloss.render(tampered, language) != rendered
    return VectorResult(vector_id, category, group, changed, "boolean", False, ())


def _projection_result(vector: dict[str, Any], vector_id: str, category: str, group: str,
                       semantics: Semantics) -> VectorResult:
    context = vector.get("context") or {}
    simple_tree = vector.get("simple_compiled_tree")
    other = vector.get("expression_tree")
    if other is None and "decision_table" in vector:
        other = compile_decision_table(dict(vector["decision_table"]))
    first = evaluate_tree(simple_tree, context, semantics)
    second = evaluate_tree(other, context, semantics)
    value, value_type, errored, warnings = _report(first)
    if _report(second)[:3] != (value, value_type, errored):
        # E7: the projections share one evaluation core, so a divergence is a
        # defect in this runner, not a property of the vector.
        raise ValueError(f"{vector_id}: projections disagree")
    return VectorResult(vector_id, category, group, value, value_type, errored, warnings)


def load_corpus(path: str) -> dict[str, Any]:
    """Load the vector file with exact numeric literals."""
    with open(path, "rb") as handle:
        raw = handle.read()
    document = load_json_exact(raw.decode("utf-8"))
    if not isinstance(document, dict) or "vectors" not in document:
        raise ValueError(f"{path} is not an ERDL vector file")
    return document


def corpus_sha256(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def evaluate_corpus(document: dict[str, Any], semantics: Semantics = DEFAULT_SEMANTICS,
                    language: str = "en") -> list[VectorResult]:
    """Evaluate every vector in the corpus.

    The semantics assertion is the guard that keeps a test-only switch out of a
    published artifact: the sentinel tests construct a deliberately wrong
    `Semantics`, and nothing that writes a submission may run with one.
    """
    if semantics != DEFAULT_SEMANTICS:
        raise ValueError("a corpus run must use the specification's semantics")
    return [evaluate_vector(vector, semantics, language) for vector in document["vectors"]]


class _RawNumber:
    """A number to be emitted unquoted, carrying its exact decimal token."""

    __slots__ = ("token",)

    def __init__(self, token: str) -> None:
        self.token = token


def _encodable(value: Value, number_format: str) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, Fraction):
        token = decimal_string(value)
        if number_format == "decimal-string":
            return token
        return _RawNumber(token)
    return value


def dumps(payload: dict[str, Any]) -> str:
    """Serialize a payload whose numbers are `_RawNumber` placeholders."""

    def default(obj: Any) -> Any:
        if isinstance(obj, _RawNumber):
            return f"{_SENTINEL_PREFIX}{obj.token}{_SENTINEL_SUFFIX}"
        raise TypeError(f"not serializable: {type(obj).__name__}")

    # Checked BEFORE serializing, not after: a string value carrying the marker
    # would be unquoted by the substitution below and would leave no residue to
    # detect afterwards, so a post-hoc check would pass on the corrupted output.
    _reject_sentinel_in_strings(payload)
    text = json.dumps(payload, indent=2, ensure_ascii=False, default=default)
    unquoted = _SENTINEL_PATTERN.sub(lambda match: match.group(1), text)
    if _SENTINEL_PREFIX in unquoted:
        raise ValueError("number sentinel survived serialization")
    return unquoted + "\n"


def _reject_sentinel_in_strings(node: Any) -> None:
    if isinstance(node, str):
        if _SENTINEL_PREFIX in node:
            raise ValueError("a string value carries the number sentinel")
        return
    if isinstance(node, dict):
        for key, value in node.items():
            _reject_sentinel_in_strings(key)
            _reject_sentinel_in_strings(value)
        return
    if isinstance(node, list):
        for item in node:
            _reject_sentinel_in_strings(item)


def submission_payload(
    results: list[VectorResult],
    *,
    runner: str,
    method: str,
    date: str,
    artifact: str,
    number_format: str = "decimal-string",
) -> dict[str, Any]:
    """Build the expression-layer submission envelope."""
    if number_format not in NUMBER_FORMATS:
        raise ValueError(f"unknown number format: {number_format}")
    return {
        "runner": runner,
        "method": method,
        "date": date,
        "artifact": artifact,
        "layer": "expression",
        "vector_file": "v-engine-vectors.json",
        "vector_count": len(results),
        "number_format": number_format,
        "results": {
            result.vector_id: {
                "value": _encodable(result.value, number_format),
                "value_type": result.value_type,
                "errored": result.errored,
                "warnings": list(result.warnings),
            }
            for result in results
        },
    }
