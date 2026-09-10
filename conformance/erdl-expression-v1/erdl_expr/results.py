"""Turn each corpus vector into the ER3 result object, and serialize the file.

ER3 fixes the shape: `{value, value_type, errored, warnings}` with `value_type`
one of number, string, boolean or the literal string `"null"` (the last only
for an E4 constraint-verification vector that was never evaluated;
EXPRESSION-RUNNER-CONTRACT.md, erdl-vectors `a12f352`: "`value_type` is
always a string, never a JSON value ... the literal `"null"` (not JSON
`null`)"). A constraint-verification vector (E4) additionally carries
`threw: true` (ER4, same commit). ER4 compares `value` (a scale-14
fixed-point value for a number, byte equality after NFC for a string),
`errored`, and -- for E4 vectors only -- `threw`; `warnings` is not part of
the equality criteria, so the codes here are diagnostic.

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

    `value_type` is the string `"null"`, never JSON `null`, for an E4
    constraint-verification vector that was never evaluated (RESULTS.md A21,
    re-settled this round): a prior round read `v-engine-answers.json`
    directly (disclosed in `METHOD_READ`), found the oracle emits this tag as
    the quoted string `"null"`, and aligned this field to it, which ER9 ("a
    runner MUST NOT read the answer oracle to pass") then ruled out -- the
    contract text at the time named no shape for a constraint vector at all,
    so the alignment had no textual support and was reverted to JSON `null`.
    The maintainer has since settled it from text, not from that read:
    EXPRESSION-RUNNER-CONTRACT.md (erdl-vectors `a12f352`) now states
    plainly, "`value_type` is always a string, never a JSON value: it is
    `"number"`, `"string"`, `"boolean"`, or -- for E4 throw results -- the
    literal `"null"` (not JSON `null`)." This field is re-applied to that
    sentence, not to the earlier oracle read.

    `threw` is `True` only for the same five E4 structural-ceiling vectors:
    EXPRESSION-RUNNER-CONTRACT.md's ER3/ER4 (`79dd76a` / `a12f352`) states
    the constraint-verification result object as `{value: null, value_type:
    "null", errored: false, threw: true}` and that "for E4
    constraint-verification vectors, `threw` must also match." A vector that
    was actually evaluated always carries `threw: False`; `as_object` and the
    submission writer surface the key only when `True`, matching the
    contract's "constraint-verification vectors (E4) additionally carry
    `threw: true`" wording -- an ordinary evaluated result does not carry
    this field at all.
    """

    vector_id: str
    category: str
    group: str
    value: Value
    value_type: str
    errored: bool
    warnings: tuple[str, ...]
    threw: bool = False

    def as_object(self) -> dict[str, Any]:
        obj: dict[str, Any] = {
            "value": self.value,
            "value_type": self.value_type,
            "errored": self.errored,
            "warnings": list(self.warnings),
        }
        if self.threw:
            obj["threw"] = True
        return obj


def _report(outcome: Outcome) -> tuple[Value, str, bool, tuple[str, ...], bool]:
    """Fold one evaluation outcome into the ER3 reportable domain.

    Returns `(value, value_type, errored, warnings, threw)`.
    """
    if outcome.not_evaluated:
        # EXPRESSION-RUNNER-CONTRACT.md ER3/ER4 (erdl-vectors `fe93f7f` /
        # `a12f352`), "Constraint vectors (E4/E5)": an E4 rejection's
        # `expected` "records whether the constraint was correctly
        # detected/triggered ... not an evaluation result", stated as
        # `{value: null, value_type: "null", errored: false, threw: true}` --
        # so it is reported directly in that shape rather than routed through
        # the errored fold or the missing-value fold below, both of which
        # describe something that was actually evaluated. `value_type` is the
        # literal string `"null"`, per ER3's own words: "`value_type` is
        # always a string, never a JSON value ... the literal `"null"` (not
        # JSON `null`)" -- re-settling RESULTS.md A21's prior contract-blind
        # JSON-`null` reading from that text, not from the earlier
        # oracle read `METHOD_READ` discloses. `threw=True` is the ER4
        # comparison field this same text adds for E4 vectors only.
        return None, "null", False, outcome.warnings, True
    if outcome.errored:
        return False, "boolean", True, outcome.warnings, False
    value = outcome.value
    if isinstance(value, bool):
        return value, "boolean", False, outcome.warnings, False
    if isinstance(value, Fraction):
        return value, "number", False, outcome.warnings, False
    if isinstance(value, str):
        return value, "string", False, outcome.warnings, False
    if isinstance(value, Undefined) or value is None:
        return False, "boolean", False, outcome.warnings + (SAFE_FOLD_UNDEFINED,), False
    return False, "boolean", False, outcome.warnings + (SAFE_FOLD_NON_SCALAR,), False


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
    value, value_type, errored, warnings, threw = _report(outcome)
    return VectorResult(vector_id, category, group, value, value_type, errored, warnings, threw)


def _gloss_result(vector: dict[str, Any], vector_id: str, category: str, group: str,
                  language: str) -> VectorResult:
    # EXPRESSION-RUNNER-CONTRACT.md (erdl-vectors `fe93f7f`), "gloss vectors
    # (V-GLOSS, incl. V-GLOSS-INTEGRITY)": "the `value` is the **gloss
    # string** rendered from the vector's `expr_tree` ... not a boolean.
    # `V-GLOSS-INTEGRITY-*` vectors carry an extra `tampered_tree` field that
    # is **integrity evidence only**; the runner still renders and reports
    # the **original** `expr_tree` gloss ... (it is not evaluated)." This
    # settles RESULTS.md A7's "reading 2" as the contract-text answer,
    # reversing this runner's prior "reading 1" (the tamper-changes-render
    # boolean); `tampered_tree` is read from the vector only to decide the
    # `_group_of` bookkeeping label (`gloss_integrity` vs. `gloss`), never
    # rendered.
    return VectorResult(
        vector_id, category, group, gloss.render(vector.get("expr_tree"), language),
        "string", False, (),
    )


def _projection_result(vector: dict[str, Any], vector_id: str, category: str, group: str,
                       semantics: Semantics) -> VectorResult:
    context = vector.get("context") or {}
    simple_tree = vector.get("simple_compiled_tree")
    other = vector.get("expression_tree")
    if other is None and "decision_table" in vector:
        other = compile_decision_table(dict(vector["decision_table"]))
    first = evaluate_tree(simple_tree, context, semantics)
    second = evaluate_tree(other, context, semantics)
    value, value_type, errored, warnings, threw = _report(first)
    if _report(second)[:3] != (value, value_type, errored):
        # E7: the projections share one evaluation core, so a divergence is a
        # defect in this runner, not a property of the vector.
        raise ValueError(f"{vector_id}: projections disagree")
    return VectorResult(vector_id, category, group, value, value_type, errored, warnings, threw)


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
                # ER3/ER4 (erdl-vectors `fe93f7f`/`a12f352`): "constraint-
                # verification vectors (E4) additionally carry `threw: true`"
                # -- an ordinary evaluated vector's object stays the plain
                # four-field shape, so the key is present only when true.
                **({"threw": True} if result.threw else {}),
            }
            for result in results
        },
    }
