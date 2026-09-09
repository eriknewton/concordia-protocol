"""Projection D: the deterministic gloss renderer.

G1 makes gloss a render product of the tree, produced by a frozen template per
node (spec section 5.5). G4 keeps it out of the hash, so a wording difference
between implementations does not break cross-implementation consistency, and G2
is the lint that binds a stored gloss to its tree.

Section 5.5 pins the rendering templates to English as canonical (spec v2.1,
2026-09-09); the Chinese column is a presentation-only projection and is no
longer part of the frozen table. English is therefore what a reported gloss
string carries, and `--gloss-language zh` survives only as that presentation
projection. RESULTS.md records the resolution as ambiguity A4.

The English templates below are transcribed from the section 5.5 table at
erdl-spec v2.1 (erdl-landing commit dcb7a55). Fifteen of them were reworded in
that revision, so a template edited here without re-reading that table will
silently change every reported gloss string; the wording is the contract, not a
matter of taste.

G3 (use the Entity `display_name`, never a raw field path) cannot be honoured
from this corpus: the vectors carry no Entity declarations, so there is no
display name to substitute and the raw path is the only available rendering.
That is a bound on the input, not a decision to ignore G3.
"""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
from typing import Any, Final

from .values import decimal_string, nfc, to_fraction

#: Field names matching these prefixes take the boolean-field reading of
#: `exists` (section 5.5 note): "has_been_notified is true", not
#: "has_been_notified exists".
_BOOLEAN_FIELD_PREFIXES: Final[tuple[str, ...]] = ("is_", "has_")

_TEMPLATES: Final[dict[str, dict[str, str]]] = {
    "and": {"en": "{A} and {B}", "zh": "{A} 且 {B}"},
    "or": {"en": "{A} or {B}", "zh": "{A} 或 {B}"},
    "not": {"en": "not ({A})", "zh": "非（{A}）"},
    "eq": {"en": "{A} equals {B}", "zh": "{A} 等于 {B}"},
    "ne": {"en": "{A} does not equal {B}", "zh": "{A} 不等于 {B}"},
    "gt": {"en": "{A} is greater than {B}", "zh": "{A} 大于 {B}"},
    "gte": {"en": "{A} is greater than or equal to {B}", "zh": "{A} 大于等于 {B}"},
    "lt": {"en": "{A} is less than {B}", "zh": "{A} 小于 {B}"},
    "lte": {"en": "{A} is less than or equal to {B}", "zh": "{A} 小于等于 {B}"},
    "in": {"en": "{A} in {B}", "zh": "{A} 属于 {B}"},
    "contains": {"en": "{A} contains {B}", "zh": "{A} 包含 {B}"},
    "match": {"en": "{A} matches {B}", "zh": "{A} 匹配正则 {B}"},
    "starts_with": {"en": "{A} starts with {B}", "zh": "{A} 以 {B} 开头"},
    "ends_with": {"en": "{A} ends with {B}", "zh": "{A} 以 {B} 结尾"},
    "exists": {"en": "{A} exists", "zh": "{A} 已发生"},
    "exists_boolean": {"en": "{A} is true", "zh": "{A} 为“是”"},
    "length": {"en": "length of {A}", "zh": "{A} 的长度"},
    "between": {
        "en": "{A} is in the inclusive range {B} to {C}",
        "zh": "{A} 介于 {B} 与 {C} 之间",
    },
    "all": {"en": 'all elements in {A} satisfy "{B}"', "zh": "{A} 中每一项均满足：{B}"},
    "any": {
        # "satisfy", not "satisfies": the section 5.5 table reads that way and a
        # frozen template is reproduced verbatim, grammar included.
        "en": 'at least one element in {A} satisfy "{B}"',
        "zh": "{A} 中存在一项满足：{B}",
    },
    "none": {"en": 'no elements in {A} satisfy "{B}"', "zh": "{A} 中无一项满足：{B}"},
    "add": {"en": "{A} plus {B}", "zh": "{A} 加 {B}"},
    "sub": {"en": "{A} minus {B}", "zh": "{A} 减 {B}"},
    "mul": {"en": "{A} times {B}", "zh": "{A} 乘 {B}"},
    "div": {"en": "{A} divided by {B}", "zh": "{A} 除以 {B}"},
    "round": {"en": "{A} rounded", "zh": "{A} 四舍五入"},
    "days_between": {"en": "days between {A} and {B}", "zh": "{A} 与 {B} 之间的天数"},
    "epoch_ms": {"en": "epoch ms of {A}", "zh": "{A} 的时间戳"},
    "date_add": {"en": "{A} plus {B} {unit}", "zh": "{A} 加 {B}{unit}"},
    "date_part": {"en": "{part} of {A}", "zh": "{A} 的 {part}"},
    "month_last_day": {
        "en": "the last day of the month of {A}",
        "zh": "{A} 所在月的最后一日",
    },
    "count": {"en": "count of {A}", "zh": "{A} 的元素个数"},
    "sum": {"en": "sum of {A}", "zh": "{A} 之和"},
    "avg": {"en": "average of {A}", "zh": "{A} 的平均值"},
    "min": {"en": "minimum of {A}", "zh": "{A} 的最小值"},
    "max": {"en": "maximum of {A}", "zh": "{A} 的最大值"},
}

LANGUAGES: Final[tuple[str, ...]] = ("en", "zh")
_LIST_SEPARATOR: Final[dict[str, str]] = {"en": ", ", "zh": "、"}


class GlossError(ValueError):
    """A tree that has no frozen template."""


def render(node: Any, language: str = "en") -> str:
    """Render a tree as gloss text, NFC-normalized like every other string."""
    if language not in LANGUAGES:
        raise GlossError(f"unsupported gloss language: {language}")
    return nfc(_render(node, language))


def _template(name: str, language: str) -> str:
    entry = _TEMPLATES.get(name)
    if entry is None:
        raise GlossError(f"no frozen template for node: {name}")
    return entry[language]


def _render(node: Any, language: str) -> str:
    if isinstance(node, dict):
        return _render_node(node, language)
    if isinstance(node, list):
        separator = _LIST_SEPARATOR[language]
        return "[" + separator.join(_render(item, language) for item in node) + "]"
    if isinstance(node, bool):
        return "true" if node else "false"
    if isinstance(node, (int, Decimal, Fraction)):
        # A literal renders at its own magnitude, not padded to scale 14: the
        # gloss is the reading layer, and "age equals 35.00000000000000" is
        # noise. The tree, not the gloss, is what the hash covers (G4).
        return decimal_string(to_fraction(node))
    if isinstance(node, str):
        return nfc(node)
    if node is None:
        return "null"
    raise GlossError(f"unrenderable literal: {type(node).__name__}")


def _render_node(node: dict[str, Any], language: str) -> str:
    keys = set(node)
    if "field" in keys and "operator" not in keys:
        return nfc(str(node["field"]))
    if "var" in keys:
        name = str(node["var"])
        return nfc(name[2:] if name.startswith("$.") else name)
    if "expr" in keys:
        return _render(node["expr"], language)
    if len(keys) != 1:
        raise GlossError(f"ambiguous node keys: {sorted(keys)}")
    (name,) = keys
    payload = node[name]

    if name in {"and", "or"}:
        if not isinstance(payload, list) or not payload:
            raise GlossError(f"{name} needs operands")
        parts = [_render(operand, language) for operand in payload]
        joined = parts[0]
        for part in parts[1:]:
            joined = _template(name, language).replace("{A}", joined).replace("{B}", part)
        return joined
    if name == "not":
        return _template("not", language).replace("{A}", _render(payload, language))
    if name in {"eq", "ne", "gt", "gte", "lt", "lte", "in", "contains", "match",
                "starts_with", "ends_with", "add", "sub", "mul", "div", "days_between"}:
        left, right = _pair(payload, name)
        return (
            _template(name, language)
            .replace("{A}", _render(left, language))
            .replace("{B}", _render(right, language))
        )
    if name == "exists":
        subject = _render(payload, language)
        template = "exists_boolean" if _is_boolean_field(payload) else "exists"
        return _template(template, language).replace("{A}", subject)
    if name in {"length", "epoch_ms", "month_last_day", "count", "sum", "avg", "min", "max"}:
        return _template(name, language).replace("{A}", _render(payload, language))
    if name == "round":
        operand = payload[0] if isinstance(payload, list) and payload else payload
        return _template("round", language).replace("{A}", _render(operand, language))
    if name == "between":
        if not isinstance(payload, list) or len(payload) != 3:
            raise GlossError("between needs three operands")
        return (
            _template("between", language)
            .replace("{A}", _render(payload[0], language))
            .replace("{B}", _render(payload[1], language))
            .replace("{C}", _render(payload[2], language))
        )
    if name in {"all", "any", "none"}:
        if not isinstance(payload, dict):
            raise GlossError(f"{name} needs a binding object")
        return (
            _template(name, language)
            .replace("{A}", _render(payload.get("over"), language))
            .replace("{B}", _render(payload.get("predicate"), language))
        )
    if name == "date_add":
        if not isinstance(payload, dict):
            raise GlossError("date_add needs an object")
        # Section 5.5 spells this template `{A} plus {B} {unit}`: the amount and
        # the unit are two slots, not one pre-joined "duration" string. Keeping
        # them separate is what lets the template own the spacing, which is the
        # only thing that distinguishes the English and Chinese forms here.
        return (
            _template("date_add", language)
            .replace("{A}", _render(payload.get("base"), language))
            .replace("{B}", _render(payload.get("amount"), language))
            .replace("{unit}", str(payload.get("unit")))
        )
    if name == "date_part":
        if not isinstance(payload, dict):
            raise GlossError("date_part needs an object")
        return (
            _template("date_part", language)
            .replace("{part}", str(payload.get("unit")))
            .replace("{A}", _render(payload.get("arg"), language))
        )
    if name == "aggregate":
        if not isinstance(payload, dict):
            raise GlossError("aggregate needs an object")
        return _template(str(payload.get("fn")), language).replace(
            "{A}", _render(payload.get("over"), language)
        )
    raise GlossError(f"no frozen template for node: {name}")


def _pair(payload: Any, name: str) -> tuple[Any, Any]:
    if not isinstance(payload, list) or len(payload) != 2:
        raise GlossError(f"{name} needs two operands")
    return payload[0], payload[1]


def _is_boolean_field(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    path = payload.get("field")
    if not isinstance(path, str):
        return False
    leaf = path.split(".")[-1]
    return leaf.startswith(_BOOLEAN_FIELD_PREFIXES)
