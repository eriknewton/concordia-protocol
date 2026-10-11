"""JSON Schema regex translation shared by the Python conformance tools."""

from __future__ import annotations

import copy
from typing import Any

SCHEMA_MAP_KEYWORDS = frozenset(
    {
        "$defs",
        "definitions",
        "dependentSchemas",
        "properties",
    }
)
SCHEMA_VALUE_KEYWORDS = frozenset(
    {
        "additionalItems",
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    }
)
SCHEMA_ARRAY_KEYWORDS = frozenset({"allOf", "anyOf", "oneOf", "prefixItems"})


def json_schema_pattern_for_python(pattern: str) -> str:
    """Translate JSON Schema's true-end `$` anchor to Python `re` semantics."""
    translated: list[str] = []
    escaped = False
    in_character_class = False
    class_members = 0
    class_can_be_negated = False
    for char in pattern:
        if escaped:
            translated.append(char)
            escaped = False
            if in_character_class:
                class_members += 1
                class_can_be_negated = False
            continue
        if char == "\\":
            translated.append(char)
            escaped = True
            continue
        if char == "[" and not in_character_class:
            in_character_class = True
            class_members = 0
            class_can_be_negated = True
            translated.append(char)
            continue
        if in_character_class:
            if char == "^" and class_can_be_negated and class_members == 0:
                translated.append(char)
                class_can_be_negated = False
                continue
            class_can_be_negated = False
            if char == "]":
                # ECMAScript and Python disagree on empty and leading-`]`
                # classes, so the Python runner refuses instead of guessing.
                if class_members == 0:
                    raise ValueError("ambiguous JSON Schema character class")
                in_character_class = False
                translated.append(char)
                continue
            translated.append(char)
            class_members += 1
            continue
        if char == "$":
            translated.append(r"\Z")
            continue
        translated.append(char)
    return "".join(translated)


def rewrite_json_schema_patterns_for_python(schema: Any) -> Any:
    """Return a schema copy with regex keywords translated for Python `re`."""
    if isinstance(schema, bool):
        return schema
    if isinstance(schema, list):
        return [rewrite_json_schema_patterns_for_python(item) for item in schema]
    if not isinstance(schema, dict):
        return copy.deepcopy(schema)

    rewritten: dict[str, Any] = {}
    for key, value in schema.items():
        if key == "pattern" and isinstance(value, str):
            rewritten[key] = json_schema_pattern_for_python(value)
        elif key == "patternProperties" and isinstance(value, dict):
            rewritten[key] = {
                json_schema_pattern_for_python(pattern): rewrite_json_schema_patterns_for_python(
                    subschema
                )
                for pattern, subschema in value.items()
            }
        elif key in SCHEMA_MAP_KEYWORDS and isinstance(value, dict):
            rewritten[key] = {
                name: rewrite_json_schema_patterns_for_python(subschema)
                for name, subschema in value.items()
            }
        elif key in SCHEMA_VALUE_KEYWORDS:
            rewritten[key] = rewrite_json_schema_patterns_for_python(value)
        elif key in SCHEMA_ARRAY_KEYWORDS and isinstance(value, list):
            rewritten[key] = [
                rewrite_json_schema_patterns_for_python(subschema)
                for subschema in value
            ]
        else:
            rewritten[key] = copy.deepcopy(value)
    return rewritten
