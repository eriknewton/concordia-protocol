"""Reference deterministic authority-gate predicate profile."""

IS_DETERMINISTIC = True
CONDITION_SCHEMA = {
    "type": "object",
    "properties": {"result": {"enum": ["satisfied", "denied"]}},
    "required": ["result"],
    "additionalProperties": True,
}
