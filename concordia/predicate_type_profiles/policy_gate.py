"""Reference deterministic policy-gate predicate profile."""

IS_DETERMINISTIC = True
CONDITION_SCHEMA = {
    "type": "object",
    "properties": {
        "result": {"enum": ["satisfied", "denied"]},
        "all": {"type": "array"},
        "any": {"type": "array"},
    },
    "required": ["result"],
    "additionalProperties": True,
}
