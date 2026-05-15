"""Reference deterministic procurement-eligibility predicate profile."""

IS_DETERMINISTIC = True
CONDITION_SCHEMA = {
    "type": "object",
    "properties": {
        "result": {"enum": ["satisfied", "denied"]},
        "operation": {"type": "string"},
        "limit": {"type": "object"},
    },
    "required": ["result"],
    "additionalProperties": True,
}
