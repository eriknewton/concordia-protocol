"""JSON Schema validation for Concordia messages and attestations.

Validates messages against the schemas defined in the specification,
and attestations against the attestation.schema.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

# Path to the bundled schemas directory
_SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"


def _load_schema(name: str) -> dict[str, Any]:
    """Load a JSON schema from the schemas directory."""
    path = _SCHEMAS_DIR / name
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Message envelope schema (derived from §4.1)
# ---------------------------------------------------------------------------

_MESSAGE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["concordia", "type", "id", "session_id", "timestamp", "from", "body", "signature"],
    "properties": {
        "concordia": {
            "type": "string",
            "pattern": r"^\d+\.\d+\.\d+$",
        },
        "type": {
            "type": "string",
            "enum": [
                "negotiate.open",
                "negotiate.accept_session",
                "negotiate.decline_session",
                "negotiate.offer",
                "negotiate.counter",
                "negotiate.accept",
                "negotiate.reject",
                "negotiate.inquire",
                "negotiate.constrain",
                "negotiate.signal",
                "negotiate.withdraw",
                "negotiate.propose_mediator",
                "negotiate.resolve",
                "negotiate.commit",
            ],
        },
        "id": {"type": "string", "minLength": 1},
        "session_id": {"type": "string", "minLength": 1},
        "timestamp": {"type": "string", "format": "date-time"},
        "from": {
            "type": "object",
            "required": ["agent_id"],
            "properties": {
                "agent_id": {"type": "string", "minLength": 1},
                "principal_id": {"type": ["string", "null"]},
            },
        },
        "to": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["agent_id"],
                "properties": {
                    "agent_id": {"type": "string"},
                },
            },
        },
        "body": {"type": "object"},
        "signature": {"type": "string"},
        "prev_hash": {"type": "string"},
        "in_reply_to": {"type": "string"},
        "thread": {"type": "string"},
        "ttl": {"type": "integer", "minimum": 0},
        "reasoning": {"type": "string"},
    },
}


def validate_message(message: dict[str, Any]) -> list[str]:
    """Validate a Concordia message against the envelope schema.

    Returns a list of validation error messages (empty if valid).
    """
    errors: list[str] = []
    validator = jsonschema.Draft202012Validator(_MESSAGE_SCHEMA)
    for error in validator.iter_errors(message):
        errors.append(f"{error.json_path}: {error.message}")
    return errors


def validate_attestation(attestation: dict[str, Any]) -> list[str]:
    """Validate an attestation against attestation.schema.json.

    Returns a list of validation error messages (empty if valid).
    """
    schema = _load_schema("attestation.schema.json")
    errors: list[str] = []
    validator = jsonschema.Draft202012Validator(schema)
    for error in validator.iter_errors(attestation):
        errors.append(f"{error.json_path}: {error.message}")
    return errors


def is_valid_message(message: dict[str, Any]) -> bool:
    """Return True if the message passes schema validation."""
    return len(validate_message(message)) == 0


def is_valid_attestation(attestation: dict[str, Any]) -> bool:
    """Return True if the attestation passes schema validation."""
    return len(validate_attestation(attestation)) == 0
