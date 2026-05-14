"""JSON Schema validation for Concordia messages and attestations.

Validates messages against the schemas defined in the specification,
and attestations against the attestation.schema.json.
"""

from __future__ import annotations

import json
from datetime import datetime
import warnings
from pathlib import Path
from typing import Any
from uuid import UUID

import jsonschema

from .attestation import REFERENCE_RELATIONSHIPS, REFERENCE_TYPES

# Path to the bundled schemas directory
_SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"
_FORMAT_CHECKER = jsonschema.FormatChecker()


@_FORMAT_CHECKER.checks("date-time", raises=ValueError)
def _is_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return True
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.tzinfo is not None


@_FORMAT_CHECKER.checks("uuid", raises=ValueError)
def _is_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return True
    UUID(value)
    return True


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
    validator = jsonschema.Draft202012Validator(
        _MESSAGE_SCHEMA,
        format_checker=_FORMAT_CHECKER,
    )
    for error in validator.iter_errors(message):
        errors.append(f"{error.json_path}: {error.message}")
    return errors


def validate_attestation(attestation: dict[str, Any]) -> list[str]:
    """Validate an attestation against attestation.schema.json.

    Returns a list of validation error messages (empty if valid).
    """
    schema = _load_schema("attestation.schema.json")
    errors: list[str] = []
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=_FORMAT_CHECKER,
    )
    for error in validator.iter_errors(attestation):
        errors.append(f"{error.json_path}: {error.message}")
    if not errors:
        _warn_on_noncanonical_references(attestation)
    return errors


def validate_approval_receipt(receipt: dict[str, Any]) -> list[str]:
    """Validate an ApprovalReceipt against approval_receipt.schema.json.

    Returns a list of validation error messages (empty if valid).
    """
    schema = _load_schema("approval_receipt.schema.json")
    errors: list[str] = []
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=_FORMAT_CHECKER,
    )
    for error in validator.iter_errors(receipt):
        errors.append(f"{error.json_path}: {error.message}")
    return errors


def _warn_on_noncanonical_references(attestation: dict[str, Any]) -> None:
    """Warn while preserving unknown references per SPEC §11.5.5 and §11.5.8."""
    references = attestation.get("references") or []
    if not isinstance(references, list):
        return
    for index, ref in enumerate(references):
        if not isinstance(ref, dict):
            continue
        ref_type = ref.get("type")
        if isinstance(ref_type, str) and ref_type not in REFERENCE_TYPES:
            warnings.warn(
                f"references[{index}].type {ref_type!r} is non-canonical; "
                "preserving as opaque string per SPEC §11.5.8",
                UserWarning,
                stacklevel=3,
            )
        relationship = ref.get("relationship")
        if (
            isinstance(relationship, str)
            and relationship not in REFERENCE_RELATIONSHIPS
        ):
            warnings.warn(
                f"references[{index}].relationship {relationship!r} is "
                "non-canonical; preserving as opaque string per SPEC §11.5.8",
                UserWarning,
                stacklevel=3,
            )


def is_valid_message(message: dict[str, Any]) -> bool:
    """Return True if the message passes schema validation."""
    return len(validate_message(message)) == 0


def is_valid_attestation(attestation: dict[str, Any]) -> bool:
    """Return True if the attestation passes schema validation."""
    return len(validate_attestation(attestation)) == 0


def is_valid_approval_receipt(receipt: dict[str, Any]) -> bool:
    """Return True if the ApprovalReceipt passes schema validation."""
    return len(validate_approval_receipt(receipt)) == 0
