"""JSON Schema validation for Concordia messages and attestations.

Validates messages against the schemas defined in the specification,
and attestations against the attestation.schema.json.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
import warnings
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import jsonschema

from .attestation import REFERENCE_RELATIONSHIPS, REFERENCE_TYPES

# Path to the bundled schemas directory.
#
# In an installed wheel the schemas are force-included INSIDE the package at
# ``concordia/schemas`` (see pyproject ``[tool.hatch.build.targets.wheel]``),
# so they resolve next to this module. In a source checkout that packaged copy
# does not exist on disk, so we fall back to the repo-root ``schemas/`` tree.
# Without the packaged copy, every schema-backed validator (attestation,
# approval-receipt, fulfillment, message) raised FileNotFoundError for pip
# users while passing in dev — a silent product-breaking gap.
_PACKAGED_SCHEMAS_DIR = Path(__file__).resolve().parent / "schemas"
_REPO_SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"
_SCHEMAS_DIR = (
    _PACKAGED_SCHEMAS_DIR if _PACKAGED_SCHEMAS_DIR.is_dir() else _REPO_SCHEMAS_DIR
)
_FORMAT_CHECKER = jsonschema.FormatChecker()
_FREE_TEXT_TERM_ERROR = (
    "free-text field must not contain obvious raw deal terms"
)
_RAW_TERM_PATTERNS = (
    re.compile(r"[$€£¥]\s*\d", re.IGNORECASE),
    re.compile(r"\b(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|CNY|INR)\s*\d", re.IGNORECASE),
    re.compile(r"\b\d+(?:[.,]\d+)?\s*(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|CNY|INR)\b", re.IGNORECASE),
    re.compile(r"\bprice\s*:", re.IGNORECASE),
    re.compile(r"\b(?:qty|quantity)\s*[:=]?\s*\d+\b", re.IGNORECASE),
    re.compile(r"\b\d+\s*(?:units?|items?|pcs|pieces)\b", re.IGNORECASE),
)


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
        return cast(dict[str, Any], json.load(f))


# Schema-side constraint values (patterns, enum lists, subschemas) can be
# long; truncate the rendering so error strings stay log-friendly. The
# truncation only ever drops schema-side text, never instance content.
_MAX_CONSTRAINT_RENDER_LENGTH = 120


def _format_validation_error(error: jsonschema.ValidationError) -> str:
    """Format a jsonschema ValidationError without echoing the instance.

    jsonschema's default ``error.message`` embeds the rejected instance
    value for pattern / maxLength / enum / type / oneOf failures, so
    building errors from it can echo raw rejected deal text back through
    MCP responses and logs (parse-boundary posture: never echo
    attacker-controlled input). Instead, report the JSON path plus the
    violated constraint: the validator keyword and its schema-side value.

    ``required`` failures keep the upstream message because it names only
    schema-side property names, never instance content, and the missing
    property name is the whole diagnostic.
    """
    if error.validator == "required":
        return f"{error.json_path}: {error.message}"
    keyword = error.validator if error.validator is not None else "schema"
    try:
        rendered = json.dumps(error.validator_value, sort_keys=True)
    except (TypeError, ValueError):
        rendered = "<unrenderable>"
    if len(rendered) > _MAX_CONSTRAINT_RENDER_LENGTH:
        rendered = rendered[:_MAX_CONSTRAINT_RENDER_LENGTH] + "..."
    return f"{error.json_path}: violates '{keyword}' constraint: {rendered}"


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
        errors.append(_format_validation_error(error))
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
        errors.append(_format_validation_error(error))
    errors.extend(_validate_attestation_free_text(attestation))
    if not errors:
        _warn_on_noncanonical_references(attestation)
    return errors


def validate_fulfillment_attestation(attestation: dict[str, Any]) -> list[str]:
    """Validate a standalone FulfillmentAttestation artifact.

    JSON Schema enforces the presence of a fulfills reference. This
    companion check enforces the local equality invariant between that
    canonical reference and ``agreement_attestation_id``.
    """
    schema = _load_schema("fulfillment_attestation.schema.json")
    errors: list[str] = []
    validator = jsonschema.Draft202012Validator(schema)
    for error in validator.iter_errors(attestation):
        errors.append(_format_validation_error(error))

    agreement_id = attestation.get("agreement_attestation_id")
    references = attestation.get("references", [])
    if isinstance(agreement_id, str) and isinstance(references, list):
        fulfills_targets = [
            ref.get("id")
            for ref in references
            if isinstance(ref, dict) and ref.get("relationship") == "fulfills"
        ]
        if fulfills_targets and agreement_id not in fulfills_targets:
            errors.append(
                "$.references: fulfills reference id must equal "
                "agreement_attestation_id"
            )

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
        errors.append(_format_validation_error(error))
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


def _validate_attestation_free_text(attestation: Any) -> list[str]:
    """Best-effort defense-in-depth check for raw terms in attestation text.

    The schema rejects structured term fields. This scanner is intentionally
    narrower: it catches obvious accidental raw-term strings without treating
    free text as the privacy guarantee, and without echoing matched content.
    """
    if not isinstance(attestation, dict):
        return []

    errors: list[str] = []
    candidates: list[tuple[str, Any]] = [
        ("$.summary", attestation.get("summary")),
    ]

    fulfillment = attestation.get("fulfillment")
    if isinstance(fulfillment, dict):
        disputes = fulfillment.get("disputes")
        if isinstance(disputes, list):
            for index, dispute in enumerate(disputes):
                if isinstance(dispute, dict):
                    candidates.append(
                        (
                            f"$.fulfillment.disputes[{index}].description",
                            dispute.get("description"),
                        )
                    )
        counterparty = fulfillment.get("counterparty_attestation")
        if isinstance(counterparty, dict):
            candidates.append(
                (
                    "$.fulfillment.counterparty_attestation.notes",
                    counterparty.get("notes"),
                )
            )

    for path, value in candidates:
        if isinstance(value, str) and _contains_obvious_raw_term(value):
            errors.append(f"{path}: {_FREE_TEXT_TERM_ERROR}")
    return errors


def _contains_obvious_raw_term(value: str) -> bool:
    return any(pattern.search(value) for pattern in _RAW_TERM_PATTERNS)


def is_valid_message(message: dict[str, Any]) -> bool:
    """Return True if the message passes schema validation."""
    return len(validate_message(message)) == 0


def is_valid_attestation(attestation: dict[str, Any]) -> bool:
    """Return True if the attestation passes schema validation."""
    return len(validate_attestation(attestation)) == 0


def is_valid_fulfillment_attestation(attestation: dict[str, Any]) -> bool:
    """Return True if the FulfillmentAttestation passes all validation."""
    return len(validate_fulfillment_attestation(attestation)) == 0


def is_valid_approval_receipt(receipt: dict[str, Any]) -> bool:
    """Return True if the ApprovalReceipt passes schema validation."""
    return len(validate_approval_receipt(receipt)) == 0
