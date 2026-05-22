"""JSON Schema validators for CMPC bilateral primitives."""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator, ValidationError  # type: ignore[import-untyped]

from .errors import SchemaValidationError


URN = r"^urn:concordia:"
ANY_ARTIFACT_URN = r"^urn:(concordia|a2cn|ap2|x402|erc8004):"
DID = r"^did:"
ISO_DATETIME = r"^\d{4}-\d{2}-\d{2}T"


CHAIN_SESSION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "chain_session_id",
        "participants",
        "closure_predicate_ref",
        "state",
        "created_at",
        "activation_deadline",
        "activated_at",
        "dissolved_at",
        "commitments",
        "unwind_record_id",
        "activation_proof_id",
    ],
    "additionalProperties": False,
    "properties": {
        "chain_session_id": {"type": "string", "pattern": r"^urn:concordia:chain-session:"},
        "participants": {
            "type": "array",
            "items": {"type": "string", "pattern": DID},
            "minItems": 1,
        },
        "closure_predicate_ref": {"type": "string", "pattern": r"^urn:concordia:predicate:"},
        "state": {
            "type": "string",
            "enum": ["PROPOSED", "OPEN", "ACTIVATED", "DISSOLVED", "EXPIRED"],
        },
        "created_at": {"type": "string", "pattern": ISO_DATETIME},
        "activation_deadline": {"type": "string", "pattern": ISO_DATETIME},
        "activated_at": {"anyOf": [{"type": "string", "pattern": ISO_DATETIME}, {"type": "null"}]},
        "dissolved_at": {"anyOf": [{"type": "string", "pattern": ISO_DATETIME}, {"type": "null"}]},
        "commitments": {
            "type": "array",
            "items": {"type": "string", "pattern": r"^urn:concordia:commitment:"},
        },
        "unwind_record_id": {
            "anyOf": [{"type": "string", "pattern": r"^urn:concordia:unwind:"}, {"type": "null"}]
        },
        "activation_proof_id": {
            "anyOf": [
                {"type": "string", "pattern": r"^urn:concordia:activation-proof:"},
                {"type": "null"},
            ]
        },
    },
}

CONDITIONAL_COMMITMENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "commitment_id",
        "chain_session_id",
        "committer_did",
        "predicate_reference",
        "commitment_terms",
        "mandate_proof_id",
        "issued_at",
        "expires_at",
        "signature",
        "algorithm",
    ],
    "additionalProperties": False,
    "properties": {
        "commitment_id": {"type": "string", "pattern": r"^urn:concordia:commitment:"},
        "chain_session_id": {"type": "string", "pattern": r"^urn:concordia:chain-session:"},
        "committer_did": {"type": "string", "pattern": DID},
        "predicate_reference": {"type": "string", "pattern": r"^urn:concordia:predicate:"},
        "commitment_terms": {"type": "object"},
        "mandate_proof_id": {"anyOf": [{"type": "string", "pattern": URN}, {"type": "null"}]},
        "issued_at": {"type": "string", "pattern": ISO_DATETIME},
        "expires_at": {"type": "string", "pattern": ISO_DATETIME},
        "signature": {"type": "string", "minLength": 1},
        "algorithm": {"type": "string", "enum": ["EdDSA"]},
    },
}

CLOSURE_PREDICATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "predicate_id",
        "type",
        "authority",
        "issuer",
        "subject",
        "condition",
        "issued_at",
        "expires_at",
        "references",
        "algorithm",
        "status",
        "signature",
    ],
    "additionalProperties": True,
    "properties": {
        "predicate_id": {"type": "string", "pattern": r"^urn:concordia:predicate:"},
        "type": {"type": "string", "pattern": r"^urn:concordia:predicate-type:"},
        "authority": {"type": "string", "pattern": DID},
        "issuer": {"type": "string", "pattern": DID},
        "subject": {"type": "string", "pattern": r"^urn:concordia:chain-session:"},
        "condition": {"type": "object"},
        "issued_at": {"type": "string", "pattern": ISO_DATETIME},
        "expires_at": {"type": "string", "pattern": ISO_DATETIME},
        "references": {"type": "array", "items": {"type": "object"}},
        "algorithm": {"type": "string", "enum": ["EdDSA"]},
        "status": {"type": "string", "enum": ["active", "expired", "revoked", "suspended"]},
        "signature": {"type": "string", "minLength": 1},
    },
}

ATOMIC_ACTIVATION_PROOF_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "activation_proof_id",
        "chain_session_id",
        "closure_predicate_id",
        "predicate_evaluation",
        "commitment_ids",
        "activated_at",
        "issuer_did",
        "signature",
        "algorithm",
    ],
    "additionalProperties": False,
    "properties": {
        "activation_proof_id": {"type": "string", "pattern": r"^urn:concordia:activation-proof:"},
        "chain_session_id": {"type": "string", "pattern": r"^urn:concordia:chain-session:"},
        "closure_predicate_id": {"type": "string", "pattern": r"^urn:concordia:predicate:"},
        "predicate_evaluation": {"type": "object"},
        "commitment_ids": {
            "type": "array",
            "items": {"type": "string", "pattern": r"^urn:concordia:commitment:"},
            "minItems": 1,
        },
        "activated_at": {"type": "string", "pattern": ISO_DATETIME},
        "issuer_did": {"type": "string", "pattern": DID},
        "signature": {"type": "string", "minLength": 1},
        "algorithm": {"type": "string", "enum": ["EdDSA"]},
    },
}

UNWIND_RECORD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "unwind_record_id",
        "chain_session_id",
        "dissolution_reason",
        "dissolution_details",
        "affected_commitment_ids",
        "issuer_did",
        "issued_at",
        "counterparty_acknowledgment",
        "signature",
        "algorithm",
    ],
    "additionalProperties": False,
    "properties": {
        "unwind_record_id": {"type": "string", "pattern": r"^urn:concordia:unwind:"},
        "chain_session_id": {"type": "string", "pattern": r"^urn:concordia:chain-session:"},
        "dissolution_reason": {
            "type": "string",
            "enum": ["predicate_failed", "timeout", "explicit_withdrawal", "mandate_violation"],
        },
        "dissolution_details": {"type": "object"},
        "affected_commitment_ids": {
            "type": "array",
            "items": {"type": "string", "pattern": r"^urn:concordia:commitment:"},
        },
        "issuer_did": {"type": "string", "pattern": DID},
        "issued_at": {"type": "string", "pattern": ISO_DATETIME},
        "counterparty_acknowledgment": {"anyOf": [{"type": "object"}, {"type": "null"}]},
        "signature": {"type": "string", "minLength": 1},
        "algorithm": {"type": "string", "enum": ["EdDSA"]},
    },
}

REFERENCE_OBJECT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["id", "type", "relationship"],
    "additionalProperties": True,
    "properties": {
        "id": {"type": "string", "minLength": 1},
        "type": {"type": "string", "minLength": 1},
        "relationship": {"type": "string", "minLength": 1},
        "version": {"type": "string"},
        "signed_at": {"type": "string", "pattern": ISO_DATETIME},
        "signer_did": {"type": "string"},
        "extensions": {"type": "object"},
    },
}

REVOCATION_RECORD_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:concordia:schema:revocation_record:v0.7",
    "type": "object",
    "required": [
        "revocation_id",
        "revoked_artifact_id",
        "revoked_artifact_type",
        "revocation_scope",
        "issuer_did",
        "issued_at",
        "effective_at",
        "reason",
        "references",
        "cascade_depth",
        "signature",
    ],
    "additionalProperties": False,
    "properties": {
        "revocation_id": {"type": "string", "pattern": r"^urn:concordia:revocation:"},
        "revoked_artifact_id": {"type": "string", "pattern": ANY_ARTIFACT_URN},
        "revoked_artifact_type": {
            "type": "string",
            "enum": [
                "mandate",
                "commitment",
                "approval_receipt",
                "predicate",
                "attestation",
                "chain_session",
            ],
        },
        "revocation_scope": {
            "type": "string",
            "enum": ["single_artifact", "cascade_to_dependents"],
        },
        "issuer_did": {"type": "string", "pattern": DID},
        "issued_at": {"type": "string", "pattern": ISO_DATETIME},
        "effective_at": {"type": "string", "pattern": ISO_DATETIME},
        "reason": {"type": "string", "minLength": 1},
        "references": {
            "type": "array",
            "minItems": 1,
            "items": REFERENCE_OBJECT_SCHEMA,
            "contains": {
                "type": "object",
                "required": ["id", "relationship"],
                "properties": {
                    "relationship": {"const": "revokes"},
                    "id": {"type": "string"},
                },
            },
        },
        "cascade_depth": {"type": "integer", "minimum": 0, "maximum": 8, "default": 3},
        "signature": {
            "type": "object",
            "required": ["alg", "value"],
            "additionalProperties": False,
            "properties": {
                "alg": {"type": "string", "enum": ["EdDSA"]},
                "value": {"type": "string", "minLength": 1},
            },
        },
        "supersedes": {"type": "string", "pattern": r"^urn:concordia:revocation:"},
        "extensions": {"type": "object", "additionalProperties": True},
    },
}


def _validate(schema: dict[str, Any], data: dict[str, Any]) -> None:
    try:
        Draft202012Validator(schema).validate(data)
    except ValidationError as exc:
        path = ".".join(str(part) for part in exc.absolute_path)
        where = f" at {path}" if path else ""
        raise SchemaValidationError(f"{exc.message}{where}") from exc


def validate_chain_session(data: dict[str, Any]) -> None:
    _validate(CHAIN_SESSION_SCHEMA, data)


def validate_conditional_commitment(data: dict[str, Any]) -> None:
    _validate(CONDITIONAL_COMMITMENT_SCHEMA, data)


def validate_closure_predicate(data: dict[str, Any]) -> None:
    _validate(CLOSURE_PREDICATE_SCHEMA, data)


def validate_atomic_activation_proof(data: dict[str, Any]) -> None:
    _validate(ATOMIC_ACTIVATION_PROOF_SCHEMA, data)


def validate_unwind_record(data: dict[str, Any]) -> None:
    _validate(UNWIND_RECORD_SCHEMA, data)


def validate_revocation_record(data: dict[str, Any]) -> None:
    _validate(REVOCATION_RECORD_SCHEMA, data)
    revoked_artifact_id = data["revoked_artifact_id"]
    if not any(
        ref.get("relationship") == "revokes" and ref.get("id") == revoked_artifact_id
        for ref in data["references"]
        if isinstance(ref, dict)
    ):
        raise SchemaValidationError("references must include a revokes link to revoked_artifact_id")
