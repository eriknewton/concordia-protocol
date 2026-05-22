"""ApprovalReceipt verification for Concordia v0.5."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .schema_validator import validate_approval_receipt
from .signing import canonical_json, verify_signature

ApprovalDecision = Literal["approve", "deny"]

SCHEMA_INVALID = "schema_invalid"
SIGNATURE_INVALID = "signature_invalid"
EXPIRED = "expired"
OFFER_HASH_MISMATCH = "offer_hash_mismatch"
MISSING_APPROVES_REFERENCE = "missing_approves_reference"
REVOKED = "revoked"

_NEGOTIATION_SESSION_TYPES = {"negotiation_session", "a2cn:negotiation_session"}


@dataclass
class ApprovalReceiptResult:
    """Typed result returned by ApprovalReceipt verification."""

    valid: bool
    decision: ApprovalDecision | None = None
    failure_reason: str | None = None
    receipt_id: str | None = None
    approver: str | None = None
    references: list[dict[str, Any]] = field(default_factory=list)
    checks: dict[str, bool] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "valid": self.valid,
            "decision": self.decision,
            "failure_reason": self.failure_reason,
            "receipt_id": self.receipt_id,
            "approver": self.approver,
            "references": self.references,
            "checks": self.checks,
            "errors": self.errors,
        }


def _has_approves_reference(receipt: dict[str, Any]) -> bool:
    references = receipt.get("references", [])
    if not isinstance(references, list):
        return False
    for reference in references:
        if not isinstance(reference, dict):
            continue
        if (
            reference.get("relationship") == "approves"
            and reference.get("type") in _NEGOTIATION_SESSION_TYPES
        ):
            return True
    return False


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _offer_hash(offer: dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(offer)).hexdigest()
    return f"sha256:{digest}"


def _public_key_from_bytes(
    public_key: bytes | Ed25519PublicKey | None,
) -> Ed25519PublicKey | None:
    if isinstance(public_key, Ed25519PublicKey):
        return public_key
    if isinstance(public_key, bytes):
        try:
            return Ed25519PublicKey.from_public_bytes(public_key)
        except ValueError:
            return None
    return None


def verify_approval_receipt(
    receipt: dict[str, Any],
    offer: dict[str, Any],
    *,
    now: datetime | None = None,
    issuer_public_key: bytes | Ed25519PublicKey | None = None,
    revocation_records: Mapping[str, Any] | None = None,
) -> ApprovalReceiptResult:
    """Verify a signed ApprovalReceipt against schema, signature, and offer."""
    scope = receipt.get("scope", {})
    approver = receipt.get("approver", {})
    result = ApprovalReceiptResult(
        valid=False,
        decision=scope.get("decision") if isinstance(scope, dict) else None,
        receipt_id=receipt.get("id"),
        approver=approver.get("identity") if isinstance(approver, dict) else None,
        references=receipt.get("references", [])
        if isinstance(receipt.get("references", []), list)
        else [],
    )

    schema_errors = validate_approval_receipt(receipt)
    result.checks["schema"] = not schema_errors
    if schema_errors:
        result.errors.extend(schema_errors)
        if not _has_approves_reference(receipt):
            result.failure_reason = MISSING_APPROVES_REFERENCE
            result.checks["approves_reference"] = False
        else:
            result.failure_reason = SCHEMA_INVALID
        return result

    result.checks["approves_reference"] = _has_approves_reference(receipt)
    if not result.checks["approves_reference"]:
        result.failure_reason = MISSING_APPROVES_REFERENCE
        result.errors.append("Missing approves reference for negotiation session")
        return result

    signature = receipt.get("signature", {})
    if not isinstance(signature, dict) or signature.get("alg") != "Ed25519":
        result.checks["signature"] = False
        result.failure_reason = SIGNATURE_INVALID
        result.errors.append("ApprovalReceipt signature must use Ed25519")
        return result

    public_key = _public_key_from_bytes(issuer_public_key)
    if public_key is None:
        result.checks["signature"] = False
        result.failure_reason = SIGNATURE_INVALID
        result.errors.append("Missing or invalid Ed25519 issuer public key")
        return result

    result.checks["signature"] = verify_signature(
        receipt,
        signature.get("value", ""),
        public_key,
        alg="EdDSA",
    )
    if not result.checks["signature"]:
        result.failure_reason = SIGNATURE_INVALID
        result.errors.append("Invalid ApprovalReceipt signature")
        return result

    expires_at = _parse_datetime(receipt["expires_at"])
    result.checks["not_expired"] = expires_at >= _normalize_now(now)
    if not result.checks["not_expired"]:
        result.failure_reason = EXPIRED
        result.errors.append("ApprovalReceipt expired")
        return result

    if revocation_records:
        from concordia.cmpc.revocation import find_revocation_for_references

        revocation = find_revocation_for_references(
            result.references,
            revocation_records,
            now=_normalize_now(now),
        )
        if revocation is not None:
            result.checks["revocation_records"] = False
            result.failure_reason = REVOKED
            result.errors.append(f"Referenced artifact revoked by {revocation.revocation_id}")
            return result
        result.checks["revocation_records"] = True

    expected_hash = _offer_hash(offer)
    result.checks["offer_hash"] = scope["offer_hash"] == expected_hash
    if not result.checks["offer_hash"]:
        result.failure_reason = OFFER_HASH_MISMATCH
        result.errors.append(
            f"Offer hash mismatch: receipt={scope['offer_hash']} computed={expected_hash}"
        )
        return result

    result.valid = True
    result.failure_reason = None
    return result
