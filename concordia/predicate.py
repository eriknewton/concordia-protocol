"""Concordia v0.6 signed predicate primitive."""

from __future__ import annotations

import base64
import importlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .attestation import _validate_reference
from .canonicalization import canonicalize_predicate
from .predicate_type_profiles import validate_condition_for_profile
from .signing import KeyPair, verify_signature


class PredicateStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


class PredicateFailureReason(str, Enum):
    SCHEMA_INVALID = "schema_invalid"
    BAD_SIGNATURE = "bad_signature"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNKNOWN_AUTHORITY = "unknown_authority"
    REF_MISMATCH = "ref_mismatch"
    WRONG_SUBJECT = "wrong_subject"
    RESOLVER_MISS = "resolver_miss"


@runtime_checkable
class PredicateResolver(Protocol):
    def __call__(self, predicate_id: str) -> Optional["Predicate"]: ...


@dataclass(frozen=True)
class Predicate:
    predicate_id: str
    type: str
    authority: str
    issuer: str
    subject: str
    condition: dict[str, Any]
    issued_at: str
    expires_at: str
    references: list[dict[str, Any]]
    algorithm: str
    status: str
    signature: str
    validity: Optional[dict[str, Any]] = None
    constraints: Optional[dict[str, Any]] = None
    delegation_chain: Optional[list[dict[str, Any]]] = None
    revocation_endpoint: Optional[str] = None
    revoked_at: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Predicate":
        """Parse predicate data, accepting ``predicate_type`` as a read alias."""
        normalized = dict(data)
        if "type" not in normalized and "predicate_type" in normalized:
            normalized["type"] = normalized.pop("predicate_type")
        normalized["references"] = [
            _validate_reference(ref, index)
            for index, ref in enumerate(normalized.get("references", []))
        ]
        return cls(
            predicate_id=normalized["predicate_id"],
            type=normalized["type"],
            authority=normalized["authority"],
            issuer=normalized["issuer"],
            subject=normalized["subject"],
            condition=normalized["condition"],
            issued_at=normalized["issued_at"],
            expires_at=normalized["expires_at"],
            references=normalized["references"],
            algorithm=normalized["algorithm"],
            status=normalized["status"],
            signature=normalized.get("signature", ""),
            validity=normalized.get("validity"),
            constraints=normalized.get("constraints"),
            delegation_chain=normalized.get("delegation_chain"),
            revocation_endpoint=normalized.get("revocation_endpoint"),
            revoked_at=normalized.get("revoked_at"),
            metadata=normalized.get("metadata"),
        )

    def to_dict(self, *, include_signature: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "predicate_id": self.predicate_id,
            "type": self.type,
            "authority": self.authority,
            "issuer": self.issuer,
            "subject": self.subject,
            "condition": self.condition,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "references": self.references,
            "algorithm": self.algorithm,
            "status": self.status,
        }
        if include_signature:
            data["signature"] = self.signature
        for key in (
            "validity",
            "constraints",
            "delegation_chain",
            "revocation_endpoint",
            "revoked_at",
            "metadata",
        ):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        return data


@dataclass
class PredicateVerificationResult:
    valid: bool
    failure_reason: Optional[str] = None
    verified_subject: Optional[str] = None
    verified_authority: Optional[str] = None
    predicate_id: Optional[str] = None
    issuer: Optional[str] = None
    checks: dict[str, bool] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    revoked_at: Optional[str] = None
    tier: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "failure_reason": self.failure_reason,
            "verified_subject": self.verified_subject,
            "verified_authority": self.verified_authority,
            "predicate_id": self.predicate_id,
            "issuer": self.issuer,
            "checks": self.checks,
            "errors": self.errors,
            "warnings": self.warnings,
            "revoked_at": self.revoked_at,
            "tier": self.tier,
        }


def serialize_predicate_canonical(predicate: Predicate | dict[str, Any]) -> bytes:
    return canonicalize_predicate(
        predicate.to_dict() if isinstance(predicate, Predicate) else predicate
    )


def _fail(
    predicate: Predicate | None,
    reason: PredicateFailureReason,
    error: str,
    checks: dict[str, bool] | None = None,
    warnings: list[str] | None = None,
) -> PredicateVerificationResult:
    return PredicateVerificationResult(
        valid=False,
        failure_reason=reason.value,
        predicate_id=predicate.predicate_id if predicate else None,
        issuer=predicate.issuer if predicate else None,
        verified_subject=predicate.subject if predicate else None,
        verified_authority=predicate.authority if predicate else None,
        checks=checks or {},
        errors=[error],
        warnings=warnings or [],
        revoked_at=predicate.revoked_at if predicate else None,
    )


def _parse_datetime(value: str, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be an ISO 8601 string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _schema_errors(data: dict[str, Any]) -> list[str]:
    required = (
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
    )
    errors: list[str] = []
    if "type" not in data and "predicate_type" in data:
        data = {**data, "type": data["predicate_type"]}
    allowed = set(required) | {
        "predicate_type",
        "validity",
        "constraints",
        "delegation_chain",
        "revocation_endpoint",
        "revoked_at",
        "metadata",
    }
    extra = sorted(set(data) - allowed)
    if extra:
        errors.append(f"additional predicate properties are not allowed: {extra}")
    missing = [field for field in required if field not in data]
    if missing:
        errors.append(f"missing required predicate fields: {missing}")
        return errors
    if not str(data["predicate_id"]).startswith("urn:concordia:predicate:"):
        errors.append("predicate_id must start with urn:concordia:predicate:")
    for field_name in ("type", "authority", "issuer", "subject", "algorithm", "status"):
        if not isinstance(data[field_name], str) or not data[field_name]:
            errors.append(f"{field_name} must be a non-empty string")
    if data["algorithm"] not in ("EdDSA", "ES256"):
        errors.append("algorithm must be EdDSA or ES256")
    if data["status"] not in {status.value for status in PredicateStatus}:
        errors.append("status must be active, expired, revoked, or suspended")
    if not isinstance(data["condition"], dict) or not data["condition"]:
        errors.append("condition must be a non-empty object")
    if not isinstance(data["references"], list):
        errors.append("references must be an array")
    else:
        for index, ref in enumerate(data["references"]):
            try:
                _validate_reference(ref, index)
            except ValueError as exc:
                errors.append(str(exc))
    for field_name in ("issued_at", "expires_at"):
        try:
            _parse_datetime(data[field_name], field_name)
        except Exception as exc:  # noqa: BLE001 - convert to schema error text
            errors.append(str(exc))
    return errors


def validate_predicate_for_write(predicate: Predicate | dict[str, Any]) -> None:
    data = predicate.to_dict() if isinstance(predicate, Predicate) else dict(predicate)
    errors = _schema_errors(data)
    if "predicate_type" in data:
        errors.append("predicate_type is read-only compatibility; write type instead")
    candidate_type = data.get("type") or data.get("predicate_type")
    if isinstance(candidate_type, str):
        errors.extend(validate_condition_for_profile(candidate_type, data.get("condition")))
    if errors:
        raise ValueError("; ".join(errors))


def sign_predicate(predicate: Predicate | dict[str, Any], key_pair: KeyPair) -> Predicate:
    """Sign a predicate with Ed25519 and return the signed immutable object."""
    data = predicate.to_dict() if isinstance(predicate, Predicate) else dict(predicate)
    data["algorithm"] = data.get("algorithm") or "EdDSA"
    if data["algorithm"] != "EdDSA":
        raise ValueError("v0.6 reference signer emits EdDSA only")
    metadata = dict(data.get("metadata") or {})
    metadata.setdefault("issuer_public_key_b64", key_pair.public_key_b64())
    data["metadata"] = metadata
    data["signature"] = ""
    validate_predicate_for_write(data)
    signature = base64.urlsafe_b64encode(
        key_pair.private_key.sign(serialize_predicate_canonical(data))
    ).decode()
    data["signature"] = signature
    return Predicate.from_dict(data)


def _public_key_from_predicate(predicate: Predicate) -> Ed25519PublicKey | None:
    metadata = predicate.metadata or {}
    raw = metadata.get("issuer_public_key_b64")
    if not isinstance(raw, str):
        return None
    try:
        key_bytes = base64.urlsafe_b64decode(raw.encode())
        return Ed25519PublicKey.from_public_bytes(key_bytes)
    except Exception:
        return None


def _call_approval_receipt_verifier(warnings: list[str]) -> None:
    try:
        importlib.import_module("concordia.approval_receipt")
    except Exception:
        warnings.append("approval_receipt_verifier_unavailable")


def verify_predicate(
    predicate: Predicate | dict[str, Any] | str,
    *,
    resolver: PredicateResolver | None = None,
) -> PredicateVerificationResult:
    """Verify a signed predicate and return stable policy-readable status."""
    checks: dict[str, bool] = {}
    warnings: list[str] = []
    if isinstance(predicate, str):
        if resolver is None:
            return _fail(None, PredicateFailureReason.RESOLVER_MISS, "resolver required")
        resolved = resolver(predicate)
        if resolved is None:
            return _fail(None, PredicateFailureReason.RESOLVER_MISS, predicate)
        if resolved.predicate_id != predicate:
            return _fail(resolved, PredicateFailureReason.REF_MISMATCH, predicate)
        predicate = resolved

    raw = predicate.to_dict() if isinstance(predicate, Predicate) else dict(predicate)
    schema_errors = _schema_errors(raw)
    if schema_errors:
        return _fail(None, PredicateFailureReason.SCHEMA_INVALID, "; ".join(schema_errors), {"schema": False})
    try:
        parsed = Predicate.from_dict(raw)
    except Exception as exc:
        return _fail(None, PredicateFailureReason.SCHEMA_INVALID, str(exc), {"schema": False})
    checks["schema"] = True

    profile_errors = validate_condition_for_profile(parsed.type, parsed.condition)
    checks["profile_condition"] = not profile_errors
    if profile_errors:
        return _fail(
            parsed,
            PredicateFailureReason.SCHEMA_INVALID,
            "; ".join(profile_errors),
            checks,
            warnings,
        )

    if resolver is not None:
        for ref in parsed.references:
            if ref["type"] != "predicate":
                continue
            resolved = resolver(ref["id"])
            if resolved is None:
                return _fail(parsed, PredicateFailureReason.RESOLVER_MISS, ref["id"], checks)
            if resolved.predicate_id != ref["id"]:
                return _fail(parsed, PredicateFailureReason.REF_MISMATCH, ref["id"], checks)
        checks["resolver_binding"] = True

    if not parsed.signature or parsed.algorithm != "EdDSA":
        return _fail(parsed, PredicateFailureReason.BAD_SIGNATURE, "missing or unsupported predicate signature", checks)
    public_key = _public_key_from_predicate(parsed)
    if public_key is None:
        return _fail(parsed, PredicateFailureReason.UNKNOWN_AUTHORITY, "issuer public key unavailable", checks)
    signature_ok = verify_signature(
        parsed.to_dict(),
        parsed.signature,
        public_key,
        alg="EdDSA",
    )
    checks["signature"] = signature_ok
    if not signature_ok:
        return _fail(parsed, PredicateFailureReason.BAD_SIGNATURE, "invalid predicate signature", checks)

    now = datetime.now(timezone.utc)
    if parsed.status == PredicateStatus.EXPIRED.value or _parse_datetime(parsed.expires_at, "expires_at") < now:
        checks["lifecycle"] = False
        return _fail(parsed, PredicateFailureReason.EXPIRED, "predicate expired", checks)
    if parsed.status == PredicateStatus.REVOKED.value or parsed.revoked_at is not None:
        checks["lifecycle"] = False
        return _fail(parsed, PredicateFailureReason.REVOKED, "predicate revoked", checks)
    if parsed.status == PredicateStatus.SUSPENDED.value:
        checks["lifecycle"] = False
        return _fail(parsed, PredicateFailureReason.REVOKED, "predicate suspended", checks)
    checks["lifecycle"] = True

    expected_subject = (parsed.metadata or {}).get("expected_subject")
    if isinstance(expected_subject, str) and expected_subject != parsed.subject:
        checks["subject_binding"] = False
        return _fail(parsed, PredicateFailureReason.WRONG_SUBJECT, "predicate subject mismatch", checks)
    checks["subject_binding"] = True

    for ref in parsed.references:
        if ref["type"] == "receipt" and ref["relationship"] == "fulfills":
            _call_approval_receipt_verifier(warnings)
    checks["reference_binding"] = True

    return PredicateVerificationResult(
        valid=True,
        verified_subject=parsed.subject,
        verified_authority=parsed.authority,
        predicate_id=parsed.predicate_id,
        issuer=parsed.issuer,
        checks=checks,
        warnings=warnings,
    )


__all__ = [
    "Predicate",
    "PredicateStatus",
    "PredicateFailureReason",
    "PredicateVerificationResult",
    "PredicateResolver",
    "serialize_predicate_canonical",
    "validate_predicate_for_write",
    "sign_predicate",
    "verify_predicate",
]
