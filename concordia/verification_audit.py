"""Append-only audit log for authority verification decisions."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .signing import canonical_json


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_input_hash(value: Any) -> str:
    """Return a stable sha256 hash for verifier inputs."""
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class VerificationAuditEvent:
    """Structured audit event for mandate and approval verification decisions."""

    timestamp: str
    verifier: str
    decision: str
    failure_reason: str | None = None
    tier: str | None = None
    resolver_outcome: str | None = None
    revoked_at: str | None = None
    session_ref: str | None = None
    offer_hash: str | None = None
    receipt_ref: str | None = None
    mandate_ref: str | None = None
    input_hashes: dict[str, str] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class VerificationAuditLog:
    """In-memory append-only verification audit log."""

    def __init__(self) -> None:
        self._events: list[VerificationAuditEvent] = []

    def append(self, event: VerificationAuditEvent) -> VerificationAuditEvent:
        self._events.append(event)
        return event

    def clear(self) -> None:
        self._events.clear()

    def list_events(self) -> list[VerificationAuditEvent]:
        return list(self._events)

    def find(
        self,
        *,
        session_ref: str | None = None,
        offer_hash: str | None = None,
        receipt_ref: str | None = None,
        mandate_ref: str | None = None,
    ) -> list[VerificationAuditEvent]:
        events = self._events
        if session_ref is not None:
            events = [event for event in events if event.session_ref == session_ref]
        if offer_hash is not None:
            events = [event for event in events if event.offer_hash == offer_hash]
        if receipt_ref is not None:
            events = [event for event in events if event.receipt_ref == receipt_ref]
        if mandate_ref is not None:
            events = [event for event in events if event.mandate_ref == mandate_ref]
        return list(events)


verification_audit_log = VerificationAuditLog()


def record_mandate_verification(
    *,
    result: Any,
    verifier: str,
    mandate_ref: str | None = None,
    session_ref: str | None = None,
    offer_hash: str | None = None,
    receipt_ref: str | None = None,
    resolver_outcome: str | None = None,
    inputs: dict[str, Any] | None = None,
    audit_log: VerificationAuditLog | None = None,
) -> VerificationAuditEvent:
    """Record a mandate verifier result as a structured audit event."""
    valid = bool(getattr(result, "valid", False))
    result_dict = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    event = VerificationAuditEvent(
        timestamp=_utc_timestamp(),
        verifier=verifier,
        decision="grant" if valid else "deny",
        failure_reason=getattr(result, "failure_reason", None),
        tier=getattr(result, "tier", None),
        resolver_outcome=resolver_outcome,
        revoked_at=getattr(result, "revoked_at", None),
        session_ref=session_ref,
        offer_hash=offer_hash,
        receipt_ref=receipt_ref,
        mandate_ref=mandate_ref or getattr(result, "mandate_id", None),
        input_hashes={
            key: stable_input_hash(value) for key, value in (inputs or {}).items()
        },
        result=result_dict,
    )
    return (audit_log or verification_audit_log).append(event)


def record_approval_verification(
    *,
    result: dict[str, Any],
    receipt_ref: str | None = None,
    session_ref: str | None = None,
    offer_hash: str | None = None,
    mandate_ref: str | None = None,
    inputs: dict[str, Any] | None = None,
    audit_log: VerificationAuditLog | None = None,
) -> VerificationAuditEvent:
    """Record an ApprovalReceipt verifier result dictionary."""
    valid = bool(result.get("valid", result.get("approved", False)))
    failure_reason = result.get("failure_reason") or result.get("reason")
    event = VerificationAuditEvent(
        timestamp=_utc_timestamp(),
        verifier="approval_receipt",
        decision="grant" if valid else "deny",
        failure_reason=failure_reason,
        tier=result.get("tier"),
        resolver_outcome=result.get("resolver_outcome"),
        revoked_at=result.get("revoked_at"),
        session_ref=session_ref or result.get("session_ref"),
        offer_hash=offer_hash or result.get("offer_hash"),
        receipt_ref=receipt_ref or result.get("receipt_ref"),
        mandate_ref=mandate_ref or result.get("mandate_ref"),
        input_hashes={
            key: stable_input_hash(value) for key, value in (inputs or {}).items()
        },
        result=dict(result),
    )
    return (audit_log or verification_audit_log).append(event)


__all__ = [
    "VerificationAuditEvent",
    "VerificationAuditLog",
    "record_approval_verification",
    "record_mandate_verification",
    "stable_input_hash",
    "verification_audit_log",
]
