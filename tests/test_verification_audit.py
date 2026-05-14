from __future__ import annotations

from datetime import datetime, timedelta, timezone

from concordia.mandate import sign_mandate
from concordia.mandate_resolver import Tier, verify_mandate_with_resolver
from concordia.models.mandate import Mandate, TemporalMode, ValidityWindow
from concordia.signing import KeyPair
from concordia.verification_audit import (
    VerificationAuditLog,
    record_approval_verification,
    verification_audit_log,
)


def _validity() -> ValidityWindow:
    now = datetime.now(timezone.utc)
    return ValidityWindow(
        mode=TemporalMode.WINDOWED,
        not_before=(now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        not_after=(now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _signed_mandate(keypair: KeyPair) -> Mandate:
    mandate = Mandate.create(
        issuer="did:concordia:issuer-audit",
        subject="did:concordia:agent-audit",
        constraints={"type": "object"},
        validity=_validity(),
    )
    return sign_mandate(mandate, keypair)


def test_mandate_grant_emits_one_audit_event_with_keys() -> None:
    keypair = KeyPair.generate()
    mandate = _signed_mandate(keypair)
    audit_log = VerificationAuditLog()

    result = verify_mandate_with_resolver(
        mandate.mandate_id,
        lambda _ref: mandate,
        tier=Tier.BASIC,
        audit_log=audit_log,
        session_ref="urn:a2cn:session:s-1",
        offer_hash="sha256:offer",
        receipt_ref="urn:concordia:receipt:r-1",
    )

    events = audit_log.list_events()
    assert result.valid is True
    assert len(events) == 1
    assert events[0].decision == "grant"
    assert events[0].resolver_outcome == "hit"
    assert events[0].mandate_ref == mandate.mandate_id
    assert events[0].session_ref == "urn:a2cn:session:s-1"
    assert events[0].offer_hash == "sha256:offer"
    assert events[0].receipt_ref == "urn:concordia:receipt:r-1"
    assert "mandate_ref" in events[0].input_hashes


def test_mandate_resolver_miss_emits_deny_event() -> None:
    audit_log = VerificationAuditLog()

    result = verify_mandate_with_resolver(
        "urn:concordia:mandate:missing",
        lambda _ref: None,
        tier=Tier.DID_VC,
        issuer_public_key=KeyPair.generate().public_key,
        audit_log=audit_log,
    )

    events = audit_log.list_events()
    assert result.valid is False
    assert len(events) == 1
    assert events[0].decision == "deny"
    assert events[0].failure_reason == "resolver_miss"
    assert events[0].resolver_outcome == "miss"


def test_mandate_proof_failure_emits_deny_event() -> None:
    signer = KeyPair.generate()
    wrong_key = KeyPair.generate()
    mandate = _signed_mandate(signer)
    audit_log = VerificationAuditLog()

    result = verify_mandate_with_resolver(
        mandate.mandate_id,
        lambda _ref: mandate,
        tier=Tier.DID_VC,
        issuer_public_key=wrong_key.public_key,
        audit_log=audit_log,
    )

    events = audit_log.list_events()
    assert result.valid is False
    assert len(events) == 1
    assert events[0].decision == "deny"
    assert events[0].failure_reason == "invalid_proof"
    assert events[0].resolver_outcome == "hit"


def test_approval_receipt_grant_and_deny_emit_audit_events() -> None:
    audit_log = VerificationAuditLog()

    grant = record_approval_verification(
        result={"valid": True, "tier": "human-approval"},
        receipt_ref="urn:concordia:approval:ok",
        session_ref="urn:a2cn:session:s-1",
        offer_hash="sha256:offer",
        mandate_ref="urn:a2cn:mandate:m-1",
        inputs={"receipt": {"artifact_type": "ApprovalReceipt"}},
        audit_log=audit_log,
    )
    deny = record_approval_verification(
        result={"valid": False, "failure_reason": "signature_invalid"},
        receipt_ref="urn:concordia:approval:bad",
        audit_log=audit_log,
    )

    assert grant.decision == "grant"
    assert deny.decision == "deny"
    assert deny.failure_reason == "signature_invalid"
    assert len(audit_log.find(session_ref="urn:a2cn:session:s-1")) == 1
    assert len(audit_log.find(offer_hash="sha256:offer")) == 1
    assert len(audit_log.find(receipt_ref="urn:concordia:approval:bad")) == 1
    assert len(audit_log.find(mandate_ref="urn:a2cn:mandate:m-1")) == 1


def test_mcp_mandate_verification_emits_audit_event() -> None:
    from concordia.mcp_server import tool_verify_mandate

    keypair = KeyPair.generate()
    mandate = _signed_mandate(keypair)
    verification_audit_log.clear()

    response = tool_verify_mandate(
        mandate=mandate.to_dict(),
        issuer_public_key_b64=keypair.public_key_b64(),
        session_ref="urn:a2cn:session:s-mcp",
        offer_hash="sha256:mcp-offer",
        receipt_ref="urn:concordia:receipt:mcp",
        mandate_ref="urn:concordia:mandate:mcp",
    )

    events = verification_audit_log.list_events()
    assert '"valid": true' in response
    assert len(events) == 1
    assert events[0].verifier == "mcp_server.concordia_verify_mandate"
    assert events[0].decision == "grant"
    assert events[0].session_ref == "urn:a2cn:session:s-mcp"
