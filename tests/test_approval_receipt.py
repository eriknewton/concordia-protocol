"""Tests for ApprovalReceipt verification."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone

from concordia.approval_receipt import (
    ApprovalReceiptResult,
    EXPIRED,
    MISSING_APPROVES_REFERENCE,
    OFFER_HASH_MISMATCH,
    REVOKED,
    SCHEMA_INVALID,
    SIGNATURE_INVALID,
    _has_approves_reference,
    _parse_datetime,
    _public_key_from_bytes,
    verify_approval_receipt,
)
from concordia.cmpc.types import RevocationRecord, RevocationScope
from concordia.schema_validator import validate_approval_receipt
from concordia.signing import KeyPair, canonical_json, sign_message


NOW = datetime(2026, 5, 14, 12, 0, tzinfo=timezone.utc)


def _offer() -> dict:
    return {
        "id": "offer-123",
        "type": "negotiate.offer",
        "terms": {
            "amount": "150000.00 USD",
            "delivery": "2026-06-01",
        },
    }


def _offer_hash(offer: dict) -> str:
    return f"sha256:{hashlib.sha256(canonical_json(offer)).hexdigest()}"


def _receipt(
    key_pair: KeyPair,
    offer: dict,
    *,
    decision: str = "approve",
    expires_at: str = "2026-05-14T13:00:00Z",
) -> dict:
    receipt = {
        "artifact_type": "ApprovalReceipt",
        "id": "urn:concordia:receipt:test-123",
        "issued_at": "2026-05-14T11:55:00Z",
        "expires_at": expires_at,
        "approver": {
            "identity": "did:web:acme.example#procurement-lead",
            "role": "procurement_authority",
        },
        "scope": {
            "decision": decision,
            "offer_hash": _offer_hash(offer),
            "amount": "150000.00 USD",
            "threshold_crossed": "100000.00 USD",
        },
        "references": [
            {
                "type": "negotiation_session",
                "id": "a2cn:session:9e4d2c11",
                "relationship": "approves",
            },
            {
                "type": "mandate",
                "id": "a2cn:mandate:m-2026-04-19-0007",
                "relationship": "fulfills",
            },
        ],
    }
    receipt["signature"] = {
        "alg": "Ed25519",
        "value": sign_message(receipt, key_pair),
    }
    return receipt


def _verify(receipt: dict, offer: dict, key_pair: KeyPair):
    return verify_approval_receipt(
        receipt,
        offer,
        now=NOW,
        issuer_public_key=key_pair.public_key_bytes(),
    )


def test_valid_approve_receipt_returns_typed_decision():
    key_pair = KeyPair.generate()
    offer = _offer()

    result = _verify(_receipt(key_pair, offer), offer, key_pair)

    assert result.valid is True
    assert result.decision == "approve"
    assert result.failure_reason is None
    assert result.references[0]["relationship"] == "approves"


def test_valid_deny_receipt_returns_typed_decision():
    key_pair = KeyPair.generate()
    offer = _offer()

    result = _verify(_receipt(key_pair, offer, decision="deny"), offer, key_pair)

    assert result.valid is True
    assert result.decision == "deny"
    assert result.failure_reason is None


def test_result_to_dict_includes_default_collections():
    result = ApprovalReceiptResult(valid=False, failure_reason=SIGNATURE_INVALID)

    assert result.to_dict() == {
        "valid": False,
        "decision": None,
        "failure_reason": SIGNATURE_INVALID,
        "receipt_id": None,
        "approver": None,
        "references": [],
        "checks": {},
        "errors": [],
    }


def test_approves_reference_helper_skips_non_dict_references():
    assert _has_approves_reference({"references": ["opaque-reference"]}) is False
    receipt = {
        "references": [
            "opaque-reference",
            {
                "type": "a2cn:negotiation_session",
                "id": "a2cn:session:9e4d2c11",
                "relationship": "approves",
            },
        ]
    }

    assert _has_approves_reference(receipt) is True


def test_parse_datetime_treats_naive_value_as_utc():
    parsed = _parse_datetime("2026-05-14T13:00:00")

    assert parsed == datetime(2026, 5, 14, 13, 0, tzinfo=timezone.utc)


def test_valid_receipt_accepts_public_key_object_and_naive_now():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer)

    result = verify_approval_receipt(
        receipt,
        offer,
        now=datetime(2026, 5, 14, 12, 0),
        issuer_public_key=key_pair.public_key,
    )

    assert result.valid is True
    assert result.checks["not_expired"] is True


def test_expired_receipt_is_rejected():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer, expires_at="2026-05-14T11:59:59Z")

    result = _verify(receipt, offer, key_pair)

    assert result.valid is False
    assert result.failure_reason == EXPIRED


def test_offer_hash_mismatch_is_rejected():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer, expires_at="2099-05-14T13:00:00Z")
    changed_offer = copy.deepcopy(offer)
    changed_offer["terms"]["amount"] = "160000.00 USD"

    result = _verify(receipt, changed_offer, key_pair)

    assert result.valid is False
    assert result.failure_reason == OFFER_HASH_MISMATCH


def test_revoked_reference_is_rejected_before_offer_hash_check():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer, expires_at="2099-05-14T13:00:00Z")
    revocation = RevocationRecord(
        revocation_id="urn:concordia:revocation:approval-001",
        revoked_artifact_id="a2cn:session:9e4d2c11",
        revoked_artifact_type="approval_receipt",
        revocation_scope=RevocationScope.SINGLE_ARTIFACT.value,
        issuer_did="did:web:principal.example",
        issued_at="2026-05-14T11:00:00Z",
        effective_at="2026-05-14T11:30:00Z",
        reason="principal_revoked",
        references=[
            {
                "id": "a2cn:session:9e4d2c11",
                "type": "approval_receipt",
                "relationship": "revokes",
            }
        ],
        signature={"alg": "EdDSA", "value": "placeholder"},
    )

    result = verify_approval_receipt(
        receipt,
        offer,
        now=NOW,
        issuer_public_key=key_pair.public_key_bytes(),
        revocation_records={"a2cn:session:9e4d2c11": revocation},
    )

    assert result.valid is False
    assert result.failure_reason == REVOKED
    assert result.checks["revocation_records"] is False
    assert result.errors == [
        "Referenced artifact revoked by urn:concordia:revocation:approval-001"
    ]


def test_missing_approves_reference_is_rejected_with_specific_reason():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer, expires_at="2099-05-14T13:00:00Z")
    receipt["references"] = [
        {
            "type": "mandate",
            "id": "a2cn:mandate:m-2026-04-19-0007",
            "relationship": "fulfills",
        }
    ]

    result = _verify(receipt, offer, key_pair)

    assert result.valid is False
    assert result.failure_reason == MISSING_APPROVES_REFERENCE


def test_schema_invalid_without_approves_reference_keeps_specific_reason():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer)
    receipt["references"] = "not-a-list"

    result = _verify(receipt, offer, key_pair)

    assert result.valid is False
    assert result.failure_reason == MISSING_APPROVES_REFERENCE
    assert result.checks["schema"] is False
    assert result.checks["approves_reference"] is False


def test_non_ed25519_signature_algorithm_is_schema_invalid():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer)
    receipt["signature"]["alg"] = "ES256"

    result = _verify(receipt, offer, key_pair)

    assert result.valid is False
    assert result.failure_reason == SCHEMA_INVALID
    assert result.checks["schema"] is False


def test_invalid_public_key_bytes_are_rejected():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer)

    result = verify_approval_receipt(
        receipt,
        offer,
        now=NOW,
        issuer_public_key=b"not-a-raw-ed25519-public-key",
    )

    assert result.valid is False
    assert result.failure_reason == SIGNATURE_INVALID
    assert result.checks["signature"] is False
    assert result.errors == ["Missing or invalid Ed25519 issuer public key"]


def test_public_key_helper_returns_none_for_missing_key():
    assert _public_key_from_bytes(None) is None


def test_bad_signature_is_rejected():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer)
    receipt["scope"]["amount"] = "151000.00 USD"

    result = _verify(receipt, offer, key_pair)

    assert result.valid is False
    assert result.failure_reason == SIGNATURE_INVALID


def test_nonmatching_revocation_records_mark_check_as_true():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer, expires_at="2099-05-14T13:00:00Z")
    revocation = RevocationRecord(
        revocation_id="urn:concordia:revocation:approval-002",
        revoked_artifact_id="a2cn:session:not-this-one",
        revoked_artifact_type="approval_receipt",
        revocation_scope=RevocationScope.SINGLE_ARTIFACT.value,
        issuer_did="did:web:principal.example",
        issued_at="2026-05-14T11:00:00Z",
        effective_at="2026-05-14T11:30:00Z",
        reason="principal_revoked",
        references=[
            {
                "id": "a2cn:session:not-this-one",
                "type": "approval_receipt",
                "relationship": "revokes",
            }
        ],
        signature={"alg": "EdDSA", "value": "placeholder"},
    )

    result = verify_approval_receipt(
        receipt,
        offer,
        now=NOW,
        issuer_public_key=key_pair.public_key_bytes(),
        revocation_records={"a2cn:session:not-this-one": revocation},
    )

    assert result.valid is True
    assert result.checks["revocation_records"] is True


def test_missing_offer_hash_is_schema_invalid():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer)
    del receipt["scope"]["offer_hash"]

    result = _verify(receipt, offer, key_pair)

    assert result.valid is False
    assert result.failure_reason == SCHEMA_INVALID


def test_missing_threshold_crossed_is_schema_invalid():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer)
    del receipt["scope"]["threshold_crossed"]

    result = _verify(receipt, offer, key_pair)

    assert result.valid is False
    assert result.failure_reason == SCHEMA_INVALID


def test_invalid_offer_hash_pattern_is_schema_invalid():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer)
    receipt["scope"]["offer_hash"] = "sha256:not-hex"

    result = _verify(receipt, offer, key_pair)

    assert result.valid is False
    assert result.failure_reason == SCHEMA_INVALID


def test_invalid_expires_at_format_is_schema_invalid():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer)
    receipt["expires_at"] = "not-a-date"

    result = _verify(receipt, offer, key_pair)

    assert result.valid is False
    assert result.failure_reason == SCHEMA_INVALID


def test_missing_expires_at_is_schema_invalid():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer)
    del receipt["expires_at"]

    result = _verify(receipt, offer, key_pair)

    assert result.valid is False
    assert result.failure_reason == SCHEMA_INVALID


def test_schema_validator_requires_approves_reference():
    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer)
    receipt["references"] = [
        {
            "type": "mandate",
            "id": "a2cn:mandate:m-2026-04-19-0007",
            "relationship": "fulfills",
        }
    ]

    errors = validate_approval_receipt(receipt)

    assert errors
    assert any("does not contain items matching the given schema" in error for error in errors)


def test_mcp_tool_returns_typed_decision():
    from concordia.mcp_server import tool_verify_approval_receipt

    key_pair = KeyPair.generate()
    offer = _offer()
    receipt = _receipt(key_pair, offer, expires_at="2099-05-14T13:00:00Z")

    result = json.loads(
        tool_verify_approval_receipt(receipt, offer, key_pair.public_key_b64())
    )

    assert result["valid"] is True
    assert result["decision"] == "approve"
    assert result["failure_reason"] is None
