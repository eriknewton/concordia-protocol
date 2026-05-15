from __future__ import annotations

from concordia.predicate import sign_predicate, verify_predicate
from concordia.signing import KeyPair


def _unsigned(predicate_id: str = "pred_sign_001") -> dict:
    return {
        "predicate_id": f"urn:concordia:predicate:{predicate_id}",
        "type": "urn:concordia:predicate-type:authority_gate:v1",
        "authority": "urn:concordia:authority:policy",
        "issuer": "did:web:issuer.example#key-1",
        "subject": "did:web:subject.example#agent",
        "condition": {"result": "satisfied"},
        "issued_at": "2026-05-14T00:00:00Z",
        "expires_at": "2027-06-14T00:00:00Z",
        "references": [],
        "algorithm": "EdDSA",
        "status": "active",
        "signature": "",
    }


def test_ed25519_sign_and_verify_round_trip() -> None:
    signed = sign_predicate(_unsigned(), KeyPair.generate())
    result = verify_predicate(signed)
    assert result.valid is True
    assert result.predicate_id == signed.predicate_id
    assert result.checks["signature"] is True


def test_signature_tampering_is_bad_signature() -> None:
    signed = sign_predicate(_unsigned(), KeyPair.generate()).to_dict()
    signed["condition"] = {"result": "denied"}
    result = verify_predicate(signed)
    assert result.valid is False
    assert result.failure_reason == "bad_signature"
