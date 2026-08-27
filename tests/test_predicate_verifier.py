from __future__ import annotations

from concordia.predicate import Predicate, sign_predicate, verify_predicate
from concordia.signing import KeyPair


def _assert_identity_unauthenticated(result) -> None:
    assert result.valid is False
    assert result.verified_subject is None
    assert result.verified_authority is None


def _assert_identity_authenticated(result) -> None:
    assert result.valid is False
    assert result.verified_subject == "did:web:subject.example#agent"
    assert result.verified_authority == "urn:concordia:authority:policy"


def _signed(**overrides) -> Predicate:
    data = {
        "predicate_id": overrides.pop("predicate_id", "urn:concordia:predicate:pred_verify_001"),
        "type": overrides.pop("type", "urn:concordia:predicate-type:authority_gate:v1"),
        "authority": overrides.pop("authority", "urn:concordia:authority:policy"),
        "issuer": overrides.pop("issuer", "did:web:issuer.example#key-1"),
        "subject": overrides.pop("subject", "did:web:subject.example#agent"),
        "condition": overrides.pop("condition", {"result": "satisfied"}),
        "issued_at": overrides.pop("issued_at", "2026-05-14T00:00:00Z"),
        "expires_at": overrides.pop("expires_at", "2027-06-14T00:00:00Z"),
        "references": overrides.pop("references", []),
        "algorithm": overrides.pop("algorithm", "EdDSA"),
        "status": overrides.pop("status", "active"),
        "signature": "",
    }
    data.update(overrides)
    return sign_predicate(data, KeyPair.generate())


def test_happy_path() -> None:
    assert verify_predicate(_signed()).valid is True


def test_schema_invalid() -> None:
    result = verify_predicate({"predicate_id": "not-enough"})
    assert result.failure_reason == "schema_invalid"
    _assert_identity_unauthenticated(result)


def test_expired() -> None:
    result = verify_predicate(_signed(expires_at="2026-01-01T00:00:00Z"))
    assert result.failure_reason == "expired"
    assert result.checks["signature"] is True
    _assert_identity_authenticated(result)


def test_revoked() -> None:
    result = verify_predicate(_signed(status="revoked"))
    assert result.failure_reason == "revoked"
    assert result.checks["signature"] is True
    _assert_identity_authenticated(result)


def test_unknown_authority() -> None:
    signed = _signed().to_dict()
    signed.pop("metadata")
    result = verify_predicate(signed)
    assert result.failure_reason == "unknown_authority"
    assert "signature" not in result.checks
    _assert_identity_unauthenticated(result)


def test_wrong_subject() -> None:
    signed = _signed(metadata={"expected_subject": "did:web:other.example#agent"})
    result = verify_predicate(signed)
    assert result.failure_reason == "wrong_subject"
    assert result.checks["signature"] is True
    _assert_identity_authenticated(result)


def test_resolver_miss() -> None:
    signed = _signed(
        references=[
            {
                "type": "predicate",
                "id": "urn:concordia:predicate:missing",
                "relationship": "references",
            }
        ]
    )
    result = verify_predicate(signed, resolver=lambda _predicate_id: None)
    assert result.failure_reason == "resolver_miss"
    assert "signature" not in result.checks
    _assert_identity_unauthenticated(result)


def test_ref_mismatch() -> None:
    signed = _signed(
        references=[
            {
                "type": "predicate",
                "id": "urn:concordia:predicate:expected",
                "relationship": "references",
            }
        ]
    )
    other = _signed(predicate_id="urn:concordia:predicate:other")
    result = verify_predicate(signed, resolver=lambda _predicate_id: other)
    assert result.failure_reason == "ref_mismatch"
    assert "signature" not in result.checks
    _assert_identity_unauthenticated(result)


def test_verify_predicate_id_without_resolver_is_resolver_miss() -> None:
    result = verify_predicate("urn:concordia:predicate:missing")
    assert result.failure_reason == "resolver_miss"
    _assert_identity_unauthenticated(result)


def test_missing_signature_is_bad_signature() -> None:
    signed = _signed().to_dict()
    signed["signature"] = ""
    result = verify_predicate(signed)
    assert result.failure_reason == "bad_signature"
    assert "signature" not in result.checks
    _assert_identity_unauthenticated(result)


def test_suspended_maps_to_revoked_failure() -> None:
    result = verify_predicate(_signed(status="suspended"))
    assert result.failure_reason == "revoked"
    assert result.checks["signature"] is True
    _assert_identity_authenticated(result)


def test_invalid_public_key_metadata_is_unknown_authority() -> None:
    signed = _signed().to_dict()
    signed["metadata"]["issuer_public_key_b64"] = "not-valid"
    result = verify_predicate(signed)
    assert result.failure_reason == "unknown_authority"
    assert "signature" not in result.checks
    _assert_identity_unauthenticated(result)


def test_schema_edges_report_schema_invalid() -> None:
    base = _signed().to_dict()
    base["extra"] = True
    base["predicate_id"] = "bad-id"
    base["algorithm"] = "RS256"
    base["status"] = "paused"
    base["condition"] = []
    base["references"] = [{"bad": True}]
    base["expires_at"] = 1
    result = verify_predicate(base)
    assert result.failure_reason == "schema_invalid"
    _assert_identity_unauthenticated(result)


def test_tampered_identity_is_not_reported_as_verified() -> None:
    signed = _signed().to_dict()
    signed["subject"] = "did:web:attacker.example#agent"
    signed["authority"] = "urn:concordia:authority:attacker"
    result = verify_predicate(signed)
    assert result.failure_reason == "bad_signature"
    assert result.checks["signature"] is False
    _assert_identity_unauthenticated(result)
