from __future__ import annotations

from dataclasses import replace

from concordia.predicate import Predicate, sign_predicate, verify_predicate
from concordia.signing import KeyPair


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


def test_expired() -> None:
    result = verify_predicate(_signed(expires_at="2026-01-01T00:00:00Z"))
    assert result.failure_reason == "expired"


def test_revoked() -> None:
    result = verify_predicate(_signed(status="revoked"))
    assert result.failure_reason == "revoked"


def test_unknown_authority() -> None:
    signed = _signed().to_dict()
    signed.pop("metadata")
    result = verify_predicate(signed)
    assert result.failure_reason == "unknown_authority"


def test_wrong_subject() -> None:
    signed = _signed(metadata={"expected_subject": "did:web:other.example#agent"})
    result = verify_predicate(signed)
    assert result.failure_reason == "wrong_subject"


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


def test_verify_predicate_id_without_resolver_is_resolver_miss() -> None:
    result = verify_predicate("urn:concordia:predicate:missing")
    assert result.failure_reason == "resolver_miss"


def test_missing_signature_is_bad_signature() -> None:
    signed = _signed().to_dict()
    signed["signature"] = ""
    result = verify_predicate(signed)
    assert result.failure_reason == "bad_signature"


def test_suspended_maps_to_revoked_failure() -> None:
    result = verify_predicate(_signed(status="suspended"))
    assert result.failure_reason == "revoked"


def test_invalid_public_key_metadata_is_unknown_authority() -> None:
    signed = _signed().to_dict()
    signed["metadata"]["issuer_public_key_b64"] = "not-valid"
    result = verify_predicate(signed)
    assert result.failure_reason == "unknown_authority"


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
