from __future__ import annotations

from concordia.predicate import Predicate, sign_predicate
from concordia.signing import KeyPair


def test_unknown_reference_strings_are_preserved_on_read() -> None:
    predicate = Predicate.from_dict(
        {
            "predicate_id": "urn:concordia:predicate:pred_ref_compat_001",
            "predicate_type": "urn:concordia:predicate-type:authority_gate:v1",
            "authority": "urn:concordia:authority:policy",
            "issuer": "did:web:issuer.example#key-1",
            "subject": "did:web:subject.example#agent",
            "condition": {"result": "satisfied"},
            "issued_at": "2026-05-14T00:00:00Z",
            "expires_at": "2027-06-14T00:00:00Z",
            "references": [
                {
                    "type": "future_artifact",
                    "id": "urn:future:thing:1",
                    "relationship": "future_relationship",
                }
            ],
            "algorithm": "EdDSA",
            "status": "active",
            "signature": "sig",
        }
    )
    assert predicate.type == "urn:concordia:predicate-type:authority_gate:v1"
    assert predicate.references[0]["type"] == "future_artifact"
    assert predicate.references[0]["relationship"] == "future_relationship"


def test_predicate_type_alias_is_not_allowed_on_write() -> None:
    data = {
        "predicate_id": "urn:concordia:predicate:pred_ref_compat_002",
        "predicate_type": "urn:concordia:predicate-type:authority_gate:v1",
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
    try:
        sign_predicate(data, KeyPair.generate())
    except ValueError as exc:
        assert "predicate_type is read-only compatibility" in str(exc)
    else:
        raise AssertionError("predicate_type write alias should fail")
