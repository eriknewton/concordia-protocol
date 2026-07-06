from __future__ import annotations

from concordia.schema_validator import validate_fulfillment_attestation


def _artifact() -> dict:
    return {
        "attestation_type": "FulfillmentAttestation",
        "id": "urn:concordia:fulfillment:f-1",
        "issued_at": "2026-05-14T12:00:00Z",
        "agreement_attestation_id": "urn:concordia:attestation:a-1",
        "fulfillment": {"status": "fulfilled_clean"},
        "references": [
            {
                "type": "attestation",
                "id": "urn:concordia:attestation:a-1",
                "relationship": "fulfills",
            }
        ],
        "signature": {"alg": "Ed25519", "value": "sig"},
    }


def test_fulfillment_requires_fulfills_reference() -> None:
    artifact = _artifact()
    artifact["references"] = [
        {
            "type": "chain_session",
            "id": "urn:a2cn:session:s-1",
            "relationship": "references",
        }
    ]

    errors = validate_fulfillment_attestation(artifact)

    assert any("violates 'contains' constraint" in error for error in errors)


def test_fulfillment_requires_fulfills_target_to_match_agreement_id() -> None:
    artifact = _artifact()
    artifact["references"][0]["id"] = "urn:concordia:attestation:wrong"

    errors = validate_fulfillment_attestation(artifact)

    assert any("must equal agreement_attestation_id" in error for error in errors)


def test_mediated_fulfillment_requires_mediator_invoked_true() -> None:
    artifact = _artifact()
    artifact["fulfillment"]["status"] = "fulfilled_with_mediation"
    artifact["meta"] = {"mediator_invoked": False}

    errors = validate_fulfillment_attestation(artifact)

    assert any("violates 'const' constraint: true" in error for error in errors)


def test_fulfillment_happy_path_passes() -> None:
    artifact = _artifact()
    artifact["fulfillment"]["status"] = "fulfilled_with_mediation"
    artifact["meta"] = {"mediator_invoked": True}

    assert validate_fulfillment_attestation(artifact) == []
