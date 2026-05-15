from __future__ import annotations

from concordia.ctef import predicate_to_ctef_claim


def test_predicate_to_ctef_claim_shape() -> None:
    claim = predicate_to_ctef_claim(
        {
            "predicate_id": "urn:concordia:predicate:pred_ctef_001",
            "type": "urn:concordia:predicate-type:authority_gate:v1",
            "authority": "urn:concordia:authority:policy",
            "issuer": "did:web:issuer.example#key-1",
            "subject": "urn:sanctuary:action:tool_call_9d4e8f01",
            "condition": {"result": "satisfied"},
            "issued_at": "2026-05-14T00:00:00Z",
            "expires_at": "2027-06-14T00:00:00Z",
            "references": [],
            "algorithm": "EdDSA",
            "status": "active",
            "signature": "sig",
        },
        verified_at="2026-05-14T00:00:00Z",
    )
    assert claim == {
        "claim_type": "authority",
        "claim_subtype": "predicate_evaluation",
        "artifact_ref": "urn:concordia:predicate:pred_ctef_001",
        "issuer": "did:web:issuer.example#key-1",
        "subject": "urn:sanctuary:action:tool_call_9d4e8f01",
        "authority": "urn:concordia:authority:policy",
        "verified_at": "2026-05-14T00:00:00Z",
        "result": "satisfied",
    }
