"""RevocationRecord conformance and cascade verification."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia.approval_receipt import REVOKED, verify_approval_receipt
from concordia.cmpc import (
    CandidateArtifact,
    RevocationRecord,
    cascade_revocation,
    canonicalize_revocation_record,
    sign_revocation_record,
    verify_revocation_record,
)
from concordia.cmpc.schemas import validate_revocation_record
from concordia.cmpc.errors import SchemaValidationError
from concordia.predicate import PredicateFailureReason, sign_predicate, verify_predicate
from concordia.signing import KeyPair, sign_message

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "revocation"
TEST_PRIVATE_KEY_BYTES = bytes(range(32))


def _fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text())


def _record(name: str) -> RevocationRecord:
    return RevocationRecord.from_dict(_fixture(name)["revocation_record"])


def _candidates(name: str) -> list[CandidateArtifact]:
    return [CandidateArtifact(**item) for item in _fixture(name)["candidate_artifacts"]]


def _key_pair() -> KeyPair:
    private = Ed25519PrivateKey.from_private_bytes(TEST_PRIVATE_KEY_BYTES)
    return KeyPair(private_key=private, public_key=private.public_key())


@pytest.mark.parametrize(
    "name",
    [
        "single-artifact-revocation.json",
        "cascade-mandate-revocation.json",
        "giskard09-mid-execution-rotation.json",
    ],
)
def test_revocation_record_schema_positive(name: str) -> None:
    validate_revocation_record(_fixture(name)["revocation_record"])


def test_revocation_record_schema_negative() -> None:
    data = _fixture("single-artifact-revocation.json")["revocation_record"]
    data["cascade_depth"] = 9
    with pytest.raises(SchemaValidationError):
        validate_revocation_record(data)


@pytest.mark.parametrize(
    "name",
    [
        "single-artifact-revocation.json",
        "cascade-mandate-revocation.json",
        "giskard09-mid-execution-rotation.json",
    ],
)
def test_revocation_record_jcs_matches_rfc8785(name: str) -> None:
    data = _fixture(name)["revocation_record"]
    signable = {key: value for key, value in data.items() if key != "signature"}
    assert canonicalize_revocation_record(data) == rfc8785.dumps(signable)


def test_revocation_record_sign_verify_round_trip() -> None:
    key_pair = _key_pair()
    unsigned = copy.deepcopy(_record("single-artifact-revocation.json"))
    unsigned.signature = {"alg": "EdDSA", "value": ""}
    signed = sign_revocation_record(unsigned, key_pair)
    assert verify_revocation_record(signed, key_pair.public_key)


def test_cascade_depth_bound() -> None:
    record = _record("cascade-mandate-revocation.json")
    record.cascade_depth = 0
    result = cascade_revocation(record, _candidates("cascade-mandate-revocation.json"))
    assert [item.artifact_id for item in result.inadmissible] == [record.revoked_artifact_id]

    record.cascade_depth = 3
    result = cascade_revocation(record, _candidates("cascade-mandate-revocation.json"))
    assert len(result.inadmissible) == 4

    bad = record.to_dict()
    bad["cascade_depth"] = 9
    with pytest.raises(SchemaValidationError):
        validate_revocation_record(bad)


def test_cascade_cycle_detection() -> None:
    record = _record("cascade-mandate-revocation.json")
    candidates = [
        CandidateArtifact(artifact_id=record.revoked_artifact_id, artifact_type="mandate", references=[]),
        CandidateArtifact(
            artifact_id="urn:concordia:commitment:a",
            artifact_type="commitment",
            references=[{"id": record.revoked_artifact_id, "type": "mandate", "relationship": "fulfills"}],
        ),
        CandidateArtifact(
            artifact_id="urn:concordia:commitment:b",
            artifact_type="commitment",
            references=[{"id": "urn:concordia:commitment:a", "type": "commitment", "relationship": "extends"}],
        ),
        CandidateArtifact(
            artifact_id="urn:concordia:commitment:a",
            artifact_type="commitment",
            references=[{"id": "urn:concordia:commitment:b", "type": "commitment", "relationship": "extends"}],
        ),
    ]
    result = cascade_revocation(record, candidates)
    ids = [item.artifact_id for item in result.inadmissible]
    assert ids.count("urn:concordia:commitment:a") <= 1


@pytest.mark.parametrize("relationship", ["fulfills", "extends", "approves", "revokes"])
def test_cascade_traversable_relationships(relationship: str) -> None:
    record = _record("cascade-mandate-revocation.json")
    result = cascade_revocation(
        record,
        [
            CandidateArtifact(artifact_id=record.revoked_artifact_id, artifact_type="mandate", references=[]),
            CandidateArtifact(
                artifact_id=f"urn:concordia:commitment:{relationship}",
                artifact_type="commitment",
                references=[
                    {
                        "id": record.revoked_artifact_id,
                        "type": "mandate",
                        "relationship": relationship,
                    }
                ],
            ),
        ],
    )
    assert len(result.inadmissible) == 2


@pytest.mark.parametrize("relationship", ["references", "supersedes"])
def test_cascade_non_traversable_relationships(relationship: str) -> None:
    record = _record("cascade-mandate-revocation.json")
    result = cascade_revocation(
        record,
        [
            CandidateArtifact(artifact_id=record.revoked_artifact_id, artifact_type="mandate", references=[]),
            CandidateArtifact(
                artifact_id=f"urn:concordia:commitment:{relationship}",
                artifact_type="commitment",
                references=[
                    {
                        "id": record.revoked_artifact_id,
                        "type": "mandate",
                        "relationship": relationship,
                    }
                ],
            ),
        ],
    )
    assert [item.artifact_id for item in result.inadmissible] == [record.revoked_artifact_id]


def test_giskard09_cascade_fixture_returns_revoked_evidence() -> None:
    fixture = _fixture("giskard09-mid-execution-rotation.json")
    record = RevocationRecord.from_dict(fixture["revocation_record"])
    result = cascade_revocation(record, _candidates("giskard09-mid-execution-rotation.json"))
    receipt = next(item for item in result.inadmissible if item.artifact_id == "urn:concordia:receipt:abc")
    assert receipt.reason is PredicateFailureReason.REVOKED
    assert receipt.revoked_via_revocation_id == "urn:concordia:revocation:def"
    assert "urn:a2cn:mandate:xyz" in receipt.evidence


def test_giskard09_fixture_has_hahs_payload_attribution() -> None:
    """Backfill assertion: the fixture metadata names HAHS v1 as the payload reference."""
    fixture_path = Path("tests/fixtures/revocation/giskard09-mid-execution-rotation.json")
    fixture = json.loads(fixture_path.read_text())
    assert "_meta" in fixture
    assert fixture["_meta"]["payload_reference"]["name"] == "HAHS v1 (Hashes-as-Histories)"
    assert fixture["_meta"]["payload_reference"]["canonical_schema_url"].startswith("https://hivetrust.onrender.com/")
    assert fixture["_meta"]["payload_reference"]["issuer_did"] == "did:hive:hivetrust-issuer-001"
    co_authors = fixture["_meta"]["co_authors"]
    assert any(author.get("identity") == "Erik Newton" for author in co_authors)
    assert any(author.get("identity") == "Steve Rotzin" for author in co_authors)


def test_predicate_verifier_revocation_records_kwarg() -> None:
    key_pair = KeyPair.generate()
    record = _record("giskard09-mid-execution-rotation.json")
    predicate = sign_predicate(
        {
            "predicate_id": "urn:concordia:predicate:giskard09",
            "type": "urn:concordia:predicate-type:approval_gate:v1",
            "authority": "did:web:authority.example",
            "issuer": "did:web:issuer.example",
            "subject": "urn:concordia:receipt:abc",
            "condition": {"result": "satisfied"},
            "issued_at": "2026-05-30T14:00:00Z",
            "expires_at": "2026-06-30T00:00:00Z",
            "references": [
                {"id": "urn:a2cn:mandate:xyz", "type": "mandate", "relationship": "fulfills"}
            ],
            "algorithm": "EdDSA",
            "status": "active",
            "signature": "",
        },
        key_pair,
    )
    result = verify_predicate(
        predicate,
        revocation_records={record.revoked_artifact_id: record},
        now=datetime(2026, 5, 30, 14, 45, tzinfo=timezone.utc),
    )
    assert result.failure_reason == PredicateFailureReason.REVOKED.value
    assert "urn:concordia:revocation:def" in result.errors[0]


def test_approval_receipt_verifier_revocation_records_kwarg() -> None:
    key_pair = KeyPair.generate()
    offer = {"id": "offer-001", "amount": "150000.00 USD"}
    offer_hash = "sha256:" + hashlib.sha256(json.dumps(offer, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    receipt = {
        "artifact_type": "ApprovalReceipt",
        "id": "urn:concordia:receipt:abc",
        "issued_at": "2026-05-30T14:00:00Z",
        "expires_at": "2026-06-30T00:00:00Z",
        "approver": {"identity": "did:web:principal.example#approval"},
        "scope": {
            "decision": "approve",
            "offer_hash": offer_hash,
            "amount": "150000.00 USD",
            "threshold_crossed": "100000.00 USD",
        },
        "references": [
            {"id": "a2cn:session:giskard09", "type": "negotiation_session", "relationship": "approves"},
            {"id": "urn:a2cn:mandate:xyz", "type": "mandate", "relationship": "fulfills"},
        ],
        "signature": {"alg": "Ed25519", "value": ""},
    }
    receipt["signature"]["value"] = sign_message(receipt, key_pair)
    record = _record("giskard09-mid-execution-rotation.json")
    result = verify_approval_receipt(
        receipt,
        offer,
        now=datetime(2026, 5, 30, 14, 45, tzinfo=timezone.utc),
        issuer_public_key=key_pair.public_key,
        revocation_records={record.revoked_artifact_id: record},
    )
    assert result.failure_reason == REVOKED
    assert "urn:concordia:revocation:def" in result.errors[0]
