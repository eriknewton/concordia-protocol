"""CMPC Stage 3 bilateral primitive serialization round-trip tests."""

import json
from pathlib import Path

import pytest

from concordia.cmpc import (
    AtomicActivationProof,
    ChainSession,
    ClosurePredicate,
    ConditionalCommitment,
    RevocationRecord,
    UnwindRecord,
    canonicalize_atomic_activation_proof,
    canonicalize_chain_session,
    canonicalize_closure_predicate,
    sign_atomic_activation_proof,
    sign_conditional_commitment,
    sign_unwind_record,
    verify_atomic_activation_proof,
    verify_conditional_commitment,
    verify_unwind_record,
)
from concordia.signing import KeyPair

FIXTURES = Path(__file__).parent / "fixtures" / "cmpc_bilateral" / "primitives"


def test_chain_session_roundtrip():
    from concordia.cmpc.schemas import validate_chain_session

    data = json.loads((FIXTURES / "chain_session.json").read_text())
    validate_chain_session(data)
    session = ChainSession(**data)
    assert session.to_dict() == data
    canonical_bytes = canonicalize_chain_session(session)
    assert isinstance(canonical_bytes, bytes)


def test_conditional_commitment_sign_verify_roundtrip():
    from concordia.cmpc.schemas import validate_conditional_commitment

    data = json.loads((FIXTURES / "conditional_commitment.json").read_text())
    validate_conditional_commitment(data)
    data.pop("signature", None)
    commitment = ConditionalCommitment(**data)
    kp = KeyPair.generate()
    signed = sign_conditional_commitment(commitment, kp)
    assert signed.signature
    assert verify_conditional_commitment(signed, kp.public_key)


def test_conditional_commitment_from_dict_preserves_values():
    data = json.loads((FIXTURES / "conditional_commitment.json").read_text())

    commitment = ConditionalCommitment.from_dict(data)

    assert commitment.commitment_id == data["commitment_id"]
    assert commitment.to_dict() == data


def test_atomic_activation_proof_sign_verify_roundtrip():
    from concordia.cmpc.schemas import validate_atomic_activation_proof

    data = json.loads((FIXTURES / "atomic_activation_proof.json").read_text())
    validate_atomic_activation_proof(data)
    data.pop("signature", None)
    proof = AtomicActivationProof(**data)
    kp = KeyPair.generate()
    signed = sign_atomic_activation_proof(proof, kp)
    assert verify_atomic_activation_proof(signed, kp.public_key)


def test_closure_predicate_to_dict_includes_optional_fields_when_present():
    data = json.loads((FIXTURES / "closure_predicate.json").read_text())
    data.update({
        "validity": {"mode": "windowed"},
        "constraints": {"type": "object"},
        "delegation_chain": [{"delegator": "did:web:root.example"}],
        "revocation_endpoint": "https://issuer.example/revocations.json",
        "revoked_at": "2026-05-18T00:00:00Z",
        "metadata": {"profile": "bilateral_chain_closure"},
    })

    predicate = ClosurePredicate.from_dict(data)

    assert predicate.to_dict() == data


def test_unwind_record_sign_verify_roundtrip():
    from concordia.cmpc.schemas import validate_unwind_record

    data = json.loads((FIXTURES / "unwind_record.json").read_text())
    validate_unwind_record(data)
    data.pop("signature", None)
    record = UnwindRecord(**data)
    kp = KeyPair.generate()
    signed = sign_unwind_record(record, kp)
    assert verify_unwind_record(signed, kp.public_key)


def test_revocation_record_to_dict_supplies_default_signature():
    data = {
        "revocation_id": "urn:concordia:revocation:cmpc-001",
        "revoked_artifact_id": "urn:concordia:commitment:cmpc-001",
        "revoked_artifact_type": "conditional_commitment",
        "revocation_scope": "single_artifact",
        "issuer_did": "did:web:issuer.example",
        "issued_at": "2026-05-17T10:00:00Z",
        "effective_at": "2026-05-17T10:05:00Z",
        "reason": "issuer_cancelled",
        "references": [],
    }

    record = RevocationRecord.from_dict(data)
    serialized = record.to_dict()

    assert serialized["signature"] == {"alg": "EdDSA", "value": ""}
    assert "supersedes" not in serialized
    assert "extensions" not in serialized


def test_revocation_record_to_dict_includes_optional_fields():
    data = {
        "revocation_id": "urn:concordia:revocation:cmpc-002",
        "revoked_artifact_id": "urn:concordia:commitment:cmpc-002",
        "revoked_artifact_type": "conditional_commitment",
        "revocation_scope": "cascade_to_dependents",
        "issuer_did": "did:web:issuer.example",
        "issued_at": "2026-05-17T10:00:00Z",
        "effective_at": "2026-05-17T10:05:00Z",
        "reason": "issuer_cancelled",
        "references": [{"id": "urn:concordia:commitment:cmpc-002"}],
        "cascade_depth": 2,
        "signature": {"alg": "EdDSA", "value": "sig"},
        "supersedes": "urn:concordia:revocation:cmpc-001",
        "extensions": {"operator": "night-shift"},
    }

    record = RevocationRecord.from_dict(data)

    assert record.to_dict() == data


def test_closure_predicate_canonicalization():
    """ClosurePredicate canonical bytes match the v0.6 predicate path."""
    from concordia.cmpc.schemas import validate_closure_predicate

    data = json.loads((FIXTURES / "closure_predicate.json").read_text())
    validate_closure_predicate(data)
    bytes_via_cmpc = canonicalize_closure_predicate(data)
    from concordia.canonicalization import canonicalize_predicate

    bytes_via_v06 = canonicalize_predicate(data)
    assert bytes_via_cmpc == bytes_via_v06


def test_schema_validation_rejects_malformed():
    """Each primitive validator raises on missing required fields."""
    from concordia.cmpc import SchemaValidationError
    from concordia.cmpc.schemas import (
        validate_chain_session,
        validate_conditional_commitment,
    )

    with pytest.raises(SchemaValidationError):
        validate_chain_session({"chain_session_id": "missing-other-fields"})
    with pytest.raises(SchemaValidationError):
        validate_conditional_commitment({})
