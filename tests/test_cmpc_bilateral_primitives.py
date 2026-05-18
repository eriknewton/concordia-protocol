"""CMPC Stage 3 bilateral primitive serialization round-trip tests."""

import json
from pathlib import Path

import pytest

from concordia.cmpc import (
    AtomicActivationProof,
    ChainSession,
    ConditionalCommitment,
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


def test_atomic_activation_proof_sign_verify_roundtrip():
    from concordia.cmpc.schemas import validate_atomic_activation_proof

    data = json.loads((FIXTURES / "atomic_activation_proof.json").read_text())
    validate_atomic_activation_proof(data)
    data.pop("signature", None)
    proof = AtomicActivationProof(**data)
    kp = KeyPair.generate()
    signed = sign_atomic_activation_proof(proof, kp)
    assert verify_atomic_activation_proof(signed, kp.public_key)


def test_unwind_record_sign_verify_roundtrip():
    from concordia.cmpc.schemas import validate_unwind_record

    data = json.loads((FIXTURES / "unwind_record.json").read_text())
    validate_unwind_record(data)
    data.pop("signature", None)
    record = UnwindRecord(**data)
    kp = KeyPair.generate()
    signed = sign_unwind_record(record, kp)
    assert verify_unwind_record(signed, kp.public_key)


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
