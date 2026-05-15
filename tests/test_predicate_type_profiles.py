from __future__ import annotations

import json
from pathlib import Path

import pytest

from concordia.predicate import sign_predicate, verify_predicate
from concordia.predicate_type_profiles import (
    get_predicate_type_profile,
    validate_condition_for_profile,
)
from concordia.signing import KeyPair


def test_non_deterministic_profile_with_result_fails_at_sign_time() -> None:
    predicate = {
        "predicate_id": "urn:concordia:predicate:pred_det_gate_fail_sign",
        "type": "urn:concordia:predicate-type:non_deterministic_test:v1",
        "authority": "urn:concordia:authority:test",
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
    with pytest.raises(ValueError, match="deterministic-semantics gate"):
        sign_predicate(predicate, KeyPair.generate())


def test_vector_13_fails_verify_schema_invalid_before_signature() -> None:
    expected = (
        Path(__file__).parent
        / "fixtures"
        / "predicate_canonical"
        / "vector_13_deterministic_gate_failure"
        / "expected_canonical.txt"
    ).read_text(encoding="utf-8")
    predicate = json.loads(expected)
    predicate["signature"] = "not-a-real-signature"
    result = verify_predicate(predicate)
    assert result.valid is False
    assert result.failure_reason == "schema_invalid"
    assert "deterministic-semantics gate" in result.errors[0]


def test_builtin_procurement_and_policy_profiles_load() -> None:
    procurement = get_predicate_type_profile(
        "urn:concordia:predicate-type:procurement_eligibility:v1"
    )
    policy = get_predicate_type_profile("urn:concordia:predicate-type:policy_gate:v1")
    assert procurement is not None and procurement.is_deterministic is True
    assert policy is not None and policy.is_deterministic is True


def test_unknown_profile_and_non_object_condition_errors() -> None:
    assert validate_condition_for_profile("urn:unknown", {}) == [
        "predicate type profile must be registered before signing: urn:unknown"
    ]
    assert validate_condition_for_profile(
        "urn:concordia:predicate-type:authority_gate:v1", []
    ) == ["condition must be an object"]
