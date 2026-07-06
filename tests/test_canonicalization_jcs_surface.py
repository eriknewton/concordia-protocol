"""Tests for the public RFC 8785 JCS canonicalization surface."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from concordia.canonicalization import (
    JCS_SPEC_ID,
    canonicalize_jcs,
    canonicalize_mandate,
    canonicalize_predicate,
)
from concordia.signing import canonical_json


def test_canonicalize_jcs_non_dict_roots_emit_exact_jcs_bytes() -> None:
    assert canonicalize_jcs([3, 1, 2]) == b"[3,1,2]"
    assert canonicalize_jcs("a") == b'"a"'
    assert canonicalize_jcs(42) == b"42"
    assert canonicalize_jcs(True) == b"true"
    assert canonicalize_jcs(None) == b"null"


def test_canonicalize_jcs_dict_path_matches_signing_canonical_json() -> None:
    data = {"z": [3, 1, 2], "a": {"signature": "kept", "n": 1}, "b": True}

    assert canonicalize_jcs(data) == b'{"a":{"n":1,"signature":"kept"},"b":true,"z":[3,1,2]}'
    assert canonicalize_jcs(data) == canonical_json(data)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -0.0])
def test_canonicalize_jcs_rejects_special_float_non_dict_roots(value: float) -> None:
    with pytest.raises(ValueError):
        canonicalize_jcs(value)


def test_jcs_spec_id_is_rfc_8785_jcs() -> None:
    assert JCS_SPEC_ID == "RFC8785-JCS"


@dataclass(frozen=True)
class PredicateLike:
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def test_canonicalize_predicate_strips_signature_from_dict_input() -> None:
    with_signature = {"predicate": "ok", "subject": "agent-1", "signature": "sig-a"}
    without_signature = {"predicate": "ok", "subject": "agent-1"}

    assert canonicalize_predicate(with_signature) == b'{"predicate":"ok","subject":"agent-1"}'
    assert canonicalize_predicate(with_signature) == canonicalize_predicate(without_signature)


def test_canonicalize_predicate_strips_signature_from_to_dict_input() -> None:
    first = PredicateLike({"predicate": "ok", "subject": "agent-1", "signature": "sig-a"})
    second = PredicateLike({"predicate": "ok", "subject": "agent-1", "signature": "sig-b"})

    assert canonicalize_predicate(first) == b'{"predicate":"ok","subject":"agent-1"}'
    assert canonicalize_predicate(first) == canonicalize_predicate(second)


def test_canonicalize_mandate_accepts_dict_and_strips_signature() -> None:
    mandate = {
        "id": "mandate-1",
        "issuer": "did:example:issuer",
        "subject": "did:example:subject",
        "signature": "sig-a",
    }
    same_mandate_different_signature = {
        "id": "mandate-1",
        "issuer": "did:example:issuer",
        "subject": "did:example:subject",
        "signature": "sig-b",
    }

    assert canonicalize_mandate(mandate) == (
        b'{"id":"mandate-1","issuer":"did:example:issuer","subject":"did:example:subject"}'
    )
    assert canonicalize_mandate(mandate) == canonicalize_mandate(same_mandate_different_signature)
