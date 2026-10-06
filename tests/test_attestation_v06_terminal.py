"""Agreement-evidence 0.6.0 terminal verification behavior.

These tests pin the byte-level, fail-closed verifier from
draft-newton-agreement-evidence-00 Sections 4, 8, 10, and 11.7.
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia.attestation import (
    ATTESTATION_VERSION,
    AttestationVerificationPolicy,
    countersign_attestation,
    verify_attestation_artifact,
)
from concordia.signing import KeyPair, sign_message


_RFC8032_SEED_1 = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
_RFC8032_SEED_2 = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)


def _key_pair(seed: bytes) -> KeyPair:
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return KeyPair(private_key=private, public_key=private.public_key())


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _artifact(now: datetime) -> tuple[dict[str, Any], dict[str, KeyPair]]:
    keys = {
        "did:example:alice": _key_pair(_RFC8032_SEED_1),
        "did:example:bob": _key_pair(_RFC8032_SEED_2),
    }
    parties: list[dict[str, Any]] = []
    for agent_id, role in (
        ("did:example:alice", "initiator"),
        ("did:example:bob", "responder"),
    ):
        party: dict[str, Any] = {
            "agent_id": agent_id,
            "role": role,
            "behavior": {
                "offers_made": 1,
                "concessions": 0,
                "concession_magnitude": 0.0,
                "reasoning_provided": True,
            },
        }
        party["signature"] = sign_message(party, keys[agent_id])
        parties.append(party)

    artifact: dict[str, Any] = {
        "concordia_attestation": "0.6.0",
        "attestation_id": "att_v06_positive",
        "session_id": "sess_v06_positive",
        "timestamp": _iso(now),
        "outcome": {
            "status": "agreed",
            "rounds": 2,
            "duration_seconds": 30,
            "terms_count": 1,
            "resolution_mechanism": "direct",
        },
        "parties": parties,
        "meta": {
            "category": "compute.gpu",
            "value_range": "1000-5000_USD",
            "extensions_used": ["cmpc"],
            "mediator_invoked": False,
        },
        "transcript_hash": "sha256:" + "0" * 64,
        "chain_head": "sha256:" + "1" * 64,
        "message_count": 3,
        "validity_temporal": {
            "mode": "absolute",
            "from": _iso(now - timedelta(seconds=30)),
            "until": _iso(now + timedelta(seconds=300)),
        },
        "summary": "Parties: did:example:alice, did:example:bob",
        "references": [
            {
                "id": "urn:concordia:receipt:one",
                "type": "receipt",
                "relationship": "references",
                "version": "0.6.0",
                "signed_at": _iso(now),
                "signer_did": "did:example:alice",
            }
        ],
    }
    artifact["countersignatures"] = {
        agent_id: countersign_attestation(artifact, key_pair)
        for agent_id, key_pair in keys.items()
    }
    return artifact, keys


def _bytes(artifact: dict[str, Any]) -> bytes:
    return json.dumps(artifact, separators=(",", ":"), sort_keys=True).encode()


def _verify(
    artifact: dict[str, Any],
    keys: dict[str, KeyPair],
    now: datetime,
    *,
    expected_session_id: str = "sess_v06_positive",
    expected_parties: set[str] | None = None,
):
    expected = expected_parties or {"did:example:alice", "did:example:bob"}
    return verify_attestation_artifact(
        _bytes(artifact),
        lambda agent_id: keys[agent_id].public_key,
        expected_session_id=expected_session_id,
        expected_party_ids=expected,
        now=now,
        revocation_checker=lambda _: False,
        policy=AttestationVerificationPolicy(),
    )


def test_v06_positive_vector_round_trips_to_current() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)

    assert ATTESTATION_VERSION == "0.6.0"
    result = _verify(artifact, keys, now)

    assert result.terminal_state == "current"
    assert result.errors == []


def test_v06_removed_and_malformed_members_terminate_not_bound() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    cases: list[dict[str, Any]] = []

    root_fulfillment = deepcopy(artifact)
    root_fulfillment["fulfillment"] = None
    cases.append(root_fulfillment)

    reference_extensions = deepcopy(artifact)
    reference_extensions["references"][0]["extensions"] = {"future": "field"}
    cases.append(reference_extensions)

    nested_undefined = deepcopy(artifact)
    nested_undefined["parties"][0]["behavior"]["unexpected"] = 1
    cases.append(nested_undefined)

    short_signature = deepcopy(artifact)
    first = next(iter(short_signature["countersignatures"]))
    short_signature["countersignatures"][first] = (
        short_signature["countersignatures"][first][:-1]
    )
    cases.append(short_signature)

    window_mode = deepcopy(artifact)
    window_mode["validity_temporal"] = {
        "mode": "window",
        "start": _iso(now - timedelta(seconds=30)),
        "end": _iso(now + timedelta(seconds=300)),
        "duration_seconds": 60,
    }
    cases.append(window_mode)

    zero_messages = deepcopy(artifact)
    zero_messages["message_count"] = 0
    cases.append(zero_messages)

    leading_zero = deepcopy(artifact)
    leading_zero["concordia_attestation"] = "0.06.0"
    cases.append(leading_zero)

    for candidate in cases:
        assert _verify(candidate, keys, now).terminal_state == "not-bound"


def test_v06_expected_party_mismatch_terminates_not_bound() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)

    result = _verify(
        artifact,
        keys,
        now,
        expected_parties={"did:example:alice", "did:example:carol"},
    )

    assert result.terminal_state == "not-bound"


def test_pre_v05_legacy_exits_before_signature_resolution() -> None:
    artifact = {"concordia_attestation": "0.4.0", "unread": {"signature": "bad"}}

    def resolver(agent_id: str):  # pragma: no cover: must not be called
        raise AssertionError(f"unexpected signature resolution for {agent_id}")

    result = verify_attestation_artifact(json.dumps(artifact).encode(), resolver)

    assert result.terminal_state == "legacy"
    assert result.signature_checks == 0
