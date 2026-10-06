"""Round-1 verifier probes from the independent gate reviews.

The probes exercise byte-level terminal-state behavior from
draft-newton-agreement-evidence-00 Section 10.
"""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from concordia.attestation import AttestationVerificationPolicy, verify_attestation_artifact

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_attestation_v06_terminal import _artifact, _bytes, _iso, _iso_ms, _resign


def _state(
    artifact: dict[str, Any] | bytes,
    keys: dict[str, Any],
    now: datetime,
    *,
    expected_session_id: str = "sess_v06_positive",
    expected_party_ids: set[str] | frozenset[str] = frozenset(
        {"did:example:alice", "did:example:bob"}
    ),
) -> str:
    payload = artifact if isinstance(artifact, bytes) else _bytes(artifact)
    result = verify_attestation_artifact(
        payload,
        lambda agent_id: keys[agent_id].public_key,
        expected_session_id=expected_session_id,
        expected_party_ids=expected_party_ids,
        now=now,
        revocation_checker=lambda _: False,
        policy=AttestationVerificationPolicy(),
    )
    print(f"probe terminal_state={result.terminal_state}")
    return result.terminal_state


@pytest.mark.parametrize(
    "name,mutator",
    [
        ("v05_fulfillment_null", lambda artifact, now: artifact.__setitem__("fulfillment", None)),
        (
            "v05_reference_extensions",
            lambda artifact, now: artifact["references"][0].__setitem__(
                "extensions", {"price": "4350"}
            ),
        ),
        (
            "v05_window",
            lambda artifact, now: artifact.__setitem__(
                "validity_temporal",
                {
                    "mode": "window",
                    "start": _iso(now - timedelta(seconds=60)),
                    "end": _iso(now + timedelta(days=3650)),
                    "duration_seconds": 60,
                },
            ),
        ),
        (
            "reference_nfd_id",
            lambda artifact, now: artifact["references"][0].__setitem__("id", "cafe\u0301"),
        ),
        (
            "reference_zero_width_id",
            lambda artifact, now: artifact["references"][0].__setitem__(
                "id", "did:example:alice\u200b"
            ),
        ),
        (
            "reference_400_octet_id",
            lambda artifact, now: artifact["references"][0].__setitem__("id", "x" * 400),
        ),
        (
            "unicode_digit_version",
            lambda artifact, now: artifact.__setitem__("concordia_attestation", "0.5.1\u0660"),
        ),
        (
            "absolute_7776000_999",
            lambda artifact, now: artifact.__setitem__(
                "validity_temporal",
                {
                    "mode": "absolute",
                    "from": _iso(now),
                    "until": _iso_ms(now + timedelta(seconds=7_776_000, milliseconds=999)),
                },
            ),
        ),
    ],
)
def test_round1_signed_probe_inputs_terminate_not_bound(name: str, mutator) -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    if name.startswith("v05_"):
        artifact["concordia_attestation"] = "0.5.0"
    mutator(artifact, now)
    _resign(artifact, keys)

    state = _state(artifact, keys, now)

    assert state == "not-bound", name


@pytest.mark.parametrize(
    "name,payload",
    [
        (
            "deep_raw_json",
            b'{"concordia_attestation":"0.6.0","x":' + b"[" * 5000 + b"]" * 5000 + b"}",
        ),
        (
            "lone_surrogate",
            b'{"concordia_attestation":"0.6.0","attestation_id":"\\ud800"}',
        ),
        (
            "outcome_status_list",
            json.dumps(
                {
                    "concordia_attestation": "0.6.0",
                    "attestation_id": "att",
                    "session_id": "sess",
                    "timestamp": "2026-10-06T00:00:00Z",
                    "outcome": {"status": [], "rounds": 1, "duration_seconds": 1},
                    "parties": [],
                    "meta": {},
                    "transcript_hash": "sha256:" + "0" * 64,
                    "chain_head": "sha256:" + "1" * 64,
                    "message_count": 1,
                    "validity_temporal": {
                        "mode": "relative",
                        "from": "2026-10-06T00:00:00Z",
                        "duration_seconds": 60,
                    },
                    "countersignatures": {},
                }
            ).encode(),
        ),
    ],
)
def test_round1_raw_exception_probe_inputs_terminate_not_bound(name: str, payload: bytes) -> None:
    now = datetime.now(timezone.utc)
    state = _state(payload, {}, now, expected_party_ids=frozenset())

    assert state == "not-bound", name


def test_round1_other_session_probe_terminates_not_bound() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    other_session = deepcopy(artifact)

    state = _state(other_session, keys, now, expected_session_id="sess_other")

    assert state == "not-bound"
