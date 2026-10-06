"""Agreement-evidence 0.6.0 terminal verification behavior.

These tests pin the byte-level, fail-closed verifier from
draft-newton-agreement-evidence-00 Sections 4, 8, 10, and 11.7.
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia.attestation import (
    ATTESTATION_VERSION,
    MAX_ATTESTATION_ARTIFACT_BYTES,
    AttestationVerificationPolicy,
    countersign_attestation,
    verify_attestation,
    verify_attestation_artifact,
)
from concordia.schema_validator import is_valid_attestation, validate_attestation
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


def _iso_ms(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


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


def _resign(artifact: dict[str, Any], keys: dict[str, KeyPair]) -> None:
    artifact.pop("countersignatures", None)
    artifact["countersignatures"] = {
        agent_id: countersign_attestation(artifact, key_pair)
        for agent_id, key_pair in keys.items()
    }


def _public_keys(keys: dict[str, KeyPair]):
    return {agent_id: key_pair.public_key for agent_id, key_pair in keys.items()}


def _wrapper_verify(
    artifact: dict[str, Any],
    keys: dict[str, KeyPair],
    *,
    transcript: list[Any] | None = None,
):
    return verify_attestation(
        artifact,
        _public_keys(keys),
        transcript=transcript,
        expected_session_id="sess_v06_positive",
        expected_party_ids=frozenset(keys),
        revocation_checker=lambda _: False,
    )


def _not_bound(artifact: dict[str, Any], keys: dict[str, KeyPair], now: datetime) -> None:
    assert _verify(artifact, keys, now).terminal_state == "not-bound"


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


def test_v05_positive_vector_without_removed_members_is_current() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    artifact["concordia_attestation"] = "0.5.0"
    _resign(artifact, keys)

    result = _verify(artifact, keys, now)

    assert validate_attestation(artifact) == []
    assert result.terminal_state == "current"


@pytest.mark.parametrize(
    "mutator",
    [
        lambda artifact, now: artifact.__setitem__("fulfillment", None),
        lambda artifact, now: artifact["references"][0].__setitem__(
            "extensions", {"x": True}
        ),
        lambda artifact, now: artifact.__setitem__(
            "validity_temporal",
            {
                "mode": "window",
                "start": _iso(now - timedelta(seconds=30)),
                "end": _iso(now + timedelta(seconds=300)),
                "duration_seconds": 60,
            },
        ),
    ],
)
def test_v05_removed_members_terminate_not_bound(mutator) -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    artifact["concordia_attestation"] = "0.5.0"
    mutator(artifact, now)
    _resign(artifact, keys)

    assert validate_attestation(artifact)
    _not_bound(artifact, keys, now)


@pytest.mark.parametrize(
    ("mutator", "expected_error"),
    [
        (
            lambda artifact: artifact["references"][0].__setitem__("id", "cafe\u0301"),
            "not-bound",
        ),
        (
            lambda artifact: artifact["references"][0].__setitem__(
                "id", "did:example:alice\u200b"
            ),
            "not-bound",
        ),
        (
            lambda artifact: artifact["references"][0].__setitem__(
                "id", "x" * 400
            ),
            "not-bound",
        ),
        (
            lambda artifact: artifact["references"][0].__setitem__(
                "id", "bad\u0001id"
            ),
            "not-bound",
        ),
    ],
)
def test_reference_string_rules_apply_to_identifier_fields(
    mutator, expected_error: str
) -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    mutator(artifact)

    assert _verify(artifact, keys, now).terminal_state == expected_error


def test_unicode_digit_version_is_malformed_not_bound() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    artifact["concordia_attestation"] = "0.5.1\u0660"
    artifact["fulfillment"] = None
    _resign(artifact, keys)

    _not_bound(artifact, keys, now)


def test_absolute_lifetime_fractional_over_cap_is_not_bound() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    artifact["validity_temporal"] = {
        "mode": "absolute",
        "from": _iso(now),
        "until": _iso_ms(now + timedelta(seconds=7_776_000, milliseconds=999)),
    }
    _resign(artifact, keys)

    _not_bound(artifact, keys, now)


def test_step_8_expected_binding_arguments_are_required() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)

    with pytest.raises(TypeError):
        verify_attestation_artifact(
            _bytes(artifact),
            lambda agent_id: keys[agent_id].public_key,
            now=now,
            revocation_checker=lambda _: False,
        )


def test_valid_artifact_for_another_session_is_not_bound() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)

    result = _verify(artifact, keys, now, expected_session_id="sess_other")

    assert result.terminal_state == "not-bound"


@pytest.mark.parametrize(
    "payload",
    [
        b'{"concordia_attestation":"0.6.0","x":' + b"[" * 5000 + b"]" * 5000 + b"}",
        b'{"concordia_attestation":"0.6.0","attestation_id":"\\ud800"}',
    ],
)
def test_parser_exception_inputs_return_not_bound(payload: bytes) -> None:
    result = verify_attestation_artifact(
        payload,
        lambda _: None,
        expected_session_id="unused",
        expected_party_ids=frozenset(),
    )

    assert result.terminal_state == "not-bound"


def test_string_input_with_lone_surrogate_returns_not_bound() -> None:
    result = verify_attestation_artifact(
        "\ud800",
        lambda _: None,
        expected_session_id="unused",
        expected_party_ids=frozenset(),
    )

    assert result.terminal_state == "not-bound"


def test_long_member_name_diagnostic_is_bounded() -> None:
    payload = json.dumps(
        {"concordia_attestation": "0.6.0", "x" * 8000: "\ud800"}
    ).encode()

    result = verify_attestation_artifact(
        payload,
        lambda _: None,
        expected_session_id="unused",
        expected_party_ids=frozenset(),
    )

    assert result.terminal_state == "not-bound"
    assert result.errors
    assert len(result.errors[0]) < 180
    assert "..." in result.errors[0]
    assert "x" * 200 not in result.errors[0]


@pytest.mark.parametrize(
    "mutator",
    [
        lambda artifact: artifact["outcome"].__setitem__("status", []),
        lambda artifact: artifact["outcome"].__setitem__("resolution_mechanism", []),
        lambda artifact: artifact["parties"][0].__setitem__("role", []),
        lambda artifact: artifact["parties"][0]["behavior"].__setitem__(
            "concession_magnitude", int("9" * 400)
        ),
        lambda artifact: artifact["validity_temporal"].__setitem__(
            "duration_seconds", (2**53) - 1
        ),
    ],
)
def test_structure_exception_inputs_return_not_bound(mutator) -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    if artifact["validity_temporal"]["mode"] == "absolute":
        artifact["validity_temporal"] = {
            "mode": "relative",
            "from": _iso(now),
            "duration_seconds": 300,
        }
    mutator(artifact)

    result = verify_attestation_artifact(
        _bytes(artifact),
        lambda agent_id: keys[agent_id].public_key,
        expected_session_id="sess_v06_positive",
        expected_party_ids={"did:example:alice", "did:example:bob"},
        now=now,
        revocation_checker=lambda _: False,
    )

    assert result.terminal_state == "not-bound"


def test_schema_validation_reports_oversized_numeric_counter() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    artifact["outcome"]["rounds"] = int("9" * 400)
    _resign(artifact, keys)

    assert validate_attestation(artifact)
    assert not is_valid_attestation(artifact)


def test_size_cap_applies_before_parse() -> None:
    payload = b" " * (MAX_ATTESTATION_ARTIFACT_BYTES + 1)

    result = verify_attestation_artifact(
        payload,
        lambda _: None,
        expected_session_id="unused",
        expected_party_ids=frozenset(),
    )

    assert result.terminal_state == "not-bound"


def test_duplicate_member_names_return_not_bound() -> None:
    payload = (
        b'{"concordia_attestation":"0.6.0",'
        b'"concordia_attestation":"0.6.0"}'
    )

    result = verify_attestation_artifact(
        payload,
        lambda _: None,
        expected_session_id="unused",
        expected_party_ids=frozenset(),
    )

    assert result.terminal_state == "not-bound"


def test_revocation_undetermined_is_bound_only_and_revoked_is_not_bound() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)

    bound_only = verify_attestation_artifact(
        _bytes(artifact),
        lambda agent_id: keys[agent_id].public_key,
        expected_session_id="sess_v06_positive",
        expected_party_ids={"did:example:alice", "did:example:bob"},
        now=now,
        revocation_checker=lambda _: None,
    )
    revoked = verify_attestation_artifact(
        _bytes(artifact),
        lambda agent_id: keys[agent_id].public_key,
        expected_session_id="sess_v06_positive",
        expected_party_ids={"did:example:alice", "did:example:bob"},
        now=now,
        revocation_checker=lambda _: True,
    )

    assert bound_only.terminal_state == "bound-only"
    assert revoked.terminal_state == "not-bound"


def test_temporal_expiry_skew_age_and_relative_lifetime_reject() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)

    expired = deepcopy(artifact)
    expired["validity_temporal"] = {
        "mode": "absolute",
        "from": _iso(now - timedelta(seconds=600)),
        "until": _iso(now - timedelta(seconds=1)),
    }
    _resign(expired, keys)
    _not_bound(expired, keys, now)

    future = deepcopy(artifact)
    future["timestamp"] = _iso(now + timedelta(seconds=301))
    future["validity_temporal"]["from"] = _iso(now + timedelta(seconds=301))
    future["validity_temporal"]["until"] = _iso(now + timedelta(seconds=600))
    _resign(future, keys)
    _not_bound(future, keys, now)

    old = deepcopy(artifact)
    old["timestamp"] = _iso(now - timedelta(seconds=7_776_001))
    old["validity_temporal"]["from"] = _iso(now - timedelta(seconds=7_776_001))
    old["validity_temporal"]["until"] = _iso(now + timedelta(seconds=1))
    _resign(old, keys)
    _not_bound(old, keys, now)

    long_relative = deepcopy(artifact)
    long_relative["validity_temporal"] = {
        "mode": "relative",
        "from": _iso(now),
        "duration_seconds": 7_776_001,
    }
    _resign(long_relative, keys)
    _not_bound(long_relative, keys, now)


def test_pre_v05_legacy_exits_before_signature_resolution() -> None:
    artifact = {"concordia_attestation": "0.4.0", "unread": {"signature": "bad"}}

    def resolver(agent_id: str):  # pragma: no cover: must not be called
        raise AssertionError(f"unexpected signature resolution for {agent_id}")

    result = verify_attestation_artifact(
        json.dumps(artifact).encode(),
        resolver,
        expected_session_id="unused",
        expected_party_ids=frozenset(),
    )

    assert result.terminal_state == "legacy"
    assert result.signature_checks == 0


@pytest.mark.parametrize(
    "version_value",
    ["0.6.0 ", "0.6", "v0.6.0", "06.0.0", "", 5, None, "٠.٦.٠", {}],
)
def test_wrapper_malformed_or_absent_version_is_not_bound(version_value: Any) -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    if version_value is None:
        artifact.pop("concordia_attestation")
    else:
        artifact["concordia_attestation"] = version_value

    result = _wrapper_verify(artifact, keys)

    assert result.valid is False
    assert result.terminal_state == "not-bound"
    assert result.set_binding_state == "error"


def test_wrapper_well_formed_below_floor_version_remains_legacy() -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    artifact["concordia_attestation"] = "0.4.0"
    _resign(artifact, keys)

    result = _wrapper_verify(artifact, keys)

    assert result.terminal_state == "legacy"


@pytest.mark.parametrize(
    "transcript",
    [
        [{"a": float("nan")}],
        [b"x"],
        [set()],
        [{"a": "\ud800"}],
    ],
)
def test_wrapper_unhashable_current_transcript_does_not_change_terminal_state(
    transcript: list[Any],
) -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)

    result = _wrapper_verify(artifact, keys, transcript=transcript)

    assert result.valid is False
    assert result.terminal_state == "current"
    assert result.set_binding_state == "error"
    assert result.set_binding_errors == ["transcript could not be evaluated"]


@pytest.mark.parametrize(
    "transcript",
    [
        [{"a": float("nan")}],
        [b"x"],
        [set()],
        [{"a": "\ud800"}],
    ],
)
def test_wrapper_unhashable_legacy_transcript_stays_legacy(
    transcript: list[Any],
) -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    artifact["concordia_attestation"] = "0.4.0"
    _resign(artifact, keys)

    result = _wrapper_verify(artifact, keys, transcript=transcript)

    assert result.valid is False
    assert result.terminal_state == "legacy"
    assert result.set_binding_state == "error"
    assert result.set_binding_errors == ["transcript could not be evaluated"]


@pytest.mark.parametrize(
    "parties",
    [
        lambda party: [party, "str"],
        lambda party: [party, 5],
        lambda party: "not-a-list",
    ],
)
def test_wrapper_legacy_malformed_parties_stay_legacy_with_schema_error(
    parties,
) -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    artifact["concordia_attestation"] = "0.4.0"
    artifact["parties"] = parties(deepcopy(artifact["parties"][0]))
    _resign(artifact, keys)

    result = _wrapper_verify(artifact, keys)

    assert result.valid is False
    assert result.terminal_state == "legacy"
    assert result.schema_errors


@pytest.mark.parametrize("version_value", ["00.5.0", "٠.٥.٠"])
def test_wrapper_receipt_bundle_version_regex_rejects_malformed_versions_before_countersignature_checks(
    version_value: str,
) -> None:
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    artifact["concordia_attestation"] = version_value

    result = _wrapper_verify(artifact, keys)

    assert result.valid is False
    assert result.terminal_state == "not-bound"
    assert not any("countersignature" in error for error in result.signature_errors)


def test_countersignature_diagnostic_does_not_echo_long_agent_id() -> None:
    now = datetime.now(timezone.utc)
    long_agent_id = "a" * 252
    artifact, keys = _artifact(now)
    keys = {
        long_agent_id: keys["did:example:alice"],
        "did:example:bob": keys["did:example:bob"],
    }
    artifact["parties"][0]["agent_id"] = long_agent_id
    artifact["parties"][0]["signature"] = sign_message(
        artifact["parties"][0],
        keys[long_agent_id],
    )
    artifact.pop("countersignatures")
    artifact["countersignatures"] = {
        long_agent_id: "malformed",
        "did:example:bob": countersign_attestation(
            artifact,
            keys["did:example:bob"],
        ),
    }

    result = _wrapper_verify(artifact, keys)
    combined = " | ".join(result.errors)

    assert result.valid is False
    assert result.errors
    assert all(len(error) < 200 for error in result.errors)
    assert long_agent_id not in combined


@pytest.mark.parametrize(
    "version_value", ["0.6.0\n", "0.5.0\n", "0.4.0\n", "0.6.0\r\n"]
)
def test_wrapper_trailing_newline_version_is_not_bound_and_invalid(
    version_value: str,
) -> None:
    """A version the schema's `$` tolerates must not verify through the wrapper.

    The legacy checks never cover the version member, so without the early
    step-2 refusal both party signatures verify and `valid` reads True while
    `terminal_state` reads not-bound.
    """
    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    artifact["concordia_attestation"] = version_value

    result = _wrapper_verify(artifact, keys)

    assert result.valid is False
    assert result.terminal_state == "not-bound"
    assert result.verified_parties == []
    assert result.errors
    assert validate_attestation(artifact)
    assert is_valid_attestation(artifact) is False


def test_bundle_refuses_trailing_newline_version_with_tampered_outcome() -> None:
    """The bundle verifier must not credit or pass an artifact whose version
    only the schema's lenient `$` admits; before this fix the artifact rode the
    legacy-unbound lane with no countersignature checked and verify_bundle
    returned valid=True."""
    from concordia.receipt_bundle import ReceiptBundle, verify_bundle

    now = datetime.now(timezone.utc)
    artifact, keys = _artifact(now)
    artifact["concordia_attestation"] = "0.6.0\n"
    artifact["outcome"]["status"] = "rejected"
    artifact["countersignatures"] = {
        agent_id: "A" * 86 + "==" for agent_id in artifact["countersignatures"]
    }
    holder = "did:example:alice"
    bundle = ReceiptBundle.create(holder, [artifact], keys[holder]).to_dict()

    result = verify_bundle(bundle, lambda agent_id: keys[agent_id].public_key)

    assert result.valid is False
    assert result.outcome_bound_count == 0
    assert any("malformed" in error for error in result.errors)
