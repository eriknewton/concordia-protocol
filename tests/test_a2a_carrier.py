from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from concordia.a2a_carrier import (
    A2A_CARRIER_MEDIA_TYPE,
    A2A_CARRIER_SCHEMA_URI,
    A2A_CARRIER_TYPE,
    A2A_CARRIER_VERSION,
    A2A_EXTENSION_URI,
    A2ACarrierError,
    build_a2a_data_part,
    parse_a2a_data_part,
)

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "a2a-negotiation-carrier-v1"
    / "part.json"
)


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text())


def test_shared_fixture_is_exact_contract_and_round_trips() -> None:
    part = load_fixture()
    envelope = copy.deepcopy(part["data"]["envelope"])

    assert build_a2a_data_part(envelope) == part
    assert parse_a2a_data_part(part, active_extensions=[A2A_EXTENSION_URI]) == envelope
    assert part["data"]["type"] == A2A_CARRIER_TYPE
    assert part["data"]["version"] == A2A_CARRIER_VERSION
    assert part["mediaType"] == A2A_CARRIER_MEDIA_TYPE
    assert part["metadata"][A2A_EXTENSION_URI]["schema"] == A2A_CARRIER_SCHEMA_URI


def test_shared_fixture_conforms_to_published_candidate_schema() -> None:
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "a2a_negotiation_part.schema.json"
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(load_fixture())) == []


def test_carrier_requires_hash_chain_pointer() -> None:
    part = load_fixture()
    part["data"]["envelope"].pop("prev_hash")

    with pytest.raises(A2ACarrierError, match="invalid envelope"):
        parse_a2a_data_part(part, active_extensions=[A2A_EXTENSION_URI])

    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "a2a_negotiation_part.schema.json"
    schema = json.loads(schema_path.read_text())
    assert list(Draft202012Validator(schema).iter_errors(part))


def test_builder_and_parser_do_not_alias_untrusted_objects() -> None:
    envelope = load_fixture()["data"]["envelope"]
    part = build_a2a_data_part(envelope)
    envelope["body"]["terms"]["delivery_days"]["value"] = 99
    assert part["data"]["envelope"]["body"]["terms"]["delivery_days"]["value"] == 7

    parsed = parse_a2a_data_part(part, active_extensions=[A2A_EXTENSION_URI])
    parsed["session_id"] = "tampered"
    assert part["data"]["envelope"]["session_id"] == "ses_a2a_carrier_0001"


def test_parser_requires_explicit_extension_activation() -> None:
    part = load_fixture()
    for active in ([], ["https://example.test/other/v1"]):
        with pytest.raises(A2ACarrierError, match="extension is not active"):
            parse_a2a_data_part(part, active_extensions=active)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda p: p.update({"text": "conflicting content"}), "content member"),
        (lambda p: p.update({"mediaType": "application/json"}), "mediaType"),
        (lambda p: p["data"].update({"type": "wrong"}), "type"),
        (lambda p: p["data"].update({"version": "2"}), "version"),
        (lambda p: p["data"].update({"extra": True}), "data members"),
        (lambda p: p["metadata"].pop(A2A_EXTENSION_URI), "metadata"),
        (
            lambda p: p["metadata"][A2A_EXTENSION_URI].update({"schema": "wrong"}),
            "schema",
        ),
        (lambda p: p["data"]["envelope"].pop("signature"), "invalid envelope"),
    ],
)
def test_parser_fails_closed_on_carrier_or_envelope_drift(mutation, message: str) -> None:
    part = load_fixture()
    mutation(part)
    with pytest.raises(A2ACarrierError, match=message):
        parse_a2a_data_part(part, active_extensions=[A2A_EXTENSION_URI])


def test_carrier_never_uses_a2a_task_or_context_as_session_identity() -> None:
    part = load_fixture()
    part["metadata"]["a2a"] = {"taskId": "task-other", "contextId": "ctx-other"}
    envelope = parse_a2a_data_part(part, active_extensions=[A2A_EXTENSION_URI])
    assert envelope["session_id"] == "ses_a2a_carrier_0001"
    assert "taskId" not in envelope
    assert "contextId" not in envelope


@pytest.mark.parametrize("a2a_id", ["taskId", "contextId", "task_id", "context_id"])
def test_a2a_identifiers_inside_signed_envelope_are_refused(a2a_id: str) -> None:
    part = load_fixture()
    part["data"]["envelope"][a2a_id] = "carrier-owned"
    with pytest.raises(A2ACarrierError, match="A2A identifiers belong outside signed bytes"):
        parse_a2a_data_part(part, active_extensions=[A2A_EXTENSION_URI])


def test_errors_do_not_echo_untrusted_payload_values() -> None:
    sentinel = "SECRET-SENTINEL-DO-NOT-ECHO"
    part = load_fixture()
    part["data"]["envelope"]["type"] = sentinel
    with pytest.raises(A2ACarrierError) as caught:
        parse_a2a_data_part(part, active_extensions=[A2A_EXTENSION_URI])
    assert sentinel not in str(caught.value)


# Activation type parity: Python must reject non-collection and non-string-member inputs.


@pytest.mark.parametrize(
    "bad_active",
    [
        A2A_EXTENSION_URI,  # bare string (URI itself) — must not activate via __contains__
        "other-string",  # bare string, not the URI
        None,  # None is not iterable as a Collection[str]
        {"key": "value"},  # non-iterable-of-strings object (dict iterates keys only)
        {A2A_EXTENSION_URI: "anything"},  # dict whose key IS the URI — must not activate via key membership
    ],
)
def test_activation_rejects_non_collection_shapes(bad_active: object) -> None:
    part = load_fixture()
    with pytest.raises(A2ACarrierError, match="extension is not active"):
        parse_a2a_data_part(part, active_extensions=bad_active)  # type: ignore[arg-type]


def test_activation_rejects_collection_with_non_string_member() -> None:
    part = load_fixture()
    with pytest.raises(A2ACarrierError, match="extension is not active"):
        parse_a2a_data_part(part, active_extensions=[A2A_EXTENSION_URI, 42])  # type: ignore[list-item]


def test_activation_accepts_set_and_list() -> None:
    part = load_fixture()
    # Both list and set are valid Collection[str] shapes.
    assert parse_a2a_data_part(part, active_extensions=[A2A_EXTENSION_URI]) is not None
    assert parse_a2a_data_part(part, active_extensions={A2A_EXTENSION_URI}) is not None


# prev_hash chain-pointer shape validation.


@pytest.mark.parametrize(
    "bad_hash",
    [
        None,  # missing (replaced with None)
        "notahash",  # no prefix
        "sha256:abc",  # too short
        "sha256:" + "a" * 63,  # 63 hex chars (one short)
        "sha256:" + "a" * 65,  # 65 hex chars (one long)
        "SHA256:" + "a" * 64,  # uppercase prefix
        "sha256:" + "A" * 64,  # uppercase hex
        "sha256:" + "g" * 64,  # non-hex character
        "md5:" + "a" * 32,  # wrong algorithm prefix
    ],
)
def test_carrier_rejects_malformed_prev_hash(bad_hash: object) -> None:
    part = load_fixture()
    part["data"]["envelope"]["prev_hash"] = bad_hash
    with pytest.raises(A2ACarrierError, match="prev_hash"):
        parse_a2a_data_part(part, active_extensions=[A2A_EXTENSION_URI])


@pytest.mark.parametrize("a2a_id", ["taskId", "contextId", "task_id", "context_id"])
def test_candidate_schema_rejects_a2a_identifiers_inside_envelope(a2a_id: str) -> None:
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "a2a_negotiation_part.schema.json"
    schema = json.loads(schema_path.read_text())
    part = load_fixture()
    part["data"]["envelope"][a2a_id] = "carrier-owned"
    assert list(Draft202012Validator(schema).iter_errors(part)), (
        f"schema should reject envelope with {a2a_id!r}"
    )


def test_carrier_schema_rejects_malformed_prev_hash() -> None:
    from jsonschema import Draft202012Validator

    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "a2a_negotiation_part.schema.json"
    schema = json.loads(schema_path.read_text())
    for bad_hash in [
        "notahash",
        "sha256:abc",
        "sha256:" + "A" * 64,
        "SHA256:" + "a" * 64,
    ]:
        part = load_fixture()
        part["data"]["envelope"]["prev_hash"] = bad_hash
        assert list(Draft202012Validator(schema).iter_errors(part)), f"schema should reject {bad_hash!r}"
