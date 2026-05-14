"""v0.5 spec tests: attestation.schema.json $id and forward-compat with v0.4.

Validates that:

1. schemas/attestation.schema.json $id is bumped to
   urn:concordia:schema:attestation:v0.5.
2. Root attestation.schema.json mirrors schemas/attestation.schema.json
   byte-for-byte (sync verification; SDK loads schemas/, the root copy is
   maintained for downstream consumers that point at the repo root).
3. The schema validates a fresh v0.5-shape attestation produced by the SDK
   (with new optional reference-object fields).
4. v0.4-shape attestations (without the new optional fields) still validate
   under v0.5 (forward-compat).

Spec reference: SPEC.md §11.5.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ATT_SCHEMA_PATH = REPO_ROOT / "schemas" / "attestation.schema.json"
ATT_SCHEMA_ROOT_PATH = REPO_ROOT / "attestation.schema.json"


@pytest.fixture(scope="module")
def attestation_schema() -> dict:
    with ATT_SCHEMA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def attestation_validator(attestation_schema: dict) -> Draft202012Validator:
    return Draft202012Validator(attestation_schema)


class TestSchemaIdentity:
    def test_schemas_attestation_id_is_v05(self, attestation_schema: dict) -> None:
        assert (
            attestation_schema.get("$id")
            == "urn:concordia:schema:attestation:v0.5"
        ), (
            "schemas/attestation.schema.json $id must be bumped to v0.5 per SPEC "
            "§11.5 ratification."
        )

    def test_root_and_schemas_dir_are_in_sync(self) -> None:
        with ATT_SCHEMA_PATH.open("rb") as canonical, ATT_SCHEMA_ROOT_PATH.open(
            "rb"
        ) as root:
            assert canonical.read() == root.read(), (
                "Root attestation.schema.json must be byte-identical to "
                "schemas/attestation.schema.json. The SDK loads schemas/ "
                "canonically; the root copy is kept in sync so downstream "
                "consumers that point at the repo root see the same schema."
            )

    def test_attestation_schema_validates_against_meta(
        self, attestation_schema: dict
    ) -> None:
        Draft202012Validator.check_schema(attestation_schema)


class TestEmbeddedReferenceDef:
    """The attestation schema has an embedded `reference` $def that mirrors
    schemas/reference.schema.json. Both must accept the same shape.
    """

    def test_embedded_reference_required_keys_match_v05(
        self, attestation_schema: dict
    ) -> None:
        ref_def = attestation_schema["$defs"]["reference"]
        assert set(ref_def["required"]) == {"id", "type", "relationship"}

    def test_embedded_reference_relationship_accepts_opaque_strings(
        self, attestation_schema: dict
    ) -> None:
        ref_def = attestation_schema["$defs"]["reference"]
        relationship = ref_def["properties"]["relationship"]
        assert relationship["type"] == "string"
        assert relationship["minLength"] == 1
        assert "enum" not in relationship

    def test_embedded_reference_type_accepts_opaque_strings(
        self, attestation_schema: dict
    ) -> None:
        ref_def = attestation_schema["$defs"]["reference"]
        ref_type = ref_def["properties"]["type"]
        assert ref_type["type"] == "string"
        assert ref_type["minLength"] == 1
        assert "enum" not in ref_type

    def test_embedded_reference_optional_v05_fields_present(
        self, attestation_schema: dict
    ) -> None:
        ref_def = attestation_schema["$defs"]["reference"]
        props = ref_def["properties"]
        for key in ("version", "signed_at", "signer_did", "extensions"):
            assert key in props, (
                f"v0.5 optional reference field '{key}' missing from "
                "schemas/attestation.schema.json $defs.reference per SPEC §11.5.6."
            )


def _minimal_v04_attestation() -> dict:
    """A minimal valid v0.4-shape attestation (no v0.5 optional reference fields).
    Establishes forward-compat: v0.4 attestations must still validate under v0.5.
    """
    return {
        "concordia_attestation": "0.4.0",
        "attestation_id": "att_v04_compat",
        "session_id": "ses_x",
        "timestamp": "2026-04-20T12:00:00Z",
        "outcome": {
            "status": "agreed",
            "rounds": 2,
            "duration_seconds": 30,
        },
        "parties": [
            {
                "agent_id": "a1",
                "role": "initiator",
                "behavior": {},
                "signature": "sig1",
            },
            {
                "agent_id": "a2",
                "role": "responder",
                "behavior": {},
                "signature": "sig2",
            },
        ],
        "meta": {},
        "transcript_hash": "sha256:" + "0" * 64,
        "references": [
            {"id": "att_prior", "type": "receipt", "relationship": "extends"},
        ],
    }


def _v05_shape_attestation() -> dict:
    """A v0.5-shape attestation that exercises the new optional reference
    fields (version, signed_at, signer_did, extensions).
    """
    att = _minimal_v04_attestation()
    att["concordia_attestation"] = "0.5.0"
    att["attestation_id"] = "att_v05_full"
    att["references"] = [
        {
            "id": "urn:concordia:attestation:att_prior",
            "type": "receipt",
            "relationship": "supersedes",
            "version": "0.4.0",
            "signed_at": "2026-04-20T12:00:00Z",
            "signer_did": "did:web:example.org:agent-x",
            "extensions": {"future_field": "opaque"},
        },
        {
            "id": "urn:concordia:mandate:mnd_x",
            "type": "mandate",
            "relationship": "fulfills",
        },
    ]
    return att


class TestForwardCompat:
    def test_v04_attestation_still_validates_under_v05(
        self, attestation_validator: Draft202012Validator
    ) -> None:
        attestation_validator.validate(_minimal_v04_attestation())

    def test_v05_shape_attestation_validates(
        self, attestation_validator: Draft202012Validator
    ) -> None:
        attestation_validator.validate(_v05_shape_attestation())
