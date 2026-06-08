"""v0.5 spec tests: schemas/reference.schema.json shape conformance.

These tests load the canonical v0.5 reference object schema and validate
sample reference objects against it. They are spec-level tests; they do
not exercise the Python SDK's runtime emit path (covered separately by
tests/test_references.py at attestation level).

Spec reference: SPEC.md §11.5 Reference linkages.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REFERENCE_SCHEMA_PATH = REPO_ROOT / "schemas" / "reference.schema.json"


@pytest.fixture(scope="module")
def reference_schema() -> dict:
    """Load schemas/reference.schema.json."""
    with REFERENCE_SCHEMA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def reference_validator(reference_schema: dict) -> Draft202012Validator:
    return Draft202012Validator(reference_schema)


class TestReferenceSchemaExists:
    def test_schema_file_exists(self) -> None:
        assert REFERENCE_SCHEMA_PATH.is_file(), (
            f"v0.5 reference schema missing at {REFERENCE_SCHEMA_PATH}. "
            "SPEC.md §11.5.6 names schemas/reference.schema.json as the "
            "canonical machine-readable schema."
        )

    def test_schema_id_is_v05_urn(self, reference_schema: dict) -> None:
        assert reference_schema.get("$id") == "urn:concordia:schema:reference:v0.5", (
            "schemas/reference.schema.json $id must be "
            "urn:concordia:schema:reference:v0.5 per SPEC §11.5.6."
        )

    def test_schema_validates_against_meta(self, reference_schema: dict) -> None:
        Draft202012Validator.check_schema(reference_schema)


class TestMinimalReferenceShape:
    def test_minimal_required_fields_validate(
        self, reference_validator: Draft202012Validator
    ) -> None:
        ref = {
            "id": "att_123e4567-e89b-12d3-a456-426614174000",
            "type": "receipt",
            "relationship": "extends",
        }
        reference_validator.validate(ref)

    @pytest.mark.parametrize("missing_key", ["id", "type", "relationship"])
    def test_missing_required_key_rejected(
        self, reference_validator: Draft202012Validator, missing_key: str
    ) -> None:
        ref = {
            "id": "att_x",
            "type": "receipt",
            "relationship": "references",
        }
        del ref[missing_key]
        with pytest.raises(ValidationError):
            reference_validator.validate(ref)

    def test_empty_id_rejected(
        self, reference_validator: Draft202012Validator
    ) -> None:
        ref = {"id": "", "type": "receipt", "relationship": "references"}
        with pytest.raises(ValidationError):
            reference_validator.validate(ref)


class TestRelationshipVocabulary:
    @pytest.mark.parametrize(
        "rel", ["supersedes", "extends", "fulfills", "references"]
    )
    def test_all_four_relationships_accepted(
        self, reference_validator: Draft202012Validator, rel: str
    ) -> None:
        ref = {"id": "x", "type": "receipt", "relationship": rel}
        reference_validator.validate(ref)

    @pytest.mark.parametrize(
        "future_rel", ["follows", "supercedes", "FULFILLS", "related"]
    )
    def test_unknown_relationship_preserved_at_schema(
        self, reference_validator: Draft202012Validator, future_rel: str
    ) -> None:
        ref = {"id": "x", "type": "receipt", "relationship": future_rel}
        reference_validator.validate(ref)

    def test_empty_relationship_rejected_at_schema(
        self, reference_validator: Draft202012Validator
    ) -> None:
        ref = {"id": "x", "type": "receipt", "relationship": ""}
        with pytest.raises(ValidationError):
            reference_validator.validate(ref)


class TestTypeVocabulary:
    @pytest.mark.parametrize(
        "ref_type", ["receipt", "chain_session", "predicate", "mandate"]
    )
    def test_all_v05_types_accepted(
        self, reference_validator: Draft202012Validator, ref_type: str
    ) -> None:
        ref = {"id": "x", "type": ref_type, "relationship": "references"}
        reference_validator.validate(ref)

    @pytest.mark.parametrize(
        "future_type", ["session", "Receipt", "MANDATE", "envelope"]
    )
    def test_unknown_type_preserved_at_schema(
        self, reference_validator: Draft202012Validator, future_type: str
    ) -> None:
        ref = {"id": "x", "type": future_type, "relationship": "references"}
        reference_validator.validate(ref)

    def test_empty_type_rejected_at_schema(
        self, reference_validator: Draft202012Validator
    ) -> None:
        ref = {"id": "x", "type": "", "relationship": "references"}
        with pytest.raises(ValidationError):
            reference_validator.validate(ref)


class TestOptionalFields:
    def test_version_signed_at_signer_did_validate(
        self, reference_validator: Draft202012Validator
    ) -> None:
        ref = {
            "id": "urn:concordia:attestation:att_x",
            "type": "receipt",
            "relationship": "extends",
            "version": "0.4.0",
            "signed_at": "2026-04-20T12:00:00Z",
            "signer_did": "did:web:example.org:agent-x",
        }
        reference_validator.validate(ref)

    def test_extensions_map_validates(
        self, reference_validator: Draft202012Validator
    ) -> None:
        ref = {
            "id": "x",
            "type": "receipt",
            "relationship": "references",
            "extensions": {
                "future_v0x_field": "opaque_value",
                "another_extension": {"nested": True},
            },
        }
        reference_validator.validate(ref)


class TestUrnShapedIdentifiers:
    """Cross-protocol URN samples per SPEC §11.5.7. Schema does not enforce
    URN shape (id is free-form non-empty string), but URN-shaped ids must
    pass validation cleanly.
    """

    @pytest.mark.parametrize(
        "urn",
        [
            "urn:concordia:attestation:att_123e4567-e89b-12d3-a456-426614174000",
            "urn:concordia:mandate:mnd_abc",
            "urn:concordia:offer:off_xyz",
            "urn:concordia:session:ses_9d4e8f01",
            "urn:a2a:task:task_42",
            "urn:ap2:mandate:mnd_pay_001",
            "urn:x402:payment:0xdeadbeef",
            "urn:erc8004:reputation:entry_99",
            "urn:foxbook:leaf:log.foxbook.dev:42",
        ],
    )
    def test_urn_shaped_id_validates(
        self, reference_validator: Draft202012Validator, urn: str
    ) -> None:
        ref = {"id": urn, "type": "receipt", "relationship": "references"}
        reference_validator.validate(ref)
