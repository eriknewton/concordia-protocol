"""Spec test: Foxbook typed-reference worked example validates against
the §11.5.6 reference schema.

Loads the cross_protocol/foxbook-typed-reference.json fixture and confirms
it validates against schemas/reference.schema.json. Also confirms the
Foxbook typed-reference v1.0 required fields are present in the extensions
map. See SPEC.md §11.5.7 worked example.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REFERENCE_SCHEMA_PATH = REPO_ROOT / "schemas" / "reference.schema.json"
FIXTURE_PATH = (
    REPO_ROOT / "tests" / "fixtures" / "cross_protocol" / "foxbook-typed-reference.json"
)


@pytest.fixture(scope="module")
def reference_schema() -> dict:
    with REFERENCE_SCHEMA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def reference_validator(reference_schema: dict) -> Draft202012Validator:
    return Draft202012Validator(reference_schema)


@pytest.fixture(scope="module")
def fixture() -> dict:
    with FIXTURE_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


class TestFoxbookTypedReference:
    """Foxbook transparency-log typed reference rides the generic
    references[] surface (§11.5.7 worked example)."""

    def test_fixture_exists(self) -> None:
        assert FIXTURE_PATH.is_file(), (
            f"Foxbook typed-reference fixture missing at {FIXTURE_PATH}"
        )

    def test_reference_validates_against_schema(
        self, reference_validator: Draft202012Validator, fixture: dict
    ) -> None:
        """The worked-example reference object MUST validate against the
        §11.5.6 reference schema fragment."""
        reference_validator.validate(fixture["reference"])

    def test_required_fields_present(
        self, reference_validator: Draft202012Validator, fixture: dict
    ) -> None:
        ref = fixture["reference"]
        assert ref["id"]
        assert ref["type"]
        assert ref["relationship"]

    def test_foxbook_urn_shape(self, fixture: dict) -> None:
        """The id SHOULD use the Foxbook URN scheme from §11.5.7."""
        ref_id = fixture["reference"]["id"]
        assert ref_id.startswith("urn:foxbook:leaf:"), (
            f"Expected urn:foxbook:leaf:* URN, got {ref_id}"
        )

    def test_extensions_carry_foxbook_typed_reference_fields(
        self, fixture: dict
    ) -> None:
        """All Foxbook typed-reference v1.0 required fields MUST be
        present in the extensions map."""
        extensions = fixture["reference"].get("extensions", {})
        expected_fields = fixture["foxbook_typed_reference_v1_required_fields"]
        for field in expected_fields:
            assert field in extensions, (
                f"Foxbook v1.0 required field '{field}' missing from extensions"
            )

    def test_typed_reference_version_is_1_0(self, fixture: dict) -> None:
        extensions = fixture["reference"]["extensions"]
        assert extensions["typed_reference_version"] == "1.0"

    def test_tl_leaf_canonical_hash_is_64_hex(self, fixture: dict) -> None:
        """tl_leaf_canonical_hash must be a 64-char lowercase hex string
        (SHA-256 hash per RFC 9162)."""
        h = fixture["reference"]["extensions"]["tl_leaf_canonical_hash"]
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_verified_signing_key_hex_is_64_hex(self, fixture: dict) -> None:
        """verified_signing_key_hex must be a 64-char lowercase hex string
        (Ed25519 public key)."""
        k = fixture["reference"]["extensions"]["verified_signing_key_hex"]
        assert len(k) == 64
        assert all(c in "0123456789abcdef" for c in k)

    def test_leaf_index_is_nonnegative_integer(self, fixture: dict) -> None:
        leaf_index = fixture["reference"]["extensions"]["leaf_index"]
        assert isinstance(leaf_index, int)
        assert leaf_index >= 0

    def test_tl_url_is_https(self, fixture: dict) -> None:
        tl_url = fixture["reference"]["extensions"]["tl_url"]
        assert tl_url.startswith("https://")

    def test_no_new_top_level_fields(self, fixture: dict) -> None:
        """Non-dependency guardrail: the Foxbook typed reference uses ONLY
        fields defined in the §11.5.6 schema. No Foxbook-specific fields
        at the top level of the reference object."""
        allowed_keys = {
            "id", "type", "relationship", "version",
            "signed_at", "signer_did", "extensions",
        }
        ref_keys = set(fixture["reference"].keys())
        extra = ref_keys - allowed_keys
        assert not extra, (
            f"Unexpected top-level keys {extra} -- Foxbook fields belong "
            "in extensions, not at the reference top level"
        )
