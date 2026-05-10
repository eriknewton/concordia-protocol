"""Tests that v0.5 emitters produce v0.5 schema URNs."""

import json
from pathlib import Path

import concordia


class TestSchemaUrnEmit:
    """Verify emitted schema URNs carry v0.5."""

    def test_attestation_schema_json_id_is_v05(self):
        schema_path = (
            Path(__file__).resolve().parent.parent / "schemas" / "attestation.schema.json"
        )
        schema = json.loads(schema_path.read_text())
        assert schema["$id"] == "urn:concordia:schema:attestation:v0.5"

    def test_reference_schema_json_id_is_v05(self):
        schema_path = (
            Path(__file__).resolve().parent.parent / "schemas" / "reference.schema.json"
        )
        schema = json.loads(schema_path.read_text())
        assert schema["$id"] == "urn:concordia:schema:reference:v0.5"

    def test_package_version_is_v05(self):
        assert concordia.__version__ == "0.5.0"
