"""Structural tests for the generated Concordia assurance truth surfaces."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "docs" / "assurance.json"
GENERATOR = REPO_ROOT / "scripts" / "assurance" / "generate.py"
EXPECTED_IDS = [
    "agreement_integrity",
    "agreement_authority",
    "agreement_voluntariness",
    "agreement_justice",
    "payload_confidentiality",
    "metadata_privacy",
]


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("assurance_generator", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_registry_has_exact_stable_dimension_ids_and_required_fields() -> None:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    assert [item["id"] for item in data["dimensions"]] == EXPECTED_IDS
    for dimension in data["dimensions"]:
        assert set(dimension["statuses"]) == {
            "design",
            "implementation",
            "test",
            "drill",
            "external_reproduction",
            "public_claim",
        }
        assert dimension["bounded_claim"]
        assert dimension["evidence"]
        assert dimension["limitations"]
        assert dimension["next_proof"]
        assert dimension["dependencies"]


def test_registry_preserves_load_bearing_claim_bounds() -> None:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    dimensions = {item["id"]: item for item in data["dimensions"]}
    integrity = " ".join(
        [dimensions["agreement_integrity"]["bounded_claim"], *dimensions["agreement_integrity"]["limitations"]]
    ).lower()
    assert "0.3.0" in integrity
    assert "1,541" in integrity
    assert "first-party" in integrity
    assert "not an independent implementation" in integrity
    assert "does not objectively prove" in integrity
    assert dimensions["agreement_authority"]["statuses"]["implementation"] == "partial"
    assert "supplied" in dimensions["agreement_authority"]["bounded_claim"].lower()
    assert dimensions["payload_confidentiality"]["statuses"]["implementation"] == "not_implemented"
    assert dimensions["metadata_privacy"]["statuses"]["implementation"] == "not_implemented"
    assert dimensions["metadata_privacy"]["statuses"]["test"] == "not_verified"
    assert "not transport metadata privacy" in dimensions["metadata_privacy"]["bounded_claim"].lower()


def test_validator_rejects_dimension_id_drift() -> None:
    module = _load_generator()
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    data["dimensions"][0]["id"] = "renamed_integrity"
    try:
        module.validate(data)
    except module.AssuranceError as exc:
        assert "dimension ids" in str(exc)
    else:
        raise AssertionError("validator accepted a renamed stable dimension id")


def test_generated_truth_surfaces_are_current() -> None:
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
