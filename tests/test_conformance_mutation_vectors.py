"""Regression tests for generated conformance mutation vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_REASON_CLASSES = {"schema", "signature", "digest", "binding", "temporal"}
TOLERATED_SIGNATURE_ESCAPE_NOTE = (
    "tolerated-escape: signature block is outside its own preimage"
)
SDK_BATTERY_REJECTS = 219
SDK_BATTERY_ACCEPTS = 3
SDK_BATTERY_TOTAL = 222
D2_ACCEPTED_IDS = {
    "mut-1404-approval-receipt-0061",
    "mut-1920-fulfillment-attestation-0061",
}
D2_ACCEPTED_TITLES = {
    "approval_receipt: inject signature",
    "fulfillment_attestation: inject signature",
}


def load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def mutation_vectors() -> list[dict[str, Any]]:
    manifest = load_json(REPO_ROOT / "conformance" / "vectors" / "manifest.json")
    mutation_files = cast(list[str], manifest["files"]["mutation"])
    return [load_json(REPO_ROOT / file_name) for file_name in mutation_files]


def test_mutation_manifest_count_and_expected_split() -> None:
    manifest = load_json(REPO_ROOT / "conformance" / "vectors" / "manifest.json")
    vectors = mutation_vectors()
    accepts = [vector for vector in vectors if vector["expected"] == "accept"]
    rejects = [vector for vector in vectors if vector["expected"] == "reject"]

    assert manifest["counts"]["mutation"] == SDK_BATTERY_TOTAL
    assert len(vectors) == SDK_BATTERY_TOTAL
    assert (len(rejects), len(accepts)) == (
        SDK_BATTERY_REJECTS + 1,
        SDK_BATTERY_ACCEPTS - 1,
    )

    for vector in rejects:
        assert vector["expected_reason_class"] in EXPECTED_REASON_CLASSES
    for vector in accepts:
        assert vector["expected_reason_class"] is None


def test_mutation_vectors_pin_d1_raw_vs_sdk_divergence() -> None:
    vectors_by_title = {
        cast(str, vector["title"]): vector for vector in mutation_vectors()
    }

    d1_divergence = vectors_by_title["revocation_A: drop cascade_depth"]
    assert d1_divergence["expected"] == "reject"
    assert d1_divergence["expected_reason_class"] == "schema"


def test_mutation_vectors_pin_d2_tolerated_accepts() -> None:
    accepts = [
        vector for vector in mutation_vectors() if vector["expected"] == "accept"
    ]

    assert {vector["id"] for vector in accepts} == D2_ACCEPTED_IDS
    assert {vector["title"] for vector in accepts} == D2_ACCEPTED_TITLES
    assert {
        vector["notes"] for vector in accepts
    } == {TOLERATED_SIGNATURE_ESCAPE_NOTE}
