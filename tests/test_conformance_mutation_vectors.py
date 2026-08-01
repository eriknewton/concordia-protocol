"""Regression tests for generated conformance mutation vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_REASON_CLASSES = {
    "schema",
    "signature",
    "digest",
    "binding",
    "temporal",
    "privacy",
}
TOLERATED_SIGNATURE_ESCAPE_NOTE = (
    "tolerated-escape: signature block is outside its own preimage"
)
EXPECTED_MUTATION_REJECTS = 664
EXPECTED_MUTATION_ACCEPTS = 34
EXPECTED_MUTATION_TOTAL = 698
EXPECTED_BATTERY_COUNTS = {
    "1404/approval_receipt.json": (63, 62, 1),
    "1404/cascade_decision_deny.json": (35, 35, 0),
    "1404/decision_object.json": (13, 13, 0),
    "1404/offer.json": (15, 15, 0),
    "1404/revocation_A.json": (33, 33, 0),
    "1920/fulfillment_attestation.json": (63, 62, 1),
    "synthetic/attestation/attestation.json::attestation-countersign-v1": (
        107,
        104,
        3,
    ),
    "synthetic/attestation/attestation.json::attestation-v1": (107, 78, 29),
    "synthetic/cosign/cosigned_receipt.json": (42, 42, 0),
    "synthetic/mandate/delegated_mandate.json": (82, 82, 0),
    "synthetic/mandate/mandate.json": (51, 51, 0),
    "synthetic/predicate/vector_02.json": (87, 87, 0),
}
EXPECTED_ACCEPTED_IDS = {
    "mut-1404-approval-receipt-0061",
    "mut-1920-fulfillment-attestation-0061",
    "mut-synthetic-attestation-0001",
    "mut-synthetic-attestation-0003",
    "mut-synthetic-attestation-0005",
    "mut-synthetic-attestation-0011",
    "mut-synthetic-attestation-0013",
    "mut-synthetic-attestation-0015",
    "mut-synthetic-attestation-0016",
    "mut-synthetic-attestation-0018",
    "mut-synthetic-attestation-0077",
    "mut-synthetic-attestation-0078",
    "mut-synthetic-attestation-0079",
    "mut-synthetic-attestation-0080",
    "mut-synthetic-attestation-0081",
    "mut-synthetic-attestation-0082",
    "mut-synthetic-attestation-0085",
    "mut-synthetic-attestation-0088",
    "mut-synthetic-attestation-0089",
    "mut-synthetic-attestation-0091",
    "mut-synthetic-attestation-0093",
    "mut-synthetic-attestation-0096",
    "mut-synthetic-attestation-0098",
    "mut-synthetic-attestation-0099",
    "mut-synthetic-attestation-0100",
    "mut-synthetic-attestation-0101",
    "mut-synthetic-attestation-0102",
    "mut-synthetic-attestation-0103",
    "mut-synthetic-attestation-0104",
    "mut-synthetic-attestation-0105",
    "mut-synthetic-attestation-0106",
    "mut-synthetic-attestation-countersign-0045",
    "mut-synthetic-attestation-countersign-0072",
    "mut-synthetic-attestation-countersign-0105",
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

    assert manifest["counts"]["mutation"] == EXPECTED_MUTATION_TOTAL
    assert len(vectors) == EXPECTED_MUTATION_TOTAL
    assert (len(rejects), len(accepts)) == (
        EXPECTED_MUTATION_REJECTS,
        EXPECTED_MUTATION_ACCEPTS,
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


def test_mutation_vectors_pin_justified_accepts() -> None:
    accepts = [
        vector for vector in mutation_vectors() if vector["expected"] == "accept"
    ]

    assert {vector["id"] for vector in accepts} == EXPECTED_ACCEPTED_IDS
    assert all(isinstance(vector["notes"], str) and vector["notes"] for vector in accepts)
    assert {
        vector["notes"]
        for vector in accepts
        if vector["id"] in {
            "mut-1404-approval-receipt-0061",
            "mut-1920-fulfillment-attestation-0061",
        }
    } == {TOLERATED_SIGNATURE_ESCAPE_NOTE}


def test_mutation_manifest_pins_per_battery_splits() -> None:
    manifest = load_json(REPO_ROOT / "conformance" / "vectors" / "manifest.json")
    batteries = cast(list[dict[str, Any]], manifest["mutation_batteries"])

    assert {
        str(item["battery_name"]): (
            int(item["total"]),
            int(item["reject"]),
            int(item["accept"]),
        )
        for item in batteries
    } == EXPECTED_BATTERY_COUNTS

    predicate_battery = next(
        item
        for item in batteries
        if item["battery_name"] == "synthetic/predicate/vector_02.json"
    )
    assert "richest predicate fixture" in predicate_battery["selection_note"]
