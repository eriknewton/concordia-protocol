"""Structural tests for the generated Concordia assurance truth surfaces."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "docs" / "assurance.json"
GENERATOR = REPO_ROOT / "scripts" / "assurance" / "generate.py"
MANIFEST = REPO_ROOT / "conformance" / "vectors" / "manifest.json"
SUMMARY_RE = re.compile(
    r"\[SUMMARY\] positive=(?P<positive>\d+) mutation=(?P<mutation>\d+) "
    r"canary=(?P<canary>\d+) ok=(?P<ok>\d+) fail=(?P<fail>\d+)"
)
VECTOR_COUNT_RE = re.compile(
    r"\b(?P<count>\d{1,3}(?:,\d{3})+)(?:[- ]vectors?|-vector)\b"
)
COUNT_SURFACES = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "ASSURANCE_MATRIX.md",
    REPO_ROOT / "conformance" / "IMPLEMENTATIONS.md",
    REPO_ROOT / "docs" / "CLAIM_VOCABULARY.md",
    REPO_ROOT / "docs" / "assurance.json",
]
EXPECTED_IDS = [
    "agreement_integrity",
    "agreement_authority",
    "agreement_voluntariness",
    "agreement_justice",
    "payload_confidentiality",
    "metadata_privacy",
]


def _expected_summary() -> str:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    counts = manifest["counts"]
    ok = counts["positive"] + counts["mutation"] + counts["canary"]
    return (
        f"[SUMMARY] positive={counts['positive']} mutation={counts['mutation']} "
        f"canary={counts['canary']} ok={ok} fail=0"
    )


def _expected_vector_count_text() -> str:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    counts = manifest["counts"]
    ok = counts["positive"] + counts["mutation"] + counts["canary"]
    return f"{ok:,}"


def _assert_conformance_counts_match_manifest(surface: Path, text: str) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    counts = manifest["counts"]
    expected_summary_counts = {
        "positive": str(counts["positive"]),
        "mutation": str(counts["mutation"]),
        "canary": str(counts["canary"]),
        "ok": str(counts["positive"] + counts["mutation"] + counts["canary"]),
        "fail": "0",
    }
    expected_count = _expected_vector_count_text()
    matched = False

    for match in SUMMARY_RE.finditer(text):
        matched = True
        assert match.groupdict() == expected_summary_counts, (
            f"{surface} has stale conformance summary {match.group(0)!r}"
        )

    for match in VECTOR_COUNT_RE.finditer(text):
        matched = True
        assert match.group("count") == expected_count, (
            f"{surface} has stale conformance vector count {match.group(0)!r}"
        )

    assert matched, f"{surface} has no manifest-derived conformance count"


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
    vector_count_text = _expected_vector_count_text()
    assert "0.3.0" in integrity
    assert vector_count_text in integrity
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


def test_validator_rejects_evidence_neutral_status_promotion() -> None:
    module = _load_generator()
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    voluntariness = next(
        item for item in data["dimensions"] if item["id"] == "agreement_voluntariness"
    )
    voluntariness["statuses"]["implementation"] = "implemented"
    try:
        module.validate(data)
    except module.AssuranceError as exc:
        assert "reviewed current-status floor" in str(exc)
    else:
        raise AssertionError(
            "validator accepted an evidence-neutral implementation promotion"
        )


def test_validator_rejects_stale_assurance_count_fixture() -> None:
    module = _load_generator()
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    evidence = next(
        item
        for item in data["dimensions"][0]["evidence"]
        if _expected_vector_count_text() in item["summary"]
    )
    evidence["summary"] = evidence["summary"].replace(
        _expected_vector_count_text(), "1,550"
    )
    try:
        module.validate(data)
    except module.AssuranceError as exc:
        assert "conformance vector count" in str(exc)
    else:
        raise AssertionError("validator accepted a stale assurance count fixture")


def test_generated_truth_surfaces_are_current() -> None:
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_published_conformance_summaries_match_manifest() -> None:
    for surface in COUNT_SURFACES:
        _assert_conformance_counts_match_manifest(
            surface, surface.read_text(encoding="utf-8")
        )


def test_published_count_checker_rejects_stale_assurance_fixture() -> None:
    text = (REPO_ROOT / "docs" / "assurance.json").read_text(encoding="utf-8")
    stale_text = text.replace(_expected_vector_count_text(), "1,550", 1)
    try:
        _assert_conformance_counts_match_manifest(
            REPO_ROOT / "docs" / "assurance.json", stale_text
        )
    except AssertionError as exc:
        assert "stale conformance vector count" in str(exc)
    else:
        raise AssertionError("count checker accepted a stale assurance fixture")


def test_published_count_checker_rejects_stale_implementations_fixture() -> None:
    text = (REPO_ROOT / "conformance" / "IMPLEMENTATIONS.md").read_text(
        encoding="utf-8"
    )
    stale_text = text.replace(
        _expected_summary(),
        "[SUMMARY] positive=53 mutation=1492 canary=5 ok=1550 fail=0",
        1,
    )
    try:
        _assert_conformance_counts_match_manifest(
            REPO_ROOT / "conformance" / "IMPLEMENTATIONS.md", stale_text
        )
    except AssertionError as exc:
        assert "stale conformance summary" in str(exc)
    else:
        raise AssertionError("count checker accepted a stale implementations fixture")
