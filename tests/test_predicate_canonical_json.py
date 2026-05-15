from __future__ import annotations

import json
from pathlib import Path

from concordia.predicate import serialize_predicate_canonical


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "predicate_canonical"


def test_all_13_predicate_vectors_match_jcs_bytes() -> None:
    vectors = sorted(FIXTURE_ROOT.glob("vector_*"))
    assert len(vectors) == 13
    for vector_dir in vectors:
        expected = (vector_dir / "expected_canonical.txt").read_text(
            encoding="utf-8"
        ).rstrip("\n")
        predicate = json.loads(expected)
        assert serialize_predicate_canonical(predicate) == expected.encode("utf-8")


def test_vector_13_documents_deterministic_gate_failure() -> None:
    readme = (
        FIXTURE_ROOT / "vector_13_deterministic_gate_failure" / "README.md"
    ).read_text(encoding="utf-8")
    assert "Q2+Q5 coupling test" in readme
    assert "schema_invalid" in readme
