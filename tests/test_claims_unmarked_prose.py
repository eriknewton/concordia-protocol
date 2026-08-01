"""Regression tests for unmarked claim-shaped prose detection."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_claims_runner():
    repo_root = Path(__file__).resolve().parent.parent
    module_path = repo_root / "scripts" / "claims" / "run.py"
    spec = importlib.util.spec_from_file_location("claims_run_for_tests", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


claims_run = load_claims_runner()


def test_unmarked_claim_probe_is_reported(tmp_path: Path) -> None:
    probe = tmp_path / "docs" / "zz_probe.md"
    probe.parent.mkdir()
    probe.write_text(
        "# Probe\n\n"
        "No implementation is privileged, including ours. "
        "Concordia is formally verified end to end.\n",
        encoding="utf-8",
    )

    findings, skipped, errors = claims_run.scan_unmarked_claims_in_path(probe)

    assert errors == []
    assert skipped == []
    assert [
        (finding.pattern_label, finding.line, finding.sentence)
        for finding in findings
    ] == [
        (
            "no implementation is/are",
            3,
            "No implementation is privileged, including ours.",
        ),
        (
            "formally verified",
            3,
            "Concordia is formally verified end to end.",
        ),
    ]


def test_marked_claim_and_not_a_claim_region_are_ignored(tmp_path: Path) -> None:
    doc = tmp_path / "docs" / "safe.md"
    doc.parent.mkdir()
    doc.write_text(
        "# Safe\n\n"
        "<!-- claim:probe -->No implementation is privileged, including ours."
        "<!-- /claim -->\n\n"
        "<!-- not-a-claim -->\n"
        "Concordia is formally verified end to end.\n"
        "<!-- /not-a-claim -->\n",
        encoding="utf-8",
    )

    findings, skipped, errors = claims_run.scan_unmarked_claims_in_path(doc)

    assert errors == []
    assert findings == []
    assert len(skipped) == 1
    assert "not-a-claim skipped: Concordia is formally verified end to end." in skipped[0]
