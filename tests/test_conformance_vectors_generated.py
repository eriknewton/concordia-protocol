"""Regression test for generated conformance vectors."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_conformance_vectors_match_generator() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "scripts/conformance/generate_vectors.py", "--check"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr + result.stdout
