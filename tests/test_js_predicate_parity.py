"""Cross-runtime parity gate for the v0.6 predicate canonicalization.

Shells to ``node scripts/js-parity/verify_predicate_vectors.mjs`` and
asserts byte-level parity across all 13 fixture vectors at
``tests/fixtures/predicate_canonical/vector_*/expected_canonical.txt``.

Mirrors the DELTA-20 shell-to-node pattern in
``tests/test_canonicalization_vectors.py``: skip cleanly when ``node`` is
not on PATH (so local Python-only environments still see green), but CI
installs Node 20 (see ``.github/workflows/ci.yml``) so this test runs there.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER = REPO_ROOT / "scripts" / "js-parity" / "verify_predicate_vectors.mjs"


@pytest.mark.integration
def test_js_predicate_parity_13_vectors() -> None:
    """JS canonicalizePredicate matches Python on all 13 fixture vectors."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node binary not available; CI installs Node 20")
    assert VERIFIER.exists(), f"verifier missing at {VERIFIER}"
    result = subprocess.run(
        [node, str(VERIFIER)],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, (
        f"verifier exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    assert "PARITY: 13/13 vectors pass" in result.stdout, (
        f"expected '13/13 vectors pass' summary, got:\n{result.stdout}"
    )
