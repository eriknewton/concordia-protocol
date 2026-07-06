"""Cross-runtime parity gate for the counterparty co-signature.

Shells to ``node scripts/js-parity/verify_cosign_fixture.mjs`` and asserts the
Concordia-produced fixture (tests/fixtures/concordia_cosigned_receipt.json)
verifies under a faithful copy of Verascore's verifier running on the SAME V8
runtime Verascore uses. This catches any Python-vs-V8 canonicalization
divergence (string escaping, number formatting, key sort) that the in-Python
parity port in test_cosign_producer.py cannot.

Mirrors the shell-to-node pattern in test_js_predicate_parity.py: skip cleanly
when ``node`` is not on PATH (so local Python-only environments stay green); CI
installs Node 20 (see .github/workflows/ci.yml) so this runs there.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER = REPO_ROOT / "scripts" / "js-parity" / "verify_cosign_fixture.mjs"


@pytest.mark.integration
def test_cosign_fixture_verifies_under_v8() -> None:
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
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "PARITY: cosign fixture verifies under V8/Node" in result.stdout, result.stdout
