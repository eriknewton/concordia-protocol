"""Regression tests for the Node.js conformance reference runner."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNNER = REPO_ROOT / "conformance" / "reference-runner-js" / "runner.mjs"
FULL_SUITE = REPO_ROOT / "conformance" / "vectors"
EXPECTED_FULL_SUMMARY = "[SUMMARY] positive=54 mutation=1484 canary=5 ok=1543 fail=0"
CANARY_REGRESSIONS = {
    "canary-chain-splice": "skip-linkage-walk",
    "canary-preimage-includes-signature": "preimage-includes-signature",
    "canary-schema-skipped": "schema-skipped",
    "canary-decision-id-not-recomputed": "decision-id-not-recomputed",
    "canary-receipt-set-unchecked": "receipt-set-unchecked",
}

NODE = shutil.which("node")
if NODE is None:
    pytest.skip(
        "node executable is required for JS conformance runner tests; CI installs Node 20",
        allow_module_level=True,
    )


def load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def run_runner(
    suite: Path,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
    }
    if extra_env is not None:
        env.update(extra_env)
    return subprocess.run(
        [cast(str, NODE), str(RUNNER), str(suite)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def copy_vector_file(tmp_root: Path, rel_path: str) -> None:
    source = REPO_ROOT / rel_path
    dest = tmp_root / rel_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)


def write_minimal_suite(tmp_path: Path, canary_id: str) -> Path:
    manifest = load_json(REPO_ROOT / "conformance" / "vectors" / "manifest.json")
    files = cast(dict[str, list[str]], manifest["files"])
    positive_file = "conformance/vectors/positive/pos-1404-decision-id.json"
    canary_file = next(path for path in files["canary"] if path.endswith(f"{canary_id}.json"))

    tmp_root = tmp_path / "suite"
    for rel_path in [positive_file, canary_file, *files["schemas"]]:
        copy_vector_file(tmp_root, rel_path)

    mini_manifest = copy.deepcopy(manifest)
    mini_manifest["counts"]["positive"] = 1
    mini_manifest["counts"]["mutation"] = 0
    mini_manifest["counts"]["canary"] = 1
    mini_manifest["counts"]["diag_canonical_bytes"] = 0
    mini_manifest["files"]["positive"] = [positive_file]
    mini_manifest["files"]["mutation"] = []
    mini_manifest["files"]["canary"] = [canary_file]
    mini_manifest["files"]["diag_canonical_bytes"] = []
    manifest_path = tmp_root / "conformance" / "vectors" / "manifest.json"
    manifest_path.write_text(
        json.dumps(mini_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return tmp_root / "conformance" / "vectors"


def test_js_reference_runner_accepts_real_suite() -> None:
    result = run_runner(FULL_SUITE)

    assert result.returncode == 0, result.stderr + result.stdout
    assert EXPECTED_FULL_SUMMARY in result.stdout


def test_js_canary_regression_discrimination(tmp_path: Path) -> None:
    for canary_id, regression in CANARY_REGRESSIONS.items():
        suite = write_minimal_suite(tmp_path / canary_id, canary_id)
        result = run_runner(
            suite,
            extra_env={
                "CONCORDIA_CONFORMANCE_TEST_REGRESS": "1",
                "RUNNER_REGRESS": regression,
            },
        )

        assert result.returncode == 1, result.stderr + result.stdout
        assert f"[FAIL] {canary_id} expected=reject got=accept" in result.stdout
        assert "[OK] pos-1404-decision-id" in result.stdout
        assert "[SUMMARY] positive=1 mutation=0 canary=1 ok=1 fail=1" in result.stdout


def test_js_reference_runner_rejects_tampered_vector(tmp_path: Path) -> None:
    suite_root = tmp_path / "suite" / "conformance" / "vectors"
    shutil.copytree(FULL_SUITE, suite_root)
    vector_path = suite_root / "positive" / "pos-1404-decision-id.json"
    original = vector_path.read_bytes()
    tampered = original.replace(b"sha256:15f84", b"sha256:05f84", 1)
    assert tampered != original
    vector_path.write_bytes(tampered)

    result = run_runner(suite_root)

    assert result.returncode == 1, result.stderr + result.stdout
    assert "[FAIL] pos-1404-decision-id expected=accept got=reject" in result.stdout
