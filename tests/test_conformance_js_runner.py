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
EXPECTED_FULL_SUMMARY = "[SUMMARY] positive=54 mutation=1496 canary=5 ok=1555 fail=0"
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


# Ingest-boundary regression (2026-09-16 delta-11 gate, Codex P1): a plain
# decimal at the 1e21 magnitude is where `String(JSON.parse(literal))` first
# becomes exponential ("1e+21"), which is exactly the shape the runner's old
# `checkNoSpecialFloatValue` `!/[eE]/` exemption let through -- readJson's
# bare `JSON.parse` never scanned the SOURCE text at all. This lives entirely
# under `conformance/reference-runner-js/`, generator-excluded
# (GENERATED_CHECK_EXCLUDED_DIRS in scripts/conformance/generate_vectors.py),
# so it never touches the generated, drift-checked vector corpus; it never
# reaches Ajv schema validation or signature verification either, because
# readJson's own parse throws first -- rejection is proven at the exact
# ingest boundary parseJsonStrict guards in the SDK.
UNSAFE_INTEGER_VECTOR: dict[str, Any] = {
    "schema_version": "concordia-conformance-vector/v1-draft",
    "id": "check-unsafe-integer-ingest",
    "title": (
        "A bare plain-decimal integer at the 1e21 magnitude -- where "
        "String(JSON.parse(literal)) becomes exponential -- is rejected at "
        "the runner's ingest boundary, matching fromJsonText/parseJsonStrict "
        "and the Python reference runner's rfc8785.IntegerDomainError bound."
    ),
    "source_fixture": "delta-11 gate, Codex P1 (2026-09-16 fix round 12)",
    "record_type": "message_chain",
    "verification_profile": "message-chain-v1",
    "expected": "reject",
    "expected_reason_class": "ingest",
    "context": {},
    "input": {
        "messages": [
            {
                "concordia": "0.1.0",
                "id": "msg_check_unsafe_integer_ingest_0001",
                "session_id": "sess_check_unsafe_integer_ingest_0001",
                "type": "negotiate.open",
                "from": {"agent_id": "did:concordia:agent:unsafe-integer-initiator"},
                "to": [{"agent_id": "did:concordia:agent:unsafe-integer-responder"}],
                "timestamp": "2026-09-16T00:00:00Z",
                "prev_hash": f"sha256:{'0' * 64}",
                "body": {"terms": {"quantity": 1000000000000000000000}},
                "reasoning": (
                    "Ingest-boundary canary: quantity is a bare plain-decimal "
                    "integer beyond Number.MAX_SAFE_INTEGER (2^53 - 1), at the "
                    "1e21 magnitude where JS Number#toString switches to "
                    "exponential notation and can defeat a post-parse-only "
                    "unsafe-integer guard. Never reaches signature "
                    "verification: the ingest scan rejects it first."
                ),
                "signature": "not-a-real-signature-ingest-must-reject-before-verification-runs",
            }
        ]
    },
}


def write_unsafe_integer_suite(tmp_path: Path) -> Path:
    tmp_root = tmp_path / "suite"
    vector_rel = "conformance/vectors/mutation/check-unsafe-integer-ingest.json"
    vector_path = tmp_root / vector_rel
    vector_path.parent.mkdir(parents=True, exist_ok=True)
    vector_path.write_text(json.dumps(UNSAFE_INTEGER_VECTOR, indent=2) + "\n", encoding="utf-8")

    manifest = {
        "counts": {"positive": 0, "mutation": 1, "canary": 0, "diag_canonical_bytes": 0},
        "files": {"positive": [], "mutation": [vector_rel], "canary": [], "diag_canonical_bytes": []},
    }
    manifest_path = tmp_root / "conformance" / "vectors" / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return tmp_root / "conformance" / "vectors"


def test_js_reference_runner_rejects_unsafe_integer_at_ingest(tmp_path: Path) -> None:
    suite = write_unsafe_integer_suite(tmp_path)

    result = run_runner(suite)

    # readJson throws on this file (that IS the fix under test), before the
    # harness loop ever reads the vector's OWN `expected` field back out of
    # it -- a file the runner cannot parse can never report what it, once
    # parsed, would have claimed to expect. So `vectorId`/`expected` stay
    # the manifest path / "<unreadable>" placeholder, "<unreadable>" !=
    # "reject" by the harness's plain string comparison, and this vector is
    # scored [FAIL] even though the underlying behavior -- reject the
    # unsafe integer at ingest -- is exactly right. Assert on that FAIL
    # line and the reject verb, not on a green summary: an [OK] here would
    # mean the file parsed far enough to read its own `expected`, which
    # means the fix did NOT reject at the ingest boundary.
    assert result.returncode == 1, result.stderr + result.stdout
    assert (
        "[FAIL] conformance/vectors/mutation/check-unsafe-integer-ingest.json "
        "expected=<unreadable> got=reject" in result.stdout
    ), result.stdout
    assert "[SUMMARY] positive=0 mutation=1 canary=0 ok=0 fail=1" in result.stdout


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
