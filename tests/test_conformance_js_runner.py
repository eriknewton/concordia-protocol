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

from scripts.conformance import generate_vectors as vector_generator

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNNER = REPO_ROOT / "conformance" / "reference-runner-js" / "runner.mjs"
FULL_SUITE = REPO_ROOT / "conformance" / "vectors"
EXPECTED_FULL_SUMMARY = "[SUMMARY] positive=53 mutation=1490 canary=5 ok=1548 fail=0"
LONG_VERSION_COMPONENT_DIGITS = 5_000
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


def run_version_parser_probe(version: str) -> dict[str, Any]:
    script = """
const runner = await import(process.argv[1]);
const parsed = runner.parseAttestationVersion(process.argv[2]);
console.log(JSON.stringify({
  parsed,
  floorComparison: parsed === null
    ? null
    : runner.compareAttestationVersion(parsed, runner.SET_BINDING_VERSION_FLOOR),
}));
"""
    result = subprocess.run(
        [cast(str, NODE), "--input-type=module", "-e", script, RUNNER.as_uri(), version],
        cwd=REPO_ROOT,
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    return cast(dict[str, Any], json.loads(result.stdout))


def run_chain_head_parser_probe(tmp_path: Path, chain_head: str) -> dict[str, Any]:
    script = """
const runner = await import(process.argv[1]);
console.log(JSON.stringify({
  matched: runner.isSha256Hex(process.argv[2]),
}));
"""
    result = subprocess.run(
        [
            cast(str, NODE),
            "--input-type=module",
            "-e",
            script,
            RUNNER.as_uri(),
            chain_head,
        ],
        cwd=REPO_ROOT,
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    return cast(dict[str, Any], json.loads(result.stdout))


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


def write_receipt_version_suite(
    tmp_path: Path,
    version: str,
    vector_id: str,
    *,
    expected: str = "reject",
) -> Path:
    manifest = load_json(REPO_ROOT / "conformance" / "vectors" / "manifest.json")
    files = cast(dict[str, list[str]], manifest["files"])
    pair = vector_generator.build_receipt_set_binding_fixture()
    messages = copy.deepcopy(pair["messages"])
    key_by_agent = vector_generator.receipt_set_binding_key_by_agent()
    if expected == "accept":
        receipt = vector_generator.draft_receipt_with_resigned_snapshot(
            pair["receipt"],
            {"concordia_attestation": version},
        )
    else:
        receipt = vector_generator.receipt_with_resigned_snapshot(
            pair["receipt"],
            {"concordia_attestation": version},
        )
    vector = vector_generator.Vector(
        vector_id=vector_id,
        title="receipt set-binding rejects unsupported attestation version syntax",
        source_fixture="synthetic/longtail/receipt_set_binding.json",
        record_type="message_chain",
        verification_profile="message-chain-v1",
        input_data={"messages": messages, "receipt": receipt},
        context={
            "expected_message_count": len(messages),
            "expected_message_hashes": [
                vector_generator.compute_hash(message) for message in messages
            ],
            "public_keys_b64url": {
                agent_id: key_pair.public_key_b64()
                for agent_id, key_pair in sorted(key_by_agent.items())
            },
        },
        expected=cast(Any, expected),
        expected_reason_class="binding",
        notes="version syntax is checked before receipt set-binding is credited",
    )

    tmp_root = tmp_path / "suite"
    for rel_path in files["schemas"]:
        copy_vector_file(tmp_root, rel_path)
    section = "positive" if expected == "accept" else "mutation"
    vector_rel_path = f"conformance/vectors/{section}/{vector_id}.json"
    vector_path = tmp_root / vector_rel_path
    vector_path.parent.mkdir(parents=True, exist_ok=True)
    vector_path.write_text(
        json.dumps(vector.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    mini_manifest = copy.deepcopy(manifest)
    mini_manifest["counts"]["positive"] = 1 if expected == "accept" else 0
    mini_manifest["counts"]["mutation"] = 0 if expected == "accept" else 1
    mini_manifest["counts"]["canary"] = 0
    mini_manifest["counts"]["diag_canonical_bytes"] = 0
    mini_manifest["files"]["positive"] = [vector_rel_path] if expected == "accept" else []
    mini_manifest["files"]["mutation"] = [] if expected == "accept" else [vector_rel_path]
    mini_manifest["files"]["canary"] = []
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


def test_js_reference_runner_accepts_long_valid_version_component(tmp_path: Path) -> None:
    version = "0." + ("9" * LONG_VERSION_COMPONENT_DIGITS) + ".0"
    vector_id = "pos-test-js-receipt-version-long-minor"
    suite = write_receipt_version_suite(tmp_path, version, vector_id, expected="accept")

    result = run_runner(suite)

    assert result.returncode == 0, result.stderr + result.stdout
    assert f"[OK] {vector_id}" in result.stdout


@pytest.mark.parametrize(
    ("version", "expected_parsed", "floor_comparison"),
    [
        ("0.3.0", ["0", "3", "0"], 0),
        ("0." + ("9" * LONG_VERSION_COMPONENT_DIGITS) + ".0", None, 1),
        ("0.3.0\n", None, None),
        ("0.03.0", None, None),
        ("0.2.9", ["0", "2", "9"], -1),
        # Length decides before digit order: "10" > "3" although "1" < "3".
        ("0.10.0", ["0", "10", "0"], 1),
        ("0.2.10", ["0", "2", "10"], -1),
        ("1.0.0", ["1", "0", "0"], 1),
    ],
)
def test_js_reference_runner_version_parser_uses_protocol_rule(
    version: str,
    expected_parsed: list[str] | None,
    floor_comparison: int | None,
) -> None:
    parsed = run_version_parser_probe(version)

    if expected_parsed is None and floor_comparison is not None:
        expected_parsed = version.split(".")
    assert parsed["parsed"] == expected_parsed
    assert parsed["floorComparison"] == floor_comparison


def test_js_reference_runner_chain_head_parser_uses_protocol_rule(tmp_path: Path) -> None:
    parsed = run_chain_head_parser_probe(
        tmp_path,
        "sha256:" + ("a" * 64) + "\n",
    )

    assert parsed == {"matched": False}


def test_symlinked_runner_still_runs_every_vector(tmp_path: Path) -> None:
    """A launch through a symlink runs the full suite instead of exiting early."""
    link = tmp_path / "runner.mjs"
    link.symlink_to(RUNNER)
    result = subprocess.run(
        [cast(str, NODE), str(link), str(FULL_SUITE)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == EXPECTED_FULL_SUMMARY
