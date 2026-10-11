"""Regression tests for the clean-room conformance reference runner."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Any, cast

import pytest

from scripts.conformance import generate_vectors as vector_generator

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNNER = REPO_ROOT / "conformance" / "reference-runner" / "runner.py"
FULL_SUITE = REPO_ROOT / "conformance" / "vectors"
EXPECTED_FULL_SUMMARY = "[SUMMARY] positive=53 mutation=1493 canary=5 ok=1551 fail=0"
LONG_VERSION_COMPONENT_DIGITS = 5_000
CANARY_REGRESSIONS = {
    "canary-chain-splice": "skip-linkage-walk",
    "canary-preimage-includes-signature": "preimage-includes-signature",
    "canary-schema-skipped": "schema-skipped",
    "canary-decision-id-not-recomputed": "decision-id-not-recomputed",
    "canary-receipt-set-unchecked": "receipt-set-unchecked",
}


def load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def clean_site_packages(tmp_path: Path) -> Path:
    source = Path(sysconfig.get_paths()["purelib"])
    clean_site = tmp_path / "clean-site"
    clean_site.mkdir(parents=True)
    blocked_prefixes = (
        "_editable_impl_concordia",
        "concordia_protocol-",
    )
    for child in source.iterdir():
        name = child.name
        if name == "concordia" or name.endswith(".pth"):
            continue
        if any(name.startswith(prefix) for prefix in blocked_prefixes):
            continue
        target = clean_site / name
        target.symlink_to(child, target_is_directory=child.is_dir())
    return clean_site


def run_runner(
    tmp_path: Path,
    suite: Path,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    clean_site = clean_site_packages(tmp_path)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(clean_site),
    }
    if extra_env is not None:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-S", str(RUNNER), str(suite)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def run_version_parser_probe(tmp_path: Path, version: str) -> dict[str, Any]:
    clean_site = clean_site_packages(tmp_path)
    script = """
import importlib.util
import json
import pathlib
import sys

spec = importlib.util.spec_from_file_location("runner_probe", sys.argv[1])
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
parsed = module.parse_attestation_version(sys.argv[2])
print(json.dumps({
    "parsed": parsed,
    "floor_comparison": None
    if parsed is None
    else module.compare_attestation_version(parsed, module.SET_BINDING_VERSION_FLOOR),
}))
"""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(clean_site),
    }
    result = subprocess.run(
        [sys.executable, "-S", "-c", script, str(RUNNER), version],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    return cast(dict[str, Any], json.loads(result.stdout))


def run_chain_head_parser_probe(tmp_path: Path, chain_head: str) -> dict[str, Any]:
    clean_site = clean_site_packages(tmp_path)
    script = """
import importlib.util
import json
import pathlib
import sys

spec = importlib.util.spec_from_file_location("runner_probe", sys.argv[1])
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
module.validate_schema = lambda *args, **kwargs: None
try:
    module.verify_message_chain_receipt_binding(
        pathlib.Path("."),
        {
            "receipt": {
                "concordia_attestation": "0.3.0",
                "chain_head": sys.argv[2],
                "message_count": 1,
            }
        },
        [],
        {},
    )
except module.Reject as exc:
    print(json.dumps({"accepted": False, "reason": str(exc)}))
else:
    print(json.dumps({"accepted": True, "reason": None}))
"""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(clean_site),
    }
    result = subprocess.run(
        [sys.executable, "-S", "-c", script, str(RUNNER), chain_head],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    return cast(dict[str, Any], json.loads(result.stdout))


def run_pattern_rewrite_probe(tmp_path: Path) -> dict[str, Any]:
    clean_site = clean_site_packages(tmp_path)
    script = r"""
import importlib.util
import json
import sys

runner_spec = importlib.util.spec_from_file_location("runner_probe", sys.argv[1])
runner = importlib.util.module_from_spec(runner_spec)
assert runner_spec.loader is not None
sys.modules["runner_probe"] = runner
runner_spec.loader.exec_module(runner)

sys.path.insert(0, sys.argv[3])
generator_spec = importlib.util.spec_from_file_location("generator_probe", sys.argv[2])
generator = importlib.util.module_from_spec(generator_spec)
assert generator_spec.loader is not None
sys.modules["generator_probe"] = generator
generator_spec.loader.exec_module(generator)

cases = [
    [r"\$", r"\$"],
    [r"a\$", r"a\$"],
    [r"[$]$", r"[$]\Z"],
    [r"[^$]+$", r"[^$]+\Z"],
    [r"a$|b$", r"a\Z|b\Z"],
    [r"^(a|b)$", r"^(a|b)\Z"],
    [r"(ab)$", r"(ab)\Z"],
    [r"^abc", r"^abc"],
    [r"a$b$", r"a\Zb\Z"],
]
invalid = [r"[]", r"[^]", r"[]a]"]
result = {"runner": [], "generator": [], "invalid": []}
for source, expected in cases:
    result["runner"].append([source, runner.json_schema_pattern_for_python(source)])
    result["generator"].append([source, generator.json_schema_pattern_for_python(source)])
for source in invalid:
    for module_name, module in [("runner", runner), ("generator", generator)]:
        try:
            module.json_schema_pattern_for_python(source)
        except ValueError:
            result["invalid"].append([module_name, source, "raised"])
        else:
            result["invalid"].append([module_name, source, "accepted"])
print(json.dumps(result))
"""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(clean_site),
    }
    result = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            script,
            str(RUNNER),
            str(REPO_ROOT / "scripts" / "conformance" / "generate_vectors.py"),
            str(REPO_ROOT),
        ],
        cwd=tmp_path,
        env=env,
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


def write_predicate_reference_id_suite(tmp_path: Path) -> Path:
    manifest = load_json(REPO_ROOT / "conformance" / "vectors" / "manifest.json")
    files = cast(dict[str, list[str]], manifest["files"])
    fixtures = vector_generator.build_synthetic_fixtures()
    key_pair = vector_generator.key_pair_from_seed(
        vector_generator.SYNTHETIC_SEEDS["predicate_issuer"]
    )
    predicate = vector_generator.without_signature(
        copy.deepcopy(fixtures.predicates["vector_02"])
    )
    predicate["references"][0]["id"] = f"{predicate['references'][0]['id']}\n"
    predicate["signature"] = vector_generator.sign_b64url(
        key_pair.private_key,
        vector_generator.canonical_json(predicate),
    )
    signed = predicate
    preimage = vector_generator.canonical_json(vector_generator.without_signature(signed))
    vector = vector_generator.Vector(
        vector_id="mut-test-predicate-reference-id-newline",
        title="predicate: reference identifier has trailing newline",
        source_fixture="synthetic/predicate/vector_02.json",
        record_type="predicate",
        verification_profile="predicate-v1",
        input_data=signed,
        context={
            "canonical_sha256": "sha256:" + vector_generator.hashlib.sha256(preimage).hexdigest(),
            "now": vector_generator.fixed_iso_now(),
            "public_key_b64url": fixtures.predicate_seed_manifest[
                "seeds_PUBLIC_test_only_do_not_reuse"
            ]["predicate_issuer"]["public_key_b64url"],
        },
        expected="reject",
        expected_reason_class="schema",
        notes="schema-reject: referenced identifiers do not allow trailing bytes",
    )

    tmp_root = tmp_path / "suite"
    for rel_path in files["schemas"]:
        copy_vector_file(tmp_root, rel_path)
    vector_rel_path = f"conformance/vectors/mutation/{vector.vector_id}.json"
    vector_path = tmp_root / vector_rel_path
    vector_path.parent.mkdir(parents=True, exist_ok=True)
    vector_path.write_text(
        json.dumps(vector.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    mini_manifest = copy.deepcopy(manifest)
    mini_manifest["counts"]["positive"] = 0
    mini_manifest["counts"]["mutation"] = 1
    mini_manifest["counts"]["canary"] = 0
    mini_manifest["counts"]["diag_canonical_bytes"] = 0
    mini_manifest["files"]["positive"] = []
    mini_manifest["files"]["mutation"] = [vector_rel_path]
    mini_manifest["files"]["canary"] = []
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


def test_reference_runner_accepts_real_suite(tmp_path: Path) -> None:
    result = run_runner(tmp_path, FULL_SUITE)

    assert result.returncode == 0, result.stderr + result.stdout
    assert EXPECTED_FULL_SUMMARY in result.stdout


def test_json_schema_pattern_rewrite_cases_match_generator(tmp_path: Path) -> None:
    result = run_pattern_rewrite_probe(tmp_path)

    expected = [
        [r"\$", r"\$"],
        [r"a\$", r"a\$"],
        [r"[$]$", r"[$]\Z"],
        [r"[^$]+$", r"[^$]+\Z"],
        [r"a$|b$", r"a\Z|b\Z"],
        [r"^(a|b)$", r"^(a|b)\Z"],
        [r"(ab)$", r"(ab)\Z"],
        [r"^abc", r"^abc"],
        [r"a$b$", r"a\Zb\Z"],
    ]
    assert result["runner"] == expected
    assert result["generator"] == expected
    assert result["invalid"] == [
        ["runner", r"[]", "raised"],
        ["generator", r"[]", "raised"],
            ["runner", r"[^]", "raised"],
            ["generator", r"[^]", "raised"],
            ["runner", r"[]a]", "raised"],
            ["generator", r"[]a]", "raised"],
        ]


def test_reference_runner_rejects_referenced_identifier_newline(tmp_path: Path) -> None:
    suite = write_predicate_reference_id_suite(tmp_path)

    result = run_runner(tmp_path / "run", suite)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "[OK] mut-test-predicate-reference-id-newline" in result.stdout


def test_canary_regression_discrimination(tmp_path: Path) -> None:
    for canary_id, regression in CANARY_REGRESSIONS.items():
        suite = write_minimal_suite(tmp_path / canary_id, canary_id)
        result = run_runner(
            tmp_path / f"{canary_id}-run",
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


def test_reference_runner_rejects_tampered_vector(tmp_path: Path) -> None:
    suite_root = tmp_path / "suite" / "conformance" / "vectors"
    shutil.copytree(FULL_SUITE, suite_root)
    vector_path = suite_root / "positive" / "pos-1404-decision-id.json"
    original = vector_path.read_bytes()
    tampered = original.replace(b"sha256:15f84", b"sha256:05f84", 1)
    assert tampered != original
    vector_path.write_bytes(tampered)

    result = run_runner(tmp_path / "run", suite_root)

    assert result.returncode == 1, result.stderr + result.stdout
    assert "[FAIL] pos-1404-decision-id expected=accept got=reject" in result.stdout


def test_reference_runner_accepts_long_valid_version_component(tmp_path: Path) -> None:
    version = "0." + ("9" * LONG_VERSION_COMPONENT_DIGITS) + ".0"
    vector_id = "pos-test-receipt-version-long-minor"
    suite = write_receipt_version_suite(tmp_path, version, vector_id, expected="accept")

    result = run_runner(tmp_path / "run", suite)

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
def test_reference_runner_version_parser_uses_protocol_rule(
    tmp_path: Path,
    version: str,
    expected_parsed: list[str] | None,
    floor_comparison: int | None,
) -> None:
    parsed = run_version_parser_probe(tmp_path, version)

    if expected_parsed is None and floor_comparison is not None:
        expected_parsed = version.split(".")
    assert parsed["parsed"] == expected_parsed
    assert parsed["floor_comparison"] == floor_comparison


def test_reference_runner_chain_head_parser_uses_protocol_rule(tmp_path: Path) -> None:
    parsed = run_chain_head_parser_probe(
        tmp_path,
        "sha256:" + ("a" * 64) + "\n",
    )

    assert parsed == {
        "accepted": False,
        "reason": "receipt chain_head is malformed",
    }
