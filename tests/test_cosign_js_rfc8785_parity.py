"""JS co-signature canonicalization agrees with an independent RFC 8785 oracle."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import rfc8785

REPO_ROOT = Path(__file__).resolve().parent.parent

VECTORS: list[tuple[str, object]] = [
    (
        "utf16_key_ordering",
        {"\ue000": 1, "😀": 2, "𐀀": 3, "a": 4, "z": 5},
    ),
    (
        "string_escaping",
        {
            "strings": [
                'quote " slash \\ newline\n tab\t nul\u0000 unit\u001f',
                "snowman ☃",
                "literal unicode escape: \\u263a",
                "\b\f\r",
            ]
        },
    ),
    (
        "integer_and_float_formatting",
        {
            "limits": {
                "safe_integer": 9007199254740991,
                "exact_float_integer": 9007199254740992.0,
            },
            "numbers": [
                0,
                -7,
                1.5,
                -3.25,
                1e30,
                1e21,
                1e20,
                1e-6,
                1e-7,
                5e-7,
                333333333.3333333,
                -0.0000033333333333333333,
            ],
        },
    ),
    (
        "nested_objects_arrays_empty_containers",
        {
            "nested": {
                "b": [{"z": 0, "a": []}, {}],
                "a": {"empty": {}, "array": [True, False, None]},
            },
            "empty_array": [],
            "empty_object": {},
        },
    ),
]

_NODE_SCRIPT = """
import { readFileSync } from "node:fs";
import { stableStringify } from "./scripts/js-parity/cosignature.mjs";

const input = JSON.parse(readFileSync(0, "utf8"));
process.stdout.write(stableStringify(input));
"""


def _js_stable_stringify(node: str, value: object) -> bytes:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    result = subprocess.run(
        [node, "--input-type=module", "-e", _NODE_SCRIPT],
        input=payload,
        capture_output=True,
        check=False,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, (
        f"node canonicalizer exited {result.returncode}\n"
        f"stdout:\n{result.stdout.decode('utf-8', 'replace')}\n"
        f"stderr:\n{result.stderr.decode('utf-8', 'replace')}"
    )
    return result.stdout


@pytest.mark.integration
def test_js_cosign_canonicalization_matches_rfc8785_reference() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node binary not available; CI installs Node 20")

    for name, vector in VECTORS:
        expected = rfc8785.dumps(vector)
        actual = _js_stable_stringify(node, vector)
        assert actual == expected, (
            f"{name} canonicalization mismatch\n"
            f"expected: {expected!r}\n"
            f"actual:   {actual!r}"
        )

    print(f"JS_RFC8785_PARITY: node={node} vectors={len(VECTORS)} compared")
