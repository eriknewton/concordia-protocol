"""RFC 8785 canonicalization edge vectors."""

from __future__ import annotations

import json
import shutil
import struct
import subprocess

import pytest

from concordia.signing import _format_number_ecmascript, canonical_json


def _float_from_ieee754_hex(raw: str) -> float:
    return struct.unpack(">d", bytes.fromhex(raw))[0]


def _node_canonical_json(value: object) -> str:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node binary not available")

    script = f"""
function canonicalize(value) {{
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{{" + keys.map((key) => JSON.stringify(key) + ":" + canonicalize(value[key])).join(",") + "}}";
}}
const input = {json.dumps(value, ensure_ascii=False)};
process.stdout.write(canonicalize(input));
"""
    result = subprocess.run(
        [node, "-e", script],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def test_non_bmp_keys_sort_by_utf16_code_units() -> None:
    data = {"\ue000": 1, "😀": 2, "a": 3, "z": 4}
    expected = '{"a":3,"z":4,"😀":2,"\ue000":1}'

    assert canonical_json(data).decode("utf-8") == expected
    assert _node_canonical_json(data) == expected


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (
            {
                "numbers": [1e30, 1e21, 1e20, 1e-6, 1e-7, 5e-7],
                "limits": {
                    "safe": 9007199254740991.0,
                    "next": 9007199254740992.0,
                },
            },
            '{"limits":{"next":9007199254740992,"safe":9007199254740991},'
            '"numbers":[1e+30,1e+21,100000000000000000000,'
            '0.000001,1e-7,5e-7]}',
        ),
        (
            {
                "amount": 1e30,
                "cap": 1e21,
                "floor": 1e-6,
                "tiny": 9.999999999999997e-7,
            },
            '{"amount":1e+30,"cap":1e+21,"floor":0.000001,'
            '"tiny":9.999999999999997e-7}',
        ),
    ],
)
def test_large_integer_valued_float_vectors_match_js(
    data: object, expected: str
) -> None:
    assert canonical_json(data).decode("utf-8") == expected
    assert _node_canonical_json(data) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0000000000000001", "5e-324"),
        ("7fefffffffffffff", "1.7976931348623157e+308"),
        ("4340000000000000", "9007199254740992"),
        ("4430000000000000", "295147905179352830000"),
        ("44b52d02c7e14af5", "9.999999999999997e+22"),
        ("44b52d02c7e14af6", "1e+23"),
        ("44b52d02c7e14af7", "1.0000000000000001e+23"),
        ("444b1ae4d6e2ef4e", "999999999999999700000"),
        ("444b1ae4d6e2ef4f", "999999999999999900000"),
        ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("41b3de4355555555", "333333333.3333333"),
        ("becbf647612f3696", "-0.0000033333333333333333"),
        ("43143ff3c1cb0959", "1424953923781206.2"),
    ],
)
def test_rfc8785_appendix_b_number_samples(raw: str, expected: str) -> None:
    assert _format_number_ecmascript(_float_from_ieee754_hex(raw)) == expected


def test_negative_zero_is_rejected() -> None:
    with pytest.raises(ValueError, match="negative zero"):
        canonical_json({"value": -0.0})
