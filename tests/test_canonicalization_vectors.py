"""DELTA-20: shared canonicalization test vectors.

These vectors assert that Python `canonical_json` and the JS
`canonicalJson` implementation in `concordia/static/respond.html`
produce byte-identical output for the same input. The JS output is
generated at test time by running the embedded function via `node`
— if node is not available, the JS half is skipped but the expected
strings still guard the Python side.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from concordia.signing import canonical_json

# ---------- expected canonical strings ----------
# Hand-verified: sorted keys, no whitespace, non-ASCII preserved raw,
# JSON.stringify number formatting (no trailing zeros).
VECTORS: list[tuple[object, str]] = [
    # basic scalars
    ({"a": 1}, '{"a":1}'),
    ({"b": "hello"}, '{"b":"hello"}'),
    ({"x": None}, '{"x":null}'),
    ({"t": True, "f": False}, '{"f":false,"t":true}'),
    # key sort order
    ({"z": 1, "a": 2, "m": 3}, '{"a":2,"m":3,"z":1}'),
    # unicode — must be preserved as raw UTF-8, not escaped
    ({"greeting": "héllo"}, '{"greeting":"héllo"}'),
    ({"emoji": "✓"}, '{"emoji":"✓"}'),
    # floats — finite only, no special representation
    ({"p": 1.5}, '{"p":1.5}'),
    ({"n": -3.25}, '{"n":-3.25}'),
    # integers
    ({"n": 0}, '{"n":0}'),
    ({"n": 42}, '{"n":42}'),
    ({"n": -7}, '{"n":-7}'),
    # nested objects — inner keys also sorted
    ({"outer": {"z": 1, "a": 2}}, '{"outer":{"a":2,"z":1}}'),
    # arrays — order preserved, not sorted
    ({"items": [3, 1, 2]}, '{"items":[3,1,2]}'),
    ({"items": ["b", "a"]}, '{"items":["b","a"]}'),
    # array of objects, each sorted
    (
        {"items": [{"b": 2, "a": 1}, {"y": "z"}]},
        '{"items":[{"a":1,"b":2},{"y":"z"}]}',
    ),
    # empty containers
    ({"e": {}, "a": []}, '{"a":[],"e":{}}'),
    # strings that need escaping
    ({"q": 'he said "hi"'}, '{"q":"he said \\"hi\\""}'),
    ({"bs": "a\\b"}, '{"bs":"a\\\\b"}'),
    ({"nl": "x\ny"}, '{"nl":"x\\ny"}'),
]


@pytest.mark.parametrize("obj,expected", VECTORS)
def test_python_canonical_json_matches_expected(obj: object, expected: str) -> None:
    """Python canonical_json produces the expected canonical string."""
    actual = canonical_json(obj).decode("utf-8")
    assert actual == expected, f"\n want: {expected}\n got:  {actual}"


def _extract_js_canonical_json() -> str:
    html = (
        Path(__file__).parent.parent
        / "concordia"
        / "static"
        / "respond.html"
    ).read_text()
    start = html.find("function canonicalJson(")
    if start < 0:
        pytest.skip("canonicalJson function not found in respond.html")
    # Walk forward to the matching closing brace.
    depth = 0
    end = start
    started = False
    for i, c in enumerate(html[start:], start=start):
        if c == "{":
            depth += 1
            started = True
        elif c == "}":
            depth -= 1
            if started and depth == 0:
                end = i + 1
                break
    return html[start:end]


@pytest.mark.parametrize("obj,expected", VECTORS)
def test_js_canonical_json_matches_python(obj: object, expected: str) -> None:
    """The JS canonicalJson in respond.html agrees with Python canonical_json."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node binary not available")
    js_fn = _extract_js_canonical_json()
    input_json = json.dumps(obj, ensure_ascii=False)
    script = f"""
{js_fn}
const input = {input_json};
process.stdout.write(canonicalJson(input));
"""
    result = subprocess.run(
        [node, "-e", script],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == expected, (
        f"\n want: {expected}\n got:  {result.stdout}"
    )
