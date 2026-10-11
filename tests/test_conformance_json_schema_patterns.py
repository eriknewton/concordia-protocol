"""Regression tests for conformance JSON Schema regex translation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

from conformance.json_schema_pattern import json_schema_pattern_for_python

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "conformance" / "vectors" / "schemas"
MANIFEST_PATH = REPO_ROOT / "conformance" / "vectors" / "manifest.json"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def walk_patterns(value: Any) -> list[str]:
    patterns: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "pattern" and isinstance(child, str):
                patterns.append(child)
            else:
                patterns.extend(walk_patterns(child))
    elif isinstance(value, list):
        for child in value:
            patterns.extend(walk_patterns(child))
    return patterns


def walk_strings(value: Any) -> list[str]:
    strings: list[str] = []
    if isinstance(value, dict):
        for child in value.values():
            strings.extend(walk_strings(child))
    elif isinstance(value, list):
        for child in value:
            strings.extend(walk_strings(child))
    elif isinstance(value, str):
        strings.append(value)
    return strings


def shipped_patterns() -> list[str]:
    patterns: set[str] = set()
    for schema_path in SCHEMA_DIR.glob("*.json"):
        patterns.update(walk_patterns(load_json(schema_path)))
    return sorted(patterns)


def vector_strings() -> list[str]:
    manifest = cast(dict[str, Any], load_json(MANIFEST_PATH))
    files = cast(dict[str, list[str]], manifest["files"])
    strings: list[str] = []
    for section in ("positive", "mutation", "canary"):
        for rel_path in files[section]:
            strings.extend(walk_strings(load_json(REPO_ROOT / rel_path)))
    return strings


def test_shipped_schema_patterns_rewrite_for_python_regex() -> None:
    values = vector_strings()

    for pattern in shipped_patterns():
        rewritten = json_schema_pattern_for_python(pattern)
        re.compile(rewritten)
        if rewritten == pattern:
            continue
        witnesses = [value for value in values if re.search(pattern, value)]
        assert witnesses, pattern
        newline_witnesses = [
            value for value in witnesses if re.search(pattern, f"{value}\n")
        ]
        assert newline_witnesses, pattern
        for value in newline_witnesses:
            assert re.search(rewritten, f"{value}\n") is None, pattern
