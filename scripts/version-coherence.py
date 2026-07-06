#!/usr/bin/env python3
"""version-coherence.py — assert the three Python publish surfaces agree.

The Concordia Python distribution declares its version in three places that
MUST move in lockstep, because they all describe the same published artifact
(`concordia-protocol` on PyPI plus the MCP-registry server entry):

    1. pyproject.toml            -> [project] version
    2. concordia/__init__.py     -> __version__
    3. server.json               -> version (and packages[].version)

If these drift, a release ships a wheel whose `__version__` disagrees with its
package metadata, or an MCP-registry entry that points at a version that was
never published. This guard fails CI on that drift.

SCOPE NOTE (deliberate): plugin.json, the js-sdk (`@concordia-protocol/sdk` on
npm), and any other surface are INTENTIONALLY NOT checked here. The JavaScript
SDK is versioned independently on its own npm release cadence, and the plugin
manifest tracks its own lifecycle; forcing them equal to the Python version
would be wrong. This guard only binds the three Python publish surfaces.

This script READS versions and compares them. It never writes or normalizes a
version number.

Run locally:  python3 scripts/version-coherence.py
Exit code:    0 = coherent, 1 = drift (or a parse error).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read_pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    # Match the [project] table's `version = "..."`. We scope to the first
    # `version =` after the [project] header to avoid matching a tool table.
    in_project = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_project = stripped == "[project]"
            continue
        if in_project:
            m = re.match(r'version\s*=\s*"([^"]+)"', stripped)
            if m:
                return m.group(1)
    raise ValueError("could not find [project] version in pyproject.toml")


def read_init_version() -> str:
    text = (ROOT / "concordia" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        raise ValueError("could not find __version__ in concordia/__init__.py")
    return m.group(1)


def read_server_json_versions() -> list[tuple[str, str]]:
    data = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    out: list[tuple[str, str]] = []
    if "version" in data:
        out.append(("server.json:version", data["version"]))
    for i, pkg in enumerate(data.get("packages", [])):
        if "version" in pkg:
            out.append((f"server.json:packages[{i}].version", pkg["version"]))
    if not out:
        raise ValueError("could not find any version in server.json")
    return out


def main() -> int:
    try:
        surfaces: list[tuple[str, str]] = [
            ("pyproject.toml", read_pyproject_version()),
            ("concordia/__init__.py", read_init_version()),
        ]
        surfaces.extend(read_server_json_versions())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"version-coherence: FAIL — {exc}")
        return 1

    print("version-coherence: checking the three Python publish surfaces")
    for name, version in surfaces:
        print(f"  {name:38s} = {version}")

    versions = {v for _, v in surfaces}
    if len(versions) == 1:
        print(f"version-coherence: PASS — all surfaces at {versions.pop()}")
        return 0

    print("version-coherence: FAIL — version drift across the Python publish surfaces.")
    print("Set pyproject.toml, concordia/__init__.py, and server.json to the same value.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
