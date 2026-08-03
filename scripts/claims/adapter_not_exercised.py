#!/usr/bin/env python3
"""Fail if conformance vectors or reference runners exercise the Verascore adapter."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFORMANCE_ROOT = REPO_ROOT / "conformance"
RUNNER_PATHS = (
    CONFORMANCE_ROOT / "reference-runner" / "runner.py",
    CONFORMANCE_ROOT / "reference-runner-js" / "runner.mjs",
)
SCAN_ROOTS = (
    CONFORMANCE_ROOT / "vectors",
    *RUNNER_PATHS,
)

ADAPTER_PATTERNS = (
    re.compile(r"\bconcordia\.verascore\b"),
    re.compile(r"\bfrom\s+concordia\s+import\s+verascore\b"),
    re.compile(r"\bimport\s+concordia\.verascore\b"),
    re.compile(r"\bmake_verascore_auto_hook\b"),
    re.compile(r"\bVerascoreClient\b"),
)
RUNNER_IMPORT_PATTERNS = (
    re.compile(r"\bfrom\s+concordia(?:\.verascore)?\s+import\b"),
    re.compile(r"\bimport\s+concordia(?:\.verascore)?\b"),
)


def iter_scan_files() -> list[Path]:
    files: list[Path] = []
    for root in SCAN_ROOTS:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(path for path in root.rglob("*") if path.is_file())
    return sorted(files)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def pattern_findings(path: Path, text: str, patterns: tuple[re.Pattern[str], ...]) -> list[str]:
    findings: list[str] = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            findings.append(
                f"{relative(path)}:{line_number(text, match.start())}: "
                f"{match.group(0)}"
            )
    return findings


def main() -> int:
    findings: list[str] = []
    for path in iter_scan_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        findings.extend(pattern_findings(path, text, ADAPTER_PATTERNS))

    for runner in RUNNER_PATHS:
        text = runner.read_text(encoding="utf-8")
        findings.extend(pattern_findings(runner, text, RUNNER_IMPORT_PATTERNS))

    if findings:
        print("[FAIL] conformance adapter references found", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1

    print("[OK] no conformance vector or reference runner imports/invokes concordia.verascore")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
