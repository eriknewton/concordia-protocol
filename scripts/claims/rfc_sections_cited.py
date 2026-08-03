#!/usr/bin/env python3
"""Fail if canonicalization sites in SPEC.md lack nearby section citations.

Rule: a site is a non-code line that applies or defines RFC 8785/JCS/
canonical-JSON behavior, excluding unrelated uses such as "canonical emit
vocabulary" or schema names. Each site must have either a direct RFC 8785
section citation (for example, §3.2.3 or Section 3.2.3) or the SPEC §9.2.1
canonicalization cross-reference within 12 physical lines. Twelve lines is a
paragraph-sized Markdown wrapping window in this spec; it is large enough for
the number-domain paragraph and small enough not to bless another section.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT / "SPEC.md"
WINDOW = 12

SITE_RE = re.compile(
    r"(?i)(RFC\s*8785|JCS|canonical JSON|canonicalized JSON|canonical-JSON|"
    r"canonicalization|canonical_json|re-canonicalize)"
)
DIRECT_RFC_SECTION_RE = re.compile(
    r"(?i)(?:RFC\s*8785\s*)?(?:§|Section\s+)3(?:\.\d+)+"
)
LOCAL_CANONICAL_SECTION_RE = re.compile(r"§9\.2\.1")
EXCLUDED_PHRASES = (
    "canonical mapping",
    "canonical emit vocabulary",
    "canonical reconciliation",
    "canonical machine-readable schema",
    "tl_leaf_canonical_hash",
)


@dataclass(frozen=True)
class Line:
    number: int
    text: str


def non_code_lines(text: str) -> list[Line]:
    lines: list[Line] = []
    in_code_block = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            continue
        lines.append(Line(number=number, text=line))
    return lines


def is_site(line: Line) -> bool:
    stripped = line.text.strip()
    if not stripped:
        return False
    lower = stripped.lower()
    if any(phrase in lower for phrase in EXCLUDED_PHRASES):
        return False
    if "does not ship a standalone predicate primitive" in lower:
        return False
    return bool(SITE_RE.search(stripped))


def nearby_lines(lines: list[Line], index: int) -> str:
    start = max(0, index - WINDOW)
    end = min(len(lines), index + WINDOW + 1)
    return "\n".join(line.text for line in lines[start:end])


def has_section_citation(context: str) -> bool:
    if DIRECT_RFC_SECTION_RE.search(context):
        return True
    return bool(LOCAL_CANONICAL_SECTION_RE.search(context))


def main() -> int:
    try:
        text = SPEC_PATH.read_text(encoding="utf-8")
    except Exception as exc:
        print(f"[FAIL] cannot read {SPEC_PATH}: {exc}", file=sys.stderr)
        return 1

    lines = non_code_lines(text)
    sites: list[tuple[int, Line]] = [
        (index, line) for index, line in enumerate(lines) if is_site(line)
    ]
    if not sites:
        print(
            f"[FAIL] {SPEC_PATH.name}: found zero canonicalization sites; detection rule broke",
            file=sys.stderr,
        )
        return 1

    missing: list[Line] = []
    for index, line in sites:
        if not has_section_citation(nearby_lines(lines, index)):
            missing.append(line)

    if missing:
        print(
            "[FAIL] canonicalization site(s) lack an RFC 8785 section citation "
            f"or SPEC §9.2.1 cross-reference within {WINDOW} lines:",
            file=sys.stderr,
        )
        for line in missing:
            print(f"  {SPEC_PATH.name}:{line.number}: {line.text.strip()}", file=sys.stderr)
        return 1

    print(
        f"[OK] canonicalization section citations present "
        f"(sites={len(sites)}, window={WINDOW} lines)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
