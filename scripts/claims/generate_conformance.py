#!/usr/bin/env python3
"""Generate the public conformance document from the claims manifest."""

from __future__ import annotations

import difflib
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.claims.run import CI_PATH, MANIFEST_PATH, Claim, parse_manifest

CONFORMANCE_PATH = REPO_ROOT / "docs" / "CONFORMANCE.md"
PREAMBLE_PATH = REPO_ROOT / "docs" / "conformance-preamble.md"
REGENERATION_COMMAND = "python scripts/claims/generate_conformance.py"
CHECK_COMMAND = "python scripts/claims/generate_conformance.py --check"


def _job_block_lines(job_name: str) -> list[str]:
    lines = CI_PATH.read_text(encoding="utf-8").splitlines()
    in_jobs = False
    start: int | None = None

    for index, line in enumerate(lines):
        if line.strip() == "jobs:" and not line.startswith(" "):
            in_jobs = True
            continue
        if in_jobs and line and not line.startswith(" "):
            break
        if in_jobs and re.fullmatch(rf"  {re.escape(job_name)}:\s*(?:#.*)?", line):
            start = index
            break

    if start is None:
        raise RuntimeError(f"CI job does not exist: {job_name}")

    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.fullmatch(r"  [A-Za-z0-9_-]+:\s*(?:#.*)?", lines[index]):
            end = index
            break
    return lines[start:end]


def _dedent_block(lines: list[str]) -> str:
    nonblank_indents = [
        len(line) - len(line.lstrip(" ")) for line in lines if line.strip()
    ]
    if not nonblank_indents:
        return ""
    indent = min(nonblank_indents)
    return "\n".join(line[indent:] if len(line) >= indent else line for line in lines).strip()


def ci_job_run_commands(job_name: str) -> list[str]:
    lines = _job_block_lines(job_name)
    commands: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^        run:\s*(.*)$", lines[index])
        if match is None:
            index += 1
            continue

        value = match.group(1).strip()
        if value in {"|", ">"}:
            block_lines: list[str] = []
            index += 1
            while index < len(lines):
                next_line = lines[index]
                if next_line.strip() and len(next_line) - len(next_line.lstrip(" ")) <= 8:
                    break
                block_lines.append(next_line)
                index += 1
            block = _dedent_block(block_lines)
            if block:
                commands.append(block)
            continue

        if value:
            commands.append(value)
        index += 1

    if not commands:
        raise RuntimeError(f"CI job has no run commands: {job_name}")
    return commands


def verification_commands(claim: Claim) -> list[str]:
    if claim.check.startswith("ci-job:"):
        return ci_job_run_commands(claim.check.removeprefix("ci-job:"))
    return [f"python {claim.check}"]


def render_conformance() -> str:
    claims = parse_manifest(MANIFEST_PATH)
    lines = [
        "# Concordia Conformance Claims",
        "",
        "GENERATED FILE. Source: `docs/claims.yaml`.",
        "",
        "Regenerate with:",
        "",
        "```bash",
        REGENERATION_COMMAND,
        "```",
        "",
        "Check committed output with:",
        "",
        "```bash",
        CHECK_COMMAND,
        "```",
        "",
        "This file is a projection of the claims manifest.",
        "Every listed claim has a manifest check. The check is the failure point when the claim stops matching the repository.",
        "",
    ]

    if PREAMBLE_PATH.exists():
        preamble = PREAMBLE_PATH.read_text(encoding="utf-8")
        lines.extend(preamble.rstrip("\n").splitlines())
        lines.append("")
        lines.append("")

    lines.append("## Claims")
    lines.append("")

    for claim in claims:
        lines.extend(
            [
                f"### `{claim.claim_id}`",
                "",
                "Claim:",
                "",
                f"> {claim.claim}",
                "",
                f"Stated in: `{claim.stated_in}`",
                "",
            ]
        )
        if claim.check.startswith("ci-job:"):
            job_name = claim.check.removeprefix("ci-job:")
            lines.append(f"Enforced by: CI job `{job_name}`")
        else:
            lines.append(f"Enforced by: `{claim.check}`")
        lines.extend(["", "Verify:", "", "```bash"])
        lines.extend(verification_commands(claim))
        lines.extend(["```", ""])

    return "\n".join(lines).rstrip() + "\n"


def write_conformance() -> int:
    output = render_conformance()
    CONFORMANCE_PATH.write_text(output, encoding="utf-8")
    print(f"Wrote {CONFORMANCE_PATH.relative_to(REPO_ROOT).as_posix()}")
    return 0


def check_conformance() -> int:
    expected = render_conformance()
    try:
        actual = CONFORMANCE_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        actual = ""

    if actual == expected:
        print("[OK] docs/CONFORMANCE.md matches generated output")
        return 0

    diff = difflib.unified_diff(
        actual.splitlines(keepends=True),
        expected.splitlines(keepends=True),
        fromfile="docs/CONFORMANCE.md",
        tofile="generated docs/CONFORMANCE.md",
    )
    print("[FAIL] docs/CONFORMANCE.md drifted from generated output", file=sys.stderr)
    print(f"Regenerate with: {REGENERATION_COMMAND}", file=sys.stderr)
    for line in diff:
        print(line, end="", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return write_conformance()
    if args == ["--check"]:
        return check_conformance()
    print(f"usage: {REGENERATION_COMMAND} [--check]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
