#!/usr/bin/env python3
"""Run the executable claims gate."""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "docs" / "claims.yaml"
CI_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
REQUIRED_KEYS = {"id", "claim", "stated_in", "check"}
CHECK_TIMEOUT_SECONDS = 120


class ManifestError(Exception):
    """The claims manifest is malformed."""


@dataclass(frozen=True)
class Claim:
    claim_id: str
    claim: str
    stated_in: str
    check: str


@dataclass(frozen=True)
class ClaimResult:
    claim_id: str
    ok: bool
    message: str
    output: str = ""


def parse_scalar(value: str, line_number: int) -> str:
    value = value.strip()
    if not value:
        raise ManifestError(f"line {line_number}: empty scalar value")
    if value[0] in {"'", '"'}:
        try:
            parsed = ast.literal_eval(value)
        except Exception as exc:
            raise ManifestError(f"line {line_number}: invalid quoted scalar: {exc}") from exc
        if not isinstance(parsed, str):
            raise ManifestError(f"line {line_number}: quoted scalar did not parse as string")
        return parsed
    return value


def parse_key_value(text: str, line_number: int) -> tuple[str, str]:
    if ":" not in text:
        raise ManifestError(f"line {line_number}: expected key: value")
    key, value = text.split(":", 1)
    key = key.strip()
    if key not in REQUIRED_KEYS:
        raise ManifestError(f"line {line_number}: unknown key {key!r}")
    return key, parse_scalar(value, line_number)


def parse_manifest(path: Path) -> list[Claim]:
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    if not raw_lines or not any(line.strip() for line in raw_lines):
        raise ManifestError(f"{path}: manifest is empty")

    meaningful = [(i + 1, line) for i, line in enumerate(raw_lines) if line.strip()]
    if not meaningful or meaningful[0][1].strip() != "claims:":
        raise ManifestError("manifest must start with 'claims:'")

    entries: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    seen_ids: set[str] = set()

    for line_number, line in meaningful[1:]:
        stripped = line.strip()
        if stripped.startswith("- "):
            if current is not None:
                entries.append(current)
            current = {}
            remainder = stripped[2:].strip()
            if remainder:
                key, value = parse_key_value(remainder, line_number)
                current[key] = value
            continue

        if current is None:
            raise ManifestError(f"line {line_number}: key appears before first claim entry")
        if not line.startswith("    "):
            raise ManifestError(f"line {line_number}: expected four-space claim key indentation")
        key, value = parse_key_value(stripped, line_number)
        if key in current:
            raise ManifestError(f"line {line_number}: duplicate key {key!r}")
        current[key] = value

    if current is not None:
        entries.append(current)
    if not entries:
        raise ManifestError("manifest contains no claims")

    claims: list[Claim] = []
    for index, entry in enumerate(entries, start=1):
        missing = REQUIRED_KEYS.difference(entry)
        if missing:
            raise ManifestError(f"claim entry {index}: missing keys {sorted(missing)}")
        claim_id = entry["id"]
        if claim_id in seen_ids:
            raise ManifestError(f"duplicate claim id {claim_id!r}")
        seen_ids.add(claim_id)
        claims.append(
            Claim(
                claim_id=claim_id,
                claim=entry["claim"],
                stated_in=entry["stated_in"],
                check=entry["check"],
            )
        )
    return claims


def normalized_text(value: str) -> str:
    return " ".join(value.split())


def validate_stated_claim(claim: Claim) -> str | None:
    stated_path = REPO_ROOT / claim.stated_in
    try:
        resolved = stated_path.resolve()
    except Exception as exc:
        return f"stated_in path cannot be resolved: {claim.stated_in}: {exc}"
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError:
        return f"stated_in path escapes repository: {claim.stated_in}"
    if not stated_path.is_file():
        return f"stated_in file does not exist: {claim.stated_in}"
    try:
        text = stated_path.read_text(encoding="utf-8")
    except Exception as exc:
        return f"stated_in file is unreadable: {claim.stated_in}: {exc}"
    if normalized_text(claim.claim) not in normalized_text(text):
        return f"claim text is not present in stated_in file: {claim.stated_in}"
    return None


def ci_job_names(path: Path) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        raise ManifestError(f"cannot read CI workflow {path}: {exc}") from exc
    jobs: set[str] = set()
    in_jobs = False
    for line in lines:
        if line.strip() == "jobs:" and not line.startswith(" "):
            in_jobs = True
            continue
        if in_jobs and line and not line.startswith(" "):
            break
        if in_jobs:
            match = re.match(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$", line)
            if match:
                jobs.add(match.group(1))
    if not jobs:
        raise ManifestError(f"{path}: no CI jobs found")
    return jobs


def run_script_check(claim: Claim) -> ClaimResult:
    check_path = Path(claim.check)
    if check_path.is_absolute():
        return ClaimResult(claim.claim_id, False, f"check path must be relative: {claim.check}")
    resolved = (REPO_ROOT / check_path).resolve()
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError:
        return ClaimResult(claim.claim_id, False, f"check path escapes repository: {claim.check}")
    if not resolved.is_file():
        return ClaimResult(claim.claim_id, False, f"check file does not exist: {claim.check}")

    try:
        completed = subprocess.run(
            [sys.executable, str(resolved)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=CHECK_TIMEOUT_SECONDS,
            check=False,
        )
    except Exception as exc:
        return ClaimResult(claim.claim_id, False, f"could not run check {claim.check}: {exc}")

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    if completed.returncode != 0:
        return ClaimResult(
            claim.claim_id,
            False,
            f"{claim.check} exited {completed.returncode}",
            output,
        )
    return ClaimResult(claim.claim_id, True, claim.check, output)


def evaluate_claim(claim: Claim, jobs: set[str]) -> ClaimResult:
    stated_error = validate_stated_claim(claim)
    if stated_error is not None:
        return ClaimResult(claim.claim_id, False, stated_error)
    if not claim.check:
        return ClaimResult(claim.claim_id, False, "claim has no check")
    if claim.check.startswith("ci-job:"):
        job_name = claim.check.removeprefix("ci-job:")
        if not job_name:
            return ClaimResult(claim.claim_id, False, "ci-job check has empty job name")
        if job_name not in jobs:
            return ClaimResult(
                claim.claim_id,
                False,
                f"CI job does not exist: {job_name}",
            )
        return ClaimResult(claim.claim_id, True, f"ci-job:{job_name} exists")
    return run_script_check(claim)


def print_result(result: ClaimResult) -> None:
    status = "OK" if result.ok else "FAIL"
    print(f"[{status}] {result.claim_id}: {result.message}")
    if result.output:
        for line in result.output.rstrip().splitlines():
            print(f"  {line}")


def main() -> int:
    try:
        claims = parse_manifest(MANIFEST_PATH)
        jobs = ci_job_names(CI_PATH)
    except ManifestError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    results = [evaluate_claim(claim, jobs) for claim in claims]
    for result in results:
        print_result(result)

    if not results or any(not result.ok for result in results):
        print("[FAIL] executable claims gate failed", file=sys.stderr)
        return 1
    print(f"[OK] executable claims gate passed ({len(results)} claims)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
