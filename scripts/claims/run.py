#!/usr/bin/env python3
"""Run the executable claims gate.

Claim markers are scanned only in public Markdown documents: ``SPEC.md``,
``README.md``, and ``docs/**/*.md``. ``Review/`` and internal documentation
directories are intentionally out of scope for this public-claims chokepoint.
"""

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
CLAIM_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
HTML_COMMENT_OPEN = "<!--"
HTML_COMMENT_CLOSE = "-->"
INTERNAL_DOC_DIR_NAMES = {"review", "internal", "_internal", "private"}


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


@dataclass(frozen=True)
class ClaimMarker:
    claim_id: str
    path: Path
    content: str
    start_line: int
    end_line: int


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


def repo_relative(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def is_internal_doc_path(path: Path) -> bool:
    return any(
        part.lower() in INTERNAL_DOC_DIR_NAMES or part.startswith(".") for part in path.parts
    )


def public_doc_paths() -> list[Path]:
    paths = {REPO_ROOT / "SPEC.md", REPO_ROOT / "README.md"}
    docs_root = REPO_ROOT / "docs"
    if not docs_root.is_dir():
        raise ManifestError("public docs directory does not exist: docs/")
    try:
        for path in docs_root.rglob("*.md"):
            relative = path.relative_to(REPO_ROOT)
            if not is_internal_doc_path(relative):
                paths.add(path)
    except Exception as exc:
        raise ManifestError(f"cannot enumerate public docs under docs/: {exc}") from exc
    return sorted(paths, key=repo_relative)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def parse_claim_marker_body(body: str) -> tuple[str, str | None]:
    if body.startswith("claim:"):
        claim_id = body.removeprefix("claim:")
        if CLAIM_ID_RE.fullmatch(claim_id) is None:
            return ("malformed", None)
        return ("open", claim_id)
    if body == "/claim":
        return ("close", None)
    if body.startswith("claim") or body.startswith("/claim"):
        return ("malformed", None)
    return ("ignore", None)


def parse_claim_markers(path: Path) -> tuple[list[ClaimMarker], list[str]]:
    relative = repo_relative(path)
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        return ([], [f"{relative}: cannot read public doc: {exc}"])

    markers: list[ClaimMarker] = []
    errors: list[str] = []
    active: tuple[str, int, int] | None = None
    offset = 0

    while True:
        start = text.find(HTML_COMMENT_OPEN, offset)
        if start == -1:
            break

        end = text.find(HTML_COMMENT_CLOSE, start + len(HTML_COMMENT_OPEN))
        start_line = line_number(text, start)
        if end == -1:
            body_prefix = text[start + len(HTML_COMMENT_OPEN) : start + 80].strip()
            if active is not None:
                errors.append(
                    f"{active[0]} in {relative}:{active[2]}: marker is unclosed"
                )
                active = None
            elif body_prefix.startswith("claim") or body_prefix.startswith("/claim"):
                errors.append(f"{relative}:{start_line}: malformed claim marker is unclosed")
            else:
                errors.append(
                    f"{relative}:{start_line}: unclosed HTML comment while scanning claim markers"
                )
            break

        body = text[start + len(HTML_COMMENT_OPEN) : end].strip()
        marker_kind, claim_id = parse_claim_marker_body(body)
        if marker_kind == "malformed":
            errors.append(f"{relative}:{start_line}: malformed claim marker {body!r}")
        elif marker_kind == "open":
            assert claim_id is not None
            if active is not None:
                errors.append(
                    f"{claim_id} in {relative}:{start_line}: nested marker inside "
                    f"{active[0]} opened at {relative}:{active[2]}"
                )
            else:
                active = (claim_id, end + len(HTML_COMMENT_CLOSE), start_line)
        elif marker_kind == "close":
            if active is None:
                errors.append(
                    f"{relative}:{start_line}: closing claim marker without opening marker"
                )
            else:
                claim_id, content_start, marker_start_line = active
                markers.append(
                    ClaimMarker(
                        claim_id=claim_id,
                        path=path,
                        content=text[content_start:start],
                        start_line=marker_start_line,
                        end_line=start_line,
                    )
                )
                active = None

        offset = end + len(HTML_COMMENT_CLOSE)

    if active is not None:
        errors.append(f"{active[0]} in {relative}:{active[2]}: marker is unclosed")

    return (markers, errors)


def validate_claim_markers(claims: list[Claim]) -> list[str]:
    claims_by_id = {claim.claim_id: claim for claim in claims}
    markers_by_id: dict[str, list[ClaimMarker]] = {}
    errors: list[str] = []

    for path in public_doc_paths():
        markers, marker_errors = parse_claim_markers(path)
        errors.extend(marker_errors)
        for marker in markers:
            markers_by_id.setdefault(marker.claim_id, []).append(marker)

    for claim_id, markers in markers_by_id.items():
        if len(markers) > 1:
            locations = ", ".join(
                f"{repo_relative(marker.path)}:{marker.start_line}" for marker in markers
            )
            errors.append(f"{claim_id}: duplicate marker id in public docs: {locations}")

        for marker in markers:
            marker_relative = repo_relative(marker.path)
            claim = claims_by_id.get(claim_id)
            if claim is None:
                errors.append(
                    f"{claim_id} in {marker_relative}:{marker.start_line}: "
                    "marker has no manifest entry"
                )
                continue

            if marker_relative != claim.stated_in:
                errors.append(
                    f"{claim_id} in {marker_relative}:{marker.start_line}: "
                    f"marker is not in manifest stated_in file {claim.stated_in}"
                )

            if normalized_text(marker.content) != normalized_text(claim.claim):
                errors.append(
                    f"{claim_id} in {marker_relative}:{marker.start_line}: "
                    "marker text does not match manifest claim"
                )

    for claim in claims:
        markers = markers_by_id.get(claim.claim_id, [])
        if not any(repo_relative(marker.path) == claim.stated_in for marker in markers):
            errors.append(
                f"{claim.claim_id} in {claim.stated_in}: "
                "manifest entry has no marker in stated_in document"
            )

    return errors


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

    marker_errors = validate_claim_markers(claims)
    if marker_errors:
        for error in marker_errors:
            print(f"[FAIL] claim markers: {error}")
        print("[FAIL] executable claims gate failed", file=sys.stderr)
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
