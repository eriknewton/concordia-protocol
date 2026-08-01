#!/usr/bin/env python3
"""Run the executable claims gate.

Claim markers are scanned only in public Markdown documents: ``SPEC.md``,
``README.md``, and ``docs/**/*.md``. ``Review/`` and internal documentation
directories are intentionally out of scope for this public-claims chokepoint.

Unmarked-claim detection is intentionally narrower than marker scanning because
this gate blocks merges and false positives are expensive. It scans prose only
in non-SPEC manifest ``stated_in`` files and in docs Markdown files outside the
baseline that existed when this gate was introduced. ``SPEC.md`` is a normative
protocol document with many RFC 2119 statements, so unmarked SPEC prose is
excluded; SPEC claims must use explicit markers and executable manifest entries.

The unmarked-prose patterns are high-confidence commitments from the vocabulary
Concordia already publishes: "no implementation is/are", "requires no",
"does not depend on", "no X is required", "without our code", "anyone can
verify", "no registry", commitment-shaped "never" and "always" phrases,
"formally verified", "byte-for-byte", and independent verification language.
Generic single words such as "never" and "independent" are deliberately not
standalone triggers.

Deliberately descriptive prose can be excluded with an explicit HTML comment
region: ``<!-- not-a-claim -->`` ... ``<!-- /not-a-claim -->``. The gate prints
each skipped region so reviewers can see every exemption.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "docs" / "claims.yaml"
CI_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
GENERATED_CONFORMANCE_RELATIVE = "docs/CONFORMANCE.md"
GENERATED_CONFORMANCE_CHECK = "scripts/claims/generate_conformance.py"
REQUIRED_KEYS = {"id", "claim", "stated_in", "check"}
CHECK_TIMEOUT_SECONDS = 120
CLAIM_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
HTML_COMMENT_OPEN = "<!--"
HTML_COMMENT_CLOSE = "-->"
NOT_A_CLAIM_OPEN = "not-a-claim"
NOT_A_CLAIM_CLOSE = "/not-a-claim"
INTERNAL_DOC_DIR_NAMES = {"review", "internal", "_internal", "private"}
FENCED_CODE_RE = re.compile(r"(?ms)^```.*?^```\s*")
PARAGRAPH_RE = re.compile(r"(?ms)([^\n].*?)(?:\n\s*\n|\Z)")
SENTENCE_RE = re.compile(r"[^.!?]+(?:[.!?]|$)")
BASELINE_DOC_MARKDOWN_PATHS = frozenset(
    {
        "docs/A2A_COMPOSITION.md",
        "docs/A2CN_FULFILLMENT.md",
        "docs/EFFICIENCY_REPORT_DEPLOYMENT.md",
        "docs/cmpc_revocation.md",
        "docs/hahs_payload_composition.md",
        "docs/index.md",
        "docs/interop/README.md",
        "docs/interop/a2a-1404-receipt-revocation-vector/README.md",
        "docs/interop/a2a-1920-fulfillment-sample/README.md",
        "docs/revocation_resolver.md",
        "docs/v0.6_migration.md",
        "docs/v0.6_predicate_primitive.md",
    }
)


@dataclass(frozen=True)
class ClaimProsePattern:
    label: str
    regex: re.Pattern[str]


UNMARKED_CLAIM_PATTERNS = (
    ClaimProsePattern(
        "no implementation is/are",
        re.compile(r"\bno implementation (?:is|are)\b", re.IGNORECASE),
    ),
    ClaimProsePattern(
        "requires no",
        re.compile(r"\brequires no\b", re.IGNORECASE),
    ),
    ClaimProsePattern(
        "does not depend on",
        re.compile(r"\bdoes not depend on\b", re.IGNORECASE),
    ),
    ClaimProsePattern(
        "no X is required",
        re.compile(r"\bno\b.{0,80}\bis required\b", re.IGNORECASE),
    ),
    ClaimProsePattern(
        "without our code",
        re.compile(r"\bwithout our code\b", re.IGNORECASE),
    ),
    ClaimProsePattern(
        "anyone can verify",
        re.compile(r"\banyone can verify\b", re.IGNORECASE),
    ),
    ClaimProsePattern(
        "no registry",
        re.compile(r"\bno (?:central )?registry\b", re.IGNORECASE),
    ),
    ClaimProsePattern(
        "never commitment",
        re.compile(
            r"\bnever\s+(?:depends?|requires?|contacts?|transmits?|exposes?|"
            r"persists?|leaks?|silently|phones?)\b",
            re.IGNORECASE,
        ),
    ),
    ClaimProsePattern(
        "always commitment",
        re.compile(
            r"\balways\s+(?:verifies?|rejects?|requires?|signs?|checks?|"
            r"enforces?|fails?)\b",
            re.IGNORECASE,
        ),
    ),
    ClaimProsePattern(
        "formally verified",
        re.compile(r"\bformally verified\b", re.IGNORECASE),
    ),
    ClaimProsePattern(
        "byte-for-byte",
        re.compile(r"\bbyte-for-byte\b", re.IGNORECASE),
    ),
    ClaimProsePattern(
        "independent verification",
        re.compile(
            r"\bindependent (?:implementation|implementer|verifier|verification|"
            r"recompute|recomputation)\b|"
            r"\bindependently verif(?:y|ies|iable|ied)\b",
            re.IGNORECASE,
        ),
    ),
)


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


@dataclass(frozen=True)
class CommentRegion:
    path: Path
    start: int
    end: int
    content_start: int
    content_end: int
    start_line: int
    end_line: int


@dataclass(frozen=True)
class UnmarkedClaim:
    path: Path
    line: int
    sentence: str
    pattern_label: str


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
                # docs/CONFORMANCE.md is generated from docs/claims.yaml and is
                # checked byte-identical before this scanner runs. That
                # regeneration check is the strictly stronger guarantee here:
                # this one path can contain only manifest-emitted claims, while
                # marker and unmarked-prose scanning would duplicate the source
                # claim checks and create duplicate ids.
                if relative.as_posix() == GENERATED_CONFORMANCE_RELATIVE:
                    continue
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


def post_baseline_doc_paths() -> set[Path]:
    docs_root = REPO_ROOT / "docs"
    if not docs_root.is_dir():
        return set()

    paths: set[Path] = set()
    for path in docs_root.rglob("*.md"):
        relative = path.relative_to(REPO_ROOT)
        relative_text = relative.as_posix()
        if is_internal_doc_path(relative):
            continue
        # See the matching exemption in public_doc_paths(). This exemption must
        # stay paired with validate_generated_conformance(), which runs before
        # scanner exemptions are applied.
        if relative_text == GENERATED_CONFORMANCE_RELATIVE:
            continue
        if relative_text not in BASELINE_DOC_MARKDOWN_PATHS:
            paths.add(path)
    return paths


def unmarked_claim_candidate_paths(
    claims: Iterable[Claim],
    extra_paths: Iterable[Path] = (),
) -> list[Path]:
    paths: set[Path] = set()
    for claim in claims:
        if claim.stated_in == "SPEC.md":
            continue
        if claim.stated_in == GENERATED_CONFORMANCE_RELATIVE:
            continue
        path = REPO_ROOT / claim.stated_in
        if path.suffix == ".md":
            paths.add(path)

    paths.update(post_baseline_doc_paths())
    paths.update(extra_paths)
    return sorted(paths, key=repo_relative)


def html_comment_regions(
    path: Path,
    text: str,
    is_open: Callable[[str], bool],
    close_body: str,
    label: str,
) -> tuple[list[CommentRegion], list[str]]:
    relative = repo_relative(path)
    regions: list[CommentRegion] = []
    errors: list[str] = []
    active: tuple[int, int, int] | None = None
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
                errors.append(f"{relative}:{active[2]}: unclosed {label} region")
                active = None
            elif is_open(body_prefix) or body_prefix == close_body:
                errors.append(f"{relative}:{start_line}: unclosed {label} comment")
            break

        comment_end = end + len(HTML_COMMENT_CLOSE)
        body = text[start + len(HTML_COMMENT_OPEN) : end].strip()
        if is_open(body):
            if active is not None:
                errors.append(
                    f"{relative}:{start_line}: nested {label} region inside "
                    f"{relative}:{active[2]}"
                )
            else:
                active = (start, comment_end, start_line)
        elif body == close_body:
            if active is None:
                errors.append(
                    f"{relative}:{start_line}: closing {label} region without open"
                )
            else:
                region_start, content_start, region_start_line = active
                regions.append(
                    CommentRegion(
                        path=path,
                        start=region_start,
                        end=comment_end,
                        content_start=content_start,
                        content_end=start,
                        start_line=region_start_line,
                        end_line=start_line,
                    )
                )
                active = None

        offset = comment_end

    if active is not None:
        errors.append(f"{relative}:{active[2]}: unclosed {label} region")

    return (regions, errors)


def claim_comment_regions(path: Path, text: str) -> tuple[list[CommentRegion], list[str]]:
    return html_comment_regions(
        path,
        text,
        lambda body: parse_claim_marker_body(body)[0] == "open",
        "/claim",
        "claim",
    )


def not_a_claim_regions(path: Path, text: str) -> tuple[list[CommentRegion], list[str]]:
    return html_comment_regions(
        path,
        text,
        lambda body: body == NOT_A_CLAIM_OPEN,
        NOT_A_CLAIM_CLOSE,
        "not-a-claim",
    )


def fenced_code_regions(path: Path, text: str) -> list[CommentRegion]:
    return [
        CommentRegion(
            path=path,
            start=match.start(),
            end=match.end(),
            content_start=match.start(),
            content_end=match.end(),
            start_line=line_number(text, match.start()),
            end_line=line_number(text, match.end()),
        )
        for match in FENCED_CODE_RE.finditer(text)
    ]


def mask_regions(text: str, regions: Iterable[CommentRegion]) -> str:
    chars = list(text)
    for region in regions:
        for index in range(region.start, region.end):
            if chars[index] != "\n":
                chars[index] = " "
    return "".join(chars)


def summarize_region_content(text: str, region: CommentRegion) -> str:
    content = normalized_text(text[region.content_start : region.content_end])
    if len(content) > 140:
        return content[:137].rstrip() + "..."
    return content


def scan_unmarked_claims_in_path(
    path: Path,
) -> tuple[list[UnmarkedClaim], list[str], list[str]]:
    relative = repo_relative(path)
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        return ([], [], [f"{relative}: cannot read public doc: {exc}"])

    claim_regions, claim_errors = claim_comment_regions(path, text)
    skip_regions, skip_errors = not_a_claim_regions(path, text)
    excluded_regions = [
        *claim_regions,
        *skip_regions,
        *fenced_code_regions(path, text),
    ]
    masked = mask_regions(text, excluded_regions)

    findings: list[UnmarkedClaim] = []
    for paragraph_match in PARAGRAPH_RE.finditer(masked):
        paragraph = paragraph_match.group(1)
        paragraph_start = paragraph_match.start(1)
        for match in SENTENCE_RE.finditer(paragraph):
            sentence = normalized_text(match.group(0))
            if not sentence:
                continue
            for pattern in UNMARKED_CLAIM_PATTERNS:
                if pattern.regex.search(sentence):
                    findings.append(
                        UnmarkedClaim(
                            path=path,
                            line=line_number(masked, paragraph_start + match.start()),
                            sentence=sentence,
                            pattern_label=pattern.label,
                        )
                    )
                    break

    skipped = [
        (
            f"{relative}:{region.start_line}-{region.end_line}: "
            f"not-a-claim skipped: {summarize_region_content(text, region)}"
        )
        for region in skip_regions
    ]
    return (findings, skipped, [*claim_errors, *skip_errors])


def validate_unmarked_claim_prose(
    claims: Iterable[Claim],
    extra_paths: Iterable[Path] = (),
) -> tuple[list[UnmarkedClaim], list[str], list[str]]:
    findings: list[UnmarkedClaim] = []
    skipped: list[str] = []
    errors: list[str] = []
    for path in unmarked_claim_candidate_paths(claims, extra_paths):
        path_findings, path_skipped, path_errors = scan_unmarked_claims_in_path(path)
        findings.extend(path_findings)
        skipped.extend(path_skipped)
        errors.extend(path_errors)
    return (findings, skipped, errors)


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


def validate_generated_conformance() -> bool:
    completed = subprocess.run(
        [sys.executable, GENERATED_CONFORMANCE_CHECK, "--check"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.stdout:
        print(completed.stdout.rstrip())
    if completed.stderr:
        print(completed.stderr.rstrip(), file=sys.stderr)
    return completed.returncode == 0


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

    if not validate_generated_conformance():
        print("[FAIL] executable claims gate failed", file=sys.stderr)
        return 1

    marker_errors = validate_claim_markers(claims)
    if marker_errors:
        for error in marker_errors:
            print(f"[FAIL] claim markers: {error}")
        print("[FAIL] executable claims gate failed", file=sys.stderr)
        return 1

    unmarked_claims, skipped_claim_prose, unmarked_scan_errors = (
        validate_unmarked_claim_prose(claims)
    )
    for skipped in skipped_claim_prose:
        print(f"[SKIP] {skipped}")
    if unmarked_scan_errors or unmarked_claims:
        for error in unmarked_scan_errors:
            print(f"[FAIL] unmarked claim scan: {error}")
        for claim in unmarked_claims:
            print(
                f"[FAIL] unmarked claim: {repo_relative(claim.path)}:{claim.line}: "
                f"{claim.pattern_label}: {claim.sentence}"
            )
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
