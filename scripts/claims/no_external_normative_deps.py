#!/usr/bin/env python3
"""Fail if SPEC.md normatively depends on a non-standards-body URL.

Rule: scan every external URL in SPEC.md and inspect a same-paragraph window of
two physical lines on each side. Two lines covers ordinary Markdown wrapping
around a URL without attributing an adjacent paragraph's RFC 2119 keyword to the
URL. Blank lines stop the window.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT / "SPEC.md"
WINDOW = 2
NORMATIVE_RE = re.compile(r"\b(?:MUST(?:\s+NOT)?|SHALL(?:\s+NOT)?|REQUIRED)\b")
URL_RE = re.compile(r"https?://[^\s)<>\"]+")
ALLOWLISTED_HOSTS = {
    "rfc-editor.org",
    "ietf.org",
    "w3.org",
    "iso.org",
    "unicode.org",
}


@dataclass(frozen=True)
class UrlMention:
    line_number: int
    url: str
    host: str
    context: str
    normative: bool
    allowlisted: bool


def host_is_allowlisted(host: str) -> bool:
    normalized = host.lower()
    return any(
        normalized == allowed or normalized.endswith(f".{allowed}")
        for allowed in ALLOWLISTED_HOSTS
    )


def context_window(lines: list[str], index: int) -> list[str]:
    start = index
    while start > 0 and index - start < WINDOW and lines[start - 1].strip():
        start -= 1
    end = index
    while end + 1 < len(lines) and end - index < WINDOW and lines[end + 1].strip():
        end += 1
    return lines[start : end + 1]


def find_mentions(lines: list[str]) -> list[UrlMention]:
    mentions: list[UrlMention] = []
    for index, line in enumerate(lines):
        for match in URL_RE.finditer(line):
            url = match.group(0).rstrip(".,;")
            host = urlparse(url).hostname
            if host is None:
                raise ValueError(f"could not parse host for URL on line {index + 1}: {url}")
            window_lines = context_window(lines, index)
            context = "\n".join(window_lines)
            mentions.append(
                UrlMention(
                    line_number=index + 1,
                    url=url,
                    host=host,
                    context=context,
                    normative=bool(NORMATIVE_RE.search(context)),
                    allowlisted=host_is_allowlisted(host),
                )
            )
    return mentions


def main() -> int:
    try:
        text = SPEC_PATH.read_text(encoding="utf-8")
    except Exception as exc:
        print(f"[FAIL] cannot read {SPEC_PATH}: {exc}", file=sys.stderr)
        return 1

    mentions = find_mentions(text.splitlines())
    if not mentions:
        print(f"[FAIL] {SPEC_PATH.name}: no external URLs found; detection rule broke", file=sys.stderr)
        return 1

    failures = [
        mention
        for mention in mentions
        if mention.normative and not mention.allowlisted
    ]

    for mention in mentions:
        status = "normative" if mention.normative else "non-normative"
        scope = "allowlisted" if mention.allowlisted else "non-allowlisted"
        print(
            f"[INFO] {SPEC_PATH.name}:{mention.line_number}: "
            f"{mention.url} host={mention.host} {status} {scope}"
        )

    if failures:
        print(
            "[FAIL] non-allowlisted external URL tied to RFC 2119 normative keyword "
            f"within same-paragraph +/-{WINDOW} line window:",
            file=sys.stderr,
        )
        for failure in failures:
            compact = " ".join(failure.context.split())
            print(
                f"  {SPEC_PATH.name}:{failure.line_number}: {failure.url} :: {compact}",
                file=sys.stderr,
            )
        return 1

    print(
        f"[OK] no non-allowlisted external URL is normative "
        f"(same-paragraph +/-{WINDOW} line window)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
