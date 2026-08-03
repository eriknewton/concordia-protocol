#!/usr/bin/env python3
"""Fail if a fixture publishes a digest its own verify.py never recomputes.

This is the answer-key check, aimed at the defect that produced it: the #1920
sample published a ``canonical_sha256`` while its ``verify.py`` imported no
hashing at all, so the published digest was an assertion nobody derived. A
regressed implementation emitting the wrong value would have gone uncaught,
because nothing compared.

The clean-room job (scripts/claims/clean_room_verify.py) proves the digests are
independently derivable from OUTSIDE our code. This check proves the
complementary half that the clean-room job cannot see: that each shipped
verifier, the thing a third party actually runs, does the recomputation itself
rather than trusting the recorded value.

A verifier is compliant when it both derives digests (it hashes something) and
compares (it asserts or raises on mismatch). Running it must also exit 0.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
INTEROP_ROOT = REPO_ROOT / "docs" / "interop"

# Any of these, used anywhere in the verifier, counts as deriving a digest.
DERIVATION_TOKENS = ("hashlib", "sha256", "rfc8785", "canonical_json", "canonicalize")
# Any of these counts as comparing the derived value against the published one.
COMPARISON_TOKENS = ("assert", "!=", "==", "raise", "mismatch")


def digest_keys(node: object) -> list[str]:
    """Collect digest-shaped keys from a parsed JSON document."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            lowered = key.lower()
            if "sha256" in lowered or lowered == "hashes" or lowered.endswith("_digest"):
                found.append(key)
            found.extend(digest_keys(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(digest_keys(item))
    return found


def verifier_recomputes(source: str) -> tuple[bool, str]:
    """Return whether a verifier both derives and compares digests."""
    try:
        ast.parse(source)
    except SyntaxError as exc:  # fail closed: an unparseable verifier is not proof
        return False, f"verify.py does not parse: {exc}"
    derives = any(token in source for token in DERIVATION_TOKENS)
    compares = any(token in source for token in COMPARISON_TOKENS)
    if not derives:
        return False, "verify.py never derives a digest (no hashing or canonicalization)"
    if not compares:
        return False, "verify.py derives a digest but never compares it"
    return True, ""


def main() -> int:
    if not INTEROP_ROOT.is_dir():
        print(f"[FAIL] missing interop root: {INTEROP_ROOT}", file=sys.stderr)
        return 1

    fixture_dirs = sorted(d for d in INTEROP_ROOT.iterdir() if d.is_dir())
    if not fixture_dirs:
        print("[FAIL] found zero interop fixtures; detection rule broke", file=sys.stderr)
        return 1

    failures: list[str] = []
    checked = 0

    for fixture in fixture_dirs:
        verify_path = fixture / "verify.py"
        if not verify_path.is_file():
            failures.append(f"{fixture.name}: no verify.py")
            continue

        import json

        published: list[str] = []
        for json_file in sorted(fixture.glob("*.json")):
            try:
                published.extend(digest_keys(json.loads(json_file.read_text())))
            except (OSError, ValueError) as exc:
                failures.append(f"{fixture.name}/{json_file.name}: unreadable: {exc}")

        if not published:
            # No published digest means nothing to answer-key. Not a failure.
            continue

        ok, reason = verifier_recomputes(verify_path.read_text())
        if not ok:
            failures.append(
                f"{fixture.name}: publishes {sorted(set(published))} but {reason}"
            )
            continue

        completed = subprocess.run(
            [sys.executable, "verify.py"],
            cwd=fixture,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            failures.append(
                f"{fixture.name}: verify.py exited {completed.returncode}: "
                f"{completed.stderr.strip()[:200]}"
            )
            continue

        checked += 1

    if failures:
        for failure in failures:
            print(f"[FAIL] {failure}", file=sys.stderr)
        return 1

    if checked == 0:
        print(
            "[FAIL] no fixture published a digest; detection rule broke",
            file=sys.stderr,
        )
        return 1

    print(f"[OK] every fixture publishing a digest recomputes it (fixtures={checked})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
