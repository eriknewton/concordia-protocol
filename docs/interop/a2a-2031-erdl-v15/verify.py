#!/usr/bin/env python3
"""Answer-key check for the published ERDL v1.5 canonical-bytes output.

Deliberately imports **no Concordia code**. The output in this directory was
produced with Concordia's own RFC 8785 canonicalizer; this verifier re-derives
everything with the independent `rfc8785` reference package, so a regression in
either implementation shows up as a disagreement rather than as a matching pair
of wrong answers.

Everything checked here is self-contained: the upstream vector file is not
needed and is not read. Five properties are re-derived from the published bytes
alone.

1. **The bytes really are RFC 8785 canonical form.** Every published
   `canonical_hex` value is hex-decoded, parsed, re-canonicalized with the
   independent canonicalizer, and compared byte for byte against what was
   published. A value that is merely valid JSON fails this.
2. **The R2 exclusions held.** No published preimage contains `audit.hash`,
   `signature` or `signing_key_id`, and every one still contains its `audit`
   object. That pair is the single-deletion-point property the K01 canary
   exists to test: deleting the whole `audit` would satisfy the first half and
   fail the second.
3. **The version gate held.** Every published preimage declares
   `erdl-do-v1.5-hash-flat`, and `V-DO-v15-C07[1]`, the one version-gated
   member of the corpus, has no key at all.
4. **The full R1 pipeline reproduces a hash carried inside the artifact.** In
   the normal chain `V-DO-v15-C01`, each member's `audit.previous_hash` is its
   predecessor's `audit.hash`. Hashing the predecessor's published preimage
   bytes must reproduce it. This exercises the deletion point, the
   canonicalization and the SHA-256 end to end against a value that was never
   an input to this verifier.
5. **The submission envelope is well formed**, including `k01_check1` being
   `MISMATCH` as R5 requires, and the key grammar the submission guide fixes.

Exit code 0 means every check passed.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import rfc8785

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "concordia-python-erdl-do-v15-output.json.txt"

PREIMAGE_VERSION = "erdl-do-v1.5-hash-flat"
EXPECTED_KEY_COUNT = 107
VERSION_GATED_KEY = "V-DO-v15-C07[1]"
CANARY_KEY = "V-DO-v15-K01"
NORMAL_CHAIN_ID = "V-DO-v15-C01"

#: `<id>`, `<id>-base`, `<id>-tampered`, or `<id>[i]` (submission guide keying).
KEY_GRAMMAR = re.compile(r"^[A-Za-z0-9\-]+(?:-base|-tampered|\[\d+\])?$")


class VerificationError(Exception):
    """A published value could not be re-derived."""


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _decode(key: str, hex_value: str) -> tuple[bytes, Any]:
    try:
        raw = bytes.fromhex(hex_value)
    except ValueError as exc:
        raise VerificationError(f"{key}: canonical_hex is not valid hex: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{key}: canonical bytes are not valid UTF-8: {exc}") from exc
    try:
        return raw, json.loads(text)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"{key}: canonical bytes are not valid JSON: {exc}") from exc


def verify_envelope(envelope: dict[str, Any]) -> dict[str, str]:
    for field in ("runner", "method", "date", "artifact", "k01_check1", "canonical_hex"):
        _check(field in envelope, f"submission envelope is missing {field!r}")
    _check(
        envelope["k01_check1"] == "MISMATCH",
        f"R5 requires k01_check1 == 'MISMATCH', found {envelope['k01_check1']!r}",
    )
    canonical_hex = envelope["canonical_hex"]
    _check(isinstance(canonical_hex, dict), "canonical_hex is not an object")
    _check(
        len(canonical_hex) == EXPECTED_KEY_COUNT,
        f"expected {EXPECTED_KEY_COUNT} canonical_hex keys, found {len(canonical_hex)}",
    )
    _check(
        VERSION_GATED_KEY not in canonical_hex,
        f"{VERSION_GATED_KEY} is version-gated and MUST NOT have a key",
    )
    _check(CANARY_KEY in canonical_hex, f"the canary {CANARY_KEY} has no key")
    for key in canonical_hex:
        _check(bool(KEY_GRAMMAR.match(key)), f"{key}: key does not follow the submission keying")
    return canonical_hex


def verify_canonical_bytes(canonical_hex: dict[str, str]) -> int:
    """Re-derive every published byte string with the independent canonicalizer."""
    for key, hex_value in sorted(canonical_hex.items()):
        raw, parsed = _decode(key, hex_value)
        _check(
            rfc8785.dumps(parsed) == raw,
            f"{key}: published bytes are not RFC 8785 canonical form",
        )

        audit = parsed.get("audit")
        _check(isinstance(audit, dict), f"{key}: preimage has no audit object")
        _check("hash" not in audit, f"{key}: preimage still contains audit.hash (R2)")
        _check("signature" not in parsed, f"{key}: preimage still contains signature (R2)")
        _check(
            "signing_key_id" not in parsed,
            f"{key}: preimage still contains signing_key_id (R2)",
        )
        _check(
            audit.get("preimage_version") == PREIMAGE_VERSION,
            f"{key}: preimage_version is {audit.get('preimage_version')!r}, "
            f"expected {PREIMAGE_VERSION!r}",
        )
    return len(canonical_hex)


def verify_chain_anchoring(canonical_hex: dict[str, str]) -> int:
    """Reproduce the normal chain's `previous_hash` links from the bytes alone."""
    members = sorted(
        (key for key in canonical_hex if key.startswith(f"{NORMAL_CHAIN_ID}[")),
        key=lambda k: int(k[len(NORMAL_CHAIN_ID) + 1 : -1]),
    )
    _check(len(members) >= 2, f"{NORMAL_CHAIN_ID}: need at least two members to check anchoring")

    compared = 0
    for index in range(1, len(members)):
        previous_raw, _ = _decode(members[index - 1], canonical_hex[members[index - 1]])
        _, current = _decode(members[index], canonical_hex[members[index]])
        recomputed = "sha256:" + hashlib.sha256(previous_raw).hexdigest()
        declared = current.get("audit", {}).get("previous_hash")
        _check(
            recomputed == declared,
            f"{members[index]}: previous_hash {declared!r} is not the recomputed "
            f"{recomputed!r} of {members[index - 1]}",
        )
        compared += 1
    return compared


def main() -> int:
    if not OUTPUT.is_file():
        print(f"[FAIL] missing published output: {OUTPUT}", file=sys.stderr)
        return 1
    try:
        envelope = json.loads(OUTPUT.read_text(encoding="utf-8"))
        canonical_hex = verify_envelope(envelope)
        recanonicalized = verify_canonical_bytes(canonical_hex)
        anchored = verify_chain_anchoring(canonical_hex)
    except VerificationError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    print(f"[OK] envelope well formed; k01_check1={envelope['k01_check1']}")
    print(f"[OK] {recanonicalized} canonical byte strings re-derived with the independent rfc8785")
    print(f"[OK] R2 exclusions and the version gate hold in all {recanonicalized} preimages")
    print(f"[OK] {anchored} {NORMAL_CHAIN_ID} previous_hash link(s) reproduced from the bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
