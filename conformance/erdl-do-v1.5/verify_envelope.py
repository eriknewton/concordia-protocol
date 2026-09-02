#!/usr/bin/env python3
"""Self-consistency check for the published ERDL v1.5 submission envelope.

**This is not an answer-key verifier and it cannot establish conformance.** It
holds no oracle, reads no vectors, and re-derives nothing that would require
one. What it does is take the committed envelope and check that the bytes
inside it are internally coherent, using a canonicalizer that is not the one
that produced them: the independent `rfc8785` reference package rather than
Concordia's own. A regression in either implementation therefore shows up as a
disagreement rather than as a matching pair of wrong answers.

Deliberately imports **no Concordia code**.

Four properties are re-derived from the published bytes alone, and one is only
a field check. The distinction is the point of this docstring:

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
   an input to this script. It covers the links inside that one chain, and
   nothing else.
5. **The envelope is well formed and pinned**: the six keys the submission
   guide fixes with validated provenance types and formats, a key grammar
   restricted to exactly one of the three shapes per vector id with
   base/tampered pairing and contiguous chain indices, and a `method` string
   naming the SHA-256 of the corpus the run was bound to. File, per-value and
   aggregate hex ceilings derived from the pinned artifact bound allocations
   before canonicalization begins.

`k01_check1` is checked to READ `"MISMATCH"`. That is a **self-reported field
check, not a re-derivation of R5**: this script holds no stored `audit.hash` to
compare against, because the published preimage is exactly the artifact with
`audit.hash` deleted. R5 evidence is the runner recomputing Check 1 against the
pinned corpus, asserted by `test_k01_check1_is_mismatch`. Nothing here can
substitute for it.

What this script cannot detect is recorded rather than glossed: it cannot see
over-deletion or projection of decision-object fields beyond the three R2
fields and `audit` presence, because `rfc8785.dumps(json.loads(raw)) == raw` is
a fixed-point check that any well-formed subset also satisfies. The `C01` chain
anchoring in check 4 is the one place that binding is end to end.

Exit code 0 means every check passed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import rfc8785

HERE = Path(__file__).resolve().parent
DEFAULT_OUTPUT = HERE / "concordia-python-erdl-do-v15-output.json"

PREIMAGE_VERSION = "erdl-do-v1.5-hash-flat"
EXPECTED_KEY_COUNT = 107
VERSION_GATED_KEY = "V-DO-v15-C07[1]"
CANARY_KEY = "V-DO-v15-K01"
NORMAL_CHAIN_ID = "V-DO-v15-C01"
ENVELOPE_FIELDS = ("runner", "method", "date", "artifact", "k01_check1", "canonical_hex")

#: SHA-256 of the pinned upstream vector file. The envelope's `method` string
#: must name it, so the submitted artifact carries the identity of the corpus
#: it describes rather than leaving it to a README.
PINNED_VECTORS_SHA256 = "d8adf32b7c691bdb3d805fdb0b3f7ac327dc16388cd59a4dfe757d9555e1778c"

#: Allocation ceilings derived from the pinned legitimate artifact. The current
#: envelope is 538,226 bytes, its largest canonical value is 6,352 hex
#: characters, and all canonical values total 534,896 characters. Doubling
#: each leaves room for submitter metadata without permitting an unbounded
#: local verification job.
PINNED_ENVELOPE_BYTES = 538_226
PINNED_MAX_CANONICAL_HEX_CHARS = 6_352
PINNED_CANONICAL_HEX_TOTAL_CHARS = 534_896
MAX_ENVELOPE_BYTES = PINNED_ENVELOPE_BYTES * 2
MAX_CANONICAL_HEX_CHARS = PINNED_MAX_CANONICAL_HEX_CHARS * 2
MAX_CANONICAL_HEX_TOTAL_CHARS = PINNED_CANONICAL_HEX_TOTAL_CHARS * 2
READ_CHUNK_BYTES = 64 * 1024

RUNNER_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,127})$")
LOWER_HEX = re.compile(r"^(?:[0-9a-f]{2})+$")

#: A vector id: `V-` then hyphen-separated alphanumeric segments. Anchored, and
#: deliberately excluding `[`, `]` and the two role suffixes so that the suffix
#: grammar below carries real discrimination instead of being absorbed by a
#: permissive character class.
VECTOR_ID = re.compile(r"^V-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$")
CHAIN_SUFFIX = re.compile(r"^\[(0|[1-9][0-9]*)\]$")
ROLE_SUFFIXES = ("-base", "-tampered")


class VerificationError(Exception):
    """A published value could not be re-derived."""


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _read_bounded(path: Path, limit: int) -> bytes:
    """Read at most ``limit`` bytes, checking before and during allocation."""
    try:
        path_size = path.stat().st_size
    except OSError as exc:
        raise VerificationError(f"{path}: cannot stat envelope: {exc}") from exc
    _check(path_size <= limit, f"{path}: envelope is {path_size} bytes; limit is {limit}")

    raw = bytearray()
    try:
        with path.open("rb") as source:
            opened_size = os.fstat(source.fileno()).st_size
            _check(
                opened_size <= limit,
                f"{path}: opened envelope is {opened_size} bytes; limit is {limit}",
            )
            while chunk := source.read(READ_CHUNK_BYTES):
                _check(
                    len(raw) + len(chunk) <= limit,
                    f"{path}: envelope grew beyond the {limit}-byte limit while reading",
                )
                raw.extend(chunk)
    except OSError as exc:
        raise VerificationError(f"{path}: cannot read envelope: {exc}") from exc
    return bytes(raw)


def load_envelope(path: Path) -> dict[str, Any]:
    """Load one size-bounded UTF-8 JSON submission envelope."""
    raw = _read_bounded(path, MAX_ENVELOPE_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{path}: envelope is not valid UTF-8: {exc}") from exc
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"{path}: envelope is not valid JSON: {exc}") from exc
    _check(isinstance(envelope, dict), "submission envelope is not an object")
    return envelope


def _text_field(envelope: dict[str, Any], field: str, max_chars: int) -> str:
    value = envelope[field]
    _check(isinstance(value, str), f"submission envelope {field!r} is not a string")
    assert isinstance(value, str)
    _check(bool(value) and value == value.strip(), f"submission envelope {field!r} is empty or padded")
    _check(len(value) <= max_chars, f"submission envelope {field!r} exceeds {max_chars} characters")
    _check(
        all(ord(char) >= 0x20 and ord(char) != 0x7F for char in value),
        f"submission envelope {field!r} contains a control character",
    )
    return value


def _decode(key: str, hex_value: str) -> tuple[bytes, Any]:
    _check(isinstance(hex_value, str), f"{key}: canonical_hex value is not a string")
    _check(
        len(hex_value) <= MAX_CANONICAL_HEX_CHARS,
        f"{key}: canonical_hex value exceeds {MAX_CANONICAL_HEX_CHARS} characters",
    )
    _check(bool(LOWER_HEX.fullmatch(hex_value)), f"{key}: canonical_hex is not lowercase byte hex")
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


def split_key(key: str) -> tuple[str, str, int | None]:
    """Return ``(vector id, role, chain index)`` for one submission key.

    ``role`` is ``"single"``, ``"base"``, ``"tampered"`` or ``"chain"``. Raises
    when the key is not one of the three shapes the submission guide defines.
    """
    head, role, index = key, "single", None
    if key.endswith("]"):
        head, _, suffix = key.partition("[")
        match = CHAIN_SUFFIX.match(f"[{suffix}")
        _check(bool(match), f"{key}: chain index is not a non-negative decimal")
        assert match is not None
        index_text = match.group(1)
        cardinality_limit = str(EXPECTED_KEY_COUNT)
        _check(
            len(index_text) < len(cardinality_limit)
            or (
                len(index_text) == len(cardinality_limit)
                and index_text <= cardinality_limit
            ),
            f"{key}: chain index exceeds canonical_hex cardinality limit "
            f"{EXPECTED_KEY_COUNT}",
        )
        role, index = "chain", int(index_text)
    else:
        for suffix in ROLE_SUFFIXES:
            if key.endswith(suffix):
                head, role = key[: -len(suffix)], suffix[1:]
                break
    _check(bool(VECTOR_ID.match(head)), f"{key}: {head!r} is not a vector id")
    _check(
        not head.endswith(ROLE_SUFFIXES),
        f"{key}: vector id {head!r} ends in a role suffix, so the key is ambiguous",
    )
    return head, role, index


def verify_key_grammar(canonical_hex: dict[str, str]) -> None:
    """Enforce the three key shapes, pair completeness and chain contiguity.

    A chain's indices must run 0..n with no hole, because a dropped member
    would otherwise look exactly like a chain that is simply shorter. The one
    permitted hole is the version-gated `V-DO-v15-C07[1]`, which the contract
    requires to have no key at all; it is allowed by name, not by class.
    """
    pairs: dict[str, set[str]] = {}
    chains: dict[str, set[int]] = {}
    shapes: dict[str, set[str]] = {}
    for key in canonical_hex:
        head, role, index = split_key(key)
        if role in ("base", "tampered"):
            shapes.setdefault(head, set()).add("pair")
            pairs.setdefault(head, set()).add(role)
        elif role == "chain":
            shapes.setdefault(head, set()).add("chain")
            assert index is not None
            _check(
                index <= len(canonical_hex),
                f"{key}: chain index exceeds canonical_hex cardinality "
                f"{len(canonical_hex)}",
            )
            chains.setdefault(head, set()).add(index)
        else:
            shapes.setdefault(head, set()).add("single")
    for head, declared_shapes in sorted(shapes.items()):
        _check(
            len(declared_shapes) == 1,
            f"{head}: vector id appears in multiple key shapes {sorted(declared_shapes)}",
        )
    for head, roles in sorted(pairs.items()):
        _check(
            roles == {"base", "tampered"},
            f"{head}: tamper pair has only {sorted(roles)}; both sides must be submitted",
        )
    for head, indices in sorted(chains.items()):
        expected = 0
        ordered = sorted(indices)
        for actual in ordered:
            if f"{head}[{expected}]" == VERSION_GATED_KEY:
                expected += 1
            _check(
                actual == expected,
                f"{head}: chain indices {ordered} have unexplained gap at {expected}",
            )
            expected += 1


def verify_envelope(envelope: dict[str, Any]) -> dict[str, str]:
    for field in ENVELOPE_FIELDS:
        _check(field in envelope, f"submission envelope is missing {field!r}")
    _check(
        set(envelope) == set(ENVELOPE_FIELDS),
        f"submission envelope carries unexpected keys "
        f"{sorted(set(envelope) - set(ENVELOPE_FIELDS))}; the guide fixes six",
    )
    runner = _text_field(envelope, "runner", 128)
    _check(bool(RUNNER_NAME.fullmatch(runner)), f"invalid runner name {runner!r}")
    method = _text_field(envelope, "method", 2_048)
    date = _text_field(envelope, "date", 10)
    try:
        parsed_date = dt.date.fromisoformat(date)
    except ValueError as exc:
        raise VerificationError(f"submission envelope date is not ISO YYYY-MM-DD: {date!r}") from exc
    _check(parsed_date.isoformat() == date, f"submission envelope date is not canonical ISO: {date!r}")
    artifact = _text_field(envelope, "artifact", 2_048)
    try:
        parsed_artifact = urlsplit(artifact)
        _ = parsed_artifact.port
    except ValueError as exc:
        raise VerificationError(f"submission envelope artifact is not a valid URL: {artifact!r}") from exc
    _check(
        parsed_artifact.scheme == "https"
        and bool(parsed_artifact.hostname)
        and parsed_artifact.username is None
        and parsed_artifact.password is None,
        "submission envelope artifact must be an HTTPS URL without embedded credentials",
    )
    _check(
        not any(char.isspace() for char in artifact),
        "submission envelope artifact URL contains whitespace",
    )
    # A field check, not a re-derivation. See the module docstring.
    _check(
        envelope["k01_check1"] == "MISMATCH",
        f"the envelope must self-report k01_check1 == 'MISMATCH' as R5 requires, "
        f"found {envelope['k01_check1']!r}",
    )
    _check(
        f"sha256:{PINNED_VECTORS_SHA256}" in method,
        "the envelope's method string does not name the pinned corpus digest "
        f"{PINNED_VECTORS_SHA256}",
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
    total_hex_chars = 0
    for key, hex_value in canonical_hex.items():
        _check(isinstance(hex_value, str), f"{key}: canonical_hex value is not a string")
        assert isinstance(hex_value, str)
        _check(
            len(hex_value) <= MAX_CANONICAL_HEX_CHARS,
            f"{key}: canonical_hex value exceeds {MAX_CANONICAL_HEX_CHARS} characters",
        )
        _check(bool(LOWER_HEX.fullmatch(hex_value)), f"{key}: canonical_hex is not lowercase byte hex")
        total_hex_chars += len(hex_value)
        _check(
            total_hex_chars <= MAX_CANONICAL_HEX_TOTAL_CHARS,
            f"canonical_hex values exceed {MAX_CANONICAL_HEX_TOTAL_CHARS} aggregate characters",
        )
    verify_key_grammar(canonical_hex)
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Self-consistency check for the envelope.")
    parser.add_argument(
        "envelope",
        nargs="?",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="path to the submission envelope (defaults to the one in this directory, "
        "so the check survives the rename to submissions/<name>-output.json)",
    )
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if not args.envelope.is_file():
        print(f"[FAIL] missing published output: {args.envelope}", file=sys.stderr)
        return 1
    try:
        envelope = load_envelope(args.envelope)
        canonical_hex = verify_envelope(envelope)
        recanonicalized = verify_canonical_bytes(canonical_hex)
        anchored = verify_chain_anchoring(canonical_hex)
    except VerificationError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    print(f"[OK] envelope well formed; self-reported k01_check1={envelope['k01_check1']}")
    print(f"[OK] method names the pinned corpus sha256:{PINNED_VECTORS_SHA256}")
    print(f"[OK] {recanonicalized} canonical byte strings re-derived with the independent rfc8785")
    print(f"[OK] R2 exclusions and the version gate hold in all {recanonicalized} preimages")
    print(f"[OK] {anchored} {NORMAL_CHAIN_ID} previous_hash link(s) reproduced from the bytes")
    print("[--] Check 2, oracle agreement and R5 re-derivation are upstream's, not checked here")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
