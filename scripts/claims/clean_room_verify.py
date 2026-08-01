#!/usr/bin/env python3
"""Clean-room verifier for public interop fixture claims.

This script intentionally runs without importing Concordia. It re-derives
published fixture digests with the stock RFC 8785 implementation and verifies
Ed25519 signatures with PyNaCl.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

assert (
    importlib.util.find_spec("concordia") is None
), "clean-room verifier requires concordia to be absent from import path"

import rfc8785
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

SHA256_PREFIXED_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE_VALUE_KEYS = {"signature_b64url"}


class VerificationError(Exception):
    """Fixture verification failed."""


@dataclass(frozen=True)
class JsonFile:
    path: Path
    rel_path: str
    data: Any


@dataclass(frozen=True)
class PublicKey:
    label: str
    key: VerifyKey


@dataclass(frozen=True)
class DigestDerivation:
    label: str
    value: str
    source: str


@dataclass(frozen=True)
class SignatureCheck:
    file: JsonFile
    field_path: str
    value: str


@dataclass
class FixtureResult:
    digests: int = 0
    signatures: int = 0


def reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is not allowed: {value}")


def load_json(path: Path, fixture_dir: Path) -> JsonFile:
    try:
        data = json.loads(path.read_text(), parse_constant=reject_json_constant)
    except Exception as exc:
        rel = path.relative_to(fixture_dir).as_posix()
        raise VerificationError(f"{fixture_dir.name}: failed to parse {rel}: {exc}") from exc
    return JsonFile(path=path, rel_path=path.relative_to(fixture_dir).as_posix(), data=data)


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode()


def jcs_bytes(value: Any) -> bytes:
    return rfc8785.dumps(value)


def sha256_jcs(value: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_bytes(value)).hexdigest()


def without_keys(data: Mapping[str, Any], keys: Iterable[str]) -> dict[str, Any]:
    blocked = set(keys)
    return {key: value for key, value in data.items() if key not in blocked}


def path_join(parent: str, key: str) -> str:
    if parent == "$":
        return f"$.{key}"
    return f"{parent}.{key}"


def walk_values(value: Any, path: str = "$") -> Iterable[tuple[str, str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = path_join(path, key)
            yield key, child_path, child
            yield from walk_values(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            yield "", child_path, child
            yield from walk_values(child, child_path)


def walk_dicts(value: Any, path: str = "$") -> Iterable[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            yield from walk_dicts(child, path_join(path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_dicts(child, f"{path}[{index}]")


def is_decision_object(value: Mapping[str, Any]) -> bool:
    return {
        "boundary_id",
        "capability_digest",
        "decision",
        "policy_version",
        "request_digest",
        "verifier",
    }.issubset(value.keys())


def is_cascade_decision(value: Mapping[str, Any]) -> bool:
    return {
        "ancestor_reads",
        "boundary_id",
        "capability_digest",
        "decision",
        "decision_id",
        "policy_version",
        "request_digest",
        "verifier",
    }.issubset(value.keys())


def add_derivation(
    derivations: dict[str, list[DigestDerivation]],
    label: str,
    value: str,
    source: str,
) -> None:
    derivations.setdefault(label, []).append(
        DigestDerivation(label=label, value=value, source=source)
    )


def build_digest_derivations(files: list[JsonFile]) -> dict[str, list[DigestDerivation]]:
    derivations: dict[str, list[DigestDerivation]] = {}

    for json_file in files:
        stem = json_file.path.stem.lower()
        data = json_file.data
        if not isinstance(data, dict):
            continue

        full_hash = sha256_jcs(data)
        add_derivation(derivations, "full_json", full_hash, json_file.rel_path)

        if "capability" in stem:
            add_derivation(derivations, "capability_digest", full_hash, json_file.rel_path)
            add_derivation(derivations, "offer_hash", full_hash, json_file.rel_path)

        if "offer" in stem:
            add_derivation(derivations, "request_digest", full_hash, json_file.rel_path)
            add_derivation(derivations, "receipt_offer_hash", full_hash, json_file.rel_path)
            add_derivation(derivations, "offer_hash", full_hash, json_file.rel_path)

        if "revocation" in stem or "revocation_id" in data:
            add_derivation(derivations, "source_digest", full_hash, json_file.rel_path)

        if stem == "approval_receipt":
            add_derivation(derivations, "approval_receipt_ref", full_hash, json_file.rel_path)

        if "signature" in data:
            signable_hash = sha256_jcs(without_keys(data, ("signature",)))
            add_derivation(
                derivations,
                "canonical_sha256",
                signable_hash,
                f"{json_file.rel_path} without $.signature",
            )

        if is_cascade_decision(data):
            preimage_hash = sha256_jcs(without_keys(data, ("decision_id", "signature")))
            add_derivation(
                derivations,
                "deny_decision_id",
                preimage_hash,
                f"{json_file.rel_path} without $.decision_id and $.signature",
            )

        for nested_path, nested in walk_dicts(data):
            if is_decision_object(nested):
                add_derivation(
                    derivations,
                    "decision_id",
                    sha256_jcs(nested),
                    f"{json_file.rel_path}:{nested_path}",
                )

    return derivations


def is_digest_publication(key: str, path: str, value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lower = key.lower()
    lower_path = path.lower()
    if SHA256_PREFIXED_RE.fullmatch(value):
        return (
            "digest" in lower
            or "hash" in lower
            or "sha256" in lower
            or lower.endswith("decision_id")
            or lower.endswith("_ref")
            or ".hashes." in lower_path
            or ".digests." in lower_path
        )
    return bool(SHA256_HEX_RE.fullmatch(value) and lower.endswith("decision_id"))


def labels_for_digest_field(key: str, value: str, root: Any, path: str) -> set[str]:
    lower = key.lower()
    if lower == "canonical_sha256":
        return {"canonical_sha256"}
    if lower == "deny_decision_id":
        return {"deny_decision_id"}
    if lower.endswith("decision_id"):
        if isinstance(root, dict) and is_cascade_decision(root) and path == "$.decision_id":
            return {"deny_decision_id"}
        return {"decision_id"}
    if lower == "capability_digest":
        return {"capability_digest"}
    if lower == "request_digest":
        return {"request_digest"}
    if lower == "receipt_offer_hash":
        return {"receipt_offer_hash"}
    if lower == "offer_hash":
        return {"offer_hash", "request_digest", "capability_digest"}
    if lower == "source_digest":
        return {"source_digest"}
    if lower == "approval_receipt_ref":
        return {"approval_receipt_ref"}
    if lower.endswith("_ref") and SHA256_PREFIXED_RE.fullmatch(value):
        return {"full_json"}
    return set()


def normalized_digest(value: str) -> str:
    return value if value.startswith("sha256:") else "sha256:" + value


def verify_digest_publications(
    fixture_name: str,
    json_file: JsonFile,
    derivations: dict[str, list[DigestDerivation]],
) -> int:
    verified = 0
    for key, path, value in walk_values(json_file.data):
        if not is_digest_publication(key, path, value):
            continue
        labels = labels_for_digest_field(key, value, json_file.data, path)
        if not labels:
            raise VerificationError(
                f"{fixture_name}: {json_file.rel_path}:{path}: "
                f"no derivation rule for digest field {key!r}"
            )

        expected = normalized_digest(value)
        matches = [
            derivation
            for label in labels
            for derivation in derivations.get(label, [])
            if derivation.value == expected
        ]
        if not matches:
            sources = ", ".join(sorted(labels))
            raise VerificationError(
                f"{fixture_name}: {json_file.rel_path}:{path}: "
                f"digest mismatch for {key!r}; no {sources} derivation produced {value}"
            )
        verified += 1
    return verified


def collect_public_keys(fixture_name: str, files: list[JsonFile]) -> list[PublicKey]:
    keys: list[PublicKey] = []
    for json_file in files:
        for key, path, value in walk_values(json_file.data):
            if not isinstance(value, str):
                continue
            if key == "public_key_b64url" or key.endswith("_public_key_b64url"):
                keys.append(
                    PublicKey(
                        label=f"{json_file.rel_path}:{path}",
                        key=decode_verify_key(
                            fixture_name, json_file.rel_path, path, value
                        ),
                    )
                )
        if isinstance(json_file.data, dict) and isinstance(
            json_file.data.get("public_keys_b64url"), dict
        ):
            for label, value in json_file.data["public_keys_b64url"].items():
                if not isinstance(value, str):
                    continue
                keys.append(
                    PublicKey(
                        label=f"{json_file.rel_path}:$.public_keys_b64url.{label}",
                        key=decode_verify_key(
                            fixture_name,
                            json_file.rel_path,
                            f"$.public_keys_b64url.{label}",
                            value,
                        ),
                    )
                )
    return keys


def decode_verify_key(
    fixture_name: str, rel_path: str, field_path: str, value: str
) -> VerifyKey:
    try:
        raw = b64url_decode(value)
    except Exception as exc:
        raise VerificationError(
            f"{fixture_name}: {rel_path}:{field_path}: "
            f"public key is not valid base64url: {exc}"
        ) from exc
    if len(raw) != 32:
        raise VerificationError(
            f"{fixture_name}: {rel_path}:{field_path}: "
            f"Ed25519 public key is {len(raw)} bytes, expected 32"
        )
    return VerifyKey(raw)


def collect_signatures(files: list[JsonFile]) -> list[SignatureCheck]:
    signatures: list[SignatureCheck] = []
    for json_file in files:
        if not isinstance(json_file.data, dict):
            continue
        signature = json_file.data.get("signature")
        if isinstance(signature, dict) and isinstance(signature.get("value"), str):
            signatures.append(
                SignatureCheck(
                    file=json_file,
                    field_path="$.signature.value",
                    value=signature["value"],
                )
            )
    return signatures


def signature_preimages(data: dict[str, Any]) -> list[tuple[str, bytes]]:
    preimages = [
        ("without $.signature", jcs_bytes(without_keys(data, ("signature",)))),
    ]
    if "decision_id" in data:
        preimages.append(
            (
                "without $.decision_id and $.signature",
                jcs_bytes(without_keys(data, ("decision_id", "signature"))),
            )
        )
    return preimages


def verify_signature(
    fixture_name: str,
    check: SignatureCheck,
    public_keys: list[PublicKey],
) -> None:
    if not public_keys:
        raise VerificationError(f"{fixture_name}: no public keys available for signature checks")
    try:
        signature = b64url_decode(check.value)
    except Exception as exc:
        raise VerificationError(
            f"{fixture_name}: {check.file.rel_path}:{check.field_path}: "
            f"signature is not valid base64url: {exc}"
        ) from exc

    for preimage_label, preimage in signature_preimages(check.file.data):
        for public_key in public_keys:
            try:
                public_key.key.verify(preimage, signature)
                return
            except BadSignatureError:
                continue
    raise VerificationError(
        f"{fixture_name}: {check.file.rel_path}:{check.field_path}: "
        "no published public key verified the signature over any supported preimage"
    )


def verify_detached_signature_expectations(
    fixture_name: str,
    files: list[JsonFile],
    verified_signature_values: set[str],
) -> int:
    checked = 0
    for json_file in files:
        for key, path, value in walk_values(json_file.data):
            if key not in SIGNATURE_VALUE_KEYS:
                continue
            if not isinstance(value, str):
                raise VerificationError(
                    f"{fixture_name}: {json_file.rel_path}:{path}: "
                    f"{key!r} must be a string"
                )
            if value not in verified_signature_values:
                raise VerificationError(
                    f"{fixture_name}: {json_file.rel_path}:{path}: "
                    f"{key!r} does not match any verified signature in this fixture"
                )
            checked += 1
    return checked


def verify_seed_public_keys(fixture_name: str, files: list[JsonFile]) -> None:
    public_keys_by_label: dict[str, str] = {}
    seeds_by_label: dict[str, str] = {}

    for json_file in files:
        data = json_file.data
        if isinstance(data, dict) and isinstance(data.get("public_keys_b64url"), dict):
            for label, value in data["public_keys_b64url"].items():
                if isinstance(value, str):
                    public_keys_by_label[str(label)] = value
        for key, _path, value in walk_values(data):
            if key == "public_key_b64url" and isinstance(value, str):
                public_keys_by_label[""] = value
            if key.endswith("_ed25519_seed_ascii") and isinstance(value, str):
                label = key[: -len("_ed25519_seed_ascii")]
                seeds_by_label[label] = value
            elif key == "seed_ed25519_ascii" and isinstance(value, str):
                seeds_by_label[""] = value

    for label, seed in seeds_by_label.items():
        if len(seed.encode()) != 32:
            raise VerificationError(
                f"{fixture_name}: seed {label or '<default>'} is not 32 bytes"
            )
        if label not in public_keys_by_label:
            continue
        derived = b64url_encode(SigningKey(seed.encode()).verify_key.encode())
        expected = public_keys_by_label[label]
        if derived != expected:
            raise VerificationError(
                f"{fixture_name}: public key for seed {label or '<default>'} "
                f"does not re-derive from the published Ed25519 seed"
            )


def verify_fixture(fixture_dir: Path) -> FixtureResult:
    files = [
        load_json(path, fixture_dir)
        for path in sorted(fixture_dir.rglob("*.json"))
        if path.is_file()
    ]
    if not files:
        raise VerificationError(f"{fixture_dir.name}: no JSON fixtures found")

    derivations = build_digest_derivations(files)
    public_keys = collect_public_keys(fixture_dir.name, files)
    signatures = collect_signatures(files)
    if not signatures:
        raise VerificationError(f"{fixture_dir.name}: no signature fields found")

    result = FixtureResult()
    for json_file in files:
        result.digests += verify_digest_publications(
            fixture_dir.name, json_file, derivations
        )
    if result.digests == 0:
        raise VerificationError(f"{fixture_dir.name}: no published digest fields found")

    for signature in signatures:
        verify_signature(fixture_dir.name, signature, public_keys)
        result.signatures += 1

    verified_signature_values = {signature.value for signature in signatures}
    verify_detached_signature_expectations(
        fixture_dir.name, files, verified_signature_values
    )
    verify_seed_public_keys(fixture_dir.name, files)

    return result


def fixture_dirs(root: Path) -> list[Path]:
    if not root.exists():
        raise VerificationError(f"{root}: fixture root does not exist")
    if not root.is_dir():
        raise VerificationError(f"{root}: fixture root is not a directory")
    fixtures = [
        child
        for child in sorted(root.iterdir())
        if child.is_dir() and any(path.is_file() for path in child.rglob("*.json"))
    ]
    if not fixtures:
        raise VerificationError(f"{root}: no interop fixture directories found")
    return fixtures


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clean-room verification for docs/interop fixtures."
    )
    parser.add_argument(
        "root",
        nargs="?",
        default="docs/interop",
        help="Directory whose direct children are interop fixture directories.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = Path(args.root)

    fixture_count = 0
    digest_count = 0
    signature_count = 0

    try:
        for fixture_dir in fixture_dirs(root):
            result = verify_fixture(fixture_dir)
            fixture_count += 1
            digest_count += result.digests
            signature_count += result.signatures
            print(
                f"[OK] {fixture_dir.name}: "
                f"digests={result.digests} signatures={result.signatures}"
            )
    except VerificationError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    if fixture_count == 0 or digest_count == 0 or signature_count == 0:
        print(
            "[FAIL] clean-room verifier did no work: "
            f"fixtures={fixture_count} digests={digest_count} signatures={signature_count}",
            file=sys.stderr,
        )
        return 1

    print(f"Verified fixtures: {fixture_count}")
    print(f"Verified digests: {digest_count}")
    print(f"Verified signatures: {signature_count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
