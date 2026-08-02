#!/usr/bin/env python3
"""Check that receipt set-binding conformance vectors are present and meaningful."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import rfc8785

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "conformance" / "vectors" / "manifest.json"

EXPECTED_VECTORS = {
    "positive": {
        "pos-synthetic-receipt-set-binding": "accept",
    },
    "mutation": {
        "mut-synthetic-receipt-set-binding-0001": "reject",
        "mut-synthetic-receipt-set-binding-0002": "reject",
        "mut-synthetic-receipt-set-binding-0003": "reject",
        "mut-synthetic-receipt-set-binding-0004": "reject",
    },
    "canary": {
        "canary-receipt-set-unchecked": "reject",
    },
}


class CheckError(RuntimeError):
    """The receipt set-binding vector claim is not backed by the suite."""


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def jcs_bytes(value: Any) -> bytes:
    return bytes(rfc8785.dumps(value))


def message_hash(message: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(jcs_bytes(message)).hexdigest()


def strip_signatures_recursive(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: strip_signatures_recursive(item)
            for key, item in value.items()
            if key != "signature"
        }
    if isinstance(value, list):
        return [strip_signatures_recursive(item) for item in value]
    return value


def countersign_preimage(receipt: dict[str, Any]) -> bytes:
    snapshot = {
        key: value for key, value in receipt.items() if key != "countersignatures"
    }
    return jcs_bytes(strip_signatures_recursive(snapshot))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckError(message)


def manifest_index() -> dict[str, dict[str, Path]]:
    manifest = load_json(MANIFEST_PATH)
    files = manifest.get("files")
    require(isinstance(files, dict), "manifest.files is missing")
    indexed: dict[str, dict[str, Path]] = {}
    for section, expected in EXPECTED_VECTORS.items():
        section_files = files.get(section)
        require(isinstance(section_files, list), f"manifest.files.{section} is missing")
        indexed[section] = {}
        for rel_path in section_files:
            require(isinstance(rel_path, str), f"{section} manifest path is not a string")
            vector = load_json(REPO_ROOT / rel_path)
            vector_id = vector.get("id")
            if vector_id in expected:
                indexed[section][vector_id] = REPO_ROOT / rel_path
    return indexed


def load_expected_vectors() -> dict[str, dict[str, dict[str, Any]]]:
    indexed = manifest_index()
    loaded: dict[str, dict[str, dict[str, Any]]] = {}
    for section, expected in EXPECTED_VECTORS.items():
        missing = sorted(set(expected) - set(indexed[section]))
        require(not missing, f"{section} missing receipt set-binding vectors: {missing}")
        loaded[section] = {
            vector_id: load_json(path) for vector_id, path in indexed[section].items()
        }
    return loaded


def receipt_pair(vector: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    require(vector.get("verification_profile") == "message-chain-v1", "wrong profile")
    require(vector.get("record_type") == "message_chain", "wrong record_type")
    input_data = vector.get("input")
    require(isinstance(input_data, dict), "vector input is not an object")
    receipt = input_data.get("receipt")
    messages = input_data.get("messages")
    require(isinstance(receipt, dict), "receipt is missing from vector input")
    require(isinstance(messages, list) and messages, "messages are missing from vector input")
    require(all(isinstance(message, dict) for message in messages), "message is not an object")
    return receipt, messages


def check_positive(vector: dict[str, Any]) -> None:
    receipt, messages = receipt_pair(vector)
    require(vector.get("expected") == "accept", "positive vector must accept")
    require(receipt.get("concordia_attestation") == "0.3.0", "receipt version is not 0.3.0")
    require(receipt.get("message_count") == len(messages), "positive message_count mismatch")
    require(receipt.get("chain_head") == message_hash(messages[-1]), "positive chain_head mismatch")
    preimage = countersign_preimage(receipt)
    require(b'"chain_head"' in preimage, "chain_head is outside countersign preimage")
    require(b'"message_count"' in preimage, "message_count is outside countersign preimage")
    require(isinstance(receipt.get("countersignatures"), dict), "receipt countersignatures missing")


def check_reject(vector: dict[str, Any], vector_id: str) -> None:
    receipt, messages = receipt_pair(vector)
    require(vector.get("expected") == "reject", f"{vector_id} must reject")
    require(vector.get("expected_reason_class") == "binding", f"{vector_id} must reject as binding")
    head_matches = receipt.get("chain_head") == message_hash(messages[-1])
    count_matches = receipt.get("message_count") == len(messages)
    if vector_id.endswith("0001"):
        require(not head_matches and count_matches, "0001 must isolate chain_head mismatch")
    elif vector_id.endswith("0002"):
        require(head_matches and not count_matches, "0002 must isolate message_count mismatch")
    elif vector_id.endswith("0003"):
        require(not head_matches and not count_matches, "0003 must truncate the transcript")
    elif vector_id.endswith("0004"):
        require(not head_matches and not count_matches, "0004 must splice the transcript")


def main() -> int:
    try:
        vectors = load_expected_vectors()
        check_positive(vectors["positive"]["pos-synthetic-receipt-set-binding"])
        for vector_id, vector in sorted(vectors["mutation"].items()):
            check_reject(vector, vector_id)
        canary = vectors["canary"]["canary-receipt-set-unchecked"]
        check_reject(canary, "canary-receipt-set-unchecked")
        require(
            canary.get("discriminates") == "receipt-set-unchecked",
            "receipt canary discriminator is missing",
        )
    except CheckError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print("[OK] receipt set-binding vectors are present and binding")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
