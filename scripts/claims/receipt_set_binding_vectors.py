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
GENESIS_HASH = "sha256:" + ("0" * 64)

EXPECTED_VECTORS = {
    "positive": {
        "pos-synthetic-receipt-set-binding": "accept",
        "pos-synthetic-receipt-set-binding-reconstruction": "accept",
    },
    "mutation": {
        "mut-synthetic-receipt-set-binding-0001": "reject",
        "mut-synthetic-receipt-set-binding-0002": "reject",
        "mut-synthetic-receipt-set-binding-0003": "reject",
        "mut-synthetic-receipt-set-binding-0004": "reject",
        "mut-synthetic-receipt-set-reconstruction-0001": "reject",
        "mut-synthetic-receipt-set-reconstruction-0002": "reject",
        "mut-synthetic-receipt-set-reconstruction-0003": "reject",
        "mut-synthetic-receipt-set-reconstruction-0004": "reject",
        "mut-synthetic-receipt-set-reconstruction-0005": "reject",
        "mut-synthetic-receipt-set-reconstruction-0006": "reject",
        "mut-synthetic-receipt-set-reconstruction-0007": "reject",
        "mut-synthetic-receipt-set-reconstruction-0008": "reject",
    },
    "canary": {
        "canary-receipt-set-unchecked": "reject",
    },
}
RECONSTRUCTION_PREFIX = "mut-synthetic-receipt-set-reconstruction-"


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


def reconstruction_pair(
    vector: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]] | None]:
    require(
        vector.get("verification_profile") == "receipt-set-binding-v1",
        "wrong profile",
    )
    require(vector.get("record_type") == "message_chain", "wrong record_type")
    input_data = vector.get("input")
    require(isinstance(input_data, dict), "vector input is not an object")
    receipt = input_data.get("receipt")
    require(isinstance(receipt, dict), "receipt is missing from vector input")
    if "messages" not in input_data:
        return receipt, None
    messages = input_data.get("messages")
    require(isinstance(messages, list) and messages, "messages are missing")
    require(
        all(isinstance(message, dict) for message in messages),
        "message is not an object",
    )
    return receipt, messages


def reconstruct_chain_tail(messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Find the reconstructed chain's last message by walking prev_hash links.

    Must match ``_reconstruct_single_chain`` in concordia/attestation.py: a
    message has no predecessor when its ``prev_hash`` key is absent or equals
    GENESIS_HASH, an explicit null is malformed, and the chain's tail is the
    one presented message no other message names as its predecessor. This
    check exists because the positive vector below is deliberately presented
    out of chain order, so the array's last element is NOT the chain tail;
    reading ``messages[-1]`` here would silently re-introduce the very
    order-dependent comparison the vector is meant to defeat.
    """
    by_digest = {message_hash(message): index for index, message in enumerate(messages)}
    require(len(by_digest) == len(messages), "duplicate presented message")
    has_successor = [False] * len(messages)
    for message in messages:
        prev_hash = message.get("prev_hash")
        if "prev_hash" not in message or prev_hash == GENESIS_HASH:
            continue
        require(prev_hash is not None, "explicit null prev_hash is malformed")
        predecessor = by_digest.get(prev_hash)
        require(predecessor is not None, "orphan prev_hash in positive fixture")
        assert predecessor is not None
        has_successor[predecessor] = True
    tails = [messages[i] for i, has in enumerate(has_successor) if not has]
    require(len(tails) == 1, "reconstructed chain must have exactly one tail")
    return tails[0]


def check_reconstruction_positive(vector: dict[str, Any]) -> None:
    receipt, messages = reconstruction_pair(vector)
    require(vector.get("expected") == "accept", "positive vector must accept")
    require(messages is not None, "the positive vector must supply a transcript")
    assert messages is not None
    require(receipt.get("message_count") == len(messages), "positive count mismatch")
    require(
        receipt.get("chain_head") == message_hash(reconstruct_chain_tail(messages)),
        "positive chain_head mismatch",
    )
    require(
        message_hash(messages[-1]) != receipt.get("chain_head"),
        "positive vector must be presented out of chain order: the last "
        "presented message must NOT be the chain tail, or a verifier that "
        "compares only a final digest and a count would still pass",
    )


def check_reconstruction_reject(vector: dict[str, Any], vector_id: str) -> None:
    """Every reconstruction reject must be one a weak verifier would accept.

    The guard these vectors defend is the difference between reconstructing a
    chain and comparing a final digest to a count. A vector that a
    digest-and-count comparison already refuses would prove nothing about that
    difference, so each one is required here to be indistinguishable from a
    genuine set under the weak comparison.
    """
    receipt, messages = reconstruction_pair(vector)
    require(vector.get("expected") == "reject", f"{vector_id} must reject")
    require(
        vector.get("expected_reason_class") == "binding",
        f"{vector_id} must reject as binding",
    )
    if messages is None:
        require(
            vector_id.endswith("0001"),
            "only 0001 presents a receipt with no transcript",
        )
        require(
            isinstance(receipt.get("chain_head"), str)
            and isinstance(receipt.get("message_count"), int),
            "0001 must carry well-formed set-binding fields",
        )
        return
    require(
        receipt.get("chain_head") == message_hash(messages[-1]),
        f"{vector_id} must keep the final presented hash matching chain_head",
    )
    require(
        receipt.get("message_count") == len(messages),
        f"{vector_id} must keep message_count matching the presented length",
    )


def main() -> int:
    try:
        vectors = load_expected_vectors()
        check_positive(vectors["positive"]["pos-synthetic-receipt-set-binding"])
        check_reconstruction_positive(
            vectors["positive"]["pos-synthetic-receipt-set-binding-reconstruction"]
        )
        for vector_id, vector in sorted(vectors["mutation"].items()):
            if vector_id.startswith(RECONSTRUCTION_PREFIX):
                check_reconstruction_reject(vector, vector_id)
                continue
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
