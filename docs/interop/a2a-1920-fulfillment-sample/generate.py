#!/usr/bin/env python3
"""Deterministic generator for the A2A #1920 FulfillmentAttestation sample.

Emits, into this directory:

  - fulfillment_attestation.json   a shipped-shape, Ed25519-signed sample
  - sample.json                    recomputable expectations (join key, hashes)

The sample composes on a shared join key that appears in BOTH the
transactional per-action receipt and this fulfillment attestation:

    charge_ref / action_ref

It carries ONLY behavioral signals + hash references. The underlying action
terms (amount, item, counterparty prices) are NEVER present -- the SPEC §9.6.6
privacy invariant. `assert_privacy_invariant()` in verify.py scans the whole
artifact for raw-term shapes and fails closed if any appear.

Only shipped Concordia surfaces are used:
  - concordia.signing.KeyPair / sign_message              (Ed25519, JCS)
  - concordia.schema_validator.validate_fulfillment_attestation  (shipped)

Field placement (all schema-allowed; the top level and references[] items are
`additionalProperties: true` in fulfillment_attestation.schema.json):
  - charge_ref / action_ref : top-level join keys (fast lookup)
  - behavioral signals       : meta.behavioral_signals (bounded enums/counts)
  - hash references          : references[].id (urn/sha256 pointers only)

Run:  python generate.py
Verify: python verify.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia.canonicalization import canonicalize_jcs
from concordia.signing import KeyPair, sign_message

HERE = Path(__file__).resolve().parent

# Fixed 32-byte Ed25519 seed -> stable bytes and signature.
SETTLEMENT_AGENT_SEED = b"a2a-1920-settlement-agent-seed01"  # 32 bytes
assert len(SETTLEMENT_AGENT_SEED) == 32


def keypair_from_seed(seed: bytes) -> KeyPair:
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return KeyPair(private_key=private, public_key=private.public_key())


def sha256_jcs(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonicalize_jcs(obj)).hexdigest()


def write_json(name: str, obj: Any) -> None:
    (HERE / name).write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )


def main() -> None:
    agent = keypair_from_seed(SETTLEMENT_AGENT_SEED)

    # The shared join key. The SAME string keys the upstream per-action charge
    # receipt (out of scope for this fixture) and this fulfillment attestation,
    # so a verifier composes the two by exact-match on charge_ref/action_ref
    # WITHOUT either artifact carrying the other's terms.
    charge_ref = "urn:a2a:charge:2026-05-10-tx-88f01c"
    action_ref = "urn:a2a:action:2026-05-10-deliver-88f01c"

    # A content-addressed pointer to the agreement attestation. Its bytes are
    # NOT in this fixture; only its digest-shaped id is referenced.
    agreement_attestation_id = "urn:concordia:attestation:agree-88f01c"

    attestation: dict[str, Any] = {
        "attestation_type": "FulfillmentAttestation",
        "id": "urn:concordia:fulfillment:a2a-1920-88f01c",
        "issued_at": "2026-05-10T15:04:00Z",
        "agreement_attestation_id": agreement_attestation_id,
        # -- transactional join keys (composition surface) -------------------
        "charge_ref": charge_ref,
        "action_ref": action_ref,
        "fulfillment": {
            "status": "fulfilled_clean",
            "settled_at": "2026-05-10T15:03:55Z",
        },
        # -- behavioral signals ONLY: bounded enums + counts, no terms -------
        "meta": {
            "mediator_invoked": False,
            "behavioral_signals": {
                "delivered_within_window": True,
                "settlement_attempts": 1,
                "counterparty_confirmed": True,
                "on_time": True,
                "disputes_raised": 0,
            },
        },
        # -- hash references only: pointers, never terms ---------------------
        "references": [
            {
                "type": "attestation",
                "id": agreement_attestation_id,
                "relationship": "fulfills",
            },
            {
                "type": "receipt",
                "id": charge_ref,
                "relationship": "references",
            },
            {
                "type": "delivery_evidence",
                # A digest of off-band delivery proof; the proof bytes are not
                # here. Content-addressed reference only.
                "id": sha256_jcs(
                    {"delivery_proof": "opaque-carrier-signed-photo-bundle"}
                ),
                "relationship": "references",
            },
        ],
    }
    # Sign over the canonical JSON (sign_message strips any signature first).
    attestation["signature"] = {
        "alg": "Ed25519",
        "value": sign_message(attestation, agent),
    }

    write_json("fulfillment_attestation.json", attestation)

    sample = {
        "description": (
            "A2A #1920 transactional per-action FulfillmentAttestation sample: "
            "composes on charge_ref/action_ref, behavioral-signal + hash-"
            "reference only, no underlying action terms (SPEC 9.6.6 privacy "
            "invariant). Shipped fulfillment_attestation.schema.json shape."
        ),
        "seed_ed25519_ascii": SETTLEMENT_AGENT_SEED.decode(),
        "public_key_b64url": agent.public_key_b64(),
        "join_keys": {"charge_ref": charge_ref, "action_ref": action_ref},
        "signature_b64url": attestation["signature"]["value"],
        "canonical_sha256": sha256_jcs(
            {k: v for k, v in attestation.items() if k != "signature"}
        ),
    }
    write_json("sample.json", sample)

    print("charge_ref            =", charge_ref)
    print("action_ref            =", action_ref)
    print("signature (b64url)    =", attestation["signature"]["value"])
    print("canonical sha256      =", sample["canonical_sha256"])
    print("agent pubkey (b64url) =", agent.public_key_b64())
    print("wrote 2 files to", HERE)


if __name__ == "__main__":
    main()
