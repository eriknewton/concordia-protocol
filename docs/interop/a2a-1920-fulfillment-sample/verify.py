#!/usr/bin/env python3
"""Offline byte-check for the A2A #1920 FulfillmentAttestation sample.

Confirms, from the retained JSON bytes (no network, no regeneration):

  1. The sample validates through the SHIPPED verifier
     concordia.schema_validator.validate_fulfillment_attestation (schema +
     the fulfills-reference equality invariant): PASS.
  2. The Ed25519 signature verifies over the shipped canonical JSON: PASS.
  3. Tampering one byte of the signed body flips the signature to REJECT.
  4. Privacy invariant: the whole artifact carries behavioral signals + hash
     references only. A recursive scan (reusing the shipped raw-deal-term
     patterns from concordia.schema_validator) finds NO raw terms anywhere:
     PASS. A synthetic term injected into a copy is caught: REJECT.
  5. The composition join key (charge_ref / action_ref) is present and matches
     sample.json.

Exit code 0 == every assertion held.

Run:  python verify.py
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from concordia.schema_validator import (
    _RAW_TERM_PATTERNS,  # shipped raw-deal-term detectors (SPEC 9.6.6)
    validate_fulfillment_attestation,
)
from concordia.signing import canonical_json

HERE = Path(__file__).resolve().parent


def load(name: str) -> Any:
    return json.loads((HERE / name).read_text())


def _walk_strings(obj: Any) -> list[str]:
    """Collect every string value and key anywhere in the artifact."""
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                out.append(k)
            out.extend(_walk_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_walk_strings(v))
    elif isinstance(obj, str):
        out.append(obj)
    return out


def contains_raw_term(obj: Any) -> tuple[bool, str]:
    """True if any string in the artifact matches a shipped raw-term pattern.

    Excludes the detached signature value (opaque base64, not deal text).
    """
    scan = {k: v for k, v in obj.items() if k != "signature"}
    for s in _walk_strings(scan):
        for pat in _RAW_TERM_PATTERNS:
            if pat.search(s):
                return True, s
    return False, ""


def main() -> int:
    ok = True

    def check(label: str, condition: bool, detail: str = "") -> None:
        nonlocal ok
        status = "PASS" if condition else "REJECT/FAIL"
        line = f"[{status}] {label}"
        if detail:
            line += f"  ({detail})"
        print(line)
        if not condition:
            ok = False

    att = load("fulfillment_attestation.json")
    sample = load("sample.json")
    pubkey = Ed25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(sample["public_key_b64url"])
    )

    # 1. Shipped verifier: PASS.
    errors = validate_fulfillment_attestation(att)
    check(
        "shipped validate_fulfillment_attestation() returns no errors",
        errors == [],
        f"errors={errors}" if errors else "",
    )

    # 2. Ed25519 signature verifies over shipped canonical JSON.
    signable = {k: v for k, v in att.items() if k != "signature"}
    sig = base64.urlsafe_b64decode(att["signature"]["value"])
    sig_ok = True
    try:
        pubkey.verify(sig, canonical_json(signable))
    except Exception:
        sig_ok = False
    check("Ed25519 signature verifies over canonical JSON", sig_ok)

    # 3. One-byte tamper -> signature REJECT.
    tampered = json.loads(json.dumps(signable))
    tampered["charge_ref"] = tampered["charge_ref"][:-1] + (
        "0" if tampered["charge_ref"][-1] != "0" else "1"
    )
    tamper_rejected = False
    try:
        pubkey.verify(sig, canonical_json(tampered))
    except Exception:
        tamper_rejected = True
    check("one-byte tamper of signed body -> signature REJECTS", tamper_rejected)

    # 4. Privacy invariant.
    has_term, hit = contains_raw_term(att)
    check(
        "privacy invariant: NO raw deal terms anywhere in the artifact",
        not has_term,
        f"unexpected raw term: {hit}" if has_term else "behavioral-signal + hash-ref only",
    )
    # Negative control: a synthetic term IS caught by the same scan.
    poisoned = json.loads(json.dumps(att))
    poisoned["meta"]["behavioral_signals"]["note"] = "price: 150000 USD"
    poisoned_has_term, _ = contains_raw_term(poisoned)
    check(
        "negative control: injected raw term IS detected (scan works)",
        poisoned_has_term,
    )

    # 5. Composition join key present + matches.
    check(
        "charge_ref join key present and matches sample.json",
        att.get("charge_ref") == sample["join_keys"]["charge_ref"],
        att.get("charge_ref", "<missing>"),
    )
    check(
        "action_ref join key present and matches sample.json",
        att.get("action_ref") == sample["join_keys"]["action_ref"],
        att.get("action_ref", "<missing>"),
    )

    print()
    print("charge_ref =", att.get("charge_ref"))
    print("action_ref =", att.get("action_ref"))
    print("OVERALL:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
