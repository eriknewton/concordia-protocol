#!/usr/bin/env python3
"""Offline byte-check for the A2A #1404 worked vector.

A third party runs this against the retained JSON bytes in this directory
(no network, no regeneration required) to confirm:

  1. decision_id recomputes from bytes: SHA-256(JCS(decision_object)).
  2. The receipt's native fields (scope.decision, scope.offer_hash) equal the
     decision object's `decision` and `request_digest` -- the honest mapping
     check that makes the wrapper checkable, not merely asserted.
  3. The signed ApprovalReceipt verifies through the SHIPPED verifier: PASS.
  4. Tampering a single byte flips the signature check to REJECT.
  5. A single status write (RevocationRecord over parent A, cascade scope)
     renders the UNCHANGED child B inadmissible/revoked through the shipped
     cascade verifier: REJECT, with the ancestor status read named in the
     receipt's evidence refs.

Exit code 0 == every assertion held; nonzero == a check failed.

Run:  python verify.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from concordia import verify_approval_receipt
from concordia.canonicalization import canonicalize_jcs
from concordia.cmpc import (
    CandidateArtifact,
    RevocationRecord,
    cascade_revocation,
    verify_revocation_record,
)

HERE = Path(__file__).resolve().parent
FIXED_NOW = datetime(2026, 5, 10, 14, 25, 0, tzinfo=timezone.utc)  # A live, B live


def load(name: str) -> Any:
    return json.loads((HERE / name).read_text())


def b64url_pubkey(value: str) -> Ed25519PublicKey:
    import base64

    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(value))


def sha256_jcs(obj: Any) -> str:
    return hashlib.sha256(canonicalize_jcs(obj)).hexdigest()


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

    offer = load("offer.json")
    decision_object = load("decision_object.json")
    receipt = load("approval_receipt.json")
    delegation_A = load("delegation_A.json")
    delegation_B_candidate = load("delegation_B_candidate.json")
    revocation_dict = load("revocation_A.json")
    vector = load("vector.json")

    approver_pk = b64url_pubkey(vector["public_keys_b64url"]["approver"])
    issuer_pk = b64url_pubkey(vector["public_keys_b64url"]["revocation_issuer"])

    # 1. decision_id recomputes from bytes.
    recomputed = "sha256:" + sha256_jcs(decision_object)
    expected = vector["hashes"]["decision_id"]
    check(
        "decision_id = SHA-256(JCS(decision_object)) recomputes",
        recomputed == expected,
        f"{recomputed}",
    )

    # 1b. Independent-JCS cross-check: if the rfc8785 reference library is
    # available, prove the decision_id is the RFC 8785 STANDARD hash, not a
    # Concordia-specific one. Skipped (not failed) if rfc8785 is absent, so a
    # third party with only `concordia` installed still gets a clean run.
    try:
        import rfc8785  # type: ignore

        ref = "sha256:" + hashlib.sha256(rfc8785.dumps(decision_object)).hexdigest()
        check(
            "decision_id matches INDEPENDENT rfc8785 reference JCS",
            ref == expected,
            ref,
        )
    except ImportError:
        print("[SKIP] rfc8785 not installed; standard-JCS cross-check skipped")

    # 2. Honest native-vs-wrapped mapping is checkable.
    ext = receipt["references"][0]["extensions"]
    check(
        "receipt.scope.decision == decision_object.decision (NATIVE field)",
        receipt["scope"]["decision"] == decision_object["decision"],
    )
    check(
        "receipt.scope.offer_hash == decision_object.request_digest (NATIVE)",
        receipt["scope"]["offer_hash"] == decision_object["request_digest"],
    )
    check(
        "wrapped decision_id in evidence extensions matches recomputed",
        ext["a2a_1404_decision_id"] == recomputed,
    )
    check(
        "ancestor status read is NAMED in evidence refs (propagation-free)",
        ext["a2a_1404_evidence_refs"]["ancestor_status_read"]
        == revocation_dict["revocation_id"],
        ext["a2a_1404_evidence_refs"]["ancestor_status_read"],
    )

    # 3. Shipped verifier: PASS.
    res_ok = verify_approval_receipt(
        receipt, offer, now=FIXED_NOW, issuer_public_key=approver_pk
    )
    check(
        "shipped verify_approval_receipt(child B) is VALID",
        res_ok.valid,
        f"decision={res_ok.decision} reason={res_ok.failure_reason}",
    )

    # 4. Tamper one byte -> REJECT.
    tampered = json.loads(json.dumps(receipt))  # deep copy
    # Flip the last hex nibble of the offer_hash: one-byte change to signed body.
    oh = tampered["scope"]["offer_hash"]
    flipped = "0" if oh[-1] != "0" else "1"
    tampered["scope"]["offer_hash"] = oh[:-1] + flipped
    res_tampered = verify_approval_receipt(
        tampered, offer, now=FIXED_NOW, issuer_public_key=approver_pk
    )
    check(
        "one-byte tamper of signed body -> verifier REJECTS",
        not res_tampered.valid,
        f"reason={res_tampered.failure_reason}",
    )

    # 5a. Revocation record itself verifies under the issuer key.
    revocation = RevocationRecord.from_dict(revocation_dict)
    check(
        "RevocationRecord signature verifies under issuer key",
        verify_revocation_record(revocation, issuer_pk),
    )

    # 5b. Baseline: before the revocation exists, B is admissible (not in the
    # inadmissible set). We model "before" by running the cascade with an empty
    # candidate set that would still flag B only if A is revoked-and-referenced.
    # Here we assert the positive path first: B references A, so once A is
    # revoked with cascade scope, B is inadmissible.
    candidates = [
        CandidateArtifact(
            artifact_id=delegation_A["id"],
            artifact_type="approval_receipt",
            references=delegation_A["references"],
        ),
        CandidateArtifact(
            artifact_id=delegation_B_candidate["artifact_id"],
            artifact_type="approval_receipt",
            references=delegation_B_candidate["references"],
        ),
    ]
    cascade = cascade_revocation(revocation, candidates)
    inadmissible_ids = {a.artifact_id for a in cascade.inadmissible}

    check(
        "cascade: parent A is inadmissible (depth 0, revoked)",
        delegation_A["id"] in inadmissible_ids,
    )
    child_hit = next(
        (
            a
            for a in cascade.inadmissible
            if a.artifact_id == delegation_B_candidate["artifact_id"]
        ),
        None,
    )
    check(
        "cascade: UNCHANGED child B re-verifies to inadmissible/revoked "
        "(single status write, no rewrite of B)",
        child_hit is not None
        and child_hit.reason.value == "revoked",
        None if child_hit is None else child_hit.evidence,
    )

    print()
    print("decision_id =", expected)
    print("OVERALL:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
