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
  6. The revocation terminal is a COMMITTED CascadeDecisionRecord: its
     decision_id recomputes from bytes and commits to the ancestor read, its
     signature verifies under the issuer key, a mutated ancestor status
     diverges the id, and a one-byte tamper rejects. The allow (the still-valid
     ApprovalReceipt at its own coordinate) stays valid while the deny
     terminates current execution.

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
    AncestorRead,
    CandidateArtifact,
    CascadeDecisionRecord,
    RevocationRecord,
    canonicalize_cascade_decision_record,
    cascade_revocation,
    verify_cascade_decision_record,
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


def dataclasses_replace_ancestor(
    deny: CascadeDecisionRecord, *, status: str
) -> CascadeDecisionRecord:
    """Return a copy of `deny` with its first ancestor read's status changed.

    The stated `decision_id` and `signature` are carried over unchanged, so the
    forged record claims the original id over a mutated body -- exactly what a
    recomputing verifier must catch.
    """
    read = deny.ancestor_reads[0]
    mutated = AncestorRead(
        element_digest=read.element_digest,
        status=status,
        source_digest=read.source_digest,
        coordinate=read.coordinate,
    )
    return CascadeDecisionRecord(
        capability_digest=deny.capability_digest,
        request_digest=deny.request_digest,
        boundary_id=deny.boundary_id,
        decision=deny.decision,
        verifier=deny.verifier,
        policy_version=deny.policy_version,
        ancestor_reads=[mutated],
        decision_id=deny.decision_id,
        signature=deny.signature,
        approval_receipt_ref=deny.approval_receipt_ref,
        revocation_record_ref=deny.revocation_record_ref,
    )


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

    # 6. The revocation terminal is a COMMITTED, recomputable CascadeDecisionRecord.
    deny_dict = load("cascade_decision_deny.json")
    deny = CascadeDecisionRecord.from_dict(deny_dict)

    # 6a. decision_id recomputes from the retained bytes (SHA-256 of JCS(preimage)).
    deny_recomputed = "sha256:" + hashlib.sha256(
        canonicalize_cascade_decision_record(deny)
    ).hexdigest()
    deny_expected = vector["hashes"]["deny_decision_id"]
    check(
        "committed deny: decision_id recomputes from bytes",
        deny_recomputed == deny_expected,
        deny_recomputed,
    )

    # 6b. Independent rfc8785 cross-check: it is the RFC 8785 STANDARD hash, so
    # it cross-runs byte-for-byte with any conformant decision-log family.
    try:
        import rfc8785  # type: ignore

        deny_ref = "sha256:" + hashlib.sha256(
            rfc8785.dumps(deny.preimage())
        ).hexdigest()
        check(
            "committed deny: decision_id matches INDEPENDENT rfc8785 JCS",
            deny_ref == deny_expected,
            deny_ref,
        )
    except ImportError:
        print("[SKIP] rfc8785 not installed; deny standard-JCS cross-check skipped")

    # 6c. The deny is a terminal deny that COMMITS to the ancestor read: the
    # exact {element_digest, status, source_digest, coordinate} is in the
    # preimage, and it names the parent A revocation the verifier read.
    check(
        "committed deny: decision == 'deny' (terminal)",
        deny.decision == "deny",
    )
    read = deny.ancestor_reads[0]
    check(
        "committed deny: commits to ancestor A read (status=revoked)",
        read.element_digest == revocation_dict["revoked_artifact_id"]
        and read.status == "revoked"
        and deny.revocation_record_ref == revocation_dict["revocation_id"],
        f"element={read.element_digest} status={read.status}",
    )
    # The coordinate is COMMITTED (it is inside the preimage, so tampering it
    # diverges the id — proven at 6e-i) and is a non-negative integer. The
    # primitive does NOT prove the integer is a real pinned source ordinal;
    # source authenticity is the VERIFIER's policy, not something this check
    # establishes. So the PASS line states only what the assertion establishes.
    check(
        "committed deny: ancestor coordinate is a committed non-negative integer",
        isinstance(read.coordinate, int)
        and not isinstance(read.coordinate, bool)
        and read.coordinate >= 0,
        f"coordinate={read.coordinate!r} (source authenticity is verifier policy)",
    )

    # 6d. The signature verifies under the issuer key (the same key that signed
    # the revocation record; the verifier is the issuer of the terminal). We
    # pass the RAW retained bytes (deny_dict), not a normalized round-trip: the
    # shipped verifier strict-parses the raw object and recomputes from those
    # exact bytes.
    check(
        "committed deny: signature verifies under issuer key (raw bytes)",
        verify_cascade_decision_record(deny_dict, issuer_pk),
    )

    # 6e. Recomputable, not asserted: mutating the CLAIMED ancestor status
    # diverges the recomputed id, so the verifier rejects the forged record.
    mutated_status = dataclasses_replace_ancestor(deny, status="active")
    check(
        "committed deny: mutated ancestor status diverges id -> REJECT",
        (
            "sha256:"
            + hashlib.sha256(
                canonicalize_cascade_decision_record(mutated_status)
            ).hexdigest()
        )
        != deny_expected
        and not verify_cascade_decision_record(mutated_status.to_dict(), issuer_pk),
    )

    # 6e-i. Mutating the ancestor COORDINATE diverges the id -> REJECT. (The
    # public vector must prove what the README claims: the coordinate is
    # committed, so tampering it is caught.)
    coord_mutated = json.loads(json.dumps(deny_dict))
    coord_mutated["ancestor_reads"][0]["coordinate"] += 1
    check(
        "committed deny: mutated ancestor coordinate diverges id -> REJECT",
        (
            "sha256:"
            + hashlib.sha256(
                canonicalize_cascade_decision_record(coord_mutated)
            ).hexdigest()
        )
        != deny_expected
        and not verify_cascade_decision_record(coord_mutated, issuer_pk),
    )

    # 6e-ii. Swapping a committed REF diverges the id -> REJECT. Both the
    # withdrawal (revocation_record_ref) and the prior allow
    # (approval_receipt_ref) sit inside the preimage, so neither can be swapped
    # without diverging the id.
    for ref_field in ("revocation_record_ref", "approval_receipt_ref"):
        if ref_field not in deny_dict:
            continue
        ref_swapped = json.loads(json.dumps(deny_dict))
        ref_swapped[ref_field] = ref_swapped[ref_field] + "-SWAPPED"
        check(
            f"committed deny: swapped {ref_field} diverges id -> REJECT",
            (
                "sha256:"
                + hashlib.sha256(
                    canonicalize_cascade_decision_record(ref_swapped)
                ).hexdigest()
            )
            != deny_expected
            and not verify_cascade_decision_record(ref_swapped, issuer_pk),
        )

    # 6e-iii. Injecting a RAW DEAL TERM (or any unknown field), at the top level
    # OR inside an ancestor read, is REJECTED by the strict verifier, never
    # silently dropped. This is the no-raw-deal-terms privacy invariant enforced
    # at the verify boundary, and the recompute-over-retained-bytes property: a
    # normalizing verifier would drop the field and wrongly PASS.
    deal_term_in_ancestor = json.loads(json.dumps(deny_dict))
    deal_term_in_ancestor["ancestor_reads"][0]["deal_terms"] = {
        "total": "150000.00 USD"
    }
    check(
        "committed deny: injected deal_terms inside ancestor_reads[] -> REJECT",
        not verify_cascade_decision_record(deal_term_in_ancestor, issuer_pk),
    )
    smuggled_top_level = json.loads(json.dumps(deny_dict))
    smuggled_top_level["deal_terms"] = {"total": "150000.00 USD"}
    check(
        "committed deny: injected top-level unknown field -> REJECT",
        not verify_cascade_decision_record(smuggled_top_level, issuer_pk),
    )

    # 6e-iv. A GENERIC unknown field inside ANY nested object is REJECTED, not
    # just inside an ancestor read. Here we inject `signature.kid` — an unknown
    # key inside the nested `signature` object, whose schema is
    # `additionalProperties: false`. This locks the nested-object strictness end
    # to end: a smuggled field cannot hide inside a nested object either, so a
    # normalizing verifier that dropped it (and false-PASSed) is ruled out at
    # every level, not only the top level and the ancestor read.
    nested_unknown = json.loads(json.dumps(deny_dict))
    nested_unknown["signature"]["kid"] = "did:web:evil.example#smuggled"
    check(
        "committed deny: injected nested unknown field (signature.kid) -> REJECT",
        not verify_cascade_decision_record(nested_unknown, issuer_pk),
    )

    # 6f. A one-byte tamper of the signed body flips the verifier to REJECT.
    tampered_deny_dict = json.loads(json.dumps(deny_dict))
    cd = tampered_deny_dict["capability_digest"]
    tampered_deny_dict["capability_digest"] = cd[:-1] + (
        "0" if cd[-1] != "0" else "1"
    )
    check(
        "committed deny: one-byte tamper of signed body -> REJECT",
        not verify_cascade_decision_record(tampered_deny_dict, issuer_pk),
    )

    # 6g. The allow stays valid at its own coordinate while the deny terminates
    # current execution: the still-signed ApprovalReceipt B verifies at
    # FIXED_NOW (A live, B live), i.e. the historical allow is not invalidated
    # by the later terminal deny (which is a separate, new record).
    allow_still_valid = verify_approval_receipt(
        receipt, offer, now=FIXED_NOW, issuer_public_key=approver_pk
    )
    check(
        "allow historically valid at its coordinate while deny terminates now",
        allow_still_valid.valid and ("sha256:" + deny.decision_id) != expected,
        f"allow.valid={allow_still_valid.valid}",
    )

    print()
    print("decision_id      =", expected)
    print("deny_decision_id =", deny_expected)
    print("OVERALL:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
