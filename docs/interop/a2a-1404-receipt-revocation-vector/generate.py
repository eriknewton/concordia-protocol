#!/usr/bin/env python3
"""Deterministic generator for the A2A #1404 worked vector.

Emits, into this directory:

  - offer.json                    the canonical request/offer the approver saw
  - decision_object.json          the six-field #1404 decision object
  - approval_receipt.json         a shipped ApprovalReceipt carrying the object
  - delegation_A.json             parent delegation (an ApprovalReceipt)
  - delegation_B.json             child delegation referencing A (allowed)
  - revocation_A.json             a shipped RevocationRecord revoking A (cascade)
  - cascade_decision_deny.json    the COMMITTED terminal deny for child B
  - vector.json                   the recomputable expectations (hashes etc.)

Everything is derived from FIXED Ed25519 seeds so the bytes and the
decision_id hashes are stable and reproducible. See README.md for the
honest native-vs-wrapped field mapping.

Run:  python generate.py    (regenerates every file in place)
Verify: python verify.py    (byte-checks sign/verify/tamper/revoke)

Only shipped Concordia primitives + the shipped canonicalizer are used:
  - concordia.signing.KeyPair / sign_message / canonical_json
  - concordia.canonicalization.canonicalize_jcs   (RFC 8785 JCS)
  - concordia.verify_approval_receipt              (shipped verifier)
  - concordia.cmpc.sign_revocation_record / cascade_revocation
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia.canonicalization import canonicalize_jcs
from concordia.cmpc import (
    CandidateArtifact,
    CascadeBoundary,
    RevocationRecord,
    RevocationScope,
    cascade_revocation,
    sign_revocation_record,
)
from concordia.signing import KeyPair, canonical_json, sign_message

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Fixed seeds. A third party who reruns this file gets byte-identical output.
# The 32-byte Ed25519 seeds are the ASCII strings below (exactly 32 bytes).
# ---------------------------------------------------------------------------
APPROVER_SEED = b"a2a-1404-approver-seed-000000001"  # 32 bytes
ISSUER_SEED = b"a2a-1404-revoc-issuer-seed-00001"    # 32 bytes
assert len(APPROVER_SEED) == 32
assert len(ISSUER_SEED) == 32


def keypair_from_seed(seed: bytes) -> KeyPair:
    """Build a deterministic Ed25519 KeyPair from a fixed 32-byte seed."""
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return KeyPair(private_key=private, public_key=private.public_key())


def sha256_jcs(obj: Any) -> str:
    """SHA-256 hex over the RFC 8785 JCS canonical bytes of obj."""
    return hashlib.sha256(canonicalize_jcs(obj)).hexdigest()


def offer_hash(offer: dict[str, Any]) -> str:
    """Match concordia.approval_receipt._offer_hash exactly."""
    return "sha256:" + hashlib.sha256(canonical_json(offer)).hexdigest()


def write_json(name: str, obj: Any) -> None:
    (HERE / name).write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )


def main() -> None:
    approver = keypair_from_seed(APPROVER_SEED)
    issuer = keypair_from_seed(ISSUER_SEED)

    # -- The request/offer the approver evaluated (drives request_digest) -----
    offer = {
        "action": "procurement.purchase_order",
        "currency": "USD",
        "line_items": [
            {"quantity": 3, "sku": "SRV-RACK-42U"},
        ],
        "total": "150000.00",
        "vendor": "did:web:vendor.example",
    }
    request_digest = "sha256:" + sha256_jcs(offer)

    # -- The capability the approver authorized (drives capability_digest) ----
    # Content-addressed description of the granted capability. Its digest is
    # one of the six #1404 binding fields; it is NOT a native receipt field, so
    # it lives in the decision object (see README, "field mapping").
    capability = {
        "action": "procurement.purchase_order",
        "constraints": {"currency": "USD", "max_total": "200000.00"},
        "granted_to": "did:web:buyer-agent.example",
    }
    capability_digest = "sha256:" + sha256_jcs(capability)

    # -- The six-field #1404 decision object ---------------------------------
    # decision_id = SHA-256 over the RFC 8785 JCS serialization of exactly
    # these six fields. Field order is irrelevant: JCS sorts keys.
    decision_object = {
        "boundary_id": "urn:a2a:boundary:acme-procurement-hitl",
        "capability_digest": capability_digest,
        "decision": "approve",
        "policy_version": "acme-procurement-policy@2026-05-01",
        "request_digest": request_digest,
        "verifier": "did:web:acme.example#procurement-lead",
    }
    decision_id = sha256_jcs(decision_object)

    # -- The shipped ApprovalReceipt -----------------------------------------
    # Two of the six fields are NATIVE: scope.decision (== decision) and
    # scope.offer_hash (== request_digest). The remaining four, plus the whole
    # six-field object and its decision_id, are carried in the "approves"
    # reference's `extensions` (schema-allowed object) so the receipt stays a
    # stock v0.5 ApprovalReceipt. The verify script asserts the native fields
    # equal the object's, so the mapping is checkable, not asserted.
    receipt: dict[str, Any] = {
        "artifact_type": "ApprovalReceipt",
        "id": "urn:concordia:receipt:a2a-1404-B",
        "issued_at": "2026-05-10T14:22:08Z",
        "expires_at": "2126-05-10T14:22:08Z",  # far future: deterministic verify
        "approver": {
            "identity": "did:web:acme.example#procurement-lead",
            "role": "procurement_authority",
        },
        "scope": {
            "decision": decision_object["decision"],
            "offer_hash": offer_hash(offer),
            "amount": "150000.00 USD",
            "threshold_crossed": "100000.00 USD",
        },
        "references": [
            {
                "type": "negotiation_session",
                "id": "urn:a2a:session:9e4d2c11",
                "relationship": "approves",
                "extensions": {
                    "a2a_1404_decision_object": decision_object,
                    "a2a_1404_decision_id": "sha256:" + decision_id,
                    "a2a_1404_evidence_refs": {
                        # The ancestor status read is NAMED here so a verifier
                        # can locate the revocation status of the parent
                        # delegation without any propagation. Content-addressed,
                        # propagation-free.
                        "ancestor_status_read": (
                            "urn:concordia:revocation:a2a-1404-A"
                        ),
                        "parent_delegation": "urn:concordia:receipt:a2a-1404-A",
                    },
                },
            }
        ],
    }
    # Sign the receipt (sign_message strips any signature field first).
    receipt_sig = sign_message(receipt, approver)
    receipt["signature"] = {"alg": "Ed25519", "value": receipt_sig}

    # -- Negative revocation vector -------------------------------------------
    # Parent delegation A: an ApprovalReceipt. Child delegation B is the receipt
    # above; it references A via a `fulfills` reference (a cascade relationship).
    # A single status write (the RevocationRecord below, scope
    # cascade_to_dependents) revokes A; re-running the cascade verifier over the
    # unchanged B yields B inadmissible/revoked WITHOUT rewriting B.
    delegation_A: dict[str, Any] = {
        "artifact_type": "ApprovalReceipt",
        "id": "urn:concordia:receipt:a2a-1404-A",
        "issued_at": "2026-05-10T14:20:00Z",
        "expires_at": "2126-05-10T14:20:00Z",
        "approver": {
            "identity": "did:web:acme.example#delegating-principal",
            "role": "delegating_principal",
        },
        "scope": {
            "decision": "approve",
            "offer_hash": offer_hash(capability),
            "amount": "200000.00 USD",
            "threshold_crossed": "100000.00 USD",
        },
        "references": [
            {
                "type": "negotiation_session",
                "id": "urn:a2a:session:9e4d2c11",
                "relationship": "approves",
            }
        ],
    }
    delegation_A["signature"] = {
        "alg": "Ed25519",
        "value": sign_message(delegation_A, approver),
    }

    # Child B, as a cascade candidate artifact: it references A with a
    # cascade relationship ("fulfills"). This is the SAME B; we do not rewrite
    # it. The cascade candidate is the projection the cascade verifier consumes.
    delegation_B_candidate = {
        "artifact_id": receipt["id"],
        "artifact_type": "approval_receipt",
        "references": [
            {
                "id": delegation_A["id"],
                "relationship": "fulfills",
                "type": "approval_receipt",
            }
        ],
    }

    # The single status write: revoke A, cascade to dependents.
    unsigned_revocation = RevocationRecord(
        revocation_id="urn:concordia:revocation:a2a-1404-A",
        revoked_artifact_id=delegation_A["id"],
        revoked_artifact_type="approval_receipt",
        revocation_scope=RevocationScope.CASCADE_TO_DEPENDENTS.value,
        issuer_did="did:web:acme.example#delegating-principal",
        issued_at="2026-05-10T14:30:00Z",
        effective_at="2026-05-10T14:30:00Z",
        reason="principal_revoked_delegation",
        references=[
            {
                "id": delegation_A["id"],
                "relationship": "revokes",
                "type": "approval_receipt",
            }
        ],
        cascade_depth=3,
    )
    revocation = sign_revocation_record(unsigned_revocation, issuer)

    # -- The COMMITTED terminal deny ------------------------------------------
    # Re-running the cascade verifier over the unchanged child B, with a boundary
    # context + the issuer key, emits a committed CascadeDecisionRecord for each
    # inadmissible artifact. We keep the one for child B: a recomputable terminal
    # deny whose decision_id content-addresses the ancestor status read (parent A
    # observed `revoked` at the status source's own ordering coordinate). The
    # source coordinate is source-ordered (a log sequence number), never a wall
    # clock. capability_digest / request_digest reuse the child's #1404 digests
    # so the deny's six-field object matches the approve object's field shape.
    boundary = CascadeBoundary(
        boundary_id=decision_object["boundary_id"],
        verifier=decision_object["verifier"],
        policy_version=decision_object["policy_version"],
        # Digest of the status source the verifier read (the revocation record's
        # canonical bytes), content-addressed so authority stays verifier-side.
        source_digest="sha256:"
        + hashlib.sha256(canonicalize_jcs(revocation.to_dict())).hexdigest(),
        # Source-ordered coordinate: the status log sequence number at which A's
        # revocation was fixed. A fixed integer here, NOT a wall clock.
        coordinate=42,
        capability_digest=capability_digest,
        request_digest=request_digest,
        approval_receipt_ref="sha256:"
        + hashlib.sha256(canonical_json(receipt)).hexdigest(),
    )
    cascade = cascade_revocation(
        revocation,
        [
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
        ],
        boundary=boundary,
        signing_key=issuer,
    )
    committed_deny = next(
        d
        for d, a in zip(cascade.decisions, cascade.inadmissible)
        if a.artifact_id == delegation_B_candidate["artifact_id"]
    )

    # -- Emit fixture bytes ---------------------------------------------------
    write_json("offer.json", offer)
    write_json("capability.json", capability)
    write_json("decision_object.json", decision_object)
    write_json("approval_receipt.json", receipt)
    write_json("delegation_A.json", delegation_A)
    write_json("delegation_B_candidate.json", delegation_B_candidate)
    write_json("revocation_A.json", revocation.to_dict())
    write_json("cascade_decision_deny.json", committed_deny.to_dict())

    vector = {
        "description": (
            "A2A #1404 worked vector: recomputable decision_id + negative "
            "revocation vector, using shipped Concordia ApprovalReceipt + "
            "RevocationRecord and the RFC 8785 JCS canonicalizer."
        ),
        "seeds": {
            "approver_ed25519_seed_ascii": APPROVER_SEED.decode(),
            "revocation_issuer_ed25519_seed_ascii": ISSUER_SEED.decode(),
        },
        "public_keys_b64url": {
            "approver": approver.public_key_b64(),
            "revocation_issuer": issuer.public_key_b64(),
        },
        "hashes": {
            "capability_digest": capability_digest,
            "request_digest": request_digest,
            "decision_id": "sha256:" + decision_id,
            "receipt_offer_hash": receipt["scope"]["offer_hash"],
            # The COMMITTED terminal deny's own recomputable id.
            "deny_decision_id": "sha256:" + committed_deny.decision_id,
        },
        "native_vs_wrapped": {
            "native_receipt_fields": ["decision", "request_digest"],
            "wrapped_in_evidence_extensions": [
                "capability_digest",
                "boundary_id",
                "verifier",
                "policy_version",
            ],
        },
    }
    write_json("vector.json", vector)

    # Human-readable console echo of the load-bearing hashes.
    print("decision_id           =", "sha256:" + decision_id)
    print("deny_decision_id      =", "sha256:" + committed_deny.decision_id)
    print("capability_digest     =", capability_digest)
    print("request_digest        =", request_digest)
    print("receipt.offer_hash    =", receipt["scope"]["offer_hash"])
    print("approver pubkey (b64u)=", approver.public_key_b64())
    print("issuer   pubkey (b64u)=", issuer.public_key_b64())
    print("wrote 9 files to", HERE)


if __name__ == "__main__":
    main()
