#!/usr/bin/env python3
"""Deterministic generator for the A2A #1734 receipt-side context_digest vector.

Emits, into this directory:

  - offer.json                              the request the approver evaluated
  - assembled_context.json                  the context set that fed the decision
  - assembled_context_dropped_artifact.json the same set minus one artifact
  - decision_binding_preimage.json          giskard09's decision_binding_ref preimage
  - approval_receipt.json                   a shipped ApprovalReceipt binding both
  - vector.json                             the recomputable expectations

The point of the fixture is a cross-check, not a restatement. giskard09's
`decision-binding-ref-v1.0` publishes `context_digest` and the
`decision_binding_ref` it produces. This directory carries the same preimage
inside a signed Concordia ApprovalReceipt, so a third party recomputes both
digests from bytes and lands on giskard09's published values, and the binding
additionally becomes non-repudiable: editing the embedded preimage breaks the
receipt's Ed25519 signature.

Everything is derived from a FIXED Ed25519 seed, so the bytes are stable and a
third party who reruns this file gets byte-identical output.

Run:    python generate.py    (regenerates every file in place)
Verify: python verify.py      (byte-checks the whole chain, exit 0 == all PASS)

Only shipped Concordia primitives are used:
  - concordia.canonicalization.canonicalize_jcs   (RFC 8785 JCS)
  - concordia.signing.KeyPair / sign_message / canonical_json
  - concordia.verify_approval_receipt              (shipped verifier)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia.canonicalization import canonicalize_jcs
from concordia.signing import KeyPair, canonical_json, sign_message

HERE = Path(__file__).resolve().parent
# Retained third-party bytes live OUTSIDE docs/interop/ on purpose: the interop
# gate requires every sha256 field in a fixture directory to be re-derivable
# from that directory, which is correct for artifacts this repository authors
# and wrong for artifacts it merely retains. See docs/external/README.md.
EXTERNAL = (
    HERE.parent.parent
    / "external"
    / "giskard09-decision-binding-context-digest-v1"
    / "vectors.json"
)

# ---------------------------------------------------------------------------
# Fixed seed. A third party who reruns this file gets byte-identical output.
# The Ed25519 seed is the ASCII string below (exactly 32 bytes).
# ---------------------------------------------------------------------------
APPROVER_SEED = b"a2a-1734-approver-seed-000000001"  # 32 bytes
assert len(APPROVER_SEED) == 32, "Ed25519 seeds are exactly 32 bytes (RFC 8032 §5.1.5)"

# Extension keys namespaced to the discussion that produced them, so a reader
# of the receipt can trace the field back to the thread and the external spec.
# Must match the pointers used in verify.py and in
# scripts/conformance/generate_vectors.py (the `a2a_1734_*` vector contexts).
EXT_PREIMAGE = "a2a_1734_decision_binding_preimage"
EXT_REF = "a2a_1734_decision_binding_ref"
EXT_SPEC = "a2a_1734_decision_binding_spec"

SPEC_URL = (
    "https://github.com/giskard09/argentum-core/blob/"
    "e04fc4b699dddd4e50074ab4b1639043723975ae/docs/spec/decision-binding-ref-v1.0.md"
)


def keypair_from_seed(seed: bytes) -> KeyPair:
    """Build a deterministic Ed25519 KeyPair from a fixed 32-byte seed."""
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return KeyPair(private_key=private, public_key=private.public_key())


def sha256_jcs(obj: Any) -> str:
    """`sha256:<hex>` over the RFC 8785 JCS canonical bytes of obj."""
    return "sha256:" + hashlib.sha256(canonicalize_jcs(obj)).hexdigest()


def offer_hash(offer: dict[str, Any]) -> str:
    """Match concordia.approval_receipt._offer_hash exactly.

    Must match `_offer_hash` in concordia/approval_receipt.py; the shipped
    verifier recomputes this value and rejects the receipt when it diverges.
    """
    return "sha256:" + hashlib.sha256(canonical_json(offer)).hexdigest()


def write_json(name: str, obj: Any) -> None:
    (HERE / name).write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )


def load_external() -> dict[str, Any]:
    """Load giskard09's retained fixture.

    Read verbatim and never rewritten. The values pulled out of it below are
    the published ones; every digest this generator emits is recomputed from
    the inputs rather than copied from the recorded hashes.
    """
    return json.loads(EXTERNAL.read_text())


def main() -> None:
    approver = keypair_from_seed(APPROVER_SEED)
    external = load_external()

    # -- The two context sets, taken verbatim from giskard09's fixture -------
    # Using their exact sets is what makes this a cross-check: our
    # canonicalizer has to land on their published digest from their inputs,
    # rather than on a digest we chose.
    context_full = external["context_sets"]["context_full"]["assembled_context"]
    context_dropped = external["context_sets"]["context_dropped_artifact"][
        "assembled_context"
    ]

    # Recomputed, never read from the fixture's recorded `sha256` member.
    context_digest = sha256_jcs(context_full)
    context_digest_dropped = sha256_jcs(context_dropped)

    # -- The action the approver evaluated -----------------------------------
    offer = {
        "action": "governance.publish_external_statement",
        "audience": "public",
        "channel": "a2a_discussion",
        "requested_by": "did:web:newton.example#drafting-agent",
    }
    receipt_offer_hash = offer_hash(offer)

    # -- The decision_binding_ref preimage, per decision-binding-ref-v1.0 ----
    # Every field here is derivable from bytes published in this directory.
    # giskard09's own vectors carry an `action_ref` whose preimage they never
    # published, so reusing their preimage verbatim would put an
    # underivable digest inside a Concordia fixture. Instead the fixture
    # derives `action_ref` from the action it actually ships, and the
    # cross-check against their published vectors runs against the retained
    # bytes in docs/external/ (see verify.py check 1). `context_digest` below
    # IS their published value, recomputed here from their published set.
    #
    # `action_ref` and `scope.offer_hash` are the same digest by construction:
    # both are SHA-256 over the JCS bytes of offer.json. That equality is a
    # binding this fixture checks, not a coincidence it relies on.
    preimage = {
        "action_ref": receipt_offer_hash,
        "context_digest": context_digest,
        "decision_at_ms": 1754301600000,
        "decision_id": "approval:a2a-1734-context-digest-worked-example",
    }
    decision_binding_ref = sha256_jcs(preimage)

    # -- The signed receipt --------------------------------------------------
    # Two bindings live here and they are different in kind. `scope.offer_hash`
    # is the native Concordia binding to the request. The `a2a_1734_*`
    # extensions carry the external decision_binding_ref, wrapped rather than
    # recomputed into a Concordia field. The README states the split so a
    # reader never reads the wrapped value as a Concordia-verified one.
    receipt: dict[str, Any] = {
        "artifact_type": "ApprovalReceipt",
        "id": "urn:concordia:receipt:a2a-1734-context-digest",
        "issued_at": "2026-08-04T10:00:00Z",
        "expires_at": "2126-08-04T10:00:00Z",
        "approver": {
            "identity": "did:web:newton.example#governance-lead",
            "role": "governance_authority",
        },
        "scope": {
            "decision": "approve",
            "offer_hash": receipt_offer_hash,
            "amount": "0.00 USD",
            "threshold_crossed": "external_publication",
        },
        "references": [
            {
                "id": "urn:a2a:session:1734-context-digest",
                "type": "negotiation_session",
                "relationship": "approves",
                "extensions": {
                    EXT_REF: decision_binding_ref,
                    EXT_PREIMAGE: preimage,
                    EXT_SPEC: SPEC_URL,
                },
            }
        ],
    }

    # Signed over JCS(receipt without /signature): the signature covers the
    # embedded preimage and context_digest, so a swapped-in stale digest is a
    # signature failure rather than a silent substitution.
    signature = sign_message(receipt, approver)
    receipt["signature"] = {"alg": "Ed25519", "value": signature}

    write_json("offer.json", offer)
    write_json("assembled_context.json", context_full)
    write_json("assembled_context_dropped_artifact.json", context_dropped)
    write_json("decision_binding_preimage.json", preimage)
    write_json("approval_receipt.json", receipt)

    vector = {
        "description": (
            "A2A #1734 receipt-side worked example: a signed Concordia "
            "ApprovalReceipt carrying giskard09's decision_binding_ref preimage, "
            "including context_digest, so the two artifacts cross-check each "
            "other rather than describing each other."
        ),
        "external_spec": SPEC_URL,
        "external_fixture": (
            "https://github.com/giskard09/argentum-core/tree/"
            "e04fc4b699dddd4e50074ab4b1639043723975ae/examples/conformance/"
            "decision-binding-context-digest-v1"
        ),
        "thread": "https://github.com/a2aproject/A2A/discussions/1734",
        "signing_seeds_PUBLIC_test_only_do_not_reuse": {
            "_warning": (
                "PUBLIC test-vector seed. Private-key material by form; published "
                "only to reproduce this fixture. NEVER use in production or reuse "
                "for any real key."
            ),
            "approver_ed25519_seed_ascii": APPROVER_SEED.decode(),
        },
        "public_keys_b64url": {"approver": approver.public_key_b64()},
        # Both context sets publish their digest under the same key name, one
        # level apart, so the interop gate resolves each by the same rule. A
        # distinct key like `context_digest_dropped_artifact` would need a
        # bespoke derivation rule in the gate, and a gate that grows a rule per
        # fixture stops being a gate.
        "hashes": {
            "context_digest": context_digest,
            "decision_binding_ref": decision_binding_ref,
            "receipt_offer_hash": receipt_offer_hash,
            "dropped_artifact_set": {"context_digest": context_digest_dropped},
        },
        "cross_check": {
            "_note": (
                "The context_digest this receipt signs is the value giskard09 "
                "published, recomputed here from their published context set "
                "with Concordia's own RFC 8785 canonicalizer. verify.py "
                "additionally recomputes all four of their vectors and both of "
                "their context sets from the retained bytes under "
                "docs/external/. A divergence on either side fails the check."
            ),
            "_source": (
                "giskard09, decision-binding-context-digest-v1, retained at "
                "docs/external/giskard09-decision-binding-context-digest-v1/"
            ),
            # Named by what they are rather than by whose they are, so the
            # interop gate derives them from bytes in this directory. That is
            # the point: the values attributed to giskard09 below are the ones
            # this repository recomputes, not ones it transcribed.
            "context_digest": external["context_sets"]["context_full"][
                "context_digest"
            ],
            "dropped_artifact_set": {
                "context_digest": external["context_sets"][
                    "context_dropped_artifact"
                ]["context_digest"]
            },
        },
        "native_vs_wrapped": {
            "native_receipt_fields": ["scope.offer_hash", "scope.decision"],
            "wrapped_in_reference_extensions": [
                EXT_REF,
                EXT_PREIMAGE,
                EXT_SPEC,
            ],
            "_note": (
                "action_ref inside the wrapped preimage is SHA-256 over the JCS "
                "bytes of offer.json, the same digest scope.offer_hash carries. "
                "Every digest this fixture publishes is derivable from bytes in "
                "this directory; nothing is carried as an opaque value."
            ),
        },
    }
    write_json("vector.json", vector)

    print("context_digest         =", context_digest)
    print("context_digest dropped =", context_digest_dropped)
    print("decision_binding_ref   =", decision_binding_ref)
    print("receipt.offer_hash     =", receipt_offer_hash)
    print("approver pubkey (b64u) =", approver.public_key_b64())
    print("wrote 6 files to", HERE)


if __name__ == "__main__":
    main()
