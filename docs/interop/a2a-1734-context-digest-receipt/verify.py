#!/usr/bin/env python3
"""Offline byte-check for the A2A #1734 receipt-side context_digest vector.

A third party runs this against the retained JSON bytes in this directory
(no network, no regeneration required) to confirm:

  1. giskard09's four published conformance vectors (cd-001 .. cd-004), both
     of their published context sets, and the four inline spec fixtures
     (A .. D) all recompute under Concordia's own RFC 8785 JCS canonicalizer.
     Their recorded digests are read only as the value being compared against,
     never as a source.
  2. Every digest this fixture publishes recomputes from the shipped bytes:
     context_digest from assembled_context.json, decision_binding_ref from
     decision_binding_preimage.json, and the native offer_hash from offer.json.
  3. The context_digest the receipt signs is the value giskard09 published for
     `context_full`, recomputed here from their published set. This is the
     cross-check: two implementations, one digest. The rest of the preimage is
     this fixture's own, and every field of it is derivable from bytes in this
     directory, so nothing is carried as an opaque value.
  4. The signed ApprovalReceipt verifies through the SHIPPED Concordia
     verifier: PASS.
  5. CONTEXT_SET_MISMATCH: presenting the dropped-artifact context set
     recomputes to a different digest than the one embedded in the receipt, so
     a verifier rejects rather than accepting a partial set as the one that
     actually fed the decision.
  6. The receipt SIGNS the binding. Swapping the embedded context_digest for
     the dropped-artifact digest flips the signature check to REJECT, so a
     stale digest cannot be substituted without detection. This is what the
     receipt side adds on top of a published digest.
  7. A one-byte tamper anywhere in the receipt flips the signature to REJECT.
  8. The published public key and signature are DERIVED from the recorded
     public test seed, not merely asserted.

Exit code 0 == every assertion held; nonzero == a check failed.

Run:  python verify.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia import verify_approval_receipt
from concordia.canonicalization import canonicalize_jcs
from concordia.signing import KeyPair, canonical_json, public_key_from_b64url

HERE = Path(__file__).resolve().parent
# Retained third-party bytes live outside docs/interop/ on purpose; see
# docs/external/README.md for why the interop gate must not scan them.
_EXTERNAL_DIR = (
    HERE.parent.parent / "external" / "giskard09-decision-binding-context-digest-v1"
)
EXTERNAL = _EXTERNAL_DIR / "vectors.json"
PROVENANCE = _EXTERNAL_DIR / "PROVENANCE.json"

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    suffix = f"  {detail}" if detail else ""
    print(f"[{status}] {label}{suffix}")
    if not condition:
        FAILURES.append(label)


def load(name: str) -> Any:
    return json.loads((HERE / name).read_text())


def sha256_jcs(obj: Any) -> str:
    """`sha256:<hex>` over the RFC 8785 JCS canonical bytes of obj."""
    return "sha256:" + hashlib.sha256(canonicalize_jcs(obj)).hexdigest()


# ---------------------------------------------------------------------------
# Check 1: giskard09's published vectors recompute under Concordia's JCS.
# ---------------------------------------------------------------------------


def check_external_vectors(external: dict[str, Any]) -> None:
    print("\n-- 1. giskard09 decision-binding-context-digest-v1, recomputed --")

    for name, entry in sorted(external["context_sets"].items()):
        assembled = entry["assembled_context"]
        # Byte comparison first: an equal digest with different bytes would be
        # a collision claim, so compare the canonical bytes as well.
        ours = canonicalize_jcs(assembled).decode("utf-8")
        check(
            f"context set {name}: canonical bytes match",
            ours == entry["jcs"],
        )
        check(
            f"context set {name}: digest matches",
            sha256_jcs(assembled) == entry["context_digest"],
            entry["context_digest"],
        )

    for vector in external["vectors"]:
        vid = vector["id"]
        preimage = vector.get("preimage") or vector["embedded_preimage"]
        published = vector.get("decision_binding_ref") or vector[
            "embedded_decision_binding_ref"
        ]
        if "canonical" in vector:
            check(
                f"{vid}: canonical bytes match",
                canonicalize_jcs(preimage).decode("utf-8") == vector["canonical"],
            )
        check(
            f"{vid}: decision_binding_ref matches",
            sha256_jcs(preimage) == published,
            published,
        )

    # cd-004 is the negative: recomputing over the PRESENTED set must diverge
    # from the digest embedded in the preimage. A vector that only agreed on
    # arithmetic would pass without the divergence ever being asserted.
    cd_004 = next(v for v in external["vectors"] if v["id"] == "cd-004")
    presented = external["context_sets"][cd_004["presented_context_set"]][
        "assembled_context"
    ]
    recomputed = sha256_jcs(presented)
    check(
        "cd-004: recomputed presented-set digest matches published",
        recomputed == cd_004["recomputed_context_digest"],
    )
    check(
        "cd-004: recomputed digest diverges from embedded context_digest "
        "(CONTEXT_SET_MISMATCH)",
        recomputed != cd_004["embedded_preimage"]["context_digest"],
    )


def check_spec_fixtures() -> None:
    """The four inline fixtures from decision-binding-ref-v1.0.md.

    Transcribed rather than retained: they are published inline in the spec
    prose, not in a machine-readable file. Each digest is recomputed from the
    transcribed preimage, so a transcription slip fails here instead of
    passing quietly.
    """
    print("\n-- 1b. decision-binding-ref-v1.0 inline fixtures A-D --")
    base = {
        "action_ref": (
            "sha256:9752a870dac7100010453be9494ec631c78fd55bb7cb41355cf03592da3862ce"
        ),
        "decision_at_ms": 1748736000000,
        "decision_id": "approval:7f3a9c21-4e5b-4d8f-b3c2-1a9e8f7d6c5b",
    }
    policy_ref = (
        "sha256:b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a6c7"
    )
    context_digest = (
        "sha256:c2bf3a88a2e5d8d63b95b22eab6b31bf2b7ab6108002b37a9b0945b722d4b9bb"
    )
    expected = json.loads(PROVENANCE.read_text())["spec_fixtures_A_to_D"]
    fixtures = {
        "A_policy_ref_only": {**base, "policy_ref": policy_ref},
        "B_neither": dict(base),
        "C_context_digest_only": {**base, "context_digest": context_digest},
        "D_both": {**base, "policy_ref": policy_ref, "context_digest": context_digest},
    }
    for name, preimage in fixtures.items():
        check(
            f"spec fixture {name}: digest matches",
            sha256_jcs(preimage) == expected[name],
            expected[name],
        )


# ---------------------------------------------------------------------------
# Checks 2-3: this fixture's own digests, and the cross-check.
# ---------------------------------------------------------------------------


def check_own_digests(
    vector: dict[str, Any],
    receipt: dict[str, Any],
    external: dict[str, Any],
) -> None:
    print("\n-- 2. this fixture's published digests, recomputed from bytes --")
    assembled = load("assembled_context.json")
    dropped = load("assembled_context_dropped_artifact.json")
    preimage = load("decision_binding_preimage.json")
    offer = load("offer.json")

    context_digest = sha256_jcs(assembled)
    binding_ref = sha256_jcs(preimage)
    native_offer_hash = (
        "sha256:" + hashlib.sha256(canonical_json(offer)).hexdigest()
    )

    check(
        "context_digest recomputes",
        context_digest == vector["hashes"]["context_digest"],
        context_digest,
    )
    check(
        "context_digest (dropped artifact) recomputes",
        sha256_jcs(dropped)
        == vector["hashes"]["dropped_artifact_set"]["context_digest"],
    )
    check(
        "decision_binding_ref recomputes",
        binding_ref == vector["hashes"]["decision_binding_ref"],
        binding_ref,
    )
    check(
        "native scope.offer_hash recomputes from offer.json",
        native_offer_hash == receipt["scope"]["offer_hash"],
    )

    extensions = receipt["references"][0]["extensions"]
    check(
        "receipt embeds the same preimage that was hashed",
        extensions["a2a_1734_decision_binding_preimage"] == preimage,
    )
    check(
        "receipt's embedded decision_binding_ref equals the recomputed one",
        extensions["a2a_1734_decision_binding_ref"] == binding_ref,
    )
    check(
        "receipt's embedded context_digest equals the recomputed one",
        extensions["a2a_1734_decision_binding_preimage"]["context_digest"]
        == context_digest,
    )

    print("\n-- 3. cross-check against giskard09's published values --")
    check(
        "the context_digest this receipt signs is their published context_full "
        "digest",
        context_digest
        == external["context_sets"]["context_full"]["context_digest"],
        context_digest,
    )
    check(
        "the dropped-set digest is their published context_dropped_artifact "
        "digest",
        sha256_jcs(dropped)
        == external["context_sets"]["context_dropped_artifact"]["context_digest"],
    )
    # Every digest in the preimage is derivable from bytes in this directory,
    # so a third party recomputes the whole chain without holding any value
    # this fixture could not produce.
    check(
        "action_ref in the preimage equals the native scope.offer_hash",
        preimage["action_ref"] == receipt["scope"]["offer_hash"],
    )


# ---------------------------------------------------------------------------
# Checks 4-8: the receipt side.
# ---------------------------------------------------------------------------


def check_receipt(vector: dict[str, Any], receipt: dict[str, Any]) -> None:
    print("\n-- 4. shipped Concordia verifier over the signed receipt --")
    offer = load("offer.json")
    now = datetime(2026, 8, 4, 10, 5, 0, tzinfo=timezone.utc)
    issuer = public_key_from_b64url(vector["public_keys_b64url"]["approver"])

    result = verify_approval_receipt(
        receipt, offer, now=now, issuer_public_key=issuer
    )
    check("receipt verifies (schema + signature + offer binding)", result.valid)
    check("receipt decision is approve", result.decision == "approve")

    print("\n-- 5. CONTEXT_SET_MISMATCH on a dropped artifact --")
    dropped = load("assembled_context_dropped_artifact.json")
    embedded = receipt["references"][0]["extensions"][
        "a2a_1734_decision_binding_preimage"
    ]["context_digest"]
    recomputed = sha256_jcs(dropped)
    check(
        "presented set recomputes to a different digest than the embedded one",
        recomputed != embedded,
        f"{recomputed} != {embedded}",
    )

    print("\n-- 6. the receipt SIGNS the binding: stale digest rejects --")
    # Substitute the dropped-artifact digest into the embedded preimage and
    # re-derive the ref, i.e. the most plausible forgery: a consistent-looking
    # binding over a smaller context set. Failure mode a reader should notice:
    # without the signature this substitution is internally consistent and a
    # digest-only check accepts it.
    swapped = copy.deepcopy(receipt)
    swapped_preimage = swapped["references"][0]["extensions"][
        "a2a_1734_decision_binding_preimage"
    ]
    swapped_preimage["context_digest"] = recomputed
    swapped["references"][0]["extensions"]["a2a_1734_decision_binding_ref"] = (
        sha256_jcs(swapped_preimage)
    )
    check(
        "the swap is internally consistent (a digest-only check would accept)",
        swapped["references"][0]["extensions"]["a2a_1734_decision_binding_ref"]
        == sha256_jcs(swapped_preimage),
    )
    swapped_result = verify_approval_receipt(
        swapped, offer, now=now, issuer_public_key=issuer
    )
    check(
        "swapped-context receipt REJECTS under the shipped verifier",
        not swapped_result.valid,
        str(swapped_result.failure_reason),
    )

    print("\n-- 7. one-byte tamper --")
    tampered = copy.deepcopy(receipt)
    tampered["approver"]["role"] = "governance_authorityX"
    tampered_result = verify_approval_receipt(
        tampered, offer, now=now, issuer_public_key=issuer
    )
    check("tampered receipt REJECTS", not tampered_result.valid)

    print("\n-- 8. published key and signature are derived, not asserted --")
    seed = vector["signing_seeds_PUBLIC_test_only_do_not_reuse"][
        "approver_ed25519_seed_ascii"
    ].encode()
    check("seed is exactly 32 bytes", len(seed) == 32)
    private = Ed25519PrivateKey.from_private_bytes(seed)
    derived = KeyPair(private_key=private, public_key=private.public_key())
    check(
        "public key re-derives from the recorded seed",
        derived.public_key_b64() == vector["public_keys_b64url"]["approver"],
    )
    signable = {k: v for k, v in receipt.items() if k != "signature"}
    import base64

    expected_sig = base64.urlsafe_b64encode(
        private.sign(canonical_json(signable))
    ).decode()
    check(
        "published signature re-derives from the recorded seed",
        expected_sig == receipt["signature"]["value"],
    )


def check_provenance(external_bytes: bytes) -> None:
    print("\n-- 0. retained third-party artifact provenance --")
    provenance = json.loads(PROVENANCE.read_text())
    entry = provenance["artifacts"][0]
    digest = hashlib.sha256(external_bytes).hexdigest()
    check(
        "retained giskard09 fixture matches its recorded sha256",
        digest == entry["retained_sha256"],
        digest,
    )


def main() -> int:
    external_bytes = EXTERNAL.read_bytes()
    external = json.loads(external_bytes)
    vector = load("vector.json")
    receipt = load("approval_receipt.json")

    check_provenance(external_bytes)
    check_external_vectors(external)
    check_spec_fixtures()
    check_own_digests(vector, receipt, external)
    check_receipt(vector, receipt)

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s)")
        for label in FAILURES:
            print(f"  - {label}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
