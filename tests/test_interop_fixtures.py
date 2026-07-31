"""Interop fixture conformance: A2A #1404 and #1920 worked vectors.

Runs the two published interop verify scripts in-process and asserts they
pass, so the fixtures under docs/interop/ are regression-protected by CI. Also
re-derives the load-bearing hashes with the INDEPENDENT rfc8785 reference
canonicalizer (not Concordia's own), so the published decision_id is proven to
be the RFC 8785 JCS standard hash, not a Concordia-specific artifact.

These fixtures are linked publicly from A2A Discussion #1404 and #1920; the
suite makes an accidental byte-drift a hard CI failure.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import rfc8785

REPO_ROOT = Path(__file__).resolve().parent.parent
INTEROP_1404 = REPO_ROOT / "docs" / "interop" / "a2a-1404-receipt-revocation-vector"
INTEROP_1920 = REPO_ROOT / "docs" / "interop" / "a2a-1920-fulfillment-sample"


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _json(path: Path) -> dict:
    return json.loads(path.read_text())


def test_1404_verify_script_passes() -> None:
    """The published #1404 verify.py returns exit code 0 (all checks PASS)."""
    verify = _load_module(INTEROP_1404 / "verify.py", "interop_1404_verify")
    assert verify.main() == 0


def test_1404_decision_id_matches_reference_jcs() -> None:
    """decision_id equals SHA-256 over the INDEPENDENT rfc8785 JCS bytes.

    Proves the published decision_id is the RFC 8785 standard hash, not a
    Concordia-specific one: a third party using any conformant JCS library
    recomputes the same value.
    """
    decision_object = _json(INTEROP_1404 / "decision_object.json")
    vector = _json(INTEROP_1404 / "vector.json")
    reference = "sha256:" + hashlib.sha256(rfc8785.dumps(decision_object)).hexdigest()
    assert reference == vector["hashes"]["decision_id"]


def test_1404_native_fields_equal_decision_object() -> None:
    """The two NATIVE receipt fields equal the decision object (honest map)."""
    receipt = _json(INTEROP_1404 / "approval_receipt.json")
    decision_object = _json(INTEROP_1404 / "decision_object.json")
    assert receipt["scope"]["decision"] == decision_object["decision"]
    assert receipt["scope"]["offer_hash"] == decision_object["request_digest"]


def test_1404_committed_deny_id_matches_reference_jcs() -> None:
    """The committed terminal deny's decision_id is the RFC 8785 STANDARD hash.

    Recomputed over the record preimage (all fields except decision_id and
    signature) with the INDEPENDENT rfc8785 reference library, so the deny
    cross-runs byte-for-byte with any conformant decision-log family.
    """
    from concordia.cmpc import CascadeDecisionRecord

    deny = CascadeDecisionRecord.from_dict(
        _json(INTEROP_1404 / "cascade_decision_deny.json")
    )
    vector = _json(INTEROP_1404 / "vector.json")
    reference = "sha256:" + hashlib.sha256(rfc8785.dumps(deny.preimage())).hexdigest()
    assert reference == vector["hashes"]["deny_decision_id"]
    assert reference == "sha256:" + deny.decision_id


def test_1404_committed_deny_commits_to_ancestor_read() -> None:
    """The deny binds the exact ancestor status read (rpelevin's control)."""
    deny = _json(INTEROP_1404 / "cascade_decision_deny.json")
    revocation = _json(INTEROP_1404 / "revocation_A.json")
    assert deny["decision"] == "deny"
    read = deny["ancestor_reads"][0]
    assert read["element_digest"] == revocation["revoked_artifact_id"]
    assert read["status"] == "revoked"
    assert deny["revocation_record_ref"] == revocation["revocation_id"]
    # Committed coordinate: a non-negative integer (the schema constrains shape
    # only; source authenticity is verifier-side policy, not proven here).
    assert isinstance(read["coordinate"], int) and not isinstance(
        read["coordinate"], bool
    )
    assert read["coordinate"] >= 0


def test_1404_committed_deny_carries_no_raw_terms() -> None:
    """The deny leaks no underlying deal terms (audit-privacy invariant)."""
    from concordia.schema_validator import _RAW_TERM_PATTERNS

    deny = _json(INTEROP_1404 / "cascade_decision_deny.json")

    def walk(obj: object) -> list[str]:
        out: list[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and k != "signature":
                    out.append(k)
                if k != "signature":
                    out.extend(walk(v))
        elif isinstance(obj, list):
            for v in obj:
                out.extend(walk(v))
        elif isinstance(obj, str):
            out.append(obj)
        return out

    for s in walk(deny):
        for pat in _RAW_TERM_PATTERNS:
            assert pat.search(s) is None, f"raw term leaked: {s!r}"


def test_1920_verify_script_passes() -> None:
    """The published #1920 verify.py returns exit code 0 (all checks PASS)."""
    verify = _load_module(INTEROP_1920 / "verify.py", "interop_1920_verify")
    assert verify.main() == 0


def test_1920_canonical_sha256_matches_reference_jcs() -> None:
    """The #1920 canonical_sha256 is the RFC 8785 STANDARD hash.

    Re-derived over the attestation minus its top-level ``signature`` with the
    INDEPENDENT rfc8785 reference library, so the digest the fixture publishes
    is proven reproducible by any conformant JCS implementation rather than
    being an artifact of Concordia's own canonicalizer. The #1404 vector has had
    this cross-check since it shipped; #1920 did not, which left the flagship
    second-implementation fixture's headline digest unguarded in CI.
    """
    att = _json(INTEROP_1920 / "fulfillment_attestation.json")
    sample = _json(INTEROP_1920 / "sample.json")
    signable = {k: v for k, v in att.items() if k != "signature"}
    reference = "sha256:" + hashlib.sha256(rfc8785.dumps(signable)).hexdigest()
    assert reference == sample["canonical_sha256"]


def test_1920_canonical_sha256_diverges_on_tamper() -> None:
    """The recorded digest is a live comparison, not a restatement.

    A one-byte change to the signed body must diverge the recomputed digest. A
    recompute that could not fail is the same defect as no recompute at all.
    """
    att = _json(INTEROP_1920 / "fulfillment_attestation.json")
    sample = _json(INTEROP_1920 / "sample.json")
    signable = {k: v for k, v in att.items() if k != "signature"}
    signable["charge_ref"] = signable["charge_ref"][:-1] + (
        "0" if signable["charge_ref"][-1] != "0" else "1"
    )
    tampered = "sha256:" + hashlib.sha256(rfc8785.dumps(signable)).hexdigest()
    assert tampered != sample["canonical_sha256"]


def test_1920_published_signature_and_key_are_derived_not_asserted() -> None:
    """sample.json's signature and public key are checkable, not just recorded.

    The signature string must equal the artifact's own signature member, and the
    public key must re-derive from the published test seed, so no field in
    sample.json is a value a reader has to take on trust.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    att = _json(INTEROP_1920 / "fulfillment_attestation.json")
    sample = _json(INTEROP_1920 / "sample.json")
    assert att["signature"]["value"] == sample["signature_b64url"]
    derived = base64.urlsafe_b64encode(
        Ed25519PrivateKey.from_private_bytes(sample["seed_ed25519_ascii"].encode())
        .public_key()
        .public_bytes_raw()
    ).decode()
    assert derived == sample["public_key_b64url"]


def test_1404_published_digests_all_recompute() -> None:
    """Every digest #1404's vector.json publishes re-derives from shipped bytes.

    capability_digest and receipt_offer_hash / request_digest were published but
    never recomputed-and-compared in the fixture's own verifier; only decision_id
    and deny_decision_id were. Same answer-key class, smaller blast radius.
    """
    from concordia.canonicalization import canonicalize_jcs

    vector = _json(INTEROP_1404 / "vector.json")
    capability = _json(INTEROP_1404 / "capability.json")
    offer = _json(INTEROP_1404 / "offer.json")
    receipt = _json(INTEROP_1404 / "approval_receipt.json")

    def digest(obj: dict) -> str:
        return "sha256:" + hashlib.sha256(canonicalize_jcs(obj)).hexdigest()

    assert digest(capability) == vector["hashes"]["capability_digest"]
    assert digest(offer) == vector["hashes"]["receipt_offer_hash"]
    assert digest(offer) == vector["hashes"]["request_digest"]
    assert digest(offer) == receipt["scope"]["offer_hash"]


def test_1920_privacy_invariant_no_raw_terms() -> None:
    """The #1920 sample carries no raw deal terms (SPEC 9.6.6)."""
    from concordia.schema_validator import _RAW_TERM_PATTERNS

    att = _json(INTEROP_1920 / "fulfillment_attestation.json")

    def walk(obj: object) -> list[str]:
        out: list[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and k != "signature":
                    out.append(k)
                if k != "signature":
                    out.extend(walk(v))
        elif isinstance(obj, list):
            for v in obj:
                out.extend(walk(v))
        elif isinstance(obj, str):
            out.append(obj)
        return out

    for s in walk(att):
        for pat in _RAW_TERM_PATTERNS:
            assert pat.search(s) is None, f"raw term leaked: {s!r}"
