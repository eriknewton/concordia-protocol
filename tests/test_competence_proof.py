"""Tests for ZK-style Competence Proofs.

Covers:
    - Competence proof creation from valid attestations
    - Merkle tree construction and proof generation
    - Merkle proof verification (valid, invalid, tampered)
    - Competence proof signature verification
    - Selective revelation of attestations
    - Full competence proof verification pipeline
    - Sybil screening integration
    - Freshness checks
    - Edge cases: empty attestations, single attestation, all attestations revealed
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from concordia.competence_proof import (
    CompetenceProof,
    CompetenceVerificationResult,
    build_merkle_tree,
    generate_merkle_proof,
    verify_merkle_proof,
    verify_competence_proof,
)
from concordia.signing import KeyPair, sign_message, canonical_json


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_KEY_REGISTRY: dict[str, KeyPair] = {}


def _get_key(agent_id: str) -> KeyPair:
    if agent_id not in _KEY_REGISTRY:
        _KEY_REGISTRY[agent_id] = KeyPair.generate()
    return _KEY_REGISTRY[agent_id]


def _test_resolver(agent_id: str) -> Ed25519PublicKey | None:
    kp = _KEY_REGISTRY.get(agent_id)
    return kp.public_key if kp else None


def _make_attestation(
    agent_a: str = "agent_a",
    agent_b: str = "agent_b",
    status: str = "agreed",
    rounds: int = 3,
    duration_seconds: int = 120,
    category: str = "electronics",
    concession_a: float = 0.2,
    concession_b: float = 0.15,
    offers_a: int = 2,
    offers_b: int = 3,
    reasoning_a: bool = True,
    reasoning_b: bool = False,
    fulfillment: dict | None = None,
    att_id: str | None = None,
    session_id: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Create a valid, signed attestation for testing."""
    att_id = att_id or f"att_{uuid.uuid4().hex[:12]}"
    session_id = session_id or f"sess_{uuid.uuid4().hex[:12]}"
    timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    party_a: dict[str, Any] = {
        "agent_id": agent_a,
        "role": "seller",
        "behavior": {
            "concession_magnitude": concession_a,
            "offers_made": offers_a,
            "reasoning_provided": reasoning_a,
            "responsiveness_seconds": 5.0,
        },
    }
    party_a["signature"] = sign_message(party_a, _get_key(agent_a))

    party_b: dict[str, Any] = {
        "agent_id": agent_b,
        "role": "buyer",
        "behavior": {
            "concession_magnitude": concession_b,
            "offers_made": offers_b,
            "reasoning_provided": reasoning_b,
            "responsiveness_seconds": 8.0,
        },
    }
    party_b["signature"] = sign_message(party_b, _get_key(agent_b))

    att: dict[str, Any] = {
        "concordia_attestation": "0.1.0",
        "attestation_id": att_id,
        "session_id": session_id,
        "timestamp": timestamp,
        "outcome": {
            "status": status,
            "rounds": rounds,
            "duration_seconds": duration_seconds,
        },
        "parties": [party_a, party_b],
        "meta": {"category": category, "extensions_used": [], "mediator_invoked": False},
        "transcript_hash": f"sha256:{uuid.uuid4().hex}",
        "fulfillment": fulfillment,
    }
    return att


# ---------------------------------------------------------------------------
# Merkle tree tests
# ---------------------------------------------------------------------------


class TestMerkleTree:
    """Tests for Merkle tree construction and proof generation."""

    def test_build_merkle_tree_empty(self):
        """Empty list produces empty tree."""
        root, layers = build_merkle_tree([])
        assert root == ""
        assert layers == []

    def test_build_merkle_tree_single(self):
        """Single ID produces a tree with one leaf and one root."""
        ids = ["id_1"]
        root, layers = build_merkle_tree(ids)
        import hashlib

        expected = hashlib.sha256("id_1".encode()).hexdigest()
        assert root == expected
        assert len(layers) == 1
        assert layers[0] == [expected]

    def test_build_merkle_tree_multiple(self):
        """Multiple IDs produce proper tree structure."""
        ids = ["id_a", "id_b", "id_c"]
        root, layers = build_merkle_tree(ids)

        assert root != ""
        assert len(layers) >= 2  # At least leaves and root
        assert len(layers[0]) == 3  # Three leaves (sorted)

    def test_build_merkle_tree_deterministic(self):
        """Same IDs in different order produce same tree."""
        ids1 = ["c", "a", "b"]
        ids2 = ["b", "c", "a"]

        root1, _ = build_merkle_tree(ids1)
        root2, _ = build_merkle_tree(ids2)

        assert root1 == root2

    def test_generate_merkle_proof(self):
        """Generate a valid Merkle proof for a specific ID."""
        ids = ["id_1", "id_2", "id_3", "id_4"]
        root, layers = build_merkle_tree(ids)

        proof = generate_merkle_proof("id_2", sorted(ids), layers)

        assert proof["attestation_id"] == "id_2"
        assert proof["index"] == sorted(ids).index("id_2")
        assert len(proof["proof"]) > 0

    def test_generate_merkle_proof_not_in_list(self):
        """Cannot generate proof for ID not in the list."""
        ids = ["id_1", "id_2", "id_3"]
        root, layers = build_merkle_tree(ids)

        with pytest.raises(ValueError, match="not found"):
            generate_merkle_proof("id_999", sorted(ids), layers)

    def test_verify_merkle_proof_valid(self):
        """A valid Merkle proof verifies successfully."""
        ids = ["id_a", "id_b", "id_c", "id_d"]
        root, layers = build_merkle_tree(ids)

        proof = generate_merkle_proof("id_b", sorted(ids), layers)
        assert verify_merkle_proof("id_b", proof, root) is True

    def test_verify_merkle_proof_all_ids(self):
        """All IDs in the tree verify successfully."""
        ids = ["z", "y", "x", "w", "v"]
        root, layers = build_merkle_tree(ids)

        for att_id in ids:
            proof = generate_merkle_proof(att_id, sorted(ids), layers)
            assert verify_merkle_proof(att_id, proof, root) is True

    def test_verify_merkle_proof_tampered_id(self):
        """Proof for one ID fails when verified against a different ID."""
        ids = ["id_1", "id_2", "id_3"]
        root, layers = build_merkle_tree(ids)

        proof = generate_merkle_proof("id_1", sorted(ids), layers)
        # Try to verify with a different ID
        assert verify_merkle_proof("id_999", proof, root) is False

    def test_verify_merkle_proof_tampered_root(self):
        """Proof fails when verified against a wrong root."""
        ids = ["a", "b", "c"]
        root, layers = build_merkle_tree(ids)

        proof = generate_merkle_proof("a", sorted(ids), layers)
        fake_root = "0" * 64
        assert verify_merkle_proof("a", proof, fake_root) is False

    def test_verify_merkle_proof_tampered_proof(self):
        """Proof fails when hash in proof is tampered."""
        ids = ["x", "y", "z"]
        root, layers = build_merkle_tree(ids)

        proof = generate_merkle_proof("x", sorted(ids), layers)
        # Tamper with a hash in the proof
        if proof["proof"]:
            proof["proof"][0] = "0" * 64

        assert verify_merkle_proof("x", proof, root) is False


# ---------------------------------------------------------------------------
# Competence proof creation tests
# ---------------------------------------------------------------------------


class TestCompetenceProofCreation:
    """Tests for competence proof creation and serialization."""

    def test_create_basic(self):
        """Create a proof from valid attestations."""
        atts = [_make_attestation() for _ in range(3)]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp)

        assert proof.proof_id.startswith("proof_")
        assert proof.agent_id == "agent_a"
        assert proof.attestation_count == 3
        assert proof.claims["total_negotiations"] == 3
        assert proof.agent_signature != ""
        assert proof.attestation_merkle_root != ""

    def test_create_single_attestation(self):
        """A single-attestation proof is valid."""
        att = _make_attestation()
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", [att], kp)

        assert proof.attestation_count == 1
        assert proof.claims["total_negotiations"] == 1

    def test_create_empty_attestations(self):
        """Creating a proof with empty attestations."""
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", [], kp)

        assert proof.attestation_count == 0
        assert proof.claims["total_negotiations"] == 0
        assert proof.attestation_merkle_root == ""

    def test_create_rejects_non_party(self):
        """Cannot create proof if agent is not a party in an attestation."""
        att = _make_attestation(agent_a="agent_x", agent_b="agent_y")
        kp = _get_key("agent_z")

        with pytest.raises(ValueError, match="not a party"):
            CompetenceProof.create("agent_z", [att], kp)

    def test_create_with_reveal_ids(self):
        """Create a proof revealing specific attestations."""
        atts = [_make_attestation() for _ in range(3)]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _get_key("agent_a")

        proof = CompetenceProof.create(
            "agent_a", atts, kp, reveal_ids=[att_ids[0], att_ids[2]]
        )

        assert len(proof.merkle_proofs) == 2
        assert len(proof.revealed_attestations) == 2

    def test_create_reveal_nonexistent_id(self):
        """Cannot reveal an attestation ID that doesn't exist."""
        atts = [_make_attestation() for _ in range(2)]
        kp = _get_key("agent_a")

        with pytest.raises(ValueError, match="not found"):
            CompetenceProof.create("agent_a", atts, kp, reveal_ids=["fake_id"])

    def test_create_aggregates_stats(self):
        """Proof aggregates BundleSummary statistics correctly."""
        atts = [
            _make_attestation(concession_a=0.1),
            _make_attestation(concession_a=0.3),
            _make_attestation(concession_a=0.2),
        ]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp)

        claims = proof.claims
        assert claims["total_negotiations"] == 3
        assert claims["agreements"] == 3  # All are "agreed" by default
        assert claims["agreement_rate"] == 1.0


# ---------------------------------------------------------------------------
# Competence proof signature tests
# ---------------------------------------------------------------------------


class TestCompetenceProofSignature:
    """Tests for signature verification."""

    def test_signature_valid(self):
        """A validly signed proof verifies."""
        atts = [_make_attestation() for _ in range(2)]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp)

        proof_dict = proof.to_dict()
        result = verify_competence_proof(proof_dict, _test_resolver)

        assert result.valid is True
        assert len(result.errors) == 0

    def test_signature_invalid_key(self):
        """Proof fails if signed with wrong key."""
        atts = [_make_attestation() for _ in range(2)]
        kp_a = _get_key("agent_a")
        kp_wrong = _get_key("agent_wrong")

        # Create with agent_a but sign with wrong key
        proof = CompetenceProof.create("agent_a", atts, kp_a)
        proof_dict = proof.to_dict()

        # Overwrite signature with one from wrong key
        signable = proof.to_dict_for_signing()
        proof_dict["agent_signature"] = sign_message(signable, kp_wrong)

        result = verify_competence_proof(proof_dict, _test_resolver)
        assert result.valid is False
        assert any("signature" in e.lower() for e in result.errors)

    def test_signature_tampered_claims(self):
        """Proof fails if claims are tampered after signing."""
        atts = [_make_attestation() for _ in range(2)]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp)

        proof_dict = proof.to_dict()
        # Tamper with claims
        proof_dict["claims"]["total_negotiations"] = 999

        result = verify_competence_proof(proof_dict, _test_resolver)
        assert result.valid is False

    def test_signature_missing_key(self):
        """Proof fails if agent key cannot be resolved."""
        atts = [_make_attestation() for _ in range(1)]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp)

        # Use a resolver that doesn't have the key
        def no_key_resolver(agent_id: str) -> Ed25519PublicKey | None:
            return None

        proof_dict = proof.to_dict()
        result = verify_competence_proof(proof_dict, no_key_resolver)
        assert result.valid is False


# ---------------------------------------------------------------------------
# Selective reveal tests
# ---------------------------------------------------------------------------


class TestSelectiveReveal:
    """Tests for selective attestation revelation."""

    def test_reveal_zero(self):
        """A proof with no revealed attestations."""
        atts = [_make_attestation() for _ in range(3)]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp, reveal_ids=[])

        assert len(proof.merkle_proofs) == 0
        assert len(proof.revealed_attestations) == 0

    def test_reveal_some(self):
        """A proof revealing a subset of attestations."""
        atts = [_make_attestation() for _ in range(5)]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _get_key("agent_a")

        reveal_subset = att_ids[1:3]
        proof = CompetenceProof.create("agent_a", atts, kp, reveal_ids=reveal_subset)

        assert len(proof.merkle_proofs) == 2
        assert len(proof.revealed_attestations) == 2

    def test_reveal_all(self):
        """A proof revealing all attestations."""
        atts = [_make_attestation() for _ in range(3)]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _get_key("agent_a")

        proof = CompetenceProof.create("agent_a", atts, kp, reveal_ids=att_ids)

        assert len(proof.merkle_proofs) == 3
        assert len(proof.revealed_attestations) == 3

    def test_reveal_merkle_proofs_valid(self):
        """Merkle proofs in revealed attestations verify against root."""
        atts = [_make_attestation() for _ in range(4)]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _get_key("agent_a")

        proof = CompetenceProof.create("agent_a", atts, kp, reveal_ids=att_ids[::2])

        for mp in proof.merkle_proofs:
            assert verify_merkle_proof(
                mp["attestation_id"], mp, proof.attestation_merkle_root
            ) is True


# ---------------------------------------------------------------------------
# Full verification tests
# ---------------------------------------------------------------------------


class TestCompetenceVerification:
    """Tests for complete proof verification pipeline."""

    def test_verify_valid_proof(self):
        """A valid proof verifies completely."""
        atts = [_make_attestation() for _ in range(3)]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp)

        proof_dict = proof.to_dict()
        result = verify_competence_proof(proof_dict, _test_resolver)

        assert result.valid is True
        assert len(result.errors) == 0

    def test_verify_with_revealed_attestations(self):
        """Verification succeeds with revealed attestations."""
        atts = [_make_attestation() for _ in range(4)]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _get_key("agent_a")

        proof = CompetenceProof.create("agent_a", atts, kp, reveal_ids=att_ids[1:3])
        proof_dict = proof.to_dict()

        result = verify_competence_proof(proof_dict, _test_resolver)
        assert result.valid is True
        assert result.merkle_proofs_valid is True

    def test_verify_attestation_count_mismatch(self):
        """Verification fails if attestation count mismatches claims."""
        atts = [_make_attestation() for _ in range(2)]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp)

        proof_dict = proof.to_dict()
        # Tamper: claim different count
        proof_dict["attestation_count"] = 999

        result = verify_competence_proof(proof_dict, _test_resolver)
        assert result.valid is False
        assert any("mismatch" in e.lower() for e in result.errors)

    def test_verify_merkle_proof_validation(self):
        """Verification detects invalid Merkle proofs."""
        atts = [_make_attestation() for _ in range(3)]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _get_key("agent_a")

        proof = CompetenceProof.create("agent_a", atts, kp, reveal_ids=[att_ids[0]])
        proof_dict = proof.to_dict()

        # Tamper with Merkle proof
        if proof_dict["merkle_proofs"]:
            proof_dict["merkle_proofs"][0]["proof"][0] = "0" * 64

        result = verify_competence_proof(proof_dict, _test_resolver)
        assert result.merkle_proofs_valid is False

    def test_verify_missing_fields(self):
        """Verification fails if required fields are missing."""
        atts = [_make_attestation()]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp)

        proof_dict = proof.to_dict()
        del proof_dict["proof_id"]

        result = verify_competence_proof(proof_dict, _test_resolver)
        assert result.valid is False
        assert any("proof_id" in e for e in result.errors)

    def test_verify_empty_proof(self):
        """Verification succeeds on empty proof (no attestations)."""
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", [], kp)

        proof_dict = proof.to_dict()
        result = verify_competence_proof(proof_dict, _test_resolver)

        assert result.valid is True


# ---------------------------------------------------------------------------
# Serialization tests
# ---------------------------------------------------------------------------


class TestSerialization:
    """Tests for proof serialization and deserialization."""

    def test_roundtrip_dict(self):
        """Proof survives dict roundtrip."""
        atts = [_make_attestation() for _ in range(2)]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp)

        proof_dict = proof.to_dict()
        proof2 = CompetenceProof.from_dict(proof_dict)

        assert proof2.proof_id == proof.proof_id
        assert proof2.agent_id == proof.agent_id
        assert proof2.attestation_count == proof.attestation_count

    def test_roundtrip_json(self):
        """Proof survives JSON roundtrip."""
        atts = [_make_attestation() for _ in range(2)]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp)

        json_str = proof.to_json()
        proof_dict = json.loads(json_str)
        proof2 = CompetenceProof.from_dict(proof_dict)

        assert proof2.proof_id == proof.proof_id
        assert proof2.agent_signature == proof.agent_signature

    def test_roundtrip_with_reveals(self):
        """Proof with revealed attestations survives roundtrip."""
        atts = [_make_attestation() for _ in range(3)]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _get_key("agent_a")

        proof = CompetenceProof.create("agent_a", atts, kp, reveal_ids=[att_ids[0]])
        proof_dict = proof.to_dict()
        proof2 = CompetenceProof.from_dict(proof_dict)

        assert len(proof2.merkle_proofs) == len(proof.merkle_proofs)
        assert len(proof2.revealed_attestations) == len(proof.revealed_attestations)


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_large_attestation_set(self):
        """Proof handles large numbers of attestations."""
        atts = [_make_attestation() for _ in range(100)]
        kp = _get_key("agent_a")

        proof = CompetenceProof.create("agent_a", atts, kp)
        assert proof.attestation_count == 100

    def test_duplicate_attestation_ids(self):
        """Merkle tree handles unique IDs correctly."""
        att1 = _make_attestation(att_id="att_001")
        att2 = _make_attestation(att_id="att_002")
        kp = _get_key("agent_a")

        proof = CompetenceProof.create("agent_a", [att1, att2], kp)
        assert proof.attestation_count == 2

    def test_claim_computation(self):
        """Claims accurately reflect attestation data."""
        # Mix of agreed and rejected
        atts = [
            _make_attestation(status="agreed"),
            _make_attestation(status="rejected"),
            _make_attestation(status="agreed"),
        ]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp)

        claims = proof.claims
        assert claims["total_negotiations"] == 3
        assert claims["agreements"] == 2
        assert round(claims["agreement_rate"], 4) == round(2.0 / 3.0, 4)


# ---------------------------------------------------------------------------
# C-H1: aggregate honesty - recompute-or-honestly-label
# ---------------------------------------------------------------------------


class TestAggregateHonesty:
    """The aggregate claims are ALWAYS prover-asserted, never independently
    verified (Path A honest downgrade, C-H1 refutation 2026-06-17).

    The verifier MUST report ``aggregate_verified=False`` and
    ``claims_asserted_not_verified=True`` under all conditions, including a full
    reveal. It keeps the SOUND checks (signature, Merkle membership, revealed
    party signatures) and rejects a full reveal whose signed claims are
    self-inconsistent with its own revealed set, but a consistent full reveal
    still does NOT promote the aggregate to verified.
    """

    def test_full_reveal_honest_claims_not_promoted_to_verified(self):
        """A full-reveal proof over LEGACY 0.1.0 attestations with honest,
        self-consistent claims is valid and passes the sound checks, but the
        aggregate stays prover-asserted: legacy outcomes are not
        cryptographically bound, so the C-H2 P4 gate's cond_a fails. (Sound
        aggregate verification requires >=0.2.0 countersigned reveals — see
        TestSoundAggregateVerification.test_honest_full_reveal_verifies_aggregate
        for the positive case.)"""
        atts = [
            _make_attestation(status="agreed"),
            _make_attestation(status="rejected"),
            _make_attestation(status="agreed"),
        ]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp, reveal_ids=att_ids)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        assert result.valid is True
        # Legacy reveals are unbound, so the aggregate is never verified here.
        assert result.aggregate_verified is False
        assert result.claims_asserted_not_verified is True
        assert result.merkle_proofs_valid is True
        # A clean full reveal of LEGACY attestations carries the honest
        # not-verified note (no silent crediting of unbound outcomes).
        assert any(
            "internally consistent" in w and "NOT verified" in w
            for w in result.warnings
        ), result.warnings
        # All three legacy reveals are surfaced as outcome-unbound.
        assert sorted(result.revealed_outcome_unbound) == sorted(att_ids)
        assert proof.claims["agreements"] == 2

    def test_full_reveal_self_inconsistent_claims_fails(self):
        """A full-reveal proof whose signed claims contradict its OWN revealed
        set is rejected as self-inconsistent (honesty about the prover's own
        arithmetic, not aggregate verification)."""
        atts = [_make_attestation(status="rejected") for _ in range(3)]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp, reveal_ids=att_ids)

        # Tamper the aggregate to brag about agreements that did not happen, then
        # re-sign so the signature check still passes; only the self-consistency
        # check can catch this.
        proof.claims["agreements"] = 3
        proof.claims["agreement_rate"] = 1.0
        proof.agent_signature = sign_message(proof.to_dict_for_signing(), kp)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        assert result.valid is False
        assert result.aggregate_verified is False
        assert any("self-inconsistent" in e.lower() for e in result.errors)

    def test_zero_reveal_inflated_claims_not_reported_verified(self):
        """A proof that reveals NOTHING but signs a wildly inflated aggregate over
        a Merkle root of zero real attestations must NOT report the aggregate as
        verified. ``valid`` may be True (signature + trivial membership hold), but
        a caller reading the result must see that the 10000 negotiations are
        unconfirmed."""
        kp = _get_key("agent_liar")
        # Build a legitimately-signed but empty proof, then inflate the claims and
        # the committed count and re-sign; no attestations are revealed.
        proof = CompetenceProof.create("agent_liar", [], kp)
        proof.claims["total_negotiations"] = 10000
        proof.claims["agreements"] = 10000
        proof.claims["agreement_rate"] = 1.0
        proof.attestation_count = 10000
        # Give it a non-empty root so it does not read as a trivially-empty proof.
        proof.attestation_merkle_root = "f" * 64
        proof.agent_signature = sign_message(proof.to_dict_for_signing(), kp)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)

        # The aggregate is the whole point of C-H1: it must NOT be verified.
        assert result.aggregate_verified is False
        assert result.claims_asserted_not_verified is True

    def test_partial_reveal_does_not_verify_aggregate(self):
        """Revealing a subset is not enough to confirm the aggregate."""
        atts = [_make_attestation() for _ in range(4)]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp, reveal_ids=att_ids[:2])

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        assert result.valid is True
        assert result.aggregate_verified is False
        assert result.claims_asserted_not_verified is True

    def test_full_reveal_with_skip_deep_check_does_not_verify_aggregate(self):
        """With check_revealed_attestations=False the aggregate is never recomputed."""
        atts = [_make_attestation() for _ in range(3)]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp, reveal_ids=att_ids)

        result = verify_competence_proof(
            proof.to_dict(), _test_resolver, check_revealed_attestations=False
        )
        assert result.aggregate_verified is False
        assert result.claims_asserted_not_verified is True

    def test_duplicate_reveal_cannot_fake_full_reveal(self):
        """Revealing the same attestation att_count times must NOT count as a full
        reveal (defends the recompute path against a double-count forgery)."""
        att = _make_attestation(status="agreed")
        kp = _get_key("agent_a")
        # One real attestation, but claim a committed count of 3.
        proof = CompetenceProof.create("agent_a", [att], kp, reveal_ids=[att["attestation_id"]])
        # Forge: pretend the set has 3 members and reveal the same one 3 times.
        proof.attestation_count = 3
        proof.claims["total_negotiations"] = 3
        proof.claims["agreements"] = 3
        proof.revealed_attestations = [att, att, att]
        proof.merkle_proofs = proof.merkle_proofs * 3
        proof.agent_signature = sign_message(proof.to_dict_for_signing(), kp)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        # Distinct-membership count is 1, not 3, so the aggregate is not verified.
        assert result.aggregate_verified is False
        assert result.claims_asserted_not_verified is True

    def test_unverified_party_surfaced_on_revealed_attestation(self):
        """A full reveal naming a counterparty whose key cannot be resolved must
        surface the party in unverified_parties. Independently, the aggregate is
        never reported as verified (Path A)."""
        # agent_a is known; the counterparty 'ghost_cp' has no key in the registry.
        att = _make_attestation(agent_a="agent_a", agent_b="ghost_cp")
        kp = _get_key("agent_a")
        proof = CompetenceProof.create(
            "agent_a", [att], kp, reveal_ids=[att["attestation_id"]]
        )

        def resolver_without_ghost(agent_id: str) -> Ed25519PublicKey | None:
            if agent_id == "ghost_cp":
                return None
            return _test_resolver(agent_id)

        result = verify_competence_proof(proof.to_dict(), resolver_without_ghost)
        # The party is surfaced...
        assert "ghost_cp" in result.unverified_parties
        # ...and the aggregate is NEVER verified (Path A removed that path).
        assert result.aggregate_verified is False
        assert result.claims_asserted_not_verified is True

    def test_full_reveal_all_parties_resolvable_still_not_verified(self):
        """Positive case: even a full reveal whose counterparties are ALL
        resolvable does NOT promote the aggregate to verified. The sound checks
        pass and the internal-consistency note is present, but
        aggregate_verified stays False (Path A)."""
        # Both agent_a and agent_b are in the registry / resolvable.
        atts = [_make_attestation(agent_a="agent_a", agent_b="agent_b") for _ in range(3)]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _get_key("agent_a")
        proof = CompetenceProof.create("agent_a", atts, kp, reveal_ids=att_ids)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        assert result.valid is True
        assert result.aggregate_verified is False
        assert result.claims_asserted_not_verified is True
        assert result.unverified_parties == []
        assert result.prover_nonmember_attestations == []
        # Internal-consistency note present; no "verified" language.
        assert any("internally consistent" in w for w in result.warnings), result.warnings

    def test_full_reveal_over_non_party_attestations_not_verified(self):
        """ATTACK (Codex claim 1): a prover full-reveals over attestations it is
        NOT a party in, trying to claim another agent's track record as its own.
        The verifier must NOT report the aggregate as verified, must flag the
        non-member attestations, and the headline numbers stay prover-asserted.

        Against the OLD code this returned aggregate_verified=True (the bug).
        """
        # victim_x and victim_y negotiated; 'thief' was never a party.
        atts = [
            _make_attestation(agent_a="victim_x", agent_b="victim_y", status="agreed")
            for _ in range(3)
        ]
        att_ids = [att["attestation_id"] for att in atts]

        # The thief hand-builds a proof over the victims' valid attestations
        # (CompetenceProof.create() would reject this, but a verifier receives an
        # arbitrary proof_dict, not necessarily one built via create()).
        import concordia.competence_proof as cp
        from concordia.receipt_bundle import _compute_summary

        root, layers = cp.build_merkle_tree(att_ids)
        sorted_ids = sorted(att_ids)
        mproofs = [cp.generate_merkle_proof(i, sorted_ids, layers) for i in att_ids]
        thief_kp = _get_key("thief")
        summary = _compute_summary("thief", atts).to_dict()
        proof = CompetenceProof(
            proof_id=f"proof_{uuid.uuid4().hex[:12]}",
            agent_id="thief",
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            claims=summary,
            attestation_merkle_root=root,
            attestation_count=len(att_ids),
            merkle_proofs=mproofs,
            revealed_attestations=atts,
        )
        proof.agent_signature = sign_message(proof.to_dict_for_signing(), thief_kp)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        # The aggregate must NOT be reported as verified.
        assert result.aggregate_verified is False
        assert result.claims_asserted_not_verified is True
        # Defense-in-depth: every revealed attestation is flagged as prover-non-member.
        assert sorted(result.prover_nonmember_attestations) == sorted(att_ids)
        assert any("do not list the prover" in w for w in result.warnings), result.warnings

    def test_full_reveal_tampered_outcome_status_not_verified(self):
        """ATTACK (Codex claim 2): the attestation party signatures cover only
        each party_record, NOT the top-level outcome.status that _compute_summary
        reads. A prover rewrites outcome.status from 'rejected' to 'agreed',
        leaves every party_record (and its signature) intact, and signs a forged
        aggregate. The verifier must NOT report the aggregate as verified.

        Against the OLD code this returned aggregate_verified=True over forged
        outcomes with no error (the bug).
        """
        # Real outcomes were ALL rejected.
        atts = [
            _make_attestation(agent_a="agent_a", agent_b="agent_b", status="rejected")
            for _ in range(3)
        ]
        att_ids = [att["attestation_id"] for att in atts]
        # Attacker rewrites the top-level outcome.status; party signatures untouched.
        for att in atts:
            att["outcome"]["status"] = "agreed"

        import concordia.competence_proof as cp
        from concordia.receipt_bundle import _compute_summary

        root, layers = cp.build_merkle_tree(att_ids)
        sorted_ids = sorted(att_ids)
        mproofs = [cp.generate_merkle_proof(i, sorted_ids, layers) for i in att_ids]
        kp = _get_key("agent_a")
        # _compute_summary reads the forged outcome.status -> claims 3/3 agreed.
        summary = _compute_summary("agent_a", atts).to_dict()
        assert summary["agreements"] == 3  # the forged claim
        proof = CompetenceProof(
            proof_id=f"proof_{uuid.uuid4().hex[:12]}",
            agent_id="agent_a",
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            claims=summary,
            attestation_merkle_root=root,
            attestation_count=len(att_ids),
            merkle_proofs=mproofs,
            revealed_attestations=atts,
        )
        proof.agent_signature = sign_message(proof.to_dict_for_signing(), kp)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        # The party signatures still verify (status is not bound), so 'valid' may
        # be True, but the forged aggregate must NEVER read as verified.
        assert result.aggregate_verified is False
        assert result.claims_asserted_not_verified is True

    def test_mcp_message_never_confirms_aggregate(self, monkeypatch):
        """When the aggregate gate does NOT hold, the MCP verify tool must report
        aggregate_verified=False and claims_asserted_not_verified=True, and the
        message must label the aggregate as prover-asserted (the honest downgrade)
        without claiming verification. Here the sound checks pass but the gate
        does not, so the message must stay prover-asserted."""
        from concordia import mcp_server

        # Drive the message branch via a controlled result: sound checks pass,
        # aggregate stays prover-asserted, prover IS a party (no non-member flag).
        fake = CompetenceVerificationResult(
            valid=True,
            errors=[],
            warnings=["Full reveal: signed claims are internally consistent ..."],
            merkle_proofs_valid=True,
            aggregate_verified=False,
            claims_asserted_not_verified=True,
            unverified_parties=[],
            prover_nonmember_attestations=[],
        )
        monkeypatch.setattr(mcp_server, "verify_competence_proof", lambda *a, **k: fake)

        out = json.loads(
            mcp_server.tool_verify_competence_proof({"proof_id": "p", "agent_id": "agent_a"})
        )
        assert out["valid"] is True
        assert out["aggregate_verified"] is False
        assert out["claims_asserted_not_verified"] is True
        msg = out["message"]
        # Never the old confirm strings.
        assert "confirmed by full reveal" not in msg
        # Must NOT claim the aggregate is verified in the downgrade message.
        assert "VERIFIED for the revealed set" not in msg
        # Honest contract surfaced.
        assert "PROVER-ASSERTED" in msg
        assert "not" in msg and "independently verified" in msg

    def test_mcp_message_flags_prover_nonmember_attestations(self, monkeypatch):
        """When the prover reveals attestations it is not a party in, the MCP
        message must warn that the prover cannot claim that history and that
        reputation must not credit it (Path A defense-in-depth)."""
        from concordia import mcp_server

        # Drive the message branch via a controlled result with non-member flags.
        fake = CompetenceVerificationResult(
            valid=True,
            errors=[],
            warnings=["... do not list the prover ..."],
            merkle_proofs_valid=True,
            aggregate_verified=False,
            claims_asserted_not_verified=True,
            unverified_parties=[],
            prover_nonmember_attestations=["att_stolen1", "att_stolen2"],
        )
        monkeypatch.setattr(mcp_server, "verify_competence_proof", lambda *a, **k: fake)

        out = json.loads(mcp_server.tool_verify_competence_proof({"proof_id": "p", "agent_id": "thief"}))
        assert out["aggregate_verified"] is False
        assert out["prover_nonmember_attestations"] == ["att_stolen1", "att_stolen2"]
        msg = out["message"]
        assert "do NOT list the prover as a party" in msg
        assert "MUST NOT credit" in msg


# ---------------------------------------------------------------------------
# C-H2 Phase 4: SOUND aggregate_verified re-enablement (closes #120).
#
# Phase 1-3 (#123) bound the attestation OUTCOME to the issuance snapshot via a
# party countersignature, and gave the verifier a fail-closed countersignature
# check. Phase 4 is verifier-side ONLY: it re-enables aggregate_verified=True,
# but ONLY under an exact 4-condition gate:
#
#   (a) every committed attestation is revealed AND each is >=0.2.0 with a valid
#       party-member countersignature (outcome-bound),
#   (b) the prover is a signed party in EVERY revealed attestation,
#   (c) all merkle proofs are valid,
#   (d) the full-reveal recompute over those countersigned outcomes equals the
#       signed claims.
#
# Knock out any single condition and the verifier MUST honestly downgrade to
# aggregate_verified=False / claims_asserted_not_verified=True (or, for the
# membership case, a hard valid=False). Test 1 proves the all-true path (the
# gate is NOT vacuously always-False); tests 2-5 each remove one condition.
#
# The legacy ``_make_attestation`` helper produces ONLY 0.1.0 (no
# countersignature) -> the mixed-version / unbound lane. The bound lane needs
# real >=0.2.0 countersigned attestations, minted via concordia.Agent +
# generate_attestation (the same pattern as test_receipt_bundle.py).
# ---------------------------------------------------------------------------

from concordia import Agent, generate_attestation  # noqa: E402
from concordia import BasicOffer as _BasicOffer  # noqa: E402
from concordia.attestation import countersign_attestation  # noqa: E402


def _mint_bound_attestation(
    seller_id: str,
    buyer_id: str,
    *,
    status: str = "agreed",
    category: str = "electronics.cameras",
) -> dict[str, Any]:
    """Mint a real, countersigned (>=0.2.0) attestation over a real session and
    register both parties' keys in THIS file's resolver registry so
    ``_test_resolver`` resolves both parties. Returns the attestation dict.

    Mirrors ``tests/test_receipt_bundle.py::_mint_bound_attestation`` (inline
    copy is the minimal, isolated choice — no shared-helper coupling). Reuses an
    already-registered keypair for either party so a prover that appears across
    SEVERAL minted attestations keeps ONE stable identity key (otherwise each
    call would mint a fresh Agent key and orphan earlier signatures)."""
    seller = Agent(seller_id, key_pair=_get_key(seller_id))
    buyer = Agent(buyer_id, key_pair=_get_key(buyer_id))
    # Keys are already registered in _KEY_REGISTRY via _get_key above.

    terms = {"price": {"value": 150.00, "currency": "USD"}}
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    buyer.accept_session()
    seller.send_offer(
        _BasicOffer(terms={"price": {"value": 135.00, "currency": "USD"}}),
        reasoning="Fair price",
    )
    if status == "agreed":
        buyer.accept_offer(reasoning="ok")
    else:
        # ACTIVE -> REJECTED is reject_offer (decline_session is PROPOSED-only).
        buyer.reject_offer(reasoning="no thanks")

    key_pairs = {seller_id: seller.key_pair, buyer_id: buyer.key_pair}
    att = generate_attestation(session, key_pairs, category=category)
    assert att["concordia_attestation"] == "0.3.0"
    assert isinstance(att.get("countersignatures"), dict) and att["countersignatures"]
    return att


class TestSoundAggregateVerification:
    """C-H2 P4: aggregate_verified can be True, but ONLY under the 4-condition
    gate. One test per condition (plus the all-true positive)."""

    def test_honest_full_reveal_verifies_aggregate(self):
        """THE re-enablement: prover is a party in every attestation; all minted
        >=0.2.0 and countersigned; full reveal; recompute matches signed claims.
        This is the FIRST time aggregate_verified is ever True — it proves the
        gate is not vacuously always-False.

        (Against the pre-P4 verifier this asserted False; the build is a FAILURE
        if it stays False here.)"""
        prover = "sound_prover_1"
        atts = [
            _mint_bound_attestation(prover, f"cp_sound_{i}", status="agreed")
            for i in range(3)
        ]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _KEY_REGISTRY[prover]
        proof = CompetenceProof.create(prover, atts, kp, reveal_ids=att_ids)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        assert result.valid is True, result.errors
        assert result.aggregate_verified is True, (
            f"the 4 conditions all hold; aggregate must verify. errors={result.errors} "
            f"warnings={result.warnings}"
        )
        assert result.claims_asserted_not_verified is False
        assert result.merkle_proofs_valid is True
        assert result.prover_nonmember_attestations == []

    def test_outcome_tamper_keeps_aggregate_false(self):
        """Condition (a) knocked out: rewrite one revealed attestation's
        outcome.status AFTER proof creation (leaving parties[*].signature
        intact), re-sign only the proof envelope. The countersignature over the
        issuance snapshot no longer matches -> fail-closed -> aggregate stays
        False. Proves #123 binding fires through the COMPETENCE verifier."""
        prover = "sound_prover_2"
        atts = [
            _mint_bound_attestation(prover, f"cp_tamper_{i}", status="agreed")
            for i in range(3)
        ]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _KEY_REGISTRY[prover]
        proof = CompetenceProof.create(prover, atts, kp, reveal_ids=att_ids)

        # Forge: flip one revealed outcome.status; party signatures untouched.
        pd = proof.to_dict()
        tampered = pd["revealed_attestations"][0]
        tampered["outcome"]["status"] = (
            "rejected" if tampered["outcome"]["status"] == "agreed" else "agreed"
        )
        # Re-sign the proof envelope so the proof-level signature is NOT the
        # thing that fails (isolating the attestation countersignature). Match
        # verify's signable shape: strip agent_signature + version.
        signable = {
            k: v
            for k, v in pd.items()
            if k not in ("agent_signature", "concordia_competence_proof")
        }
        pd["agent_signature"] = sign_message(signable, kp)

        result = verify_competence_proof(pd, _test_resolver)
        assert result.aggregate_verified is False
        assert result.claims_asserted_not_verified is True
        assert any("countersignature" in e for e in result.errors), (
            f"expected a countersignature error, got: {result.errors}"
        )

    def test_stolen_history_rejected_by_membership(self):
        """Condition (b) knocked out: prover 'thief_x' full-reveals over
        attestations between agent_a/agent_b (thief is NOT a party). Build the
        proof_dict directly (CompetenceProof.create would reject non-membership
        at creation; the verifier must reject an arbitrary hand-built dict, which
        is the actual threat). aggregate stays False AND it is a hard
        valid=False (stolen-history rejection is now a hard error, P4 STEP 3)."""
        atts = [
            _mint_bound_attestation("victim_a", "victim_b", status="agreed")
            for _ in range(3)
        ]
        att_ids = [att["attestation_id"] for att in atts]

        import concordia.competence_proof as cp
        from concordia.receipt_bundle import _compute_summary

        root, layers = cp.build_merkle_tree(att_ids)
        sorted_ids = sorted(att_ids)
        mproofs = [cp.generate_merkle_proof(i, sorted_ids, layers) for i in att_ids]
        thief_kp = _get_key("thief_x")
        summary = _compute_summary("thief_x", atts).to_dict()
        proof = CompetenceProof(
            proof_id=f"proof_{uuid.uuid4().hex[:12]}",
            agent_id="thief_x",
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            claims=summary,
            attestation_merkle_root=root,
            attestation_count=len(att_ids),
            merkle_proofs=mproofs,
            revealed_attestations=atts,
        )
        proof.agent_signature = sign_message(proof.to_dict_for_signing(), thief_kp)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        assert result.valid is False, (
            "stolen-history full reveal must be a hard rejection (P4 STEP 3)"
        )
        assert result.aggregate_verified is False
        assert result.claims_asserted_not_verified is True
        assert sorted(result.prover_nonmember_attestations) == sorted(att_ids)
        assert any(
            "not a party" in e.lower() for e in result.errors
        ), f"expected a prover-not-a-party error, got: {result.errors}"

    def test_mixed_version_keeps_aggregate_false(self):
        """Condition (a) knocked out via MIXED VERSION: a full reveal where one
        revealed attestation is legacy 0.1.0 (unbound) and the rest are bound
        0.2.0; prover is a party in all. aggregate stays False because
        len(revealed_outcome_bound) != att_count; the legacy reveal is surfaced
        (no silent crediting). Being legacy alone is NOT a hard valid=False
        (bundle dual-accept philosophy) absent a membership/sig error."""
        prover = "sound_prover_mix"
        bound = [
            _mint_bound_attestation(prover, f"cp_mix_{i}", status="agreed")
            for i in range(2)
        ]
        # Legacy 0.1.0 where the SAME prover is a party. _mint registered the
        # prover's key; _make_attestation re-signs party_a under the registry's
        # current prover key, so the bundle agent key stays consistent.
        legacy = _make_attestation(agent_a=prover, agent_b="cp_mix_legacy", status="agreed")
        assert legacy["concordia_attestation"] == "0.1.0"
        atts = bound + [legacy]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _KEY_REGISTRY[prover]
        proof = CompetenceProof.create(prover, atts, kp, reveal_ids=att_ids)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        assert result.aggregate_verified is False, (
            "a single legacy <0.2.0 reveal must break cond_a"
        )
        assert result.claims_asserted_not_verified is True
        # Surfaced, not silently credited: the legacy id is in the unbound list.
        assert legacy["attestation_id"] in result.revealed_outcome_unbound
        # Not a hard rejection purely for being legacy (no membership/sig error).
        assert result.valid is True, result.errors

    def test_partial_reveal_keeps_aggregate_false(self):
        """Conditions (a)/(d) knocked out: bound atts, prover a party in all, but
        reveal only a SUBSET. aggregate stays False (a partial reveal can never
        verify the aggregate). Guards the partial-reveal shortcut."""
        prover = "sound_prover_partial"
        atts = [
            _mint_bound_attestation(prover, f"cp_part_{i}", status="agreed")
            for i in range(4)
        ]
        att_ids = [att["attestation_id"] for att in atts]
        kp = _KEY_REGISTRY[prover]
        proof = CompetenceProof.create(prover, atts, kp, reveal_ids=att_ids[:2])

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        assert result.valid is True, result.errors
        assert result.aggregate_verified is False
        assert result.claims_asserted_not_verified is True

    def test_self_rebind_single_party_countersig_not_verified(self):
        """OUTCOME-TAMPER forge (HIGH): the prover mints GENUINE rejected
        sessions, flips each outcome.status to 'agreed', DROPS the counterparty's
        countersignature, and re-countersigns the tampered snapshot with its OWN
        key alone. Under a 'at least one party signed' rule this would have
        yielded aggregate_verified=True over a fabricated 100% record. Dual-accept
        binding requires EVERY listed party's countersignature, so the missing
        counterparty countersignature makes the outcome unbound -> aggregate False
        and a hard valid=False."""
        prover = "self_rebind_prover"
        forged = []
        for i in range(3):
            att = _mint_bound_attestation(prover, f"cp_rebind_{i}", status="rejected")
            assert att["outcome"]["status"] == "rejected"
            # Forge: flip to agreed, drop counterparty, re-sign with prover key.
            att["outcome"]["status"] = "agreed"
            att["countersignatures"] = {
                prover: countersign_attestation(att, _KEY_REGISTRY[prover])
            }
            forged.append(att)
        att_ids = [att["attestation_id"] for att in forged]
        kp = _KEY_REGISTRY[prover]
        proof = CompetenceProof.create(prover, forged, kp, reveal_ids=att_ids)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        assert result.aggregate_verified is False, (
            "a holder self-rebinding a flipped outcome with its own key alone must "
            "NOT verify the aggregate (dual-accept)"
        )
        assert result.valid is False
        assert result.claims_asserted_not_verified is True
        # The dropped counterparty is surfaced as an unbound-outcome error.
        assert any(
            "countersignature" in e or "outcome not bound" in e
            for e in result.errors
        ), f"expected a missing-party-countersignature error, got: {result.errors}"

    def test_count_root_mismatch_keeps_aggregate_false(self):
        """FINDING 2 (count not bound to committed leaf set): the prover commits a
        3-leaf Merkle root but claims attestation_count=2 and reveals only the 2
        favorable leaves (dropping a loss from the CLAIM/reveal while keeping it in
        the root). Per-leaf inclusion proofs still verify (cond_c) but the
        recomputed root over the revealed 2-leaf set differs from the signed
        3-leaf root -> cond_e fails -> aggregate stays False with a hard error."""
        prover = "count_mismatch_prover"
        win1 = _mint_bound_attestation(prover, "cm_w1", status="agreed")
        win2 = _mint_bound_attestation(prover, "cm_w2", status="agreed")
        loss = _mint_bound_attestation(prover, "cm_l1", status="rejected")
        wins = [win1, win2]
        win_ids = [a["attestation_id"] for a in wins]
        all3_ids = [a["attestation_id"] for a in [win1, win2, loss]]

        from concordia.receipt_bundle import _compute_summary

        root3, layers3 = build_merkle_tree(all3_ids)
        sorted3 = sorted(all3_ids)
        mproofs = [generate_merkle_proof(i, sorted3, layers3) for i in win_ids]
        claims2 = _compute_summary(prover, wins).to_dict()  # claims over 2 wins
        kp = _KEY_REGISTRY[prover]
        proof = CompetenceProof(
            proof_id=f"proof_{uuid.uuid4().hex[:12]}",
            agent_id=prover,
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            claims=claims2,
            attestation_merkle_root=root3,  # commits to 3 leaves
            attestation_count=2,            # but claims only 2
            merkle_proofs=mproofs,
            revealed_attestations=wins,
        )
        proof.agent_signature = sign_message(proof.to_dict_for_signing(), kp)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        assert result.aggregate_verified is False, (
            "a count smaller than the committed leaf set must not verify"
        )
        assert result.valid is False
        assert any(
            "root does not match" in e.lower() or "not bound to the commitment" in e.lower()
            for e in result.errors
        ), f"expected a root/count-binding error, got: {result.errors}"

    def test_cherrypick_subset_verifies_but_is_not_completeness(self):
        """STOLEN-HISTORY FINDING 1 (completeness, inherent to selective
        disclosure): the prover is a GENUINE party in 2 wins and 1 loss, but
        commits the Merkle root over ONLY the 2 wins (omitting the loss entirely)
        and full-reveals that subset. Every gate condition holds for the COMMITTED
        SET, so aggregate_verified is True -- this is SOUND for what it claims
        (the revealed set is real and party-bound). The fix is the honest CONTRACT:
        the success warning MUST disclose that this is not a completeness proof, so
        a consumer never reads it as the prover's full record."""
        prover = "cherrypick_prover"
        win1 = _mint_bound_attestation(prover, "cherry_w1", status="agreed")
        win2 = _mint_bound_attestation(prover, "cherry_w2", status="agreed")
        # A real loss the prover simply never commits to.
        _loss = _mint_bound_attestation(prover, "cherry_l1", status="rejected")
        wins = [win1, win2]
        win_ids = [a["attestation_id"] for a in wins]
        kp = _KEY_REGISTRY[prover]
        proof = CompetenceProof.create(prover, wins, kp, reveal_ids=win_ids)

        result = verify_competence_proof(proof.to_dict(), _test_resolver)
        # Sound for the committed set: it IS internally consistent + party-bound.
        assert result.valid is True, result.errors
        assert result.aggregate_verified is True
        assert proof.claims["agreement_rate"] == 1.0
        assert proof.claims["total_negotiations"] == 2
        # Honest contract: the success path must flag the completeness limitation
        # so no consumer reads the verified aggregate as a complete track record.
        assert any(
            "completeness" in w.lower() or "omitted" in w.lower()
            for w in result.warnings
        ), (
            "aggregate_verified=True over a cherry-picked subset MUST surface the "
            f"completeness caveat; warnings were: {result.warnings}"
        )
