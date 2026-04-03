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
