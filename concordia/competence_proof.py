"""ZK-style Competence Proofs — privacy-preserving negotiation competence.

A competence proof is a privacy-preserving alternative to a receipt bundle.
Instead of sharing all attestations (which reveals counterparties and session
details), it shares only:
  - Aggregate statistics (from BundleSummary)
  - A Merkle root of the attestation IDs (so individual attestations can be
    selectively revealed later if the prover chooses)
  - Ed25519 signature over the whole thing

This allows an agent to prove negotiation competence without revealing:
  - Individual counterparties
  - Deal terms
  - Specific sessions
  - Timeline details

Implements Viral Strategy item #18 (session receipts as portable proof) with
privacy-by-architecture rather than privacy-by-policy.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .signing import KeyPair, canonical_json, sign_message, verify_signature
from .receipt_bundle import BundleSummary, _compute_summary


# ---------------------------------------------------------------------------
# Merkle tree construction and proof generation
# ---------------------------------------------------------------------------


def build_merkle_tree(
    attestation_ids: list[str],
) -> tuple[str, list[list[str]]]:
    """Build a Merkle tree from sorted attestation IDs.

    Args:
        attestation_ids: List of attestation IDs to include in the tree.

    Returns:
        A tuple of (root_hash, all_layers) where:
        - root_hash is the SHA-256 hash of the root
        - all_layers is a list of layers from leaves to root, where each layer
          is a list of hashes at that height. Layer 0 is the leaf hashes.

    If the list is empty, returns ("", []).
    """
    if not attestation_ids:
        return "", []

    # Sort and hash the leaves
    sorted_ids = sorted(attestation_ids)
    layers: list[list[str]] = []
    current_layer = [
        hashlib.sha256(att_id.encode("utf-8")).hexdigest() for att_id in sorted_ids
    ]
    layers.append(current_layer)

    # Build layers up to root
    while len(current_layer) > 1:
        next_layer: list[str] = []
        for i in range(0, len(current_layer), 2):
            if i + 1 < len(current_layer):
                combined = current_layer[i] + current_layer[i + 1]
            else:
                # Odd one out — hash it with itself
                combined = current_layer[i] + current_layer[i]
            hash_val = hashlib.sha256(combined.encode("utf-8")).hexdigest()
            next_layer.append(hash_val)
        layers.append(next_layer)
        current_layer = next_layer

    root = current_layer[0] if current_layer else ""
    return root, layers


def generate_merkle_proof(
    attestation_id: str, sorted_ids: list[str], layers: list[list[str]]
) -> dict[str, Any]:
    """Generate a Merkle inclusion proof for a specific attestation.

    Args:
        attestation_id: The attestation ID to prove.
        sorted_ids: The same sorted list used to build the tree.
        layers: The result of build_merkle_tree()[1].

    Returns:
        A dict with keys:
          - attestation_id: the ID being proved
          - index: the leaf index in the sorted list
          - proof: list of sibling hashes from leaf to root

    Raises:
        ValueError: if attestation_id is not in sorted_ids.
    """
    if attestation_id not in sorted_ids:
        raise ValueError(f"Attestation '{attestation_id}' not found in sorted_ids")

    index = sorted_ids.index(attestation_id)

    proof: list[str] = []
    current_index = index

    # Walk up the tree, collecting siblings
    for layer_idx in range(len(layers) - 1):
        current_layer = layers[layer_idx]

        # Find the sibling in this layer
        if current_index % 2 == 0:
            # We're the left child, sibling is on the right
            sibling_index = current_index + 1
        else:
            # We're the right child, sibling is on the left
            sibling_index = current_index - 1

        if sibling_index < len(current_layer):
            proof.append(current_layer[sibling_index])
        else:
            # No sibling exists at this level (odd node out).
            # In build_merkle_tree, this node was hashed with itself.
            # To reconstruct correctly, include the node's own hash as the "sibling".
            proof.append(current_layer[current_index])

        # Move to next layer
        current_index //= 2

    return {
        "attestation_id": attestation_id,
        "index": index,
        "proof": proof,
    }


def verify_merkle_proof(attestation_id: str, proof: dict[str, Any], root: str) -> bool:
    """Verify a Merkle inclusion proof against a root.

    Args:
        attestation_id: The attestation ID being verified.
        proof: The proof dict from generate_merkle_proof.
        root: The Merkle root to verify against.

    Returns:
        True if the proof is valid, False otherwise.
    """
    if root == "":
        # Empty tree
        return False

    # Hash the leaf
    current_hash = hashlib.sha256(attestation_id.encode("utf-8")).hexdigest()

    # Walk up the tree using siblings from the proof
    index = proof.get("index", 0)
    proof_hashes = proof.get("proof", [])

    for sibling_hash in proof_hashes:
        if index % 2 == 0:
            # We're the left child
            combined = current_hash + sibling_hash
        else:
            # We're the right child
            combined = sibling_hash + current_hash

        current_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
        index //= 2

    return current_hash == root


# ---------------------------------------------------------------------------
# Competence Proof data structure
# ---------------------------------------------------------------------------


@dataclass
class CompetenceProof:
    """Privacy-preserving proof of negotiation competence.

    Proves aggregate stats without revealing individual sessions, counterparties,
    or deal terms. A verifier can confirm:
      1. The proof is signed by the claiming agent
      2. The Merkle root commits to specific attestations
      3. Individual attestations can be spot-checked via Merkle inclusion proofs

    Fields:
        proof_id: Unique ID (format: "proof_<12-hex-chars>")
        agent_id: The agent claiming competence
        created_at: ISO 8601 timestamp
        claims: Aggregate stats dict (shape matches BundleSummary.to_dict())
        attestation_merkle_root: SHA-256 Merkle root of sorted attestation IDs
        attestation_count: Must match claims.total_negotiations
        concordia_competence_proof: Version string "0.1.0"
        merkle_proofs: List of Merkle inclusion proofs for revealed attestations
        revealed_attestations: Subset of attestations the prover chose to reveal
        agent_signature: Ed25519 signature over everything except this field
    """

    proof_id: str
    agent_id: str
    created_at: str
    claims: dict[str, Any]  # BundleSummary.to_dict()
    attestation_merkle_root: str
    attestation_count: int
    concordia_competence_proof: str = "0.1.0"
    merkle_proofs: list[dict[str, Any]] = field(default_factory=list)
    revealed_attestations: list[dict[str, Any]] = field(default_factory=list)
    agent_signature: str = ""

    @classmethod
    def create(
        cls,
        agent_id: str,
        attestations: list[dict[str, Any]],
        key_pair: KeyPair,
        reveal_ids: list[str] | None = None,
    ) -> CompetenceProof:
        """Create a competence proof from attestations.

        Args:
            agent_id: The proving agent.
            attestations: Full attestation list (used to compute stats and Merkle tree).
                         Individual attestations are NOT included in the proof unless
                         explicitly included in reveal_ids.
            key_pair: Ed25519 key pair for signing.
            reveal_ids: Optional list of attestation IDs to include Merkle proofs and
                       attestation data for. Useful for spot-checking.

        Returns:
            A signed CompetenceProof.

        Raises:
            ValueError: If agent_id is not a party in every attestation.
        """
        # Validate that agent appears in every attestation
        for i, att in enumerate(attestations):
            parties = att.get("parties", [])
            party_ids = [p.get("agent_id", "") for p in parties]
            if agent_id not in party_ids:
                raise ValueError(
                    f"Agent '{agent_id}' is not a party in attestation {i} "
                    f"(attestation: {att.get('attestation_id', 'unknown')})"
                )

        # Compute aggregate statistics
        summary = _compute_summary(agent_id, attestations)

        # Build Merkle tree from attestation IDs
        att_ids = [att.get("attestation_id", "") for att in attestations]
        root, layers = build_merkle_tree(att_ids)

        # Generate Merkle proofs for revealed attestations
        merkle_proofs: list[dict[str, Any]] = []
        revealed_attestations: list[dict[str, Any]] = []

        if reveal_ids:
            sorted_ids = sorted(att_ids)
            for rev_id in reveal_ids:
                if rev_id not in att_ids:
                    raise ValueError(f"Attestation '{rev_id}' not found in attestations")
                proof = generate_merkle_proof(rev_id, sorted_ids, layers)
                merkle_proofs.append(proof)

                # Include the attestation itself
                for att in attestations:
                    if att.get("attestation_id", "") == rev_id:
                        revealed_attestations.append(att)
                        break

        # Create the proof object
        proof_id = f"proof_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        proof = cls(
            proof_id=proof_id,
            agent_id=agent_id,
            created_at=created_at,
            claims=summary.to_dict(),
            attestation_merkle_root=root,
            attestation_count=len(att_ids),
            concordia_competence_proof="0.1.0",
            merkle_proofs=merkle_proofs,
            revealed_attestations=revealed_attestations,
            agent_signature="",  # Will be filled by sign
        )

        # Sign it
        signable = proof.to_dict_for_signing()
        proof.agent_signature = sign_message(signable, key_pair)

        return proof

    def to_dict(self) -> dict[str, Any]:
        """Serialize the proof to a dict."""
        return {
            "concordia_competence_proof": self.concordia_competence_proof,
            "proof_id": self.proof_id,
            "agent_id": self.agent_id,
            "created_at": self.created_at,
            "claims": self.claims,
            "attestation_merkle_root": self.attestation_merkle_root,
            "attestation_count": self.attestation_count,
            "merkle_proofs": self.merkle_proofs,
            "revealed_attestations": self.revealed_attestations,
            "agent_signature": self.agent_signature,
        }

    def to_dict_for_signing(self) -> dict[str, Any]:
        """Return the dict to be signed (excludes signature and version fields)."""
        return {
            "proof_id": self.proof_id,
            "agent_id": self.agent_id,
            "created_at": self.created_at,
            "claims": self.claims,
            "attestation_merkle_root": self.attestation_merkle_root,
            "attestation_count": self.attestation_count,
            "merkle_proofs": self.merkle_proofs,
            "revealed_attestations": self.revealed_attestations,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompetenceProof:
        """Deserialize a proof from a dict."""
        return cls(
            concordia_competence_proof=data.get("concordia_competence_proof", "0.1.0"),
            proof_id=data.get("proof_id", ""),
            agent_id=data.get("agent_id", ""),
            created_at=data.get("created_at", ""),
            claims=data.get("claims", {}),
            attestation_merkle_root=data.get("attestation_merkle_root", ""),
            attestation_count=data.get("attestation_count", 0),
            merkle_proofs=data.get("merkle_proofs", []),
            revealed_attestations=data.get("revealed_attestations", []),
            agent_signature=data.get("agent_signature", ""),
        )

    def to_json(self) -> str:
        """Canonical JSON for portability."""
        return canonical_json(self.to_dict()).decode("utf-8")


# ---------------------------------------------------------------------------
# Competence Proof verification
# ---------------------------------------------------------------------------


@dataclass
class CompetenceVerificationResult:
    """Result of verifying a competence proof."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    merkle_proofs_valid: bool = True
    sybil_flags: dict[str, Any] = field(default_factory=dict)


def verify_competence_proof(
    proof_dict: dict[str, Any],
    resolve_key: Callable[[str], Ed25519PublicKey | None],
    check_revealed_attestations: bool = True,
) -> CompetenceVerificationResult:
    """Verify a competence proof.

    Checks:
      1. Signature validity against the agent's public key
      2. Merkle root consistency: attestation_count matches claims.total_negotiations
      3. If revealed_attestations are present:
         a. Each has a valid Merkle inclusion proof against the root
         b. Each attestation validates against party signatures (if keys are available)

    Args:
        proof_dict: The proof as a dict (from CompetenceProof.to_dict()).
        resolve_key: Callback that maps agent_id to Ed25519PublicKey, or None.
        check_revealed_attestations: If False, skip deep attestation verification.

    Returns:
        CompetenceVerificationResult with valid flag and any errors/warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []
    merkle_proofs_valid = True

    # Check required fields
    for f in (
        "proof_id",
        "agent_id",
        "created_at",
        "claims",
        "attestation_merkle_root",
        "attestation_count",
        "agent_signature",
    ):
        if f not in proof_dict:
            errors.append(f"Missing required field: '{f}'")
    if errors:
        return CompetenceVerificationResult(valid=False, errors=errors)

    agent_id = proof_dict["agent_id"]
    signature = proof_dict["agent_signature"]
    root = proof_dict["attestation_merkle_root"]
    att_count = proof_dict["attestation_count"]
    claims = proof_dict.get("claims", {})
    merkle_proofs = proof_dict.get("merkle_proofs", [])
    revealed_attestations = proof_dict.get("revealed_attestations", [])

    # 1. Verify signature
    agent_key = resolve_key(agent_id)
    if agent_key is None:
        errors.append(f"Cannot resolve public key for agent '{agent_id}'")
    else:
        # Remove version and signature fields, keep everything else
        signable = {
            k: v
            for k, v in proof_dict.items()
            if k not in ("agent_signature", "concordia_competence_proof")
        }
        if not verify_signature(signable, signature, agent_key):
            errors.append("Proof signature verification failed")

    # 2. Check Merkle consistency
    if att_count != claims.get("total_negotiations", 0):
        errors.append(
            f"Attestation count mismatch: root commits to {att_count}, "
            f"claims says {claims.get('total_negotiations', 0)}"
        )

    # 3. Verify revealed attestations and Merkle proofs
    if check_revealed_attestations and revealed_attestations:
        for att in revealed_attestations:
            att_id = att.get("attestation_id", "")

            # Find the corresponding Merkle proof
            proof_for_att = None
            for mp in merkle_proofs:
                if mp.get("attestation_id", "") == att_id:
                    proof_for_att = mp
                    break

            if proof_for_att is None:
                warnings.append(
                    f"Revealed attestation '{att_id}' has no Merkle proof"
                )
                merkle_proofs_valid = False
            else:
                # Verify the Merkle proof
                if not verify_merkle_proof(att_id, proof_for_att, root):
                    errors.append(
                        f"Merkle proof failed for revealed attestation '{att_id}'"
                    )
                    merkle_proofs_valid = False

            # Verify attestation party signatures (if keys available)
            parties = att.get("parties", [])
            for j, party in enumerate(parties):
                pid = party.get("agent_id", "")
                sig = party.get("signature", "")
                if not sig:
                    errors.append(
                        f"Revealed attestation '{att_id}', party {j} ('{pid}'): "
                        f"empty signature"
                    )
                    continue
                party_key = resolve_key(pid)
                if party_key is None:
                    warnings.append(
                        f"Revealed attestation '{att_id}', party {j} ('{pid}'): "
                        f"cannot resolve key, signature not verified"
                    )
                    continue
                signable_party = {
                    k: v for k, v in party.items() if k != "signature"
                }
                if not verify_signature(signable_party, sig, party_key):
                    errors.append(
                        f"Revealed attestation '{att_id}', party {j} ('{pid}'): "
                        f"invalid signature"
                    )

    return CompetenceVerificationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        merkle_proofs_valid=merkle_proofs_valid,
        sybil_flags={},
    )
