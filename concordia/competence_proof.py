"""Competence Proofs — selectively revealable, signed negotiation-history commitment.

A competence proof is a privacy-preserving alternative to sharing a full receipt
bundle. Instead of sharing all attestations (which reveals counterparties and
session details), it shares:
  - Aggregate statistics that the PROVER ASSERTS (from BundleSummary)
  - A Merkle root committing to the prover's attestation IDs (so individual
    attestations can be selectively revealed)
  - Ed25519 signature over the whole thing

What a verifier can confirm depends on how much the prover reveals:

  - **Signature + membership (always):** the proof is signed by the claiming
    agent, and any *revealed* attestation provably belongs to the committed
    Merkle set. The revealed attestations' own party signatures are checked.

  - **Full reveal (all attestations revealed, all membership proofs valid):**
    the verifier RECOMPUTES the aggregate statistics from the revealed
    attestations and rejects the proof if the prover's signed ``claims`` do not
    match. In this mode the headline numbers are actually verified
    (``aggregate_verified=True``), exactly like ``verify_receipt_bundle``.

  - **Subset / no reveal:** the aggregate statistics are PROVER-ASSERTED, NOT
    verified. The Merkle root commits only to attestation *IDs*, not to
    outcomes, so the verifier cannot recompute ``agreement_rate`` or
    ``total_negotiations`` from anything it can check. The result reports
    ``aggregate_verified=False`` and ``claims_asserted_not_verified=True``; a
    caller MUST NOT read the headline numbers as confirmed.

IMPORTANT — this is NOT a zero-knowledge proof. There is no cryptographic
argument that the unrevealed aggregate is correct; absent a full reveal, the
summary statistics carry only the prover's signature, not a verifiable
guarantee. The privacy property is selective disclosure (reveal nothing, a
subset, or everything), not a ZK aggregate.

Implements Viral Strategy item #18 (session receipts as portable proof) with
privacy via selective disclosure rather than privacy-by-policy.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .receipt_bundle import BundleSummary, _compute_summary
from .signing import KeyPair, canonical_json, sign_message, verify_signature

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
    """Selectively revealable, signed commitment to negotiation history.

    Carries prover-ASSERTED aggregate stats plus a Merkle commitment to the
    prover's attestation IDs, without forcing disclosure of individual sessions,
    counterparties, or deal terms. A verifier can always confirm:
      1. The proof is signed by the claiming agent
      2. Any *revealed* attestation provably belongs to the committed Merkle set
      3. Revealed attestations' own party signatures are checked

    The Merkle root commits to attestation IDs only (not outcomes), so the
    aggregate ``claims`` are PROVER-ASSERTED, not verified, UNLESS the prover
    reveals the full committed set — in which case ``verify_competence_proof``
    recomputes and confirms the aggregate (see that function and
    ``CompetenceVerificationResult.aggregate_verified``). This is selective
    disclosure, NOT a zero-knowledge proof of the unrevealed aggregate.

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
                merkle_proof = generate_merkle_proof(rev_id, sorted_ids, layers)
                merkle_proofs.append(merkle_proof)

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
    """Result of verifying a competence proof.

    ``valid`` means "signature is good, every revealed attestation provably
    belongs to the committed Merkle set, and the revealed attestations' own
    party signatures check out." It does NOT by itself mean the headline
    aggregate numbers (``total_negotiations``, ``agreement_rate``, ...) are
    proven — read ``aggregate_verified`` for that.

    ``aggregate_verified`` is True ONLY when the prover revealed the full
    committed set, every membership proof verified, and the verifier's
    recomputation of the aggregate from the revealed attestations matched the
    prover's signed ``claims``. In that case the headline numbers are verified,
    exactly like ``verify_receipt_bundle``.

    ``claims_asserted_not_verified`` is True whenever the aggregate could NOT be
    recomputed (no reveal, or only a subset revealed). A caller MUST treat the
    proof's ``claims`` as a self-asserted advertisement in that case, never as a
    confirmed count — a prover can sign ``{total_negotiations: 10000,
    agreement_rate: 1.0}`` over a Merkle root of zero real attestations and the
    signature/membership checks still pass.

    ``unverified_parties`` names parties on revealed attestations whose key the
    verifier could not resolve. Their signatures were NOT checked, so a
    self-named counterparty in this list must not be read as independent
    evidence (a Sybil can name a counterparty it controls or invents).
    """

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    merkle_proofs_valid: bool = True
    sybil_flags: dict[str, Any] = field(default_factory=dict)
    aggregate_verified: bool = False
    claims_asserted_not_verified: bool = True
    unverified_parties: list[str] = field(default_factory=list)


def verify_competence_proof(
    proof_dict: dict[str, Any],
    resolve_key: Callable[[str], Ed25519PublicKey | None],
    check_revealed_attestations: bool = True,
) -> CompetenceVerificationResult:
    """Verify a competence proof.

    Checks:
      1. Signature validity against the agent's public key.
      2. Internal consistency: ``attestation_count`` matches
         ``claims.total_negotiations`` (both are prover-chosen and inside the
         same signed blob, so this only catches an inconsistent forgery, not an
         inflated-but-consistent one).
      3. If ``revealed_attestations`` are present:
         a. Each has a valid Merkle inclusion proof against the root.
         b. Each revealed attestation validates against its party signatures
            (parties whose key cannot be resolved are surfaced in
            ``unverified_parties`` and are NOT counted as independent evidence).
      4. **Aggregate verification (full reveal only):** if the prover reveals the
         FULL committed set (one distinct revealed attestation per committed ID,
         all membership proofs valid), the aggregate is RECOMPUTED from the
         revealed attestations and the proof FAILS if the signed ``claims`` do
         not match. ``aggregate_verified`` is then True. Otherwise the aggregate
         is NOT recomputable and the result reports
         ``aggregate_verified=False`` and ``claims_asserted_not_verified=True``;
         callers MUST treat ``claims`` as self-asserted, never as confirmed.

    The Merkle root commits to attestation IDs only, not outcomes. Without a full
    reveal there is NO cryptographic guarantee behind the headline aggregate;
    this is selective disclosure, not a zero-knowledge proof.

    Args:
        proof_dict: The proof as a dict (from CompetenceProof.to_dict()).
        resolve_key: Callback that maps agent_id to Ed25519PublicKey, or None.
        check_revealed_attestations: If False, skip deep attestation verification.
            When False, the aggregate is never recomputed (no full-reveal
            confirmation), so ``aggregate_verified`` stays False.

    Returns:
        CompetenceVerificationResult with valid flag, the aggregate-honesty
        fields, and any errors/warnings.
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

    # 3. Verify revealed attestations and Merkle proofs.
    #
    # Track which revealed attestation IDs have a VALID membership proof — only
    # those can support a full-reveal aggregate recomputation below. Track
    # parties whose key could not be resolved so a self-named (possibly Sybil)
    # counterparty does not silently read as independently verified.
    revealed_membership_valid: set[str] = set()
    unverified_parties: set[str] = set()
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
                if verify_merkle_proof(att_id, proof_for_att, root):
                    revealed_membership_valid.add(att_id)
                else:
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
                    if pid != agent_id:
                        unverified_parties.add(pid)
                    continue
                party_key = resolve_key(pid)
                if party_key is None:
                    # Non-fatal (a legitimate partial reveal may name a
                    # counterparty this verifier does not know), but the party's
                    # signature was NOT checked, so surface it distinctly rather
                    # than letting it pass as verified evidence.
                    warnings.append(
                        f"Revealed attestation '{att_id}', party {j} ('{pid}'): "
                        f"cannot resolve key, signature not verified"
                    )
                    if pid != agent_id:
                        unverified_parties.add(pid)
                    continue
                signable_party = {
                    k: v for k, v in party.items() if k != "signature"
                }
                if not verify_signature(signable_party, sig, party_key):
                    errors.append(
                        f"Revealed attestation '{att_id}', party {j} ('{pid}'): "
                        f"invalid signature"
                    )
                    if pid != agent_id:
                        unverified_parties.add(pid)

    # 4. Aggregate verification — only possible on a FULL reveal.
    #
    # The Merkle root commits to attestation IDs, not to outcomes, so the
    # aggregate claims cannot be recomputed from anything the verifier can check
    # UNLESS the prover reveals the entire committed set. "Full reveal" means:
    # check_revealed_attestations is on, every committed attestation is revealed
    # with a VALID membership proof, and no ID is double-counted to fake the
    # count. Only then do we recompute the BundleSummary from the revealed
    # attestations and require the signed claims to match.
    aggregate_verified = False
    claims_asserted_not_verified = True
    if (
        check_revealed_attestations
        and att_count > 0
        and len(revealed_attestations) == att_count
        and len(revealed_membership_valid) == att_count
        and merkle_proofs_valid
    ):
        recomputed = _compute_summary(agent_id, revealed_attestations).to_dict()
        claimed = BundleSummary.from_dict(claims).to_dict()
        mismatches: list[str] = []
        for key in recomputed:
            rec_val = recomputed[key]
            claim_val = claimed.get(key)
            if isinstance(rec_val, float) and isinstance(claim_val, (int, float)):
                if abs(float(claim_val) - rec_val) > 0.001:
                    mismatches.append(
                        f"{key}: claimed {claim_val}, recomputed {rec_val}"
                    )
            elif isinstance(rec_val, list):
                if sorted(map(str, claim_val or [])) != sorted(map(str, rec_val)):
                    mismatches.append(f"{key} mismatch")
            elif claim_val != rec_val:
                mismatches.append(f"{key}: claimed {claim_val}, recomputed {rec_val}")

        if mismatches:
            for m in mismatches:
                errors.append(f"Full-reveal aggregate mismatch: {m}")
        else:
            aggregate_verified = True
            claims_asserted_not_verified = False

    return CompetenceVerificationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        merkle_proofs_valid=merkle_proofs_valid,
        sybil_flags={},
        aggregate_verified=aggregate_verified,
        claims_asserted_not_verified=claims_asserted_not_verified,
        unverified_parties=sorted(unverified_parties),
    )
