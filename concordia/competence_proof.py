"""Competence Proofs - selectively revealable, signed negotiation-history commitment.

A competence proof is a privacy-preserving alternative to sharing a full receipt
bundle. Instead of sharing all attestations (which reveals counterparties and
session details), it shares:
  - Aggregate statistics that the PROVER ASSERTS (from BundleSummary)
  - A Merkle root committing to the prover's attestation IDs (so individual
    attestations can be selectively revealed)
  - Ed25519 signature over the whole thing

What a verifier CAN confirm (the sound checks):

  - **Signature:** the proof is signed by the claiming agent.
  - **Membership:** any *revealed* attestation provably belongs to the committed
    Merkle set.
  - **Party signatures on revealed attestations:** each revealed attestation's
    own party_record signatures are checked (parties whose key cannot be
    resolved are surfaced as unverified, not counted as evidence).

Sound aggregate verification (C-H2 P4, closes #120): the aggregate statistics
(``total_negotiations``, ``agreement_rate``, ``unique_counterparties``, ...) are
reported as INDEPENDENTLY VERIFIED (``aggregate_verified=True``,
``claims_asserted_not_verified=False``) IFF an exact four-condition gate holds:

  (a) every committed attestation is revealed AND each is ``>=0.2.0`` with a
      party-member countersignature that verifies over its issuance snapshot
      (the outcome is cryptographically bound),
  (b) the prover is a signed party in EVERY revealed attestation,
  (c) all merkle inclusion proofs are valid, and
  (d) the recompute over those countersigned outcomes equals the signed claims.

If any condition fails, the verifier HONESTLY DOWNGRADES: the aggregate is left
prover-asserted (``aggregate_verified=False``, ``claims_asserted_not_verified=True``),
and a caller MUST NOT read the headline numbers as confirmed. A stolen-history
reveal (prover not a party) is a HARD rejection (``valid=False``).

History (C-H1 refutation, 2026-06-17 -> C-H2 P4 re-enablement): an adversarial
review once refuted a naive "full reveal => aggregate_verified=True" path on two
counts: (1) outcomes were not signature-bound (a prover could rewrite
``outcome.status``), and (2) prover party-membership was not enforced at verify
time. C-H2 (#123) closed (1) by binding the attestation's ``outcome`` /
``fulfillment`` / ``meta`` into a party countersignature over the issuance
snapshot; P4 closes (2) by enforcing prover party-membership as a hard error.
Both holes closed, the four-condition gate above re-enables sound aggregate
verification.

This is NOT a zero-knowledge proof. The privacy property is selective disclosure
(reveal nothing, a subset, or everything), not a ZK aggregate. In short: a
competence proof proves the revealed attestations are members of a signed set
and their party signatures verify; the aggregate is independently verified only
under the four-condition gate, and is otherwise prover-asserted.

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

from .attestation import verify_attestation_countersignature
from .receipt_bundle import (
    _OUTCOME_BINDING_MIN,
    BundleSummary,
    _attestation_version_at_least,
    _compute_summary,
)
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

    The Merkle root commits to attestation IDs only. The aggregate ``claims`` are
    prover-asserted unless an independent verifier confirms them under the C-H2
    P4 four-condition gate (full reveal, every reveal ``>=0.2.0`` + valid party
    countersignature, prover a party in every reveal, recompute matches signed
    claims); see ``verify_competence_proof`` and
    ``CompetenceVerificationResult.aggregate_verified``. This is selective
    disclosure, NOT a zero-knowledge proof of the aggregate.

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
    belongs to the committed Merkle set, the revealed attestations' own party
    signatures and (for ``>=0.2.0``) outcome countersignatures check out, the
    prover is a party in every revealed attestation, and the signed claims are
    not self-inconsistent with a full revealed set." A stolen-history reveal
    (prover not a party) makes ``valid=False`` (C-H2 P4). ``valid=True`` alone
    does NOT mean the headline aggregate numbers are independently proven — read
    ``aggregate_verified`` for that.

    ``aggregate_verified`` is True IFF the C-H2 P4 four-condition gate holds:
    (a) full reveal of every committed attestation, each ``>=0.2.0`` with a valid
    party-member countersignature (outcome cryptographically bound); (b) the
    prover is a signed party in every reveal; (c) all merkle proofs valid; and
    (d) the recompute over those countersigned outcomes equals the signed claims.
    Otherwise it is False (the honest downgrade): the aggregate stays
    prover-asserted. (Pre-P4 this was always False; #123 closed the
    outcome-binding hole and P4 closed the membership hole, re-enabling the gate.)

    ``claims_asserted_not_verified`` is ``not aggregate_verified``: True whenever
    the aggregate is NOT independently confirmed. A caller MUST treat ``claims``
    as a self-asserted advertisement whenever this is True — a prover can sign
    ``{total_negotiations: 10000, agreement_rate: 1.0}`` over a Merkle root of
    zero real attestations and the signature/membership checks still pass, so a
    zero/partial/legacy reveal never flips this to False.

    ``unverified_parties`` names parties on revealed attestations whose key the
    verifier could not resolve. Their signatures were NOT checked, so a
    self-named counterparty in this list must not be read as independent
    evidence (a Sybil can name a counterparty it controls or invents).

    ``prover_nonmember_attestations`` names revealed attestations that do NOT
    list the prover (``agent_id``) as a party. This is now a HARD error
    (``valid=False``): the "stolen history" full reveal is rejected, and
    reputation MUST NOT credit these attestations to the prover.

    ``revealed_outcome_unbound`` names revealed attestations whose OUTCOME is not
    cryptographically bound — legacy ``<0.2.0`` reveals (prover-asserted, not an
    error) plus any ``>=0.2.0`` reveal whose countersignature failed (also an
    error). A non-empty list means the aggregate cannot be verified (cond_a
    fails); a consumer MUST NOT credit these outcomes.
    """

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    merkle_proofs_valid: bool = True
    sybil_flags: dict[str, Any] = field(default_factory=dict)
    aggregate_verified: bool = False
    claims_asserted_not_verified: bool = True
    unverified_parties: list[str] = field(default_factory=list)
    prover_nonmember_attestations: list[str] = field(default_factory=list)
    revealed_outcome_unbound: list[str] = field(default_factory=list)


def verify_competence_proof(
    proof_dict: dict[str, Any],
    resolve_key: Callable[[str], Ed25519PublicKey | None],
    check_revealed_attestations: bool = True,
) -> CompetenceVerificationResult:
    """Verify a competence proof.

    Sound checks (what this function confirms):
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
         c. Each ``>=0.2.0`` revealed attestation carries a valid party-member
            countersignature binding its outcome to the issuance snapshot
            (fail-closed: a tampered outcome or missing/invalid countersignature
            is an error). Legacy ``<0.2.0`` reveals are recorded as
            ``revealed_outcome_unbound`` (prover-asserted, not an error).
         d. The prover is a party in EVERY revealed attestation; a stolen-history
            reveal (prover not a party) is a HARD error (``valid=False``).
      4. Self-consistency of a FULL reveal: if the prover reveals the full
         committed set, the signed ``claims`` must not contradict the revealed
         set's own arithmetic (a self-inconsistent proof is rejected).

    Sound aggregate verification (C-H2 P4, closes #120):
      - ``aggregate_verified`` is True IFF the four-condition gate holds:
        (a) full reveal of every committed attestation, each ``>=0.2.0`` with a
        valid party-member countersignature (outcome bound); (b) the prover is a
        signed party in every reveal; (c) all merkle proofs valid; (d) the
        recompute over those countersigned outcomes equals the signed claims.
        When True, ``claims_asserted_not_verified`` is False and the headline
        numbers ARE independently confirmed.
      - Otherwise the verifier honestly downgrades: ``aggregate_verified`` is
        False, ``claims_asserted_not_verified`` is True, and a caller MUST treat
        ``claims`` as self-asserted. A zero/partial/legacy/mixed-version reveal,
        a tampered outcome, or a stolen-history reveal each block the gate.

    The Merkle root commits to attestation IDs only; the outcome binding comes
    from the per-attestation ``>=0.2.0`` countersignature (#123), not the root.
    This is selective disclosure, not a zero-knowledge proof.

    Args:
        proof_dict: The proof as a dict (from CompetenceProof.to_dict()).
        resolve_key: Callback that maps agent_id to Ed25519PublicKey, or None.
        check_revealed_attestations: If False, skip deep attestation verification
            (membership, party signatures, outcome binding, and the recompute);
            with it False the aggregate can never be verified.

    Returns:
        CompetenceVerificationResult with valid flag, the aggregate-verification
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
    # Track which revealed attestation IDs have a VALID membership proof (used
    # for the full-reveal self-consistency note below). Track parties whose key
    # could not be resolved so a self-named (possibly Sybil) counterparty does
    # not silently read as independently verified.
    revealed_membership_valid: set[str] = set()
    unverified_parties: set[str] = set()
    # C-H2 P4 outcome-binding over the revealed set: a revealed attestation's
    # OUTCOME is creditable only if it is >=0.2.0 AND carries a party-member
    # countersignature that verifies over the canonical issuance snapshot
    # (closes #123 reason 1). Legacy <0.2.0 reveals are recorded as unbound
    # (NOT an error — mixed-version handling lives in the aggregate gate). This
    # mirrors verify_bundle step (f) byte-for-byte so the two verifiers agree.
    revealed_outcome_bound: set[str] = set()
    revealed_outcome_unbound: list[str] = []
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

            # C-H2 P4 outcome-binding (per revealed attestation). Decide whether
            # this attestation's OUTCOME is cryptographically bound to its
            # issuance snapshot by a party-member countersignature. This is the
            # SAME fail-closed logic as verify_bundle step (f) (receipt_bundle.py
            # (f) block) so a forged outcome cannot survive in either verifier.
            ver = att.get("concordia_attestation", "")
            if not _attestation_version_at_least(ver, *_OUTCOME_BINDING_MIN):
                # Legacy / pre-C-H2 (or malformed version): outcome is
                # prover-asserted. Recorded as unbound, NOT an error here
                # (mixed-version handling is the aggregate gate's job).
                revealed_outcome_unbound.append(att_id)
            else:
                # >=0.2.0 MUST carry a valid party-member countersignature or
                # the outcome is NOT bound (fail-closed -> error).
                cs = att.get("countersignatures")
                att_party_ids = {
                    p.get("agent_id", "") for p in att.get("parties", [])
                }
                if not isinstance(cs, dict) or not cs:
                    errors.append(
                        f"Revealed attestation '{att_id}': version {ver} requires "
                        f"countersignatures; none present"
                    )
                    revealed_outcome_unbound.append(att_id)
                else:
                    any_party_member_verified = False
                    all_named_party_sigs_ok = True
                    for aid, sig in cs.items():
                        if aid not in att_party_ids:
                            # A countersignature naming a non-party cannot bind
                            # the outcome on a party's behalf; ignore it for
                            # crediting (does not, by itself, error).
                            continue
                        party_key = resolve_key(aid)
                        if party_key is None:
                            all_named_party_sigs_ok = False
                            continue
                        if verify_attestation_countersignature(att, sig, party_key):
                            any_party_member_verified = True
                        else:
                            all_named_party_sigs_ok = False
                            errors.append(
                                f"Revealed attestation '{att_id}': countersignature "
                                f"for '{aid}' failed verification"
                            )

                    if not all_named_party_sigs_ok:
                        if not any(
                            f"Revealed attestation '{att_id}': countersignature" in e
                            for e in errors
                        ):
                            errors.append(
                                f"Revealed attestation '{att_id}': a party "
                                f"countersignature could not be confirmed; "
                                f"outcome not bound"
                            )
                        revealed_outcome_unbound.append(att_id)
                    elif not any_party_member_verified:
                        errors.append(
                            f"Revealed attestation '{att_id}': version {ver} "
                            f"carries no verifiable party countersignature; "
                            f"outcome not bound"
                        )
                        revealed_outcome_unbound.append(att_id)
                    else:
                        revealed_outcome_bound.add(att_id)

    # 4. SOUND aggregate verification (C-H2 P4, closes #120). The aggregate is
    # reported as verified IFF an exact 4-condition gate holds; otherwise the
    # verifier HONESTLY DOWNGRADES to aggregate_verified=False /
    # claims_asserted_not_verified=True. This re-enables the path Path A removed,
    # but only because #123 closed the two soundness holes that justified the
    # removal:
    #
    #   (1) [closed by #123 countersignatures] Outcomes are now signature-bound.
    #       A >=0.2.0 attestation's outcome/meta/transcript_hash are bound to the
    #       issuance snapshot by a party countersignature. A rewritten
    #       ``outcome.status`` breaks that countersignature -> the per-reveal
    #       binding check above errors and the attestation is NOT in
    #       ``revealed_outcome_bound`` -> cond_a fails. (Legacy <0.2.0 reveals
    #       stay prover-asserted and break cond_a too: mixed-version => False.)
    #
    #   (2) [closed by STEP 3 below] Prover party-membership is enforced at
    #       verify time as a HARD ERROR, so a prover can no longer full-reveal
    #       over OTHER agents' attestations and have a recompute credit their
    #       track record.
    #
    # STEP 3: prover party-membership is now a HARD ERROR (was a warning under
    # Path A). A stolen-history full reveal is rejected (valid=False), not merely
    # flagged. We still compute and surface ``prover_nonmember_attestations`` so a
    # consumer sees exactly which reveals were not the prover's.
    prover_nonmember_attestations: list[str] = []
    if check_revealed_attestations and revealed_attestations:
        for att in revealed_attestations:
            party_ids = [
                p.get("agent_id", "") for p in att.get("parties", [])
            ]
            if agent_id not in party_ids:
                prover_nonmember_attestations.append(
                    att.get("attestation_id", "")
                )
        if prover_nonmember_attestations:
            n = len(prover_nonmember_attestations)
            # HARD ERROR: this makes valid=False (the stolen-history rejection).
            errors.append(
                f"Prover '{agent_id}' is not a party in {n} revealed "
                f"attestation(s): {sorted(prover_nonmember_attestations)}; "
                f"cannot claim this history."
            )
            # Keep the explanatory warning too (consumer-facing framing).
            warnings.append(
                f"{n} revealed attestation{'s' if n != 1 else ''} do not list the "
                f"prover ('{agent_id}') as a party; the prover cannot claim this "
                f"history as its own. Reputation MUST NOT credit these "
                f"attestations to the prover."
            )

    # Recompute over the revealed set. ``recompute_matches`` is condition (d) of
    # the gate. The recompute is only credited on a FULL, distinct-membership
    # reveal (a partial or double-counted reveal can never verify the aggregate),
    # AND it is only SOUND because cond_a guarantees those revealed outcomes are
    # countersigned (the soundness link: the recompute reads ``outcome.status`` /
    # ``fulfillment`` / ``meta`` from a snapshot a party signed).
    recompute_matches = False
    full_reveal = (
        check_revealed_attestations
        and att_count > 0
        and len(revealed_attestations) == att_count
        and len(revealed_membership_valid) == att_count
        and merkle_proofs_valid
    )
    if full_reveal:
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

        recompute_matches = len(mismatches) == 0
        if mismatches:
            # A full reveal whose signed claims contradict its OWN revealed set is
            # self-inconsistent: reject it (hard error). This also forces cond_d
            # / aggregate_verified False via the len(errors)==0 clause below.
            for m in mismatches:
                errors.append(f"Self-inconsistent claims vs revealed set: {m}")

    # The exact 4-condition gate for aggregate_verified=True.
    cond_a = (
        att_count > 0
        and len(revealed_attestations) == att_count
        and len(revealed_membership_valid) == att_count
        and len(revealed_outcome_bound) == att_count
    )  # every reveal is >=0.2.0 with a valid party-member countersignature
    cond_b = len(prover_nonmember_attestations) == 0  # prover a party in every reveal
    cond_c = merkle_proofs_valid                       # all merkle proofs valid
    cond_d = recompute_matches                         # full-reveal recompute == signed claims

    aggregate_verified = bool(
        cond_a
        and cond_b
        and cond_c
        and cond_d
        and len(errors) == 0  # no countersig / membership / signature error fired
    )
    claims_asserted_not_verified = not aggregate_verified

    if aggregate_verified:
        warnings.append(
            "Aggregate VERIFIED: full reveal of every committed attestation, each "
            ">=0.2.0 with a valid party-member countersignature binding its "
            "outcome, the prover is a signed party in every one, all merkle proofs "
            "valid, and the recompute over those countersigned outcomes matches "
            "the signed claims."
        )
    elif full_reveal and recompute_matches and len(errors) == 0:
        # A full reveal that is internally consistent but does NOT meet the
        # binding/membership conditions (e.g. mixed-version / legacy reveals):
        # the aggregate stays prover-asserted. Be explicit so a consumer does not
        # read a consistent recompute as confirmation.
        warnings.append(
            "Full reveal: signed claims are internally consistent with the "
            "revealed set's arithmetic, but the aggregate is NOT verified — at "
            "least one revealed attestation's outcome is not cryptographically "
            "bound (legacy <0.2.0 or missing a party countersignature). The "
            "aggregate statistics remain PROVER-ASSERTED."
        )

    return CompetenceVerificationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        merkle_proofs_valid=merkle_proofs_valid,
        sybil_flags={},
        aggregate_verified=aggregate_verified,
        claims_asserted_not_verified=claims_asserted_not_verified,
        unverified_parties=sorted(unverified_parties),
        prover_nonmember_attestations=sorted(prover_nonmember_attestations),
        revealed_outcome_unbound=sorted(revealed_outcome_unbound),
    )
