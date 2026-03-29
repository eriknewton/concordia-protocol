"""Attestation Store — ingestion, validation, deduplication, and retrieval.

Every attestation submitted to the Reputation Service passes through a
validation pipeline before being stored:

    1. Schema conformance (required fields, correct types)
    2. Signature verification (Ed25519 signatures from both parties)
    3. Transcript hash format check
    4. Deduplication (same attestation_id or same session_id rejected)
    5. Sybil signal detection (flagged, not blocked — scoring adjusts)

Storage is in-memory for the reference implementation. The interface is
designed so a persistent backend (PostgreSQL, DynamoDB) can be swapped in.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..signing import KeyPair, verify_signature


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """Result of attestation validation."""
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Sybil signals
# ---------------------------------------------------------------------------

@dataclass
class SybilSignals:
    """Signals that may indicate Sybil or gaming behavior."""
    self_dealing: bool = False          # same agent on both sides
    suspiciously_fast: bool = False     # negotiation completed in < 5 seconds
    symmetric_concessions: bool = False # both parties conceded identically
    closed_loop: bool = False           # A↔B only transact with each other
    flagged: bool = False               # any signal triggered

    def check(self, attestation: dict[str, Any], store: AttestationStore) -> None:
        """Run all Sybil checks against an attestation."""
        parties = attestation.get("parties", [])
        agent_ids = [p.get("agent_id", "") for p in parties]

        # Self-dealing: same agent_id on both sides
        if len(agent_ids) >= 2 and agent_ids[0] == agent_ids[1]:
            self.self_dealing = True

        # Suspiciously fast: < 5 seconds
        outcome = attestation.get("outcome", {})
        duration = outcome.get("duration_seconds", 999)
        if duration < 5:
            self.suspiciously_fast = True

        # Symmetric concessions
        if len(parties) >= 2:
            behaviors = [p.get("behavior", {}) for p in parties]
            if (len(behaviors) >= 2
                    and behaviors[0].get("concession_magnitude", -1)
                    == behaviors[1].get("concession_magnitude", -2)
                    and behaviors[0].get("concession_magnitude", 0) > 0):
                self.symmetric_concessions = True

        # Closed loop: check if these two agents only transact with each other
        if len(agent_ids) >= 2:
            a, b = agent_ids[0], agent_ids[1]
            a_counterparties = store.get_counterparties(a)
            b_counterparties = store.get_counterparties(b)
            # If both have history and only with each other, flag it
            if (len(a_counterparties) > 2 and a_counterparties == {b}
                    and len(b_counterparties) > 2 and b_counterparties == {a}):
                self.closed_loop = True

        self.flagged = any([
            self.self_dealing,
            self.suspiciously_fast,
            self.symmetric_concessions,
            self.closed_loop,
        ])

    def to_dict(self) -> dict[str, bool]:
        return {
            "self_dealing": self.self_dealing,
            "suspiciously_fast": self.suspiciously_fast,
            "symmetric_concessions": self.symmetric_concessions,
            "closed_loop": self.closed_loop,
            "flagged": self.flagged,
        }


# ---------------------------------------------------------------------------
# Stored attestation record
# ---------------------------------------------------------------------------

@dataclass
class StoredAttestation:
    """An attestation plus ingestion metadata."""
    attestation: dict[str, Any]
    attestation_id: str
    session_id: str
    agent_ids: list[str]
    ingested_at: str
    sybil_signals: SybilSignals
    validation: ValidationResult


# ---------------------------------------------------------------------------
# Attestation Store
# ---------------------------------------------------------------------------

class AttestationStore:
    """In-memory attestation store with validation and deduplication.

    The store indexes attestations by attestation_id, session_id, and
    agent_id for efficient querying by the scoring engine.
    """

    # Resource limit
    MAX_ATTESTATIONS = 100_000

    # Required top-level fields per attestation schema
    REQUIRED_FIELDS = {
        "concordia_attestation", "attestation_id", "session_id",
        "timestamp", "outcome", "parties", "meta", "transcript_hash",
    }

    # Required outcome fields
    REQUIRED_OUTCOME_FIELDS = {"status", "rounds", "duration_seconds"}

    # Valid outcome statuses
    VALID_STATUSES = {"agreed", "rejected", "expired", "withdrawn"}

    # Required party fields
    REQUIRED_PARTY_FIELDS = {"agent_id", "role", "behavior", "signature"}

    def __init__(self) -> None:
        # Primary storage: attestation_id → StoredAttestation
        self._by_id: dict[str, StoredAttestation] = {}
        # Index: session_id → attestation_id (for dedup)
        self._by_session: dict[str, str] = {}
        # Index: agent_id → list of attestation_ids
        self._by_agent: dict[str, list[str]] = defaultdict(list)
        # Index: agent_id → set of counterparty agent_ids
        self._counterparties: dict[str, set[str]] = defaultdict(set)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(
        self,
        attestation: dict[str, Any],
        public_key_resolver: Callable[[str], Ed25519PublicKey | None],
    ) -> tuple[bool, ValidationResult]:
        """Validate and store an attestation.

        Args:
            attestation: The attestation dict to ingest.
            public_key_resolver: Mandatory callback that maps an agent_id
                to its Ed25519 public key, or returns ``None`` if the
                identity is unknown.  Follows the SEC-005 cluster contract:
                mandatory parameter, null return = rejection.

        Returns:
            (accepted, validation_result) tuple.
        """
        # Step 1: Validate
        validation = self._validate(attestation, public_key_resolver)
        if not validation.valid:
            return False, validation

        att_id = attestation["attestation_id"]
        session_id = attestation["session_id"]

        # Step 2: Deduplication
        if att_id in self._by_id:
            validation.valid = False
            validation.errors.append(
                f"Duplicate attestation_id: '{att_id}' already exists."
            )
            return False, validation

        if session_id in self._by_session:
            validation.valid = False
            validation.errors.append(
                f"Duplicate session_id: attestation for session '{session_id}' already exists."
            )
            return False, validation

        # Check capacity before proceeding
        if len(self._by_id) >= self.MAX_ATTESTATIONS:
            validation.valid = False
            validation.errors.append("Attestation store capacity reached")
            return False, validation

        # Step 3: Sybil detection
        sybil = SybilSignals()
        sybil.check(attestation, self)
        if sybil.flagged:
            validation.warnings.append(
                f"Sybil signals detected: {sybil.to_dict()}"
            )

        # Step 4: Store
        parties = attestation.get("parties", [])
        agent_ids = [p["agent_id"] for p in parties]

        record = StoredAttestation(
            attestation=attestation,
            attestation_id=att_id,
            session_id=session_id,
            agent_ids=agent_ids,
            ingested_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            sybil_signals=sybil,
            validation=validation,
        )

        self._by_id[att_id] = record
        self._by_session[session_id] = att_id

        for agent_id in agent_ids:
            self._by_agent[agent_id].append(att_id)

        # Update counterparty index
        if len(agent_ids) >= 2:
            for i, aid in enumerate(agent_ids):
                for j, other in enumerate(agent_ids):
                    if i != j:
                        self._counterparties[aid].add(other)

        return True, validation

    def get(self, attestation_id: str) -> StoredAttestation | None:
        """Retrieve a stored attestation by its ID."""
        return self._by_id.get(attestation_id)

    def get_by_session(self, session_id: str) -> StoredAttestation | None:
        """Retrieve a stored attestation by session ID."""
        att_id = self._by_session.get(session_id)
        if att_id:
            return self._by_id.get(att_id)
        return None

    def get_by_agent(self, agent_id: str) -> list[StoredAttestation]:
        """Retrieve all attestations involving a given agent."""
        att_ids = self._by_agent.get(agent_id, [])
        return [self._by_id[aid] for aid in att_ids if aid in self._by_id]

    def get_counterparties(self, agent_id: str) -> set[str]:
        """Return the set of agent_ids this agent has transacted with."""
        return self._counterparties.get(agent_id, set())

    def count(self) -> int:
        """Total number of stored attestations."""
        return len(self._by_id)

    def agent_count(self, agent_id: str) -> int:
        """Number of attestations for a specific agent."""
        return len(self._by_agent.get(agent_id, []))

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(
        self,
        attestation: dict[str, Any],
        public_key_resolver: Callable[[str], Ed25519PublicKey | None],
    ) -> ValidationResult:
        """Run the full validation pipeline on an attestation.

        Signature verification is mandatory — follows the SEC-005 cluster
        contract.  The ``public_key_resolver`` callback must be provided;
        if it returns ``None`` for any party the attestation is rejected.
        """
        errors: list[str] = []
        warnings: list[str] = []

        # Schema: required top-level fields
        for f in self.REQUIRED_FIELDS:
            if f not in attestation:
                errors.append(f"Missing required field: '{f}'")

        if errors:
            return ValidationResult(valid=False, errors=errors)

        # Schema: outcome fields
        outcome = attestation.get("outcome", {})
        for f in self.REQUIRED_OUTCOME_FIELDS:
            if f not in outcome:
                errors.append(f"Missing required outcome field: '{f}'")

        # Schema: outcome status
        status = outcome.get("status", "")
        if status and status not in self.VALID_STATUSES:
            errors.append(
                f"Invalid outcome status: '{status}'. "
                f"Must be one of: {self.VALID_STATUSES}"
            )

        # Schema: parties
        parties = attestation.get("parties", [])
        if not isinstance(parties, list) or len(parties) < 2:
            errors.append("Attestation must have at least 2 parties.")
        else:
            for i, party in enumerate(parties):
                for f in self.REQUIRED_PARTY_FIELDS:
                    if f not in party:
                        errors.append(f"Party {i}: missing required field '{f}'")
                # Validate that signature is not empty
                sig = party.get("signature", "")
                if not sig or not sig.strip():
                    errors.append(f"Party {i}: signature must not be empty")

        # Transcript hash format
        transcript_hash = attestation.get("transcript_hash", "")
        if transcript_hash and not transcript_hash.startswith("sha256:"):
            errors.append(
                f"Invalid transcript_hash format: must start with 'sha256:'"
            )

        # Mandatory signature verification (SEC-014 fix — cluster contract)
        # No fallback path: every party's signature must be verified.
        if not errors:
            for party in parties:
                agent_id = party.get("agent_id", "")
                signature = party.get("signature", "")
                if not signature:
                    # Already caught by empty-signature check above,
                    # but guard defensively.
                    continue

                public_key = public_key_resolver(agent_id)
                if public_key is None:
                    errors.append(
                        f"Unknown agent identity '{agent_id}' — "
                        "resolver returned None, signature cannot be verified"
                    )
                    continue

                signable = {k: v for k, v in party.items() if k != "signature"}
                try:
                    valid = verify_signature(signable, signature, public_key)
                    if not valid:
                        errors.append(
                            f"Invalid signature for agent '{agent_id}'"
                        )
                except Exception as e:
                    errors.append(
                        f"Signature verification failed for '{agent_id}': {e}"
                    )

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )
