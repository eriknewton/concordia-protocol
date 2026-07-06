"""CMPC bilateral primitive dataclasses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class RevocationScope(str, Enum):
    SINGLE_ARTIFACT = "single_artifact"
    CASCADE_TO_DEPENDENTS = "cascade_to_dependents"


@dataclass(kw_only=True)
class ConditionalCommitment:
    commitment_id: str
    chain_session_id: str
    committer_did: str
    predicate_reference: str
    commitment_terms: dict[str, Any]
    mandate_proof_id: str | None
    issued_at: datetime
    expires_at: datetime
    signature: str = ""
    algorithm: str = "EdDSA"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConditionalCommitment":
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "commitment_id": self.commitment_id,
            "chain_session_id": self.chain_session_id,
            "committer_did": self.committer_did,
            "predicate_reference": self.predicate_reference,
            "commitment_terms": self.commitment_terms,
            "mandate_proof_id": self.mandate_proof_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
            "algorithm": self.algorithm,
        }


@dataclass(kw_only=True)
class ClosurePredicate:
    predicate_id: str
    type: str
    authority: str
    issuer: str
    subject: str
    condition: dict[str, Any]
    issued_at: str
    expires_at: str
    references: list[dict[str, Any]]
    algorithm: str
    status: str
    signature: str
    validity: dict[str, Any] | None = None
    constraints: dict[str, Any] | None = None
    delegation_chain: list[dict[str, Any]] | None = None
    revocation_endpoint: str | None = None
    revoked_at: str | None = None
    metadata: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClosurePredicate":
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "predicate_id": self.predicate_id,
            "type": self.type,
            "authority": self.authority,
            "issuer": self.issuer,
            "subject": self.subject,
            "condition": self.condition,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "references": self.references,
            "algorithm": self.algorithm,
            "status": self.status,
            "signature": self.signature,
        }
        for key in (
            "validity",
            "constraints",
            "delegation_chain",
            "revocation_endpoint",
            "revoked_at",
            "metadata",
        ):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        return data


@dataclass(kw_only=True)
class AtomicActivationProof:
    activation_proof_id: str
    chain_session_id: str
    closure_predicate_id: str
    predicate_evaluation: dict[str, Any]
    commitment_ids: list[str]
    activated_at: datetime
    issuer_did: str
    signature: str = ""
    algorithm: str = "EdDSA"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AtomicActivationProof":
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "activation_proof_id": self.activation_proof_id,
            "chain_session_id": self.chain_session_id,
            "closure_predicate_id": self.closure_predicate_id,
            "predicate_evaluation": self.predicate_evaluation,
            "commitment_ids": self.commitment_ids,
            "activated_at": self.activated_at,
            "issuer_did": self.issuer_did,
            "signature": self.signature,
            "algorithm": self.algorithm,
        }


@dataclass(kw_only=True)
class UnwindRecord:
    unwind_record_id: str
    chain_session_id: str
    dissolution_reason: str
    dissolution_details: dict[str, Any]
    affected_commitment_ids: list[str]
    issuer_did: str
    issued_at: datetime
    counterparty_acknowledgment: dict[str, Any] | None
    signature: str = ""
    algorithm: str = "EdDSA"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UnwindRecord":
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "unwind_record_id": self.unwind_record_id,
            "chain_session_id": self.chain_session_id,
            "dissolution_reason": self.dissolution_reason,
            "dissolution_details": self.dissolution_details,
            "affected_commitment_ids": self.affected_commitment_ids,
            "issuer_did": self.issuer_did,
            "issued_at": self.issued_at,
            "counterparty_acknowledgment": self.counterparty_acknowledgment,
            "signature": self.signature,
            "algorithm": self.algorithm,
        }


@dataclass(kw_only=True)
class AncestorRead:
    """One ancestor status observation the terminal deny re-derived through.

    Binds *what* was read (``element_digest``, ``status``) and *which source*
    was read (``source_digest``) at *which point in that source's own ordering*
    (``coordinate``). It carries digests + status + coordinate ONLY; never any
    underlying deal terms (the audit-privacy invariant).

    ``coordinate`` is the status source's OWN ordering coordinate (a sequence
    number / block height / log index). It is NEVER a wall clock: a wall clock
    is not re-askable, so a wall-clock coordinate cannot anchor a recomputable
    decision. A coordinate the pinned history has not fixed yet is refused, not
    defaulted (enforced by the schema + the builder).
    """

    element_digest: str
    status: str
    source_digest: str
    coordinate: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AncestorRead":
        return cls(
            element_digest=data["element_digest"],
            status=data["status"],
            source_digest=data["source_digest"],
            coordinate=data["coordinate"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "element_digest": self.element_digest,
            "status": self.status,
            "source_digest": self.source_digest,
            "coordinate": self.coordinate,
        }


@dataclass(kw_only=True)
class CascadeDecisionRecord:
    """A committed, recomputable terminal-deny decision object.

    Emitted when the cascade verifier terminates an artifact as inadmissible
    due to an ancestor revocation. Unlike ``InadmissibleArtifact`` (a live
    ``reason`` enum + free-text ``evidence`` string), this record is
    content-addressed: its ``decision_id`` is ``SHA-256`` over the RFC 8785 JCS
    serialization of exactly the bound fields (everything except ``decision_id``
    and ``signature`` themselves), so a third party recomputes it offline from
    the retained bytes with no callback.

    The ``decision_id`` commits to the ancestor read: ``ancestor_reads`` is
    inside the preimage, so mutating any claimed ancestor ``status`` or
    ``coordinate`` diverges the recomputed id. Optional refs, when present, also
    sit inside the preimage so a ref cannot be swapped without diverging the id.

    Authority stays verifier-side: the record proves *what* was read and *which*
    source (by digest); the verifier policy proves whether that source is
    authoritative for the element. Naming a source here confers no authority.
    """

    capability_digest: str
    request_digest: str
    boundary_id: str
    decision: str
    verifier: str
    policy_version: str
    ancestor_reads: list[AncestorRead]
    decision_id: str = ""
    signature: dict[str, str] | None = None
    approval_receipt_ref: str | None = None
    revocation_record_ref: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CascadeDecisionRecord":
        return cls(
            capability_digest=data["capability_digest"],
            request_digest=data["request_digest"],
            boundary_id=data["boundary_id"],
            decision=data["decision"],
            verifier=data["verifier"],
            policy_version=data["policy_version"],
            ancestor_reads=[
                AncestorRead.from_dict(read) for read in data["ancestor_reads"]
            ],
            decision_id=data.get("decision_id", ""),
            signature=data.get("signature"),
            approval_receipt_ref=data.get("approval_receipt_ref"),
            revocation_record_ref=data.get("revocation_record_ref"),
        )

    def preimage(self) -> dict[str, Any]:
        """The bound fields the ``decision_id`` commits to.

        Excludes ``decision_id`` and ``signature`` (a hash/signature cannot
        commit to itself). Optional refs are INCLUDED when present so the id
        commits to them. This is the exact object fed to the JCS canonicalizer
        for both the ``decision_id`` digest and the signing bytes.
        """
        data: dict[str, Any] = {
            "capability_digest": self.capability_digest,
            "request_digest": self.request_digest,
            "boundary_id": self.boundary_id,
            "decision": self.decision,
            "verifier": self.verifier,
            "policy_version": self.policy_version,
            "ancestor_reads": [read.to_dict() for read in self.ancestor_reads],
        }
        if self.approval_receipt_ref is not None:
            data["approval_receipt_ref"] = self.approval_receipt_ref
        if self.revocation_record_ref is not None:
            data["revocation_record_ref"] = self.revocation_record_ref
        return data

    def to_dict(self) -> dict[str, Any]:
        data = self.preimage()
        data["decision_id"] = self.decision_id
        data["signature"] = self.signature or {"alg": "EdDSA", "value": ""}
        return data


@dataclass(kw_only=True)
class RevocationRecord:
    revocation_id: str
    revoked_artifact_id: str
    revoked_artifact_type: str
    revocation_scope: str
    issuer_did: str
    issued_at: str
    effective_at: str
    reason: str
    references: list[dict[str, Any]]
    cascade_depth: int = 3
    signature: dict[str, str] | None = None
    supersedes: str | None = None
    extensions: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RevocationRecord":
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "revocation_id": self.revocation_id,
            "revoked_artifact_id": self.revoked_artifact_id,
            "revoked_artifact_type": self.revoked_artifact_type,
            "revocation_scope": self.revocation_scope,
            "issuer_did": self.issuer_did,
            "issued_at": self.issued_at,
            "effective_at": self.effective_at,
            "reason": self.reason,
            "references": self.references,
            "cascade_depth": self.cascade_depth,
            "signature": self.signature or {"alg": "EdDSA", "value": ""},
        }
        if self.supersedes is not None:
            data["supersedes"] = self.supersedes
        if self.extensions is not None:
            data["extensions"] = self.extensions
        return data
