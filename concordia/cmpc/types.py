"""CMPC bilateral primitive dataclasses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from concordia.cmpc.chain_session import ChainSession, ChainSessionState


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
