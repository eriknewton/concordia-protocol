"""RevocationRecord signing and cascade verification."""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from concordia.predicate import PredicateFailureReason
from concordia.signing import KeyPair

from .canonical import canonicalize_revocation_record
from .schemas import validate_revocation_record
from .types import RevocationRecord, RevocationScope

CascadeArtifactType = Literal[
    "mandate",
    "commitment",
    "approval_receipt",
    "predicate",
    "attestation",
]

CASCADE_RELATIONSHIPS = {"fulfills", "extends", "approves", "revokes"}


@dataclass(frozen=True, kw_only=True)
class CandidateArtifact:
    artifact_id: str
    artifact_type: CascadeArtifactType
    references: list[dict[str, Any]]


@dataclass(frozen=True, kw_only=True)
class InadmissibleArtifact:
    artifact_id: str
    reason: PredicateFailureReason
    revoked_via_revocation_id: str
    cascade_depth: int
    evidence: str


@dataclass(frozen=True, kw_only=True)
class CascadeResult:
    inadmissible: list[InadmissibleArtifact]


def sign_revocation_record(record: RevocationRecord, key_pair: KeyPair) -> RevocationRecord:
    unsigned = replace(record, signature={"alg": "EdDSA", "value": ""})
    signature = base64.urlsafe_b64encode(
        key_pair.private_key.sign(canonicalize_revocation_record(unsigned))
    ).decode()
    signed = replace(unsigned, signature={"alg": "EdDSA", "value": signature})
    validate_revocation_record(signed.to_dict())
    return signed


def verify_revocation_record(record: RevocationRecord, public_key: Ed25519PublicKey) -> bool:
    try:
        validate_revocation_record(record.to_dict())
        signature = record.signature or {}
        raw_signature = base64.urlsafe_b64decode(signature.get("value", "").encode())
        public_key.verify(raw_signature, canonicalize_revocation_record(record))
        return True
    except Exception:
        return False


def _references_artifact(candidate: CandidateArtifact, artifact_id: str) -> dict[str, Any] | None:
    for reference in candidate.references:
        if (
            isinstance(reference, dict)
            and reference.get("id") == artifact_id
            and reference.get("relationship") in CASCADE_RELATIONSHIPS
        ):
            return reference
    return None


def _evidence(
    artifact_id: str,
    referenced_id: str,
    revocation: RevocationRecord,
) -> str:
    return (
        f"artifact {artifact_id} references {revocation.revoked_artifact_type} "
        f"{referenced_id} which is revoked by {revocation.revocation_id}"
    )


def cascade_revocation(
    revocation: RevocationRecord,
    candidate_artifacts: Sequence[CandidateArtifact],
) -> CascadeResult:
    validate_revocation_record(revocation.to_dict())
    max_depth = min(max(revocation.cascade_depth, 0), 8)
    revoked_id = revocation.revoked_artifact_id
    by_id: Mapping[str, CandidateArtifact] = {
        candidate.artifact_id: candidate for candidate in candidate_artifacts
    }
    inadmissible: list[InadmissibleArtifact] = [
        InadmissibleArtifact(
            artifact_id=revoked_id,
            reason=PredicateFailureReason.REVOKED,
            revoked_via_revocation_id=revocation.revocation_id,
            cascade_depth=0,
            evidence=f"artifact {revoked_id} is revoked by {revocation.revocation_id}",
        )
    ]
    seen = {revoked_id}
    frontier = [(revoked_id, 0, {revoked_id})]

    if revocation.revocation_scope == RevocationScope.SINGLE_ARTIFACT.value:
        return CascadeResult(inadmissible=inadmissible)

    while frontier:
        current_id, current_depth, path = frontier.pop(0)
        if current_depth >= max_depth:
            continue
        for candidate in by_id.values():
            if candidate.artifact_id in path:
                continue
            reference = _references_artifact(candidate, current_id)
            if reference is None:
                continue
            next_depth = current_depth + 1
            if candidate.artifact_id not in seen:
                inadmissible.append(
                    InadmissibleArtifact(
                        artifact_id=candidate.artifact_id,
                        reason=PredicateFailureReason.REVOKED,
                        revoked_via_revocation_id=revocation.revocation_id,
                        cascade_depth=next_depth,
                        evidence=_evidence(candidate.artifact_id, current_id, revocation),
                    )
                )
                seen.add(candidate.artifact_id)
            frontier.append((candidate.artifact_id, next_depth, path | {candidate.artifact_id}))

    return CascadeResult(inadmissible=inadmissible)


def find_revocation_for_references(
    references: Sequence[dict[str, Any]],
    revocation_records: Mapping[str, RevocationRecord] | None,
    *,
    now: datetime | None = None,
) -> RevocationRecord | None:
    if not revocation_records:
        return None
    effective_now = now or datetime.now(timezone.utc)
    if effective_now.tzinfo is None:
        effective_now = effective_now.replace(tzinfo=timezone.utc)
    effective_now = effective_now.astimezone(timezone.utc)
    for reference in references:
        if not isinstance(reference, dict):
            continue
        reference_id = reference.get("id")
        if not isinstance(reference_id, str) or reference_id not in revocation_records:
            continue
        revocation = revocation_records[reference_id]
        effective_at = datetime.fromisoformat(revocation.effective_at.replace("Z", "+00:00"))
        if effective_at.tzinfo is None:
            effective_at = effective_at.replace(tzinfo=timezone.utc)
        if effective_at.astimezone(timezone.utc) <= effective_now:
            return revocation
    return None


__all__ = [
    "CASCADE_RELATIONSHIPS",
    "CandidateArtifact",
    "CascadeResult",
    "InadmissibleArtifact",
    "cascade_revocation",
    "find_revocation_for_references",
    "sign_revocation_record",
    "verify_revocation_record",
]
