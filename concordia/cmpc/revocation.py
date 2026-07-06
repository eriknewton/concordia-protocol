"""RevocationRecord signing and cascade verification."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from concordia.predicate import PredicateFailureReason
from concordia.signing import KeyPair

from .canonical import (
    canonicalize_cascade_decision_record,
    canonicalize_revocation_record,
)
from .schemas import validate_cascade_decision_record, validate_revocation_record
from .types import (
    AncestorRead,
    CascadeDecisionRecord,
    RevocationRecord,
    RevocationScope,
)

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
    # Committed, recomputable terminal-deny records — one per inadmissible
    # artifact — emitted alongside the live `inadmissible` list. Defaults to an
    # empty list so existing consumers that read only `inadmissible` are
    # unaffected; callers that want the durable, offline-recomputable terminal
    # read `decisions`. Populated only when the caller supplies the boundary
    # context needed to build a committed record (see `cascade_revocation`).
    decisions: list[CascadeDecisionRecord] = field(default_factory=list)


def _decision_id(record: CascadeDecisionRecord) -> str:
    """SHA-256 hex over the RFC 8785 JCS bytes of the bound preimage."""
    return hashlib.sha256(canonicalize_cascade_decision_record(record)).hexdigest()


def emit_cascade_decision(
    *,
    capability_digest: str,
    request_digest: str,
    boundary_id: str,
    verifier: str,
    policy_version: str,
    ancestor_reads: Sequence[AncestorRead],
    approval_receipt_ref: str | None = None,
    revocation_record_ref: str | None = None,
) -> CascadeDecisionRecord:
    """Build an UNSIGNED committed terminal-deny record from the re-derived reads.

    The decision is always ``"deny"``: this primitive exists only to commit a
    terminal deny. ``ancestor_reads`` is the exact set of ancestor observations
    the verifier re-derived through (proving what/which-source-at-which-
    coordinate was read), and must be non-empty — a deny that commits to no
    ancestor read is refused by the schema. ``decision_id`` and ``signature``
    are filled in by ``sign_cascade_decision_record``.
    """
    return CascadeDecisionRecord(
        capability_digest=capability_digest,
        request_digest=request_digest,
        boundary_id=boundary_id,
        decision="deny",
        verifier=verifier,
        policy_version=policy_version,
        ancestor_reads=list(ancestor_reads),
        approval_receipt_ref=approval_receipt_ref,
        revocation_record_ref=revocation_record_ref,
    )


def sign_cascade_decision_record(
    record: CascadeDecisionRecord, key_pair: KeyPair
) -> CascadeDecisionRecord:
    """Compute ``decision_id`` and sign a ``CascadeDecisionRecord``.

    ``decision_id = SHA-256(JCS(preimage))`` and the Ed25519 signature covers
    the SAME preimage bytes (excluding ``decision_id`` and ``signature``), via
    the shared cascade canonicalizer — the identical signing path as
    ``sign_revocation_record``. The signed record is schema-validated before it
    is returned, so an ill-formed record never leaves this function.
    """
    unsigned = replace(record, decision_id="", signature={"alg": "EdDSA", "value": ""})
    preimage_bytes = canonicalize_cascade_decision_record(unsigned)
    decision_id = hashlib.sha256(preimage_bytes).hexdigest()
    signature = base64.urlsafe_b64encode(
        key_pair.private_key.sign(preimage_bytes)
    ).decode()
    signed = replace(
        unsigned,
        decision_id=decision_id,
        signature={"alg": "EdDSA", "value": signature},
    )
    validate_cascade_decision_record(signed.to_dict())
    return signed


def verify_cascade_decision_record(
    record: Mapping[str, Any], public_key: Ed25519PublicKey
) -> bool:
    """Fail-closed verify over the RETAINED BYTES, not a normalized round-trip.

    RAW-MAPPING-ONLY. This function verifies ONLY the raw mapping as received
    (the JSON bytes a third party retained). It deliberately does NOT accept an
    already-parsed ``CascadeDecisionRecord``: a typed record has ALREADY passed
    through ``from_dict``, which silently DROPS any unknown field (e.g. a
    smuggled ``deal_terms`` inside an ``ancestor_reads[]`` element). Once the
    original bytes are lost, the record cannot be securely verified — a
    normalizing round-trip would re-serialize a laundered body and false-pass.
    A typed instance is therefore REJECTED (see below): the only secure path is
    to hand this function the raw retained mapping/bytes. The steps, all on the
    raw bytes:

      1. STRICT schema-validate the raw object. ``additionalProperties: false``
         at the top level AND inside every ``ancestor_reads[]`` element means an
         unknown/extra field is REJECTED here, never dropped — this is what
         defends the no-raw-deal-terms privacy invariant and fail-closed
         mutation rejection.
      2. Recompute ``decision_id = SHA-256(JCS(preimage))`` over the raw bytes
         (preimage = the raw object minus ``decision_id`` + ``signature``) and
         require it equals the claimed ``decision_id``. A mutated field —
         including a claimed ancestor ``status`` or ``coordinate``, or a swapped
         ref — diverges the id and is rejected.
      3. Verify the Ed25519 signature over those SAME raw preimage bytes.

    ANY failure (validation, hash mismatch, bad signature, malformed input, or a
    typed record handed in place of raw bytes) returns False; it never raises and
    never degrades to allow. A typed record is only constructed AFTER all three
    pass; this function returns a bool, so it constructs none.
    """
    try:
        # A typed/normalized object has already lost the original bytes (unknown
        # fields dropped by from_dict), so it CANNOT be securely verified. Refuse
        # it explicitly: callers must pass the raw retained mapping, not a parsed
        # record. Fail closed (return False), never re-serialize-and-trust.
        if isinstance(record, CascadeDecisionRecord):
            return False
        raw: Mapping[str, Any] = record
        if not isinstance(raw, Mapping):
            return False
        # 1. Strict-validate the RAW object: extra/unknown fields are rejected.
        validate_cascade_decision_record(dict(raw))
        # 2. Recompute over the raw preimage bytes (strips decision_id +
        #    signature only; every OTHER field, incl. any that slipped past a
        #    non-strict caller, is inside the preimage).
        preimage_bytes = canonicalize_cascade_decision_record(raw)
        recomputed = hashlib.sha256(preimage_bytes).hexdigest()
        claimed_id = raw.get("decision_id", "")
        if not isinstance(claimed_id, str) or recomputed != claimed_id:
            return False
        # 3. Verify the signature over the SAME raw preimage bytes.
        signature = raw.get("signature") or {}
        if not isinstance(signature, Mapping):
            return False
        raw_signature = base64.urlsafe_b64decode(
            str(signature.get("value", "")).encode()
        )
        public_key.verify(raw_signature, preimage_bytes)
        return True
    except Exception:
        return False


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


@dataclass(frozen=True, kw_only=True)
class CascadeBoundary:
    """Verifier-side boundary context for emitting committed terminal denies.

    Supplied by the caller to ``cascade_revocation`` when it wants a committed
    ``CascadeDecisionRecord`` alongside each live ``InadmissibleArtifact``. It
    carries the boundary-wide identity fields of the decision object
    (``boundary_id``, ``verifier``, ``policy_version``) plus the ancestor
    ``source_digest`` and ``coordinate`` that the verifier read the revocation
    status FROM.

    The ``source_digest`` + ``coordinate`` are the verifier's re-derived read of
    the status source: the ``coordinate`` is intended to be that source's own
    ordering position, which the caller obtains from the pinned status history.
    It is COMMITTED (inside the ``decision_id`` preimage) and a non-negative
    integer; the primitive does not prove the integer is a genuine pinned source
    ordinal rather than, e.g., a wall-clock epoch value. Whether it names a real
    position in an authoritative source is verifier-side policy. A caller that
    cannot pin the coordinate must not synthesize one; it refuses to emit rather
    than default (this dataclass makes ``coordinate`` mandatory).

    ``capability_digest`` and ``request_digest`` describe the child artifact and
    invocation being evaluated at the boundary; they default to the child's own
    ``artifact_id`` digest when the caller does not resolve them per artifact.
    """

    boundary_id: str
    verifier: str
    policy_version: str
    source_digest: str
    coordinate: int
    capability_digest: str | None = None
    request_digest: str | None = None
    approval_receipt_ref: str | None = None


def _sha256_hex(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _emit_committed_deny(
    *,
    artifact_id: str,
    revocation: RevocationRecord,
    boundary: CascadeBoundary,
    signing_key: KeyPair,
) -> CascadeDecisionRecord:
    """Build + sign the committed terminal deny for one inadmissible artifact.

    The ancestor read binds the revoked element digest, its observed status
    (``revoked``), the status source read, and the committed coordinate (a
    non-negative integer; source authenticity is verifier-side policy) — the
    exact tuple the verifier re-derived through. The withdrawal is carried as
    ``revocation_record_ref`` inside the preimage so the id commits to it.
    """
    ancestor_read = AncestorRead(
        element_digest=revocation.revoked_artifact_id,
        status="revoked",
        source_digest=boundary.source_digest,
        coordinate=boundary.coordinate,
    )
    record = emit_cascade_decision(
        capability_digest=boundary.capability_digest or _sha256_hex(artifact_id),
        request_digest=boundary.request_digest or _sha256_hex(artifact_id),
        boundary_id=boundary.boundary_id,
        verifier=boundary.verifier,
        policy_version=boundary.policy_version,
        ancestor_reads=[ancestor_read],
        approval_receipt_ref=boundary.approval_receipt_ref,
        revocation_record_ref=revocation.revocation_id,
    )
    return sign_cascade_decision_record(record, signing_key)


def cascade_revocation(
    revocation: RevocationRecord,
    candidate_artifacts: Sequence[CandidateArtifact],
    *,
    boundary: CascadeBoundary | None = None,
    signing_key: KeyPair | None = None,
) -> CascadeResult:
    """Return the artifacts rendered inadmissible by ``revocation``.

    Backward-compatible default: with no ``boundary``/``signing_key``, the
    result's ``decisions`` list is empty and only the live ``inadmissible``
    list is populated (the pre-existing behavior).

    When BOTH ``boundary`` and ``signing_key`` are supplied, each inadmissible
    artifact ALSO gets a committed, recomputable ``CascadeDecisionRecord`` in
    ``result.decisions`` — the durable terminal deny whose ``decision_id``
    commits to the ancestor read. Emitting a committed record needs the boundary
    identity + the ancestor coordinate (committed, a non-negative integer; its
    source authenticity is verifier-side policy), which is why it is opt-in and
    fails closed (no committed record without both).
    """
    validate_revocation_record(revocation.to_dict())
    emit = boundary is not None and signing_key is not None
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
    decisions: list[CascadeDecisionRecord] = []
    if emit:
        assert boundary is not None and signing_key is not None
        decisions.append(
            _emit_committed_deny(
                artifact_id=revoked_id,
                revocation=revocation,
                boundary=boundary,
                signing_key=signing_key,
            )
        )
    seen = {revoked_id}
    frontier = [(revoked_id, 0, {revoked_id})]

    if revocation.revocation_scope == RevocationScope.SINGLE_ARTIFACT.value:
        return CascadeResult(inadmissible=inadmissible, decisions=decisions)

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
                if emit:
                    assert boundary is not None and signing_key is not None
                    decisions.append(
                        _emit_committed_deny(
                            artifact_id=candidate.artifact_id,
                            revocation=revocation,
                            boundary=boundary,
                            signing_key=signing_key,
                        )
                    )
            frontier.append((candidate.artifact_id, next_depth, path | {candidate.artifact_id}))

    return CascadeResult(inadmissible=inadmissible, decisions=decisions)


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
    "CascadeBoundary",
    "CascadeResult",
    "InadmissibleArtifact",
    "cascade_revocation",
    "emit_cascade_decision",
    "find_revocation_for_references",
    "sign_cascade_decision_record",
    "sign_revocation_record",
    "verify_cascade_decision_record",
    "verify_revocation_record",
]
