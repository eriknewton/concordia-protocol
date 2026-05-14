"""WP4: resolver-based mandate verification (v0.4.1).

The classical ``concordia.mandate.verify_mandate`` takes a fully-formed
Mandate object plus the issuer's public key. WP4 introduces a parallel
entry point keyed by a mandate URN reference and a resolver callable
matching the contract A2CN settled on:

    def resolve(mandate_ref: str) -> Optional[Mandate]: ...

Trust contract (from the A2CN coordination thread):

 - The resolver is the authority for the declared trust tier.
 - On hit, the resolver returns a Mandate object. Hit semantics depend
   on the tier (see below).
 - On miss, the resolver returns ``None`` and the caller (session
   policy) decides whether to hard-fail or soft-degrade.
 - Resolver exceptions propagate as protocol errors (NOT soft misses).
   Wrapped as :class:`ResolverError` for callers that want a single
   except surface.
 - Sync for v0.4.1. Async is a v0.4.2 question for high-latency DID
   resolution paths.

Trust tiers:

 - ``Tier.BASIC``: the resolver answer is authoritative on its own.
   No additional cryptographic check is performed. Suitable for
   internal trust roots where the resolver IS the audit boundary.

 - ``Tier.DID_VC``: two-step trust. (1) the resolver returns the
   mandate; (2) the verifier checks the cryptographic proof on the
   returned mandate against the issuer's public key (which the caller
   supplies). This is the SD-JWT-adjacent / W3C VC tier. The proof
   check delegates to the classical :func:`concordia.mandate.verify_mandate`
   so all existing temporal / constraint / delegation / revocation
   checks apply.

Revocation mid-session (operator-decision per the 2026-05-10 thread):

  Option A: the resolver returns a ``revoked_at`` timestamp on
  resolved mandates when revocation is on file. The verifier surfaces
  that timestamp on :class:`MandateVerificationResult` but does NOT
  short-circuit. The session-policy layer decides whether to hard
  stop, grant grace, or re-check per offer. The verifier MAY emit a
  warning so downstream operators can see the field travelled through.

  The classical verifier's HTTP-endpoint revocation check
  (``check_revocation``) still applies on the DID-VC tier when the
  resolved mandate carries a ``revocation_endpoint``; that is the
  classical fail-closed path. The new ``revoked_at`` surface is for
  resolver-provided knowledge, not endpoint polling.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional, Protocol, runtime_checkable

from .mandate import verify_mandate as _verify_resolved_mandate
from .models.mandate import (
    Mandate,
    MandateStatus,
    MandateVerificationResult,
)


# ---------------------------------------------------------------------------
# Public tier constants
# ---------------------------------------------------------------------------


class Tier:
    """Trust tier identifiers passed to :func:`verify_mandate_with_resolver`.

    Not an :class:`enum.Enum` so callers can pass plain strings without
    importing this module (matches the rest of Concordia's
    string-literal tier conventions).
    """

    BASIC = "basic"
    DID_VC = "did-vc"


VALID_TIERS = frozenset({Tier.BASIC, Tier.DID_VC})


# ---------------------------------------------------------------------------
# Resolver protocol + error
# ---------------------------------------------------------------------------


@runtime_checkable
class MandateResolver(Protocol):
    """Sync resolver protocol per the A2CN contract.

    Implementations MAY also be plain callables; this Protocol is
    primarily a documentation aid and an ``isinstance`` surface for
    callers that want a structural type-check.
    """

    def __call__(self, mandate_ref: str) -> Optional[Mandate]: ...


class ResolverError(Exception):
    """Wraps an exception raised by the resolver.

    Use this to distinguish protocol errors (resolver itself errored)
    from soft misses (resolver returned ``None``). The original
    exception is chained via ``__cause__``.
    """


# ---------------------------------------------------------------------------
# Failure reason constants — single-string summaries for session policy
# ---------------------------------------------------------------------------


class FailureReason:
    """Stable string codes on :class:`MandateVerificationResult.failure_reason`."""

    RESOLVER_MISS = "resolver_miss"
    INVALID_TIER = "invalid_tier"
    MISSING_ISSUER_KEY = "missing_issuer_key"
    INVALID_PROOF = "invalid_proof"
    SCHEMA_INVALID = "schema_invalid"
    REF_MISMATCH = "ref_mismatch"


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


def verify_mandate_with_resolver(
    mandate_ref: str,
    resolver: Callable[[str], Optional[Mandate]],
    *,
    tier: str = Tier.BASIC,
    issuer_public_key: Any = None,
    now: Optional[datetime] = None,
    sequence_key: Optional[str] = None,
    state_active: Optional[bool] = None,
    action: Optional[dict[str, Any]] = None,
    delegation_public_keys: Optional[dict[str, Any]] = None,
    check_revocation_status: bool = True,
    revocation_timeout: float = 5.0,
) -> MandateVerificationResult:
    """Verify a mandate by URN reference using a caller-supplied resolver.

    See module docstring for the resolver contract, tier semantics, and
    revocation-mid-session surface.

    Args:
        mandate_ref: The mandate URN identifier (``urn:concordia:mandate:...``).
            Passed verbatim to the resolver; this function does not
            interpret URN structure.
        resolver: Sync callable matching the A2CN contract. Receives
            ``mandate_ref`` and returns the :class:`Mandate` on hit or
            ``None`` on miss. Exceptions propagate (wrapped in
            :class:`ResolverError`).
        tier: Trust tier. ``Tier.BASIC`` returns the resolver's answer
            as-is; ``Tier.DID_VC`` runs the classical cryptographic
            verifier on the resolved mandate. Invalid tier strings
            return a failed result with ``failure_reason="invalid_tier"``.
        issuer_public_key: Required for ``Tier.DID_VC``. Ed25519 or
            EC public key the classical verifier checks the mandate
            signature against. Missing for DID-VC tier returns
            ``failure_reason="missing_issuer_key"``.
        now, sequence_key, state_active, action, delegation_public_keys,
        check_revocation_status, revocation_timeout:
            Forwarded verbatim to the classical
            :func:`concordia.mandate.verify_mandate` on DID-VC tier.
            Ignored on basic tier.

    Returns:
        :class:`MandateVerificationResult` with the WP4 optional fields
        populated:

        - ``mandate``: the resolved object (or ``None`` on miss).
        - ``failure_reason``: short string code from
          :class:`FailureReason` when ``valid`` is ``False``.
        - ``revoked_at``: surfaced from the resolved mandate when
          present; the verifier does NOT short-circuit.
        - ``tier``: echoes the tier string the verifier ran.

    Raises:
        ResolverError: when the resolver itself raised an exception.
            Soft misses (resolver returned ``None``) do NOT raise; they
            produce a non-valid result with ``failure_reason="resolver_miss"``.
    """
    # --- Tier sanity check (cheap; before any resolver call) ---
    if tier not in VALID_TIERS:
        return MandateVerificationResult(
            valid=False,
            tier=tier,
            failure_reason=FailureReason.INVALID_TIER,
            errors=[
                f"Unknown trust tier {tier!r}; expected one of "
                f"{sorted(VALID_TIERS)}"
            ],
        )

    # --- Call resolver. Exceptions wrap as ResolverError (protocol error). ---
    try:
        resolved = resolver(mandate_ref)
    except Exception as exc:  # noqa: BLE001 — wrap any caller exception
        raise ResolverError(
            f"resolver raised on mandate_ref={mandate_ref!r}: {exc}"
        ) from exc

    # --- Soft miss: caller-decides. NOT raised. ---
    if resolved is None:
        return MandateVerificationResult(
            valid=False,
            tier=tier,
            mandate=None,
            failure_reason=FailureReason.RESOLVER_MISS,
            errors=[f"resolver returned no mandate for ref={mandate_ref!r}"],
        )

    if resolved.mandate_id != mandate_ref:
        return MandateVerificationResult(
            valid=False,
            mandate_id=resolved.mandate_id,
            issuer=resolved.issuer,
            subject=resolved.subject,
            tier=tier,
            mandate=resolved,
            failure_reason=FailureReason.REF_MISMATCH,
            checks={"resolver_hit": True, "ref_binding": False},
            errors=[
                f"resolver returned mandate_id={resolved.mandate_id!r} "
                f"for requested ref={mandate_ref!r}"
            ],
        )

    # --- Revocation surface: pull through but do NOT short-circuit. ---
    # Session policy decides revocation semantics per the 2026-05-10 thread.
    revoked_at = resolved.revoked_at

    if resolved.status != MandateStatus.ACTIVE:
        return MandateVerificationResult(
            valid=False,
            mandate_id=resolved.mandate_id,
            issuer=resolved.issuer,
            subject=resolved.subject,
            mandate=resolved,
            tier=tier,
            revoked_at=revoked_at,
            failure_reason=f"mandate_{resolved.status.value}",
            checks={
                "resolver_hit": True,
                "ref_binding": True,
                "lifecycle_status": False,
            },
            errors=[f"Mandate lifecycle status is {resolved.status.value!r}"],
        )

    # --- Basic tier: resolver answer is authoritative. ---
    if tier == Tier.BASIC:
        result = MandateVerificationResult(
            valid=True,
            mandate_id=resolved.mandate_id,
            issuer=resolved.issuer,
            subject=resolved.subject,
            mandate=resolved,
            tier=tier,
            revoked_at=revoked_at,
            checks={"resolver_hit": True, "ref_binding": True},
        )
        if revoked_at is not None:
            result.warnings.append(
                f"mandate has revoked_at={revoked_at}; session policy decides "
                f"whether to honor"
            )
        return result

    # --- DID-VC tier: two-step. Resolver gave us the mandate;
    # the classical verifier checks the proof against the issuer key. ---
    if issuer_public_key is None:
        return MandateVerificationResult(
            valid=False,
            mandate_id=resolved.mandate_id,
            issuer=resolved.issuer,
            subject=resolved.subject,
            mandate=resolved,
            tier=tier,
            revoked_at=revoked_at,
            failure_reason=FailureReason.MISSING_ISSUER_KEY,
            errors=[
                "DID-VC tier requires issuer_public_key for proof verification"
            ],
        )

    proof_result = _verify_resolved_mandate(
        resolved,
        issuer_public_key=issuer_public_key,
        now=now,
        sequence_key=sequence_key,
        state_active=state_active,
        action=action,
        delegation_public_keys=delegation_public_keys,
        check_revocation_status=check_revocation_status,
        revocation_timeout=revocation_timeout,
    )

    # Merge classical result with WP4 fields. The proof_result already
    # carries valid / mandate_id / issuer / subject / checks / errors /
    # warnings; layer the resolver-side context on top.
    proof_result.mandate = resolved
    proof_result.tier = tier
    proof_result.revoked_at = revoked_at
    proof_result.checks["ref_binding"] = True
    if not proof_result.valid and proof_result.failure_reason is None:
        # Map the most-relevant check name to a stable failure_reason
        # so session policy can branch without parsing free-text errors.
        if proof_result.checks.get("schema") is False:
            proof_result.failure_reason = FailureReason.SCHEMA_INVALID
        else:
            proof_result.failure_reason = FailureReason.INVALID_PROOF
    if revoked_at is not None and proof_result.valid:
        proof_result.warnings.append(
            f"mandate has revoked_at={revoked_at}; session policy decides "
            f"whether to honor"
        )
    return proof_result


__all__ = [
    "FailureReason",
    "MandateResolver",
    "ResolverError",
    "Tier",
    "VALID_TIERS",
    "verify_mandate_with_resolver",
]
