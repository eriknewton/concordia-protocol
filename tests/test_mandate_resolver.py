"""WP4 regression suite: resolver-based mandate verification (v0.4.1).

Covers the verifier-hook surface that takes a URN reference + a
caller-supplied resolver callable per the A2CN trust contract, plus
the RFC 8785 canonicalization round-trip at the mandate layer and the
revoked-at surface that lets session policy decide revocation
semantics.

Scenarios (drives every contract point from the WP4 spec):

  1. Resolver hit + valid proof at DID-VC tier         → valid=True
  2. Resolver hit + invalid proof at DID-VC tier       → valid=False,
     failure_reason="invalid_proof"
  3. Resolver miss                                      → valid=False,
     failure_reason="resolver_miss" (session policy decides hard-fail
     vs soft-degrade against the SAME VerificationResult)
  4. Resolver exception                                  → ResolverError
     propagates (NOT swallowed as a soft miss)
  5. Resolved mandate carries revoked_at                 → VerificationResult
     exposes the timestamp; verifier does NOT short-circuit
  6. RFC 8785 canonicalization round-trip                → sign(canonicalize)
     + verify_signature(canonicalize) succeeds on the resolved mandate;
     spec name ``RFC8785-JCS`` is surfaced via ``JCS_SPEC_ID``
  7. Multi-tier behavior                                  → basic tier returns
     resolver answer authoritatively (no proof step); DID-VC tier runs the
     proof step (and rejects when issuer_public_key is absent)

Plus invariants:

 - Tier sanity check refuses unknown tier strings.
 - Resolved mandate is surfaced on the result (``mandate`` field).
 - Basic-tier result with revoked_at still flags valid=True and emits
   a warning, so session policy can branch without re-fetching.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

from concordia.canonicalization import (
    JCS_SPEC_ID,
    canonicalize_jcs,
    canonicalize_mandate,
)
from concordia.mandate import sign_mandate
from concordia.mandate_resolver import (
    FailureReason,
    MandateResolver,
    ResolverError,
    Tier,
    VALID_TIERS,
    verify_mandate_with_resolver,
)
from concordia.models.mandate import (
    Mandate,
    MandateStatus,
    MandateVerificationResult,
    TemporalMode,
    ValidityWindow,
)
from concordia.signing import KeyPair, canonical_json, verify_signature


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def issuer_keypair() -> KeyPair:
    return KeyPair.generate()


@pytest.fixture
def other_keypair() -> KeyPair:
    """A different keypair used to forge mismatched signatures."""
    return KeyPair.generate()


def _windowed_validity(seconds_before: int = -3600, seconds_after: int = 3600) -> ValidityWindow:
    now = datetime.now(timezone.utc)
    nb = now + timedelta(seconds=seconds_before)
    na = now + timedelta(seconds=seconds_after)
    return ValidityWindow(
        mode=TemporalMode.WINDOWED,
        not_before=nb.strftime("%Y-%m-%dT%H:%M:%SZ"),
        not_after=na.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _make_signed_mandate(
    keypair: KeyPair,
    *,
    revoked_at: Optional[str] = None,
    mandate_id: Optional[str] = None,
) -> Mandate:
    constraints = {
        "type": "object",
        "properties": {"max_spend": {"type": "number", "maximum": 1000}},
        "required": ["max_spend"],
    }
    mandate = Mandate.create(
        issuer="did:concordia:issuer-wp4",
        subject="did:concordia:agent-wp4",
        constraints=constraints,
        validity=_windowed_validity(),
    )
    if mandate_id is not None:
        mandate.mandate_id = mandate_id
    if revoked_at is not None:
        mandate.revoked_at = revoked_at
    return sign_mandate(mandate, keypair)


def _fixed_resolver(target: Optional[Mandate]):
    """Build a resolver that returns ``target`` regardless of mandate_ref."""

    def _resolve(_ref: str) -> Optional[Mandate]:
        return target

    return _resolve


# ---------------------------------------------------------------------------
# Scenario 1: resolver hit + valid proof at DID-VC tier
# ---------------------------------------------------------------------------


class TestResolverHitValidProof:
    def test_did_vc_tier_with_valid_proof_returns_valid_true(
        self, issuer_keypair: KeyPair
    ) -> None:
        mandate = _make_signed_mandate(issuer_keypair)
        result = verify_mandate_with_resolver(
            mandate.mandate_id,
            _fixed_resolver(mandate),
            tier=Tier.DID_VC,
            issuer_public_key=issuer_keypair.public_key,
        )
        assert result.valid is True
        assert result.failure_reason is None
        assert result.tier == Tier.DID_VC
        assert result.mandate is mandate
        assert result.mandate_id == mandate.mandate_id
        # The classical proof checks all ran (schema / signature /
        # temporal / constraints / delegation / revocation).
        for check_name in (
            "schema",
            "issuer_signature",
            "temporal_validity",
            "constraint_compliance",
        ):
            assert result.checks.get(check_name) is True, check_name

    def test_basic_tier_returns_valid_true_without_running_proof(
        self, issuer_keypair: KeyPair
    ) -> None:
        mandate = _make_signed_mandate(issuer_keypair)
        result = verify_mandate_with_resolver(
            mandate.mandate_id,
            _fixed_resolver(mandate),
            tier=Tier.BASIC,
        )
        assert result.valid is True
        assert result.tier == Tier.BASIC
        # Basic tier does NOT run the proof check; only the resolver-hit
        # and reference binding checks are recorded.
        assert result.checks == {"resolver_hit": True, "ref_binding": True}
        assert result.failure_reason is None


class TestResolverRefBinding:
    def test_basic_tier_ref_mismatch_denies(self, issuer_keypair: KeyPair) -> None:
        requested_ref = "urn:concordia:mandate:requested"
        returned = _make_signed_mandate(
            issuer_keypair,
            mandate_id="urn:concordia:mandate:returned",
        )

        result = verify_mandate_with_resolver(
            requested_ref,
            _fixed_resolver(returned),
            tier=Tier.BASIC,
        )

        assert result.valid is False
        assert result.failure_reason == FailureReason.REF_MISMATCH
        assert result.checks["ref_binding"] is False

    def test_did_vc_tier_ref_mismatch_denies_before_proof(
        self, issuer_keypair: KeyPair
    ) -> None:
        requested_ref = "urn:concordia:mandate:requested"
        returned = _make_signed_mandate(
            issuer_keypair,
            mandate_id="urn:concordia:mandate:returned",
        )

        result = verify_mandate_with_resolver(
            requested_ref,
            _fixed_resolver(returned),
            tier=Tier.DID_VC,
            issuer_public_key=issuer_keypair.public_key,
        )

        assert result.valid is False
        assert result.failure_reason == FailureReason.REF_MISMATCH
        assert "issuer_signature" not in result.checks

    def test_basic_tier_revoked_status_denies(self, issuer_keypair: KeyPair) -> None:
        mandate = _make_signed_mandate(issuer_keypair)
        mandate.status = MandateStatus.REVOKED
        mandate = sign_mandate(mandate, issuer_keypair)

        result = verify_mandate_with_resolver(
            mandate.mandate_id,
            _fixed_resolver(mandate),
            tier=Tier.BASIC,
        )

        assert result.valid is False
        assert result.failure_reason == "mandate_revoked"


# ---------------------------------------------------------------------------
# Scenario 2: resolver hit + INVALID proof at DID-VC tier
# ---------------------------------------------------------------------------


class TestResolverHitInvalidProof:
    def test_did_vc_tier_with_wrong_issuer_key_fails(
        self, issuer_keypair: KeyPair, other_keypair: KeyPair
    ) -> None:
        mandate = _make_signed_mandate(issuer_keypair)
        result = verify_mandate_with_resolver(
            mandate.mandate_id,
            _fixed_resolver(mandate),
            tier=Tier.DID_VC,
            issuer_public_key=other_keypair.public_key,
        )
        assert result.valid is False
        assert result.failure_reason == FailureReason.INVALID_PROOF
        assert result.tier == Tier.DID_VC
        # Signature check explicitly failed.
        assert result.checks.get("issuer_signature") is False
        assert any("signature" in e.lower() for e in result.errors)
        # Resolved mandate is still surfaced for downstream forensics.
        assert result.mandate is mandate

    def test_did_vc_tier_missing_issuer_key_returns_missing_issuer_key(
        self, issuer_keypair: KeyPair
    ) -> None:
        mandate = _make_signed_mandate(issuer_keypair)
        result = verify_mandate_with_resolver(
            mandate.mandate_id,
            _fixed_resolver(mandate),
            tier=Tier.DID_VC,
            issuer_public_key=None,
        )
        assert result.valid is False
        assert result.failure_reason == FailureReason.MISSING_ISSUER_KEY
        assert result.tier == Tier.DID_VC
        assert result.mandate is mandate


# ---------------------------------------------------------------------------
# Scenario 3: resolver MISS → caller decides hard-fail vs soft-degrade
# ---------------------------------------------------------------------------


class TestResolverMiss:
    def test_miss_returns_resolver_miss_failure_reason(self) -> None:
        result = verify_mandate_with_resolver(
            "urn:concordia:mandate:does-not-exist",
            _fixed_resolver(None),
            tier=Tier.BASIC,
        )
        assert result.valid is False
        assert result.failure_reason == FailureReason.RESOLVER_MISS
        assert result.mandate is None
        # Did NOT raise — soft miss is caller-decides.

    def test_session_policy_hard_fail_against_miss(self) -> None:
        """Same VerificationResult; session policy = hard fail."""
        result = verify_mandate_with_resolver(
            "urn:concordia:mandate:missing",
            _fixed_resolver(None),
            tier=Tier.DID_VC,
        )

        def session_policy_hard_fail(r: MandateVerificationResult) -> bool:
            return r.valid

        assert session_policy_hard_fail(result) is False

    def test_session_policy_soft_degrade_against_same_miss(self) -> None:
        """Same VerificationResult; session policy = soft degrade.

        Session policy may decide a resolver_miss is acceptable for a
        low-stakes interaction (e.g. let the offer through with a
        flag) instead of hard-failing. The verifier MUST NOT make that
        call; it only surfaces the miss so policy can branch.
        """
        result = verify_mandate_with_resolver(
            "urn:concordia:mandate:missing",
            _fixed_resolver(None),
            tier=Tier.DID_VC,
        )

        def session_policy_soft_degrade(r: MandateVerificationResult) -> bool:
            # Treat resolver_miss as "proceed with caveat" rather than
            # hard refusal.
            if r.failure_reason == FailureReason.RESOLVER_MISS:
                return True
            return r.valid

        assert session_policy_soft_degrade(result) is True


# ---------------------------------------------------------------------------
# Scenario 4: resolver exception → ResolverError propagates
# ---------------------------------------------------------------------------


class TestResolverException:
    def test_resolver_exception_propagates_as_resolver_error(self) -> None:
        def boom(_ref: str) -> Optional[Mandate]:
            raise RuntimeError("transport error")

        with pytest.raises(ResolverError) as excinfo:
            verify_mandate_with_resolver(
                "urn:concordia:mandate:any",
                boom,
                tier=Tier.BASIC,
            )
        # Original exception is chained.
        assert isinstance(excinfo.value.__cause__, RuntimeError)
        assert "transport error" in str(excinfo.value.__cause__)

    def test_resolver_exception_does_not_become_soft_miss(self) -> None:
        """A resolver that raises must NOT silently produce a non-valid
        result with failure_reason=resolver_miss; that would let a
        broken transport masquerade as a clean miss.
        """

        def boom(_ref: str) -> Optional[Mandate]:
            raise ConnectionError("dns failure")

        with pytest.raises(ResolverError):
            verify_mandate_with_resolver(
                "urn:concordia:mandate:any",
                boom,
                tier=Tier.BASIC,
            )


# ---------------------------------------------------------------------------
# Scenario 5: revoked_at surface (verifier does NOT short-circuit)
# ---------------------------------------------------------------------------


class TestRevokedAtSurface:
    def test_revoked_at_is_exposed_on_result_basic_tier(
        self, issuer_keypair: KeyPair
    ) -> None:
        ts = "2026-05-09T12:00:00Z"
        mandate = _make_signed_mandate(issuer_keypair, revoked_at=ts)
        result = verify_mandate_with_resolver(
            mandate.mandate_id,
            _fixed_resolver(mandate),
            tier=Tier.BASIC,
        )
        # Verifier does NOT short-circuit on revoked_at — session
        # policy decides. Result still reports valid=True for basic
        # tier when the resolver hit and no proof failure.
        assert result.valid is True
        assert result.revoked_at == ts
        # And a warning surfaces so operators can see the field
        # travelled through.
        assert any("revoked_at" in w for w in result.warnings)

    def test_revoked_at_is_exposed_on_result_did_vc_tier(
        self, issuer_keypair: KeyPair
    ) -> None:
        ts = "2026-05-09T12:00:00Z"
        mandate = _make_signed_mandate(issuer_keypair, revoked_at=ts)
        result = verify_mandate_with_resolver(
            mandate.mandate_id,
            _fixed_resolver(mandate),
            tier=Tier.DID_VC,
            issuer_public_key=issuer_keypair.public_key,
        )
        assert result.valid is True
        assert result.revoked_at == ts

    def test_session_policy_can_hard_stop_on_revoked_at(
        self, issuer_keypair: KeyPair
    ) -> None:
        ts = "2026-05-09T12:00:00Z"
        mandate = _make_signed_mandate(issuer_keypair, revoked_at=ts)
        result = verify_mandate_with_resolver(
            mandate.mandate_id,
            _fixed_resolver(mandate),
            tier=Tier.BASIC,
        )

        def hard_stop_on_revocation(r: MandateVerificationResult) -> bool:
            if r.revoked_at is not None:
                return False
            return r.valid

        assert hard_stop_on_revocation(result) is False
        # But the verifier itself flagged valid=True — the hard stop
        # is a session-policy decision, not a protocol invariant.
        assert result.valid is True

    def test_session_policy_can_grace_revoked_at(
        self, issuer_keypair: KeyPair
    ) -> None:
        """Grace-period policy: accept revocations older than 30 days."""
        revoked_60_days_ago = (
            datetime.now(timezone.utc) - timedelta(days=60)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        revoked_5_min_ago = (
            datetime.now(timezone.utc) - timedelta(minutes=5)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        old_revocation_mandate = _make_signed_mandate(
            issuer_keypair,
            revoked_at=revoked_60_days_ago,
            mandate_id="urn:concordia:mandate:old-revocation",
        )
        new_revocation_mandate = _make_signed_mandate(
            issuer_keypair,
            revoked_at=revoked_5_min_ago,
            mandate_id="urn:concordia:mandate:new-revocation",
        )

        def grace_policy(r: MandateVerificationResult, *, grace_days: int = 30) -> bool:
            if r.revoked_at is None:
                return r.valid
            revoked = datetime.fromisoformat(r.revoked_at.replace("Z", "+00:00"))
            age = datetime.now(timezone.utc) - revoked
            return r.valid and age < timedelta(days=grace_days)

        old_result = verify_mandate_with_resolver(
            old_revocation_mandate.mandate_id,
            _fixed_resolver(old_revocation_mandate),
            tier=Tier.BASIC,
        )
        new_result = verify_mandate_with_resolver(
            new_revocation_mandate.mandate_id,
            _fixed_resolver(new_revocation_mandate),
            tier=Tier.BASIC,
        )

        # 60-day-old revocation fails the 30-day grace policy.
        assert grace_policy(old_result) is False
        # 5-minute-old revocation is still inside the grace window.
        assert grace_policy(new_result) is True


# ---------------------------------------------------------------------------
# Scenario 6: RFC 8785 canonicalization round-trip
# ---------------------------------------------------------------------------


class TestRFC8785Canonicalization:
    def test_jcs_spec_id_is_surfaced(self) -> None:
        assert JCS_SPEC_ID == "RFC8785-JCS"

    def test_canonicalize_jcs_matches_signing_canonical_json(self) -> None:
        """The public JCS surface produces the same bytes as the
        load-bearing implementation in concordia.signing.
        """
        data = {"b": 2, "a": 1, "nested": {"y": [3, 2, 1], "x": "α"}}
        jcs_bytes = canonicalize_jcs(data)
        legacy_bytes = canonical_json(data)
        assert jcs_bytes == legacy_bytes

    def test_canonicalize_jcs_sorts_keys_and_omits_whitespace(self) -> None:
        out = canonicalize_jcs({"b": 1, "a": 2}).decode()
        assert out == '{"a":2,"b":1}'

    def test_canonicalize_jcs_preserves_non_ascii_raw(self) -> None:
        out = canonicalize_jcs({"k": "αβγ"}).decode()
        # RFC 8785 / V8 JSON.stringify emits non-ASCII raw, not escaped.
        assert "αβγ" in out

    def test_canonicalize_jcs_rejects_nan(self) -> None:
        with pytest.raises(ValueError):
            canonicalize_jcs({"k": float("nan")})

    def test_canonicalize_mandate_strips_signature_field(
        self, issuer_keypair: KeyPair
    ) -> None:
        mandate = _make_signed_mandate(issuer_keypair)
        assert mandate.signature != ""
        canonical_bytes = canonicalize_mandate(mandate)
        # Signature field must NOT appear in the canonical output.
        assert b'"signature"' not in canonical_bytes

    def test_canonicalize_mandate_accepts_dict_and_object_identically(
        self, issuer_keypair: KeyPair
    ) -> None:
        mandate = _make_signed_mandate(issuer_keypair)
        from_obj = canonicalize_mandate(mandate)
        from_dict = canonicalize_mandate(mandate.to_dict())
        assert from_obj == from_dict

    def test_jcs_canonicalization_round_trip_verifies_signature(
        self, issuer_keypair: KeyPair
    ) -> None:
        """End-to-end round-trip: sign over canonical bytes, verify
        signature against the same canonical bytes. The classical
        sign/verify already uses canonical_json; this test asserts the
        named JCS surface is equivalent.
        """
        mandate = _make_signed_mandate(issuer_keypair)
        signable = {k: v for k, v in mandate.to_dict().items() if k != "signature"}
        # The signing path used canonical_json; verify against the JCS
        # alias to prove byte equivalence.
        assert canonical_json(signable) == canonicalize_jcs(signable)
        assert verify_signature(
            signable,
            mandate.signature,
            issuer_keypair.public_key,
            alg=mandate.algorithm,
        )


# ---------------------------------------------------------------------------
# Scenario 7: multi-tier behavior
# ---------------------------------------------------------------------------


class TestMultiTierBehavior:
    def test_basic_and_did_vc_diverge_on_invalid_proof(
        self, issuer_keypair: KeyPair, other_keypair: KeyPair
    ) -> None:
        """Same mandate, same resolver, different tier → different valid.

        Basic tier trusts the resolver answer. DID-VC tier additionally
        verifies the cryptographic proof; a mandate signed with the
        wrong key passes basic but fails DID-VC.
        """
        mandate = _make_signed_mandate(issuer_keypair)
        resolver = _fixed_resolver(mandate)

        basic = verify_mandate_with_resolver(
            mandate.mandate_id,
            resolver,
            tier=Tier.BASIC,
        )
        did_vc = verify_mandate_with_resolver(
            mandate.mandate_id,
            resolver,
            tier=Tier.DID_VC,
            issuer_public_key=other_keypair.public_key,
        )
        assert basic.valid is True
        assert did_vc.valid is False
        assert did_vc.failure_reason == FailureReason.INVALID_PROOF

    def test_unknown_tier_string_is_refused_before_resolver_call(
        self, issuer_keypair: KeyPair
    ) -> None:
        """Tier sanity check happens BEFORE the resolver is called, so
        a typo cannot accidentally hit the resolver.
        """
        calls: list[str] = []

        def tracking_resolver(ref: str) -> Optional[Mandate]:
            calls.append(ref)
            return _make_signed_mandate(issuer_keypair)

        result = verify_mandate_with_resolver(
            "urn:concordia:mandate:typo",
            tracking_resolver,
            tier="silver",  # not a real tier
        )
        assert result.valid is False
        assert result.failure_reason == FailureReason.INVALID_TIER
        # Resolver was NOT called.
        assert calls == []

    def test_valid_tiers_constant_matches_attributes(self) -> None:
        assert Tier.BASIC in VALID_TIERS
        assert Tier.DID_VC in VALID_TIERS
        # Adding a new tier requires updating both the class and the set.
        assert len(VALID_TIERS) == 2

    def test_resolver_protocol_accepts_plain_callable(
        self, issuer_keypair: KeyPair
    ) -> None:
        """Resolvers may be plain callables; the Protocol is purely
        documentation + a structural type-check surface.
        """
        mandate = _make_signed_mandate(issuer_keypair)

        def plain(_ref: str) -> Optional[Mandate]:
            return mandate

        assert isinstance(plain, MandateResolver)


# ---------------------------------------------------------------------------
# Result-shape invariants
# ---------------------------------------------------------------------------


class TestResultShape:
    def test_to_dict_round_trips_wp4_fields(
        self, issuer_keypair: KeyPair
    ) -> None:
        ts = "2026-05-09T12:00:00Z"
        mandate = _make_signed_mandate(issuer_keypair, revoked_at=ts)
        result = verify_mandate_with_resolver(
            mandate.mandate_id,
            _fixed_resolver(mandate),
            tier=Tier.BASIC,
        )
        d = result.to_dict()
        assert d["valid"] is True
        assert d["tier"] == Tier.BASIC
        assert d["revoked_at"] == ts
        assert d["mandate"]["mandate_id"] == mandate.mandate_id

    def test_to_dict_omits_optional_fields_when_absent(self) -> None:
        result = MandateVerificationResult(valid=True)
        d = result.to_dict()
        assert "failure_reason" not in d
        assert "revoked_at" not in d
        assert "tier" not in d
        assert "mandate" not in d
