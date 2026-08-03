from __future__ import annotations

import pytest

from concordia.agent_profile import (
    AgentCapabilityProfile,
    AgentProfileStore,
    ProfileSignatureError,
    ReputationAssertion,
    TrustSignals,
)
from concordia.signing import KeyPair, canonical_json, sign_message


def _profile(agent_id: str = "did:concordia:agent-profile") -> AgentCapabilityProfile:
    return AgentCapabilityProfile(
        agent_id=agent_id,
        name=agent_id,
        trust_signals=TrustSignals(verascore_composite=80),
    )


def _signed_profile(keypair: KeyPair, agent_id: str = "did:concordia:agent-profile") -> AgentCapabilityProfile:
    profile = _profile(agent_id)
    profile.signature = sign_message(profile.to_canonical_dict(), keypair)
    return profile


def test_valid_profile_signature_sets_verified_true() -> None:
    keypair = KeyPair.generate()
    profile = _signed_profile(keypair)
    store = AgentProfileStore()

    stored = store.publish(profile, public_key_bytes=keypair.public_key_bytes())

    assert stored.verified is True
    assert store.get(profile.agent_id).verified is True


def test_invalid_profile_signature_rejects() -> None:
    signer = KeyPair.generate()
    wrong_key = KeyPair.generate()
    profile = _signed_profile(signer)
    store = AgentProfileStore()

    with pytest.raises(ProfileSignatureError, match="verification failed"):
        store.publish(profile, public_key_bytes=wrong_key.public_key_bytes())

    assert store.get(profile.agent_id) is None


def test_pre_reputation_signature_survives_new_code_round_trip() -> None:
    keypair = KeyPair.generate()
    profile = AgentCapabilityProfile(
        agent_id="did:concordia:signed-before-reputation",
        name="Pre reputation profile",
    )
    old_canonical = profile.to_canonical_dict()
    old_canonical["trust_signals"].pop("reputation", None)
    profile.signature = sign_message(old_canonical, keypair)
    serialized = profile.to_dict()
    serialized["trust_signals"].pop("reputation", None)

    restored = AgentCapabilityProfile.from_dict(serialized)

    assert restored.trust_signals.reputation is None
    assert restored.verify_signature(keypair.public_key) is True


def test_unset_reputation_keeps_canonical_trust_signal_keys_stable() -> None:
    profile = AgentCapabilityProfile(
        agent_id="did:concordia:no-reputation",
        name="No reputation profile",
    )
    canonical_trust_signals = profile.to_canonical_dict()["trust_signals"]

    assert canonical_json(sorted(canonical_trust_signals)) == (
        b'["attestation_count","concordia_preferred",'
        b'"concordia_sessions_completed","sovereignty"]'
    )


def test_profile_round_trips_multiple_reputation_providers() -> None:
    profile = AgentCapabilityProfile(
        agent_id="did:concordia:multi-reputation",
        name="Multi reputation profile",
        trust_signals=TrustSignals(
            reputation=[
                ReputationAssertion(
                    provider="verascore.ai",
                    subject_did="did:key:z6MkVerascore",
                    tier="verified-sovereign",
                    composite=92,
                ),
                ReputationAssertion(
                    provider="example-scores.test",
                    subject_did="did:key:z6MkExample",
                    tier="gold",
                    composite=88,
                ),
            ],
        ),
    )

    restored = AgentCapabilityProfile.from_dict(profile.to_dict())
    assertions = restored.trust_signals.reputation

    assert assertions is not None
    assert [assertion.provider for assertion in assertions] == [
        "verascore.ai",
        "example-scores.test",
    ]
    assert restored.to_dict()["trust_signals"]["reputation"] == [
        {
            "provider": "verascore.ai",
            "subject_did": "did:key:z6MkVerascore",
            "tier": "verified-sovereign",
            "composite": 92,
        },
        {
            "provider": "example-scores.test",
            "subject_did": "did:key:z6MkExample",
            "tier": "gold",
            "composite": 88,
        },
    ]


def test_reputation_assertion_filters_nested_none_from_canonical_bytes() -> None:
    implicit_none = ReputationAssertion(
        provider="example-scores.test",
        tier="gold",
    )
    explicit_none = ReputationAssertion(
        provider="example-scores.test",
        subject_did=None,
        tier="gold",
        composite=None,
    )

    implicit_bytes = canonical_json(implicit_none.to_dict())
    explicit_bytes = canonical_json(explicit_none.to_dict())
    profile_bytes = canonical_json(
        TrustSignals(reputation=[explicit_none]).to_dict()
    )

    assert implicit_bytes == explicit_bytes
    assert b"null" not in implicit_bytes
    assert b"null" not in profile_bytes
    assert explicit_none.to_dict() == {
        "provider": "example-scores.test",
        "tier": "gold",
    }


def test_missing_key_stores_unsigned_profile_as_unverified() -> None:
    profile = _profile()
    store = AgentProfileStore()

    stored = store.publish(profile)

    assert stored.verified is False


def test_verified_profiles_rank_above_unsigned_profiles() -> None:
    keypair = KeyPair.generate()
    verified = _signed_profile(keypair, "did:concordia:verified")
    unsigned = _profile("did:concordia:unsigned")
    unsigned.trust_signals.verascore_composite = 95
    store = AgentProfileStore()

    store.publish(unsigned)
    store.publish(verified, public_key_bytes=keypair.public_key_bytes())

    results = store.search(limit=2)

    assert [profile.agent_id for profile, _score in results] == [
        "did:concordia:verified",
        "did:concordia:unsigned",
    ]


def test_trust_signals_to_dict_covers_every_declared_field() -> None:
    """Guard the explicit key list in TrustSignals.to_dict().

    to_dict() enumerates its keys by hand rather than calling asdict(), which is
    deliberate: it keeps an unset field out of the signed canonical form. The cost
    is that a field added to the dataclass without a matching to_dict() entry is
    silently excluded from the signed bytes, so it could then be altered without
    invalidating the signature. This test fails when that drift happens.
    """
    from dataclasses import fields

    populated = TrustSignals(
        verascore_did="did:web:example.test:agent",
        verascore_tier="verified-sovereign",
        verascore_composite=90,
        concordia_sessions_completed=3,
        attestation_count=1,
        concordia_preferred=True,
        reputation=[ReputationAssertion(provider="example-scores.test")],
    )

    declared = {f.name for f in fields(TrustSignals)}
    emitted = set(populated.to_dict())

    assert declared == emitted, (
        f"TrustSignals fields missing from to_dict(): {sorted(declared - emitted)}. "
        "to_dict() lists its keys explicitly, so a new field must be added there "
        "or it will be silently excluded from the signed canonical form."
    )
