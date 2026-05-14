from __future__ import annotations

import pytest

from concordia.agent_profile import (
    AgentCapabilityProfile,
    AgentProfileStore,
    ProfileSignatureError,
    TrustSignals,
)
from concordia.signing import KeyPair, sign_message


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
