from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from concordia.agent_profile import (
    AgentCapabilityProfile,
    AgentProfileStore,
    Capabilities,
    Location,
    NegotiationProfile,
    TrustSignals,
)


def _timestamp(seconds_ago: int = 0) -> str:
    value = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _profile(
    agent_id: str,
    *,
    categories: list[str] | None = None,
    offer_types: list[str] | None = None,
    jurisdictions: list[str] | None = None,
    tier: str | None = None,
    score: int | None = None,
    preferred: bool = True,
    sessions: int = 0,
    agreement_rate: float = 0.0,
    ttl: int = 86400,
    updated_at: str | None = None,
) -> AgentCapabilityProfile:
    return AgentCapabilityProfile(
        agent_id=agent_id,
        name=agent_id,
        description="test profile",
        capabilities=Capabilities(
            categories=categories or [],
            offer_types=offer_types or ["basic"],
        ),
        location=Location(jurisdictions=jurisdictions or []),
        trust_signals=TrustSignals(
            verascore_tier=tier,
            verascore_composite=score,
            concordia_preferred=preferred,
            concordia_sessions_completed=sessions,
        ),
        negotiation_profile=NegotiationProfile(agreement_rate=agreement_rate),
        ttl=ttl,
        updated_at=updated_at or _timestamp(),
    )


def test_publish_rejects_missing_agent_id() -> None:
    store = AgentProfileStore()

    with pytest.raises(ValueError, match="agent_id"):
        store.publish(AgentCapabilityProfile(name="missing"), verify_signature=False)


def test_capacity_allows_existing_profile_update_but_rejects_new_profile() -> None:
    store = AgentProfileStore()
    store.MAX_PROFILES = 1
    first = _profile("agent-one", score=10)
    replacement = _profile("agent-one", score=20)

    store.publish(first, verify_signature=False)
    store.publish(replacement, verify_signature=False)

    assert store.get("agent-one") is replacement
    with pytest.raises(RuntimeError, match="capacity"):
        store.publish(_profile("agent-two"), verify_signature=False)


def test_expired_profiles_are_pruned_from_get_list_count_and_search() -> None:
    store = AgentProfileStore()
    store.publish(
        _profile("expired", ttl=1, updated_at=_timestamp(seconds_ago=5)),
        verify_signature=False,
    )
    store.publish(_profile("active", categories=["compute.gpu"]), verify_signature=False)

    assert store.get("expired") is None
    assert [profile.agent_id for profile in store.list_all()] == ["active"]
    assert store.count() == 1
    assert [profile.agent_id for profile, _ in store.search(categories=["compute"])] == [
        "active"
    ]


def test_include_expired_lists_profiles_without_pruning_them() -> None:
    store = AgentProfileStore()
    store.publish(
        _profile("expired", ttl=1, updated_at=_timestamp(seconds_ago=5)),
        verify_signature=False,
    )

    assert [profile.agent_id for profile in store.list_all(include_expired=True)] == [
        "expired"
    ]
    assert store.get("expired") is None


def test_search_combines_tier_offer_jurisdiction_and_preferred_filters() -> None:
    store = AgentProfileStore()
    store.publish(
        _profile(
            "match",
            categories=["infrastructure.compute.gpu"],
            offer_types=["basic", "conditional", "bundle"],
            jurisdictions=["US-CA", "EU"],
            tier="verified-sovereign",
            score=90,
            preferred=True,
        ),
        verify_signature=False,
    )
    store.publish(
        _profile(
            "tier-too-low",
            categories=["infrastructure.compute"],
            offer_types=["basic", "conditional", "bundle"],
            jurisdictions=["US-CA"],
            tier="self-attested",
            score=95,
            preferred=True,
        ),
        verify_signature=False,
    )
    store.publish(
        _profile(
            "missing-offer",
            categories=["infrastructure.compute"],
            offer_types=["basic"],
            jurisdictions=["US-CA"],
            tier="verified-sovereign",
            score=90,
            preferred=True,
        ),
        verify_signature=False,
    )
    store.publish(
        _profile(
            "wrong-jurisdiction",
            categories=["infrastructure.compute"],
            offer_types=["basic", "conditional", "bundle"],
            jurisdictions=["APAC"],
            tier="verified-sovereign",
            score=90,
            preferred=True,
        ),
        verify_signature=False,
    )
    store.publish(
        _profile(
            "not-preferred",
            categories=["infrastructure.compute"],
            offer_types=["basic", "conditional", "bundle"],
            jurisdictions=["US-CA"],
            tier="verified-sovereign",
            score=90,
            preferred=False,
        ),
        verify_signature=False,
    )

    results = store.search(
        categories=["infrastructure"],
        min_sovereignty_tier="verified-degraded",
        offer_types_required=["conditional", "bundle"],
        jurisdictions=["US-CA"],
        concordia_preferred=True,
    )

    assert [(profile.agent_id, score) for profile, score in results] == [
        ("match", 1.0)
    ]


def test_search_sort_options_and_unknown_sort_pin_current_ordering() -> None:
    store = AgentProfileStore()
    store.publish(
        _profile("low-rate", score=100, sessions=5, agreement_rate=0.25),
        verify_signature=False,
    )
    store.publish(
        _profile("high-rate", score=10, sessions=9, agreement_rate=0.95),
        verify_signature=False,
    )

    assert [p.agent_id for p, _ in store.search(sort_by="agreement_rate")] == [
        "high-rate",
        "low-rate",
    ]
    assert [p.agent_id for p, _ in store.search(sort_by="sessions_completed")] == [
        "high-rate",
        "low-rate",
    ]
    assert [p.agent_id for p, _ in store.search(sort_by="unknown")] == [
        "low-rate",
        "high-rate",
    ]


def test_get_stats_ignores_missing_scores_and_counts_distinct_categories() -> None:
    store = AgentProfileStore()
    store.publish(
        _profile("one", categories=["compute", "gpu"], score=80, preferred=True),
        verify_signature=False,
    )
    store.publish(
        _profile("two", categories=["compute"], score=None, preferred=False),
        verify_signature=False,
    )

    assert store.get_stats() == {
        "total_profiles": 2,
        "average_verascore": 80.0,
        "total_categories": 2,
        "concordia_preferred_count": 1,
    }
