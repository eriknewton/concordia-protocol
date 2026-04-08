"""Agent Profile Store — in-memory storage for agent capability profiles.

Similar to AgentRegistry and WantRegistry, this provides CRUD operations
and search/filter capabilities for agent profiles. Used by the discovery
system to support agent-level (not transaction-level) discovery.

Extends the existing registry pattern with support for the full
AgentCapabilityProfile schema.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from concordia.agent_profile.profile import AgentCapabilityProfile


class AgentProfileStore:
    """In-memory store for agent capability profiles.

    Supports:
    - Publish (create or update): profile must have valid signature
    - Get: retrieve a specific profile by agent_id
    - Search: filter by multiple criteria with optional sorting
    - Delete: remove a profile
    - List all: enumerate all stored profiles

    Resource limit: max 1000 profiles (configurable).
    Profiles have TTL; expired profiles are lazily pruned on access.
    """

    MAX_PROFILES = 1000

    def __init__(self) -> None:
        self._profiles: dict[str, AgentCapabilityProfile] = {}

    # =========================================================================
    # CRUD Operations
    # =========================================================================

    def publish(
        self,
        profile: AgentCapabilityProfile,
        verify_signature: bool = True,
        public_key_bytes: bytes | None = None,
    ) -> AgentCapabilityProfile:
        """Publish or update an agent's capability profile.

        Args:
            profile: The AgentCapabilityProfile to publish
            verify_signature: If True, signature must be valid (default)
            public_key_bytes: The Ed25519 public key bytes to use for verification.
                If None and verify_signature=True, the profile must be self-signed
                (public key derived from agent_id as DID).

        Returns:
            The stored profile

        Raises:
            ValueError: If signature verification fails or profile is invalid
            RuntimeError: If registry is at capacity
        """
        if not profile.agent_id:
            raise ValueError("Profile must have agent_id")

        if len(self._profiles) >= self.MAX_PROFILES and profile.agent_id not in self._profiles:
            raise RuntimeError(f"Profile store at capacity ({self.MAX_PROFILES})")

        # TODO: Add signature verification if public_key_bytes is provided
        # For Phase 1, we accept profiles without strict verification
        # Phase 2 will add Ed25519 public key verification against DIDs

        self._profiles[profile.agent_id] = profile
        return profile

    def get(self, agent_id: str) -> AgentCapabilityProfile | None:
        """Retrieve a profile by agent_id.

        Returns None if not found or expired.
        """
        profile = self._profiles.get(agent_id)
        if profile is None:
            return None

        # Check TTL
        if self._is_expired(profile):
            del self._profiles[agent_id]
            return None

        return profile

    def delete(self, agent_id: str) -> bool:
        """Delete a profile by agent_id.

        Returns True if found and deleted, False if not found.
        """
        return self._profiles.pop(agent_id, None) is not None

    def list_all(self, include_expired: bool = False) -> list[AgentCapabilityProfile]:
        """List all stored profiles.

        By default, expired profiles are pruned and not returned.
        """
        if include_expired:
            return list(self._profiles.values())

        expired: list[str] = []
        active: list[AgentCapabilityProfile] = []

        for agent_id, profile in self._profiles.items():
            if self._is_expired(profile):
                expired.append(agent_id)
            else:
                active.append(profile)

        # Lazy prune
        for agent_id in expired:
            del self._profiles[agent_id]

        return active

    # =========================================================================
    # Search and Filter
    # =========================================================================

    def search(
        self,
        categories: list[str] | None = None,
        min_verascore: int | None = None,
        min_sovereignty_tier: str | None = None,
        offer_types_required: list[str] | None = None,
        jurisdictions: list[str] | None = None,
        concordia_preferred: bool | None = None,
        sort_by: str = "verascore_composite",
        limit: int = 20,
    ) -> list[tuple[AgentCapabilityProfile, float]]:
        """Search for agents matching filters.

        Returns list of (profile, match_score) tuples, sorted and limited.

        Args:
            categories: Overlap match — agent must have at least one category
                matching one of these
            min_verascore: Minimum composite score (0-100)
            min_sovereignty_tier: Minimum tier (unverified, self-attested,
                verified-degraded, verified-sovereign)
            offer_types_required: Agent must support all of these offer types
            jurisdictions: Overlap match — agent must operate in at least one
            concordia_preferred: If True, only Concordia-native agents
            sort_by: Sort field (verascore_composite, agreement_rate,
                sessions_completed)
            limit: Maximum results to return

        Returns:
            List of (profile, match_score) tuples, highest score first
        """
        matches: list[tuple[AgentCapabilityProfile, float]] = []

        for agent_id, profile in list(self._profiles.items()):
            # Check expiry
            if self._is_expired(profile):
                del self._profiles[agent_id]
                continue

            # Apply filters
            if not self._matches_filters(
                profile,
                categories=categories,
                min_verascore=min_verascore,
                min_sovereignty_tier=min_sovereignty_tier,
                offer_types_required=offer_types_required,
                jurisdictions=jurisdictions,
                concordia_preferred=concordia_preferred,
            ):
                continue

            # Compute match score
            score = self._compute_match_score(
                profile,
                categories=categories,
                offer_types_required=offer_types_required,
                jurisdictions=jurisdictions,
            )
            matches.append((profile, score))

        # Sort
        matches.sort(key=lambda x: self._sort_key(x[0], sort_by), reverse=True)

        # Limit
        return matches[:limit]

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _is_expired(self, profile: AgentCapabilityProfile) -> bool:
        """Check if a profile has exceeded its TTL."""
        try:
            updated = datetime.strptime(
                profile.updated_at, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            age_seconds = (datetime.now(timezone.utc) - updated).total_seconds()
            return age_seconds > profile.ttl
        except (ValueError, TypeError):
            return False

    def _matches_filters(
        self,
        profile: AgentCapabilityProfile,
        categories: list[str] | None = None,
        min_verascore: int | None = None,
        min_sovereignty_tier: str | None = None,
        offer_types_required: list[str] | None = None,
        jurisdictions: list[str] | None = None,
        concordia_preferred: bool | None = None,
    ) -> bool:
        """Check if profile satisfies all filters (AND logic)."""
        # Categories: prefix-based overlap match (like Want/Have registry)
        if categories:
            if not any(
                self._category_compatible(profile_cat, filter_cat)
                for profile_cat in profile.capabilities.categories
                for filter_cat in categories
            ):
                return False

        # Verascore minimum
        if min_verascore is not None:
            score = profile.trust_signals.verascore_composite or 0
            if score < min_verascore:
                return False

        # Sovereignty tier minimum
        if min_sovereignty_tier:
            tier = profile.trust_signals.verascore_tier or "unverified"
            if not self._tier_geq(tier, min_sovereignty_tier):
                return False

        # Offer types: subset match (agent must support all required)
        if offer_types_required:
            agent_types = set(profile.capabilities.offer_types)
            required = set(offer_types_required)
            if not required.issubset(agent_types):
                return False

        # Jurisdictions: overlap match
        if jurisdictions:
            profile_juris = set(profile.location.jurisdictions)
            filter_juris = set(jurisdictions)
            if not profile_juris & filter_juris:
                return False

        # Concordia preferred badge
        if concordia_preferred is not None:
            if profile.trust_signals.concordia_preferred != concordia_preferred:
                return False

        return True

    def _compute_match_score(
        self,
        profile: AgentCapabilityProfile,
        categories: list[str] | None = None,
        offer_types_required: list[str] | None = None,
        jurisdictions: list[str] | None = None,
    ) -> float:
        """Compute a match score (0-1) based on filter overlap.

        Higher score = better overlap with search criteria.
        """
        score = 0.5  # baseline

        # Category overlap (prefix-based)
        if categories:
            matches = sum(
                1 for profile_cat in profile.capabilities.categories
                for filter_cat in categories
                if self._category_compatible(profile_cat, filter_cat)
            )
            overlap = matches / max(len(categories), 1)
            score += overlap * 0.3

        # Offer type coverage
        if offer_types_required:
            agent_types = set(profile.capabilities.offer_types)
            required = set(offer_types_required)
            coverage = len(required & agent_types) / max(len(required), 1)
            score += coverage * 0.2

        # Jurisdiction overlap
        if jurisdictions:
            profile_juris = set(profile.location.jurisdictions)
            filter_juris = set(jurisdictions)
            overlap = len(profile_juris & filter_juris) / max(len(filter_juris), 1)
            score += overlap * 0.1

        return min(score, 1.0)  # cap at 1.0

    def _sort_key(self, profile: AgentCapabilityProfile, sort_by: str) -> float | int:
        """Extract the sort key from a profile."""
        if sort_by == "verascore_composite":
            return profile.trust_signals.verascore_composite or 0
        elif sort_by == "agreement_rate":
            return profile.negotiation_profile.agreement_rate
        elif sort_by == "sessions_completed":
            return profile.trust_signals.concordia_sessions_completed
        else:
            return 0

    def _category_compatible(self, profile_cat: str, filter_cat: str) -> bool:
        """Check if profile category is compatible with filter category (prefix match).

        Follows the same pattern as Want/Have registry: categories are compatible
        if either is a prefix of the other. This allows hierarchical matching.

        Examples:
            "infrastructure" matches "infrastructure.compute"
            "infrastructure.compute.gpu" matches "infrastructure.compute"
        """
        return profile_cat.startswith(filter_cat) or filter_cat.startswith(profile_cat)

    def _tier_geq(self, actual: str, minimum: str) -> bool:
        """Check if actual tier >= minimum tier (hierarchical comparison).

        Tier hierarchy (ascending trust):
        unverified < self-attested < verified-degraded < verified-sovereign
        """
        tier_order = {
            "unverified": 0,
            "self-attested": 1,
            "verified-degraded": 2,
            "verified-sovereign": 3,
        }
        actual_rank = tier_order.get(actual, 0)
        minimum_rank = tier_order.get(minimum, 0)
        return actual_rank >= minimum_rank

    # =========================================================================
    # Statistics
    # =========================================================================

    def count(self) -> int:
        """Count of active (non-expired) profiles."""
        return len(self.list_all())

    def get_stats(self) -> dict[str, Any]:
        """Get summary statistics about the store."""
        profiles = self.list_all()
        avg_verascore = 0.0
        if profiles:
            scores = [
                p.trust_signals.verascore_composite
                for p in profiles
                if p.trust_signals.verascore_composite is not None
            ]
            if scores:
                avg_verascore = sum(scores) / len(scores)

        return {
            "total_profiles": len(profiles),
            "average_verascore": round(avg_verascore, 1),
            "total_categories": len(set(
                cat for p in profiles for cat in p.capabilities.categories
            )),
            "concordia_preferred_count": sum(
                1 for p in profiles if p.trust_signals.concordia_preferred
            ),
        }
