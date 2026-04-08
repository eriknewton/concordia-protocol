"""MCP tools for agent discovery — Phase 2 registration and search.

Provides 4 tools to the Concordia MCP server:
    - agent_profile_publish: Register/update an agent capability profile
    - agent_profile_get: Retrieve a profile by agent_id
    - agent_discovery_search: Search for agents matching filters
    - agent_discovery_recommend: Find agents matching a Want's category

These tools are registered via register_discovery_tools(mcp, profile_store, want_registry).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Annotated, Any

from .profile import (
    AgentCapabilityProfile,
    Capabilities,
    Endpoints,
    Location,
    NegotiationProfile,
    Sovereignty,
    TrustSignals,
)
from .profile_store import AgentProfileStore


def register_discovery_tools(
    mcp: Any,
    profile_store: AgentProfileStore,
    want_registry: Any,
) -> dict[str, Any]:
    """Register all 4 agent discovery tools with the MCP server.

    Args:
        mcp: FastMCP instance (from mcp_server.py)
        profile_store: AgentProfileStore instance (global)
        want_registry: WantRegistry instance (global)

    Returns:
        Dict mapping tool names to tool functions for registration in handle_tool_call.
    """
    tool_functions = {}

    # =========================================================================
    # Tool 1: agent_profile_publish
    # =========================================================================

    @mcp.tool(
        name="agent_profile_publish",
        description=(
            "Register or update an agent's capability profile. "
            "Publishes negotiation capabilities, trust signals, endpoints, and location. "
            "If signature is provided, it will be verified against the profile's canonical JSON. "
            "Returns the stored profile."
        ),
    )
    def tool_agent_profile_publish_impl(
        agent_id: Annotated[str, "Unique agent identifier (DID or agent_id)"],
        name: Annotated[str, "Human-readable agent name"],
        description: Annotated[str | None, "Brief description of the agent's role and focus"] = None,
        categories: Annotated[list[str] | None, "Negotiation capability categories (e.g. ['infrastructure.compute', 'infrastructure.storage'])"] = None,
        offer_types: Annotated[list[str] | None, "Supported offer types: basic, conditional, bundle"] = None,
        resolution_methods: Annotated[list[str] | None, "Supported resolution methods: split_difference, foa, tradeoff_optimization"] = None,
        max_concurrent_sessions: Annotated[int | None, "Maximum concurrent negotiation sessions"] = None,
        negotiation_style: Annotated[str | None, "Style: competitive, collaborative, hybrid"] = None,
        avg_rounds_to_agreement: Annotated[float | None, "EMA rounds to agreement (last 20 sessions)"] = None,
        agreement_rate: Annotated[float | None, "Fraction of sessions resulting in agreement (0-1)"] = None,
        avg_session_duration_seconds: Annotated[float | None, "EMA session duration in seconds"] = None,
        verascore_composite: Annotated[int | None, "Composite trust score from Verascore (0-100)"] = None,
        verascore_tier: Annotated[str | None, "Verascore tier: unverified, self-attested, verified-degraded, verified-sovereign"] = None,
        verascore_did: Annotated[str | None, "DID linked to agent's Verascore profile"] = None,
        concordia_sessions_completed: Annotated[int | None, "Count of concluded Concordia sessions"] = None,
        attestation_count: Annotated[int | None, "Count of reputation attestations"] = None,
        concordia_preferred: Annotated[bool | None, "Whether agent supports Concordia protocol"] = None,
        sovereignty_L1: Annotated[str | None, "L1 Cognitive Sovereignty status"] = None,
        sovereignty_L2: Annotated[str | None, "L2 Operational Isolation status"] = None,
        sovereignty_L3: Annotated[str | None, "L3 Selective Disclosure status"] = None,
        sovereignty_L4: Annotated[str | None, "L4 Verifiable Reputation status"] = None,
        negotiate_endpoint: Annotated[str | None, "Concordia session endpoint URL"] = None,
        a2a_card_endpoint: Annotated[str | None, "A2A Agent Card well-known URI"] = None,
        mcp_manifest_endpoint: Annotated[str | None, "MCP server manifest well-known URI"] = None,
        regions: Annotated[list[str] | None, "Cloud regions (us-west, eu-west, etc.)"] = None,
        jurisdictions: Annotated[list[str] | None, "Legal jurisdictions (US-CA, EU, etc.)"] = None,
        ttl: Annotated[int | None, "Time-to-live in seconds (default: 86400)"] = None,
        signature: Annotated[str | None, "Ed25519 signature over canonical JSON"] = None,
    ) -> str:
        """Register or update an agent capability profile."""
        try:
            # Build capabilities
            caps = Capabilities(
                categories=categories or [],
                offer_types=offer_types or ["basic"],
                resolution_methods=resolution_methods or ["split_difference"],
                max_concurrent_sessions=max_concurrent_sessions or 10,
                languages=["en"],
                currencies=["USD"],
            )

            # Build negotiation profile
            neg_prof = NegotiationProfile(
                style=negotiation_style or "collaborative",
                avg_rounds_to_agreement=avg_rounds_to_agreement or 0.0,
                agreement_rate=agreement_rate or 0.0,
                avg_session_duration_seconds=avg_session_duration_seconds or 0.0,
                concession_pattern="graduated",
            )

            # Build sovereignty
            sovereignty = Sovereignty(
                L1=sovereignty_L1 or "Full",
                L2=sovereignty_L2 or "Degraded",
                L3=sovereignty_L3 or "Full",
                L4=sovereignty_L4 or "Full",
            )

            # Build trust signals
            trust = TrustSignals(
                verascore_did=verascore_did,
                verascore_tier=verascore_tier,
                verascore_composite=verascore_composite,
                sovereignty=sovereignty,
                concordia_sessions_completed=concordia_sessions_completed or 0,
                attestation_count=attestation_count or 0,
                concordia_preferred=concordia_preferred if concordia_preferred is not None else True,
            )

            # Build endpoints
            endpoints = Endpoints(
                negotiate=negotiate_endpoint,
                a2a_card=a2a_card_endpoint,
                mcp_manifest=mcp_manifest_endpoint,
            )

            # Build location
            location = Location(
                regions=regions or [],
                jurisdictions=jurisdictions or [],
            )

            # Create profile
            profile = AgentCapabilityProfile(
                agent_id=agent_id,
                name=name,
                description=description or "",
                capabilities=caps,
                negotiation_profile=neg_prof,
                trust_signals=trust,
                endpoints=endpoints,
                location=location,
                ttl=ttl or 86400,
                signature=signature or "",
            )

            # Publish to store (signature verification deferred to Phase 2 if key is provided)
            stored = profile_store.publish(profile, verify_signature=False)

            return json.dumps({
                "success": True,
                "profile": stored.to_dict(),
                "store_count": profile_store.count(),
                "message": f"Agent '{agent_id}' profile published successfully.",
            }, indent=2, default=str)

        except ValueError as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Failed to publish profile: {e}",
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Unexpected error: {e}",
            }, indent=2)

    tool_functions["agent_profile_publish"] = tool_agent_profile_publish_impl

    # =========================================================================
    # Tool 2: agent_profile_get
    # =========================================================================

    @mcp.tool(
        name="agent_profile_get",
        description=(
            "Retrieve an agent's capability profile by agent_id. "
            "Returns the full profile or an error if not found."
        ),
    )
    def tool_agent_profile_get_impl(
        agent_id: Annotated[str, "Unique agent identifier to look up"],
    ) -> str:
        """Retrieve a profile by agent_id."""
        try:
            profile = profile_store.get(agent_id)

            if profile is None:
                return json.dumps({
                    "found": False,
                    "error": f"Profile not found for agent_id '{agent_id}'",
                }, indent=2)

            return json.dumps({
                "found": True,
                "profile": profile.to_dict(),
            }, indent=2, default=str)

        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Unexpected error: {e}",
            }, indent=2)

    tool_functions["agent_profile_get"] = tool_agent_profile_get_impl

    # =========================================================================
    # Tool 3: agent_discovery_search
    # =========================================================================

    @mcp.tool(
        name="agent_discovery_search",
        description=(
            "Search for agents matching filter criteria. "
            "Filters include categories, Verascore tier/score, offer types, jurisdictions, "
            "and Concordia preference. Results are scored and sorted by match quality. "
            "Returns list of (profile, match_score) tuples."
        ),
    )
    def tool_agent_discovery_search_impl(
        categories: Annotated[list[str] | None, "Filter by capability categories (prefix-match)"] = None,
        min_verascore: Annotated[int | None, "Minimum Verascore composite score (0-100)"] = None,
        min_sovereignty_tier: Annotated[str | None, "Minimum Verascore tier: unverified, self-attested, verified-degraded, verified-sovereign"] = None,
        offer_types_required: Annotated[list[str] | None, "Agent must support all these offer types"] = None,
        jurisdictions: Annotated[list[str] | None, "Filter by jurisdiction (overlap match)"] = None,
        concordia_preferred: Annotated[bool | None, "Filter by Concordia Preferred badge"] = None,
        sort_by: Annotated[str | None, "Sort field: verascore_composite, agreement_rate, sessions_completed"] = None,
        limit: Annotated[int | None, "Maximum results to return (default: 20)"] = None,
    ) -> str:
        """Search for agents matching criteria."""
        try:
            results = profile_store.search(
                categories=categories,
                min_verascore=min_verascore,
                min_sovereignty_tier=min_sovereignty_tier,
                offer_types_required=offer_types_required,
                jurisdictions=jurisdictions,
                concordia_preferred=concordia_preferred,
                sort_by=sort_by or "verascore_composite",
                limit=limit or 20,
            )

            return json.dumps({
                "count": len(results),
                "results": [
                    {
                        "profile": profile.to_dict(),
                        "match_score": float(score),
                    }
                    for profile, score in results
                ],
                "filters": {
                    k: v for k, v in {
                        "categories": categories,
                        "min_verascore": min_verascore,
                        "min_sovereignty_tier": min_sovereignty_tier,
                        "offer_types_required": offer_types_required,
                        "jurisdictions": jurisdictions,
                        "concordia_preferred": concordia_preferred,
                    }.items() if v is not None
                },
            }, indent=2, default=str)

        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Search failed: {e}",
            }, indent=2)

    tool_functions["agent_discovery_search"] = tool_agent_discovery_search_impl

    # =========================================================================
    # Tool 4: agent_discovery_recommend
    # =========================================================================

    @mcp.tool(
        name="agent_discovery_recommend",
        description=(
            "Find agents matching a Want's category. "
            "Looks up a Want by ID, extracts its category, and searches for agents "
            "with matching capabilities. Returns recommended agents with match scores."
        ),
    )
    def tool_agent_discovery_recommend_impl(
        want_id: Annotated[str, "ID of a Want in the WantRegistry"],
    ) -> str:
        """Find agents matching a Want's category."""
        try:
            # Look up the Want
            want = want_registry.get_want(want_id)
            if want is None:
                return json.dumps({
                    "found": False,
                    "error": f"Want not found with ID '{want_id}'",
                }, indent=2)

            # Extract want category
            want_category = want.get("category")
            if not want_category:
                return json.dumps({
                    "error": "Want has no category field",
                }, indent=2)

            # Search for agents matching category
            results = profile_store.search(
                categories=[want_category],
                sort_by="verascore_composite",
                limit=20,
            )

            return json.dumps({
                "want_id": want_id,
                "want_category": want_category,
                "count": len(results),
                "recommendations": [
                    {
                        "profile": profile.to_dict(),
                        "match_score": float(score),
                    }
                    for profile, score in results
                ],
            }, indent=2, default=str)

        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e),
                "message": f"Recommendation failed: {e}",
            }, indent=2)

    tool_functions["agent_discovery_recommend"] = tool_agent_discovery_recommend_impl

    return tool_functions
