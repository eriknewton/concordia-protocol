"""Agent Discovery Registry — registry of Concordia-speaking agents (§7, §10.1).

Agents register themselves with:
    - Identity (agent_id)
    - Concordia capabilities (protocol version, supported roles, categories,
      resolution mechanisms)
    - Optional metadata (endpoint, description, A2A Agent Card fields)

Other agents query the registry to find negotiation partners by category,
role, or capability. The registry also supports the "Concordia Preferred"
badge — a machine-readable signal that an agent speaks Concordia.

This is the discovery complement to the Want Registry. The Want Registry
answers "who wants/has X?" while the Agent Registry answers "who can I
negotiate with, and what do they support?"
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = "0.1.0"


@dataclass
class AgentCapabilities:
    """What a registered agent supports within the Concordia protocol."""

    protocol: str = "concordia"
    version: str = PROTOCOL_VERSION
    roles: list[str] = field(default_factory=lambda: ["buyer", "seller"])
    categories: list[str] = field(default_factory=list)
    resolution_mechanisms: list[str] = field(
        default_factory=lambda: ["split", "foa", "tradeoff"]
    )
    max_concurrent_sessions: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "protocol": self.protocol,
            "version": self.version,
            "roles": self.roles,
            "categories": self.categories,
            "resolution_mechanisms": self.resolution_mechanisms,
        }
        if self.max_concurrent_sessions is not None:
            d["max_concurrent_sessions"] = self.max_concurrent_sessions
        return d

    def supports_category(self, category: str) -> bool:
        """Check if agent supports a category (prefix match, like §7.3)."""
        if not self.categories:
            return True  # no categories listed = accepts all
        return any(
            cat.startswith(category) or category.startswith(cat)
            for cat in self.categories
        )

    def supports_role(self, role: str) -> bool:
        return role.lower() in [r.lower() for r in self.roles]


@dataclass
class RegisteredAgent:
    """An agent entry in the discovery registry."""

    agent_id: str
    capabilities: AgentCapabilities
    endpoint: str | None = None
    description: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    registered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )
    last_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )
    ttl: int = 86400 * 30  # 30 days default

    def is_expired(self) -> bool:
        """Check if this registration has expired based on last_seen + ttl."""
        try:
            last = datetime.strptime(self.last_seen, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
            age = (datetime.now(timezone.utc) - last).total_seconds()
            return age > self.ttl
        except (ValueError, TypeError):
            return False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "agent_id": self.agent_id,
            "capabilities": self.capabilities.to_dict(),
            "registered_at": self.registered_at,
            "last_seen": self.last_seen,
            "concordia_preferred": True,
        }
        if self.endpoint:
            d["endpoint"] = self.endpoint
        if self.description:
            d["description"] = self.description
        if self.metadata:
            d["metadata"] = self.metadata
        return d

    def to_agent_card(self) -> dict[str, Any]:
        """Produce an A2A-compatible Agent Card fragment (§10.1)."""
        return {
            "name": self.agent_id,
            "description": self.description or f"Concordia agent: {self.agent_id}",
            "capabilities": [self.capabilities.to_dict()],
            "concordia_preferred": True,
        }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class AgentRegistry:
    """In-memory registry of Concordia-speaking agents.

    Supports registration, heartbeat (refresh last_seen), lookup by ID,
    search by category/role/capability, and listing. Expired entries are
    lazily pruned on access.
    """

    def __init__(self) -> None:
        self._agents: dict[str, RegisteredAgent] = {}

    # -- Registration -------------------------------------------------------

    def register(
        self,
        agent_id: str,
        roles: list[str] | None = None,
        categories: list[str] | None = None,
        resolution_mechanisms: list[str] | None = None,
        max_concurrent_sessions: int | None = None,
        endpoint: str | None = None,
        description: str | None = None,
        metadata: dict[str, Any] | None = None,
        ttl: int = 86400 * 30,
    ) -> RegisteredAgent:
        """Register or update an agent in the registry."""
        caps = AgentCapabilities(
            roles=roles or ["buyer", "seller"],
            categories=categories or [],
            resolution_mechanisms=resolution_mechanisms or ["split", "foa", "tradeoff"],
            max_concurrent_sessions=max_concurrent_sessions,
        )
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        existing = self._agents.get(agent_id)
        if existing:
            # Update existing registration
            existing.capabilities = caps
            existing.last_seen = now
            existing.endpoint = endpoint or existing.endpoint
            existing.description = description or existing.description
            existing.metadata = metadata if metadata is not None else existing.metadata
            existing.ttl = ttl
            return existing

        agent = RegisteredAgent(
            agent_id=agent_id,
            capabilities=caps,
            endpoint=endpoint,
            description=description,
            metadata=metadata or {},
            registered_at=now,
            last_seen=now,
            ttl=ttl,
        )
        self._agents[agent_id] = agent
        return agent

    def deregister(self, agent_id: str) -> bool:
        """Remove an agent from the registry. Returns True if found."""
        return self._agents.pop(agent_id, None) is not None

    def heartbeat(self, agent_id: str) -> bool:
        """Update last_seen for an agent. Returns True if agent is registered."""
        agent = self._agents.get(agent_id)
        if agent is None:
            return False
        agent.last_seen = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return True

    # -- Lookup -------------------------------------------------------------

    def get(self, agent_id: str) -> RegisteredAgent | None:
        """Get a registered agent by ID. Returns None if not found or expired."""
        agent = self._agents.get(agent_id)
        if agent and agent.is_expired():
            del self._agents[agent_id]
            return None
        return agent

    def search(
        self,
        category: str | None = None,
        role: str | None = None,
        resolution_mechanism: str | None = None,
        limit: int = 50,
    ) -> list[RegisteredAgent]:
        """Search for agents matching criteria.

        All filters are AND-combined. Expired agents are pruned during search.
        """
        results: list[RegisteredAgent] = []
        expired: list[str] = []

        for agent_id, agent in self._agents.items():
            if agent.is_expired():
                expired.append(agent_id)
                continue

            if category and not agent.capabilities.supports_category(category):
                continue
            if role and not agent.capabilities.supports_role(role):
                continue
            if resolution_mechanism:
                if resolution_mechanism not in agent.capabilities.resolution_mechanisms:
                    continue

            results.append(agent)
            if len(results) >= limit:
                break

        # Lazy prune
        for aid in expired:
            del self._agents[aid]

        return results

    def list_all(self, include_expired: bool = False) -> list[RegisteredAgent]:
        """List all registered agents."""
        if include_expired:
            return list(self._agents.values())

        expired: list[str] = []
        active: list[RegisteredAgent] = []
        for agent_id, agent in self._agents.items():
            if agent.is_expired():
                expired.append(agent_id)
            else:
                active.append(agent)
        for aid in expired:
            del self._agents[aid]
        return active

    def count(self) -> int:
        """Count of active (non-expired) agents."""
        return len(self.list_all())

    # -- Concordia Preferred badge ------------------------------------------

    def is_concordia_preferred(self, agent_id: str) -> bool:
        """Check if an agent has the Concordia Preferred badge (is registered)."""
        agent = self.get(agent_id)
        return agent is not None

    def get_agent_card(self, agent_id: str) -> dict[str, Any] | None:
        """Get the A2A Agent Card fragment for a registered agent."""
        agent = self.get(agent_id)
        if agent is None:
            return None
        return agent.to_agent_card()
