"""Agent Capability Profile for discovery (Concordia Protocol §11 — Agent Discovery).

Defines the structure for publishing agent capabilities, negotiation behavior,
trust signals, and endpoints to make agents discoverable.

An AgentCapabilityProfile is published by an agent to advertise what it can
negotiate about, its track record, and where to reach it. Profiles are signed
with Ed25519 and can be stored in registries or published at well-known URIs.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from concordia.signing import canonical_json, verify_signature


def _new_timestamp() -> str:
    """Return an ISO 8601 timestamp in UTC."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Capabilities:
    """What this agent can negotiate about."""

    categories: list[str] = field(default_factory=list)
    """Hierarchical capability categories (e.g., infrastructure.compute.gpu)."""

    offer_types: list[str] = field(default_factory=lambda: ["basic"])
    """Supported offer types: basic, conditional, bundle."""

    resolution_methods: list[str] = field(default_factory=lambda: ["split_difference"])
    """Supported resolution methods: split_difference, foa, tradeoff_optimization."""

    max_concurrent_sessions: int = 10
    """Maximum concurrent negotiation sessions."""

    languages: list[str] = field(default_factory=lambda: ["en"])
    """Supported languages (ISO 639-1 codes)."""

    currencies: list[str] = field(default_factory=lambda: ["USD"])
    """Supported currencies (ISO 4217 codes)."""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NegotiationProfile:
    """Behavioral summary derived from completed Concordia sessions."""

    style: str = "collaborative"
    """Negotiation style: competitive, collaborative, hybrid."""

    avg_rounds_to_agreement: float = 0.0
    """EMA of rounds to reach agreement (last 20 sessions)."""

    agreement_rate: float = 0.0
    """Fraction of sessions resulting in agreement (0-1)."""

    avg_session_duration_seconds: float = 0.0
    """EMA of session duration in seconds."""

    concession_pattern: str = "graduated"
    """Pattern of concessions: none, immediate, graduated, strategic."""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Sovereignty:
    """Sovereignty Health Report (SHR) summary."""

    L1: str = "Full"
    """Cognitive Sovereignty (encryption)."""

    L2: str = "Degraded"
    """Operational Isolation (human approval)."""

    L3: str = "Full"
    """Selective Disclosure (ZK proofs)."""

    L4: str = "Full"
    """Verifiable Reputation (attestations)."""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TrustSignals:
    """External trust indicators."""

    verascore_did: str | None = None
    """DID linked to this agent's Verascore profile."""

    verascore_tier: str | None = None
    """Verascore tier: verified-sovereign, verified-degraded, self-attested, unverified."""

    verascore_composite: int | None = None
    """Composite trust score (0-100) from Verascore."""

    sovereignty: Sovereignty = field(default_factory=Sovereignty)
    """Most recent Sovereignty Health Report summary."""

    concordia_sessions_completed: int = 0
    """Count of concluded Concordia sessions (verifiable against receipts)."""

    attestation_count: int = 0
    """Count of reputation attestations."""

    concordia_preferred: bool = True
    """Whether agent supports Concordia protocol."""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Don't include None values
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class Endpoints:
    """Where to reach this agent."""

    negotiate: str | None = None
    """Concordia session endpoint (https://...)."""

    a2a_card: str | None = None
    """A2A Agent Card well-known URI."""

    mcp_manifest: str | None = None
    """MCP server manifest well-known URI."""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Don't include None values
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class Location:
    """Where this agent operates."""

    regions: list[str] = field(default_factory=list)
    """Cloud regions (us-west, eu-west, etc.)."""

    jurisdictions: list[str] = field(default_factory=list)
    """Legal jurisdictions (US-CA, EU, etc.)."""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AgentCapabilityProfile:
    """Complete agent capability profile for discovery.

    Signed with Ed25519 over the canonical JSON (minus the signature field).
    """

    type: str = "concordia.agent_profile"
    version: str = "1.0"
    agent_id: str = ""
    """DID or unique identifier for the agent."""

    name: str = ""
    """Human-readable agent name."""

    description: str = ""
    """Brief description of the agent's role and focus."""

    capabilities: Capabilities = field(default_factory=Capabilities)
    negotiation_profile: NegotiationProfile = field(default_factory=NegotiationProfile)
    trust_signals: TrustSignals = field(default_factory=TrustSignals)
    endpoints: Endpoints = field(default_factory=Endpoints)
    location: Location = field(default_factory=Location)

    ttl: int = 86400
    """Time-to-live in seconds (default: 1 day)."""

    updated_at: str = field(default_factory=_new_timestamp)
    """ISO 8601 timestamp of last update."""

    signature: str = ""
    """Ed25519 signature over canonical JSON (minus this field)."""

    def to_canonical_dict(self) -> dict[str, Any]:
        """Produce the canonical form for signing (excludes signature field)."""
        return {
            "type": self.type,
            "version": self.version,
            "agent_id": self.agent_id,
            "name": self.name,
            "description": self.description,
            "capabilities": self.capabilities.to_dict(),
            "negotiation_profile": self.negotiation_profile.to_dict(),
            "trust_signals": self.trust_signals.to_dict(),
            "endpoints": self.endpoints.to_dict(),
            "location": self.location.to_dict(),
            "ttl": self.ttl,
            "updated_at": self.updated_at,
        }

    def to_dict(self) -> dict[str, Any]:
        """Produce the full profile dict including signature."""
        d = self.to_canonical_dict()
        d["signature"] = self.signature
        return d

    def to_canonical_json_bytes(self) -> bytes:
        """Produce deterministic JSON bytes for signing."""
        return canonical_json(self.to_canonical_dict())

    def verify_signature(self, public_key: Ed25519PublicKey) -> bool:
        """Verify the signature over the profile using the provided public key.

        Returns True if the signature is valid, False otherwise.
        """
        return verify_signature(
            self.to_canonical_dict(),
            self.signature,
            public_key,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentCapabilityProfile:
        """Parse a profile dict into an AgentCapabilityProfile instance.

        Used for deserializing profiles from registries or well-known URIs.
        """
        caps = Capabilities(**data.get("capabilities", {}))
        neg_prof = NegotiationProfile(**data.get("negotiation_profile", {}))
        trust = TrustSignals(
            **{
                k: v
                for k, v in data.get("trust_signals", {}).items()
                if k != "sovereignty"
            }
        )
        # Handle nested sovereignty
        if "sovereignty" in data.get("trust_signals", {}):
            trust.sovereignty = Sovereignty(**data["trust_signals"]["sovereignty"])

        endpoints = Endpoints(**data.get("endpoints", {}))
        location = Location(**data.get("location", {}))

        return cls(
            type=data.get("type", "concordia.agent_profile"),
            version=data.get("version", "1.0"),
            agent_id=data.get("agent_id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            capabilities=caps,
            negotiation_profile=neg_prof,
            trust_signals=trust,
            endpoints=endpoints,
            location=location,
            ttl=data.get("ttl", 86400),
            updated_at=data.get("updated_at", _new_timestamp()),
            signature=data.get("signature", ""),
        )
