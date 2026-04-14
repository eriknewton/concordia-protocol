"""Mandate credential model and JSON Schema for mandate_verification.

A mandate is a signed credential that authorizes an agent to act within
specified constraints on behalf of an issuer. Mandates support:

- Issuer signature verification (EdDSA / ES256)
- Validity windows aligned with Concordia's three-mode temporal model
  (sequence, windowed, state_bound)
- Constraint schema compliance — structured limits on what the mandate
  authorizes (max spend, allowed categories, geographic bounds, etc.)
- Delegation chains — ordered list proving authority from root to holder
- Revocation status checks via an optional revocation list endpoint

Design: aligned with SD-JWT-based mandate models (Prove Verified Agent /
Mastercard VI) without depending on SD-JWT infrastructure. The constraint
schema uses JSON Schema for expressiveness and interoperability.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Temporal validity modes (three-mode enum per #1734 consensus)
# ---------------------------------------------------------------------------

class TemporalMode(Enum):
    """Validity temporal modes aligned with trust-evidence-format v1.0.0."""
    SEQUENCE = "sequence"
    WINDOWED = "windowed"
    STATE_BOUND = "state_bound"


# ---------------------------------------------------------------------------
# Mandate status
# ---------------------------------------------------------------------------

class MandateStatus(Enum):
    """Lifecycle status of a mandate credential."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


# ---------------------------------------------------------------------------
# Delegation link
# ---------------------------------------------------------------------------

@dataclass
class DelegationLink:
    """A single link in a delegation chain.

    Each link records that ``delegator`` authorized ``delegate`` with
    a signature over the delegation payload.
    """
    delegator: str          # DID or agent_id of the delegator
    delegate: str           # DID or agent_id of the delegate
    scope_restriction: dict[str, Any] | None = None  # narrowing constraints
    delegated_at: str = ""  # ISO 8601 timestamp
    signature: str = ""     # base64url EdDSA/ES256 over canonical payload
    algorithm: str = "EdDSA"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "delegator": self.delegator,
            "delegate": self.delegate,
            "delegated_at": self.delegated_at,
            "signature": self.signature,
            "algorithm": self.algorithm,
        }
        if self.scope_restriction is not None:
            d["scope_restriction"] = self.scope_restriction
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DelegationLink:
        return cls(
            delegator=data["delegator"],
            delegate=data["delegate"],
            scope_restriction=data.get("scope_restriction"),
            delegated_at=data.get("delegated_at", ""),
            signature=data.get("signature", ""),
            algorithm=data.get("algorithm", "EdDSA"),
        )


# ---------------------------------------------------------------------------
# Validity window
# ---------------------------------------------------------------------------

@dataclass
class ValidityWindow:
    """Temporal validity for a mandate.

    Three modes:
    - sequence: valid for a specific sequence_key (e.g. a session ID)
    - windowed: valid between not_before and not_after timestamps
    - state_bound: valid while a named state condition holds
    """
    mode: TemporalMode
    not_before: str | None = None       # ISO 8601 (windowed mode)
    not_after: str | None = None        # ISO 8601 (windowed mode)
    sequence_key: str | None = None     # opaque key (sequence mode)
    state_condition: str | None = None  # named condition (state_bound mode)
    max_uses: int | None = None         # optional use count limit

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"mode": self.mode.value}
        if self.not_before is not None:
            d["not_before"] = self.not_before
        if self.not_after is not None:
            d["not_after"] = self.not_after
        if self.sequence_key is not None:
            d["sequence_key"] = self.sequence_key
        if self.state_condition is not None:
            d["state_condition"] = self.state_condition
        if self.max_uses is not None:
            d["max_uses"] = self.max_uses
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidityWindow:
        return cls(
            mode=TemporalMode(data["mode"]),
            not_before=data.get("not_before"),
            not_after=data.get("not_after"),
            sequence_key=data.get("sequence_key"),
            state_condition=data.get("state_condition"),
            max_uses=data.get("max_uses"),
        )


# ---------------------------------------------------------------------------
# Mandate credential
# ---------------------------------------------------------------------------

@dataclass
class Mandate:
    """A signed credential authorizing an agent to act within constraints.

    Attributes:
        mandate_id: Unique identifier (URN format).
        issuer: DID or agent_id of the mandate issuer.
        subject: DID or agent_id of the authorized agent.
        issued_at: ISO 8601 timestamp of issuance.
        validity: Temporal validity window.
        constraints: JSON Schema dict defining what the mandate authorizes.
        delegation_chain: Ordered list of delegation links (root -> holder).
        revocation_endpoint: Optional URL to check revocation status.
        metadata: Additional key-value pairs.
        signature: Base64url signature over all fields except signature itself.
        algorithm: Signing algorithm ("EdDSA" or "ES256").
        status: Current mandate status.
    """
    mandate_id: str = ""
    issuer: str = ""
    subject: str = ""
    issued_at: str = ""
    validity: ValidityWindow | None = None
    constraints: dict[str, Any] = field(default_factory=dict)
    delegation_chain: list[DelegationLink] = field(default_factory=list)
    revocation_endpoint: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    algorithm: str = "EdDSA"
    status: MandateStatus = MandateStatus.ACTIVE

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict (canonical form for signing)."""
        d: dict[str, Any] = {
            "mandate_id": self.mandate_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "issued_at": self.issued_at,
            "algorithm": self.algorithm,
            "status": self.status.value,
        }
        if self.validity is not None:
            d["validity"] = self.validity.to_dict()
        if self.constraints:
            d["constraints"] = self.constraints
        if self.delegation_chain:
            d["delegation_chain"] = [link.to_dict() for link in self.delegation_chain]
        if self.revocation_endpoint is not None:
            d["revocation_endpoint"] = self.revocation_endpoint
        if self.metadata:
            d["metadata"] = self.metadata
        if self.signature:
            d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Mandate:
        """Deserialize from dict."""
        validity = None
        if "validity" in data:
            validity = ValidityWindow.from_dict(data["validity"])

        chain = []
        if "delegation_chain" in data:
            chain = [DelegationLink.from_dict(link) for link in data["delegation_chain"]]

        status = MandateStatus.ACTIVE
        if "status" in data:
            try:
                status = MandateStatus(data["status"])
            except ValueError:
                status = MandateStatus.ACTIVE

        return cls(
            mandate_id=data.get("mandate_id", ""),
            issuer=data.get("issuer", ""),
            subject=data.get("subject", ""),
            issued_at=data.get("issued_at", ""),
            validity=validity,
            constraints=data.get("constraints", {}),
            delegation_chain=chain,
            revocation_endpoint=data.get("revocation_endpoint"),
            metadata=data.get("metadata", {}),
            signature=data.get("signature", ""),
            algorithm=data.get("algorithm", "EdDSA"),
            status=status,
        )

    @classmethod
    def create(
        cls,
        issuer: str,
        subject: str,
        constraints: dict[str, Any],
        validity: ValidityWindow,
        revocation_endpoint: str | None = None,
        metadata: dict[str, Any] | None = None,
        delegation_chain: list[DelegationLink] | None = None,
        algorithm: str = "EdDSA",
    ) -> Mandate:
        """Factory method to create a new mandate with auto-generated ID and timestamp."""
        now = datetime.now(timezone.utc)
        return cls(
            mandate_id=f"urn:concordia:mandate:{uuid.uuid4()}",
            issuer=issuer,
            subject=subject,
            issued_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            validity=validity,
            constraints=constraints,
            delegation_chain=delegation_chain or [],
            revocation_endpoint=revocation_endpoint,
            metadata=metadata or {},
            algorithm=algorithm,
        )


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------

@dataclass
class MandateVerificationResult:
    """Result of mandate verification."""
    valid: bool
    mandate_id: str = ""
    issuer: str = ""
    subject: str = ""
    checks: dict[str, bool] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "mandate_id": self.mandate_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "checks": self.checks,
            "errors": self.errors,
            "warnings": self.warnings,
        }


# ---------------------------------------------------------------------------
# JSON Schema for mandate validation
# ---------------------------------------------------------------------------

MANDATE_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:concordia:schema:mandate:v1",
    "title": "Concordia Mandate Credential",
    "description": "A signed credential authorizing an agent to act within constraints.",
    "type": "object",
    "required": ["mandate_id", "issuer", "subject", "issued_at", "validity", "constraints", "algorithm"],
    "properties": {
        "mandate_id": {
            "type": "string",
            "pattern": "^urn:concordia:mandate:",
            "description": "Unique mandate identifier in URN format",
        },
        "issuer": {
            "type": "string",
            "minLength": 1,
            "description": "DID or agent_id of the mandate issuer",
        },
        "subject": {
            "type": "string",
            "minLength": 1,
            "description": "DID or agent_id of the authorized agent",
        },
        "issued_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 issuance timestamp",
        },
        "algorithm": {
            "type": "string",
            "enum": ["EdDSA", "ES256"],
            "description": "Signing algorithm",
        },
        "status": {
            "type": "string",
            "enum": ["active", "expired", "revoked", "suspended"],
            "default": "active",
        },
        "validity": {
            "type": "object",
            "required": ["mode"],
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["sequence", "windowed", "state_bound"],
                },
                "not_before": {"type": "string", "format": "date-time"},
                "not_after": {"type": "string", "format": "date-time"},
                "sequence_key": {"type": "string"},
                "state_condition": {"type": "string"},
                "max_uses": {"type": "integer", "minimum": 1},
            },
            "allOf": [
                {
                    "if": {"properties": {"mode": {"const": "windowed"}}},
                    "then": {"required": ["not_before", "not_after"]},
                },
                {
                    "if": {"properties": {"mode": {"const": "sequence"}}},
                    "then": {"required": ["sequence_key"]},
                },
                {
                    "if": {"properties": {"mode": {"const": "state_bound"}}},
                    "then": {"required": ["state_condition"]},
                },
            ],
        },
        "constraints": {
            "type": "object",
            "description": "JSON Schema defining what the mandate authorizes",
            "minProperties": 1,
        },
        "delegation_chain": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["delegator", "delegate", "delegated_at", "signature", "algorithm"],
                "properties": {
                    "delegator": {"type": "string", "minLength": 1},
                    "delegate": {"type": "string", "minLength": 1},
                    "delegated_at": {"type": "string", "format": "date-time"},
                    "signature": {"type": "string", "minLength": 1},
                    "algorithm": {"type": "string", "enum": ["EdDSA", "ES256"]},
                    "scope_restriction": {"type": "object"},
                },
            },
        },
        "revocation_endpoint": {
            "type": "string",
            "format": "uri",
        },
        "metadata": {
            "type": "object",
        },
        "signature": {
            "type": "string",
            "description": "Base64url signature over all fields except signature",
        },
    },
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Constraint schema for mandate constraints (what a mandate authorizes)
# ---------------------------------------------------------------------------

# Common constraint patterns that mandates can use.
# These are JSON Schema snippets for reuse.
CONSTRAINT_PATTERNS: dict[str, dict[str, Any]] = {
    "max_spend": {
        "type": "object",
        "properties": {
            "amount": {"type": "number", "minimum": 0},
            "currency": {"type": "string", "minLength": 3, "maxLength": 3},
        },
        "required": ["amount", "currency"],
    },
    "allowed_categories": {
        "type": "object",
        "properties": {
            "categories": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
            },
        },
        "required": ["categories"],
    },
    "geographic_bounds": {
        "type": "object",
        "properties": {
            "allowed_regions": {
                "type": "array",
                "items": {"type": "string"},
            },
            "excluded_regions": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
    },
    "temporal_budget": {
        "type": "object",
        "properties": {
            "max_sessions": {"type": "integer", "minimum": 1},
            "max_concurrent": {"type": "integer", "minimum": 1},
        },
    },
}
