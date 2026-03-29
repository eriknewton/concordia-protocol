"""Sanctuary Bridge — optional integration between Concordia and Sanctuary Framework.

When Sanctuary is present, Concordia can leverage its sovereignty infrastructure:

1. **Commitment binding** — When a Concordia negotiation reaches AGREED, the
   agreement terms are committed to Sanctuary's L3 cryptographic commitment
   system. This produces a tamper-proof, verifiable commitment that goes
   beyond Concordia's protocol-level agreement.

2. **Reputation recording** — Concordia session receipts (attestations) are
   recorded in Sanctuary's L4 reputation system, building the agent's
   verifiable, portable reputation alongside the Concordia reputation service.

3. **Identity bridging** — Maps Concordia agent_ids to Sanctuary DIDs,
   allowing attestations to reference the agent's sovereign identity.

The bridge is entirely optional. When Sanctuary is absent, Concordia's own
protocol-level commitments, signatures, and reputation system work independently.
This preserves the non-dependency principle from the viral strategy.

Architecture:
    The bridge does NOT directly call Sanctuary MCP tools (they may be in a
    separate process). Instead, it produces the correctly-shaped payloads
    that a client can forward to Sanctuary. This keeps the bridge portable
    and testable without requiring a running Sanctuary server.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .signing import KeyPair, canonical_json


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class SanctuaryBridgeConfig:
    """Configuration for the Sanctuary bridge.

    Attributes:
        enabled: Whether to generate Sanctuary payloads on agreement.
        identity_map: Maps Concordia agent_ids to Sanctuary identity_ids.
        did_map: Maps Concordia agent_ids to Sanctuary DIDs.
        default_context: Default reputation context for Sanctuary attestations.
        commitment_on_agree: Auto-generate commitment payloads on AGREED.
        reputation_on_receipt: Auto-generate reputation payloads on receipt.
    """

    enabled: bool = False
    identity_map: dict[str, str] = field(default_factory=dict)
    did_map: dict[str, str] = field(default_factory=dict)
    default_context: str = "concordia_negotiation"
    commitment_on_agree: bool = True
    reputation_on_receipt: bool = True

    def map_identity(self, concordia_agent_id: str, sanctuary_identity_id: str,
                     sanctuary_did: str | None = None) -> None:
        """Register a mapping from a Concordia agent to a Sanctuary identity."""
        self.identity_map[concordia_agent_id] = sanctuary_identity_id
        if sanctuary_did:
            self.did_map[concordia_agent_id] = sanctuary_did

    def get_sanctuary_id(self, concordia_agent_id: str) -> str | None:
        return self.identity_map.get(concordia_agent_id)

    def get_did(self, concordia_agent_id: str) -> str | None:
        return self.did_map.get(concordia_agent_id)


# ---------------------------------------------------------------------------
# Commitment payloads (L3)
# ---------------------------------------------------------------------------

def build_commitment_payload(
    session_id: str,
    agreed_terms: dict[str, Any],
    parties: list[str],
    transcript_hash: str | None = None,
) -> dict[str, Any]:
    """Build a Sanctuary-compatible commitment payload from a Concordia agreement.

    The commitment value is a canonical JSON representation of the agreement,
    suitable for passing to ``sanctuary/proof_commitment``.

    Returns a dict with:
        - ``tool``: The Sanctuary tool to call (``sanctuary/proof_commitment``)
        - ``arguments``: The arguments to pass
        - ``agreement_summary``: Human-readable summary of what's committed
    """
    if not agreed_terms or not isinstance(agreed_terms, dict):
        raise ValueError("agreed_terms must be a non-empty dict")
    if not parties or not isinstance(parties, list):
        raise ValueError("parties must be a non-empty list")

    agreement = {
        "concordia_session_id": session_id,
        "agreed_terms": agreed_terms,
        "parties": sorted(parties),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if transcript_hash:
        agreement["transcript_hash"] = transcript_hash

    # Canonical JSON for deterministic commitment value.
    # Uses canonical_json (not json.dumps) to ensure byte-identical output
    # with TypeScript's stableStringify for cross-repo verification (SEC-003).
    value = canonical_json(agreement).decode("utf-8")

    return {
        "tool": "sanctuary/proof_commitment",
        "arguments": {
            "value": value,
        },
        "agreement_summary": {
            "session_id": session_id,
            "parties": sorted(parties),
            "term_count": len(agreed_terms),
            "has_transcript_hash": transcript_hash is not None,
        },
        "raw_value": value,
    }


def build_reveal_payload(
    commitment: str,
    original_value: str,
    blinding_factor: str,
) -> dict[str, Any]:
    """Build a Sanctuary-compatible reveal payload.

    Used when a party needs to prove what was committed (e.g., in dispute
    resolution or audit).
    """
    return {
        "tool": "sanctuary/proof_reveal",
        "arguments": {
            "commitment": commitment,
            "value": original_value,
            "blinding_factor": blinding_factor,
        },
    }


# ---------------------------------------------------------------------------
# Reputation payloads (L4)
# ---------------------------------------------------------------------------

def build_reputation_payload(
    attestation: dict[str, Any],
    config: SanctuaryBridgeConfig,
    recording_agent_id: str,
) -> dict[str, Any] | None:
    """Build a Sanctuary-compatible reputation recording from a Concordia attestation.

    Maps Concordia attestation fields to Sanctuary's ``sanctuary/reputation_record``
    input schema. Returns None if the recording agent has no Sanctuary identity mapped.
    """
    sanctuary_id = config.get_sanctuary_id(recording_agent_id)
    if sanctuary_id is None:
        return None

    # Find the counterparty
    parties = attestation.get("parties", [])
    counterparty_id = None
    for party in parties:
        if party.get("agent_id") != recording_agent_id:
            counterparty_id = party.get("agent_id")
            break

    counterparty_did = config.get_did(counterparty_id) if counterparty_id else None

    # Map Concordia outcome to Sanctuary outcome
    outcome = attestation.get("outcome", {})
    concordia_status = outcome.get("status", "")
    sanctuary_result = _map_outcome_result(concordia_status)

    # Extract metrics from Concordia attestation
    metrics: dict[str, float] = {}
    for party in parties:
        if party.get("agent_id") == recording_agent_id:
            behavior = party.get("behavior", {})
            if "concession_magnitude" in behavior:
                metrics["concession_magnitude"] = behavior["concession_magnitude"]
            if "offers_made" in behavior:
                metrics["offers_made"] = float(behavior["offers_made"])
            break

    if outcome.get("rounds"):
        metrics["rounds"] = float(outcome["rounds"])
    if outcome.get("duration_seconds"):
        metrics["duration_seconds"] = float(outcome["duration_seconds"])

    # Context from attestation meta
    meta = attestation.get("meta", {})
    context = meta.get("category", config.default_context)

    arguments: dict[str, Any] = {
        "interaction_id": attestation.get("session_id", ""),
        "counterparty_did": counterparty_did or f"concordia:{counterparty_id or 'unknown'}",
        "outcome": {
            "type": "negotiation",
            "result": sanctuary_result,
            "metrics": metrics,
        },
        "context": context,
    }

    if sanctuary_id:
        arguments["identity_id"] = sanctuary_id

    return {
        "tool": "sanctuary/reputation_record",
        "arguments": arguments,
        "concordia_attestation_id": attestation.get("attestation_id", ""),
        "concordia_session_id": attestation.get("session_id", ""),
    }


def _map_outcome_result(concordia_status: str) -> str:
    """Map a Concordia outcome status to a Sanctuary outcome result."""
    mapping = {
        "agreed": "completed",
        "rejected": "failed",
        "expired": "failed",
        "withdrawn": "partial",
    }
    return mapping.get(concordia_status, "partial")


# ---------------------------------------------------------------------------
# Full bridge output — combines commitment + reputation
# ---------------------------------------------------------------------------

@dataclass
class BridgeResult:
    """The output of running the Sanctuary bridge on a Concordia event.

    Contains pre-built payloads ready to forward to Sanctuary MCP tools.
    """

    session_id: str
    commitment_payload: dict[str, Any] | None = None
    reputation_payloads: list[dict[str, Any]] = field(default_factory=list)
    skipped_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "session_id": self.session_id,
            "sanctuary_enabled": self.commitment_payload is not None
            or len(self.reputation_payloads) > 0,
            "commitment_payload": self.commitment_payload,
            "reputation_payloads": self.reputation_payloads,
            "reputation_payload_count": len(self.reputation_payloads),
        }
        if self.skipped_reason:
            d["skipped_reason"] = self.skipped_reason
        return d


def bridge_on_agreement(
    session_id: str,
    agreed_terms: dict[str, Any],
    parties: list[str],
    transcript_hash: str | None,
    config: SanctuaryBridgeConfig,
) -> BridgeResult:
    """Run the bridge when a Concordia session reaches AGREED.

    Produces:
        - A commitment payload (if config.commitment_on_agree)
        - No reputation payloads yet (those come from attestations)
    """
    if not session_id or not isinstance(session_id, str) or not session_id.strip():
        return BridgeResult(
            session_id=session_id or "",
            skipped_reason="Invalid session_id: must be a non-empty string.",
        )

    if not config.enabled:
        return BridgeResult(
            session_id=session_id,
            skipped_reason="Sanctuary bridge is not enabled.",
        )

    result = BridgeResult(session_id=session_id)

    if config.commitment_on_agree:
        result.commitment_payload = build_commitment_payload(
            session_id=session_id,
            agreed_terms=agreed_terms,
            parties=parties,
            transcript_hash=transcript_hash,
        )

    return result


def bridge_on_attestation(
    attestation: dict[str, Any],
    config: SanctuaryBridgeConfig,
) -> BridgeResult:
    """Run the bridge when a Concordia attestation is generated.

    Produces reputation payloads for each party that has a Sanctuary identity
    mapped.
    """
    session_id = attestation.get("session_id", "")

    if not session_id or not isinstance(session_id, str):
        return BridgeResult(
            session_id=session_id or "",
            skipped_reason="Invalid session_id in attestation.",
        )

    parties = attestation.get("parties", [])
    if not parties:
        return BridgeResult(
            session_id=session_id,
            skipped_reason="Attestation has no parties.",
        )

    if not config.enabled:
        return BridgeResult(
            session_id=session_id,
            skipped_reason="Sanctuary bridge is not enabled.",
        )

    result = BridgeResult(session_id=session_id)

    if config.reputation_on_receipt:
        for party in parties:
            agent_id = party.get("agent_id")
            if agent_id and config.get_sanctuary_id(agent_id):
                payload = build_reputation_payload(
                    attestation=attestation,
                    config=config,
                    recording_agent_id=agent_id,
                )
                if payload:
                    result.reputation_payloads.append(payload)

    return result
