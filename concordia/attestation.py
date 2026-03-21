"""Reputation attestation generation (§9.6).

Every completed Concordia session — whether it ends in agreement, rejection,
or expiry — produces a Reputation Attestation: a signed, structured record
of what happened.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from .message import compute_hash
from .signing import KeyPair, canonical_json, sign_message
from .types import (
    BehaviorRecord,
    OutcomeStatus,
    PartyRole,
    ResolutionMechanism,
    SessionState,
)

if TYPE_CHECKING:
    from .session import Session

ATTESTATION_VERSION = "0.1.0"


def _map_state_to_outcome(state: SessionState) -> OutcomeStatus:
    """Map a terminal session state to an attestation outcome status."""
    mapping = {
        SessionState.AGREED: OutcomeStatus.AGREED,
        SessionState.REJECTED: OutcomeStatus.REJECTED,
        SessionState.EXPIRED: OutcomeStatus.EXPIRED,
    }
    return mapping.get(state, OutcomeStatus.REJECTED)


def generate_attestation(
    session: Session,
    key_pairs: dict[str, KeyPair],
    *,
    category: str | None = None,
    value_range: str | None = None,
    resolution_mechanism: ResolutionMechanism = ResolutionMechanism.DIRECT,
) -> dict[str, Any]:
    """Generate a reputation attestation from a concluded session.

    Args:
        session: The concluded Session.
        key_pairs: Mapping of agent_id → KeyPair for signing.
        category: Optional transaction category (e.g. 'electronics.cameras').
        value_range: Optional value bucket (e.g. '1000-5000_USD').
        resolution_mechanism: How agreement was reached.

    Returns:
        A dict conforming to the attestation schema (§9.6.2).
    """
    if not session.is_terminal and session.state != SessionState.EXPIRED:
        raise ValueError(
            f"Cannot generate attestation for session in state {session.state.value}"
        )

    outcome_status = _map_state_to_outcome(session.state)

    # Count terms from the open message body, if available
    terms_count = 0
    if session.terms:
        terms_count = len(session.terms)

    # Build outcome
    outcome: dict[str, Any] = {
        "status": outcome_status.value,
        "rounds": session.round_count,
        "duration_seconds": session.duration_seconds(),
    }
    if terms_count > 0:
        outcome["terms_count"] = terms_count
    outcome["resolution_mechanism"] = resolution_mechanism.value

    # Build party records with signatures
    parties: list[dict[str, Any]] = []
    for agent_id, role in session.parties.items():
        behavior = session.get_behavior(agent_id)
        party_record: dict[str, Any] = {
            "agent_id": agent_id,
            "role": role.value,
            "behavior": behavior.to_dict(),
        }
        # Sign the party's behavioral record
        if agent_id in key_pairs:
            sig = sign_message(party_record, key_pairs[agent_id])
            party_record["signature"] = sig
        else:
            party_record["signature"] = ""
        parties.append(party_record)

    # Compute transcript hash
    transcript_hash = _compute_transcript_hash(session.transcript)

    # Build meta
    meta: dict[str, Any] = {
        "extensions_used": [],
        "mediator_invoked": False,
    }
    if category:
        meta["category"] = category
    if value_range:
        meta["value_range"] = value_range

    attestation: dict[str, Any] = {
        "concordia_attestation": ATTESTATION_VERSION,
        "attestation_id": f"att_{uuid.uuid4().hex[:8]}",
        "session_id": session.session_id,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "outcome": outcome,
        "parties": parties,
        "meta": meta,
        "transcript_hash": transcript_hash,
        "fulfillment": None,
    }

    return attestation


def _compute_transcript_hash(transcript: list[dict[str, Any]]) -> str:
    """Compute a single SHA-256 hash over the entire transcript."""
    import hashlib
    from .signing import canonical_json

    combined = b""
    for msg in transcript:
        combined += canonical_json(msg)
    digest = hashlib.sha256(combined).hexdigest()
    return f"sha256:{digest}"
