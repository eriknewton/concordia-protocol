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

    # Attach a plaintext 4-line summary for quick human/agent inspection.
    attestation["summary"] = generate_receipt_summary(attestation)

    return attestation


def generate_receipt_summary(receipt: dict[str, Any]) -> str:
    """Generate a 4-line plaintext summary of a session receipt/attestation.

    Format:
        Parties: <party_a_did_short>, <party_b_did_short>
        Topic: <topic or N/A>
        Outcome: <AGREED/REJECTED/EXPIRED>
        Transcript hash: <first 16 chars of hash>

    Args:
        receipt: A full attestation dict (as produced by generate_attestation).

    Returns:
        A four-line plaintext string (newline-separated).
    """
    def _short(did: str) -> str:
        if not did:
            return "unknown"
        # Keep last 12 chars for short display (or whole string if shorter).
        return did if len(did) <= 16 else f"...{did[-12:]}"

    parties = receipt.get("parties", []) or []
    party_ids = [p.get("agent_id", "") for p in parties]
    while len(party_ids) < 2:
        party_ids.append("")
    parties_line = f"Parties: {_short(party_ids[0])}, {_short(party_ids[1])}"

    meta = receipt.get("meta", {}) or {}
    topic = meta.get("category") or meta.get("topic") or "N/A"
    topic_line = f"Topic: {topic}"

    outcome = receipt.get("outcome", {}) or {}
    status = outcome.get("status", "")
    outcome_line = f"Outcome: {str(status).upper() if status else 'UNKNOWN'}"

    transcript_hash = receipt.get("transcript_hash", "") or ""
    # Strip sha256: prefix if present, take first 16 chars of the hex digest.
    digest = transcript_hash.split(":", 1)[1] if ":" in transcript_hash else transcript_hash
    hash_line = f"Transcript hash: {digest[:16]}"

    return "\n".join([parties_line, topic_line, outcome_line, hash_line])


def _compute_transcript_hash(transcript: list[dict[str, Any]]) -> str:
    """Compute a single SHA-256 hash over the entire transcript."""
    import hashlib
    from .signing import canonical_json

    combined = b""
    for msg in transcript:
        combined += canonical_json(msg)
    digest = hashlib.sha256(combined).hexdigest()
    return f"sha256:{digest}"
