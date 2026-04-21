"""Reputation attestation generation (§9.6).

Every completed Concordia session — whether it ends in agreement, rejection,
or expiry — produces a Reputation Attestation: a signed, structured record
of what happened.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
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

# WP2 v0.4.0: generalized references[] shape — forward-compat with CMPC v0.5
# primitive types (chain_session, predicate, mandate). Only `receipt` is
# emitted by generate_attestation() today; other `type` values are accepted
# by the schema and treated as opaque refs until v0.5 adds type-specific
# resolution.
REFERENCE_TYPES = ("receipt", "chain_session", "predicate", "mandate")
REFERENCE_RELATIONSHIPS = ("supersedes", "extends", "fulfills", "references")

# WP3 v0.4.0: three-mode validity_temporal on attestations. Distinct from the
# models/mandate.py::ValidityWindow (sequence/windowed/state_bound) which is
# the trust-evidence-format #1734 envelope shape. Unification across the two
# is v0.5+ work. Build plan specifies these three modes explicitly.
VALIDITY_TEMPORAL_MODES = ("absolute", "relative", "window")


def _parse_iso8601(ts: str, field_name: str) -> datetime:
    """Parse an ISO 8601 UTC timestamp string. Accepts trailing 'Z'."""
    if not isinstance(ts, str):
        raise ValueError(f"{field_name} must be an ISO 8601 string")
    s = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as e:
        raise ValueError(f"{field_name} is not a valid ISO 8601 timestamp: {e}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _validate_validity_temporal(vt: Any) -> dict[str, Any]:
    """Validate a validity_temporal tagged union. Returns the normalized dict."""
    if not isinstance(vt, dict):
        raise ValueError("validity_temporal must be a dict")
    mode = vt.get("mode")
    if mode not in VALIDITY_TEMPORAL_MODES:
        raise ValueError(
            f"validity_temporal.mode {mode!r} not in {VALIDITY_TEMPORAL_MODES}"
        )
    if mode == "absolute":
        required = ("from", "until")
        missing = [k for k in required if k not in vt]
        if missing:
            raise ValueError(f"validity_temporal[absolute] missing: {missing}")
        frm = _parse_iso8601(vt["from"], "validity_temporal.from")
        until = _parse_iso8601(vt["until"], "validity_temporal.until")
        if until <= frm:
            raise ValueError("validity_temporal[absolute]: until must be after from")
        return {"mode": "absolute", "from": vt["from"], "until": vt["until"]}
    if mode == "relative":
        required = ("from", "duration_seconds")
        missing = [k for k in required if k not in vt]
        if missing:
            raise ValueError(f"validity_temporal[relative] missing: {missing}")
        _parse_iso8601(vt["from"], "validity_temporal.from")
        duration = vt["duration_seconds"]
        if not isinstance(duration, int) or duration < 1:
            raise ValueError(
                "validity_temporal[relative].duration_seconds must be a positive int"
            )
        return {"mode": "relative", "from": vt["from"], "duration_seconds": duration}
    # window
    required = ("start", "end", "duration_seconds")
    missing = [k for k in required if k not in vt]
    if missing:
        raise ValueError(f"validity_temporal[window] missing: {missing}")
    start = _parse_iso8601(vt["start"], "validity_temporal.start")
    end = _parse_iso8601(vt["end"], "validity_temporal.end")
    if end <= start:
        raise ValueError("validity_temporal[window]: end must be after start")
    duration = vt["duration_seconds"]
    if not isinstance(duration, int) or duration < 1:
        raise ValueError(
            "validity_temporal[window].duration_seconds must be a positive int"
        )
    if duration > (end - start).total_seconds():
        raise ValueError(
            "validity_temporal[window].duration_seconds exceeds the window span"
        )
    return {
        "mode": "window",
        "start": vt["start"],
        "end": vt["end"],
        "duration_seconds": duration,
    }


def is_valid_now(
    attestation: dict[str, Any], now: datetime | None = None
) -> bool:
    """Return True if the attestation's validity_temporal contains ``now``.

    If the attestation has no ``validity_temporal`` field, returns True
    (no temporal constraint). Added in v0.4.0 (WP3).
    """
    vt = attestation.get("validity_temporal")
    if vt is None:
        return True
    if not isinstance(vt, dict) or "mode" not in vt:
        return False
    now_dt = now or datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    mode = vt["mode"]
    if mode == "absolute":
        frm = _parse_iso8601(vt["from"], "validity_temporal.from")
        until = _parse_iso8601(vt["until"], "validity_temporal.until")
        return frm <= now_dt < until
    if mode == "relative":
        frm = _parse_iso8601(vt["from"], "validity_temporal.from")
        until = frm + timedelta(seconds=int(vt["duration_seconds"]))
        return frm <= now_dt < until
    if mode == "window":
        start = _parse_iso8601(vt["start"], "validity_temporal.start")
        end = _parse_iso8601(vt["end"], "validity_temporal.end")
        # Valid during any N-second window inside [start, end]. Any instant
        # between [start, end - duration_seconds + ... ] could be "inside
        # some window." Build plan: "verifier checks any window matches."
        # Interpretation: the attestation is currently valid if now is
        # inside [start, end] AND at least a duration_seconds-sized tail
        # remains before end (i.e., a window anchored at `now` still fits).
        if not (start <= now_dt < end):
            return False
        # A window anchored at now fits if (end - now) >= duration_seconds.
        duration = timedelta(seconds=int(vt["duration_seconds"]))
        return (end - now_dt) >= duration
    return False


def _validate_reference(ref: Any, index: int) -> dict[str, Any]:
    """Validate a single reference dict against the {type, id, relationship} shape."""
    if not isinstance(ref, dict):
        raise ValueError(f"references[{index}] must be a dict, got {type(ref).__name__}")
    missing = [k for k in ("type", "id", "relationship") if k not in ref]
    if missing:
        raise ValueError(
            f"references[{index}] missing required keys: {missing}"
        )
    ref_type = ref["type"]
    ref_id = ref["id"]
    relationship = ref["relationship"]
    if ref_type not in REFERENCE_TYPES:
        raise ValueError(
            f"references[{index}].type {ref_type!r} not in {REFERENCE_TYPES}"
        )
    if not isinstance(ref_id, str) or not ref_id:
        raise ValueError(f"references[{index}].id must be a non-empty string")
    if relationship not in REFERENCE_RELATIONSHIPS:
        raise ValueError(
            f"references[{index}].relationship {relationship!r} "
            f"not in {REFERENCE_RELATIONSHIPS}"
        )
    return {"type": ref_type, "id": ref_id, "relationship": relationship}


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
    references: list[dict[str, Any]] | None = None,
    validity_temporal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a reputation attestation from a concluded session.

    Args:
        session: The concluded Session.
        key_pairs: Mapping of agent_id → KeyPair for signing.
        category: Optional transaction category (e.g. 'electronics.cameras').
        value_range: Optional value bucket (e.g. '1000-5000_USD').
        resolution_mechanism: How agreement was reached.
        references: Optional list of references to other signed artifacts
            that this attestation extends, supersedes, fulfills, or
            references. Each entry must be a dict with keys
            ``{type, id, relationship}``. ``type`` ∈
            ``{receipt, chain_session, predicate, mandate}``.
            ``relationship`` ∈
            ``{supersedes, extends, fulfills, references}``. The
            ``chain_session``, ``predicate``, and ``mandate`` types are
            reserved for CMPC primitives (v0.5) and treated as opaque in
            v0.4.0. Added in v0.4.0 (WP2).
        validity_temporal: Optional temporal validity window. Tagged
            union with three modes:
            ``{mode: "absolute", from, until}`` for fixed clock bounds,
            ``{mode: "relative", from, duration_seconds}`` for "valid
            for N seconds from anchor," or
            ``{mode: "window", start, end, duration_seconds}`` for
            "valid during any N-second window in [start, end]."
            When absent the attestation has no temporal constraint.
            Added in v0.4.0 (WP3).

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

    # WP2 v0.4.0: validate and normalize references[] if supplied
    if references:
        normalized_refs = [
            _validate_reference(ref, i) for i, ref in enumerate(references)
        ]
    else:
        normalized_refs = []

    # WP3 v0.4.0: validate validity_temporal if supplied
    normalized_vt: dict[str, Any] | None = None
    if validity_temporal is not None:
        normalized_vt = _validate_validity_temporal(validity_temporal)

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
        "references": normalized_refs,
    }
    if normalized_vt is not None:
        attestation["validity_temporal"] = normalized_vt

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
