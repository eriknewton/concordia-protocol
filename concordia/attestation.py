"""Reputation attestation generation (§9.6).

Every completed Concordia session — whether it ends in agreement, rejection,
or expiry — produces a Reputation Attestation: a signed, structured record
of what happened.
"""

from __future__ import annotations

import re
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

# v0.5 SPEC §11.5: generalized attestation-level references[] shape. Per
# §11.5.6 the four canonical type values are receipt, chain_session,
# predicate, mandate. Per §11.5.5 the four canonical relationship values
# are supersedes, extends, fulfills, references. Per §11.5.8 (MUST) unknown
# values for either field are preserved as opaque strings rather than
# rejected, for forward-compat with v0.x extensions.
REFERENCE_TYPES = ("receipt", "chain_session", "predicate", "mandate")
REFERENCE_RELATIONSHIPS = ("supersedes", "extends", "fulfills", "references")
WEAK_RELATIONSHIP = "references"

# WP3 v0.4.0: three-mode validity_temporal on attestations. Distinct from the
# models/mandate.py::ValidityWindow (sequence/windowed/state_bound) which is
# the trust-evidence-format #1734 envelope shape. Unification across the two
# is v0.5+ work. Build plan specifies these three modes explicitly.
VALIDITY_TEMPORAL_MODES = ("absolute", "relative", "window")

# L3 hardening (security audit 2026-06-09): attestation meta context is
# constrained at issuance so a party cannot stuff its own raw deal terms
# into the exported record (SPEC §9.6.6 privacy invariant: behavioral
# signals only, never deal terms).
#
# value_range is an ENUMERATED bucket vocabulary, not a free grammar. A
# regex that merely enforced "<low>-<high>_<CCY>" would still let an
# issuer encode the exact price (e.g. "4350-4351_USD"); fixing the bands
# to a 1-5-10 logarithmic scale caps the channel at order-of-magnitude
# granularity, which is exactly what SPEC §9.6.6 promises ("logarithmic
# buckets ... rather than exact amounts"). The full value is
# "<bucket>_<CURRENCY>" where CURRENCY is an ISO 4217-shaped 3-letter
# uppercase code (shape-validated, not enumerated).
VALUE_RANGE_BUCKETS = (
    "0-100",
    "100-500",
    "500-1000",
    "1000-5000",
    "5000-10000",
    "10000-50000",
    "50000-100000",
    "100000-500000",
    "500000-1000000",
    "1000000+",
)
# \Z (not $) so a trailing newline cannot smuggle past the anchor.
_VALUE_RANGE_PATTERN = re.compile(
    r"^(?:" + "|".join(re.escape(b) for b in VALUE_RANGE_BUCKETS) + r")_[A-Z]{3}\Z"
)

# category is a coarse dotted taxonomy path (e.g. "electronics.cameras").
# The character class excludes whitespace and punctuation so prose deal
# terms ("selling at $1200/unit") cannot ride in it; the length cap bounds
# the residual channel.
MAX_CATEGORY_LENGTH = 64
_CATEGORY_PATTERN = re.compile(r"^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\Z")

# references[] caps (L3 + exhaustion lens): bound the count, each string
# field, and the serialized size of the opaque extensions escape hatch.
MAX_REFERENCES = 32
MAX_REFERENCE_TYPE_LENGTH = 64
MAX_REFERENCE_RELATIONSHIP_LENGTH = 64
MAX_REFERENCE_ID_LENGTH = 256
MAX_REFERENCE_OPTIONAL_STRING_LENGTH = 256
MAX_REFERENCE_EXTENSIONS_BYTES = 2048


def _validate_value_range(value_range: Any) -> str:
    """Validate value_range against the enumerated bucket vocabulary.

    Fail-closed: anything outside "<bucket>_<CCY>" raises ValueError.
    The invalid input is deliberately NOT echoed back in the error
    (content-injection lens: attestation errors can land in logs and
    MCP responses).
    """
    if (
        not isinstance(value_range, str)
        or len(value_range) > 32
        or not _VALUE_RANGE_PATTERN.match(value_range)
    ):
        raise ValueError(
            "value_range must be '<bucket>_<CURRENCY>' where bucket is one "
            f"of {VALUE_RANGE_BUCKETS} and CURRENCY is a 3-letter uppercase "
            "code (e.g. '1000-5000_USD'); free-text values are rejected "
            "per SPEC §9.6.6 (attestations carry bucketed context, never "
            "raw deal terms)"
        )
    return value_range


def _validate_category(category: Any) -> str:
    """Validate category as a coarse dotted taxonomy path.

    Fail-closed: prose or oversized input raises ValueError. The invalid
    input is deliberately NOT echoed back in the error.
    """
    if (
        not isinstance(category, str)
        or len(category) > MAX_CATEGORY_LENGTH
        or not _CATEGORY_PATTERN.match(category)
    ):
        raise ValueError(
            "category must be a dotted lowercase taxonomy path of at most "
            f"{MAX_CATEGORY_LENGTH} chars matching "
            "'[a-z0-9_-]+(.[a-z0-9_-]+)*' (e.g. 'electronics.cameras'); "
            "free-text values are rejected per SPEC §9.6.6"
        )
    return category


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
        required: tuple[str, ...] = ("from", "until")
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
    """Validate a single attestation-level reference per SPEC §11.5.

    Required keys ``type``, ``id``, ``relationship`` are enforced
    structurally per §11.5.6. ``type`` and ``relationship`` values outside
    the canonical vocabularies (§11.5.5, §11.5.6) are preserved as opaque
    strings per the §11.5.8 MUST forward-compat clause. Read-side schemas
    accept non-empty strings per §11.5.5 and §11.5.8; the canonical
    vocabulary remains the emit-side default. Optional keys (``version``,
    ``signed_at``, ``signer_did``, ``extensions``) are passed through
    when present so callers can roundtrip extension data per §11.5.6.

    L3 hardening (security audit 2026-06-09): every string field is
    length-capped and ``extensions`` is size-capped (canonical JSON
    bytes), so the §11.5.8 opaque-string forward-compat clause cannot be
    used to smuggle free-text deal terms or unbounded payloads into a
    signed attestation. Fail-closed: oversize or wrongly-typed values
    raise ValueError; invalid values are never echoed back.
    """
    if not isinstance(ref, dict):
        raise ValueError(
            f"references[{index}] must be a dict, got {type(ref).__name__} "
            f"per SPEC §11.5.6"
        )
    missing = [k for k in ("type", "id", "relationship") if k not in ref]
    if missing:
        raise ValueError(
            f"references[{index}] missing required keys {missing} "
            f"per SPEC §11.5.6 (id, type, relationship)"
        )
    ref_type = ref["type"]
    ref_id = ref["id"]
    relationship = ref["relationship"]
    if (
        not isinstance(ref_type, str)
        or not ref_type
        or len(ref_type) > MAX_REFERENCE_TYPE_LENGTH
    ):
        raise ValueError(
            f"references[{index}].type must be a non-empty string of at "
            f"most {MAX_REFERENCE_TYPE_LENGTH} chars per SPEC §11.5.6"
        )
    if (
        not isinstance(ref_id, str)
        or not ref_id
        or len(ref_id) > MAX_REFERENCE_ID_LENGTH
    ):
        raise ValueError(
            f"references[{index}].id must be a non-empty string of at "
            f"most {MAX_REFERENCE_ID_LENGTH} chars per SPEC §11.5.6"
        )
    if (
        not isinstance(relationship, str)
        or not relationship
        or len(relationship) > MAX_REFERENCE_RELATIONSHIP_LENGTH
    ):
        raise ValueError(
            f"references[{index}].relationship must be a non-empty string "
            f"of at most {MAX_REFERENCE_RELATIONSHIP_LENGTH} chars "
            f"per SPEC §11.5.6"
        )
    normalized: dict[str, Any] = {
        "type": ref_type,
        "id": ref_id,
        "relationship": relationship,
    }
    for optional_key in ("version", "signed_at", "signer_did"):
        if optional_key in ref:
            value = ref[optional_key]
            if (
                not isinstance(value, str)
                or len(value) > MAX_REFERENCE_OPTIONAL_STRING_LENGTH
            ):
                raise ValueError(
                    f"references[{index}].{optional_key} must be a string "
                    f"of at most {MAX_REFERENCE_OPTIONAL_STRING_LENGTH} "
                    f"chars"
                )
            normalized[optional_key] = value
    if "extensions" in ref:
        extensions = ref["extensions"]
        if not isinstance(extensions, dict):
            raise ValueError(
                f"references[{index}].extensions must be an object"
            )
        try:
            extensions_bytes = len(canonical_json(extensions))
        except (TypeError, ValueError):
            raise ValueError(
                f"references[{index}].extensions is not canonically "
                f"serializable"
            )
        if extensions_bytes > MAX_REFERENCE_EXTENSIONS_BYTES:
            raise ValueError(
                f"references[{index}].extensions exceeds "
                f"{MAX_REFERENCE_EXTENSIONS_BYTES} canonical-JSON bytes"
            )
        normalized["extensions"] = extensions
    return normalized


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
        category: Optional transaction category (e.g.
            'electronics.cameras'). Must be a dotted lowercase taxonomy
            path of at most 64 chars; free text is rejected (§9.6.6).
        value_range: Optional value bucket (e.g. '1000-5000_USD'). Must
            be '<bucket>_<CURRENCY>' where bucket is one of the
            VALUE_RANGE_BUCKETS logarithmic bands and CURRENCY is a
            3-letter uppercase code; free text is rejected (§9.6.6).
        resolution_mechanism: How agreement was reached.
        references: Optional list of attestation-level references per
            SPEC §11.5. Each entry is a dict with required keys
            ``{type, id, relationship}`` and optional keys
            ``{version, signed_at, signer_did, extensions}`` per §11.5.6.
            Canonical ``type`` values: receipt, chain_session, predicate,
            mandate (§11.5.6). Canonical ``relationship`` values:
            supersedes, extends, fulfills, references (§11.5.5).
            Implementations preserve unknown values as opaque strings per
            §11.5.8 forward-compat. The layering boundary against
            envelope-level references is documented in §11.5.4. Added in
            v0.4.0 (WP2); ratified in v0.5 (SPEC §11.5).
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
    # L3 hardening (security audit 2026-06-09): caller-supplied context is
    # validated fail-closed at issuance so raw deal terms can never ride
    # in an exported attestation (§9.6.6).
    if category:
        meta["category"] = _validate_category(category)
    if value_range:
        meta["value_range"] = _validate_value_range(value_range)

    # WP2 v0.4.0: validate and normalize references[] if supplied
    if references:
        if len(references) > MAX_REFERENCES:
            raise ValueError(
                f"references[] exceeds the maximum of {MAX_REFERENCES} "
                f"entries"
            )
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
