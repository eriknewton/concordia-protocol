"""Trust-evidence-format v1.0.0 envelope builder.

Wraps Concordia attestations into interoperable signed envelopes compatible
with the multi-provider trust evidence format (A2A Discussion #1734).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from .signing import (
    ES256KeyPair,
    KeyPair,
    canonical_json,
    _check_no_special_floats,
)

import base64

# Outcome status mapping: Concordia internal -> envelope standard
_OUTCOME_MAP = {
    "agreed": "ACCEPTED",
    "rejected": "REJECTED",
    "expired": "EXPIRED",
    "withdrawn": "WITHDRAWN",
}

ENVELOPE_VERSION = "1.0.0"
DEFAULT_EXPIRY_DAYS = 7


def _map_attestation_to_payload(attestation: dict[str, Any]) -> dict[str, Any]:
    """Map Concordia attestation fields to envelope payload fields."""
    import concordia

    outcome = attestation.get("outcome", {})
    parties = attestation.get("parties", [])
    meta = attestation.get("meta", {})
    fulfillment = attestation.get("fulfillment")

    # Find the initiator (first party) behavior for quality signals
    initiator_behavior = {}
    counterparty_did = None
    if len(parties) >= 2:
        initiator_behavior = parties[0].get("behavior", {})
        counterparty_did = parties[1].get("agent_id")
    elif len(parties) == 1:
        initiator_behavior = parties[0].get("behavior", {})

    # Build quality_signals from behavior
    quality_signals: dict[str, Any] = {}
    concession = initiator_behavior.get("concession_magnitude")
    if concession is not None:
        quality_signals["concession_magnitude"] = concession
    reasoning = initiator_behavior.get("reasoning_provided")
    if reasoning is not None:
        quality_signals["reasoning_quality"] = reasoning
    response_time = initiator_behavior.get("response_time_avg_seconds")
    if response_time is not None:
        quality_signals["response_latency_p50_ms"] = response_time * 1000

    # Build commitment block
    outcome_status = _OUTCOME_MAP.get(
        outcome.get("status", "").lower(), "REJECTED"
    )
    commitment: dict[str, Any] = {
        "committed": outcome_status == "ACCEPTED",
        "commitment_hash": attestation.get("transcript_hash"),
    }
    if fulfillment:
        commitment["honored"] = fulfillment.get("honored")
        commitment["honored_verified_at"] = fulfillment.get("verified_at")
    else:
        commitment["honored"] = None
        commitment["honored_verified_at"] = None

    payload: dict[str, Any] = {
        "session_id": attestation.get("session_id"),
        "session_protocol": "concordia",
        "session_protocol_version": concordia.__version__,
        "outcome": outcome_status,
        "counterparty_did": counterparty_did,
        "completion_timestamp": attestation.get("timestamp"),
        "rounds_to_completion": outcome.get("rounds"),
        "quality_signals": quality_signals,
        "commitment": commitment,
        "privacy_guarantees": {
            "deal_terms_disclosed": False,
            "counterparty_identity_disclosed": True,
            "zk_proof_available": False,
        },
    }

    return payload


def build_trust_evidence_envelope(
    attestation: dict[str, Any],
    key_pair: KeyPair | ES256KeyPair,
    provider_did: str,
    provider_kid: str,
    subject_did: str,
    references: list[dict[str, Any]] | None = None,
    visibility: str = "public",
    expires_at: str | None = None,
) -> dict[str, Any]:
    """Build a trust-evidence-format v1.0.0 envelope from a Concordia attestation.

    Args:
        attestation: Attestation dict as produced by ``generate_attestation()``.
        key_pair: Ed25519 KeyPair or ES256KeyPair for signing.
        provider_did: DID of the envelope provider.
        provider_kid: Key identifier for the signing key.
        subject_did: DID of the subject agent.
        references: Additional reference objects to merge into ``references[]``.
        visibility: ``"public"``, ``"restricted"``, or ``"private"``.
        expires_at: ISO 8601 expiry timestamp (default: 7 days from now).

    Returns:
        The complete v1.0.0 envelope dict with signature.
    """
    now = datetime.now(timezone.utc)
    issued_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    if expires_at is None:
        exp = now + timedelta(days=DEFAULT_EXPIRY_DAYS)
        expires_at = exp.strftime("%Y-%m-%dT%H:%M:%SZ")

    session_id = attestation.get("session_id", "")
    transcript_hash = attestation.get("transcript_hash", "")

    # Auto-populate source_session reference per #1734 consensus:
    # full shape is {kind, urn, verified_at, verifier_did, hash}
    auto_ref = {
        "kind": "source_session",
        "urn": f"urn:concordia:session:{session_id}",
        "verified_at": issued_at,
        "verifier_did": provider_did,
        "hash": transcript_hash,
    }
    all_references = [auto_ref]
    if references:
        for ref in references:
            # kind and urn are required. verified_at, verifier_did, and hash
            # are expected per #1734 but not enforced — other reference kinds
            # (e.g. chain_state, mandate_proof) may not have a verifier.
            if not isinstance(ref, dict) or "kind" not in ref or "urn" not in ref:
                raise ValueError(
                    "Each reference must be a dict with at least 'kind' and 'urn'"
                )
            all_references.append(ref)

    # Determine algorithm from key type
    if isinstance(key_pair, ES256KeyPair):
        alg = "ES256"
    else:
        alg = "EdDSA"

    payload = _map_attestation_to_payload(attestation)

    envelope: dict[str, Any] = {
        "envelope_version": ENVELOPE_VERSION,
        "envelope_id": f"urn:uuid:{uuid.uuid4()}",
        "issued_at": issued_at,
        "expires_at": expires_at,
        "refresh_hint": {
            "strategy": "event_driven",
            "events": [
                "session_completed",
                "dispute_raised",
                "commitment_verified",
            ],
            "max_age_seconds": 604800,
        },
        "validity_temporal": {
            "mode": "sequence",
            "sequence_key": session_id,
            "baseline": None,
            "aliasing_risk": None,
        },
        "provider": {
            "did": provider_did,
            "category": "transactional",
            "kid": provider_kid,
            "name": "Concordia",
        },
        "subject": {"did": subject_did},
        "category": "transactional",
        "visibility": visibility,
        "references": all_references,
        "payload": payload,
    }

    # Sign over everything except the signature field (detached JWS style)
    _check_no_special_floats(envelope)
    sig_payload = canonical_json(envelope)

    if alg == "ES256":
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives.hashes import SHA256

        raw_sig = key_pair.private_key.sign(sig_payload, ECDSA(SHA256()))
    else:
        raw_sig = key_pair.private_key.sign(sig_payload)

    sig_b64 = base64.urlsafe_b64encode(raw_sig).decode()

    envelope["signature"] = {
        "alg": alg,
        "kid": provider_kid,
        "value": sig_b64,
    }

    return envelope


def verify_envelope_signature(
    envelope: dict[str, Any],
    public_key: Any,
    alg: str = "EdDSA",
) -> bool:
    """Verify the signature on a trust-evidence envelope.

    Args:
        envelope: The complete envelope dict (with signature).
        public_key: The signer's public key.
        alg: ``"EdDSA"`` or ``"ES256"``.

    Returns:
        True if the signature is valid.
    """
    sig_block = envelope.get("signature")
    if not sig_block or "value" not in sig_block:
        return False

    # Reconstruct the signed payload (envelope without signature)
    signable = {k: v for k, v in envelope.items() if k != "signature"}
    payload = canonical_json(signable)
    raw_sig = base64.urlsafe_b64decode(sig_block["value"])

    try:
        if alg == "ES256":
            from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
            from cryptography.hazmat.primitives.hashes import SHA256

            public_key.verify(raw_sig, payload, ECDSA(SHA256()))
        else:
            public_key.verify(raw_sig, payload)
        return True
    except Exception:
        return False
