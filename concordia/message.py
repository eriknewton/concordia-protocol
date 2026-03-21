"""Concordia message envelope and hash-chain transcript (§4, §9.3).

Every message follows the standard envelope format. Each message includes
the SHA-256 hash of the previous message, forming an immutable chain.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .signing import KeyPair, canonical_json, sign_message
from .types import AgentIdentity, MessageType

PROTOCOL_VERSION = "0.1.0"


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id(prefix: str = "msg") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def compute_hash(message: dict[str, Any]) -> str:
    """Compute the SHA-256 hash of a message for chain integrity (§9.3).

    Returns the hash in the format ``sha256:<hex>``.
    """
    payload = canonical_json(message)
    digest = hashlib.sha256(payload).hexdigest()
    return f"sha256:{digest}"


# The genesis hash — used as prev_hash for the first message in a session.
GENESIS_HASH = f"sha256:{'0' * 64}"


def build_envelope(
    *,
    message_type: MessageType,
    session_id: str,
    sender: AgentIdentity,
    body: dict[str, Any],
    key_pair: KeyPair,
    prev_hash: str = GENESIS_HASH,
    recipients: list[AgentIdentity] | None = None,
    in_reply_to: str | None = None,
    reasoning: str | None = None,
    ttl: int | None = None,
    message_id: str | None = None,
) -> dict[str, Any]:
    """Construct a signed Concordia message envelope.

    The message is signed with the sender's Ed25519 key pair and includes
    the hash of the previous message for transcript integrity.
    """
    msg: dict[str, Any] = {
        "concordia": PROTOCOL_VERSION,
        "type": message_type.value,
        "id": message_id or _new_id(),
        "session_id": session_id,
        "timestamp": _utcnow(),
        "from": sender.to_dict(),
        "prev_hash": prev_hash,
        "body": body,
    }

    if recipients:
        msg["to"] = [r.to_dict() for r in recipients]
    if in_reply_to:
        msg["in_reply_to"] = in_reply_to
    if reasoning:
        msg["reasoning"] = reasoning
    if ttl is not None:
        msg["ttl"] = ttl

    # Sign the message (§9.2)
    msg["signature"] = sign_message(msg, key_pair)

    return msg


def validate_chain(messages: list[dict[str, Any]]) -> bool:
    """Validate the hash chain of a message sequence.

    Each message's ``prev_hash`` must equal the SHA-256 hash of the
    preceding message. The first message must reference the genesis hash.
    """
    if not messages:
        return True

    if messages[0].get("prev_hash") != GENESIS_HASH:
        return False

    for i in range(1, len(messages)):
        expected = compute_hash(messages[i - 1])
        if messages[i].get("prev_hash") != expected:
            return False

    return True
