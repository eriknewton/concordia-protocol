"""Ed25519 message signing and verification (§9.2).

Every Concordia message is signed with Ed25519. The signature covers the
canonical JSON serialization of all fields except the signature itself.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


@dataclass
class KeyPair:
    """An Ed25519 key pair for signing and verifying Concordia messages."""

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls) -> KeyPair:
        """Generate a fresh Ed25519 key pair."""
        private = Ed25519PrivateKey.generate()
        return cls(private_key=private, public_key=private.public_key())

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte public key."""
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def public_key_b64(self) -> str:
        """Return the public key as a URL-safe base64 string."""
        return base64.urlsafe_b64encode(self.public_key_bytes()).decode()

    def private_key_bytes(self) -> bytes:
        """Return the raw 32-byte private key."""
        return self.private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )


def canonical_json(data: dict[str, Any]) -> bytes:
    """Produce a deterministic JSON serialization for signing.

    Keys are sorted, no extra whitespace, and non-ASCII characters
    are preserved (ensure_ascii=False for readability).
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign_message(data: dict[str, Any], key_pair: KeyPair) -> str:
    """Sign a message dict, returning a base64-encoded Ed25519 signature.

    The ``signature`` field, if present, is excluded before signing.
    """
    signable = {k: v for k, v in data.items() if k != "signature"}
    payload = canonical_json(signable)
    raw_sig = key_pair.private_key.sign(payload)
    return base64.urlsafe_b64encode(raw_sig).decode()


def verify_signature(data: dict[str, Any], signature: str,
                     public_key: Ed25519PublicKey) -> bool:
    """Verify an Ed25519 signature over a message dict.

    Returns True if valid, False if the signature does not match.
    """
    signable = {k: v for k, v in data.items() if k != "signature"}
    payload = canonical_json(signable)
    raw_sig = base64.urlsafe_b64decode(signature)
    try:
        public_key.verify(raw_sig, payload)
        return True
    except Exception:
        return False
