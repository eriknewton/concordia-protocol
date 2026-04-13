"""Message signing and verification (§9.2).

Concordia messages are signed with Ed25519 (default) or ES256 (ECDSA P-256).
The signature covers the canonical JSON serialization of all fields except
the signature itself.
"""

from __future__ import annotations

import base64
import json
import math
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
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


@dataclass
class ES256KeyPair:
    """An ECDSA P-256 key pair for ES256 signing and verification."""

    private_key: EllipticCurvePrivateKey
    public_key: EllipticCurvePublicKey

    @classmethod
    def generate(cls) -> ES256KeyPair:
        """Generate a fresh P-256 key pair."""
        private = generate_private_key(SECP256R1())
        return cls(private_key=private, public_key=private.public_key())

    def public_key_bytes(self) -> bytes:
        """Return the uncompressed public key bytes (X9.62 format)."""
        return self.public_key.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

    def public_key_b64(self) -> str:
        """Return the public key as a URL-safe base64 string."""
        return base64.urlsafe_b64encode(self.public_key_bytes()).decode()

    def private_key_bytes(self) -> bytes:
        """Return the raw DER-encoded private key."""
        return self.private_key.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )


def _check_no_special_floats(data: Any) -> None:
    """Reject NaN, Infinity, and -0.0 which break deterministic JSON."""
    if isinstance(data, float):
        if math.isnan(data) or math.isinf(data):
            raise ValueError(f"Cannot serialize special float: {data}")
        if data == 0.0 and math.copysign(1.0, data) < 0:
            raise ValueError("Cannot serialize negative zero (-0.0)")
    elif isinstance(data, dict):
        for v in data.values():
            _check_no_special_floats(v)
    elif isinstance(data, (list, tuple)):
        for v in data:
            _check_no_special_floats(v)


def _format_number_ecmascript(value: int | float) -> str:
    """Format a number to match ECMAScript's JSON.stringify output.

    Implements the Number::toString rules from ECMA-262 §6.1.6.1.20 to ensure
    byte-identical output with V8's JSON.stringify for all finite numbers.

    Key differences from Python's default formatting:
    - Integer-valued floats drop the decimal: 1.0 -> "1" (not "1.0")
    - Decimal notation for large integers up to 10^21: 1e20 -> "100000000000000000000"
    - ECMAScript-style exponential notation for very large/small values
    """
    if isinstance(value, bool):
        raise TypeError("bool is not a JSON number")
    if isinstance(value, int):
        return str(value)

    # Float handling — special floats already rejected by _check_no_special_floats
    if value == 0.0:
        return "0"

    sign = ""
    if value < 0:
        sign = "-"
        value = -value

    # Integer-valued floats: format as integer (matching V8)
    if value.is_integer():
        int_val = int(value)
        s = str(int_val)
        if len(s) <= 21:
            # ECMAScript uses decimal notation for integers up to 21 digits
            return sign + s
        # For > 21 digits, use exponential notation
        trimmed = s.rstrip("0")
        exp = len(s) - 1
        if len(trimmed) == 1:
            return sign + trimmed + "e+" + str(exp)
        return sign + trimmed[0] + "." + trimmed[1:] + "e+" + str(exp)

    # Non-integer floats: parse Python's repr and reformat to ECMAScript rules.
    # Python's repr() uses the same shortest-representation algorithm as V8
    # (Grisu3/Dragon4), so the significant digits are identical — only the
    # decimal/exponential formatting thresholds differ.
    r = repr(value)

    # Parse into significant digits and exponent
    if "e" in r:
        m_part, e_part = r.split("e")
        exp_raw = int(e_part)
        if "." in m_part:
            int_p, frac_p = m_part.split(".")
            digits = int_p + frac_p
        else:
            digits = m_part
        # For "d.ddde+XX": n = exp_raw + 1 (one digit before decimal in mantissa)
        n = exp_raw + 1
    elif "." in r:
        int_p, frac_p = r.split(".")
        if int_p == "0":
            # Small decimal like 0.000123
            leading_zeros = len(frac_p) - len(frac_p.lstrip("0"))
            digits = frac_p.lstrip("0")
            n = -leading_zeros
        else:
            digits = int_p + frac_p
            n = len(int_p)
    else:
        # Shouldn't happen for non-integer float, but handle gracefully
        digits = r
        n = len(r)

    k = len(digits)

    # ECMAScript Number::toString formatting rules (ECMA-262 §6.1.6.1.20):
    if k <= n <= 21:
        # Decimal with trailing zeros: digits + "0" * (n - k)
        result = digits + "0" * (n - k)
    elif 0 < n <= 21:
        # Decimal point falls within the digits
        result = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        # Small decimal: "0." + (-n) zeros + digits
        result = "0." + "0" * (-n) + digits
    else:
        # Exponential notation
        e = n - 1
        e_str = ("+" if e >= 0 else "") + str(e)
        if k == 1:
            result = digits + "e" + e_str
        else:
            result = digits[0] + "." + digits[1:] + "e" + e_str

    return sign + result


def _stable_stringify(value: Any) -> str:
    """Recursive stable JSON serialization matching ECMAScript's JSON.stringify.

    This is the Python equivalent of TypeScript's stableStringify in bridge.ts.
    Both functions produce byte-identical output for the same input, enabling
    cross-repo signature verification (SEC-003).

    Rules:
    - Object keys are sorted alphabetically
    - No whitespace between tokens
    - Non-ASCII characters preserved (not escaped)
    - Numbers formatted per ECMAScript Number::toString
    - None/null -> "null"
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _format_number_ecmascript(value)
    if isinstance(value, str):
        # json.dumps with ensure_ascii=False matches V8's JSON.stringify for
        # string escaping: control chars U+0000-U+001F are \uXXXX-escaped,
        # quote and backslash are escaped, all other characters (including
        # non-ASCII) are emitted as raw UTF-8.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_stable_stringify(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys())
        pairs = (
            json.dumps(k, ensure_ascii=False) + ":" + _stable_stringify(value[k])
            for k in keys
        )
        return "{" + ",".join(pairs) + "}"
    raise TypeError(f"Cannot canonicalize type: {type(value).__name__}")


def canonical_json(data: dict[str, Any]) -> bytes:
    """Produce a deterministic JSON serialization for signing.

    Uses a manual recursive builder that matches ECMAScript's JSON.stringify
    with sorted keys, ensuring byte-identical output with TypeScript's
    stableStringify in Sanctuary's bridge.ts (SEC-003).

    Keys are sorted, no extra whitespace, non-ASCII characters are preserved
    (raw UTF-8, not escaped). Rejects special floats (NaN, Infinity, -0.0).
    """
    _check_no_special_floats(data)
    return _stable_stringify(data).encode("utf-8")


def sign_message(
    data: dict[str, Any],
    key_pair: KeyPair | ES256KeyPair,
    alg: str = "EdDSA",
) -> str:
    """Sign a message dict, returning a base64url-encoded signature.

    The ``signature`` field, if present, is excluded before signing.

    Args:
        data: The message dict to sign.
        key_pair: An Ed25519 KeyPair (for EdDSA) or ES256KeyPair (for ES256).
        alg: ``"EdDSA"`` (default) or ``"ES256"``.
    """
    signable = {k: v for k, v in data.items() if k != "signature"}
    _check_no_special_floats(signable)
    payload = canonical_json(signable)

    if alg == "ES256":
        if not isinstance(key_pair, ES256KeyPair):
            raise TypeError("ES256 requires an ES256KeyPair")
        raw_sig = key_pair.private_key.sign(payload, ECDSA(SHA256()))
    elif alg == "EdDSA":
        if not isinstance(key_pair, KeyPair):
            raise TypeError("EdDSA requires an Ed25519 KeyPair")
        raw_sig = key_pair.private_key.sign(payload)
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")

    return base64.urlsafe_b64encode(raw_sig).decode()


def verify_signature(
    data: dict[str, Any],
    signature: str,
    public_key: Ed25519PublicKey | EllipticCurvePublicKey,
    alg: str = "EdDSA",
) -> bool:
    """Verify a signature over a message dict.

    Args:
        data: The message dict that was signed.
        signature: Base64url-encoded signature.
        public_key: The signer's public key.
        alg: ``"EdDSA"`` (default) or ``"ES256"``.

    Returns True if valid, False if the signature does not match.
    """
    signable = {k: v for k, v in data.items() if k != "signature"}
    payload = canonical_json(signable)
    raw_sig = base64.urlsafe_b64decode(signature)
    try:
        if alg == "ES256":
            if not isinstance(public_key, EllipticCurvePublicKey):
                return False
            public_key.verify(raw_sig, payload, ECDSA(SHA256()))
        elif alg == "EdDSA":
            if not isinstance(public_key, Ed25519PublicKey):
                return False
            public_key.verify(raw_sig, payload)
        else:
            return False
        return True
    except Exception:
        return False
