"""Counterparty co-signature producer for Concordia negotiation receipts.

SECURITY (H1/H2, 2026-06-09): a Concordia receipt is bilateral evidence ("agent
A and agent B negotiated, here is how it went"), but the shipped wire format
carried only the PUBLISHER's signature. That let an agent self-mint negotiation
history naming any counterparty and pump its own trust-bearing score (H1), and
let a 2-DID actor manufacture the "counterparty evidence" that unlocks the
transactions Reliability gate (H2).

Verascore (the consumer, verascore#63) now REQUIRES the named ``counterparty_did``
party to have cryptographically co-signed a receipt before it can move a
trust-bearing score. This module is the PRODUCER half: it collects the
counterparty's Ed25519 signature over the canonical (signature-stripped) receipt
and places it on the counterparty's ``parties[]`` entry, so legitimate bilateral
receipts can earn the ``cryptographic`` tier and count again.

The co-sign contract is the shared cross-repo anchor
(Wiki/concepts/concordia-bilateral-attestation-anchor-2026-06-09.md):

1. **Who signs:** the ``counterparty_did`` party, in addition to the publisher.
2. **What they sign:** ``canonical_json`` of the receipt with EVERY ``signature``
   field removed recursively (so a signature can never cover itself or a
   sibling's signature). This is byte-identical to Verascore's
   ``canonicalCosignBytes`` (src/lib/concordia-cosignature.ts) and reuses the
   exact ``concordia/signing.py`` ``canonical_json`` serialization.
3. **Where it goes:** ``signature`` (base64url Ed25519) on the single
   ``parties[]`` entry whose ``agent_id == counterparty_did``.
4. **Identity:** first interop target is ``did:key`` counterparties — the Ed25519
   public key is embedded in the DID (self-contained, no network resolution, no
   SSRF).

**Fail closed (CLAUDE.md rule #5):** if the counterparty signature cannot be
collected, the receipt is emitted clearly single-signed (current behavior). A
malformed or empty co-signature field is NEVER written, and a co-signature is
NEVER fabricated under any error path.

If you change the canonical message (the strip rule or the serialization) or the
signature placement, that is an ANCHOR change requiring coordinator sign-off and
a same-change update to the anchor doc — not a unilateral edit. Canonicalization
must stay byte-identical across repos or every co-signed receipt fails.
"""

from __future__ import annotations

import base64
import copy
from typing import Any, Callable

from .signing import KeyPair, canonical_json

# Ed25519 multicodec prefix (0xed 0x01) used by the ``did:key`` multibase
# encoding. Verascore's publicKeyFromDid (src/lib/crypto.ts) decodes the same
# two-byte header. We emit the base64url variant under the "z" multibase prefix,
# matching Sanctuary's publicKeyToDidBase64url / deriveAgentId, which Verascore
# tries first.
_ED25519_MULTICODEC = b"\xed\x01"
_DID_KEY_PREFIX = "did:key:z"

# A collector that, given the receipt-to-be-signed, returns the counterparty's
# base64url Ed25519 signature over the canonical (signature-stripped) receipt.
# Returning a falsy value (or raising) means "counterparty unavailable" and the
# receipt is emitted single-signed.
CounterpartySigner = Callable[[dict[str, Any]], "str | None"]


class CosignError(Exception):
    """Raised when a counterparty co-signature cannot be placed safely.

    Placement fails closed: callers that want a single-signed fallback must
    catch this (``build_cosigned_receipt`` does) rather than emit a malformed
    receipt.
    """


# ---------------------------------------------------------------------------
# Canonical message (contract §2) — strip every signature, then canonicalize.
# ---------------------------------------------------------------------------

def strip_signatures(value: Any) -> Any:
    """Recursively drop every ``"signature"`` property from an object graph.

    The canonical message both parties sign is the receipt with ALL signature
    fields removed, so a signature can never sign over itself or over a
    sibling's signature. Byte-for-byte mirror of Verascore's ``stripSignatures``
    (src/lib/concordia-cosignature.ts).
    """
    if isinstance(value, dict):
        return {
            k: strip_signatures(v)
            for k, v in value.items()
            if k != "signature"
        }
    if isinstance(value, (list, tuple)):
        return [strip_signatures(v) for v in value]
    return value


def canonical_cosign_bytes(receipt: dict[str, Any]) -> bytes:
    """The exact bytes a counterparty signs: signature-stripped, canonicalized.

    Equivalent to Verascore's ``canonicalCosignBytes``:
    ``stableStringify(stripSignatures(receipt))`` as UTF-8. Reuses the shared
    ``canonical_json`` (RFC 8785 / ECMAScript JSON.stringify, UTF-16 key sort,
    raw non-ASCII) so a signature produced here verifies there.

    Raises ``ValueError`` for inputs that are not canonicalizable (special
    floats, lone UTF-16 surrogates — composes with the #69 fail-closed rule).
    """
    return canonical_json(strip_signatures(receipt))


# ---------------------------------------------------------------------------
# did:key codec (contract §4) — Ed25519 only, base64url multibase variant.
# ---------------------------------------------------------------------------

def ed25519_did_key(public_key_bytes: bytes) -> str:
    """Encode a raw 32-byte Ed25519 public key as a ``did:key`` string.

    Produces ``did:key:z<base64url(0xed01 || pubkey)>`` — the base64url variant
    Sanctuary/Concordia emit and Verascore's publicKeyFromDid decodes first.
    """
    if len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes")
    multicodec = _ED25519_MULTICODEC + public_key_bytes
    encoded = base64.urlsafe_b64encode(multicodec).rstrip(b"=").decode("ascii")
    return _DID_KEY_PREFIX + encoded


def public_key_bytes_from_did_key(did: str) -> bytes | None:
    """Decode the raw 32-byte Ed25519 public key from a base64url ``did:key``.

    Returns ``None`` for any DID that is not a base64url Ed25519 ``did:key:z``
    (e.g. did:web, base58btc-only, wrong multicodec). Mirrors the base64url
    branch of Verascore's publicKeyFromDid.
    """
    if not did.startswith(_DID_KEY_PREFIX):
        return None
    encoded = did[len(_DID_KEY_PREFIX):]
    # Restore base64url padding (Verascore's base64urlToBuffer does the same).
    padding = (4 - (len(encoded) % 4)) % 4
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=" * padding)
    except Exception:
        return None
    if len(decoded) == 34 and decoded[:2] == _ED25519_MULTICODEC:
        return decoded[2:]
    return None


def did_key_for(key_pair: KeyPair) -> str:
    """Convenience: the ``did:key`` for a Concordia Ed25519 key pair."""
    return ed25519_did_key(key_pair.public_key_bytes())


# ---------------------------------------------------------------------------
# Producing and placing the counterparty co-signature (contract §1, §3).
# ---------------------------------------------------------------------------

def cosign_receipt(receipt: dict[str, Any], key_pair: KeyPair) -> str:
    """Produce a base64url Ed25519 co-signature over the canonical receipt.

    The COUNTERPARTY calls this with its OWN key. The signature covers
    ``canonical_cosign_bytes(receipt)`` (all signatures stripped), so it is
    independent of where it is later placed and of any other party's signature.

    Raises ``ValueError`` if the receipt is not canonicalizable (fail-closed,
    composes with #69 surrogate rejection).
    """
    raw_sig = key_pair.private_key.sign(canonical_cosign_bytes(receipt))
    # Unpadded base64url, matching Verascore's bufferToBase64url convention.
    # Verascore's base64urlToBuffer re-adds padding on the verify side.
    return base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode("ascii")


def place_counterparty_cosignature(
    receipt: dict[str, Any],
    counterparty_did: str,
    signature: str,
) -> dict[str, Any]:
    """Return a copy of ``receipt`` with ``signature`` set on the counterparty's
    ``parties[]`` entry (the one whose ``agent_id == counterparty_did``).

    Fail closed (``CosignError``) when the placement would be unsafe:
      - the signature is missing/empty or not a string,
      - ``parties`` is absent or not a list,
      - zero entries match ``counterparty_did`` (nothing to co-sign), or
      - more than one entry matches (ambiguous — an attacker must not be able to
        smuggle a second counterparty entry; Verascore rejects >1 too).

    Never writes an empty/placeholder ``signature`` field.
    """
    if not isinstance(signature, str) or signature == "":
        raise CosignError("refusing to place an empty counterparty signature")

    parties = receipt.get("parties")
    if not isinstance(parties, list):
        raise CosignError("receipt has no parties[] to carry a co-signature")

    matches = [
        i
        for i, p in enumerate(parties)
        if isinstance(p, dict) and p.get("agent_id") == counterparty_did
    ]
    if len(matches) == 0:
        raise CosignError(
            f"no parties[] entry matches counterparty_did {counterparty_did!r}"
        )
    if len(matches) > 1:
        raise CosignError(
            f"ambiguous: {len(matches)} parties[] entries match "
            f"counterparty_did {counterparty_did!r}; refusing to co-sign"
        )

    out = copy.deepcopy(receipt)
    out["parties"][matches[0]]["signature"] = signature
    return out


# ---------------------------------------------------------------------------
# Receipt builder + one-shot co-sign (the producer entry points).
# ---------------------------------------------------------------------------

def build_concordia_receipt(
    session_data: dict[str, Any],
    publisher_did: str,
    *,
    protocol_version: str = "0.5",
    graceful_degradation: bool = False,
) -> dict[str, Any]:
    """Build the receipt object Verascore consumes, in single-signed form.

    Shape matches Verascore's ``normalizeConcordiaReceipt`` /
    ``verifyCounterpartyCosignatureStructural``: a top-level ``outcome`` object,
    and a ``parties[]`` array with the publisher first (no signature — the
    publisher authenticates the publish envelope) and the counterparty second
    (its ``signature`` is added later by the co-sign step).

    ``session_data`` is the behavioral-signal dict from
    ``verascore._extract_session_data`` (session_id, counterparty_did, outcome,
    rounds, duration_seconds, terms_count, concessions_made, fulfillment_status).
    No deal terms or prices (CLAUDE.md rule #8).
    """
    counterparty_did = session_data["counterparty_did"]
    return {
        "concordia": protocol_version,
        "session_id": session_data["session_id"],
        "counterparty_did": counterparty_did,
        "outcome": {
            "status": session_data["outcome"],
            "rounds": session_data["rounds"],
            "duration_seconds": session_data["duration_seconds"],
            "terms_count": session_data["terms_count"],
        },
        "parties": [
            {
                "agent_id": publisher_did,
                "role": "initiator",
                "behavior": {"concessions": session_data["concessions_made"]},
            },
            {
                "agent_id": counterparty_did,
                "role": "responder",
                "behavior": {},
            },
        ],
        "fulfillment": {"status": session_data["fulfillment_status"]},
        "graceful_degradation": graceful_degradation,
    }


def build_cosigned_receipt(
    session_data: dict[str, Any],
    publisher_did: str,
    *,
    counterparty_signer: CounterpartySigner | None = None,
    protocol_version: str = "0.5",
    graceful_degradation: bool = False,
) -> dict[str, Any]:
    """Build a receipt and co-sign it with the counterparty if one is available.

    ``counterparty_signer`` is a collector that returns the counterparty's
    base64url signature over the receipt (e.g. backed by the counterparty's key
    via ``cosign_receipt``). It is invoked on the fully-built, signature-free
    receipt so the bytes it signs match what Verascore re-derives.

    FAIL CLOSED: if no signer is supplied, or the signer returns nothing /
    raises, or the signature cannot be placed safely, the receipt is returned
    clearly single-signed — never with an empty or fabricated co-signature.
    """
    receipt = build_concordia_receipt(
        session_data,
        publisher_did,
        protocol_version=protocol_version,
        graceful_degradation=graceful_degradation,
    )
    if counterparty_signer is None:
        return receipt
    try:
        signature = counterparty_signer(receipt)
    except Exception:
        # Counterparty unavailable / signing failed (incl. non-canonicalizable
        # input). Single-signed is the safe, advertised fallback.
        return receipt
    if not signature or not isinstance(signature, str):
        return receipt
    try:
        return place_counterparty_cosignature(
            receipt, receipt["counterparty_did"], signature
        )
    except CosignError:
        return receipt


def keypair_signer(key_pair: KeyPair) -> CounterpartySigner:
    """A ``CounterpartySigner`` backed by a held Ed25519 key pair.

    For the in-memory reference implementation and tests, where the counterparty
    key is available in-process. In a live cross-agent negotiation the collector
    would instead round-trip the canonical bytes to the counterparty agent for
    signing; only the public key is ever needed on the publisher's side.
    """
    def _sign(receipt: dict[str, Any]) -> str:
        return cosign_receipt(receipt, key_pair)

    return _sign
