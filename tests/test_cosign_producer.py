"""Counterparty co-signature PRODUCER tests + cross-repo parity.

The acceptance gate for this build (Cosign_Producer_Build_Spawn_Prompt_2026-06-10):

  1. A real co-signed receipt fixture produced by ``concordia.cosign`` passes a
     FAITHFUL, INDEPENDENT port of Verascore's verifier
     (verascore/src/lib/concordia-cosignature.ts:
     ``canonicalCosignBytes`` + ``verifyCounterpartyCosignatureStructural``).
     The port below is re-implemented from the TS source on purpose — it does
     NOT call ``concordia.cosign``'s own canonicalization — so a byte-level
     divergence between the two repos' canonicalization would make the
     signature fail to verify here.
  2. Happy-path co-sign; recursive signature-strip canonicalization;
     wrong-counterparty key rejected; missing counterparty -> clean
     single-signed receipt; lone-surrogate input -> fail-closed.

Anchor: Wiki/concepts/concordia-bilateral-attestation-anchor-2026-06-09.md
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from concordia import cosign
from concordia.cosign import CosignError
from concordia.signing import KeyPair
from tests.generate_cosign_fixture import build_fixture, keypair_from_seed

FIXTURE_PATH = (
    pathlib.Path(__file__).parent / "fixtures" / "concordia_cosigned_receipt.json"
)


def _kp(seed_byte: int) -> KeyPair:
    return keypair_from_seed(bytes([seed_byte]) * 32)


def _session_data(counterparty_did: str, **overrides) -> dict:
    data = {
        "session_id": "concordia:session:test-0001",
        "counterparty_did": counterparty_did,
        "outcome": "agreed",
        "rounds": 3,
        "duration_seconds": 120,
        "terms_count": 2,
        "concessions_made": 1,
        "fulfillment_status": "fulfilled",
        "negotiation_competence": 80,
    }
    data.update(overrides)
    return data


# ===========================================================================
# INDEPENDENT port of verascore/src/lib/concordia-cosignature.ts + crypto.ts.
# Deliberately re-implemented from the TS source (NOT importing concordia.cosign
# canonicalization) so this is a genuine cross-repo parity check.
# ===========================================================================

def _ts_strip_signatures(value):
    """Port of stripSignatures() in concordia-cosignature.ts."""
    if isinstance(value, list):
        return [_ts_strip_signatures(v) for v in value]
    if isinstance(value, dict):
        return {
            k: _ts_strip_signatures(v)
            for k, v in value.items()
            if k != "signature"
        }
    return value


def _ts_stable_stringify(value) -> str:
    """Port of stableStringify() in concordia-cosignature.ts.

    Keys sorted by UTF-16 code unit (JS default sort); no whitespace; numbers
    and strings via JSON.stringify semantics. The fixture uses only ASCII keys
    and integer/string values, where Python ``json.dumps`` and ``sorted`` match
    V8's JSON.stringify and Array.prototype.sort byte-for-byte.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):  # bool already handled above
        return json.dumps(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("Cannot canonicalize non-finite number")
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_ts_stable_stringify(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys())  # JS default sort == UTF-16 code unit order
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + _ts_stable_stringify(value[k])
                for k in keys
            )
            + "}"
        )
    raise TypeError(f"Cannot canonicalize type: {type(value).__name__}")


def _ts_canonical_cosign_bytes(receipt) -> bytes:
    """Port of canonicalCosignBytes()."""
    return _ts_stable_stringify(_ts_strip_signatures(receipt)).encode("utf-8")


def _ts_base64url_to_bytes(s: str) -> bytes:
    """Port of base64urlToBuffer() in crypto.ts."""
    b64 = s.replace("-", "+").replace("_", "/")
    pad = (4 - (len(b64) % 4)) % 4
    return base64.b64decode(b64 + "=" * pad)


def _ts_public_key_from_did(did: str) -> bytes | None:
    """Port of publicKeyFromDid() in crypto.ts (base64url multibase branch).

    Concordia/Sanctuary emit the base64url 'z' variant, which the TS tries
    first; base58btc is the standard-did:key fallback and is not exercised by
    Concordia-produced receipts.
    """
    if not did.startswith("did:key:z"):
        return None
    encoded = did[len("did:key:z"):]
    try:
        decoded = _ts_base64url_to_bytes(encoded)
    except Exception:
        return None
    if len(decoded) == 34 and decoded[0] == 0xED and decoded[1] == 0x01:
        return decoded[2:]
    return None


def _ts_verify_ed25519(message: bytes, signature: bytes, pubkey: bytes) -> bool:
    """Port of verifyEd25519() in crypto.ts."""
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, message)
        return True
    except Exception:
        return False


def _ts_find_counterparty_signature(receipt: dict, counterparty_did: str):
    """Port of findCounterpartySignature(): exactly-one match or reject."""
    parties = receipt.get("parties")
    parties = parties if isinstance(parties, list) else []
    matches = [
        p
        for p in parties
        if isinstance(p, dict)
        and (p.get("agent_id") == counterparty_did or p.get("agentId") == counterparty_did)
    ]
    if len(matches) != 1:
        return None
    sig = matches[0].get("signature")
    return sig if isinstance(sig, str) and len(sig) > 0 else None


def verascore_verify_counterparty_cosignature_structural(
    receipt, counterparty_did: str, publisher_did: str
) -> bool:
    """FAITHFUL port of verifyCounterpartyCosignatureStructural().

    Bound to verascore/src/lib/concordia-cosignature.ts (lines 137-163). Any
    divergence between Concordia's ``canonical_json`` and the TS stableStringify
    would make a Concordia-produced signature fail here.
    """
    try:
        if not isinstance(receipt, dict):
            return False
        if not counterparty_did or not counterparty_did.startswith("did:key:"):
            return False
        if not publisher_did:
            return False
        if counterparty_did == publisher_did:  # non-self
            return False
        counterparty_key = _ts_public_key_from_did(counterparty_did)
        if counterparty_key is None:
            return False
        sig_b64 = _ts_find_counterparty_signature(receipt, counterparty_did)
        if not sig_b64:
            return False
        signature = _ts_base64url_to_bytes(sig_b64)
        if len(signature) != 64:
            return False
        message = _ts_canonical_cosign_bytes(receipt)
        return _ts_verify_ed25519(message, signature, counterparty_key)
    except Exception:
        return False


# ===========================================================================
# Acceptance gate 1 — cross-repo parity fixture.
# ===========================================================================

def test_committed_fixture_passes_verascore_port() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["expected_counterparty_verified"] is True
    assert verascore_verify_counterparty_cosignature_structural(
        fixture["receipt"],
        fixture["counterparty_did"],
        fixture["publisher_did"],
    )


def test_committed_fixture_is_regenerable_no_drift() -> None:
    """The committed JSON must match what the deterministic generator produces,
    so the fixture cannot silently drift from the producer."""
    committed = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    regenerated = build_fixture()
    assert committed == regenerated


def test_fixture_counterparty_pubkey_matches_did() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    from_did = cosign.public_key_bytes_from_did_key(fixture["counterparty_did"])
    from_b64 = _ts_base64url_to_bytes(fixture["counterparty_public_key_b64url"])
    assert from_did == from_b64


# ===========================================================================
# Acceptance gate 2 — required producer scenarios.
# ===========================================================================

def test_happy_path_cosign_verifies() -> None:
    publisher, counterparty = _kp(11), _kp(22)
    pub_did = cosign.did_key_for(publisher)
    cp_did = cosign.did_key_for(counterparty)

    receipt = cosign.build_cosigned_receipt(
        _session_data(cp_did),
        pub_did,
        counterparty_signer=cosign.keypair_signer(counterparty),
    )

    # The counterparty entry carries a real base64url signature.
    cp_entry = next(p for p in receipt["parties"] if p["agent_id"] == cp_did)
    assert isinstance(cp_entry["signature"], str) and cp_entry["signature"]
    # And it passes the independent Verascore port.
    assert verascore_verify_counterparty_cosignature_structural(receipt, cp_did, pub_did)


def test_signature_strip_is_recursive_and_canonical_invariant() -> None:
    """Every nested ``signature`` field is removed before canonicalizing, so
    receipts that differ ONLY in signature fields canonicalize identically."""
    nested = {
        "concordia": "0.5",
        "signature": "TOP_LEVEL_SHOULD_BE_STRIPPED",
        "outcome": {"status": "agreed", "signature": "NESTED_SHOULD_BE_STRIPPED"},
        "parties": [
            {"agent_id": "a", "behavior": {"concessions": 1}, "signature": "P0"},
            {"agent_id": "b", "behavior": {"signature": "DEEP"}, "signature": "P1"},
        ],
        "references": [{"id": "r1", "signature": "REF"}],
    }
    stripped = cosign.strip_signatures(nested)

    # No "signature" key survives anywhere in the graph.
    def _no_sig(value) -> bool:
        if isinstance(value, dict):
            return "signature" not in value and all(_no_sig(v) for v in value.values())
        if isinstance(value, list):
            return all(_no_sig(v) for v in value)
        return True

    assert _no_sig(stripped)

    # Two receipts differing only by signature values -> identical canonical bytes.
    variant = json.loads(json.dumps(nested))
    variant["signature"] = "DIFFERENT"
    variant["parties"][0]["signature"] = "ALSO_DIFFERENT"
    variant["parties"][1]["behavior"]["signature"] = "ALSO_DEEP_DIFFERENT"
    assert cosign.canonical_cosign_bytes(nested) == cosign.canonical_cosign_bytes(variant)

    # And the producer's canonical bytes equal the independent Verascore port's.
    assert cosign.canonical_cosign_bytes(nested) == _ts_canonical_cosign_bytes(nested)


def test_wrong_counterparty_key_is_rejected() -> None:
    publisher = _kp(11)
    real_counterparty = _kp(22)
    impostor = _kp(33)
    pub_did = cosign.did_key_for(publisher)
    cp_did = cosign.did_key_for(real_counterparty)  # receipt names the real CP

    # Sign with the WRONG key (impostor), but place it on the real CP's entry.
    receipt = cosign.build_cosigned_receipt(
        _session_data(cp_did),
        pub_did,
        counterparty_signer=cosign.keypair_signer(impostor),
    )
    cp_entry = next(p for p in receipt["parties"] if p["agent_id"] == cp_did)
    assert cp_entry["signature"]  # a signature is present...
    # ...but it does not verify against the named counterparty's did:key.
    assert not verascore_verify_counterparty_cosignature_structural(receipt, cp_did, pub_did)


def test_missing_counterparty_yields_clean_single_signed_receipt() -> None:
    """No signer -> receipt is emitted single-signed: the counterparty entry has
    NO ``signature`` key at all (never an empty/placeholder string)."""
    publisher, counterparty = _kp(11), _kp(22)
    pub_did = cosign.did_key_for(publisher)
    cp_did = cosign.did_key_for(counterparty)

    receipt = cosign.build_cosigned_receipt(_session_data(cp_did), pub_did)

    cp_entry = next(p for p in receipt["parties"] if p["agent_id"] == cp_did)
    assert "signature" not in cp_entry  # fail-closed: absent, not empty
    # Verascore treats it as not co-signed (contributes nothing), but it is
    # well-formed and verification simply returns False.
    assert not verascore_verify_counterparty_cosignature_structural(receipt, cp_did, pub_did)


def test_signer_that_fails_yields_single_signed_not_fabricated() -> None:
    publisher, counterparty = _kp(11), _kp(22)
    pub_did = cosign.did_key_for(publisher)
    cp_did = cosign.did_key_for(counterparty)

    def _broken_signer(_receipt):
        raise RuntimeError("counterparty unreachable")

    receipt = cosign.build_cosigned_receipt(
        _session_data(cp_did), pub_did, counterparty_signer=_broken_signer
    )
    cp_entry = next(p for p in receipt["parties"] if p["agent_id"] == cp_did)
    assert "signature" not in cp_entry

    # A signer returning empty/None must NOT produce an empty signature field.
    for bad in (None, "", b"x"):
        r = cosign.build_cosigned_receipt(
            _session_data(cp_did), pub_did, counterparty_signer=lambda _r, v=bad: v
        )
        e = next(p for p in r["parties"] if p["agent_id"] == cp_did)
        assert "signature" not in e


def test_lone_surrogate_input_fails_closed() -> None:
    """A lone UTF-16 surrogate is not canonicalizable (composes with #69). The
    low-level cosign raises; the high-level builder falls back to single-signed
    rather than emitting a fabricated/empty co-signature."""
    publisher, counterparty = _kp(11), _kp(22)
    pub_did = cosign.did_key_for(publisher)
    cp_did = cosign.did_key_for(counterparty)

    poisoned = {
        "concordia": "0.5",
        "counterparty_did": cp_did,
        "note": "bad \ud800 surrogate",
        "parties": [{"agent_id": cp_did, "behavior": {}}],
    }
    with pytest.raises(ValueError):
        cosign.canonical_cosign_bytes(poisoned)
    with pytest.raises(ValueError):
        cosign.cosign_receipt(poisoned, counterparty)

    # High-level builder: a session whose field carries a lone surrogate
    # collapses to single-signed (the signer raises, build_cosigned_receipt
    # swallows and returns the unsigned receipt).
    sd = _session_data(cp_did, fulfillment_status="bad \ud800")
    receipt = cosign.build_cosigned_receipt(
        sd, pub_did, counterparty_signer=cosign.keypair_signer(counterparty)
    )
    cp_entry = next(p for p in receipt["parties"] if p["agent_id"] == cp_did)
    assert "signature" not in cp_entry


# ===========================================================================
# Placement + did:key codec unit coverage.
# ===========================================================================

def test_place_cosignature_fail_closed_paths() -> None:
    base = {
        "counterparty_did": "did:key:zCP",
        "parties": [
            {"agent_id": "did:key:zPUB", "behavior": {}},
            {"agent_id": "did:key:zCP", "behavior": {}},
        ],
    }
    # Happy placement.
    out = cosign.place_counterparty_cosignature(base, "did:key:zCP", "SIG")
    assert out["parties"][1]["signature"] == "SIG"
    # Input is not mutated.
    assert "signature" not in base["parties"][1]

    # Empty / non-str signature -> refuse.
    with pytest.raises(CosignError):
        cosign.place_counterparty_cosignature(base, "did:key:zCP", "")
    with pytest.raises(CosignError):
        cosign.place_counterparty_cosignature(base, "did:key:zCP", None)  # type: ignore[arg-type]

    # Zero matching parties -> refuse.
    with pytest.raises(CosignError):
        cosign.place_counterparty_cosignature(base, "did:key:zUNKNOWN", "SIG")

    # Ambiguous: two entries match -> refuse (attacker can't smuggle a 2nd entry).
    ambiguous = {
        "counterparty_did": "did:key:zCP",
        "parties": [
            {"agent_id": "did:key:zCP", "behavior": {}},
            {"agent_id": "did:key:zCP", "behavior": {}},
        ],
    }
    with pytest.raises(CosignError):
        cosign.place_counterparty_cosignature(ambiguous, "did:key:zCP", "SIG")

    # No parties[] -> refuse.
    with pytest.raises(CosignError):
        cosign.place_counterparty_cosignature({"counterparty_did": "x"}, "x", "SIG")


def test_did_key_codec_roundtrip_and_rejection() -> None:
    kp = _kp(7)
    did = cosign.did_key_for(kp)
    assert did.startswith("did:key:z")
    # Round-trips back to the same raw public key, and matches the TS port.
    assert cosign.public_key_bytes_from_did_key(did) == kp.public_key_bytes()
    assert _ts_public_key_from_did(did) == kp.public_key_bytes()

    # Non-did:key inputs decode to None (did:web etc. are not verifiable here).
    assert cosign.public_key_bytes_from_did_key("did:web:example.com#agent") is None
    assert cosign.public_key_bytes_from_did_key("did:key:zNOTREALb64!!") is None
    assert cosign.public_key_bytes_from_did_key("") is None

    # Wrong key length is rejected at encode time.
    with pytest.raises(ValueError):
        cosign.ed25519_did_key(b"\x00" * 31)


def test_did_key_matches_sanctuary_deriveagentid_encoding() -> None:
    """did:key:z<base64url(0xed01 || pubkey)> — the exact form Verascore's
    deriveAgentId / publicKeyToDidBase64url emits and publicKeyFromDid decodes."""
    raw = _kp(9).public_key_bytes()
    expected = "did:key:z" + base64.urlsafe_b64encode(b"\xed\x01" + raw).rstrip(b"=").decode()
    assert cosign.ed25519_did_key(raw) == expected
