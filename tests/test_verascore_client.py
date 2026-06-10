"""Tests for direct Verascore client reporting.

The envelope these tests pin is the live Verascore ``POST /api/publish``
contract (src/app/api/publish/route.ts, branch at commit a3e6090 / #63):

    {
      "type": "concordia-receipt",
      "publicKey": "<base64url raw 32-byte Ed25519 public key>",
      "signature": "<base64url raw 64-byte Ed25519 sig over JSON.stringify(data)>",
      "data": { "did": "<publisher did:key>", "receipt": { ... } }
    }

agentId is NOT sent (the route derives it from the verified publicKey).
"""

from __future__ import annotations

import base64
import json
import urllib.error

import pytest

from concordia import cosign
from concordia.signing import KeyPair, canonical_json
from concordia.verascore import VerascoreClient


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _session_data(counterparty_did: str = "did:key:counterparty") -> dict:
    return {
        "session_id": "session-123",
        "counterparty_did": counterparty_did,
        "outcome": "agreed",
        "rounds": 3,
        "duration_seconds": 42,
        "terms_count": 2,
        "concessions_made": 1,
        "fulfillment_status": "fulfilled",
        "negotiation_competence": 90,
    }


class _Response:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body

    def close(self) -> None:
        return None


def test_report_concordia_receipt_posts_signed_envelope(monkeypatch) -> None:
    captured = {}

    def fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        captured["headers"] = req.headers
        captured["raw"] = req.data
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Response(b'{"status":"accepted"}')

    monkeypatch.setattr("concordia.verascore.urllib.request.urlopen", fake_urlopen)

    publisher = KeyPair.generate()
    pub_did = cosign.did_key_for(publisher)

    result = VerascoreClient("https://verascore.example/").report_concordia_receipt(
        _session_data(),
        publisher,
        pub_did,
    )

    assert result == {"status": "accepted"}
    assert captured["url"] == "https://verascore.example/api/publish"
    assert captured["timeout"] == 30
    assert captured["headers"]["Content-type"] == "application/json"

    body = captured["body"]
    # Exactly the four fields the route destructures — no legacy did/timestamp/
    # payload at the top level.
    assert set(body.keys()) == {"type", "publicKey", "signature", "data"}
    assert body["type"] == "concordia-receipt"

    # publicKey is base64url raw 32-byte Ed25519 key matching the signer.
    assert _b64url_decode(body["publicKey"]) == publisher.public_key_bytes()
    assert len(_b64url_decode(body["publicKey"])) == 32

    # data.did binds to the publicKey; receipt is nested untouched.
    data = body["data"]
    assert data["did"] == pub_did
    assert data["receipt"]["session_id"] == "session-123"

    # signature is base64url raw 64-byte Ed25519 over JSON.stringify(data),
    # which the route computes as canonical_json(data) after re-parsing.
    sig = _b64url_decode(body["signature"])
    assert len(sig) == 64
    publisher.public_key.verify(sig, canonical_json(data))

    # The wire `data` sub-object, re-parsed and re-canonicalized (what the
    # route's JSON.stringify(data) does), reproduces the exact signed bytes —
    # proving key-order survives the round-trip.
    reparsed = json.loads(captured["raw"].decode("utf-8"))["data"]
    assert canonical_json(reparsed) == canonical_json(data)

    # A single-signed receipt is still emitted (no counterparty_signer here);
    # the counterparty entry must NOT carry a placeholder signature.
    cp_entry = next(
        p for p in data["receipt"]["parties"]
        if p["agent_id"] == "did:key:counterparty"
    )
    assert "signature" not in cp_entry


def test_report_concordia_receipt_rejects_did_key_mismatch() -> None:
    """Fail closed: agent_did that is not the signing key's did:key cannot
    produce a verifiable envelope, so we raise rather than send a partial."""
    publisher = KeyPair.generate()
    with pytest.raises(ValueError, match="does not match the signing key"):
        VerascoreClient("https://verascore.example").report_concordia_receipt(
            _session_data(),
            publisher,
            "did:key:reporter",  # not derived from `publisher`
        )


def test_report_concordia_receipt_emits_counterparty_cosignature(monkeypatch) -> None:
    """With a counterparty_signer, the emitted receipt carries a verifiable
    co-signature on the counterparty's parties[] entry (the H1/H2 producer)."""
    captured = {}

    def fake_urlopen(req, timeout):
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Response(b'{"status":"accepted"}')

    monkeypatch.setattr("concordia.verascore.urllib.request.urlopen", fake_urlopen)

    counterparty = KeyPair.generate()
    cp_did = cosign.did_key_for(counterparty)
    publisher = KeyPair.generate()
    pub_did = cosign.did_key_for(publisher)

    session = _session_data(counterparty_did=cp_did)

    VerascoreClient("https://verascore.example").report_concordia_receipt(
        session,
        publisher,
        pub_did,
        counterparty_signer=cosign.keypair_signer(counterparty),
    )

    receipt = captured["body"]["data"]["receipt"]
    cp_entry = next(p for p in receipt["parties"] if p["agent_id"] == cp_did)
    sig = _b64url_decode(cp_entry["signature"])
    message = cosign.canonical_cosign_bytes(receipt)
    # The counterparty's key verifies its signature over the canonical receipt.
    counterparty.public_key.verify(sig, message)


def test_report_concordia_receipt_returns_raw_response_for_non_json(monkeypatch) -> None:
    def fake_urlopen(req, timeout):
        return _Response(b"accepted")

    monkeypatch.setattr("concordia.verascore.urllib.request.urlopen", fake_urlopen)

    publisher = KeyPair.generate()
    result = VerascoreClient("https://verascore.example").report_concordia_receipt(
        _session_data(),
        publisher,
        cosign.did_key_for(publisher),
    )

    assert result == {"status": "ok", "raw_response": "accepted"}


def test_report_concordia_receipt_returns_http_error_detail(monkeypatch) -> None:
    def fake_urlopen(req, timeout):
        raise urllib.error.HTTPError(
            url=req.full_url,
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=_Response(b"maintenance"),
        )

    monkeypatch.setattr("concordia.verascore.urllib.request.urlopen", fake_urlopen)

    publisher = KeyPair.generate()
    result = VerascoreClient("https://verascore.example").report_concordia_receipt(
        _session_data(),
        publisher,
        cosign.did_key_for(publisher),
    )

    assert result == {
        "error": "Verascore API returned HTTP 503",
        "status_code": 503,
        "detail": "maintenance",
    }


def test_report_concordia_receipt_returns_url_error_reason(monkeypatch) -> None:
    def fake_urlopen(req, timeout):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr("concordia.verascore.urllib.request.urlopen", fake_urlopen)

    publisher = KeyPair.generate()
    result = VerascoreClient("https://verascore.example").report_concordia_receipt(
        _session_data(),
        publisher,
        cosign.did_key_for(publisher),
    )

    assert result == {"error": "Failed to connect to Verascore: offline"}
