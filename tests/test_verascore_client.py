"""Tests for direct Verascore client reporting."""

from __future__ import annotations

import json
import urllib.error

from concordia.signing import KeyPair
from concordia.verascore import VerascoreClient


def _session_data() -> dict:
    return {
        "session_id": "session-123",
        "counterparty_did": "did:key:counterparty",
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


def test_report_concordia_receipt_posts_signed_payload(monkeypatch) -> None:
    captured = {}

    def fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        captured["headers"] = req.headers
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Response(b'{"status":"accepted"}')

    monkeypatch.setattr("concordia.verascore.urllib.request.urlopen", fake_urlopen)

    result = VerascoreClient("https://verascore.example/").report_concordia_receipt(
        _session_data(),
        KeyPair.generate(),
        "did:key:reporter",
    )

    assert result == {"status": "accepted"}
    assert captured["url"] == "https://verascore.example/api/publish"
    assert captured["timeout"] == 30
    assert captured["headers"]["Content-type"] == "application/json"
    assert captured["body"]["type"] == "concordia-receipt"
    assert captured["body"]["did"] == "did:key:reporter"
    assert captured["body"]["signature"]
    assert captured["body"]["payload"]["session_id"] == "session-123"


def test_report_concordia_receipt_returns_raw_response_for_non_json(monkeypatch) -> None:
    def fake_urlopen(req, timeout):
        return _Response(b"accepted")

    monkeypatch.setattr("concordia.verascore.urllib.request.urlopen", fake_urlopen)

    result = VerascoreClient("https://verascore.example").report_concordia_receipt(
        _session_data(),
        KeyPair.generate(),
        "did:key:reporter",
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

    result = VerascoreClient("https://verascore.example").report_concordia_receipt(
        _session_data(),
        KeyPair.generate(),
        "did:key:reporter",
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

    result = VerascoreClient("https://verascore.example").report_concordia_receipt(
        _session_data(),
        KeyPair.generate(),
        "did:key:reporter",
    )

    assert result == {"error": "Failed to connect to Verascore: offline"}
