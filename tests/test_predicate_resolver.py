from __future__ import annotations

import json
import urllib.error

import pytest

from concordia.predicate import sign_predicate, verify_predicate
from concordia.predicate_resolver import BasicHttpsResolver, ResolverProtocolError
from concordia.signing import KeyPair


def _signed(predicate_id: str = "urn:concordia:predicate:pred_resolve_001"):
    return sign_predicate(
        {
            "predicate_id": predicate_id,
            "type": "urn:concordia:predicate-type:authority_gate:v1",
            "authority": "urn:concordia:authority:policy",
            "issuer": "did:web:issuer.example#key-1",
            "subject": "did:web:subject.example#agent",
            "condition": {"result": "satisfied"},
            "issued_at": "2026-05-14T00:00:00Z",
            "expires_at": "2027-06-14T00:00:00Z",
            "references": [],
            "algorithm": "EdDSA",
            "status": "active",
            "signature": "",
        },
        KeyPair.generate(),
    )


def test_basic_resolver_hit_and_cache() -> None:
    pred = _signed()
    resolver = BasicHttpsResolver(mirror={pred.predicate_id: pred})
    assert resolver(pred.predicate_id) == pred
    assert pred.predicate_id in resolver.cache
    assert resolver.cache[pred.predicate_id].canonical_sha256
    assert resolver(pred.predicate_id) == pred


def test_basic_resolver_miss() -> None:
    resolver = BasicHttpsResolver(mirror={})
    assert resolver("urn:concordia:predicate:missing") is None


def test_basic_resolver_invalid_payload_raises_protocol_error() -> None:
    resolver = BasicHttpsResolver(mirror={"urn:concordia:predicate:bad": {"bad": True}})
    with pytest.raises(ResolverProtocolError):
        resolver("urn:concordia:predicate:bad")


def test_basic_resolver_invalid_signature_raises_protocol_error() -> None:
    pred = _signed().to_dict()
    pred["condition"] = {"result": "denied"}
    resolver = BasicHttpsResolver(mirror={pred["predicate_id"]: pred})
    with pytest.raises(ResolverProtocolError, match="invalid"):
        resolver(pred["predicate_id"])


def test_basic_resolver_requires_https() -> None:
    resolver = BasicHttpsResolver(base_url="http://issuer.example")
    with pytest.raises(ResolverProtocolError, match="HTTPS"):
        resolver("urn:concordia:predicate:any")


def test_basic_resolver_http_404_is_soft_miss(monkeypatch) -> None:
    def fake_urlopen(*args, **kwargs):
        raise urllib.error.HTTPError("https://issuer.example", 404, "not found", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    resolver = BasicHttpsResolver(base_url="https://issuer.example")
    assert resolver("urn:concordia:predicate:missing") is None


def test_basic_resolver_http_error_raises_protocol_error(monkeypatch) -> None:
    def fake_urlopen(*args, **kwargs):
        raise urllib.error.HTTPError("https://issuer.example", 500, "boom", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    resolver = BasicHttpsResolver(base_url="https://issuer.example")
    with pytest.raises(ResolverProtocolError, match="fetch failed"):
        resolver("urn:concordia:predicate:error")


def test_basic_resolver_https_success(monkeypatch) -> None:
    pred = _signed()

    class FakeResponse:
        headers = {"ETag": '"abc"'}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return json.dumps(pred.to_dict()).encode("utf-8")

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: FakeResponse())
    resolver = BasicHttpsResolver(base_url="https://issuer.example")
    assert resolver(pred.predicate_id) == pred
    assert resolver.cache[pred.predicate_id].etag == '"abc"'


def test_verify_by_predicate_id_uses_resolver() -> None:
    pred = _signed()
    resolver = BasicHttpsResolver(mirror={pred.predicate_id: pred})
    assert verify_predicate(pred.predicate_id, resolver=resolver).valid is True


def test_verify_by_predicate_id_id_mismatch() -> None:
    pred = _signed("urn:concordia:predicate:other")
    resolver = BasicHttpsResolver(
        mirror={"urn:concordia:predicate:expected": pred},
        check_signature=False,
    )
    result = verify_predicate("urn:concordia:predicate:expected", resolver=resolver)
    assert result.failure_reason == "ref_mismatch"
