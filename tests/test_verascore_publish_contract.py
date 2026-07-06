"""Contract test: the Verascore publish envelope this client emits matches the
committed copy of Verascore's accepted /api/publish schema.

The schema in tests/fixtures/verascore_publish_contract.schema.json is a copy of
the body Verascore accepts, bound to its source:

    Verascore repo: src/app/api/publish/route.ts
                    src/lib/concordia-receipts.ts
                    src/lib/concordia-cosignature.ts
                    src/lib/crypto.ts
    Branch commit:  a3e6090  (#63, require counterparty co-signature for
                    trust-bearing Concordia receipts; H1/H2)

If Verascore's route contract changes, update BOTH the schema fixture (with the
new commit) and this test. The cross-repo canonicalization is the
bilateral-attestation anchor
(Wiki/concepts/concordia-bilateral-attestation-anchor-2026-06-09.md): a change
to the signed bytes or signature placement is an anchor change.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import jsonschema

from concordia import cosign
from concordia.signing import KeyPair, canonical_json
from concordia.verascore import VerascoreClient

_SCHEMA_PATH = (
    Path(__file__).parent / "fixtures" / "verascore_publish_contract.schema.json"
)


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _capture_envelope(*, with_cosignature: bool) -> dict:
    """Build a real envelope by intercepting the client's outbound request."""
    captured: dict = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

        def read(self):
            return b'{"status":"accepted"}'

    publisher = KeyPair.generate()
    pub_did = cosign.did_key_for(publisher)
    counterparty = KeyPair.generate()
    cp_did = cosign.did_key_for(counterparty)

    session_data = {
        "session_id": "session-contract-1",
        "counterparty_did": cp_did,
        "outcome": "agreed",
        "rounds": 4,
        "duration_seconds": 17,
        "terms_count": 3,
        "concessions_made": 2,
        "fulfillment_status": "fulfilled",
        "negotiation_competence": 88,
    }

    signer = cosign.keypair_signer(counterparty) if with_cosignature else None

    import concordia.verascore as vmod

    orig = vmod.urllib.request.urlopen

    def fake_urlopen(req, timeout):  # noqa: ANN001
        captured["raw"] = req.data
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Resp()

    vmod.urllib.request.urlopen = fake_urlopen  # type: ignore[assignment]
    try:
        VerascoreClient("https://verascore.example").report_concordia_receipt(
            session_data,
            publisher,
            pub_did,
            counterparty_signer=signer,
        )
    finally:
        vmod.urllib.request.urlopen = orig  # type: ignore[assignment]

    captured["publisher"] = publisher
    captured["counterparty"] = counterparty
    captured["pub_did"] = pub_did
    captured["cp_did"] = cp_did
    return captured


def test_envelope_validates_against_committed_schema() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text())
    for with_cosignature in (False, True):
        cap = _capture_envelope(with_cosignature=with_cosignature)
        # Raises ValidationError on any drift from the accepted contract.
        jsonschema.validate(instance=cap["body"], schema=schema)


def test_publisher_envelope_signature_matches_route_check() -> None:
    """Mirror route.ts: verify raw Ed25519(JSON.stringify(data)) with the
    decoded publicKey. canonical_json(data) == JSON.stringify(data) because the
    route re-stringifies the object it parsed and we send sorted keys."""
    cap = _capture_envelope(with_cosignature=True)
    body = cap["body"]

    pub = _b64url_decode(body["publicKey"])
    sig = _b64url_decode(body["signature"])
    assert len(pub) == 32
    assert len(sig) == 64

    # The bytes the route signs over: JSON.stringify of the parsed data.
    reparsed_data = json.loads(cap["raw"].decode("utf-8"))["data"]
    cap["publisher"].public_key.verify(sig, canonical_json(reparsed_data))

    # publicKey must encode the same did:key the route derives (deriveAgentId)
    # and that data.did declares.
    assert body["data"]["did"] == cap["pub_did"]
    assert cosign.ed25519_did_key(pub) == body["data"]["did"]


def test_counterparty_cosignature_matches_anchor() -> None:
    """The counterparty signature on parties[] verifies over the canonical
    signature-stripped receipt — the shared anchor Verascore re-derives."""
    cap = _capture_envelope(with_cosignature=True)
    receipt = cap["body"]["data"]["receipt"]
    cp_entry = next(
        p for p in receipt["parties"] if p["agent_id"] == cap["cp_did"]
    )
    sig = _b64url_decode(cp_entry["signature"])
    cap["counterparty"].public_key.verify(sig, cosign.canonical_cosign_bytes(receipt))


def test_committed_envelope_fixture_matches_generator() -> None:
    """The committed cross-repo transport-envelope fixture is exactly what
    ``build_publish_body`` produces today (deterministic seed keys), and it
    validates against the committed copy of Verascore's route schema.

    Verascore's test suite consumes this same fixture with its REAL
    route-layer functions; this test guarantees the committed bytes never
    drift from the producer code.
    """
    from tests.generate_cosign_fixture import (
        ENVELOPE_FIXTURE_PATH,
        build_envelope_fixture,
    )

    committed = json.loads(ENVELOPE_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert committed == build_envelope_fixture()

    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(committed["body"], schema)
