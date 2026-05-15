from __future__ import annotations

import builtins
import importlib
import sys

from concordia.predicate import sign_predicate, verify_predicate
from concordia.signing import KeyPair


def test_receipt_fulfills_reference_composes_when_available() -> None:
    predicate = sign_predicate(
        {
            "predicate_id": "urn:concordia:predicate:pred_receipt_001",
            "type": "urn:concordia:predicate-type:authority_gate:v1",
            "authority": "urn:concordia:authority:approval",
            "issuer": "did:web:issuer.example#key-1",
            "subject": "urn:concordia:offer:off_001",
            "condition": {"result": "satisfied"},
            "issued_at": "2026-05-14T00:00:00Z",
            "expires_at": "2027-06-14T00:00:00Z",
            "references": [
                {
                    "type": "receipt",
                    "id": "urn:concordia:approval_receipt:ar_001",
                    "relationship": "fulfills",
                }
            ],
            "algorithm": "EdDSA",
            "status": "active",
            "signature": "",
        },
        KeyPair.generate(),
    )
    result = verify_predicate(predicate)
    assert result.valid is True
    assert result.warnings == []


def test_receipt_verifier_unavailable_warns_and_continues(monkeypatch) -> None:
    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "concordia.approval_receipt" or name.endswith(".approval_receipt"):
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    sys.modules.pop("concordia.approval_receipt", None)
    real_import_module = importlib.import_module

    def blocked_import_module(name, *args, **kwargs):
        if name == "concordia.approval_receipt":
            raise ImportError("blocked")
        return real_import_module(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    monkeypatch.setattr(importlib, "import_module", blocked_import_module)
    predicate = sign_predicate(
        {
            "predicate_id": "urn:concordia:predicate:pred_receipt_002",
            "type": "urn:concordia:predicate-type:authority_gate:v1",
            "authority": "urn:concordia:authority:approval",
            "issuer": "did:web:issuer.example#key-1",
            "subject": "urn:concordia:offer:off_001",
            "condition": {"result": "satisfied"},
            "issued_at": "2026-05-14T00:00:00Z",
            "expires_at": "2027-06-14T00:00:00Z",
            "references": [
                {
                    "type": "receipt",
                    "id": "urn:concordia:approval_receipt:ar_001",
                    "relationship": "fulfills",
                }
            ],
            "algorithm": "EdDSA",
            "status": "active",
            "signature": "",
        },
        KeyPair.generate(),
    )
    result = verify_predicate(predicate)
    assert result.valid is True
    assert result.warnings == ["approval_receipt_verifier_unavailable"]
