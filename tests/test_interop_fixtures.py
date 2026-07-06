"""Interop fixture conformance: A2A #1404 and #1920 worked vectors.

Runs the two published interop verify scripts in-process and asserts they
pass, so the fixtures under docs/interop/ are regression-protected by CI. Also
re-derives the load-bearing hashes with the INDEPENDENT rfc8785 reference
canonicalizer (not Concordia's own), so the published decision_id is proven to
be the RFC 8785 JCS standard hash, not a Concordia-specific artifact.

These fixtures are linked publicly from A2A Discussion #1404 and #1920; the
suite makes an accidental byte-drift a hard CI failure.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import rfc8785

REPO_ROOT = Path(__file__).resolve().parent.parent
INTEROP_1404 = REPO_ROOT / "docs" / "interop" / "a2a-1404-receipt-revocation-vector"
INTEROP_1920 = REPO_ROOT / "docs" / "interop" / "a2a-1920-fulfillment-sample"


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _json(path: Path) -> dict:
    return json.loads(path.read_text())


def test_1404_verify_script_passes() -> None:
    """The published #1404 verify.py returns exit code 0 (all checks PASS)."""
    verify = _load_module(INTEROP_1404 / "verify.py", "interop_1404_verify")
    assert verify.main() == 0


def test_1404_decision_id_matches_reference_jcs() -> None:
    """decision_id equals SHA-256 over the INDEPENDENT rfc8785 JCS bytes.

    Proves the published decision_id is the RFC 8785 standard hash, not a
    Concordia-specific one: a third party using any conformant JCS library
    recomputes the same value.
    """
    decision_object = _json(INTEROP_1404 / "decision_object.json")
    vector = _json(INTEROP_1404 / "vector.json")
    reference = "sha256:" + hashlib.sha256(rfc8785.dumps(decision_object)).hexdigest()
    assert reference == vector["hashes"]["decision_id"]


def test_1404_native_fields_equal_decision_object() -> None:
    """The two NATIVE receipt fields equal the decision object (honest map)."""
    receipt = _json(INTEROP_1404 / "approval_receipt.json")
    decision_object = _json(INTEROP_1404 / "decision_object.json")
    assert receipt["scope"]["decision"] == decision_object["decision"]
    assert receipt["scope"]["offer_hash"] == decision_object["request_digest"]


def test_1920_verify_script_passes() -> None:
    """The published #1920 verify.py returns exit code 0 (all checks PASS)."""
    verify = _load_module(INTEROP_1920 / "verify.py", "interop_1920_verify")
    assert verify.main() == 0


def test_1920_privacy_invariant_no_raw_terms() -> None:
    """The #1920 sample carries no raw deal terms (SPEC 9.6.6)."""
    from concordia.schema_validator import _RAW_TERM_PATTERNS

    att = _json(INTEROP_1920 / "fulfillment_attestation.json")

    def walk(obj: object) -> list[str]:
        out: list[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and k != "signature":
                    out.append(k)
                if k != "signature":
                    out.extend(walk(v))
        elif isinstance(obj, list):
            for v in obj:
                out.extend(walk(v))
        elif isinstance(obj, str):
            out.append(obj)
        return out

    for s in walk(att):
        for pat in _RAW_TERM_PATTERNS:
            assert pat.search(s) is None, f"raw term leaked: {s!r}"
