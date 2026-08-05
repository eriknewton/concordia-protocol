"""Cross-check: giskard09's decision_binding_ref context_digest vectors.

Two claims are made publicly in A2A Discussion #1734 and each one is bound
here to a check that fails when the claim stops being true:

  1. giskard09's four published conformance vectors, both published context
     sets, and the four inline fixtures in `decision-binding-ref-v1.0.md`
     recompute under Concordia's own RFC 8785 canonicalizer, and under the
     INDEPENDENT `rfc8785` reference library. Two independent implementations
     landing on their published digests is what makes the agreement evidence
     rather than a restatement.

  2. The receipt-side worked example under
     `docs/interop/a2a-1734-context-digest-receipt/` carries their preimage
     inside a signed Concordia ApprovalReceipt, so the recomputed
     `decision_binding_ref` equals their published `cd-001` value and the
     binding is additionally non-repudiable: substituting a stale
     `context_digest` breaks the receipt signature.

The retained copy of their fixture is byte-verbatim and pinned by SHA-256 in
`external/PROVENANCE.json`. Failure mode that pin guards against: a silently
re-fetched or hand-edited copy still cross-checks cleanly against itself, so
the comparison would report agreement while proving nothing.

Never cite these results as third-party verification of Concordia. They are a
cross-check between two independently authored artifacts: giskard09 authored
the vectors, this repository authored the recompute and the receipt.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import rfc8785

from concordia import verify_approval_receipt
from concordia.canonicalization import canonicalize_jcs
from concordia.signing import public_key_from_b64url

REPO_ROOT = Path(__file__).resolve().parent.parent
INTEROP_1734 = REPO_ROOT / "docs" / "interop" / "a2a-1734-context-digest-receipt"
# Retained third-party bytes live outside docs/interop/ on purpose; the interop
# gate requires every sha256 field in a fixture directory to be re-derivable
# from that directory, and a third-party artifact can legitimately name a digest
# whose preimage its author never published. See docs/external/README.md.
EXTERNAL_DIR = (
    REPO_ROOT / "docs" / "external" / "giskard09-decision-binding-context-digest-v1"
)
EXTERNAL = EXTERNAL_DIR / "vectors.json"
PROVENANCE = EXTERNAL_DIR / "PROVENANCE.json"

EXT_PREIMAGE = "a2a_1734_decision_binding_preimage"
EXT_REF = "a2a_1734_decision_binding_ref"

# Deterministic verification moment: the receipt's expires_at is far future,
# so this only has to be at or after issued_at. Must match the `now` in the
# pos-1734-receipt-signed-binding vector context in
# scripts/conformance/generate_vectors.py.
NOW = datetime(2026, 8, 4, 10, 5, 0, tzinfo=timezone.utc)


def _json(path: Path) -> Any:
    return json.loads(path.read_text())


def _sha256_jcs(obj: Any) -> str:
    """`sha256:<hex>` over Concordia's own RFC 8785 JCS bytes."""
    return "sha256:" + hashlib.sha256(canonicalize_jcs(obj)).hexdigest()


def _sha256_reference_jcs(obj: Any) -> str:
    """`sha256:<hex>` over the INDEPENDENT rfc8785 library's JCS bytes."""
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


@pytest.fixture(scope="module")
def external() -> dict[str, Any]:
    return _json(EXTERNAL)


@pytest.fixture(scope="module")
def receipt() -> dict[str, Any]:
    return _json(INTEROP_1734 / "approval_receipt.json")


@pytest.fixture(scope="module")
def local_vector() -> dict[str, Any]:
    return _json(INTEROP_1734 / "vector.json")


def _external_vector(external: dict[str, Any], vector_id: str) -> dict[str, Any]:
    return next(v for v in external["vectors"] if v["id"] == vector_id)


def _preimage_of(vector: dict[str, Any]) -> dict[str, Any]:
    return vector.get("preimage") or vector["embedded_preimage"]


def _published_ref(vector: dict[str, Any]) -> str:
    return vector.get("decision_binding_ref") or vector["embedded_decision_binding_ref"]


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def test_retained_external_fixture_matches_recorded_digest() -> None:
    """The retained third-party bytes are the ones the provenance record names."""
    entry = _json(PROVENANCE)["artifacts"][0]
    digest = hashlib.sha256(EXTERNAL.read_bytes()).hexdigest()
    assert digest == entry["retained_sha256"]


# ---------------------------------------------------------------------------
# Claim 1: their published vectors recompute under two canonicalizers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("set_name", ["context_full", "context_dropped_artifact"])
def test_published_context_sets_recompute(
    external: dict[str, Any], set_name: str
) -> None:
    entry = external["context_sets"][set_name]
    assembled = entry["assembled_context"]
    # Compare canonical bytes as well as the digest: equal digests over
    # different bytes would be a collision claim, not an agreement.
    assert canonicalize_jcs(assembled).decode("utf-8") == entry["jcs"]
    assert _sha256_jcs(assembled) == entry["context_digest"]
    assert _sha256_reference_jcs(assembled) == entry["context_digest"]


@pytest.mark.parametrize("vector_id", ["cd-001", "cd-002", "cd-003", "cd-004"])
def test_published_vectors_recompute(
    external: dict[str, Any], vector_id: str
) -> None:
    vector = _external_vector(external, vector_id)
    preimage = _preimage_of(vector)
    published = _published_ref(vector)
    if "canonical" in vector:
        assert canonicalize_jcs(preimage).decode("utf-8") == vector["canonical"]
    assert _sha256_jcs(preimage) == published
    assert _sha256_reference_jcs(preimage) == published


def test_cd_004_negative_actually_diverges(external: dict[str, Any]) -> None:
    """The CONTEXT_SET_MISMATCH vector must diverge, not merely be labelled so.

    A vector whose arithmetic agrees but whose divergence is never asserted
    would pass a recompute suite while proving nothing about fail-closed
    behavior.
    """
    vector = _external_vector(external, "cd-004")
    presented = external["context_sets"][vector["presented_context_set"]][
        "assembled_context"
    ]
    recomputed = _sha256_jcs(presented)
    assert recomputed == vector["recomputed_context_digest"]
    assert recomputed != vector["embedded_preimage"]["context_digest"]


def test_spec_inline_fixtures_recompute() -> None:
    """Fixtures A-D published inline in decision-binding-ref-v1.0.md.

    Transcribed rather than retained (the spec publishes them in prose), so
    each digest is recomputed from the transcribed preimage: a transcription
    slip fails here instead of passing quietly.
    """
    base = {
        "action_ref": (
            "sha256:9752a870dac7100010453be9494ec631c78fd55bb7cb41355cf03592da3862ce"
        ),
        "decision_at_ms": 1748736000000,
        "decision_id": "approval:7f3a9c21-4e5b-4d8f-b3c2-1a9e8f7d6c5b",
    }
    policy_ref = (
        "sha256:b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a6c7"
    )
    context_digest = (
        "sha256:c2bf3a88a2e5d8d63b95b22eab6b31bf2b7ab6108002b37a9b0945b722d4b9bb"
    )
    expected = _json(PROVENANCE)["spec_fixtures_A_to_D"]
    fixtures = {
        "A_policy_ref_only": {**base, "policy_ref": policy_ref},
        "B_neither": dict(base),
        "C_context_digest_only": {**base, "context_digest": context_digest},
        "D_both": {**base, "policy_ref": policy_ref, "context_digest": context_digest},
    }
    for name, preimage in fixtures.items():
        assert _sha256_jcs(preimage) == expected[name], name
        assert _sha256_reference_jcs(preimage) == expected[name], name


def test_omit_not_null_is_not_the_same_digest() -> None:
    """The spec's absence rule has teeth: omitting differs from nulling.

    If a `null` optional field produced the same preimage bytes as an omitted
    one, the absence rule would be cosmetic. It is not, and this pins that.
    """
    base = {
        "action_ref": (
            "sha256:9752a870dac7100010453be9494ec631c78fd55bb7cb41355cf03592da3862ce"
        ),
        "decision_at_ms": 1748736000000,
        "decision_id": "approval:7f3a9c21-4e5b-4d8f-b3c2-1a9e8f7d6c5b",
    }
    nulled = {**base, "context_digest": None}
    assert _sha256_jcs(nulled) != _sha256_jcs(base)


# ---------------------------------------------------------------------------
# Claim 2: the receipt-side worked example
# ---------------------------------------------------------------------------


def test_receipt_context_digest_recomputes_from_presented_set(
    receipt: dict[str, Any],
) -> None:
    assembled = _json(INTEROP_1734 / "assembled_context.json")
    embedded = receipt["references"][0]["extensions"][EXT_PREIMAGE]["context_digest"]
    assert _sha256_jcs(assembled) == embedded
    assert _sha256_reference_jcs(assembled) == embedded


def test_receipt_context_digest_equals_giskard09_published_value(
    receipt: dict[str, Any], external: dict[str, Any]
) -> None:
    """The cross-check: two implementations, one digest.

    The rest of the preimage is this fixture's own. Only `context_digest` is
    shared, and it is shared because it was recomputed from their published
    context set rather than transcribed from their recorded value.
    """
    preimage = receipt["references"][0]["extensions"][EXT_PREIMAGE]
    embedded = receipt["references"][0]["extensions"][EXT_REF]
    assert _sha256_jcs(preimage) == embedded
    assert _sha256_reference_jcs(preimage) == embedded
    assert (
        preimage["context_digest"]
        == external["context_sets"]["context_full"]["context_digest"]
    )


def test_receipt_preimage_is_fully_derivable(receipt: dict[str, Any]) -> None:
    """No field of the preimage is an opaque value this repository cannot produce.

    giskard09's own vectors carry an `action_ref` whose preimage they never
    published. Reusing it would have put an underivable digest inside a
    Concordia fixture, which the interop gate rejects by design.
    """
    preimage = receipt["references"][0]["extensions"][EXT_PREIMAGE]
    offer = _json(INTEROP_1734 / "offer.json")
    assembled = _json(INTEROP_1734 / "assembled_context.json")
    assert preimage["action_ref"] == _sha256_jcs(offer)
    assert preimage["action_ref"] == receipt["scope"]["offer_hash"]
    assert preimage["context_digest"] == _sha256_jcs(assembled)


def test_receipt_verifies_under_shipped_verifier(
    receipt: dict[str, Any], local_vector: dict[str, Any]
) -> None:
    offer = _json(INTEROP_1734 / "offer.json")
    issuer = public_key_from_b64url(local_vector["public_keys_b64url"]["approver"])
    result = verify_approval_receipt(
        receipt, offer, now=NOW, issuer_public_key=issuer
    )
    assert result.valid, result.failure_reason
    assert result.decision == "approve"


def test_dropped_context_artifact_fails_the_recompute(
    receipt: dict[str, Any],
) -> None:
    """CONTEXT_SET_MISMATCH: a partial context set does not verify as the whole."""
    dropped = _json(INTEROP_1734 / "assembled_context_dropped_artifact.json")
    embedded = receipt["references"][0]["extensions"][EXT_PREIMAGE]["context_digest"]
    assert _sha256_jcs(dropped) != embedded


def test_swapping_in_a_stale_context_digest_breaks_the_signature(
    receipt: dict[str, Any], local_vector: dict[str, Any]
) -> None:
    """What the receipt side adds on top of a published digest.

    The forgery modelled here is the plausible one: substitute the smaller
    context set's digest and re-derive the ref so the artifact stays
    internally consistent. A digest-only check accepts that. The signature
    covers the embedded preimage, so the shipped verifier does not.
    """
    offer = _json(INTEROP_1734 / "offer.json")
    issuer = public_key_from_b64url(local_vector["public_keys_b64url"]["approver"])
    dropped = _json(INTEROP_1734 / "assembled_context_dropped_artifact.json")

    swapped = copy.deepcopy(receipt)
    preimage = swapped["references"][0]["extensions"][EXT_PREIMAGE]
    preimage["context_digest"] = _sha256_jcs(dropped)
    swapped["references"][0]["extensions"][EXT_REF] = _sha256_jcs(preimage)

    # The substitution is self-consistent, which is precisely why a
    # digest-only verifier would accept it.
    assert swapped["references"][0]["extensions"][EXT_REF] == _sha256_jcs(preimage)

    result = verify_approval_receipt(
        swapped, offer, now=NOW, issuer_public_key=issuer
    )
    assert not result.valid
    assert result.failure_reason == "signature_invalid"


def test_interop_verify_script_passes() -> None:
    """The published verify.py returns exit code 0 (every check PASS)."""
    spec = importlib.util.spec_from_file_location(
        "interop_1734_verify", INTEROP_1734 / "verify.py"
    )
    assert spec is not None and spec.loader is not None
    module: ModuleType = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main() == 0


def test_published_local_digests_all_recompute(
    local_vector: dict[str, Any], receipt: dict[str, Any]
) -> None:
    """Every hash vector.json publishes is derived, never merely recorded."""
    hashes = local_vector["hashes"]
    assert _sha256_jcs(_json(INTEROP_1734 / "assembled_context.json")) == hashes[
        "context_digest"
    ]
    assert (
        _sha256_jcs(_json(INTEROP_1734 / "assembled_context_dropped_artifact.json"))
        == hashes["dropped_artifact_set"]["context_digest"]
    )
    assert _sha256_jcs(
        _json(INTEROP_1734 / "decision_binding_preimage.json")
    ) == hashes["decision_binding_ref"]
    assert receipt["scope"]["offer_hash"] == hashes["receipt_offer_hash"]


def test_receipt_carries_no_raw_context_content(receipt: dict[str, Any]) -> None:
    """The receipt binds a digest of the context set, never the content.

    Concordia's privacy invariant applies to this extension the same way it
    applies to attestations: presence is attestable, content is not carried.
    """
    extensions = receipt["references"][0]["extensions"]
    serialized = json.dumps(extensions)
    assembled = _json(INTEROP_1734 / "assembled_context.json")
    for artifact in assembled["artifacts"]:
        assert artifact not in serialized
