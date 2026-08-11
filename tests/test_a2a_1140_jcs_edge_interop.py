"""Standing cross-check: chopmob-cloud's jcs_edge_v1 RFC 8785 edge vectors.

On 2026-07-19 the ten `jcs_edge_v1` canonicalization vectors published by
chopmob-cloud (AlgoVoi) in `algovoi-jcs-conformance-vectors`, announced on
A2A Issue #1140 as a proposed conformance appendix for the Content Integrity
Profile, were reproduced 10/10 byte-for-byte against Concordia's shipping
canonicalizer in a one-time run. This module converts that run into a
standing check that executes on every CI run:

  1. The retained copy of their vector set (and the upstream LICENSE and
     NOTICE alongside it) is byte-verbatim, pinned by SHA-256 in
     `docs/external/chopmob-cloud-jcs-edge-v1/PROVENANCE.json`. Failure mode
     the pin guards against: a silently re-fetched or hand-edited copy still
     cross-checks cleanly against itself, so the comparison would report
     agreement while proving nothing about their bytes.

  2. Every vector's preimage recomputes to their published canonical bytes,
     SHA-256, and receipt-level content hash under Concordia's own RFC 8785
     canonicalizer, and under the INDEPENDENT `rfc8785` reference library
     (their stated reference implementation). Two implementations landing on
     the published bytes is what makes the agreement evidence rather than a
     restatement.

Honest bound, stated because a reader will check: `rfc8785` is a declared
dependency of this repository, where it serves as a test oracle. It is never
imported on the production canonicalization path; Concordia's shipping
serializer is the hand-written `concordia/signing.py::canonical_json`
(exposed as `concordia.canonicalization.canonicalize_jcs`). So the claim
these tests support is "independent implementation, identical bytes on their
published vectors", never "no rfc8785 dependency anywhere in the repo".

Never cite these results as third-party verification of Concordia. They are
a cross-check between two independently authored artifacts: chopmob-cloud
authored the vectors, this repository authored the recompute.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import rfc8785

from concordia.canonicalization import canonicalize_jcs

REPO_ROOT = Path(__file__).resolve().parent.parent
# Retained third-party bytes live outside docs/interop/ on purpose; the interop
# gate requires every sha256 field in a fixture directory to be re-derivable
# from that directory, and a third-party artifact can legitimately name a digest
# whose preimage its author never published. See docs/external/README.md.
EXTERNAL_DIR = REPO_ROOT / "docs" / "external" / "chopmob-cloud-jcs-edge-v1"
VECTORS_FILE = EXTERNAL_DIR / "jcs_edge_v1.json"
PROVENANCE = EXTERNAL_DIR / "PROVENANCE.json"

# The ten vector ids as published on 2026-07-19. Hardcoded so a swapped-in
# file with a different (even superset) vector list fails loudly here as well
# as at the digest pin.
VECTOR_IDS = [
    "jcs-edge-001-sep-in-value",
    "jcs-edge-002-sep-in-key",
    "jcs-edge-003-nonbmp-key-order",
    "jcs-edge-004-nonbmp-key-order-multi",
    "jcs-edge-005-number-one-float",
    "jcs-edge-006-number-one-int",
    "jcs-edge-007-mandatory-short-escapes",
    "jcs-edge-008-control-u-escape",
    "jcs-edge-009-solidus-and-html-literal",
    "jcs-edge-010-accented-nfc-literal",
]


def _json(path: Path) -> Any:
    return json.loads(path.read_text())


@pytest.fixture(scope="module")
def vector_set() -> dict[str, Any]:
    return _json(VECTORS_FILE)


def _vector(vector_set: dict[str, Any], vector_id: str) -> dict[str, Any]:
    return next(v for v in vector_set["vectors"] if v["vector_id"] == vector_id)


# ---------------------------------------------------------------------------
# Provenance: the retained bytes are the ones the record names
# ---------------------------------------------------------------------------


def test_every_retained_file_matches_recorded_digest() -> None:
    """Each retained file hashes to the SHA-256 its provenance entry records."""
    artifacts = _json(PROVENANCE)["artifacts"]
    assert artifacts, "provenance record lists no artifacts"
    for entry in artifacts:
        digest = hashlib.sha256((EXTERNAL_DIR / entry["file"]).read_bytes()).hexdigest()
        assert digest == entry["retained_sha256"], entry["file"]


def test_every_retained_file_is_in_the_provenance_record() -> None:
    """No file rides along unpinned; PROVENANCE.json itself is the only exception."""
    recorded = {entry["file"] for entry in _json(PROVENANCE)["artifacts"]}
    on_disk = {p.name for p in EXTERNAL_DIR.iterdir() if p.name != "PROVENANCE.json"}
    assert on_disk == recorded


def test_vector_set_shape_is_the_published_one(vector_set: dict[str, Any]) -> None:
    assert vector_set["name"] == "jcs_edge_v1"
    assert vector_set["license"] == "Apache-2.0"
    assert vector_set["canon_version"] == "jcs-rfc8785-v1"
    assert [v["vector_id"] for v in vector_set["vectors"]] == VECTOR_IDS


# ---------------------------------------------------------------------------
# The standing reproduction: 10/10 on all three published axes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector_id", VECTOR_IDS)
def test_canonical_bytes_byte_for_byte(vector_set: dict[str, Any], vector_id: str) -> None:
    """Concordia's canonicalizer emits exactly their published JCS bytes.

    Compare canonical bytes as well as the digest: equal digests over
    different bytes would be a collision claim, not an agreement.
    """
    vector = _vector(vector_set, vector_id)
    expected = base64.b64decode(vector["expected_jcs_bytes_b64"])
    assert canonicalize_jcs(vector["preimage"]) == expected


@pytest.mark.parametrize("vector_id", VECTOR_IDS)
def test_published_sha256_recomputes(vector_set: dict[str, Any], vector_id: str) -> None:
    vector = _vector(vector_set, vector_id)
    digest = hashlib.sha256(canonicalize_jcs(vector["preimage"])).hexdigest()
    assert digest == vector["expected_sha256"]
    # Their published expected bytes and expected digest also agree with each
    # other; a retained set that is internally inconsistent should fail here
    # rather than be silently split between the two assertions above.
    published_bytes = base64.b64decode(vector["expected_jcs_bytes_b64"])
    assert hashlib.sha256(published_bytes).hexdigest() == vector["expected_sha256"]


@pytest.mark.parametrize("vector_id", VECTOR_IDS)
def test_receipt_content_hash_recomputes(vector_set: dict[str, Any], vector_id: str) -> None:
    vector = _vector(vector_set, vector_id)
    digest = hashlib.sha256(canonicalize_jcs(vector["receipt"])).hexdigest()
    assert digest == vector["expected_content_hash"]


@pytest.mark.parametrize("vector_id", VECTOR_IDS)
def test_reference_library_agrees(vector_set: dict[str, Any], vector_id: str) -> None:
    """The independent rfc8785 library lands on the same published bytes.

    This is the second implementation in the two-implementation agreement; it
    also means a future divergence identifies which side moved.
    """
    vector = _vector(vector_set, vector_id)
    expected = base64.b64decode(vector["expected_jcs_bytes_b64"])
    assert rfc8785.dumps(vector["preimage"]) == expected


# ---------------------------------------------------------------------------
# Pair invariants published with the set
# ---------------------------------------------------------------------------


def test_number_form_one_float_equals_one_int(vector_set: dict[str, Any]) -> None:
    """1.0 and 1 canonicalize to byte-identical output (RFC 8785 §3.2.2.3).

    A serializer that preserves the trailing `.0` diverges here; the pair
    invariant is asserted over recomputed bytes, never over recorded values.
    """
    float_vector = _vector(vector_set, "jcs-edge-005-number-one-float")
    int_vector = _vector(vector_set, "jcs-edge-006-number-one-int")
    assert canonicalize_jcs(float_vector["preimage"]) == canonicalize_jcs(int_vector["preimage"])
    assert float_vector["expected_sha256"] == int_vector["expected_sha256"]


def test_nonbmp_key_order_is_utf16_code_units(vector_set: dict[str, Any]) -> None:
    """U+1F600 sorts before U+FFFF under RFC 8785 §3.2.3 UTF-16 ordering.

    The supplementary-plane emoji's surrogate pair leads with 0xD83D, so it
    precedes U+FFFF; naive code-point ordering would place it after. Per the
    set author's A2A #1140 write-up this is the case that catches serializers
    which pass every simpler fixture, so the ordering itself is asserted here
    on Concordia's recomputed bytes rather than trusted from the record.
    """
    vector = _vector(vector_set, "jcs-edge-003-nonbmp-key-order")
    produced = canonicalize_jcs(vector["preimage"])
    emoji_key = "\U0001f600".encode("utf-8")
    ffff_key = "￿".encode("utf-8")
    assert produced.index(emoji_key) < produced.index(ffff_key)
    assert produced == base64.b64decode(vector["expected_jcs_bytes_b64"])
