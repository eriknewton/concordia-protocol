"""CascadeDecisionRecord conformance: committed, recomputable terminal deny.

Covers every invariant from the design spec with its fail-closed negative:

  - decision_id recomputes from bytes (allow analog + deny), and equals the
    INDEPENDENT rfc8785 reference JCS (not a Concordia-specific hash);
  - mutating ANY bound field (incl. an ancestor status / coordinate, or a
    swapped ref) diverges the recomputed id and is rejected by the verifier;
  - the deny commits to the ancestor read (a deny that does not is rejected);
  - one-byte tamper of the signed body is rejected;
  - signature verifies under the issuer key, and a wrong key is rejected;
  - the child artifact never mutates across a revocation (a NEW immutable deny
    with a NEW id is derived);
  - the allow record stays valid at its own coordinate;
  - the coordinate is a committed non-negative integer (schema constrains shape
    only): a non-integer coordinate (ISO-8601 string, float) or a negative
    placeholder is rejected, while a non-negative-integer epoch value still
    verifies as committed — the primitive does not prove it is a genuine source
    ordinal (source authenticity is verifier-side policy).
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
from collections.abc import Iterator, Mapping
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia.canonicalization import canonicalize_jcs
from concordia.cmpc import (
    AncestorRead,
    CandidateArtifact,
    CascadeBoundary,
    CascadeDecisionRecord,
    RevocationRecord,
    RevocationScope,
    canonicalize_cascade_decision_record,
    cascade_revocation,
    emit_cascade_decision,
    sign_cascade_decision_record,
    sign_revocation_record,
    verify_cascade_decision_record,
)
from concordia.cmpc.errors import SchemaValidationError
from concordia.cmpc.schemas import validate_cascade_decision_record
from concordia.signing import KeyPair

APPROVER_SEED = bytes(range(32))
ISSUER_SEED = bytes(range(1, 33))


def _key(seed: bytes) -> KeyPair:
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return KeyPair(private_key=private, public_key=private.public_key())


def _ancestor_read() -> AncestorRead:
    return AncestorRead(
        element_digest="urn:concordia:receipt:a2a-1404-A",
        status="revoked",
        source_digest="sha256:0f" * 16,
        coordinate=17,
    )


def _unsigned(**overrides: object) -> CascadeDecisionRecord:
    base = dict(
        capability_digest="sha256:" + "ab" * 32,
        request_digest="sha256:" + "cd" * 32,
        boundary_id="urn:a2a:boundary:acme-procurement-hitl",
        verifier="did:web:acme.example#procurement-lead",
        policy_version="acme-procurement-policy@2026-05-01",
        ancestor_reads=[_ancestor_read()],
        revocation_record_ref="urn:concordia:revocation:a2a-1404-A",
    )
    base.update(overrides)
    return emit_cascade_decision(**base)  # type: ignore[arg-type]


def _signed(key: KeyPair | None = None, **overrides: object) -> CascadeDecisionRecord:
    return sign_cascade_decision_record(_unsigned(**overrides), key or _key(ISSUER_SEED))


def _digest(record: CascadeDecisionRecord) -> str:
    return hashlib.sha256(canonicalize_cascade_decision_record(record)).hexdigest()


# ---------------------------------------------------------------------------
# Recompute + independent JCS parity
# ---------------------------------------------------------------------------


def test_decision_id_recomputes_from_bytes() -> None:
    record = _signed()
    assert _digest(record) == record.decision_id


def test_decision_id_matches_independent_rfc8785_reference() -> None:
    """The id is the RFC 8785 STANDARD hash, not a Concordia-specific one.

    A third party using any conformant JCS library recomputes the same value,
    which is what lets the deny cross-run byte-for-byte with ERC8312's
    decision-log family.
    """
    record = _signed()
    reference = hashlib.sha256(rfc8785.dumps(record.preimage())).hexdigest()
    assert reference == record.decision_id


def test_signing_is_deterministic() -> None:
    a = _signed()
    b = _signed()
    assert a.decision_id == b.decision_id
    assert a.signature == b.signature


def test_from_dict_to_dict_round_trip_verifies() -> None:
    key = _key(ISSUER_SEED)
    record = _signed(key)
    restored = CascadeDecisionRecord.from_dict(record.to_dict())
    assert restored == record
    # verify is RAW-MAPPING-ONLY: it verifies the retained bytes, not a parsed
    # record. Serialize the restored record back to its raw mapping to verify.
    assert verify_cascade_decision_record(restored.to_dict(), key.public_key)


def test_optional_refs_are_inside_the_preimage() -> None:
    """A ref that could be swapped without diverging the id is untrustworthy."""
    key = _key(ISSUER_SEED)
    with_ref = _signed(key)
    without_ref = sign_cascade_decision_record(
        emit_cascade_decision(
            capability_digest=with_ref.capability_digest,
            request_digest=with_ref.request_digest,
            boundary_id=with_ref.boundary_id,
            verifier=with_ref.verifier,
            policy_version=with_ref.policy_version,
            ancestor_reads=list(with_ref.ancestor_reads),
        ),
        key,
    )
    # Dropping the ref changes the id: the ref is committed.
    assert with_ref.decision_id != without_ref.decision_id


# ---------------------------------------------------------------------------
# Sign / verify / wrong-key / tamper
# ---------------------------------------------------------------------------


def test_signature_verifies_under_issuer_key() -> None:
    key = _key(ISSUER_SEED)
    assert verify_cascade_decision_record(_signed(key).to_dict(), key.public_key)


def test_wrong_key_rejects() -> None:
    record = _signed(_key(ISSUER_SEED))
    assert not verify_cascade_decision_record(
        record.to_dict(), _key(APPROVER_SEED).public_key
    )


def test_one_byte_tamper_of_signed_body_rejects() -> None:
    key = _key(ISSUER_SEED)
    record = _signed(key)
    body = record.capability_digest
    flipped = body[:-1] + ("0" if body[-1] != "0" else "1")
    tampered = dataclasses.replace(record, capability_digest=flipped)
    assert not verify_cascade_decision_record(tampered.to_dict(), key.public_key)


def test_tamper_of_decision_id_only_rejects() -> None:
    """Swapping the stated id without the body no longer recomputes."""
    key = _key(ISSUER_SEED)
    record = _signed(key)
    forged = dataclasses.replace(record, decision_id="00" * 32)
    assert not verify_cascade_decision_record(forged.to_dict(), key.public_key)


def test_empty_signature_rejects() -> None:
    key = _key(ISSUER_SEED)
    record = _signed(key)
    unsigned = dataclasses.replace(record, signature={"alg": "EdDSA", "value": ""})
    assert not verify_cascade_decision_record(unsigned.to_dict(), key.public_key)


# ---------------------------------------------------------------------------
# Mutate-each-bound-field-diverges (recomputable, not asserted)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("capability_digest", "sha256:" + "00" * 32),
        ("request_digest", "sha256:" + "00" * 32),
        ("boundary_id", "urn:a2a:boundary:other"),
        ("verifier", "did:web:evil.example#x"),
        ("policy_version", "policy@2099-01-01"),
        ("revocation_record_ref", "urn:concordia:revocation:OTHER"),
    ],
)
def test_mutating_any_top_level_bound_field_diverges_and_rejects(
    field: str, value: str
) -> None:
    key = _key(ISSUER_SEED)
    record = _signed(key)
    mutated = dataclasses.replace(record, **{field: value})
    assert _digest(mutated) != record.decision_id
    assert not verify_cascade_decision_record(mutated.to_dict(), key.public_key)


@pytest.mark.parametrize(
    "field,value",
    [
        ("element_digest", "urn:concordia:receipt:OTHER"),
        ("status", "active"),
        ("source_digest", "sha256:" + "ff" * 16),
        ("coordinate", 999),
    ],
)
def test_mutating_any_ancestor_read_field_diverges_and_rejects(
    field: str, value: object
) -> None:
    """Including a claimed ancestor status or coordinate: the deny commits to
    the exact read, so a mutated read is a different, unsigned record."""
    key = _key(ISSUER_SEED)
    record = _signed(key)
    read = dataclasses.replace(record.ancestor_reads[0], **{field: value})
    mutated = dataclasses.replace(record, ancestor_reads=[read])
    assert _digest(mutated) != record.decision_id
    assert not verify_cascade_decision_record(mutated.to_dict(), key.public_key)


# ---------------------------------------------------------------------------
# The deny commits to the ancestor read (rpelevin's control)
# ---------------------------------------------------------------------------


def test_deny_binds_the_ancestor_read_it_depends_on() -> None:
    record = _signed()
    assert len(record.ancestor_reads) >= 1
    read = record.ancestor_reads[0]
    # The read is inside the preimage: recomputing after dropping it changes id.
    preimage_without_read = record.preimage()
    preimage_without_read["ancestor_reads"] = []
    id_without_read = hashlib.sha256(
        rfc8785.dumps(preimage_without_read)
    ).hexdigest()
    assert id_without_read != record.decision_id
    assert read.status == "revoked"


def test_deny_not_committing_to_any_ancestor_read_is_rejected() -> None:
    """A terminal deny with an empty ancestor_reads set is refused: it does not
    commit to any status it claims to depend on."""
    key = _key(ISSUER_SEED)
    record = _signed(key)
    empty = dataclasses.replace(record, ancestor_reads=[])
    # The schema (invoked inside verify) refuses an empty ancestor_reads set.
    assert not verify_cascade_decision_record(empty.to_dict(), key.public_key)
    with pytest.raises(SchemaValidationError):
        validate_cascade_decision_record(empty.to_dict())


def test_signing_an_empty_ancestor_read_set_is_refused() -> None:
    with pytest.raises(SchemaValidationError):
        sign_cascade_decision_record(
            _unsigned(ancestor_reads=[]), _key(ISSUER_SEED)
        )


# ---------------------------------------------------------------------------
# Coordinate is a committed non-negative integer (source authenticity is
# verifier-side policy). The schema constrains SHAPE only: an integer is
# required, so a non-integer (an ISO-8601 string, a float) or a negative
# placeholder is rejected. A non-negative-integer epoch value still passes
# (see the honesty test below) — the primitive does not prove it is a genuine
# pinned source ordinal.
# ---------------------------------------------------------------------------


def test_iso8601_string_coordinate_is_rejected() -> None:
    """An ISO-8601 string in coordinate is a type error: the schema requires an
    integer, so a string coordinate is rejected (a shape constraint, not a
    proof that the integer is a genuine source ordinal)."""
    key = _key(ISSUER_SEED)
    record = _signed(key)
    data = record.to_dict()
    data["ancestor_reads"][0]["coordinate"] = "2026-05-10T14:30:00Z"
    with pytest.raises(SchemaValidationError):
        validate_cascade_decision_record(data)


def test_float_coordinate_is_rejected() -> None:
    key = _key(ISSUER_SEED)
    data = _signed(key).to_dict()
    data["ancestor_reads"][0]["coordinate"] = 17.5
    with pytest.raises(SchemaValidationError):
        validate_cascade_decision_record(data)


def test_negative_or_unpinned_coordinate_is_refused_not_defaulted() -> None:
    """A coordinate the pinned history has not fixed yet is refused, not
    silently defaulted to 0 (minimum: 0 rejects a negative placeholder)."""
    key = _key(ISSUER_SEED)
    data = _signed(key).to_dict()
    data["ancestor_reads"][0]["coordinate"] = -1
    with pytest.raises(SchemaValidationError):
        validate_cascade_decision_record(data)


def test_zero_coordinate_is_a_valid_source_ordinal() -> None:
    key = _key(ISSUER_SEED)
    read = AncestorRead(
        element_digest="urn:concordia:receipt:A",
        status="revoked",
        source_digest="sha256:" + "aa" * 16,
        coordinate=0,
    )
    record = _signed(key, ancestor_reads=[read])
    assert verify_cascade_decision_record(record.to_dict(), key.public_key)


# ---------------------------------------------------------------------------
# Decision is a committed terminal deny only
# ---------------------------------------------------------------------------


def test_non_deny_decision_cannot_be_committed_through_this_shape() -> None:
    key = _key(ISSUER_SEED)
    data = _signed(key).to_dict()
    data["decision"] = "approve"
    with pytest.raises(SchemaValidationError):
        validate_cascade_decision_record(data)


def test_extra_top_level_field_is_rejected() -> None:
    key = _key(ISSUER_SEED)
    data = _signed(key).to_dict()
    data["smuggled"] = "x"
    with pytest.raises(SchemaValidationError):
        validate_cascade_decision_record(data)


# ---------------------------------------------------------------------------
# BLOCKER regression: verify over RETAINED BYTES + strict-parse, never a
# normalized round-trip. `from_dict()` DROPS unknown fields, so a verifier that
# checks `from_dict().to_dict()` would silently accept a smuggled `deal_terms`.
# The verifier MUST take the RAW mapping and reject any unknown field.
# ---------------------------------------------------------------------------


def test_verify_rejects_injected_deal_terms_inside_ancestor_read_raw() -> None:
    """The exact reproduced attack: a raw deal term appended to an ancestor read.

    A normalizing verifier drops it and wrongly PASSes; the shipped verifier
    strict-parses the RAW mapping and REJECTS (defends the no-raw-deal-terms
    privacy invariant + fail-closed mutation rejection + recompute-from-bytes).
    """
    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    raw["ancestor_reads"][0]["deal_terms"] = {"total": "150000.00 USD"}
    assert not verify_cascade_decision_record(raw, key.public_key)
    # Cross-check the failure mode: from_dict() DROPS the field (which is exactly
    # why a normalizing verify path was unsafe). So the raw path is load-bearing.
    reparsed = CascadeDecisionRecord.from_dict(raw)
    assert not any(
        hasattr(r, "deal_terms") for r in reparsed.ancestor_reads
    ), "from_dict silently drops the smuggled field; verify must not normalize"


def test_verify_rejects_injected_top_level_field_raw() -> None:
    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    raw["deal_terms"] = {"total": "150000.00 USD"}
    assert not verify_cascade_decision_record(raw, key.public_key)


def test_verify_accepts_clean_raw_mapping() -> None:
    """The raw-mapping path verifies a well-formed record (no false negatives)."""
    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    assert verify_cascade_decision_record(raw, key.public_key)


def test_verify_raw_mutated_field_diverges_and_rejects() -> None:
    """A mutated bound field in the RAW mapping diverges the recomputed id."""
    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    raw["ancestor_reads"][0]["coordinate"] += 1  # committed field, id diverges
    assert not verify_cascade_decision_record(raw, key.public_key)


def test_verify_raw_swapped_ref_diverges_and_rejects() -> None:
    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    raw["revocation_record_ref"] = raw["revocation_record_ref"] + "-SWAPPED"
    assert not verify_cascade_decision_record(raw, key.public_key)


def test_verify_does_not_normalize_before_checking() -> None:
    """Guard the property directly: a raw record with an extra field whose
    NORMALIZED round-trip (from_dict().to_dict()) is byte-identical to a clean,
    validly-signed record must STILL be rejected, because the verifier checks
    the raw bytes, not the round-trip.
    """
    key = _key(ISSUER_SEED)
    clean = _signed(key).to_dict()
    # A raw record whose from_dict()/to_dict() equals `clean` but carries an
    # extra field on the wire. If verify normalized first, this would PASS.
    smuggled = copy.deepcopy(clean)
    smuggled["ancestor_reads"][0]["deal_terms"] = {"total": "150000.00 USD"}
    assert CascadeDecisionRecord.from_dict(smuggled).to_dict() == clean
    assert not verify_cascade_decision_record(smuggled, key.public_key)


def test_verify_rejects_typed_record_laundering_smuggled_field() -> None:
    """BLOCKER regression (the TYPED pre-parse bypass Codex reproduced).

    ``verify`` is RAW-MAPPING-ONLY. Handing it a parsed
    ``CascadeDecisionRecord`` built from a SMUGGLED raw mapping must NOT return
    True: ``from_dict`` silently drops the injected ``deal_terms`` before strict
    validation, so a verifier that trusted the typed record would false-pass a
    tampered body. The raw path rejects the same smuggled bytes; the typed path
    must NOT launder them into an accept.
    """
    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    smuggled = copy.deepcopy(raw)
    smuggled["ancestor_reads"][0]["deal_terms"] = {"total": "150000.00 USD"}
    # The raw smuggled mapping is rejected (strict-parse over retained bytes)...
    assert not verify_cascade_decision_record(smuggled, key.public_key)
    # ...and the TYPED record parsed from those same smuggled bytes, which has
    # already LOST the injected field, must NOT verify True. Passing a typed
    # record is refused outright (it cannot carry the retained bytes).
    laundered = CascadeDecisionRecord.from_dict(smuggled)
    assert "deal_terms" not in laundered.ancestor_reads[0].to_dict()
    assert not verify_cascade_decision_record(laundered, key.public_key)


def test_verify_refuses_typed_record_even_when_clean() -> None:
    """A typed record is refused outright, clean or not: verify needs the raw
    retained bytes, not a normalized object (which has lost the original bytes).
    The secure flow is raw-bytes-first, so a caller must pass ``.to_dict()``."""
    key = _key(ISSUER_SEED)
    record = _signed(key)
    # The typed record is refused (raw-only contract) even though its raw form
    # verifies cleanly — proving the refusal is about the INPUT TYPE, not the
    # record's validity.
    assert not verify_cascade_decision_record(record, key.public_key)
    assert verify_cascade_decision_record(record.to_dict(), key.public_key)


# ---------------------------------------------------------------------------
# Honesty: a wall-clock epoch integer VERIFIES as committed (the true property);
# the primitive does NOT prove it is "not a wall clock". Source authenticity is
# verifier-side policy, not something the schema/builder establishes.
# ---------------------------------------------------------------------------


def test_wall_clock_epoch_integer_coordinate_still_verifies_as_committed() -> None:
    """A wall-clock epoch-SECONDS integer is a valid non-negative integer, so it
    passes the schema and verifies as COMMITTED. This is the honest framing: the
    primitive commits the coordinate (tampering it diverges the id) but does NOT
    prove it is a genuine pinned source ordinal rather than a wall clock. The
    schema constrains SHAPE (non-negative integer) only.
    """
    key = _key(ISSUER_SEED)
    epoch_seconds = 1_778_589_000  # 2026-05-12T... as epoch seconds: an INTEGER
    read = AncestorRead(
        element_digest="urn:concordia:receipt:A",
        status="revoked",
        source_digest="sha256:" + "aa" * 16,
        coordinate=epoch_seconds,
    )
    record = _signed(key, ancestor_reads=[read])
    # It VERIFIES (honest: a numeric epoch is a valid non-negative integer)...
    assert verify_cascade_decision_record(record.to_dict(), key.public_key)
    # ...and it is COMMITTED: tampering the coordinate diverges the id.
    tampered = record.to_dict()
    tampered["ancestor_reads"][0]["coordinate"] = epoch_seconds + 1
    assert not verify_cascade_decision_record(tampered, key.public_key)


# ---------------------------------------------------------------------------
# Cascade verifier emit path: child never mutates, allow stays valid
# ---------------------------------------------------------------------------


def _revocation(key: KeyPair) -> RevocationRecord:
    return sign_revocation_record(
        RevocationRecord(
            revocation_id="urn:concordia:revocation:a2a-1404-A",
            revoked_artifact_id="urn:concordia:receipt:a2a-1404-A",
            revoked_artifact_type="approval_receipt",
            revocation_scope=RevocationScope.CASCADE_TO_DEPENDENTS.value,
            issuer_did="did:web:acme.example#delegating-principal",
            issued_at="2026-05-10T14:30:00Z",
            effective_at="2026-05-10T14:30:00Z",
            reason="principal_revoked_delegation",
            references=[
                {
                    "id": "urn:concordia:receipt:a2a-1404-A",
                    "relationship": "revokes",
                    "type": "approval_receipt",
                }
            ],
            cascade_depth=3,
        ),
        key,
    )


def _candidates() -> list[CandidateArtifact]:
    return [
        CandidateArtifact(
            artifact_id="urn:concordia:receipt:a2a-1404-A",
            artifact_type="approval_receipt",
            references=[],
        ),
        CandidateArtifact(
            artifact_id="urn:concordia:receipt:a2a-1404-B",
            artifact_type="approval_receipt",
            references=[
                {
                    "id": "urn:concordia:receipt:a2a-1404-A",
                    "relationship": "fulfills",
                    "type": "approval_receipt",
                }
            ],
        ),
    ]


def _boundary() -> CascadeBoundary:
    return CascadeBoundary(
        boundary_id="urn:a2a:boundary:acme-procurement-hitl",
        verifier="did:web:acme.example#procurement-lead",
        policy_version="acme-procurement-policy@2026-05-01",
        source_digest="sha256:" + "0f" * 16,
        coordinate=17,
    )


def test_cascade_without_boundary_emits_no_committed_decisions() -> None:
    """Backward-compatible default: consumers of `inadmissible` are unaffected."""
    key = _key(ISSUER_SEED)
    result = cascade_revocation(_revocation(key), _candidates())
    assert [a.artifact_id for a in result.inadmissible] == [
        "urn:concordia:receipt:a2a-1404-A",
        "urn:concordia:receipt:a2a-1404-B",
    ]
    assert result.decisions == []


def test_cascade_with_boundary_emits_committed_verifiable_denies() -> None:
    key = _key(ISSUER_SEED)
    result = cascade_revocation(
        _revocation(key), _candidates(), boundary=_boundary(), signing_key=key
    )
    assert len(result.decisions) == len(result.inadmissible) == 2
    for decision in result.decisions:
        assert decision.decision == "deny"
        assert verify_cascade_decision_record(decision.to_dict(), key.public_key)
        assert decision.ancestor_reads[0].element_digest == (
            "urn:concordia:receipt:a2a-1404-A"
        )
        assert decision.ancestor_reads[0].status == "revoked"
        assert decision.revocation_record_ref == "urn:concordia:revocation:a2a-1404-A"


def test_cascade_emit_is_fail_closed_without_a_signing_key() -> None:
    """A boundary with no key emits nothing rather than an unsigned record."""
    key = _key(ISSUER_SEED)
    result = cascade_revocation(
        _revocation(key), _candidates(), boundary=_boundary()
    )
    assert result.decisions == []


def test_child_artifact_never_mutates_across_revocation() -> None:
    """The child candidate is not rewritten; the deny is a NEW record."""
    key = _key(ISSUER_SEED)
    candidates = _candidates()
    before = copy.deepcopy(candidates[1])
    result = cascade_revocation(
        _revocation(key), candidates, boundary=_boundary(), signing_key=key
    )
    # The candidate object is untouched by the cascade run.
    assert candidates[1] == before
    # Two independent runs produce byte-identical denies (a NEW immutable record
    # with a deterministic id), never an edit of an existing one.
    again = cascade_revocation(
        _revocation(key), _candidates(), boundary=_boundary(), signing_key=key
    )
    ids_first = sorted(d.decision_id for d in result.decisions)
    ids_again = sorted(d.decision_id for d in again.decisions)
    assert ids_first == ids_again


def test_allow_record_stays_valid_at_its_own_coordinate() -> None:
    """The historical allow (a deny-free record at an earlier coordinate)
    remains verifiable; a later revocation derives a separate deny and does not
    invalidate the allow's own signature."""
    key = _key(ISSUER_SEED)
    # An allow-analog committed at coordinate 10 (the child was admissible then).
    allow = sign_cascade_decision_record(
        emit_cascade_decision(
            capability_digest="sha256:" + "ab" * 32,
            request_digest="sha256:" + "cd" * 32,
            boundary_id="urn:a2a:boundary:acme-procurement-hitl",
            verifier="did:web:acme.example#procurement-lead",
            policy_version="acme-procurement-policy@2026-05-01",
            ancestor_reads=[
                AncestorRead(
                    element_digest="urn:concordia:receipt:a2a-1404-A",
                    status="active",
                    source_digest="sha256:" + "0f" * 16,
                    coordinate=10,
                )
            ],
        ),
        key,
    )
    # The later deny at coordinate 17 is a different record with a different id.
    result = cascade_revocation(
        _revocation(key), _candidates(), boundary=_boundary(), signing_key=key
    )
    deny_ids = {d.decision_id for d in result.decisions}
    assert allow.decision_id not in deny_ids
    # The allow still verifies at its own coordinate, unmutated.
    assert verify_cascade_decision_record(allow.to_dict(), key.public_key)
    assert allow.ancestor_reads[0].coordinate == 10
    assert allow.ancestor_reads[0].status == "active"


# ---------------------------------------------------------------------------
# BLOCKER regression (Codex round-3): the split-view / TOCTOU laundering class.
#
# The prior verify path materialized the input TWICE — `dict(raw)` for schema
# validation, then the canonicalizer read `raw` AGAIN for the id/signature. A
# hostile `Mapping`/dict subclass could return a CLEAN snapshot the first time
# (passing additionalProperties:false) and a DIRTY snapshot (with a smuggled
# ancestor_reads[].deal_terms) the second time (getting signed/verified). The
# chokepoint fix materializes the input into ONE immutable plain snapshot at the
# top and refuses any non-plain container, so there is no second-read surface.
# ---------------------------------------------------------------------------


class SplitViewMapping(Mapping):  # type: ignore[type-arg]
    """A Mapping that shows a clean view first, a dirty view after.

    Codex's exact repro shape: the first read (schema validation) sees a clean,
    schema-valid object; a later read (canonicalization / signature) sees dirty
    content carrying an extra field. The chokepoint must refuse this outright.
    """

    def __init__(self, clean: dict[str, Any], dirty: dict[str, Any]) -> None:
        self.clean = clean
        self.dirty = dirty
        self.materializations = 0
        self.current = clean

    def _snapshot(self) -> dict[str, Any]:
        return self.current

    def __iter__(self) -> Iterator[str]:
        self.current = self.clean if self.materializations == 0 else self.dirty
        snap = self.current
        self.materializations += 1
        return iter(snap)

    def __getitem__(self, key: str) -> Any:
        return self._snapshot()[key]

    def __len__(self) -> int:
        return len(self._snapshot())


def _split_view_record(key: KeyPair) -> SplitViewMapping:
    """Build the clean-then-dirty split view over a validly signed record.

    The dirty snapshot carries a smuggled ``deal_terms`` inside its ancestor
    read AND a matching decision_id + signature computed over the dirty preimage,
    so that a verifier reading only the dirty view would recompute and verify it.
    The clean snapshot carries the SAME dirty id/signature so a first, clean read
    still passes strict schema validation. Only a single-materialization verifier
    that refuses the non-plain container is safe.
    """
    record = _signed(key)
    clean = record.to_dict()
    dirty = copy.deepcopy(clean)
    dirty["ancestor_reads"][0]["deal_terms"] = {"total": "150000.00 USD"}
    dirty_preimage = copy.deepcopy(dirty)
    dirty_preimage.pop("decision_id", None)
    dirty_preimage.pop("signature", None)
    dirty_bytes = canonicalize_jcs(dirty_preimage)
    dirty["decision_id"] = hashlib.sha256(dirty_bytes).hexdigest()
    dirty["signature"] = {
        "alg": "EdDSA",
        "value": base64.urlsafe_b64encode(key.private_key.sign(dirty_bytes)).decode(),
    }
    clean_for_validation = copy.deepcopy(clean)
    clean_for_validation["decision_id"] = dirty["decision_id"]
    clean_for_validation["signature"] = dirty["signature"]
    return SplitViewMapping(clean_for_validation, dirty)


def test_verify_rejects_split_view_mapping_clean_then_dirty() -> None:
    """The TOCTOU blocker: a Mapping that reads clean then dirty is REJECTED.

    Before the chokepoint this false-passed (schema saw the clean view, the
    canonicalizer/signature saw the dirty view). The single-materialization
    chokepoint refuses the non-plain Mapping before any downstream read.
    """
    key = _key(ISSUER_SEED)
    split = _split_view_record(key)
    assert not verify_cascade_decision_record(split, key.public_key)


class _DictSubclassWithExtra(dict):
    """A `dict` SUBCLASS — refused because it could override reads per access."""


class _MappingSubclassWithExtra(Mapping):  # type: ignore[type-arg]
    """A non-`dict` Mapping — refused: not a plain JSON container."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __len__(self) -> int:
        return len(self._data)


def test_verify_rejects_dict_subclass_carrying_extra_field() -> None:
    """A `dict` SUBCLASS input is refused (no plain-dict guarantee)."""
    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    raw["ancestor_reads"][0]["deal_terms"] = {"total": "150000.00 USD"}
    subclassed = _DictSubclassWithExtra(raw)
    assert not verify_cascade_decision_record(subclassed, key.public_key)


def test_verify_rejects_clean_dict_subclass_at_top_level() -> None:
    """Even a CLEAN `dict` subclass is refused: the refusal is about the type,
    not the content — a subclass has a per-read override surface we do not trust.
    """
    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    subclassed = _DictSubclassWithExtra(raw)
    assert not verify_cascade_decision_record(subclassed, key.public_key)


def test_verify_rejects_mapping_subclass_carrying_extra_field() -> None:
    """A non-`dict` Mapping subclass carrying an extra field is refused."""
    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    raw["ancestor_reads"][0]["deal_terms"] = {"total": "150000.00 USD"}
    mapped = _MappingSubclassWithExtra(raw)
    assert not verify_cascade_decision_record(mapped, key.public_key)


def test_verify_rejects_nested_dict_subclass_inside_ancestor_read() -> None:
    """The refusal is RECURSIVE: a plain top-level dict whose ancestor_reads[]
    element is a `dict` SUBCLASS is refused at the nested level.
    """
    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    hostile_read = _DictSubclassWithExtra(raw["ancestor_reads"][0])
    raw["ancestor_reads"][0] = hostile_read
    assert not verify_cascade_decision_record(raw, key.public_key)


def test_verify_rejects_nested_mapping_subclass_inside_signature() -> None:
    """Recursive refusal reaches the `signature` object too: a Mapping subclass
    in place of the plain signature dict is refused.
    """
    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    raw["signature"] = _MappingSubclassWithExtra(dict(raw["signature"]))
    assert not verify_cascade_decision_record(raw, key.public_key)


def test_verify_rejects_non_plain_list_subclass_for_ancestor_reads() -> None:
    """A `list` SUBCLASS for ancestor_reads is refused (sequence read surface)."""

    class _ListSubclass(list):  # type: ignore[type-arg]
        pass

    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    raw["ancestor_reads"] = _ListSubclass(raw["ancestor_reads"])
    assert not verify_cascade_decision_record(raw, key.public_key)


def test_verify_still_accepts_a_plain_clean_record_after_chokepoint() -> None:
    """Sanity: the chokepoint does not introduce a false negative — a plain-dict
    clean record still verifies True."""
    key = _key(ISSUER_SEED)
    assert verify_cascade_decision_record(_signed(key).to_dict(), key.public_key)


def test_verify_still_rejects_plain_dict_with_extra_field_after_chokepoint() -> None:
    """Sanity: a plain-dict record with an injected extra field still rejects via
    strict schema validation over the materialized snapshot."""
    key = _key(ISSUER_SEED)
    raw = _signed(key).to_dict()
    raw["ancestor_reads"][0]["deal_terms"] = {"total": "150000.00 USD"}
    assert not verify_cascade_decision_record(raw, key.public_key)
