"""Regression tests for the A2CN DISPUTE_RESOLVED -> fulfillment adapter.

Coverage:
  - The three resolution outcomes (buyer_prevails, seller_prevails,
    mutual_settlement) round-trip through parse + map and produce the
    expected fulfillment + meta + references shapes.
  - Schema validation rejects malformed messages (wrong type, missing
    required, bad enum, wrong message_type const).
  - Optional fields (evidence_references, resolution_notes) pass
    through when present and are absent when absent.
  - apply_dispute_resolved_to_attestation does NOT mutate the input
    attestation (returns a new dict).
  - The reference shape is exactly Concordia v0.4.0:
    {type: "receipt", id, relationship: "fulfills"}.
  - The FulfillmentStatus enum carries the new mediation value.
  - The top-level attestation schema accepts the new status value.

Test scaffolding mirrors the existing tests/test_attestation.py style.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from concordia.adapters.a2cn import (
    DISPUTE_RESOLVED_SCHEMA,
    DisputeResolvedSchemaError,
    apply_dispute_resolved_to_attestation,
    build_fulfillment_from_dispute_resolved,
    parse_dispute_resolved,
)
from concordia.types import FulfillmentStatus

SAMPLE_RESOLUTION_TS = "2026-05-11T15:42:00Z"
SAMPLE_HASH = "a" * 64
SAMPLE_RESOLVER_DID = "did:web:example.org:resolver:001"
SAMPLE_DISPUTE_NOTICE_ID = "msg_disp_notice_001"
SAMPLE_SESSION_ID = "session_abc123"
SAMPLE_MESSAGE_UUID = "11111111-2222-4333-8444-555555555555"


def _base_message(outcome: str = "buyer_prevails") -> dict[str, Any]:
    return {
        "message_type": "DISPUTE_RESOLVED",
        "message_id": SAMPLE_MESSAGE_UUID,
        "session_id": SAMPLE_SESSION_ID,
        "transaction_record_hash": SAMPLE_HASH,
        "dispute_notice_message_id": SAMPLE_DISPUTE_NOTICE_ID,
        "resolution_outcome": outcome,
        "resolver_did": SAMPLE_RESOLVER_DID,
        "resolution_timestamp": SAMPLE_RESOLUTION_TS,
    }


def _base_attestation() -> dict[str, Any]:
    return {
        "concordia_attestation": "0.4.1",
        "attestation_id": "att_existing",
        "session_id": SAMPLE_SESSION_ID,
        "timestamp": "2026-05-10T09:00:00Z",
        "outcome": {"status": "agreed", "rounds": 3, "duration_seconds": 120},
        "parties": [
            {
                "agent_id": "agent_buyer",
                "role": "initiator",
                "behavior": {"offers_made": 2, "concessions": 1},
                "signature": "sig_buyer_stub",
            },
            {
                "agent_id": "agent_seller",
                "role": "responder",
                "behavior": {"offers_made": 1, "concessions": 0},
                "signature": "sig_seller_stub",
            },
        ],
        "meta": {"extensions_used": [], "mediator_invoked": False},
        "transcript_hash": "sha256:" + ("d" * 64),
        "fulfillment": None,
        "references": [],
    }


# ── A. Schema + parser ───────────────────────────────────────────────


def test_schema_loaded_with_expected_required_fields():
    required = set(DISPUTE_RESOLVED_SCHEMA["required"])
    assert "message_id" in required
    assert "session_id" in required
    assert "transaction_record_hash" in required
    assert "dispute_notice_message_id" in required
    assert "resolution_outcome" in required
    assert "resolver_did" in required
    assert "resolution_timestamp" in required
    assert "message_type" in required


def test_parse_returns_deep_copy():
    msg = _base_message()
    parsed = parse_dispute_resolved(msg)
    parsed["resolution_outcome"] = "MUTATED"
    assert msg["resolution_outcome"] == "buyer_prevails"


def test_parse_fills_evidence_references_default():
    msg = _base_message()
    parsed = parse_dispute_resolved(msg)
    assert parsed["evidence_references"] == []


def test_parse_preserves_optional_fields():
    msg = _base_message()
    msg["resolution_notes"] = "Buyer demonstrated non-delivery; refund ordered."
    msg["evidence_references"] = ["evid_a", "evid_b"]
    msg["protocol_version"] = "0.2.1"
    parsed = parse_dispute_resolved(msg)
    assert parsed["resolution_notes"].startswith("Buyer demonstrated")
    assert parsed["evidence_references"] == ["evid_a", "evid_b"]
    assert parsed["protocol_version"] == "0.2.1"


def test_parse_rejects_non_dict():
    with pytest.raises(DisputeResolvedSchemaError):
        parse_dispute_resolved("not-a-dict")  # type: ignore[arg-type]


def test_parse_rejects_missing_required_field():
    msg = _base_message()
    del msg["transaction_record_hash"]
    with pytest.raises(DisputeResolvedSchemaError) as info:
        parse_dispute_resolved(msg)
    assert "transaction_record_hash" in str(info.value)


def test_parse_rejects_unknown_outcome_enum():
    msg = _base_message(outcome="resolver_was_bribed")
    with pytest.raises(DisputeResolvedSchemaError) as info:
        parse_dispute_resolved(msg)
    assert "resolution_outcome" == info.value.path


def test_parse_rejects_wrong_message_type_const():
    msg = _base_message()
    msg["message_type"] = "DISPUTE_NOTICE"  # neighboring valid msg name
    with pytest.raises(DisputeResolvedSchemaError) as info:
        parse_dispute_resolved(msg)
    assert "message_type" == info.value.path


def test_parse_rejects_short_transaction_hash():
    msg = _base_message()
    msg["transaction_record_hash"] = "deadbeef"  # 8 chars; schema requires 64+
    with pytest.raises(DisputeResolvedSchemaError):
        parse_dispute_resolved(msg)


def test_parse_rejects_additional_properties():
    msg = _base_message()
    msg["sneaky_field"] = "value"
    with pytest.raises(DisputeResolvedSchemaError):
        parse_dispute_resolved(msg)


# ── B. build_fulfillment_from_dispute_resolved ───────────────────────


def test_fulfillment_status_is_fulfilled_with_mediation():
    fulfillment = build_fulfillment_from_dispute_resolved(_base_message())
    assert fulfillment["status"] == "fulfilled_with_mediation"
    assert fulfillment["settled_at"] == SAMPLE_RESOLUTION_TS
    assert fulfillment["fulfilled_at"] == SAMPLE_RESOLUTION_TS


# ── C. apply_dispute_resolved_to_attestation: three outcomes ─────────


@pytest.mark.parametrize(
    "outcome",
    ["buyer_prevails", "seller_prevails", "mutual_settlement"],
)
def test_apply_three_outcomes_produce_correct_meta(outcome: str):
    msg = _base_message(outcome=outcome)
    base = _base_attestation()
    out = apply_dispute_resolved_to_attestation(
        attestation=base,
        message=msg,
        agreement_attestation_id="att_existing",
    )
    assert out["fulfillment"]["status"] == "fulfilled_with_mediation"
    assert out["meta"]["mediator_invoked"] is True
    assert out["meta"]["resolution_outcome"] == outcome
    assert out["meta"]["resolver_did"] == SAMPLE_RESOLVER_DID
    assert out["meta"]["resolution_timestamp"] == SAMPLE_RESOLUTION_TS
    assert out["meta"]["transaction_record_hash"] == SAMPLE_HASH
    assert out["meta"]["dispute_notice_message_id"] == SAMPLE_DISPUTE_NOTICE_ID
    assert out["meta"]["a2cn_message_id"] == SAMPLE_MESSAGE_UUID


def test_apply_preserves_existing_meta_keys():
    msg = _base_message()
    base = _base_attestation()
    base["meta"]["extensions_used"] = ["foo", "bar"]
    base["meta"]["custom_key"] = "preserved"
    out = apply_dispute_resolved_to_attestation(
        attestation=base,
        message=msg,
        agreement_attestation_id="att_existing",
    )
    assert out["meta"]["extensions_used"] == ["foo", "bar"]
    assert out["meta"]["custom_key"] == "preserved"
    # And mediation fields are merged in too.
    assert out["meta"]["mediator_invoked"] is True


def test_apply_does_not_mutate_input_attestation():
    msg = _base_message()
    base = _base_attestation()
    base_snapshot = copy.deepcopy(base)
    apply_dispute_resolved_to_attestation(
        attestation=base,
        message=msg,
        agreement_attestation_id="att_existing",
    )
    assert base == base_snapshot


# ── D. references shape (the composition seam) ───────────────────────


def test_apply_appends_fulfills_reference_with_v040_shape():
    msg = _base_message()
    base = _base_attestation()
    out = apply_dispute_resolved_to_attestation(
        attestation=base,
        message=msg,
        agreement_attestation_id="att_existing",
    )
    assert len(out["references"]) == 1
    ref = out["references"][0]
    assert ref == {
        "type": "receipt",
        "id": "att_existing",
        "relationship": "fulfills",
    }


def test_apply_preserves_existing_references():
    msg = _base_message()
    base = _base_attestation()
    base["references"] = [
        {
            "type": "receipt",
            "id": "att_prior",
            "relationship": "supersedes",
        },
    ]
    out = apply_dispute_resolved_to_attestation(
        attestation=base,
        message=msg,
        agreement_attestation_id="att_existing",
    )
    assert len(out["references"]) == 2
    assert out["references"][0]["relationship"] == "supersedes"
    assert out["references"][1]["relationship"] == "fulfills"


def test_apply_rejects_empty_agreement_attestation_id():
    msg = _base_message()
    with pytest.raises(ValueError):
        apply_dispute_resolved_to_attestation(
            attestation=_base_attestation(),
            message=msg,
            agreement_attestation_id="",
        )


# ── E. Optional pass-through fields ──────────────────────────────────


def test_apply_passes_through_evidence_references_when_present():
    msg = _base_message()
    msg["evidence_references"] = ["evid_screenshots", "evid_logs"]
    out = apply_dispute_resolved_to_attestation(
        attestation=_base_attestation(),
        message=msg,
        agreement_attestation_id="att_existing",
    )
    assert out["meta"]["evidence_references"] == [
        "evid_screenshots",
        "evid_logs",
    ]


def test_apply_omits_evidence_references_when_absent():
    msg = _base_message()
    out = apply_dispute_resolved_to_attestation(
        attestation=_base_attestation(),
        message=msg,
        agreement_attestation_id="att_existing",
    )
    assert "evidence_references" not in out["meta"]


def test_apply_passes_through_resolution_notes_when_present():
    msg = _base_message()
    msg["resolution_notes"] = "Mutual settlement reached; both sides receive 50%."
    out = apply_dispute_resolved_to_attestation(
        attestation=_base_attestation(),
        message=msg,
        agreement_attestation_id="att_existing",
    )
    assert out["meta"]["resolution_notes"].startswith("Mutual settlement")


# ── F. Concordia status enum + attestation schema ────────────────────


def test_fulfillment_status_enum_has_fulfilled_with_mediation():
    assert (
        FulfillmentStatus.FULFILLED_WITH_MEDIATION.value
        == "fulfilled_with_mediation"
    )


def test_attestation_schema_accepts_fulfilled_with_mediation():
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "attestation.schema.json"
    )
    with schema_path.open(encoding="utf-8") as fp:
        schema = json.load(fp)
    status_enum = schema["$defs"]["fulfillment_attestation"]["properties"]["status"][
        "enum"
    ]
    assert "fulfilled_with_mediation" in status_enum
    # Validate a synthetic attestation carrying the new status against
    # the schema (full document, not just the fulfillment block).
    full_attestation = _base_attestation()
    full_attestation["fulfillment"] = build_fulfillment_from_dispute_resolved(
        _base_message(),
    )
    jsonschema.validate(full_attestation, schema)
