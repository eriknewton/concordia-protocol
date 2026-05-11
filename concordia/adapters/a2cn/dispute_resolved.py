"""A2CN DISPUTE_RESOLVED message adapter.

Consumes A2CN DISPUTE_RESOLVED messages (defined upstream in A2CN PR #12,
commit ``06c33d0``) and maps them into Concordia fulfillment attestations.

Mapping (per Erik directive + Christian's composition-seam endorsement
on the A2CN side):

  - ``fulfillment.status`` = ``"fulfilled_with_mediation"`` (new enum
    value added in Concordia v0.4.1 to record mediated closure).
  - ``fulfillment.settled_at`` = the DISPUTE_RESOLVED
    ``resolution_timestamp``.
  - ``meta.mediator_invoked`` = True.
  - ``meta.resolution_outcome`` = the A2CN enum value
    (``buyer_prevails`` | ``seller_prevails`` | ``mutual_settlement``).
  - ``meta.resolver_did`` = the resolver's DID.
  - ``meta.resolution_timestamp`` = the resolution timestamp.
  - ``meta.dispute_notice_message_id`` = the DISPUTE_NOTICE this
    DISPUTE_RESOLVED closes.
  - ``meta.transaction_record_hash`` = the SHA-256 hex digest of the
    agreed transaction record (anchors back to the original commitment).
  - ``meta.a2cn_message_id`` = the DISPUTE_RESOLVED ``message_id`` so
    downstream consumers (Verascore) have a deterministic dedupe key.
  - ``meta.evidence_references`` (optional) = A2CN-side evidence
    pointers, surfaced for downstream audit.
  - ``meta.resolution_notes`` (optional) = the resolver's free-text
    explanation, capped at the A2CN-side schema's bounds.
  - ``references`` extends with a single entry of shape
    ``{"type": "receipt", "id": <agreement_att_id>,
       "relationship": "fulfills"}`` per the Concordia v0.4.0
    composition seam (SPEC §11.5). Christian's PR #12 review
    explicitly endorsed this seam.

The adapter validates the incoming message against the A2CN
DISPUTE_RESOLVED schema mirrored at ``schemas/a2cn/dispute_resolved.schema.json``
before mapping. Validation failures raise ``DisputeResolvedSchemaError``
with the offending field path so callers can route the failure into
Concordia's graceful-degradation path rather than crash.

Sovereignty discipline: this adapter introduces no outbound surface.
It is pure dict-to-dict translation, mirroring the existing
``sanctuary_bridge.py`` posture (payload builder; never calls anything
across a trust boundary itself).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import jsonschema

# Load the schema once at import time. Mirrored from the A2CN upstream
# repo at A2CN PR #12 (commit 06c33d0). Refreshed by re-running the
# upstream curl and committing the new schema; the validator below
# tracks whatever JSON sits at the canonical path.
_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / ".."
    / "schemas"
    / "a2cn"
    / "dispute_resolved.schema.json"
).resolve()

with _SCHEMA_PATH.open(encoding="utf-8") as _fp:
    DISPUTE_RESOLVED_SCHEMA: dict[str, Any] = json.load(_fp)

VALID_RESOLUTION_OUTCOMES: tuple[str, ...] = (
    "buyer_prevails",
    "seller_prevails",
    "mutual_settlement",
)


class DisputeResolvedSchemaError(ValueError):
    """Raised when an incoming DISPUTE_RESOLVED message does not validate.

    Carries the JSON-pointer path of the offending field plus the
    underlying validator message so callers can log + route to the
    graceful-degradation path without re-parsing.
    """

    def __init__(self, message: str, *, path: str = ""):
        super().__init__(message)
        self.path = path


def parse_dispute_resolved(message: Any) -> dict[str, Any]:
    """Validate + return a normalized DISPUTE_RESOLVED message dict.

    The returned dict is a deep copy so the caller can mutate freely
    without poisoning a shared object. Default values are filled in for
    optional fields where the schema specifies them
    (``evidence_references`` defaults to ``[]``).

    Raises ``DisputeResolvedSchemaError`` on validation failure.
    """
    if not isinstance(message, dict):
        raise DisputeResolvedSchemaError(
            f"DISPUTE_RESOLVED message must be a dict, got "
            f"{type(message).__name__}",
        )
    try:
        jsonschema.validate(message, DISPUTE_RESOLVED_SCHEMA)
    except jsonschema.ValidationError as exc:
        path = "/".join(str(p) for p in exc.absolute_path)
        raise DisputeResolvedSchemaError(
            f"DISPUTE_RESOLVED schema violation at /{path}: {exc.message}",
            path=path,
        ) from exc
    out = copy.deepcopy(message)
    # Apply schema-declared defaults.
    if "evidence_references" not in out:
        out["evidence_references"] = []
    return out


def build_fulfillment_from_dispute_resolved(
    message: dict[str, Any],
) -> dict[str, Any]:
    """Build the Concordia ``fulfillment`` block from a validated message.

    The returned dict matches the ``fulfillment_attestation`` schema
    block: ``status`` + ``settled_at`` + optional fulfilled / protocol
    fields. Concordia v0.4.1 adds ``fulfilled_with_mediation`` to the
    schema's status enum specifically for this use.
    """
    return {
        "status": "fulfilled_with_mediation",
        "settled_at": message["resolution_timestamp"],
        "fulfilled_at": message["resolution_timestamp"],
        "delivery_confirmed": False,
    }


def _build_mediation_meta(message: dict[str, Any]) -> dict[str, Any]:
    """Build the meta-fields delta for a DISPUTE_RESOLVED-driven fulfillment.

    Verascore's reputation scorer reads these keys. The shape is
    deliberately flat (no nested dicts beyond ``evidence_references``)
    so downstream consumers can stream them into a key-value scorer
    without recursive walks.
    """
    meta_delta: dict[str, Any] = {
        "mediator_invoked": True,
        "resolution_outcome": message["resolution_outcome"],
        "resolver_did": message["resolver_did"],
        "resolution_timestamp": message["resolution_timestamp"],
        "dispute_notice_message_id": message["dispute_notice_message_id"],
        "transaction_record_hash": message["transaction_record_hash"],
        "a2cn_message_id": message["message_id"],
    }
    if message.get("resolution_notes"):
        meta_delta["resolution_notes"] = message["resolution_notes"]
    evidence = message.get("evidence_references") or []
    if evidence:
        meta_delta["evidence_references"] = list(evidence)
    return meta_delta


def _build_fulfills_reference(agreement_attestation_id: str) -> dict[str, Any]:
    """Build the v0.4.0-shape reference entry that anchors the mediated
    fulfillment back to the original AGREED attestation.

    Christian's A2CN PR #12 review explicitly endorsed this composition
    seam: every mediated fulfillment carries a ``relationship: "fulfills"``
    reference to its agreement attestation so a Verascore scorer can walk
    backward without an out-of-band lookup.
    """
    if not isinstance(agreement_attestation_id, str) or not agreement_attestation_id:
        raise ValueError(
            "agreement_attestation_id must be a non-empty string",
        )
    return {
        "type": "receipt",
        "id": agreement_attestation_id,
        "relationship": "fulfills",
    }


def apply_dispute_resolved_to_attestation(
    *,
    attestation: dict[str, Any],
    message: dict[str, Any],
    agreement_attestation_id: str,
) -> dict[str, Any]:
    """Apply a DISPUTE_RESOLVED message to an existing Concordia attestation.

    Returns a NEW attestation dict (the input is not mutated). The new
    dict has:

      - ``fulfillment`` populated with the
        ``"fulfilled_with_mediation"`` block.
      - ``meta`` extended with mediation fields
        (``mediator_invoked``, ``resolution_outcome``, etc.).
      - ``references`` extended with a single
        ``{type: "receipt", id, relationship: "fulfills"}`` entry
        pointing at ``agreement_attestation_id``.

    The function validates the message against the A2CN schema before
    applying, so callers can pass raw input without a separate parse
    step. To split parse and apply, call ``parse_dispute_resolved``
    first and pass its output as ``message`` (the validation runs
    again but is idempotent).

    Raises ``DisputeResolvedSchemaError`` when ``message`` does not
    validate, and ``ValueError`` when ``agreement_attestation_id`` is
    missing or non-string.
    """
    validated = parse_dispute_resolved(message)
    new_attestation = copy.deepcopy(attestation)
    new_attestation["fulfillment"] = build_fulfillment_from_dispute_resolved(
        validated,
    )
    meta = dict(new_attestation.get("meta") or {})
    meta.update(_build_mediation_meta(validated))
    new_attestation["meta"] = meta
    references = list(new_attestation.get("references") or [])
    references.append(_build_fulfills_reference(agreement_attestation_id))
    new_attestation["references"] = references
    return new_attestation
