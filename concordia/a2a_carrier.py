"""A2A structured-data carrier for one signed Concordia envelope.

This module implements the private v1 prototype described in
``docs/A2A_EXTENSION_DRAFT.md``.  It deliberately does not depend on an A2A
SDK: the A2A wire shape is a plain JSON object and Concordia remains the
authority for its signed envelope.
"""

from __future__ import annotations

from collections.abc import Collection
from copy import deepcopy
from typing import Any

from .registry import A2A_EXTENSION_URI
from .schema_validator import validate_message

A2A_CARRIER_TYPE = f"{A2A_EXTENSION_URI}#envelope"
A2A_CARRIER_VERSION = "1"
A2A_CARRIER_SCHEMA_URI = f"{A2A_EXTENSION_URI}/schema/data-part.json"
A2A_CARRIER_MEDIA_TYPE = "application/vnd.concordia.negotiation+json"

_DATA_KEYS = frozenset({"type", "version", "envelope"})
_A2A_CONTENT_KEYS = frozenset({"text", "raw", "url"})
_A2A_ID_KEYS = frozenset({"taskId", "contextId", "task_id", "context_id"})


class A2ACarrierError(ValueError):
    """The A2A part cannot be safely interpreted as a Concordia carrier."""


def _validate_envelope(envelope: object) -> dict[str, Any]:
    if not isinstance(envelope, dict):
        raise A2ACarrierError("invalid envelope: expected an object")
    if _A2A_ID_KEYS.intersection(envelope):
        raise A2ACarrierError("invalid envelope: A2A identifiers belong outside signed bytes")
    if validate_message(envelope):
        # Do not forward jsonschema diagnostics here: even though the shared
        # validator is no-echo, this trust boundary promises a fixed, bounded
        # carrier diagnostic independent of rejected values.
        raise A2ACarrierError("invalid envelope: Concordia message validation failed")
    return envelope


def build_a2a_data_part(envelope: dict[str, Any]) -> dict[str, Any]:
    """Build one A2A ``Part`` whose structured ``data`` is a Concordia envelope.

    The returned object owns a deep copy of ``envelope``.  Carrier metadata is
    outside the signed Concordia bytes and therefore never affects the
    Concordia session identifier or signature payload.
    """

    validated = _validate_envelope(envelope)
    return {
        "data": {
            "type": A2A_CARRIER_TYPE,
            "version": A2A_CARRIER_VERSION,
            "envelope": deepcopy(validated),
        },
        "metadata": {
            A2A_EXTENSION_URI: {
                "schema": A2A_CARRIER_SCHEMA_URI,
            }
        },
        "mediaType": A2A_CARRIER_MEDIA_TYPE,
    }


def parse_a2a_data_part(
    part: object,
    *,
    active_extensions: Collection[str],
) -> dict[str, Any]:
    """Validate and extract a Concordia envelope from an activated A2A part.

    ``active_extensions`` is the request- or response-side set that the caller
    already derived from A2A's binding-specific activation mechanism.  An
    absent activation is a hard refusal; the mere presence of carrier-shaped
    bytes does not activate extension semantics.
    """

    if isinstance(active_extensions, str) or A2A_EXTENSION_URI not in active_extensions:
        raise A2ACarrierError("Concordia A2A extension is not active")
    if not isinstance(part, dict):
        raise A2ACarrierError("invalid A2A part: expected an object")
    if _A2A_CONTENT_KEYS.intersection(part):
        raise A2ACarrierError("invalid A2A part: conflicting content member")
    if part.get("mediaType") != A2A_CARRIER_MEDIA_TYPE:
        raise A2ACarrierError("invalid A2A part mediaType")

    data = part.get("data")
    if not isinstance(data, dict):
        raise A2ACarrierError("invalid A2A part data")
    if set(data) != _DATA_KEYS:
        raise A2ACarrierError("invalid A2A part data members")
    if data.get("type") != A2A_CARRIER_TYPE:
        raise A2ACarrierError("invalid A2A carrier type")
    if data.get("version") != A2A_CARRIER_VERSION:
        raise A2ACarrierError("invalid A2A carrier version")

    metadata = part.get("metadata")
    if not isinstance(metadata, dict):
        raise A2ACarrierError("invalid A2A carrier metadata")
    extension_metadata = metadata.get(A2A_EXTENSION_URI)
    if not isinstance(extension_metadata, dict):
        raise A2ACarrierError("invalid A2A carrier metadata")
    if set(extension_metadata) != {"schema"}:
        raise A2ACarrierError("invalid A2A carrier metadata members")
    if extension_metadata.get("schema") != A2A_CARRIER_SCHEMA_URI:
        raise A2ACarrierError("invalid A2A carrier schema")

    return deepcopy(_validate_envelope(data.get("envelope")))
