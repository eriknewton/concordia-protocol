"""Canonicalization wrappers for CMPC bilateral primitives."""

from __future__ import annotations

from typing import Any

from concordia.canonicalization import canonicalize_jcs


def _canonicalize_primitive(primitive: Any) -> bytes:
    data = primitive.to_dict() if hasattr(primitive, "to_dict") else dict(primitive)
    data.pop("signature", None)
    return canonicalize_jcs(data)


def canonicalize_chain_session(session: Any) -> bytes:
    return _canonicalize_primitive(session)


def canonicalize_conditional_commitment(commitment: Any) -> bytes:
    return _canonicalize_primitive(commitment)


def canonicalize_closure_predicate(predicate: Any) -> bytes:
    return _canonicalize_primitive(predicate)


def canonicalize_atomic_activation_proof(proof: Any) -> bytes:
    return _canonicalize_primitive(proof)


def canonicalize_unwind_record(record: Any) -> bytes:
    return _canonicalize_primitive(record)


def canonicalize_revocation_record(record: Any) -> bytes:
    return _canonicalize_primitive(record)


def canonicalize_cascade_decision_record(record: Any) -> bytes:
    """Return the JCS canonical bytes the ``decision_id`` and signature commit to.

    The preimage EXCLUDES ``decision_id`` and ``signature`` (neither can commit
    to itself) and INCLUDES the optional refs when present. A record exposes
    that exact object via ``preimage()``; a plain mapping is stripped of
    ``decision_id`` and ``signature`` here so both call shapes agree byte for
    byte. Uses the same RFC 8785 JCS canonicalizer as every other primitive.
    """
    if hasattr(record, "preimage"):
        return canonicalize_jcs(record.preimage())
    data = dict(record)
    data.pop("decision_id", None)
    data.pop("signature", None)
    return canonicalize_jcs(data)
