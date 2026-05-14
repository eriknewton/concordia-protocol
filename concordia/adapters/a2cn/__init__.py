"""A2CN protocol adapter.

A2CN (Agent-to-Agent Commerce Network) is a parallel-track negotiation
protocol with which Concordia interoperates at the message-shape level.
This adapter consumes A2CN messages (DISPUTE_RESOLVED at v0.4.1) and
maps them into Concordia's attestation primitives.

Schema source: https://github.com/A2CN-protocol/A2CN/blob/main/spec/schemas/
Local mirror: ``schemas/a2cn/``
"""

from concordia.adapters.a2cn.dispute_resolved import (
    DISPUTE_RESOLVED_SCHEMA,
    DisputeResolvedApplicationError,
    DisputeResolvedSchemaError,
    parse_dispute_resolved,
    apply_dispute_resolved_to_attestation,
    build_fulfillment_from_dispute_resolved,
)

__all__ = [
    "DISPUTE_RESOLVED_SCHEMA",
    "DisputeResolvedApplicationError",
    "DisputeResolvedSchemaError",
    "parse_dispute_resolved",
    "apply_dispute_resolved_to_attestation",
    "build_fulfillment_from_dispute_resolved",
]
