"""Concordia Reputation Service — attestation ingestion, scoring, and query API.

Implements the hosted reputation layer described in SERVICE_ARCHITECTURE.md.
Ingests attestations (§9.6), computes reputation scores, and responds to
queries using the standard format from §9.6.7.

Components:
    store   — Attestation storage, validation, and deduplication
    scorer  — Reputation score computation from aggregated attestations
    query   — Standard §9.6.7 query/response interface
"""

from .store import AttestationStore
from .scorer import ReputationScorer
from .query import ReputationQueryHandler

__all__ = [
    "AttestationStore",
    "ReputationScorer",
    "ReputationQueryHandler",
]
