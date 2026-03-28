"""Reputation Query Handler — implements the §9.6.7 query/response interface.

Agents query reputation information about a counterparty before entering a
negotiation.  This module validates incoming queries, delegates to the scorer,
and produces the standard ``concordia.reputation.response`` envelope — optionally
signed by a service key pair.

Query shape (§9.6.7):
    {
      "type": "concordia.reputation.query",
      "subject_agent_id": "...",
      "requester_agent_id": "...",
      "context": {
        "category": "electronics",
        "value_range": "1000-5000_USD",
        "role": "seller"
      }
    }

Response shape includes: overall_score, confidence, summary stats,
context-specific scores, flags, attestation metadata, and an optional
service signature.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..signing import KeyPair, sign_message
from .scorer import ReputationScorer
from .store import AttestationStore


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

QUERY_TYPE = "concordia.reputation.query"
RESPONSE_TYPE = "concordia.reputation.response"


# ---------------------------------------------------------------------------
# Query validation
# ---------------------------------------------------------------------------

def validate_query(query: dict[str, Any]) -> list[str]:
    """Validate a reputation query dict.  Returns a list of errors (empty = valid)."""
    errors: list[str] = []

    if query.get("type") != QUERY_TYPE:
        errors.append(
            f"Invalid query type: expected '{QUERY_TYPE}', "
            f"got '{query.get('type')}'"
        )

    if not query.get("subject_agent_id"):
        errors.append("Missing required field: 'subject_agent_id'")

    if not query.get("requester_agent_id"):
        errors.append("Missing required field: 'requester_agent_id'")

    context = query.get("context")
    if context is not None and not isinstance(context, dict):
        errors.append("'context' must be a dict if provided")

    return errors


# ---------------------------------------------------------------------------
# Flags logic
# ---------------------------------------------------------------------------

_NEW_AGENT_THRESHOLD = 5       # fewer than this → "new_agent" flag
_LOW_CONFIDENCE_THRESHOLD = 0.3  # below this → "low_confidence" flag


def _compute_flags(
    score: Any,  # ReputationScore
    store: AttestationStore,
    agent_id: str,
) -> list[str]:
    """Derive human-readable flags from a reputation score."""
    flags: list[str] = []

    if score.total_negotiations < _NEW_AGENT_THRESHOLD:
        flags.append("new_agent")

    if score.confidence < _LOW_CONFIDENCE_THRESHOLD:
        flags.append("low_confidence")

    if score.sybil_flagged_count > 0:
        flags.append("sybil_signals_detected")

    if score.fulfillment_rate < 0.8 and score.total_agreements > 0:
        flags.append("low_fulfillment")

    if score.agreement_rate < 0.3 and score.total_negotiations >= _NEW_AGENT_THRESHOLD:
        flags.append("low_agreement_rate")

    return flags


# ---------------------------------------------------------------------------
# Context-specific scoring helpers
# ---------------------------------------------------------------------------

def _context_specific(
    scorer: ReputationScorer,
    agent_id: str,
    context: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compute context-specific sub-scores when a context block is supplied."""
    if not context:
        return {}

    result: dict[str, Any] = {}

    category = context.get("category")
    value_range = context.get("value_range")
    role = context.get("role")

    # Category-specific score
    if category:
        cat_score = scorer.score(agent_id, category=category)
        if cat_score:
            result["category_score"] = round(cat_score.overall_score, 4)
            result["category_negotiations"] = cat_score.total_negotiations
        else:
            result["category_score"] = None
            result["category_negotiations"] = 0

    # Value-range-specific score
    if value_range:
        vr_score = scorer.score(agent_id, value_range=value_range)
        if vr_score:
            result["value_range_score"] = round(vr_score.overall_score, 4)
        else:
            result["value_range_score"] = None

    # Role-specific score
    if role:
        role_score = scorer.score(agent_id, role=role)
        if role_score:
            result["role_score"] = round(role_score.overall_score, 4)
        else:
            result["role_score"] = None

    return result


# ---------------------------------------------------------------------------
# Attestation time range helpers
# ---------------------------------------------------------------------------

def _attestation_time_range(
    store: AttestationStore,
    agent_id: str,
) -> tuple[str | None, str | None]:
    """Return (earliest, latest) attestation timestamps for an agent."""
    records = store.get_by_agent(agent_id)
    if not records:
        return None, None

    timestamps: list[str] = []
    for r in records:
        ts = r.attestation.get("timestamp")
        if ts:
            timestamps.append(ts)

    if not timestamps:
        return None, None

    timestamps.sort()
    return timestamps[0], timestamps[-1]


# ---------------------------------------------------------------------------
# Reputation Query Handler
# ---------------------------------------------------------------------------

class ReputationQueryHandler:
    """Processes §9.6.7 reputation queries and produces signed responses.

    The handler ties together the store and scorer, adds context-specific
    sub-scores, flags, and attestation metadata, then optionally signs the
    response with a service key pair.
    """

    def __init__(
        self,
        store: AttestationStore,
        scorer: ReputationScorer,
        service_id: str = "concordia_reputation_service",
        service_key: KeyPair | None = None,
    ):
        self.store = store
        self.scorer = scorer
        self.service_id = service_id
        self.service_key = service_key

    def handle(self, query: dict[str, Any]) -> dict[str, Any]:
        """Process a reputation query and return a response dict.

        If the query is invalid, returns an error response.
        If the subject has no attestations, returns a response with null scores
        and a ``new_agent`` flag.
        """
        # Validate
        errors = validate_query(query)
        if errors:
            return self._error_response(query, errors)

        agent_id = query["subject_agent_id"]
        context = query.get("context")

        # Compute overall score
        score = self.scorer.score(
            agent_id,
            category=context.get("category") if context else None,
            value_range=context.get("value_range") if context else None,
            role=context.get("role") if context else None,
        )

        # No data for this agent
        if score is None:
            return self._no_data_response(query)

        # Context-specific sub-scores (unfiltered scorer calls)
        ctx_specific = _context_specific(self.scorer, agent_id, context)

        # Flags
        flags = _compute_flags(score, self.store, agent_id)

        # Attestation time range
        earliest, latest = _attestation_time_range(self.store, agent_id)

        response: dict[str, Any] = {
            "type": RESPONSE_TYPE,
            "subject_agent_id": agent_id,
            "service_id": self.service_id,
            "computed_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "summary": {
                "overall_score": round(score.overall_score, 4),
                "confidence": round(score.confidence, 4),
                "total_negotiations": score.total_negotiations,
                "total_agreements": score.total_agreements,
                "agreement_rate": round(score.agreement_rate, 4),
                "fulfillment_rate": round(score.fulfillment_rate, 4),
                "avg_concession_willingness": round(
                    score.avg_concession_willingness, 4
                ),
                "reasoning_rate": round(score.reasoning_rate, 4),
                "median_rounds_to_agreement": score.median_rounds_to_agreement,
                "categories_active": score.categories_active,
            },
            "context_specific": ctx_specific,
            "flags": flags,
            "attestation_count": score.total_negotiations,
            "earliest_attestation": earliest,
            "latest_attestation": latest,
            "counterparty_count": score.counterparty_count,
        }

        # Sign the response if we have a service key
        if self.service_key:
            sig = sign_message(response, self.service_key)
            response["service_signature"] = sig
        else:
            response["service_signature"] = None

        return response

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _error_response(
        self,
        query: dict[str, Any],
        errors: list[str],
    ) -> dict[str, Any]:
        """Return a structured error response."""
        return {
            "type": RESPONSE_TYPE,
            "subject_agent_id": query.get("subject_agent_id"),
            "service_id": self.service_id,
            "computed_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "error": True,
            "errors": errors,
        }

    def _no_data_response(self, query: dict[str, Any]) -> dict[str, Any]:
        """Return a response for an agent with no attestation history."""
        return {
            "type": RESPONSE_TYPE,
            "subject_agent_id": query["subject_agent_id"],
            "service_id": self.service_id,
            "computed_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "summary": None,
            "context_specific": {},
            "flags": ["new_agent", "no_data"],
            "attestation_count": 0,
            "earliest_attestation": None,
            "latest_attestation": None,
            "counterparty_count": 0,
            "service_signature": None,
        }
