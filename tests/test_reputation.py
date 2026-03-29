"""Tests for the Concordia Reputation Service (store, scorer, query handler).

Covers:
    - AttestationStore: validation, dedup, Sybil detection, indexing
    - ReputationScorer: score computation, confidence, components, Sybil penalties
    - ReputationQueryHandler: §9.6.7 query/response format, flags, context-specific scores
    - MCP tool integration: ingest, query, and score tools via handle_tool_call
"""

from __future__ import annotations

import json
import math
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from concordia.reputation.store import (
    AttestationStore,
    StoredAttestation,
    SybilSignals,
    ValidationResult,
)
from concordia.reputation.scorer import (
    DEFAULT_WEIGHTS,
    ReputationScorer,
    ReputationScore,
    ScoreComponents,
)
from concordia.reputation.query import (
    QUERY_TYPE,
    RESPONSE_TYPE,
    ReputationQueryHandler,
    validate_query,
)
from concordia.signing import KeyPair, sign_message


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

# Shared key registry: agent_id → KeyPair.  Lazily populated so every
# agent_id used in tests gets a stable key pair.
_KEY_REGISTRY: dict[str, KeyPair] = {}


def _get_key(agent_id: str) -> KeyPair:
    """Return a stable KeyPair for *agent_id*, creating one if needed."""
    if agent_id not in _KEY_REGISTRY:
        _KEY_REGISTRY[agent_id] = KeyPair.generate()
    return _KEY_REGISTRY[agent_id]


def _test_resolver(agent_id: str) -> Ed25519PublicKey | None:
    """Public-key resolver backed by the shared test key registry."""
    kp = _KEY_REGISTRY.get(agent_id)
    return kp.public_key if kp else None


def _make_attestation(
    agent_a: str = "agent_a",
    agent_b: str = "agent_b",
    status: str = "agreed",
    rounds: int = 3,
    duration_seconds: int = 120,
    category: str = "electronics",
    value_range: str = "100-500_USD",
    concession_a: float = 0.2,
    concession_b: float = 0.15,
    offers_a: int = 2,
    offers_b: int = 3,
    reasoning_a: bool = True,
    reasoning_b: bool = False,
    fulfillment_status: str | None = "fulfilled",
    att_id: str | None = None,
    session_id: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Create a valid, properly-signed attestation dict for testing.

    Each party's ``signature`` field is a real Ed25519 signature computed
    over the party record (excluding the signature itself), matching the
    verification logic in ``AttestationStore._validate()``.
    """
    att_id = att_id or f"att_{uuid.uuid4().hex[:12]}"
    session_id = session_id or f"sess_{uuid.uuid4().hex[:12]}"
    timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build party records without signatures first, then sign
    party_a_record: dict[str, Any] = {
        "agent_id": agent_a,
        "role": "seller",
        "behavior": {
            "concession_magnitude": concession_a,
            "offers_made": offers_a,
            "reasoning_provided": reasoning_a,
        },
    }
    party_a_record["signature"] = sign_message(party_a_record, _get_key(agent_a))

    party_b_record: dict[str, Any] = {
        "agent_id": agent_b,
        "role": "buyer",
        "behavior": {
            "concession_magnitude": concession_b,
            "offers_made": offers_b,
            "reasoning_provided": reasoning_b,
        },
    }
    party_b_record["signature"] = sign_message(party_b_record, _get_key(agent_b))

    att: dict[str, Any] = {
        "concordia_attestation": "1.0",
        "attestation_id": att_id,
        "session_id": session_id,
        "timestamp": timestamp,
        "outcome": {
            "status": status,
            "rounds": rounds,
            "duration_seconds": duration_seconds,
        },
        "parties": [party_a_record, party_b_record],
        "meta": {
            "category": category,
            "value_range": value_range,
        },
        "transcript_hash": "sha256:abc123def456",
    }

    if fulfillment_status and status == "agreed":
        att["fulfillment"] = {"status": fulfillment_status}

    return att


def _ingest_n(store: AttestationStore, n: int, **kwargs: Any) -> list[dict[str, Any]]:
    """Ingest n attestations into a store and return them."""
    attestations = []
    for _ in range(n):
        att = _make_attestation(**kwargs)
        accepted, _ = store.ingest(att, _test_resolver)
        assert accepted, f"Failed to ingest: {att['attestation_id']}"
        attestations.append(att)
    return attestations


# ===================================================================
# AttestationStore tests
# ===================================================================

class TestAttestationStoreValidation:
    """Test the attestation validation pipeline."""

    def test_valid_attestation_accepted(self):
        store = AttestationStore()
        att = _make_attestation()
        accepted, result = store.ingest(att, _test_resolver)
        assert accepted is True
        assert result.valid is True
        assert result.errors == []

    def test_missing_required_field(self):
        store = AttestationStore()
        att = _make_attestation()
        del att["outcome"]
        accepted, result = store.ingest(att, _test_resolver)
        assert accepted is False
        assert any("outcome" in e for e in result.errors)

    def test_missing_multiple_fields(self):
        store = AttestationStore()
        att = {"concordia_attestation": "1.0"}
        accepted, result = store.ingest(att, _test_resolver)
        assert accepted is False
        assert len(result.errors) >= 5  # many fields missing

    def test_invalid_outcome_status(self):
        store = AttestationStore()
        att = _make_attestation()
        att["outcome"]["status"] = "invalid_status"
        accepted, result = store.ingest(att, _test_resolver)
        assert accepted is False
        assert any("status" in e for e in result.errors)

    def test_missing_outcome_fields(self):
        store = AttestationStore()
        att = _make_attestation()
        del att["outcome"]["rounds"]
        accepted, result = store.ingest(att, _test_resolver)
        assert accepted is False
        assert any("rounds" in e for e in result.errors)

    def test_fewer_than_two_parties(self):
        store = AttestationStore()
        att = _make_attestation()
        att["parties"] = [att["parties"][0]]  # only one party
        accepted, result = store.ingest(att, _test_resolver)
        assert accepted is False
        assert any("2 parties" in e for e in result.errors)

    def test_missing_party_fields(self):
        store = AttestationStore()
        att = _make_attestation()
        del att["parties"][0]["signature"]
        accepted, result = store.ingest(att, _test_resolver)
        assert accepted is False
        assert any("signature" in e for e in result.errors)

    def test_invalid_transcript_hash_format(self):
        store = AttestationStore()
        att = _make_attestation()
        att["transcript_hash"] = "md5:notvalid"
        accepted, result = store.ingest(att, _test_resolver)
        assert accepted is False
        assert any("sha256:" in e for e in result.errors)

    def test_valid_statuses(self):
        store = AttestationStore()
        for status in ["agreed", "rejected", "expired", "withdrawn"]:
            att = _make_attestation(status=status, fulfillment_status=None)
            accepted, result = store.ingest(att, _test_resolver)
            assert accepted is True, f"Status '{status}' should be valid"


class TestAttestationStoreDedup:
    """Test deduplication logic."""

    def test_duplicate_attestation_id_rejected(self):
        store = AttestationStore()
        att = _make_attestation(att_id="att_123")
        store.ingest(att, _test_resolver)

        att2 = _make_attestation(att_id="att_123", session_id="sess_different")
        accepted, result = store.ingest(att2, _test_resolver)
        assert accepted is False
        assert any("Duplicate attestation_id" in e for e in result.errors)

    def test_duplicate_session_id_rejected(self):
        store = AttestationStore()
        att = _make_attestation(session_id="sess_456")
        store.ingest(att, _test_resolver)

        att2 = _make_attestation(att_id="att_different", session_id="sess_456")
        accepted, result = store.ingest(att2, _test_resolver)
        assert accepted is False
        assert any("Duplicate session_id" in e for e in result.errors)

    def test_unique_attestations_accepted(self):
        store = AttestationStore()
        for i in range(5):
            att = _make_attestation()
            accepted, _ = store.ingest(att, _test_resolver)
            assert accepted is True
        assert store.count() == 5


class TestAttestationStoreIndexing:
    """Test index-based retrieval methods."""

    def test_get_by_id(self):
        store = AttestationStore()
        att = _make_attestation(att_id="att_lookup")
        store.ingest(att, _test_resolver)
        record = store.get("att_lookup")
        assert record is not None
        assert record.attestation_id == "att_lookup"

    def test_get_by_session(self):
        store = AttestationStore()
        att = _make_attestation(session_id="sess_lookup")
        store.ingest(att, _test_resolver)
        record = store.get_by_session("sess_lookup")
        assert record is not None
        assert record.session_id == "sess_lookup"

    def test_get_by_agent(self):
        store = AttestationStore()
        _ingest_n(store, 3, agent_a="alice", agent_b="bob")
        _ingest_n(store, 2, agent_a="alice", agent_b="charlie")

        alice_records = store.get_by_agent("alice")
        assert len(alice_records) == 5

        bob_records = store.get_by_agent("bob")
        assert len(bob_records) == 3

    def test_get_counterparties(self):
        store = AttestationStore()
        _ingest_n(store, 2, agent_a="alice", agent_b="bob")
        _ingest_n(store, 1, agent_a="alice", agent_b="charlie")

        counterparties = store.get_counterparties("alice")
        assert counterparties == {"bob", "charlie"}

    def test_count_methods(self):
        store = AttestationStore()
        _ingest_n(store, 3, agent_a="x", agent_b="y")
        assert store.count() == 3
        assert store.agent_count("x") == 3
        assert store.agent_count("y") == 3
        assert store.agent_count("z") == 0

    def test_get_missing_returns_none(self):
        store = AttestationStore()
        assert store.get("nonexistent") is None
        assert store.get_by_session("nonexistent") is None
        assert store.get_by_agent("nonexistent") == []


class TestSybilDetection:
    """Test Sybil signal detection."""

    def test_self_dealing_detected(self):
        store = AttestationStore()
        att = _make_attestation(agent_a="same_agent", agent_b="same_agent")
        accepted, result = store.ingest(att, _test_resolver)
        assert accepted is True  # accepted but flagged
        assert any("Sybil" in w for w in result.warnings)
        record = store.get(att["attestation_id"])
        assert record.sybil_signals.self_dealing is True
        assert record.sybil_signals.flagged is True

    def test_suspiciously_fast_detected(self):
        store = AttestationStore()
        att = _make_attestation(duration_seconds=2)
        accepted, result = store.ingest(att, _test_resolver)
        assert accepted is True
        record = store.get(att["attestation_id"])
        assert record.sybil_signals.suspiciously_fast is True
        assert record.sybil_signals.flagged is True

    def test_symmetric_concessions_detected(self):
        store = AttestationStore()
        att = _make_attestation(concession_a=0.25, concession_b=0.25)
        accepted, result = store.ingest(att, _test_resolver)
        assert accepted is True
        record = store.get(att["attestation_id"])
        assert record.sybil_signals.symmetric_concessions is True

    def test_normal_attestation_not_flagged(self):
        store = AttestationStore()
        att = _make_attestation(
            agent_a="alice", agent_b="bob",
            duration_seconds=120,
            concession_a=0.2, concession_b=0.15,
        )
        accepted, result = store.ingest(att, _test_resolver)
        assert accepted is True
        record = store.get(att["attestation_id"])
        assert record.sybil_signals.flagged is False


# ===================================================================
# ReputationScorer tests
# ===================================================================

class TestReputationScorer:
    """Test the scoring engine."""

    def test_no_data_returns_none(self):
        store = AttestationStore()
        scorer = ReputationScorer(store)
        assert scorer.score("unknown_agent") is None

    def test_basic_score_computation(self):
        store = AttestationStore()
        _ingest_n(store, 10, agent_a="seller", agent_b="buyer")
        scorer = ReputationScorer(store)

        score = scorer.score("seller")
        assert score is not None
        assert 0.0 <= score.overall_score <= 1.0
        assert 0.0 <= score.confidence <= 1.0
        assert score.total_negotiations == 10
        assert score.agent_id == "seller"

    def test_agreement_rate(self):
        store = AttestationStore()
        # 7 agreed, 3 rejected
        _ingest_n(store, 7, agent_a="s", agent_b="b", status="agreed")
        _ingest_n(store, 3, agent_a="s", agent_b="b", status="rejected",
                  fulfillment_status=None)

        scorer = ReputationScorer(store)
        score = scorer.score("s")
        assert score is not None
        assert abs(score.agreement_rate - 0.7) < 0.01

    def test_fulfillment_rate(self):
        store = AttestationStore()
        _ingest_n(store, 8, agent_a="s", agent_b="b", fulfillment_status="fulfilled")
        _ingest_n(store, 2, agent_a="s", agent_b="b", fulfillment_status="disputed")

        scorer = ReputationScorer(store)
        score = scorer.score("s")
        assert score is not None
        assert abs(score.fulfillment_rate - 0.8) < 0.01

    def test_fulfillment_benefit_of_doubt(self):
        """No fulfillment data → default to 1.0."""
        store = AttestationStore()
        _ingest_n(store, 3, agent_a="s", agent_b="b",
                  status="rejected", fulfillment_status=None)

        scorer = ReputationScorer(store)
        score = scorer.score("s")
        assert score is not None
        assert score.components.fulfillment_rate == 1.0

    def test_confidence_increases_with_volume(self):
        store = AttestationStore()
        scorer = ReputationScorer(store)

        _ingest_n(store, 3, agent_a="a", agent_b="b")
        score_3 = scorer.score("a")

        _ingest_n(store, 20, agent_a="a", agent_b="c")
        score_23 = scorer.score("a")

        assert score_23.confidence > score_3.confidence

    def test_confidence_increases_with_diversity(self):
        store = AttestationStore()
        scorer = ReputationScorer(store)

        # 10 attestations, all with same counterparty
        _ingest_n(store, 10, agent_a="alice", agent_b="bob")
        score_low_div = scorer.score("alice")

        # Add 10 more with different counterparties
        for i in range(10):
            att = _make_attestation(agent_a="alice", agent_b=f"cp_{i}")
            store.ingest(att, _test_resolver)
        score_high_div = scorer.score("alice")

        assert score_high_div.confidence > score_low_div.confidence

    def test_sybil_penalty_reduces_score(self):
        store = AttestationStore()
        # Ingest some normal attestations
        _ingest_n(store, 5, agent_a="agent_x", agent_b="agent_y")
        scorer = ReputationScorer(store)
        clean_score = scorer.score("agent_x")

        # Now ingest sybil-flagged attestations (self-dealing)
        store2 = AttestationStore()
        _ingest_n(store2, 5, agent_a="agent_x", agent_b="agent_y")
        _ingest_n(store2, 5, agent_a="agent_x", agent_b="agent_x")  # self-dealing
        scorer2 = ReputationScorer(store2)
        sybil_score = scorer2.score("agent_x")

        assert sybil_score.overall_score < clean_score.overall_score

    def test_category_filter(self):
        store = AttestationStore()
        _ingest_n(store, 5, agent_a="s", agent_b="b", category="electronics")
        _ingest_n(store, 3, agent_a="s", agent_b="b", category="furniture")

        scorer = ReputationScorer(store)
        all_score = scorer.score("s")
        elec_score = scorer.score("s", category="electronics")

        assert all_score.total_negotiations == 8
        assert elec_score.total_negotiations == 5

    def test_role_filter(self):
        store = AttestationStore()
        _ingest_n(store, 5, agent_a="agent", agent_b="other")
        scorer = ReputationScorer(store)

        seller_score = scorer.score("agent", role="seller")
        buyer_score = scorer.score("agent", role="buyer")

        assert seller_score is not None
        assert seller_score.total_negotiations == 5
        # agent is always "seller" in these attestations, so buyer filter → None
        assert buyer_score is None

    def test_custom_weights(self):
        store = AttestationStore()
        _ingest_n(store, 10, agent_a="s", agent_b="b")

        # Default weights
        scorer1 = ReputationScorer(store)
        score1 = scorer1.score("s")

        # Heavily weight fulfillment
        custom = {
            "agreement_rate": 0.0,
            "concession_willingness": 0.0,
            "fulfillment_rate": 1.0,
            "reasoning_rate": 0.0,
            "consistency": 0.0,
            "responsiveness": 0.0,
        }
        scorer2 = ReputationScorer(store, weights=custom)
        score2 = scorer2.score("s")

        # Since fulfillment is 1.0 by default, the custom score should be close to 1.0
        assert score2.overall_score >= 0.9

    def test_score_components_present(self):
        store = AttestationStore()
        _ingest_n(store, 10, agent_a="s", agent_b="b")
        scorer = ReputationScorer(store)
        score = scorer.score("s")

        comp = score.components
        assert 0.0 <= comp.agreement_rate <= 1.0
        assert 0.0 <= comp.concession_willingness <= 1.0
        assert 0.0 <= comp.fulfillment_rate <= 1.0
        assert 0.0 <= comp.reasoning_rate <= 1.0
        assert 0.0 <= comp.consistency <= 1.0
        assert 0.0 <= comp.responsiveness <= 1.0

    def test_score_to_dict(self):
        store = AttestationStore()
        _ingest_n(store, 5, agent_a="s", agent_b="b")
        scorer = ReputationScorer(store)
        score = scorer.score("s")

        d = score.to_dict()
        assert "overall_score" in d
        assert "confidence" in d
        assert "components" in d
        assert "total_negotiations" in d
        assert isinstance(d["components"], dict)


class TestScoreComponents:
    """Test ScoreComponents dataclass."""

    def test_defaults(self):
        comp = ScoreComponents()
        assert comp.agreement_rate == 0.0
        assert comp.responsiveness == 0.0

    def test_to_dict_rounding(self):
        comp = ScoreComponents(agreement_rate=0.87654321)
        d = comp.to_dict()
        assert d["agreement_rate"] == 0.8765


# ===================================================================
# ReputationQueryHandler tests
# ===================================================================

class TestQueryValidation:
    """Test query validation logic."""

    def test_valid_query(self):
        errors = validate_query({
            "type": QUERY_TYPE,
            "subject_agent_id": "agent_a",
            "requester_agent_id": "agent_b",
        })
        assert errors == []

    def test_missing_type(self):
        errors = validate_query({
            "subject_agent_id": "agent_a",
            "requester_agent_id": "agent_b",
        })
        assert len(errors) > 0

    def test_wrong_type(self):
        errors = validate_query({
            "type": "wrong.type",
            "subject_agent_id": "agent_a",
            "requester_agent_id": "agent_b",
        })
        assert any("type" in e.lower() for e in errors)

    def test_missing_subject(self):
        errors = validate_query({
            "type": QUERY_TYPE,
            "requester_agent_id": "agent_b",
        })
        assert any("subject_agent_id" in e for e in errors)

    def test_missing_requester(self):
        errors = validate_query({
            "type": QUERY_TYPE,
            "subject_agent_id": "agent_a",
        })
        assert any("requester_agent_id" in e for e in errors)

    def test_invalid_context_type(self):
        errors = validate_query({
            "type": QUERY_TYPE,
            "subject_agent_id": "agent_a",
            "requester_agent_id": "agent_b",
            "context": "not a dict",
        })
        assert any("context" in e for e in errors)

    def test_optional_context_accepted(self):
        errors = validate_query({
            "type": QUERY_TYPE,
            "subject_agent_id": "agent_a",
            "requester_agent_id": "agent_b",
            "context": {"category": "electronics"},
        })
        assert errors == []


class TestReputationQueryHandler:
    """Test the full query handler."""

    def _setup(self, n: int = 10, **kwargs: Any) -> tuple[
        AttestationStore, ReputationScorer, ReputationQueryHandler
    ]:
        store = AttestationStore()
        _ingest_n(store, n, **kwargs)
        scorer = ReputationScorer(store)
        handler = ReputationQueryHandler(
            store=store,
            scorer=scorer,
            service_id="test_service",
        )
        return store, scorer, handler

    def test_basic_query_response(self):
        _, _, handler = self._setup(10, agent_a="seller", agent_b="buyer")
        response = handler.handle({
            "type": QUERY_TYPE,
            "subject_agent_id": "seller",
            "requester_agent_id": "buyer",
        })

        assert response["type"] == RESPONSE_TYPE
        assert response["subject_agent_id"] == "seller"
        assert response["service_id"] == "test_service"
        assert "computed_at" in response
        assert "summary" in response
        assert response["summary"]["total_negotiations"] == 10

    def test_summary_fields(self):
        _, _, handler = self._setup(10, agent_a="s", agent_b="b")
        response = handler.handle({
            "type": QUERY_TYPE,
            "subject_agent_id": "s",
            "requester_agent_id": "b",
        })

        summary = response["summary"]
        assert "overall_score" in summary
        assert "confidence" in summary
        assert "agreement_rate" in summary
        assert "fulfillment_rate" in summary
        assert "avg_concession_willingness" in summary
        assert "reasoning_rate" in summary
        assert "median_rounds_to_agreement" in summary
        assert "categories_active" in summary

    def test_no_data_response(self):
        store = AttestationStore()
        scorer = ReputationScorer(store)
        handler = ReputationQueryHandler(store=store, scorer=scorer)

        response = handler.handle({
            "type": QUERY_TYPE,
            "subject_agent_id": "unknown",
            "requester_agent_id": "asker",
        })

        assert response["summary"] is None
        assert "no_data" in response["flags"]
        assert "new_agent" in response["flags"]
        assert response["attestation_count"] == 0

    def test_error_response_invalid_query(self):
        store = AttestationStore()
        scorer = ReputationScorer(store)
        handler = ReputationQueryHandler(store=store, scorer=scorer)

        response = handler.handle({"type": "wrong"})
        assert response.get("error") is True
        assert len(response.get("errors", [])) > 0

    def test_context_specific_scores(self):
        store = AttestationStore()
        _ingest_n(store, 5, agent_a="s", agent_b="b", category="electronics")
        _ingest_n(store, 5, agent_a="s", agent_b="b", category="furniture")
        scorer = ReputationScorer(store)
        handler = ReputationQueryHandler(store=store, scorer=scorer)

        response = handler.handle({
            "type": QUERY_TYPE,
            "subject_agent_id": "s",
            "requester_agent_id": "b",
            "context": {
                "category": "electronics",
                "role": "seller",
            },
        })

        ctx = response.get("context_specific", {})
        assert "category_score" in ctx
        assert "role_score" in ctx
        assert ctx["category_negotiations"] == 5

    def test_flags_new_agent(self):
        _, _, handler = self._setup(2, agent_a="new_s", agent_b="new_b")
        response = handler.handle({
            "type": QUERY_TYPE,
            "subject_agent_id": "new_s",
            "requester_agent_id": "new_b",
        })
        assert "new_agent" in response["flags"]

    def test_flags_sybil(self):
        store = AttestationStore()
        # Ingest self-dealing attestations
        _ingest_n(store, 10, agent_a="shady", agent_b="shady")
        scorer = ReputationScorer(store)
        handler = ReputationQueryHandler(store=store, scorer=scorer)

        response = handler.handle({
            "type": QUERY_TYPE,
            "subject_agent_id": "shady",
            "requester_agent_id": "checker",
        })
        assert "sybil_signals_detected" in response["flags"]

    def test_signed_response(self):
        store = AttestationStore()
        _ingest_n(store, 5, agent_a="s", agent_b="b")
        scorer = ReputationScorer(store)
        service_key = KeyPair.generate()
        handler = ReputationQueryHandler(
            store=store,
            scorer=scorer,
            service_key=service_key,
        )

        response = handler.handle({
            "type": QUERY_TYPE,
            "subject_agent_id": "s",
            "requester_agent_id": "b",
        })

        assert response["service_signature"] is not None
        assert len(response["service_signature"]) > 0

    def test_unsigned_response(self):
        _, _, handler = self._setup(5, agent_a="s", agent_b="b")
        response = handler.handle({
            "type": QUERY_TYPE,
            "subject_agent_id": "s",
            "requester_agent_id": "b",
        })
        assert response["service_signature"] is None

    def test_attestation_time_range(self):
        store = AttestationStore()
        att1 = _make_attestation(
            agent_a="s", agent_b="b",
            timestamp="2026-01-15T00:00:00Z",
        )
        att2 = _make_attestation(
            agent_a="s", agent_b="b",
            timestamp="2026-03-20T00:00:00Z",
        )
        store.ingest(att1, _test_resolver)
        store.ingest(att2, _test_resolver)

        scorer = ReputationScorer(store)
        handler = ReputationQueryHandler(store=store, scorer=scorer)

        response = handler.handle({
            "type": QUERY_TYPE,
            "subject_agent_id": "s",
            "requester_agent_id": "b",
        })

        assert response["earliest_attestation"] == "2026-01-15T00:00:00Z"
        assert response["latest_attestation"] == "2026-03-20T00:00:00Z"

    def test_counterparty_count_in_response(self):
        store = AttestationStore()
        _ingest_n(store, 3, agent_a="s", agent_b="b1")
        _ingest_n(store, 3, agent_a="s", agent_b="b2")
        scorer = ReputationScorer(store)
        handler = ReputationQueryHandler(store=store, scorer=scorer)

        response = handler.handle({
            "type": QUERY_TYPE,
            "subject_agent_id": "s",
            "requester_agent_id": "b1",
        })
        assert response["counterparty_count"] == 2


# ===================================================================
# MCP Tool integration tests
# ===================================================================

class TestReputationMcpTools:
    """Test reputation tools via handle_tool_call."""

    @pytest.fixture(autouse=True)
    def reset_stores(self):
        """Reset both stores and auth tokens between tests."""
        from concordia.mcp_server import (
            _store, _attestation_store, _scorer, _query_handler, _auth,
        )
        _store._sessions.clear()
        _attestation_store._by_id.clear()
        _attestation_store._by_session.clear()
        _attestation_store._by_agent.clear()
        _attestation_store._counterparties.clear()
        _auth._agent_tokens.clear()
        _auth._session_tokens.clear()
        _auth._token_to_agent.clear()
        yield

    def _parse(self, result_str: str) -> dict:
        return json.loads(result_str)

    def _create_session_and_receipt(self, agent_a: str, agent_b: str):
        """Create a session via the MCP server's session store and generate
        a properly-signed attestation (receipt) for it.

        Returns (session_id, attestation_dict).
        """
        from concordia.mcp_server import _store, tool_session_receipt, _auth
        from concordia.types import AgentIdentity, MessageType
        from concordia.message import build_envelope

        terms = {"price": {"type": "numeric", "value": 100}}
        ctx = _store.create(agent_a, agent_b, terms)
        session_id = ctx.session.session_id

        def _resolver(aid: str):
            if aid == agent_a:
                return ctx.initiator_key.public_key
            if aid == agent_b:
                return ctx.responder_key.public_key
            return None

        # Send an offer from initiator
        offer_msg = build_envelope(
            message_type=MessageType.OFFER,
            session_id=session_id,
            sender=AgentIdentity(agent_id=agent_a),
            body={"terms": terms},
            key_pair=ctx.initiator_key,
            prev_hash=ctx.session.prev_hash,
            recipients=[AgentIdentity(agent_id=agent_b)],
        )
        ctx.session.apply_message(offer_msg, _resolver)

        # Accept from responder
        accept_msg = build_envelope(
            message_type=MessageType.ACCEPT,
            session_id=session_id,
            sender=AgentIdentity(agent_id=agent_b),
            body={},
            key_pair=ctx.responder_key,
            prev_hash=ctx.session.prev_hash,
            recipients=[AgentIdentity(agent_id=agent_a)],
        )
        ctx.session.apply_message(accept_msg, _resolver)

        # Generate receipt (attestation) — properly signed by both parties
        init_token, _ = _auth.register_session_tokens(
            session_id, agent_a, agent_b,
        )
        receipt_result = json.loads(tool_session_receipt(
            session_id=session_id, auth_token=init_token,
        ))
        return session_id, receipt_result["receipt"]

    def test_ingest_valid_attestation(self):
        from concordia.mcp_server import tool_register_agent, tool_ingest_attestation
        # Register an agent first to get auth_token
        reg_result = self._parse(tool_register_agent(agent_id="ingest_agent"))
        agent_id = "ingest_agent"
        auth_token = reg_result["auth_token"]

        # Create a real session and get a properly-signed receipt
        _, att = self._create_session_and_receipt("ingest_agent", "buyer_z")
        result = self._parse(tool_ingest_attestation(
            agent_id=agent_id,
            auth_token=auth_token,
            attestation=att,
        ))
        assert result["accepted"] is True
        assert result["store_count"] == 1

    def test_ingest_invalid_attestation(self):
        from concordia.mcp_server import tool_register_agent, tool_ingest_attestation
        # Register an agent first to get auth_token
        reg_result = self._parse(tool_register_agent(agent_id="ingest_agent2"))
        agent_id = "ingest_agent2"
        auth_token = reg_result["auth_token"]

        result = self._parse(tool_ingest_attestation(
            agent_id=agent_id,
            auth_token=auth_token,
            attestation={"bad": "data"},
        ))
        assert result["accepted"] is False
        assert len(result["errors"]) > 0

    def test_ingest_duplicate_rejected(self):
        from concordia.mcp_server import tool_register_agent, tool_ingest_attestation
        # Register an agent first to get auth_token
        reg_result = self._parse(tool_register_agent(agent_id="ingest_agent3"))
        agent_id = "ingest_agent3"
        auth_token = reg_result["auth_token"]

        _, att = self._create_session_and_receipt("ingest_agent3", "buyer_dup")
        tool_ingest_attestation(
            agent_id=agent_id,
            auth_token=auth_token,
            attestation=att,
        )

        # Try to ingest same attestation again (same att_id)
        result = self._parse(tool_ingest_attestation(
            agent_id=agent_id,
            auth_token=auth_token,
            attestation=att,
        ))
        assert result["accepted"] is False

    def test_reputation_query_no_data(self):
        from concordia.mcp_server import tool_reputation_query
        result = self._parse(tool_reputation_query(
            subject_agent_id="nobody",
            requester_agent_id="asker",
        ))
        assert result["type"] == RESPONSE_TYPE
        assert result["summary"] is None
        assert "no_data" in result["flags"]

    def test_reputation_query_with_data(self):
        from concordia.mcp_server import (
            tool_register_agent, tool_ingest_attestation, tool_reputation_query,
        )
        # Register agent first to get auth_token
        reg_result = self._parse(tool_register_agent(agent_id="seller_1"))
        agent_id = "seller_1"
        auth_token = reg_result["auth_token"]

        for _ in range(5):
            _, att = self._create_session_and_receipt("seller_1", "buyer_1")
            tool_ingest_attestation(
                agent_id=agent_id,
                auth_token=auth_token,
                attestation=att,
            )

        result = self._parse(tool_reputation_query(
            subject_agent_id="seller_1",
            requester_agent_id="buyer_1",
        ))
        assert result["type"] == RESPONSE_TYPE
        assert result["summary"] is not None
        assert result["summary"]["total_negotiations"] == 5

    def test_reputation_query_with_context(self):
        from concordia.mcp_server import (
            tool_register_agent, tool_ingest_attestation, tool_reputation_query,
        )
        # Register agent first to get auth_token
        reg_result = self._parse(tool_register_agent(agent_id="s"))
        agent_id = "s"
        auth_token = reg_result["auth_token"]

        for _ in range(5):
            _, att = self._create_session_and_receipt("s", "b")
            tool_ingest_attestation(
                agent_id=agent_id,
                auth_token=auth_token,
                attestation=att,
            )
        for _ in range(3):
            _, att = self._create_session_and_receipt("s", "b")
            tool_ingest_attestation(
                agent_id=agent_id,
                auth_token=auth_token,
                attestation=att,
            )

        result = self._parse(tool_reputation_query(
            subject_agent_id="s",
            requester_agent_id="b",
            category="electronics",
        ))
        assert "context_specific" in result

    def test_reputation_score_no_data(self):
        from concordia.mcp_server import tool_reputation_score
        result = self._parse(tool_reputation_score(agent_id="nobody"))
        assert result["score"] is None

    def test_reputation_score_with_data(self):
        from concordia.mcp_server import (
            tool_register_agent, tool_ingest_attestation, tool_reputation_score,
        )
        # Register agent first to get auth_token
        reg_result = self._parse(tool_register_agent(agent_id="scored_agent"))
        agent_id = "scored_agent"
        auth_token = reg_result["auth_token"]

        for _ in range(10):
            _, att = self._create_session_and_receipt("scored_agent", "counterparty")
            tool_ingest_attestation(
                agent_id=agent_id,
                auth_token=auth_token,
                attestation=att,
            )

        result = self._parse(tool_reputation_score(agent_id="scored_agent"))
        assert result["score"] is not None
        assert "overall_score" in result["score"]
        assert "components" in result["score"]

    def test_handle_tool_call_reputation(self):
        from concordia.mcp_server import (
            handle_tool_call, tool_register_agent, tool_ingest_attestation,
        )
        # Register agent first to get auth_token
        reg_result = self._parse(tool_register_agent(agent_id="htc_seller"))
        agent_id = "htc_seller"
        auth_token = reg_result["auth_token"]

        # Ingest some data first
        for _ in range(5):
            _, att = self._create_session_and_receipt("htc_seller", "htc_buyer")
            tool_ingest_attestation(
                agent_id=agent_id,
                auth_token=auth_token,
                attestation=att,
            )

        # Test via handle_tool_call
        result = handle_tool_call("concordia_reputation_score", {
            "agent_id": "htc_seller",
        })
        assert "error" not in result
        assert result["score"] is not None

    def test_handle_tool_call_query(self):
        from concordia.mcp_server import (
            handle_tool_call, tool_register_agent, tool_ingest_attestation,
        )
        # Register agent first to get auth_token
        reg_result = self._parse(tool_register_agent(agent_id="q_seller"))
        agent_id = "q_seller"
        auth_token = reg_result["auth_token"]

        for _ in range(5):
            _, att = self._create_session_and_receipt("q_seller", "q_buyer")
            tool_ingest_attestation(
                agent_id=agent_id,
                auth_token=auth_token,
                attestation=att,
            )

        result = handle_tool_call("concordia_reputation_query", {
            "subject_agent_id": "q_seller",
            "requester_agent_id": "q_buyer",
        })
        assert result["type"] == RESPONSE_TYPE
        assert result["summary"]["total_negotiations"] == 5

    def test_full_lifecycle_negotiate_then_score(self):
        """End-to-end: open session, negotiate, generate receipt, ingest, score."""
        from concordia.mcp_server import handle_tool_call

        # Register both agents first to get auth_tokens
        seller_reg = handle_tool_call("concordia_register_agent", {
            "agent_id": "seller_e2e",
        })
        seller_token = seller_reg["auth_token"]

        buyer_reg = handle_tool_call("concordia_register_agent", {
            "agent_id": "buyer_e2e",
        })
        buyer_token = buyer_reg["auth_token"]

        # Open a session
        open_result = handle_tool_call("concordia_open_session", {
            "initiator_id": "seller_e2e",
            "responder_id": "buyer_e2e",
            "terms": {
                "price": {"type": "number", "label": "Price (USD)"},
            },
        })
        session_id = open_result["session_id"]
        initiator_token = open_result["initiator_token"]
        responder_token = open_result["responder_token"]

        # Propose
        handle_tool_call("concordia_propose", {
            "session_id": session_id,
            "role": "initiator",
            "auth_token": initiator_token,
            "terms": {"price": {"value": 1000}},
            "reasoning": "Starting high",
        })

        # Counter
        handle_tool_call("concordia_counter", {
            "session_id": session_id,
            "role": "responder",
            "auth_token": responder_token,
            "terms": {"price": {"value": 850}},
            "reasoning": "Meeting in the middle",
        })

        # Accept
        handle_tool_call("concordia_accept", {
            "session_id": session_id,
            "role": "initiator",
            "auth_token": initiator_token,
            "reasoning": "Deal accepted",
        })

        # Generate receipt
        receipt_result = handle_tool_call("concordia_session_receipt", {
            "session_id": session_id,
            "auth_token": initiator_token,
            "category": "electronics",
            "value_range": "500-1500_USD",
        })
        assert "receipt" in receipt_result
        attestation = receipt_result["receipt"]

        # Ingest
        ingest_result = handle_tool_call("concordia_ingest_attestation", {
            "agent_id": "seller_e2e",
            "auth_token": seller_token,
            "attestation": attestation,
        })
        assert ingest_result["accepted"] is True

        # Score
        score_result = handle_tool_call("concordia_reputation_score", {
            "agent_id": "seller_e2e",
        })
        assert score_result["score"] is not None
        assert score_result["score"]["total_negotiations"] == 1

        # Query
        query_result = handle_tool_call("concordia_reputation_query", {
            "subject_agent_id": "seller_e2e",
            "requester_agent_id": "buyer_e2e",
            "category": "electronics",
        })
        assert query_result["type"] == RESPONSE_TYPE
        assert query_result["summary"] is not None
