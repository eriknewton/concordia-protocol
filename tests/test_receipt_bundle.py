"""Tests for portable receipt bundles.

Covers:
    - Bundle creation from valid attestations
    - Bundle signature verification (valid, tampered, wrong key)
    - Summary accuracy (computed stats match attestation data)
    - Sybil screening (low diversity, symmetric patterns, self-dealing)
    - Round-trip serialization (create -> export -> import -> verify)
    - Edge cases: empty bundle, single attestation, mixed outcomes
    - MCP tool integration tests through handle_tool_call
    - Agent can only bundle attestations where it appears as a party
    - Freshness: bundles older than a configurable threshold get flagged
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from concordia.receipt_bundle import (
    BundleSummary,
    BundleStore,
    ReceiptBundle,
    verify_bundle,
    screen_bundle,
    check_freshness,
    _compute_summary,
)
from concordia.signing import KeyPair, sign_message


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_KEY_REGISTRY: dict[str, KeyPair] = {}


def _get_key(agent_id: str) -> KeyPair:
    if agent_id not in _KEY_REGISTRY:
        _KEY_REGISTRY[agent_id] = KeyPair.generate()
    return _KEY_REGISTRY[agent_id]


def _test_resolver(agent_id: str) -> Ed25519PublicKey | None:
    kp = _KEY_REGISTRY.get(agent_id)
    return kp.public_key if kp else None


def _make_attestation(
    agent_a: str = "agent_a",
    agent_b: str = "agent_b",
    status: str = "agreed",
    rounds: int = 3,
    duration_seconds: int = 120,
    category: str = "electronics",
    concession_a: float = 0.2,
    concession_b: float = 0.15,
    offers_a: int = 2,
    offers_b: int = 3,
    reasoning_a: bool = True,
    reasoning_b: bool = False,
    fulfillment: dict | None = None,
    att_id: str | None = None,
    session_id: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Create a valid, signed attestation for testing."""
    att_id = att_id or f"att_{uuid.uuid4().hex[:12]}"
    session_id = session_id or f"sess_{uuid.uuid4().hex[:12]}"
    timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    party_a: dict[str, Any] = {
        "agent_id": agent_a,
        "role": "seller",
        "behavior": {
            "concession_magnitude": concession_a,
            "offers_made": offers_a,
            "reasoning_provided": reasoning_a,
            "responsiveness_seconds": 5.0,
        },
    }
    party_a["signature"] = sign_message(party_a, _get_key(agent_a))

    party_b: dict[str, Any] = {
        "agent_id": agent_b,
        "role": "buyer",
        "behavior": {
            "concession_magnitude": concession_b,
            "offers_made": offers_b,
            "reasoning_provided": reasoning_b,
            "responsiveness_seconds": 8.0,
        },
    }
    party_b["signature"] = sign_message(party_b, _get_key(agent_b))

    att: dict[str, Any] = {
        "concordia_attestation": "0.1.0",
        "attestation_id": att_id,
        "session_id": session_id,
        "timestamp": timestamp,
        "outcome": {
            "status": status,
            "rounds": rounds,
            "duration_seconds": duration_seconds,
        },
        "parties": [party_a, party_b],
        "meta": {"category": category, "extensions_used": [], "mediator_invoked": False},
        "transcript_hash": f"sha256:{uuid.uuid4().hex}",
        "fulfillment": fulfillment,
    }
    return att


# ---------------------------------------------------------------------------
# Bundle creation
# ---------------------------------------------------------------------------


class TestBundleCreation:

    def test_create_basic(self):
        """Create a bundle from valid attestations."""
        atts = [_make_attestation() for _ in range(3)]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)

        assert bundle.bundle_id.startswith("bundle_")
        assert bundle.agent_id == "agent_a"
        assert len(bundle.attestations) == 3
        assert bundle.agent_signature

    def test_create_single_attestation(self):
        """A single-attestation bundle is valid."""
        att = _make_attestation()
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", [att], kp)
        assert bundle.summary.total_negotiations == 1

    def test_create_rejects_non_party(self):
        """Cannot bundle attestations where the agent is not a party."""
        att = _make_attestation(agent_a="agent_x", agent_b="agent_y")
        kp = _get_key("agent_z")
        with pytest.raises(ValueError, match="not a party"):
            ReceiptBundle.create("agent_z", [att], kp)

    def test_create_mixed_outcomes(self):
        """Bundle can include both agreed and rejected sessions."""
        agreed = _make_attestation(status="agreed")
        rejected = _make_attestation(status="rejected")
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", [agreed, rejected], kp)
        assert bundle.summary.total_negotiations == 2
        assert bundle.summary.agreements == 1
        assert bundle.summary.agreement_rate == 0.5


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


class TestBundleSignature:

    def test_valid_signature(self):
        """A properly signed bundle passes verification."""
        atts = [_make_attestation() for _ in range(2)]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        result = verify_bundle(bundle.to_dict(), _test_resolver)
        assert result.valid, f"Errors: {result.errors}"

    def test_tampered_bundle(self):
        """Tampering with the bundle invalidates the signature."""
        atts = [_make_attestation() for _ in range(2)]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        d = bundle.to_dict()
        d["agent_id"] = "agent_evil"
        result = verify_bundle(d, _test_resolver)
        assert not result.valid

    def test_wrong_key(self):
        """Verifying with a different agent's key fails."""
        atts = [_make_attestation()]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        d = bundle.to_dict()

        other_key = KeyPair.generate()

        def bad_resolver(aid: str) -> Ed25519PublicKey | None:
            if aid == "agent_a":
                return other_key.public_key
            return _test_resolver(aid)

        result = verify_bundle(d, bad_resolver)
        assert not result.valid
        assert any("signature verification failed" in e.lower() for e in result.errors)

    def test_tampered_attestation_party_signature(self):
        """Tampering with a party's behavior invalidates attestation signature."""
        atts = [_make_attestation()]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        d = bundle.to_dict()
        # Tamper with the party behavior inside the attestation
        d["attestations"][0]["parties"][0]["behavior"]["concession_magnitude"] = 999.0
        # Re-sign the bundle (so bundle sig is valid but attestation sig is bad)
        signable = {k: v for k, v in d.items() if k not in ("agent_signature", "concordia_receipt_bundle")}
        d["agent_signature"] = sign_message(signable, kp)

        result = verify_bundle(d, _test_resolver)
        assert not result.valid
        assert any("invalid signature" in e.lower() for e in result.errors)


# ---------------------------------------------------------------------------
# Summary accuracy
# ---------------------------------------------------------------------------


class TestSummaryAccuracy:

    def test_summary_matches_attestations(self):
        """Summary stats match the actual attestation data."""
        atts = [
            _make_attestation(status="agreed", category="electronics", concession_a=0.2, reasoning_a=True),
            _make_attestation(status="agreed", category="furniture", concession_a=0.3, reasoning_a=True),
            _make_attestation(status="rejected", category="electronics", concession_a=0.1, reasoning_a=False),
        ]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)

        assert bundle.summary.total_negotiations == 3
        assert bundle.summary.agreements == 2
        assert abs(bundle.summary.agreement_rate - 2 / 3) < 0.01
        assert bundle.summary.unique_counterparties == 1  # all with agent_b
        assert sorted(bundle.summary.categories) == ["electronics", "furniture"]

    def test_inflated_summary_detected(self):
        """Verification catches inflated summary claims."""
        atts = [_make_attestation(status="rejected")]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        d = bundle.to_dict()
        # Inflate the summary
        d["summary"]["agreements"] = 100
        d["summary"]["agreement_rate"] = 1.0
        # Re-sign
        signable = {k: v for k, v in d.items() if k not in ("agent_signature", "concordia_receipt_bundle")}
        d["agent_signature"] = sign_message(signable, kp)

        result = verify_bundle(d, _test_resolver)
        assert not result.valid
        assert not result.summary_accurate

    def test_concession_magnitude_accuracy(self):
        """Average concession magnitude is accurately computed."""
        atts = [
            _make_attestation(concession_a=0.1),
            _make_attestation(concession_a=0.3),
            _make_attestation(concession_a=0.5),
        ]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        assert abs(bundle.summary.avg_concession_magnitude - 0.3) < 0.001

    def test_fulfillment_rate_accuracy(self):
        """Fulfillment rate reflects actual fulfillment data."""
        atts = [
            _make_attestation(fulfillment={"status": "fulfilled"}),
            _make_attestation(fulfillment={"status": "fulfilled"}),
            _make_attestation(fulfillment={"status": "unfulfilled"}),
            _make_attestation(fulfillment=None),  # no fulfillment data
        ]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        # 2 fulfilled out of 3 that have fulfillment data
        assert abs(bundle.summary.fulfillment_rate - 2 / 3) < 0.01

    def test_reasoning_rate_accuracy(self):
        """Reasoning rate correctly reflects party behavior."""
        atts = [
            _make_attestation(reasoning_a=True),
            _make_attestation(reasoning_a=True),
            _make_attestation(reasoning_a=False),
        ]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        assert abs(bundle.summary.reasoning_rate - 2 / 3) < 0.01


# ---------------------------------------------------------------------------
# Sybil screening
# ---------------------------------------------------------------------------


class TestSybilScreening:

    def test_self_dealing_detected(self):
        """Bundles with self-dealing attestations are flagged."""
        att = _make_attestation(agent_a="agent_x", agent_b="agent_x")
        kp = _get_key("agent_x")
        bundle = ReceiptBundle.create("agent_x", [att], kp)
        flags = screen_bundle(bundle.to_dict())
        assert flags["self_dealing"]
        assert flags["flagged"]

    def test_low_diversity_detected(self):
        """More than 3 sessions with only 1 counterparty is flagged."""
        atts = [_make_attestation() for _ in range(5)]  # all with agent_b
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        flags = screen_bundle(bundle.to_dict())
        assert flags["low_counterparty_diversity"]
        assert flags["flagged"]

    def test_timing_anomaly_detected(self):
        """Majority of suspiciously fast sessions are flagged."""
        atts = [
            _make_attestation(duration_seconds=2),
            _make_attestation(duration_seconds=3),
            _make_attestation(duration_seconds=1),
            _make_attestation(duration_seconds=120),
        ]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        flags = screen_bundle(bundle.to_dict())
        assert flags["timing_anomaly"]

    def test_symmetric_concessions_detected(self):
        """Symmetric concession patterns across sessions are flagged."""
        atts = [
            _make_attestation(concession_a=0.5, concession_b=0.5),
            _make_attestation(concession_a=0.5, concession_b=0.5),
            _make_attestation(concession_a=0.5, concession_b=0.5),
        ]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        flags = screen_bundle(bundle.to_dict())
        assert flags["symmetric_concessions"]

    def test_healthy_bundle_not_flagged(self):
        """A diverse, normally-timed bundle is not flagged."""
        atts = [
            _make_attestation(agent_b="b1", concession_a=0.1, concession_b=0.2, duration_seconds=60),
            _make_attestation(agent_b="b2", concession_a=0.3, concession_b=0.1, duration_seconds=120),
            _make_attestation(agent_b="b3", concession_a=0.2, concession_b=0.3, duration_seconds=90),
        ]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        flags = screen_bundle(bundle.to_dict())
        assert not flags["flagged"]

    def test_empty_bundle_not_flagged(self):
        """Empty attestation list produces no flags."""
        flags = screen_bundle({"agent_id": "x", "attestations": []})
        assert not flags["flagged"]

    def test_sybil_screening_in_verification(self):
        """Sybil flags appear in the verification result."""
        atts = [_make_attestation(duration_seconds=1) for _ in range(4)]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        result = verify_bundle(bundle.to_dict(), _test_resolver)
        assert result.sybil_flags["timing_anomaly"]


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------


class TestSerialization:

    def test_round_trip_dict(self):
        """Create -> to_dict -> from_dict preserves all data."""
        atts = [_make_attestation()]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)

        d = bundle.to_dict()
        restored = ReceiptBundle.from_dict(d)

        assert restored.bundle_id == bundle.bundle_id
        assert restored.agent_id == bundle.agent_id
        assert restored.created_at == bundle.created_at
        assert restored.agent_signature == bundle.agent_signature
        assert len(restored.attestations) == len(bundle.attestations)
        assert restored.summary.total_negotiations == bundle.summary.total_negotiations

    def test_round_trip_json(self):
        """Create -> to_json -> parse -> verify works."""
        atts = [_make_attestation()]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)

        json_str = bundle.to_json()
        parsed = json.loads(json_str)
        result = verify_bundle(parsed, _test_resolver)
        assert result.valid, f"Errors: {result.errors}"

    def test_to_dict_includes_version(self):
        """to_dict includes the schema version marker."""
        atts = [_make_attestation()]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        d = bundle.to_dict()
        assert d["concordia_receipt_bundle"] == "0.1.0"

    def test_round_trip_verify(self):
        """Create -> export -> import -> verify passes verification."""
        atts = [_make_attestation() for _ in range(3)]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)

        # Export to JSON, parse, verify
        exported = json.loads(bundle.to_json())
        result = verify_bundle(exported, _test_resolver)
        assert result.valid
        assert result.summary_accurate


# ---------------------------------------------------------------------------
# Verification edge cases
# ---------------------------------------------------------------------------


class TestVerificationEdgeCases:

    def test_missing_required_field(self):
        """Missing required field causes verification failure."""
        d = {"agent_id": "a", "attestations": []}  # missing other fields
        result = verify_bundle(d, _test_resolver)
        assert not result.valid

    def test_duplicate_attestation_ids(self):
        """Duplicate attestation_ids are caught."""
        att1 = _make_attestation(att_id="att_dupe")
        att2 = _make_attestation(att_id="att_dupe")
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", [att1, att2], kp)
        d = bundle.to_dict()
        result = verify_bundle(d, _test_resolver)
        assert not result.valid
        assert any("duplicate" in e.lower() for e in result.errors)

    def test_duplicate_session_ids(self):
        """Duplicate session_ids are caught."""
        att1 = _make_attestation(session_id="sess_dupe")
        att2 = _make_attestation(session_id="sess_dupe")
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", [att1, att2], kp)
        d = bundle.to_dict()
        result = verify_bundle(d, _test_resolver)
        assert not result.valid
        assert any("duplicate" in e.lower() for e in result.errors)

    def test_unknown_party_key_warning(self):
        """Unknown party key produces a warning, not an error."""
        att = _make_attestation(agent_b="unknown_agent")
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", [att], kp)
        d = bundle.to_dict()

        def partial_resolver(aid: str) -> Ed25519PublicKey | None:
            if aid == "unknown_agent":
                return None
            return _test_resolver(aid)

        result = verify_bundle(d, partial_resolver)
        # Still valid (unknown key is a warning), but bundle sig check must pass
        assert any("cannot resolve key" in w.lower() for w in result.warnings)

    def test_unresolvable_bundle_agent_key(self):
        """Cannot verify if the bundle agent's key is unknown."""
        att = _make_attestation()
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", [att], kp)
        d = bundle.to_dict()

        def no_resolver(aid: str) -> Ed25519PublicKey | None:
            return None

        result = verify_bundle(d, no_resolver)
        assert not result.valid
        assert any("cannot resolve" in e.lower() for e in result.errors)


# ---------------------------------------------------------------------------
# Freshness
# ---------------------------------------------------------------------------


class TestFreshness:

    def test_fresh_bundle(self):
        """A just-created bundle is fresh."""
        atts = [_make_attestation()]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        is_fresh, msg = check_freshness(bundle.to_dict())
        assert is_fresh

    def test_stale_bundle(self):
        """A bundle older than the threshold is flagged."""
        atts = [_make_attestation()]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        d = bundle.to_dict()
        # Set created_at to 60 days ago
        old_time = (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        d["created_at"] = old_time
        is_fresh, msg = check_freshness(d, max_age_hours=720)
        assert not is_fresh

    def test_custom_freshness_threshold(self):
        """Custom freshness threshold works."""
        atts = [_make_attestation()]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        d = bundle.to_dict()
        # Set to 2 hours ago
        old_time = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        d["created_at"] = old_time
        is_fresh, _ = check_freshness(d, max_age_hours=1)
        assert not is_fresh
        is_fresh, _ = check_freshness(d, max_age_hours=5)
        assert is_fresh

    def test_missing_created_at(self):
        """Missing created_at is not fresh."""
        is_fresh, msg = check_freshness({"created_at": ""})
        assert not is_fresh


# ---------------------------------------------------------------------------
# BundleStore
# ---------------------------------------------------------------------------


class TestBundleStore:

    def test_store_and_retrieve(self):
        """Store a bundle and retrieve it."""
        store = BundleStore()
        atts = [_make_attestation()]
        kp = _get_key("agent_a")
        bundle = ReceiptBundle.create("agent_a", atts, kp)
        store.store(bundle)

        assert store.count() == 1
        retrieved = store.get(bundle.bundle_id)
        assert retrieved is not None
        assert retrieved["bundle_id"] == bundle.bundle_id

    def test_list_by_agent(self):
        """List bundles by agent."""
        store = BundleStore()
        kp = _get_key("agent_a")
        for _ in range(3):
            bundle = ReceiptBundle.create("agent_a", [_make_attestation()], kp)
            store.store(bundle)

        bundles = store.list_by_agent("agent_a")
        assert len(bundles) == 3

    def test_list_empty(self):
        """Empty store returns empty list."""
        store = BundleStore()
        assert store.list_by_agent("nobody") == []


# ---------------------------------------------------------------------------
# BundleSummary
# ---------------------------------------------------------------------------


class TestBundleSummary:

    def test_empty_attestations(self):
        """Empty attestation list produces zero summary."""
        summary = _compute_summary("agent_a", [])
        assert summary.total_negotiations == 0
        assert summary.agreements == 0
        assert summary.agreement_rate == 0.0

    def test_multiple_counterparties(self):
        """Unique counterparty count is accurate."""
        atts = [
            _make_attestation(agent_b="b1"),
            _make_attestation(agent_b="b2"),
            _make_attestation(agent_b="b3"),
            _make_attestation(agent_b="b1"),  # repeat
        ]
        summary = _compute_summary("agent_a", atts)
        assert summary.unique_counterparties == 3

    def test_summary_to_dict_from_dict(self):
        """Summary round-trips through dict serialization."""
        original = BundleSummary(
            total_negotiations=5,
            agreements=3,
            agreement_rate=0.6,
            avg_concession_magnitude=0.25,
            fulfillment_rate=0.8,
            unique_counterparties=4,
            categories=["electronics", "furniture"],
            earliest="2026-01-01T00:00:00Z",
            latest="2026-03-01T00:00:00Z",
            reasoning_rate=0.6,
        )
        d = original.to_dict()
        restored = BundleSummary.from_dict(d)
        assert restored.total_negotiations == original.total_negotiations
        assert restored.categories == original.categories


# ---------------------------------------------------------------------------
# MCP tool integration
# ---------------------------------------------------------------------------


class TestMcpToolIntegration:

    def _setup_negotiation(self):
        """Run a complete negotiation and return context for bundle testing."""
        from concordia.mcp_server import handle_tool_call, _store, _auth, _attestation_store, _key_registry, _bundle_store

        # Reset state
        _store._sessions.clear()
        _auth._agent_tokens.clear()
        _auth._token_to_agent.clear()
        _auth._session_tokens.clear()
        _attestation_store._by_id.clear()
        _attestation_store._by_session.clear()
        _attestation_store._by_agent.clear()
        _attestation_store._counterparties.clear()
        _key_registry.clear()
        _bundle_store._bundles.clear()
        _bundle_store._by_agent.clear()

        # Open a session
        result = handle_tool_call("concordia_open_session", {
            "initiator_id": "seller_01",
            "responder_id": "buyer_01",
            "terms": {"price": {"type": "numeric", "label": "Price USD"}},
        })
        session_id = result["session_id"]
        init_token = result["initiator_token"]
        resp_token = result["responder_token"]

        # Negotiate
        handle_tool_call("concordia_propose", {
            "session_id": session_id, "role": "initiator",
            "terms": {"price": {"value": 1000}},
            "auth_token": init_token,
        })
        handle_tool_call("concordia_accept", {
            "session_id": session_id, "role": "responder",
            "auth_token": resp_token,
        })

        # Generate receipt
        receipt = handle_tool_call("concordia_session_receipt", {
            "session_id": session_id,
            "auth_token": init_token,
        })
        attestation = receipt["receipt"]

        # Register agent token for seller (needed for agent-scoped tools)
        from concordia.mcp_server import _auth
        agent_token = _auth.register_agent_token("seller_01")

        # Ingest attestation (requires agent-scoped auth)
        ingest_result = handle_tool_call("concordia_ingest_attestation", {
            "agent_id": "seller_01",
            "attestation": attestation,
            "auth_token": agent_token,
        })
        assert ingest_result.get("accepted", False), f"Ingest failed: {ingest_result}"

        return {
            "session_id": session_id,
            "init_token": init_token,
            "resp_token": resp_token,
            "agent_token": agent_token,
            "attestation": attestation,
        }

    def test_create_bundle_via_tool(self):
        """Create a receipt bundle through the MCP tool."""
        from concordia.mcp_server import handle_tool_call
        ctx = self._setup_negotiation()

        result = handle_tool_call("concordia_create_receipt_bundle", {
            "agent_id": "seller_01",
            "auth_token": ctx["agent_token"],
        })
        assert "error" not in result, f"Error: {result}"
        assert result["bundle_id"].startswith("bundle_")
        assert len(result["attestations"]) == 1

    def test_list_bundles_via_tool(self):
        """List receipt bundles through the MCP tool."""
        from concordia.mcp_server import handle_tool_call
        ctx = self._setup_negotiation()

        handle_tool_call("concordia_create_receipt_bundle", {
            "agent_id": "seller_01",
            "auth_token": ctx["agent_token"],
        })

        result = handle_tool_call("concordia_list_receipt_bundles", {
            "agent_id": "seller_01",
            "auth_token": ctx["agent_token"],
        })
        assert result["bundle_count"] == 1

    def test_verify_bundle_via_tool(self):
        """Verify a receipt bundle through the MCP tool."""
        from concordia.mcp_server import handle_tool_call
        ctx = self._setup_negotiation()

        bundle_result = handle_tool_call("concordia_create_receipt_bundle", {
            "agent_id": "seller_01",
            "auth_token": ctx["agent_token"],
        })
        assert "error" not in bundle_result, f"Error: {bundle_result}"

        # Build a clean bundle dict for verification (remove non-schema fields)
        bundle_dict = {
            "concordia_receipt_bundle": bundle_result["concordia_receipt_bundle"],
            "bundle_id": bundle_result["bundle_id"],
            "agent_id": bundle_result["agent_id"],
            "created_at": bundle_result["created_at"],
            "attestations": bundle_result["attestations"],
            "summary": bundle_result["summary"],
            "agent_signature": bundle_result["agent_signature"],
        }

        verify_result = handle_tool_call("concordia_verify_receipt_bundle", {
            "bundle": bundle_dict,
        })
        assert verify_result["valid"], f"Errors: {verify_result.get('errors')}"

    def test_create_bundle_auth_required(self):
        """Bundle creation requires valid auth token."""
        from concordia.mcp_server import handle_tool_call
        ctx = self._setup_negotiation()

        result = handle_tool_call("concordia_create_receipt_bundle", {
            "agent_id": "seller_01",
            "auth_token": "bad_token",
        })
        assert "error" in result

    def test_list_bundles_auth_required(self):
        """Bundle listing requires valid auth token."""
        from concordia.mcp_server import handle_tool_call
        ctx = self._setup_negotiation()

        result = handle_tool_call("concordia_list_receipt_bundles", {
            "agent_id": "seller_01",
            "auth_token": "bad_token",
        })
        assert "error" in result
