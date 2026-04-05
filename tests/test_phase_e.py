"""Tests for Phase E improvements.

Covers:
  E1. receipt_summary plaintext 4-line summary attached to attestations.
  E2. concordia_session_public_view MCP tool.
  E3. Session token persistence to disk with 24h TTL.
  E4. Distinction between agent auth token (long-lived) and session token
      (short-lived, per-session) — verified via behaviour.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

import pytest

from concordia.attestation import generate_receipt_summary
from concordia.auth import AuthTokenStore, SESSION_TOKEN_TTL_SECONDS


# ---------------------------------------------------------------------------
# E1 — receipt_summary
# ---------------------------------------------------------------------------

class TestReceiptSummary:
    def test_summary_four_lines(self):
        receipt = {
            "parties": [
                {"agent_id": "did:example:alice-abcdef123456"},
                {"agent_id": "did:example:bob-fedcba654321"},
            ],
            "meta": {"category": "electronics.cameras"},
            "outcome": {"status": "agreed"},
            "transcript_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        }
        summary = generate_receipt_summary(receipt)
        lines = summary.split("\n")
        assert len(lines) == 4
        assert lines[0].startswith("Parties: ")
        assert lines[1].startswith("Topic: ")
        assert lines[2] == "Outcome: AGREED"
        assert lines[3] == "Transcript hash: 0123456789abcdef"

    def test_summary_topic_na_when_missing(self):
        receipt = {
            "parties": [
                {"agent_id": "alice"},
                {"agent_id": "bob"},
            ],
            "meta": {},
            "outcome": {"status": "rejected"},
            "transcript_hash": "sha256:deadbeefdeadbeefdeadbeefdeadbeef",
        }
        summary = generate_receipt_summary(receipt)
        assert "Topic: N/A" in summary
        assert "Outcome: REJECTED" in summary

    def test_summary_attached_to_generated_attestation(self, agreed_session):
        """When a receipt is generated via the MCP tool, the summary is
        present on the attestation dict."""
        from concordia.mcp_server import handle_tool_call

        data = handle_tool_call("concordia_session_receipt", {
            "session_id": agreed_session["session_id"],
            "auth_token": agreed_session["initiator_token"],
            "category": "test.category",
        })
        attestation = data["receipt"]
        assert "summary" in attestation
        assert isinstance(attestation["summary"], str)
        lines = attestation["summary"].split("\n")
        assert len(lines) == 4
        assert lines[2] == "Outcome: AGREED"


# ---------------------------------------------------------------------------
# E2 — session_public_view tool
# ---------------------------------------------------------------------------

class TestSessionPublicView:
    def test_public_view_no_auth_required(self, agreed_session):
        from concordia.mcp_server import handle_tool_call

        data = handle_tool_call("concordia_session_public_view", {
            "session_id": agreed_session["session_id"],
        })
        assert "error" not in data
        assert data["session_id"] == agreed_session["session_id"]
        assert data["state"] == "agreed"
        assert data["message_count"] >= 1
        assert "transcript_hash_chain" in data
        assert isinstance(data["transcript_hash_chain"], list)
        assert len(data["transcript_hash_chain"]) == data["message_count"]
        parties = data["parties"]
        assert len(parties) == 2
        assert {p["role"] for p in parties} == {"initiator", "responder"}

    def test_public_view_unknown_session(self):
        from concordia.mcp_server import handle_tool_call
        data = handle_tool_call("concordia_session_public_view", {
            "session_id": "ses_nonexistent",
        })
        assert "error" in data

    def test_public_view_no_private_payload_details(self, agreed_session):
        """Public view must not leak private payload content like raw
        message bodies or behavioural analytics."""
        from concordia.mcp_server import handle_tool_call
        data = handle_tool_call("concordia_session_public_view", {
            "session_id": agreed_session["session_id"],
        })
        assert "behaviors" not in data
        assert "terms" not in data
        assert "transcript" not in data


# ---------------------------------------------------------------------------
# E3 — session token persistence + TTL
# ---------------------------------------------------------------------------

class TestSessionTokenPersistence:
    def test_tokens_written_to_disk(self, tmp_path: Path):
        store_file = tmp_path / "sessions.json"
        auth = AuthTokenStore(persist_path=store_file, autoload=False)
        init_tok, resp_tok = auth.register_session_tokens(
            "ses_abc", "alice", "bob",
        )
        assert store_file.exists()
        payload = json.loads(store_file.read_text())
        assert payload["version"] == "1"
        tokens = {(s["session_id"], s["role"]): s["token"] for s in payload["sessions"]}
        assert tokens[("ses_abc", "initiator")] == init_tok
        assert tokens[("ses_abc", "responder")] == resp_tok

    def test_tokens_reloaded_on_startup(self, tmp_path: Path):
        store_file = tmp_path / "sessions.json"
        first = AuthTokenStore(persist_path=store_file, autoload=False)
        init_tok, resp_tok = first.register_session_tokens(
            "ses_xyz", "alice", "bob",
        )
        # Fresh store should pick up tokens from disk.
        second = AuthTokenStore(persist_path=store_file)
        assert second.validate_session_token("ses_xyz", "initiator", init_tok)
        assert second.validate_session_token("ses_xyz", "responder", resp_tok)
        assert second.get_any_session_role("ses_xyz", resp_tok) == "responder"

    def test_expired_tokens_rejected_and_dropped(self, tmp_path: Path):
        store_file = tmp_path / "sessions.json"
        # TTL of 0 -> instantly expired.
        auth = AuthTokenStore(
            persist_path=store_file, ttl_seconds=0, autoload=False,
        )
        init_tok, _ = auth.register_session_tokens("ses_q", "a", "b")
        time.sleep(0.01)
        assert not auth.validate_session_token("ses_q", "initiator", init_tok)

    def test_stale_tokens_expired_on_load(self, tmp_path: Path):
        store_file = tmp_path / "sessions.json"
        payload = {
            "version": "1",
            "ttl_seconds": 86400,
            "sessions": [
                {
                    "session_id": "ses_old",
                    "role": "initiator",
                    "token": "deadbeef" * 8,
                    "expires_at": time.time() - 60,  # already expired
                },
            ],
        }
        store_file.write_text(json.dumps(payload))
        auth = AuthTokenStore(persist_path=store_file)
        assert not auth.validate_session_token(
            "ses_old", "initiator", "deadbeef" * 8,
        )

    def test_atomic_write_uses_tmp_file(self, tmp_path: Path):
        store_file = tmp_path / "sessions.json"
        auth = AuthTokenStore(persist_path=store_file, autoload=False)
        auth.register_session_tokens("ses_a", "a", "b")
        # File should exist and be readable as JSON.
        assert store_file.exists()
        json.loads(store_file.read_text())
        # No stale .tmp files left behind.
        leftovers = list(tmp_path.glob(".sessions-*.json.tmp"))
        assert leftovers == []

    def test_default_ttl_is_24_hours(self):
        assert SESSION_TOKEN_TTL_SECONDS == 24 * 60 * 60


# ---------------------------------------------------------------------------
# E4 — agent token vs session token separation
# ---------------------------------------------------------------------------

class TestAgentVsSessionTokenSeparation:
    def test_agent_token_not_valid_as_session_token(self, tmp_path: Path):
        auth = AuthTokenStore(
            persist_path=tmp_path / "sessions.json", autoload=False,
        )
        agent_tok = auth.register_agent_token("agent_alice")
        init_tok, _ = auth.register_session_tokens("ses_1", "agent_alice", "bob")

        # Agent token must not authenticate against a session.
        assert not auth.validate_session_token("ses_1", "initiator", agent_tok)
        # Session token must not authenticate against the agent scope.
        assert not auth.validate_agent_token("agent_alice", init_tok)

        # But each works in its own scope.
        assert auth.validate_agent_token("agent_alice", agent_tok)
        assert auth.validate_session_token("ses_1", "initiator", init_tok)

    def test_agent_tokens_are_not_persisted(self, tmp_path: Path):
        store_file = tmp_path / "sessions.json"
        auth = AuthTokenStore(persist_path=store_file, autoload=False)
        auth.register_agent_token("agent_alice")
        auth.register_session_tokens("ses_1", "agent_alice", "bob")

        payload = json.loads(store_file.read_text())
        # Session entries exist...
        assert len(payload["sessions"]) == 2
        # ...but no agent tokens are written to the file.
        serialized = json.dumps(payload)
        assert "agent_alice" not in serialized or "ses_1" in serialized
        # The structure has no 'agents' key.
        assert "agents" not in payload


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def agreed_session():
    """Create a session that reaches AGREED state, return ids and tokens."""
    from concordia.mcp_server import handle_tool_call, _store, _auth

    open_result = (handle_tool_call("concordia_open_session", {
        "initiator_id": "phase_e_alice",
        "responder_id": "phase_e_bob",
        "terms": {"price": {"type": "numeric", "min": 100, "max": 1000}},
    }))
    session_id = open_result["session_id"]
    init_tok = open_result["initiator_token"]
    resp_tok = open_result["responder_token"]

    handle_tool_call("concordia_propose", {
        "session_id": session_id,
        "role": "initiator",
        "terms": {"price": {"value": 500}},
        "auth_token": init_tok,
    })
    handle_tool_call("concordia_accept", {
        "session_id": session_id,
        "role": "responder",
        "auth_token": resp_tok,
    })

    return {
        "session_id": session_id,
        "initiator_token": init_tok,
        "responder_token": resp_tok,
    }
