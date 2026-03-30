"""Tests for the Negotiation Relay — message routing and session management.

Covers:
    - RelaySession lifecycle: create, join, conclude, timeout, archive
    - Message routing: send, receive (store-and-forward), delivery status
    - Transcript retrieval and archival
    - Participant tracking: messages sent/received, connection state
    - NegotiationRelay: stats, list_sessions, concordia session linking
    - MCP tool integration: all 10 Relay tools via handle_tool_call
    - Full relay lifecycle: create → join → exchange messages → conclude → archive
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from concordia.relay import (
    NegotiationRelay,
    RelaySession,
    RelaySessionState,
    RelayedMessage,
    RelayParticipant,
    DeliveryStatus,
    TranscriptArchive,
)


# ===================================================================
# RelayedMessage tests
# ===================================================================

class TestRelayedMessage:

    def test_to_dict(self):
        msg = RelayedMessage(
            message_id="rmsg_001",
            session_id="relay_001",
            from_agent="agent_a",
            to_agent="agent_b",
            message_type="negotiate.offer",
            payload={"terms": {"price": 1000}},
        )
        d = msg.to_dict()
        assert d["message_id"] == "rmsg_001"
        assert d["status"] == "queued"
        assert d["from_agent"] == "agent_a"
        assert d["to_agent"] == "agent_b"

    def test_not_expired_by_default(self):
        msg = RelayedMessage(
            message_id="m1", session_id="s1",
            from_agent="a", to_agent="b",
            message_type="test", payload={}, ttl=3600,
        )
        assert msg.is_expired is False


class TestRelayParticipant:

    def test_to_dict(self):
        p = RelayParticipant(agent_id="agent_a", endpoint="https://a.example.com")
        d = p.to_dict()
        assert d["agent_id"] == "agent_a"
        assert d["endpoint"] == "https://a.example.com"
        assert d["connected"] is True
        assert d["messages_sent"] == 0


class TestRelaySession:

    def test_to_dict(self):
        initiator = RelayParticipant(agent_id="agent_a")
        session = RelaySession(
            relay_session_id="relay_001",
            concordia_session_id="ses_001",
            initiator=initiator,
        )
        d = session.to_dict()
        assert d["relay_session_id"] == "relay_001"
        assert d["concordia_session_id"] == "ses_001"
        assert d["state"] == "pending"
        assert d["message_count"] == 0

    def test_message_count(self):
        session = RelaySession(
            relay_session_id="r1",
            concordia_session_id=None,
            initiator=RelayParticipant(agent_id="a"),
        )
        assert session.message_count == 0
        session.transcript.append(
            RelayedMessage(
                message_id="m1", session_id="r1",
                from_agent="a", to_agent="b",
                message_type="test", payload={},
            )
        )
        assert session.message_count == 1


# ===================================================================
# NegotiationRelay — session lifecycle
# ===================================================================

class TestRelaySessionLifecycle:

    def test_create_with_both_parties(self):
        relay = NegotiationRelay()
        session = relay.create_session("agent_a", "agent_b")
        assert session.state == RelaySessionState.ACTIVE
        assert session.initiator.agent_id == "agent_a"
        assert session.responder.agent_id == "agent_b"

    def test_create_pending(self):
        relay = NegotiationRelay()
        session = relay.create_session("agent_a")
        assert session.state == RelaySessionState.PENDING
        assert session.responder is None

    def test_join_session(self):
        relay = NegotiationRelay()
        session = relay.create_session("agent_a")
        result = relay.join_session(session.relay_session_id, "agent_b")
        assert result is not None
        assert result.state == RelaySessionState.ACTIVE
        assert result.responder.agent_id == "agent_b"

    def test_join_nonexistent(self):
        relay = NegotiationRelay()
        assert relay.join_session("fake", "b") is None

    def test_join_already_active(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        assert relay.join_session(session.relay_session_id, "c") is None

    def test_get_session(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        retrieved = relay.get_session(session.relay_session_id)
        assert retrieved is not None
        assert retrieved.relay_session_id == session.relay_session_id

    def test_get_session_missing(self):
        relay = NegotiationRelay()
        assert relay.get_session("fake") is None

    def test_link_concordia_session(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        assert relay.link_concordia_session(session.relay_session_id, "ses_123") is True
        found = relay.get_by_concordia_id("ses_123")
        assert found is not None
        assert found.relay_session_id == session.relay_session_id

    def test_get_by_concordia_id_missing(self):
        relay = NegotiationRelay()
        assert relay.get_by_concordia_id("nonexistent") is None

    def test_conclude_session(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        result = relay.conclude_session(session.relay_session_id, "agreed")
        assert result.state == RelaySessionState.CONCLUDED
        assert result.conclusion_reason == "agreed"
        assert result.concluded_at is not None

    def test_conclude_nonexistent(self):
        relay = NegotiationRelay()
        assert relay.conclude_session("fake") is None

    def test_conclude_already_concluded(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        relay.conclude_session(session.relay_session_id, "agreed")
        result = relay.conclude_session(session.relay_session_id, "again")
        assert result.state == RelaySessionState.CONCLUDED  # no error, idempotent


# ===================================================================
# Message routing
# ===================================================================

class TestMessageRouting:

    def test_send_message(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        msg = relay.send_message(
            session.relay_session_id, "a",
            "negotiate.offer", {"price": 1000},
        )
        assert msg is not None
        assert msg.from_agent == "a"
        assert msg.to_agent == "b"
        assert msg.status == DeliveryStatus.QUEUED

    def test_send_updates_stats(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        relay.send_message(session.relay_session_id, "a", "offer", {"x": 1})
        assert session.initiator.messages_sent == 1

    def test_send_to_nonexistent_session(self):
        relay = NegotiationRelay()
        assert relay.send_message("fake", "a", "offer", {}) is None

    def test_send_to_concluded_session(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        relay.conclude_session(session.relay_session_id)
        assert relay.send_message(session.relay_session_id, "a", "offer", {}) is None

    def test_send_without_responder(self):
        relay = NegotiationRelay()
        session = relay.create_session("a")  # pending, no responder
        assert relay.send_message(session.relay_session_id, "a", "offer", {}) is None

    def test_receive_messages(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        relay.send_message(session.relay_session_id, "a", "offer", {"price": 1000})
        relay.send_message(session.relay_session_id, "a", "info", {"note": "hello"})

        received = relay.receive_messages("b")
        assert len(received) == 2
        assert received[0].status == DeliveryStatus.DELIVERED
        assert received[0].delivered_at is not None
        assert received[1].payload == {"note": "hello"}

    def test_receive_updates_stats(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        relay.send_message(session.relay_session_id, "a", "offer", {})
        relay.receive_messages("b")
        assert session.responder.messages_received == 1

    def test_receive_no_messages(self):
        relay = NegotiationRelay()
        received = relay.receive_messages("nobody")
        assert received == []

    def test_receive_filtered_by_session(self):
        relay = NegotiationRelay()
        s1 = relay.create_session("a", "b")
        s2 = relay.create_session("a", "b")
        relay.send_message(s1.relay_session_id, "a", "offer", {"from": "s1"})
        relay.send_message(s2.relay_session_id, "a", "offer", {"from": "s2"})

        received = relay.receive_messages("b", relay_session_id=s1.relay_session_id)
        assert len(received) == 1
        assert received[0].payload == {"from": "s1"}

        # s2 message still in mailbox
        remaining = relay.receive_messages("b")
        assert len(remaining) == 1
        assert remaining[0].payload == {"from": "s2"}

    def test_receive_limit(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        for i in range(10):
            relay.send_message(session.relay_session_id, "a", "msg", {"i": i})
        received = relay.receive_messages("b", limit=3)
        assert len(received) == 3

    def test_terminal_message_concludes_session(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        relay.send_message(session.relay_session_id, "a", "negotiate.offer", {"price": 1000})
        relay.send_message(session.relay_session_id, "b", "negotiate.accept", {})
        assert session.state == RelaySessionState.CONCLUDED
        assert session.conclusion_reason == "negotiate.accept"

    def test_bidirectional_exchange(self):
        relay = NegotiationRelay()
        session = relay.create_session("seller", "buyer")

        relay.send_message(session.relay_session_id, "seller", "negotiate.offer", {"price": 1200})
        relay.send_message(session.relay_session_id, "buyer", "negotiate.counter", {"price": 900})
        relay.send_message(session.relay_session_id, "seller", "negotiate.counter", {"price": 1050})

        assert session.message_count == 3
        assert session.initiator.messages_sent == 2
        assert session.responder.messages_sent == 1

        # Buyer receives 2 messages from seller
        buyer_msgs = relay.receive_messages("buyer")
        assert len(buyer_msgs) == 2

        # Seller receives 1 message from buyer
        seller_msgs = relay.receive_messages("seller")
        assert len(seller_msgs) == 1


# ===================================================================
# Transcript and archival
# ===================================================================

class TestTranscriptAndArchival:

    def test_get_transcript(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        relay.send_message(session.relay_session_id, "a", "offer", {"x": 1})
        relay.send_message(session.relay_session_id, "b", "counter", {"x": 2})

        transcript = relay.get_transcript(session.relay_session_id)
        assert transcript is not None
        assert len(transcript) == 2
        assert transcript[0]["from_agent"] == "a"
        assert transcript[1]["from_agent"] == "b"

    def test_get_transcript_with_limit(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        for i in range(10):
            relay.send_message(session.relay_session_id, "a", "msg", {"i": i})
        transcript = relay.get_transcript(session.relay_session_id, limit=3)
        assert len(transcript) == 3

    def test_get_transcript_nonexistent(self):
        relay = NegotiationRelay()
        assert relay.get_transcript("fake") is None

    def test_archive_concluded_session(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        relay.send_message(session.relay_session_id, "a", "offer", {"x": 1})
        relay.conclude_session(session.relay_session_id, "agreed")

        archive = relay.archive_session(session.relay_session_id)
        assert archive is not None
        assert archive.message_count == 1
        assert archive.parties == ["a", "b"]
        assert archive.conclusion_reason == "agreed"
        assert session.state == RelaySessionState.ARCHIVED

    def test_archive_active_session_fails(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        assert relay.archive_session(session.relay_session_id) is None

    def test_archive_nonexistent(self):
        relay = NegotiationRelay()
        assert relay.archive_session("fake") is None

    def test_get_archive(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        relay.conclude_session(session.relay_session_id)
        archive = relay.archive_session(session.relay_session_id)
        retrieved = relay.get_archive(archive.archive_id)
        assert retrieved is not None
        assert retrieved.archive_id == archive.archive_id

    def test_list_archives(self):
        relay = NegotiationRelay()
        for i in range(3):
            s = relay.create_session(f"a{i}", f"b{i}")
            relay.conclude_session(s.relay_session_id)
            relay.archive_session(s.relay_session_id)
        assert len(relay.list_archives()) == 3

    def test_list_archives_by_agent(self):
        relay = NegotiationRelay()
        s1 = relay.create_session("alice", "bob")
        s2 = relay.create_session("alice", "carol")
        s3 = relay.create_session("bob", "carol")
        for s in [s1, s2, s3]:
            relay.conclude_session(s.relay_session_id)
            relay.archive_session(s.relay_session_id)

        alice_archives = relay.list_archives(agent_id="alice")
        assert len(alice_archives) == 2
        carol_archives = relay.list_archives(agent_id="carol")
        assert len(carol_archives) == 2

    def test_archive_has_messages(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        relay.send_message(session.relay_session_id, "a", "offer", {"price": 100})
        relay.send_message(session.relay_session_id, "b", "accept", {})
        relay.conclude_session(session.relay_session_id)
        archive = relay.archive_session(session.relay_session_id)
        assert len(archive.messages) == 2

    def test_archive_retention_days(self):
        relay = NegotiationRelay()
        session = relay.create_session("a", "b")
        relay.conclude_session(session.relay_session_id)
        archive = relay.archive_session(session.relay_session_id, retention_days=90)
        assert archive.retention_days == 90


# ===================================================================
# Stats and listing
# ===================================================================

class TestRelayStats:

    def test_empty_stats(self):
        relay = NegotiationRelay()
        stats = relay.stats()
        assert stats["total_sessions"] == 0
        assert stats["total_messages_relayed"] == 0
        assert stats["total_archives"] == 0

    def test_stats_with_activity(self):
        relay = NegotiationRelay()
        s1 = relay.create_session("a", "b")
        relay.send_message(s1.relay_session_id, "a", "offer", {})
        relay.send_message(s1.relay_session_id, "b", "counter", {})
        s2 = relay.create_session("c")  # pending

        stats = relay.stats()
        assert stats["total_sessions"] == 2
        assert stats["total_messages_relayed"] == 2
        assert stats["sessions_by_state"]["active"] == 1
        assert stats["sessions_by_state"]["pending"] == 1
        assert stats["pending_deliveries"] == 2  # not yet received

    def test_list_sessions(self):
        relay = NegotiationRelay()
        relay.create_session("a", "b")
        relay.create_session("c", "d")
        sessions = relay.list_sessions()
        assert len(sessions) == 2

    def test_list_sessions_by_agent(self):
        relay = NegotiationRelay()
        relay.create_session("alice", "bob")
        relay.create_session("alice", "carol")
        relay.create_session("bob", "carol")
        sessions = relay.list_sessions(agent_id="alice")
        assert len(sessions) == 2

    def test_list_sessions_by_state(self):
        relay = NegotiationRelay()
        s1 = relay.create_session("a", "b")
        relay.create_session("c")  # pending
        relay.conclude_session(s1.relay_session_id)

        active = relay.list_sessions(state="active")
        assert len(active) == 0
        pending = relay.list_sessions(state="pending")
        assert len(pending) == 1
        concluded = relay.list_sessions(state="concluded")
        assert len(concluded) == 1


# ===================================================================
# MCP Tool integration tests
# ===================================================================

class TestRelayMcpTools:

    @pytest.fixture(autouse=True)
    def reset_relay(self):
        from concordia.mcp_server import _relay, _auth
        _relay._sessions.clear()
        _relay._archives.clear()
        _relay._mailboxes.clear()
        _relay._concordia_index.clear()
        _auth._agent_tokens.clear()
        _auth._session_tokens.clear()
        _auth._token_to_agent.clear()
        yield

    def _parse(self, result_str: str) -> dict:
        return json.loads(result_str)

    def test_relay_create(self):
        from concordia.mcp_server import tool_relay_create, tool_register_agent
        # Register initiator to get auth_token
        reg_result = self._parse(tool_register_agent(agent_id="seller_01"))
        auth_token = reg_result["auth_token"]

        result = self._parse(tool_relay_create(
            initiator_id="seller_01",
            auth_token=auth_token,
            responder_id="buyer_42",
        ))
        assert result["session"]["state"] == "active"
        assert result["session"]["initiator"]["agent_id"] == "seller_01"

    def test_relay_create_pending(self):
        from concordia.mcp_server import tool_relay_create, tool_register_agent
        # Register initiator to get auth_token
        reg_result = self._parse(tool_register_agent(agent_id="seller_01"))
        auth_token = reg_result["auth_token"]

        result = self._parse(tool_relay_create(initiator_id="seller_01", auth_token=auth_token))
        assert result["session"]["state"] == "pending"

    def test_relay_join(self):
        from concordia.mcp_server import tool_relay_create, tool_relay_join, tool_register_agent
        # Register both agents
        reg_seller = self._parse(tool_register_agent(agent_id="seller_01"))
        seller_token = reg_seller["auth_token"]
        reg_buyer = self._parse(tool_register_agent(agent_id="buyer_42"))
        buyer_token = reg_buyer["auth_token"]

        created = self._parse(tool_relay_create(initiator_id="seller_01", auth_token=seller_token))
        rid = created["session"]["relay_session_id"]

        result = self._parse(tool_relay_join(relay_session_id=rid, agent_id="buyer_42", auth_token=buyer_token))
        assert result["joined"] is True
        assert result["session"]["state"] == "active"

    def test_relay_join_not_found(self):
        from concordia.mcp_server import tool_relay_join, tool_register_agent
        # Register agent to get auth_token
        reg_result = self._parse(tool_register_agent(agent_id="b"))
        auth_token = reg_result["auth_token"]

        result = self._parse(tool_relay_join(relay_session_id="fake", agent_id="b", auth_token=auth_token))
        assert "error" in result

    def test_relay_send(self):
        from concordia.mcp_server import tool_relay_create, tool_relay_send, tool_register_agent
        # Register agents
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]

        created = self._parse(tool_relay_create(
            initiator_id="a", auth_token=token_a, responder_id="b",
        ))
        rid = created["session"]["relay_session_id"]

        result = self._parse(tool_relay_send(
            relay_session_id=rid,
            from_agent="a",
            message_type="negotiate.offer",
            payload={"price": 1000},
            auth_token=token_a,
        ))
        assert result["sent"] is True
        assert result["message"]["from_agent"] == "a"

    def test_relay_receive(self):
        from concordia.mcp_server import tool_relay_create, tool_relay_send, tool_relay_receive, tool_register_agent
        # Register agents
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]
        reg_b = self._parse(tool_register_agent(agent_id="b"))
        token_b = reg_b["auth_token"]

        created = self._parse(tool_relay_create(initiator_id="a", auth_token=token_a, responder_id="b"))
        rid = created["session"]["relay_session_id"]

        tool_relay_send(relay_session_id=rid, from_agent="a", auth_token=token_a,
                        message_type="offer", payload={"price": 1000})

        result = self._parse(tool_relay_receive(agent_id="b", auth_token=token_b))
        assert result["count"] == 1
        assert result["payloads"][0] == {"price": 1000}

    def test_relay_status(self):
        from concordia.mcp_server import tool_relay_create, tool_relay_status, tool_register_agent
        # Register agents
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]

        created = self._parse(tool_relay_create(initiator_id="a", auth_token=token_a, responder_id="b"))
        rid = created["session"]["relay_session_id"]

        result = self._parse(tool_relay_status(relay_session_id=rid, agent_id="a", auth_token=token_a))
        assert result["session"]["state"] == "active"

    def test_relay_status_not_found(self):
        from concordia.mcp_server import tool_relay_status, tool_register_agent
        reg = self._parse(tool_register_agent(agent_id="statusnf"))
        token = reg["auth_token"]
        result = self._parse(tool_relay_status(relay_session_id="fake", agent_id="statusnf", auth_token=token))
        assert "error" in result

    def test_relay_conclude(self):
        from concordia.mcp_server import tool_relay_create, tool_relay_conclude, tool_register_agent
        # Register agents
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]

        created = self._parse(tool_relay_create(initiator_id="a", auth_token=token_a, responder_id="b"))
        rid = created["session"]["relay_session_id"]

        result = self._parse(tool_relay_conclude(relay_session_id=rid, agent_id="a", auth_token=token_a, reason="agreed"))
        assert result["concluded"] is True
        assert result["session"]["state"] == "concluded"

    def test_relay_transcript(self):
        from concordia.mcp_server import tool_relay_create, tool_relay_send, tool_relay_transcript, tool_register_agent
        # Register agents
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]
        reg_b = self._parse(tool_register_agent(agent_id="b"))
        token_b = reg_b["auth_token"]

        created = self._parse(tool_relay_create(initiator_id="a", auth_token=token_a, responder_id="b"))
        rid = created["session"]["relay_session_id"]

        tool_relay_send(relay_session_id=rid, from_agent="a", auth_token=token_a, message_type="offer", payload={"x": 1})
        tool_relay_send(relay_session_id=rid, from_agent="b", auth_token=token_b, message_type="counter", payload={"x": 2})

        result = self._parse(tool_relay_transcript(relay_session_id=rid, agent_id="a", auth_token=token_a))
        assert result["count"] == 2

    def test_relay_archive(self):
        from concordia.mcp_server import tool_relay_create, tool_relay_conclude, tool_relay_archive, tool_register_agent
        # Register agents
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]

        created = self._parse(tool_relay_create(initiator_id="a", auth_token=token_a, responder_id="b"))
        rid = created["session"]["relay_session_id"]
        tool_relay_conclude(relay_session_id=rid, agent_id="a", auth_token=token_a)

        result = self._parse(tool_relay_archive(relay_session_id=rid, agent_id="a", auth_token=token_a, retention_days=90))
        assert result["archived"] is True
        assert result["archive"]["retention_days"] == 90

    def test_relay_archive_active_fails(self):
        from concordia.mcp_server import tool_relay_create, tool_relay_archive, tool_register_agent
        # Register agents
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]

        created = self._parse(tool_relay_create(initiator_id="a", auth_token=token_a, responder_id="b"))
        rid = created["session"]["relay_session_id"]
        result = self._parse(tool_relay_archive(relay_session_id=rid, agent_id="a", auth_token=token_a))
        assert "error" in result

    def test_relay_list_archives(self):
        from concordia.mcp_server import (
            tool_relay_create, tool_relay_conclude,
            tool_relay_archive, tool_relay_list_archives, tool_register_agent,
        )
        # Register a single agent that participates in all 3 sessions
        reg_a = self._parse(tool_register_agent(agent_id="la_agent"))
        token_a = reg_a["auth_token"]

        for i in range(3):
            created = self._parse(tool_relay_create(
                initiator_id="la_agent", auth_token=token_a, responder_id=f"la_b{i}",
            ))
            rid = created["session"]["relay_session_id"]
            tool_relay_conclude(relay_session_id=rid, agent_id="la_agent", auth_token=token_a)
            tool_relay_archive(relay_session_id=rid, agent_id="la_agent", auth_token=token_a)

        # Agent sees archives for sessions they participated in
        result = self._parse(tool_relay_list_archives(agent_id="la_agent", auth_token=token_a))
        assert result["count"] == 3

    # -- Auth rejection tests (H-16, H-17, H-18) --

    def test_relay_status_rejects_bad_token(self):
        """H-16: relay_status rejects unauthenticated callers."""
        from concordia.mcp_server import tool_relay_create, tool_relay_status, tool_register_agent
        reg = self._parse(tool_register_agent(agent_id="auth_s"))
        token = reg["auth_token"]
        created = self._parse(tool_relay_create(initiator_id="auth_s", auth_token=token, responder_id="auth_s2"))
        rid = created["session"]["relay_session_id"]
        result = self._parse(tool_relay_status(relay_session_id=rid, agent_id="auth_s", auth_token="bad_token"))
        assert "error" in result

    def test_relay_status_rejects_non_participant(self):
        """H-16: relay_status rejects non-participants."""
        from concordia.mcp_server import tool_relay_create, tool_relay_status, tool_register_agent
        reg_a = self._parse(tool_register_agent(agent_id="rs_p1"))
        token_a = reg_a["auth_token"]
        reg_c = self._parse(tool_register_agent(agent_id="rs_outsider"))
        token_c = reg_c["auth_token"]
        created = self._parse(tool_relay_create(initiator_id="rs_p1", auth_token=token_a, responder_id="rs_p2"))
        rid = created["session"]["relay_session_id"]
        result = self._parse(tool_relay_status(relay_session_id=rid, agent_id="rs_outsider", auth_token=token_c))
        assert "error" in result

    def test_relay_archive_rejects_bad_token(self):
        """H-17: relay_archive rejects unauthenticated callers."""
        from concordia.mcp_server import tool_relay_create, tool_relay_conclude, tool_relay_archive, tool_register_agent
        reg = self._parse(tool_register_agent(agent_id="ra_auth"))
        token = reg["auth_token"]
        created = self._parse(tool_relay_create(initiator_id="ra_auth", auth_token=token, responder_id="ra_b"))
        rid = created["session"]["relay_session_id"]
        tool_relay_conclude(relay_session_id=rid, agent_id="ra_auth", auth_token=token)
        result = self._parse(tool_relay_archive(relay_session_id=rid, agent_id="ra_auth", auth_token="bad"))
        assert "error" in result

    def test_relay_list_archives_rejects_bad_token(self):
        """H-18: relay_list_archives rejects unauthenticated callers."""
        from concordia.mcp_server import tool_relay_list_archives, tool_register_agent
        self._parse(tool_register_agent(agent_id="rla_auth"))
        result = self._parse(tool_relay_list_archives(agent_id="rla_auth", auth_token="bad"))
        assert "error" in result

    def test_relay_stats(self):
        from concordia.mcp_server import tool_relay_create, tool_relay_send, tool_relay_stats, tool_register_agent
        # Register agents
        reg_a = self._parse(tool_register_agent(agent_id="a"))
        token_a = reg_a["auth_token"]

        created = self._parse(tool_relay_create(initiator_id="a", auth_token=token_a, responder_id="b"))
        rid = created["session"]["relay_session_id"]
        tool_relay_send(relay_session_id=rid, from_agent="a", auth_token=token_a, message_type="offer", payload={})

        result = self._parse(tool_relay_stats())
        assert result["total_sessions"] == 1
        assert result["total_messages_relayed"] == 1

    # -- Full lifecycle via handle_tool_call --

    def test_full_relay_lifecycle(self):
        """End-to-end: create → join → exchange → conclude → archive."""
        from concordia.mcp_server import handle_tool_call

        # Register agents first
        seller_reg = handle_tool_call("concordia_register_agent", {
            "agent_id": "seller_agent",
        })
        seller_token = seller_reg["auth_token"]

        buyer_reg = handle_tool_call("concordia_register_agent", {
            "agent_id": "buyer_agent",
        })
        buyer_token = buyer_reg["auth_token"]

        # Create relay session (pending)
        created = handle_tool_call("concordia_relay_create", {
            "initiator_id": "seller_agent",
            "auth_token": seller_token,
        })
        rid = created["session"]["relay_session_id"]
        assert created["session"]["state"] == "pending"

        # Responder joins
        joined = handle_tool_call("concordia_relay_join", {
            "relay_session_id": rid,
            "agent_id": "buyer_agent",
            "auth_token": buyer_token,
        })
        assert joined["joined"] is True
        assert joined["session"]["state"] == "active"

        # Exchange messages
        handle_tool_call("concordia_relay_send", {
            "relay_session_id": rid,
            "from_agent": "seller_agent",
            "message_type": "negotiate.offer",
            "payload": {"price": 2000, "condition": "like_new"},
            "auth_token": seller_token,
        })
        handle_tool_call("concordia_relay_send", {
            "relay_session_id": rid,
            "from_agent": "buyer_agent",
            "message_type": "negotiate.counter",
            "payload": {"price": 1500, "condition": "like_new"},
            "auth_token": buyer_token,
        })
        handle_tool_call("concordia_relay_send", {
            "relay_session_id": rid,
            "from_agent": "seller_agent",
            "message_type": "negotiate.counter",
            "payload": {"price": 1750, "condition": "like_new"},
            "auth_token": seller_token,
        })

        # Buyer receives messages
        buyer_msgs = handle_tool_call("concordia_relay_receive", {
            "agent_id": "buyer_agent",
            "relay_session_id": rid,
            "auth_token": buyer_token,
        })
        assert buyer_msgs["count"] == 2  # offer + counter from seller

        # Seller receives messages
        seller_msgs = handle_tool_call("concordia_relay_receive", {
            "agent_id": "seller_agent",
            "relay_session_id": rid,
            "auth_token": seller_token,
        })
        assert seller_msgs["count"] == 1  # counter from buyer

        # Check transcript
        transcript = handle_tool_call("concordia_relay_transcript", {
            "relay_session_id": rid,
            "agent_id": "seller_agent",
            "auth_token": seller_token,
        })
        assert transcript["count"] == 3

        # Check status
        status = handle_tool_call("concordia_relay_status", {
            "relay_session_id": rid,
            "agent_id": "seller_agent",
            "auth_token": seller_token,
        })
        assert status["session"]["message_count"] == 3
        assert status["session"]["initiator"]["messages_sent"] == 2
        assert status["session"]["responder"]["messages_sent"] == 1

        # Conclude
        concluded = handle_tool_call("concordia_relay_conclude", {
            "relay_session_id": rid,
            "agent_id": "seller_agent",
            "auth_token": seller_token,
            "reason": "agreed",
        })
        assert concluded["concluded"] is True

        # Archive
        archived = handle_tool_call("concordia_relay_archive", {
            "relay_session_id": rid,
            "agent_id": "seller_agent",
            "auth_token": seller_token,
            "retention_days": 180,
        })
        assert archived["archived"] is True
        assert archived["archive"]["message_count"] == 3
        assert archived["archive"]["parties"] == ["seller_agent", "buyer_agent"]

        # List archives
        archives = handle_tool_call("concordia_relay_list_archives", {
            "agent_id": "seller_agent",
            "auth_token": seller_token,
        })
        assert archives["count"] == 1

        # Final stats
        stats = handle_tool_call("concordia_relay_stats", {})
        assert stats["total_sessions"] == 1
        assert stats["total_messages_relayed"] == 3
        assert stats["total_archives"] == 1
