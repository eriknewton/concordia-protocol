"""Negotiation Relay — message routing and session management service.

Routes Concordia messages between agents that cannot communicate directly,
stores session transcripts for archival and compliance, enforces timeouts,
and optionally auto-generates attestations when sessions conclude.

Per SERVICE_ARCHITECTURE.md §3, the relay is valuable when:
    - Agents lack persistent endpoints (ephemeral / mobile agents)
    - Firewall traversal is needed (enterprise agents behind NATs)
    - Legal compliance requires transcript retention
    - Automatic attestation submission to the Reputation Service is desired

Architecture:
    Agent A ──► Relay ──► Agent B
                 │
                 ├─ Transcript archive
                 ├─ Timeout enforcement
                 └─ Auto-attestation → Reputation Service

This module is pure in-process logic — no networking.  MCP tools in
``mcp_server.py`` expose it to external callers.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Any


# Audit M4 hardening: keep one initiator from monopolizing relay sessions while
# preserving the existing global relay caps.
MAX_ACTIVE_RELAY_SESSIONS_PER_INITIATOR = 100
MAX_TTL_SECONDS = 7 * 24 * 60 * 60

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RelaySessionState(str, Enum):
    """Lifecycle of a relay-managed session."""
    PENDING = "pending"        # Created, waiting for responder to join
    ACTIVE = "active"          # Both parties connected, messages flowing
    CONCLUDED = "concluded"    # Terminal state reached (agreed/rejected/expired)
    ARCHIVED = "archived"      # Transcript archived, session frozen
    TIMED_OUT = "timed_out"    # Relay enforced timeout


class DeliveryStatus(str, Enum):
    """Status of a relayed message."""
    QUEUED = "queued"          # In relay, not yet delivered
    DELIVERED = "delivered"    # Confirmed received by target
    EXPIRED = "expired"        # TTL exceeded before delivery
    FAILED = "failed"          # Delivery failed


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class RelayedMessage:
    """A message passing through the relay."""

    message_id: str
    session_id: str
    from_agent: str
    to_agent: str
    message_type: str
    payload: dict[str, Any]
    status: DeliveryStatus = DeliveryStatus.QUEUED
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    delivered_at: str | None = None
    ttl: int = 3600  # 1 hour default

    @property
    def is_expired(self) -> bool:
        """Check if this message has expired based on TTL."""
        created_ts = datetime.fromisoformat(self.created_at).timestamp()
        return time.time() > created_ts + self.ttl

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "session_id": self.session_id,
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "message_type": self.message_type,
            "status": self.status.value,
            "created_at": self.created_at,
            "delivered_at": self.delivered_at,
            "ttl": self.ttl,
        }


@dataclass
class RelayParticipant:
    """An agent connected to a relay session."""

    agent_id: str
    endpoint: str | None = None
    connected: bool = True
    confirmed: bool = True
    last_seen: float = field(default_factory=time.time)
    messages_sent: int = 0
    messages_received: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "endpoint": self.endpoint,
            "connected": self.connected,
            "confirmed": self.confirmed,
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RelayParticipant":
        return cls(
            agent_id=data["agent_id"],
            endpoint=data.get("endpoint"),
            connected=data.get("connected", True),
            confirmed=data.get("confirmed", True),
            messages_sent=data.get("messages_sent", 0),
            messages_received=data.get("messages_received", 0),
        )


@dataclass
class RelaySession:
    """A relay-managed negotiation session.

    The relay wraps a Concordia session with routing, delivery tracking,
    transcript archival, and timeout enforcement.
    """

    relay_session_id: str
    concordia_session_id: str | None  # linked Concordia session, if any
    initiator: RelayParticipant
    responder: RelayParticipant | None = None
    state: RelaySessionState = RelaySessionState.PENDING
    transcript: list[RelayedMessage] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    concluded_at: str | None = None
    conclusion_reason: str | None = None
    session_ttl: int = 86_400  # 24 hours default
    auto_attest: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_timed_out(self) -> bool:
        created_ts = datetime.fromisoformat(self.created_at).timestamp()
        return time.time() > created_ts + self.session_ttl

    @property
    def message_count(self) -> int:
        return len(self.transcript)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "relay_session_id": self.relay_session_id,
            "concordia_session_id": self.concordia_session_id,
            "state": self.state.value,
            "initiator": self.initiator.to_dict(),
            "message_count": self.message_count,
            "created_at": self.created_at,
            "session_ttl": self.session_ttl,
            "auto_attest": self.auto_attest,
        }
        if self.responder:
            d["responder"] = self.responder.to_dict()
        if self.concluded_at:
            d["concluded_at"] = self.concluded_at
            d["conclusion_reason"] = self.conclusion_reason
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class TranscriptArchive:
    """An archived transcript for compliance and dispute resolution."""

    archive_id: str
    relay_session_id: str
    concordia_session_id: str | None
    parties: list[str]
    message_count: int
    conclusion_reason: str | None
    messages: list[dict[str, Any]]
    initiator: dict[str, Any] | None = None
    responder: dict[str, Any] | None = None
    archived_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    retention_days: int = 365  # 1 year default

    def to_dict(self) -> dict[str, Any]:
        d = {
            "archive_id": self.archive_id,
            "relay_session_id": self.relay_session_id,
            "concordia_session_id": self.concordia_session_id,
            "parties": self.parties,
            "message_count": self.message_count,
            "conclusion_reason": self.conclusion_reason,
            "archived_at": self.archived_at,
            "retention_days": self.retention_days,
        }
        if self.initiator is not None:
            d["initiator"] = self.initiator
        if self.responder is not None:
            d["responder"] = self.responder
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TranscriptArchive":
        return cls(
            archive_id=data["archive_id"],
            relay_session_id=data["relay_session_id"],
            concordia_session_id=data.get("concordia_session_id"),
            parties=list(data["parties"]),
            message_count=data["message_count"],
            conclusion_reason=data.get("conclusion_reason"),
            messages=list(data.get("messages", [])),
            initiator=data.get("initiator"),
            responder=data.get("responder"),
            archived_at=data.get("archived_at", datetime.now(timezone.utc).isoformat()),
            retention_days=data.get("retention_days", 365),
        )


# ---------------------------------------------------------------------------
# Relay
# ---------------------------------------------------------------------------

class NegotiationRelay:
    """Message routing and session management relay.

    Core responsibilities:
        1. Route messages between agents (store-and-forward)
        2. Track delivery status
        3. Enforce session timeouts
        4. Archive transcripts on conclusion
        5. Optionally trigger attestation generation
    """

    # Security and resource limits
    MAX_SESSIONS = 10_000
    MAX_ARCHIVES = 50_000
    MAX_MAILBOX_SIZE = 1_000
    MAX_TRANSCRIPT_SIZE = 10_000

    def __init__(self) -> None:
        self._sessions: dict[str, RelaySession] = {}
        self._archives: dict[str, TranscriptArchive] = {}
        # Mailbox: agent_id → list of pending messages
        self._mailboxes: dict[str, list[RelayedMessage]] = {}
        # Index: concordia_session_id → relay_session_id
        self._concordia_index: dict[str, str] = {}

    # -- Session lifecycle ---------------------------------------------------

    def create_session(
        self,
        initiator_id: str,
        responder_id: str | None = None,
        concordia_session_id: str | None = None,
        session_ttl: int = 86_400,
        auto_attest: bool = True,
        initiator_endpoint: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> RelaySession:
        """Create a relay session.

        A pre-named responder is a reservation until that exact responder joins.
        """
        # Prevent self-sessions
        if responder_id and initiator_id == responder_id:
            raise ValueError("Cannot create relay session with same agent as both initiator and responder")
        if session_ttl > MAX_TTL_SECONDS:
            raise ValueError("TTL exceeds maximum")

        # Check session limit
        self._expire_timed_out_sessions()
        if len(self._sessions) >= self.MAX_SESSIONS:
            raise ValueError("Relay session limit reached")
        if (
            self._active_session_count_for_initiator(initiator_id)
            >= MAX_ACTIVE_RELAY_SESSIONS_PER_INITIATOR
        ):
            raise ValueError("Relay session limit reached")

        relay_id = f"relay_{uuid.uuid4().hex[:12]}"
        initiator = RelayParticipant(
            agent_id=initiator_id,
            endpoint=initiator_endpoint,
            confirmed=True,
        )
        responder = None
        state = RelaySessionState.PENDING
        if responder_id:
            responder = RelayParticipant(
                agent_id=responder_id,
                connected=False,
                confirmed=False,
            )

        session = RelaySession(
            relay_session_id=relay_id,
            concordia_session_id=concordia_session_id,
            initiator=initiator,
            responder=responder,
            state=state,
            session_ttl=session_ttl,
            auto_attest=auto_attest,
            metadata=metadata or {},
        )
        self._sessions[relay_id] = session
        if concordia_session_id:
            self._concordia_index[concordia_session_id] = relay_id
        return session

    def join_session(
        self,
        relay_session_id: str,
        agent_id: str,
        endpoint: str | None = None,
    ) -> RelaySession | None:
        """Responder joins a pending relay session."""
        session = self._sessions.get(relay_session_id)
        if session is None:
            return None
        if session.state != RelaySessionState.PENDING:
            return None
        if session.responder is not None:
            if session.responder.agent_id != agent_id:
                return None
            session.responder.endpoint = endpoint
            session.responder.connected = True
            session.responder.confirmed = True
            session.responder.last_seen = time.time()
            session.state = RelaySessionState.ACTIVE
            return session

        session.responder = RelayParticipant(
            agent_id=agent_id,
            endpoint=endpoint,
            confirmed=True,
        )
        session.state = RelaySessionState.ACTIVE
        return session

    def get_session(self, relay_session_id: str) -> RelaySession | None:
        session = self._sessions.get(relay_session_id)
        if (
            session
            and session.is_timed_out
            and session.state in (RelaySessionState.PENDING, RelaySessionState.ACTIVE)
        ):
            self._timeout_session(session)
        return session

    def get_by_concordia_id(self, concordia_session_id: str) -> RelaySession | None:
        relay_id = self._concordia_index.get(concordia_session_id)
        if relay_id:
            return self.get_session(relay_id)
        return None

    def link_concordia_session(
        self,
        relay_session_id: str,
        concordia_session_id: str,
    ) -> bool:
        """Link a relay session to a Concordia session after creation."""
        session = self._sessions.get(relay_session_id)
        if session is None:
            return False
        session.concordia_session_id = concordia_session_id
        self._concordia_index[concordia_session_id] = relay_session_id
        return True

    # -- Message routing -----------------------------------------------------

    def send_message(
        self,
        relay_session_id: str,
        from_agent: str,
        message_type: str,
        payload: dict[str, Any],
        ttl: int = 3600,
    ) -> RelayedMessage | None:
        """Route a message through the relay.

        The message is stored in the transcript and placed in the
        recipient's mailbox for retrieval.
        """
        session = self._sessions.get(relay_session_id)
        if session is None:
            return None

        # Verify sender is a participant
        sender = self._get_participant(session, from_agent)
        if sender is None or not sender.confirmed:
            return None

        # Check session is active
        if session.state not in (RelaySessionState.ACTIVE, RelaySessionState.PENDING):
            return None

        # Check timeout
        if session.is_timed_out:
            self._timeout_session(session)
            return None

        # Check transcript size limit
        if len(session.transcript) >= self.MAX_TRANSCRIPT_SIZE:
            return None

        # Determine recipient
        to_agent = self._get_counterparty(session, from_agent)
        if to_agent is None:
            return None

        msg = RelayedMessage(
            message_id=f"rmsg_{uuid.uuid4().hex[:12]}",
            session_id=relay_session_id,
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=message_type,
            payload=payload,
            ttl=ttl,
        )

        # Append to session transcript
        session.transcript.append(msg)

        # Update sender stats
        sender_participant = self._get_participant(session, from_agent)
        if sender_participant:
            sender_participant.messages_sent += 1
            sender_participant.last_seen = time.time()

        # Place in recipient's mailbox (with size limit check)
        mailbox = self._mailboxes.setdefault(to_agent, [])
        if len(mailbox) >= self.MAX_MAILBOX_SIZE:
            return None
        mailbox.append(msg)

        # Check for terminal message types
        if message_type in ("negotiate.accept", "negotiate.reject",
                            "negotiate.withdraw", "negotiate.commit"):
            self._conclude_session(session, reason=message_type)

        return msg

    def receive_messages(
        self,
        agent_id: str,
        relay_session_id: str | None = None,
        limit: int = 50,
    ) -> list[RelayedMessage]:
        """Retrieve pending messages for an agent (poll model).

        Marks messages as delivered upon retrieval. Optionally filter
        by relay session.
        """
        mailbox = self._mailboxes.get(agent_id, [])
        delivered: list[RelayedMessage] = []
        remaining: list[RelayedMessage] = []

        for msg in mailbox:
            if msg.is_expired:
                msg.status = DeliveryStatus.EXPIRED
                continue
            if relay_session_id and msg.session_id != relay_session_id:
                remaining.append(msg)
                continue
            if len(delivered) >= limit:
                remaining.append(msg)
                continue

            msg.status = DeliveryStatus.DELIVERED
            msg.delivered_at = datetime.now(timezone.utc).isoformat()
            delivered.append(msg)

            # Update receiver stats
            session = self._sessions.get(msg.session_id)
            if session:
                receiver = self._get_participant(session, agent_id)
                if receiver:
                    receiver.messages_received += 1
                    receiver.last_seen = time.time()

        self._mailboxes[agent_id] = remaining
        return delivered

    def get_transcript(
        self,
        relay_session_id: str,
        requesting_agent: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]] | None:
        """Retrieve the full message transcript for a relay session.

        If requesting_agent is provided, verify the agent is a participant
        before returning the transcript.
        """
        session = self._sessions.get(relay_session_id)
        if session is None:
            return None
        # Access control: only participants can read transcripts
        if requesting_agent is not None:
            if self._get_participant(session, requesting_agent) is None:
                return None
        messages = session.transcript
        if limit:
            messages = messages[-limit:]
        return [m.to_dict() for m in messages]

    # -- Session conclusion --------------------------------------------------

    def conclude_session(
        self,
        relay_session_id: str,
        reason: str = "manual",
    ) -> RelaySession | None:
        """Manually conclude a relay session."""
        session = self._sessions.get(relay_session_id)
        if session is None:
            return None
        if session.state in (RelaySessionState.CONCLUDED, RelaySessionState.ARCHIVED):
            return session
        self._conclude_session(session, reason=reason)
        return session

    def _conclude_session(self, session: RelaySession, reason: str) -> None:
        """Internal: mark a session as concluded."""
        session.state = RelaySessionState.CONCLUDED
        session.concluded_at = datetime.now(timezone.utc).isoformat()
        session.conclusion_reason = reason
        self._record_auto_attest_skip_if_unconfirmed(session)

    def _timeout_session(self, session: RelaySession) -> None:
        """Internal: mark a session as timed out."""
        session.state = RelaySessionState.TIMED_OUT
        session.concluded_at = datetime.now(timezone.utc).isoformat()
        session.conclusion_reason = "session_timeout"
        self._record_auto_attest_skip_if_unconfirmed(session)

    def _record_auto_attest_skip_if_unconfirmed(self, session: RelaySession) -> None:
        """Fail closed before any auto-attest path can name a reservation."""
        if not session.auto_attest:
            return
        if session.responder is None or session.responder.confirmed:
            return
        reason = (
            "auto_attest skipped: responder "
            f"'{session.responder.agent_id}' has not confirmed by joining"
        )
        session.metadata["auto_attest_skipped"] = reason
        logger.warning(
            "Skipping relay auto-attest for %s: responder %s is unconfirmed",
            session.relay_session_id,
            session.responder.agent_id,
        )

    def _expire_timed_out_sessions(self) -> None:
        for session in self._sessions.values():
            if (
                session.state in (RelaySessionState.PENDING, RelaySessionState.ACTIVE)
                and session.is_timed_out
            ):
                self._timeout_session(session)

    def _active_session_count_for_initiator(self, initiator_id: str) -> int:
        return sum(
            1 for session in self._sessions.values()
            if (
                session.initiator.agent_id == initiator_id
                and session.state in (
                    RelaySessionState.PENDING,
                    RelaySessionState.ACTIVE,
                )
                and not session.is_timed_out
            )
        )

    # -- Archival ------------------------------------------------------------

    def archive_session(
        self,
        relay_session_id: str,
        retention_days: int = 365,
    ) -> TranscriptArchive | None:
        """Archive a concluded session's transcript for compliance."""
        session = self._sessions.get(relay_session_id)
        if session is None:
            return None
        if session.state not in (
            RelaySessionState.CONCLUDED,
            RelaySessionState.TIMED_OUT,
        ):
            return None

        # Check archive limit
        if len(self._archives) >= self.MAX_ARCHIVES:
            raise ValueError("Archive limit reached")

        parties = [session.initiator.agent_id]
        if session.responder:
            parties.append(session.responder.agent_id)

        archive = TranscriptArchive(
            archive_id=f"arch_{uuid.uuid4().hex[:12]}",
            relay_session_id=relay_session_id,
            concordia_session_id=session.concordia_session_id,
            parties=parties,
            message_count=session.message_count,
            conclusion_reason=session.conclusion_reason,
            messages=[m.to_dict() for m in session.transcript],
            initiator=session.initiator.to_dict(),
            responder=session.responder.to_dict() if session.responder else None,
            retention_days=retention_days,
        )
        self._archives[archive.archive_id] = archive
        session.state = RelaySessionState.ARCHIVED
        return archive

    def get_archive(self, archive_id: str) -> TranscriptArchive | None:
        return self._archives.get(archive_id)

    def list_archives(
        self,
        agent_id: str | None = None,
        limit: int = 20,
    ) -> list[TranscriptArchive]:
        """List transcript archives, optionally filtered by participant."""
        results: list[TranscriptArchive] = []
        for archive in self._archives.values():
            if agent_id and agent_id not in archive.parties:
                continue
            results.append(archive)
        results.sort(key=lambda a: a.archived_at, reverse=True)
        return results[:limit]

    # -- Helpers -------------------------------------------------------------

    def _get_counterparty(self, session: RelaySession, agent_id: str) -> str | None:
        """Find the other party in a session."""
        if session.initiator.agent_id == agent_id:
            if session.responder and session.responder.confirmed:
                return session.responder.agent_id
            return None
        if session.responder and session.responder.agent_id == agent_id:
            if not session.responder.confirmed:
                return None
            return session.initiator.agent_id
        return None

    def _get_participant(
        self, session: RelaySession, agent_id: str
    ) -> RelayParticipant | None:
        if session.initiator.agent_id == agent_id:
            return session.initiator
        if session.responder and session.responder.agent_id == agent_id:
            return session.responder
        return None

    # -- Stats ---------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Summary statistics for the relay."""
        states: dict[str, int] = {}
        total_messages = 0
        for s in self._sessions.values():
            states[s.state.value] = states.get(s.state.value, 0) + 1
            total_messages += s.message_count

        pending_deliveries = sum(
            len(msgs) for msgs in self._mailboxes.values()
        )

        return {
            "total_sessions": len(self._sessions),
            "sessions_by_state": states,
            "total_messages_relayed": total_messages,
            "pending_deliveries": pending_deliveries,
            "total_archives": len(self._archives),
        }

    def list_sessions(
        self,
        agent_id: str | None = None,
        state: str | None = None,
        limit: int = 20,
    ) -> list[RelaySession]:
        """List relay sessions, optionally filtered."""
        results: list[RelaySession] = []
        for session in self._sessions.values():
            if state and session.state.value != state:
                continue
            if agent_id:
                is_party = (
                    session.initiator.agent_id == agent_id
                    or (session.responder and session.responder.agent_id == agent_id)
                )
                if not is_party:
                    continue
            results.append(session)
        results.sort(key=lambda s: s.created_at, reverse=True)
        return results[:limit]
