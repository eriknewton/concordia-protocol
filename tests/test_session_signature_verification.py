"""Regression tests for SEC-010: Session state machine signature verification.

Verifies that Session.apply_message() enforces mandatory signature
verification via the public_key_resolver callback, following the
SEC-005 cluster contract:
  - Resolver is a required parameter (not optional)
  - Null return from resolver → rejection (InvalidSignatureError)
  - Invalid/missing/forged signatures → rejection
  - Session state is unchanged on any rejection
"""

import base64

import pytest

from concordia import (
    Agent,
    BasicOffer,
    ChainIntegrityError,
    InvalidSignatureError,
    Session,
    SessionBindingError,
    SessionState,
)
from concordia.message import GENESIS_HASH, build_envelope
from concordia.signing import KeyPair, sign_message
from concordia.types import AgentIdentity, MessageType, PartyRole


@pytest.fixture
def keys():
    """Generate two key pairs for testing."""
    return KeyPair.generate(), KeyPair.generate()


@pytest.fixture
def session_with_parties(keys):
    """Create a session with two registered parties and their keys."""
    key_a, key_b = keys
    session = Session()
    session.add_party("agent_a", PartyRole.INITIATOR, key_a.public_key)
    session.add_party("agent_b", PartyRole.RESPONDER, key_b.public_key)

    def resolver(agent_id):
        return session._party_keys.get(agent_id)

    return session, key_a, key_b, resolver


class TestValidSignedMessageAccepted:
    """Test 1: Valid signed messages are accepted and state transitions work."""

    def test_full_negotiation_with_signatures(self):
        """End-to-end negotiation via Agent API (signatures verified internally)."""
        seller = Agent("seller")
        buyer = Agent("buyer")
        terms = {"price": {"value": 100.00, "currency": "USD"}}
        session = seller.open_session(counterparty=buyer.identity, terms=terms)
        buyer.join_session(session)

        assert session.state == SessionState.PROPOSED
        buyer.accept_session()
        assert session.state == SessionState.ACTIVE

        offer = BasicOffer(terms={"price": {"value": 90.00, "currency": "USD"}})
        buyer.send_offer(offer)
        assert session.state == SessionState.ACTIVE

        seller.accept_offer()
        assert session.state == SessionState.AGREED

    def test_apply_message_with_valid_signature(self, session_with_parties):
        """Direct apply_message with a properly signed message succeeds."""
        session, key_a, key_b, resolver = session_with_parties
        sender = AgentIdentity(agent_id="agent_a")

        msg = build_envelope(
            message_type=MessageType.OPEN,
            session_id=session.session_id,
            sender=sender,
            body={"terms": {"price": {"value": 50}}},
            key_pair=key_a,
            prev_hash=GENESIS_HASH,
        )

        state = session.apply_message(msg, resolver)
        assert state == SessionState.PROPOSED
        assert len(session.transcript) == 1


class TestForgedSignatureRejected:
    """Test 2: Forged signatures cause rejection."""

    def test_tampered_signature_rejected(self, session_with_parties):
        """A message with a modified signature is rejected."""
        session, key_a, _, resolver = session_with_parties
        sender = AgentIdentity(agent_id="agent_a")

        msg = build_envelope(
            message_type=MessageType.OPEN,
            session_id=session.session_id,
            sender=sender,
            body={"terms": {"price": {"value": 50}}},
            key_pair=key_a,
            prev_hash=GENESIS_HASH,
        )

        # Tamper with the signature — flip some bytes
        raw = base64.urlsafe_b64decode(msg["signature"])
        tampered = bytes([b ^ 0xFF for b in raw[:8]]) + raw[8:]
        msg["signature"] = base64.urlsafe_b64encode(tampered).decode()

        with pytest.raises(InvalidSignatureError, match="Invalid signature"):
            session.apply_message(msg, resolver)


class TestMissingSignatureRejected:
    """Test 3: Messages without a signature field are rejected."""

    def test_no_signature_field(self, session_with_parties):
        """A message with no 'signature' key is rejected."""
        session, key_a, _, resolver = session_with_parties
        sender = AgentIdentity(agent_id="agent_a")

        msg = build_envelope(
            message_type=MessageType.OPEN,
            session_id=session.session_id,
            sender=sender,
            body={"terms": {"price": {"value": 50}}},
            key_pair=key_a,
            prev_hash=GENESIS_HASH,
        )

        del msg["signature"]

        with pytest.raises(InvalidSignatureError, match="missing 'signature'"):
            session.apply_message(msg, resolver)

    def test_empty_signature_string(self, session_with_parties):
        """A message with an empty signature string is rejected."""
        session, key_a, _, resolver = session_with_parties
        sender = AgentIdentity(agent_id="agent_a")

        msg = build_envelope(
            message_type=MessageType.OPEN,
            session_id=session.session_id,
            sender=sender,
            body={"terms": {"price": {"value": 50}}},
            key_pair=key_a,
            prev_hash=GENESIS_HASH,
        )

        msg["signature"] = ""

        with pytest.raises(InvalidSignatureError, match="missing 'signature'"):
            session.apply_message(msg, resolver)


class TestUnknownAgentRejected:
    """Test 4: Messages from an agent_id the resolver doesn't recognize."""

    def test_unknown_agent_id_rejected(self, session_with_parties):
        """A message from an unregistered agent is rejected."""
        session, _, _, resolver = session_with_parties
        unknown_key = KeyPair.generate()
        sender = AgentIdentity(agent_id="agent_unknown")

        msg = build_envelope(
            message_type=MessageType.OPEN,
            session_id=session.session_id,
            sender=sender,
            body={"terms": {"price": {"value": 50}}},
            key_pair=unknown_key,
            prev_hash=GENESIS_HASH,
        )

        with pytest.raises(InvalidSignatureError, match="Unknown agent identity"):
            session.apply_message(msg, resolver)


class TestResolverReturningNone:
    """Test 5: Resolver returning None causes rejection (cluster contract)."""

    def test_none_resolver_rejects(self, session_with_parties):
        """A resolver that always returns None rejects all messages."""
        session, key_a, _, _ = session_with_parties
        sender = AgentIdentity(agent_id="agent_a")

        msg = build_envelope(
            message_type=MessageType.OPEN,
            session_id=session.session_id,
            sender=sender,
            body={"terms": {"price": {"value": 50}}},
            key_pair=key_a,
            prev_hash=GENESIS_HASH,
        )

        null_resolver = lambda agent_id: None

        with pytest.raises(InvalidSignatureError, match="resolver returned None"):
            session.apply_message(msg, null_resolver)


class TestWrongKeyRejected:
    """Test 6: Message signed with key A but resolver returns key B."""

    def test_wrong_public_key_rejects(self, session_with_parties):
        """Signing with one key but verifying with another fails."""
        session, key_a, key_b, _ = session_with_parties
        sender = AgentIdentity(agent_id="agent_a")

        # Sign with key_a
        msg = build_envelope(
            message_type=MessageType.OPEN,
            session_id=session.session_id,
            sender=sender,
            body={"terms": {"price": {"value": 50}}},
            key_pair=key_a,
            prev_hash=GENESIS_HASH,
        )

        # Resolver returns key_b's public key for agent_a
        wrong_resolver = lambda agent_id: key_b.public_key

        with pytest.raises(InvalidSignatureError, match="Invalid signature"):
            session.apply_message(msg, wrong_resolver)


class TestStateUnchangedOnRejection:
    """Test 7: Session state is unchanged after any signature rejection."""

    def test_state_unchanged_on_forged_signature(self, session_with_parties):
        """Session state, transcript, and round count unchanged on rejection."""
        session, key_a, key_b, resolver = session_with_parties
        sender_a = AgentIdentity(agent_id="agent_a")

        # Apply a valid OPEN message first
        open_msg = build_envelope(
            message_type=MessageType.OPEN,
            session_id=session.session_id,
            sender=sender_a,
            body={"terms": {"price": {"value": 50}}},
            key_pair=key_a,
            prev_hash=GENESIS_HASH,
        )
        session.apply_message(open_msg, resolver)

        # Snapshot state
        state_before = session.state
        transcript_len_before = len(session.transcript)
        round_count_before = session.round_count

        # Try to apply a message with forged signature
        sender_b = AgentIdentity(agent_id="agent_b")
        accept_msg = build_envelope(
            message_type=MessageType.ACCEPT_SESSION,
            session_id=session.session_id,
            sender=sender_b,
            body={},
            key_pair=key_b,
            prev_hash=session.prev_hash,
        )
        # Forge the signature
        accept_msg["signature"] = base64.urlsafe_b64encode(b"\x00" * 64).decode()

        with pytest.raises(InvalidSignatureError):
            session.apply_message(accept_msg, resolver)

        # Verify nothing changed
        assert session.state == state_before
        assert len(session.transcript) == transcript_len_before
        assert session.round_count == round_count_before

    def test_state_unchanged_on_missing_from(self):
        """Message with no 'from' field rejected, state unchanged."""
        session = Session()

        state_before = session.state
        transcript_len_before = len(session.transcript)

        msg = {"type": "negotiate.open", "body": {}, "signature": "abc"}
        resolver = lambda agent_id: None

        with pytest.raises(InvalidSignatureError, match="missing 'from.agent_id'"):
            session.apply_message(msg, resolver)

        assert session.state == state_before
        assert len(session.transcript) == transcript_len_before


class TestCrossSessionReplayRejected:
    """H3: a validly-signed message bound to session A must not be replayable
    into a different Session object between the same parties."""

    def test_cross_session_replay_rejected(self, keys):
        key_a, key_b = keys

        def make_session():
            s = Session()
            s.add_party("agent_a", PartyRole.INITIATOR, key_a.public_key)
            s.add_party("agent_b", PartyRole.RESPONDER, key_b.public_key)
            return s

        session_a = make_session()
        session_b = make_session()
        assert session_a.session_id != session_b.session_id
        resolver_b = lambda agent_id: session_b._party_keys.get(agent_id)

        # A genuinely valid OPEN message for session_a.
        msg = build_envelope(
            message_type=MessageType.OPEN,
            session_id=session_a.session_id,
            sender=AgentIdentity(agent_id="agent_a"),
            body={"terms": {"price": {"value": 50}}},
            key_pair=key_a,
            prev_hash=GENESIS_HASH,
        )

        # Signature is valid and agent_a is a party of B — but the message is
        # bound to session_a, so applying it to session_b must be rejected.
        with pytest.raises(SessionBindingError):
            session_b.apply_message(msg, resolver_b)
        assert len(session_b.transcript) == 0  # nothing appended


class TestChainTipBinding:
    """H3: prev_hash must chain to the live transcript tip at append time, not
    merely be advisory in validate_chain()."""

    def test_stale_prev_hash_rejected(self, session_with_parties):
        session, key_a, key_b, resolver = session_with_parties

        open_msg = build_envelope(
            message_type=MessageType.OPEN,
            session_id=session.session_id,
            sender=AgentIdentity(agent_id="agent_a"),
            body={"terms": {}},
            key_pair=key_a,
            prev_hash=GENESIS_HASH,
        )
        session.apply_message(open_msg, resolver)
        assert len(session.transcript) == 1

        # A validly-signed ACCEPT_SESSION whose prev_hash still points at
        # genesis (not the OPEN message tip) — a forked / out-of-order link.
        bad = build_envelope(
            message_type=MessageType.ACCEPT_SESSION,
            session_id=session.session_id,
            sender=AgentIdentity(agent_id="agent_b"),
            body={},
            key_pair=key_b,
            prev_hash=GENESIS_HASH,  # WRONG: should be hash of open_msg
        )
        with pytest.raises(ChainIntegrityError):
            session.apply_message(bad, resolver)
        assert session.state == SessionState.PROPOSED  # unchanged
        assert len(session.transcript) == 1  # not appended

    def test_correctly_chained_message_accepted(self, session_with_parties):
        session, key_a, key_b, resolver = session_with_parties

        open_msg = build_envelope(
            message_type=MessageType.OPEN,
            session_id=session.session_id,
            sender=AgentIdentity(agent_id="agent_a"),
            body={"terms": {}},
            key_pair=key_a,
            prev_hash=GENESIS_HASH,
        )
        session.apply_message(open_msg, resolver)

        accept = build_envelope(
            message_type=MessageType.ACCEPT_SESSION,
            session_id=session.session_id,
            sender=AgentIdentity(agent_id="agent_b"),
            body={},
            key_pair=key_b,
            prev_hash=session.prev_hash,  # correct tip
        )
        state = session.apply_message(accept, resolver)
        assert state == SessionState.ACTIVE
        assert len(session.transcript) == 2
