from __future__ import annotations

from typing import Any

import pytest

from concordia.agent import Agent
from concordia.message import build_envelope
from concordia.session import Session
from concordia.signing import KeyPair
from concordia.types import (
    AgentIdentity,
    Flexibility,
    MessageType,
    PreferenceSignal,
    SessionState,
)


def _capture_send(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_send(
        self: Agent,
        msg_type: MessageType,
        body: dict[str, Any],
        recipients: list[AgentIdentity] | None = None,
        reasoning: str | None = None,
    ) -> dict[str, Any]:
        call = {
            "type": msg_type,
            "body": body,
            "recipients": recipients,
            "reasoning": reasoning,
        }
        calls.append(call)
        return call

    monkeypatch.setattr(Agent, "_send", fake_send)
    return calls


def test_decline_reject_accept_and_withdraw_optional_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _capture_send(monkeypatch)
    agent = Agent("agent-a")
    agent.session = Session()

    assert agent.decline_session() == calls[-1]
    assert calls[-1]["body"] == {}
    assert calls[-1]["type"] is MessageType.DECLINE_SESSION

    agent.decline_session(reason="not a fit", reasoning="policy")
    assert calls[-1]["body"] == {"reason": "not a fit"}
    assert calls[-1]["reasoning"] == "policy"

    agent.accept_offer()
    assert calls[-1]["body"] == {}
    agent.accept_offer(offer_id="offer-a")
    assert calls[-1]["body"] == {"offer_id": "offer-a"}

    agent.reject_offer()
    assert calls[-1]["body"] == {}
    agent.reject_offer(reason="price")
    assert calls[-1]["body"] == {"reason": "price"}

    agent.withdraw()
    assert calls[-1]["body"] == {"reactivatable": False}
    agent.session.state = SessionState.REJECTED
    agent.withdraw(reason="pause", reactivatable=True)
    assert calls[-1]["body"] == {"reactivatable": True, "reason": "pause"}
    assert agent.session.state is SessionState.DORMANT


def test_signal_includes_only_present_preference_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _capture_send(monkeypatch)
    agent = Agent("agent-a")
    agent.session = Session()

    agent.signal(
        PreferenceSignal(
            priority_ranking=["price", "delivery"],
            flexibility={"price": Flexibility.FIRM},
            aspiration={"price": 100},
            reservation={"price": 150},
        ),
        reasoning="share preference",
    )

    assert calls[-1] == {
        "type": MessageType.SIGNAL,
        "body": {
            "priority_ranking": ["price", "delivery"],
            "flexibility": {"price": "firm"},
            "aspiration": {"price": 100},
            "reservation": {"price": 150},
        },
        "recipients": None,
        "reasoning": "share preference",
    }

    agent.signal(PreferenceSignal())
    assert calls[-1]["body"] == {}


def test_open_session_adds_timing_and_recipient_to_open_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _capture_send(monkeypatch)
    agent = Agent("initiator")
    counterparty = AgentIdentity("responder", principal_id="principal-b")

    session = agent.open_session(
        counterparty=counterparty,
        terms={"price": {"value": 100}},
        reasoning="start",
    )

    assert agent.session is session
    assert calls[-1]["type"] is MessageType.OPEN
    assert calls[-1]["body"] == {"terms": {"price": {"value": 100}}}
    assert calls[-1]["recipients"] == [counterparty]
    assert calls[-1]["reasoning"] == "start"


@pytest.mark.parametrize(
    ("method_name", "args", "expected_type", "expected_body"),
    [
        ("accept_session", (), MessageType.ACCEPT_SESSION, {}),
        ("inquire", (["price"],), MessageType.INQUIRE, {"term_ids": ["price"]}),
        ("constrain", ({"price": {"max": 100}},), MessageType.CONSTRAIN, {"constraints": {"price": {"max": 100}}}),
        ("propose_mediator", ("mediator-a",), MessageType.PROPOSE_MEDIATOR, {"mediator_id": "mediator-a"}),
        ("resolve", ({"price": {"value": 100}},), MessageType.RESOLVE, {"terms": {"price": {"value": 100}}, "mechanism": "split"}),
        ("commit", (), MessageType.COMMIT, {}),
    ],
)
def test_simple_message_helpers_delegate_expected_payloads(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    args: tuple[Any, ...],
    expected_type: MessageType,
    expected_body: dict[str, Any],
) -> None:
    calls = _capture_send(monkeypatch)
    agent = Agent("agent-a")
    agent.session = Session()

    getattr(agent, method_name)(*args)

    assert calls[-1]["type"] is expected_type
    assert calls[-1]["body"] == expected_body


def test_send_requires_active_session() -> None:
    agent = Agent("agent-a")

    with pytest.raises(RuntimeError, match="No active session"):
        agent.accept_session()


def test_generate_attestation_requires_active_session() -> None:
    agent = Agent("agent-a")

    with pytest.raises(RuntimeError, match="No active session"):
        agent.generate_attestation({})


def test_public_key_resolver_handles_self_counterparty_and_unknown() -> None:
    agent = Agent("agent-a")
    peer_key = KeyPair.generate().public_key
    agent.session = Session()
    agent.session._party_keys["peer"] = peer_key

    assert agent._public_key_resolver("agent-a") is agent.key_pair.public_key
    assert agent._public_key_resolver("peer") is peer_key
    assert agent._public_key_resolver("missing") is None

    agent.session = None
    assert agent._public_key_resolver("peer") is None


def test_verify_message_returns_true_for_matching_signature_and_false_for_tamper() -> None:
    key_pair = KeyPair.generate()
    sender = Agent("sender", key_pair=key_pair)
    message = build_envelope(
        message_type=MessageType.INQUIRE,
        session_id="session-a",
        sender=sender.identity,
        body={"term_ids": ["price"]},
        key_pair=key_pair,
        message_id="msg-a",
    )

    assert sender.verify_message(message, key_pair.public_key)

    tampered = {**message, "body": {"term_ids": ["delivery"]}}
    assert not sender.verify_message(tampered, key_pair.public_key)
