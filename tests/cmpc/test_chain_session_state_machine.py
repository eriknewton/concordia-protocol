"""CMPC ChainSession state-machine tests."""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from concordia.cmpc import (
    ChainSession,
    ChainSessionState,
    InvalidTransitionError,
    verify_transcript,
)


FIXTURE_DIR = (
    pathlib.Path(__file__).parent.parent
    / "fixtures"
    / "cmpc_bilateral"
    / "state_machine"
)


def _make_session(**overrides: Any) -> ChainSession:
    now = datetime.now(timezone.utc)
    base: dict[str, Any] = {
        "chain_session_id": "urn:concordia:chain-session:test",
        "participants": ["did:web:r.test", "did:web:w.test"],
        "closure_predicate_ref": "urn:concordia:predicate:test",
        "state": ChainSessionState.PROPOSED,
        "created_at": now,
        "activation_deadline": now + timedelta(hours=1),
        "commitments": ["urn:c:1", "urn:c:2"],
    }
    base.update(overrides)
    return ChainSession(**base)


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _session_from_fixture(data: dict[str, Any]) -> ChainSession:
    initial = dict(data["initial_session"])
    for key in ("created_at", "activation_deadline", "activated_at", "dissolved_at"):
        if key in initial and initial[key] is not None:
            initial[key] = _parse_dt(initial[key])
    return _make_session(**initial)


def test_proposed_to_open_happy() -> None:
    session = _make_session()
    session.transition_to(ChainSessionState.OPEN)
    assert session.state == ChainSessionState.OPEN
    assert len(session.transitions) == 1


def test_proposed_to_open_missing_commitments() -> None:
    session = _make_session(commitments=[])
    with pytest.raises(InvalidTransitionError):
        session.transition_to(ChainSessionState.OPEN)


def test_open_to_activated_happy() -> None:
    session = _make_session(
        state=ChainSessionState.OPEN,
        activation_proof_id="urn:concordia:activation-proof:1",
    )
    session.transition_to(ChainSessionState.ACTIVATED)
    assert session.state == ChainSessionState.ACTIVATED
    assert session.activated_at is not None


def test_open_to_activated_missing_proof() -> None:
    session = _make_session(state=ChainSessionState.OPEN)
    with pytest.raises(InvalidTransitionError):
        session.transition_to(ChainSessionState.ACTIVATED)


def test_open_to_activated_past_deadline() -> None:
    now = datetime.now(timezone.utc)
    session = _make_session(
        state=ChainSessionState.OPEN,
        activation_proof_id="urn:concordia:activation-proof:1",
        activation_deadline=now - timedelta(hours=1),
    )
    with pytest.raises(InvalidTransitionError):
        session.transition_to(ChainSessionState.ACTIVATED, now=now)


def test_open_to_dissolved_happy() -> None:
    session = _make_session(
        state=ChainSessionState.OPEN,
        unwind_record_id="urn:concordia:unwind:1",
    )
    session.transition_to(ChainSessionState.DISSOLVED)
    assert session.state == ChainSessionState.DISSOLVED
    assert session.dissolved_at is not None


def test_open_to_dissolved_missing_unwind_record() -> None:
    session = _make_session(state=ChainSessionState.OPEN)
    with pytest.raises(InvalidTransitionError):
        session.transition_to(ChainSessionState.DISSOLVED)


def test_open_to_expired_happy() -> None:
    now = datetime.now(timezone.utc)
    session = _make_session(
        state=ChainSessionState.OPEN,
        activation_deadline=now - timedelta(hours=1),
    )
    session.transition_to(ChainSessionState.EXPIRED, now=now)
    assert session.state == ChainSessionState.EXPIRED
    assert session.dissolved_at is not None


def test_open_to_expired_rejects_before_deadline() -> None:
    now = datetime.now(timezone.utc)
    session = _make_session(
        state=ChainSessionState.OPEN,
        activation_deadline=now + timedelta(hours=1),
    )
    with pytest.raises(InvalidTransitionError):
        session.transition_to(ChainSessionState.EXPIRED, now=now)


def test_open_to_expired_rejects_activation_proof() -> None:
    now = datetime.now(timezone.utc)
    session = _make_session(
        state=ChainSessionState.OPEN,
        activation_deadline=now - timedelta(hours=1),
        activation_proof_id="urn:concordia:activation-proof:1",
    )
    with pytest.raises(InvalidTransitionError):
        session.transition_to(ChainSessionState.EXPIRED, now=now)


def test_expire_due_to_timeout_records_timeout_evidence() -> None:
    now = datetime.now(timezone.utc)
    session = _make_session(
        state=ChainSessionState.OPEN,
        activation_deadline=now - timedelta(hours=1),
    )
    session.expire_due_to_timeout(now=now)
    assert session.state == ChainSessionState.EXPIRED
    assert session.transitions[-1].evidence == {"reason": "activation_timeout"}


def test_terminal_states_reject_transitions() -> None:
    terminal_states = (
        ChainSessionState.ACTIVATED,
        ChainSessionState.DISSOLVED,
        ChainSessionState.EXPIRED,
    )
    target_states = (
        ChainSessionState.PROPOSED,
        ChainSessionState.OPEN,
        ChainSessionState.ACTIVATED,
        ChainSessionState.DISSOLVED,
        ChainSessionState.EXPIRED,
    )
    for terminal in terminal_states:
        session = _make_session(state=terminal)
        for target in target_states:
            if target == terminal:
                continue
            with pytest.raises(InvalidTransitionError):
                session.transition_to(target)


def test_transcript_chain_intact() -> None:
    session = _make_session()
    session.transition_to(ChainSessionState.OPEN)
    session.activation_proof_id = "urn:concordia:activation-proof:1"
    session.transition_to(ChainSessionState.ACTIVATED)
    assert verify_transcript(session)
    assert session.transitions[1].prev_transition_hash == session.transitions[0].transition_hash


def test_transcript_tamper_detected() -> None:
    session = _make_session()
    session.transition_to(ChainSessionState.OPEN)
    session.activation_proof_id = "urn:concordia:activation-proof:1"
    session.transition_to(ChainSessionState.ACTIVATED)
    session.transitions[0].evidence = {"tampered": True}
    assert not verify_transcript(session)


def test_transcript_prev_hash_tamper_detected() -> None:
    session = _make_session()
    session.transition_to(ChainSessionState.OPEN)
    session.activation_proof_id = "urn:concordia:activation-proof:1"
    session.transition_to(ChainSessionState.ACTIVATED)
    session.transitions[1].prev_transition_hash = "not-the-previous-hash"
    assert not verify_transcript(session)


def test_fixture_transition_matrix() -> None:
    fixture_paths = sorted(FIXTURE_DIR.glob("*.json"))
    assert len(fixture_paths) == 10
    for fixture_path in fixture_paths:
        fixture = json.loads(fixture_path.read_text())
        session = _session_from_fixture(fixture)
        target = ChainSessionState(fixture["attempt_transition"])
        transition_now = _parse_dt(fixture["transition_now"])

        if fixture["expected"] == "ok":
            session.transition_to(target, now=transition_now)
            assert session.state == target
            assert verify_transcript(session)
        else:
            with pytest.raises(InvalidTransitionError):
                session.transition_to(target, now=transition_now)
