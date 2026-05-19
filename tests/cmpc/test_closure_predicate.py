"""Fixture coverage for CMPC closure-predicate evaluation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import pathlib

import pytest

from concordia.cmpc import ClosurePredicate, evaluate_predicate
from concordia.cmpc.chain_session import ChainSession, ChainSessionState


FIXTURE_DIR = (
    pathlib.Path(__file__).parent.parent
    / "fixtures"
    / "cmpc_bilateral"
    / "predicates"
)


def test_unknown_predicate_type_unsatisfied() -> None:
    predicate = ClosurePredicate(
        predicate_id="p1",
        type_urn="urn:concordia:predicate-type:nonexistent:v1",
        parameters={},
    )
    result = evaluate_predicate(predicate, _make_session(), [])
    assert result.result == "unsatisfied"
    assert "unknown_predicate_type" in (result.reason or "")


@pytest.mark.parametrize("fixture_path", sorted(FIXTURE_DIR.glob("*.json")))
def test_fixture(fixture_path: pathlib.Path) -> None:
    fixture = json.loads(fixture_path.read_text())
    predicate = ClosurePredicate(**fixture["predicate"])
    result = evaluate_predicate(predicate, _make_session(), fixture["commitments"])
    assert result.result == fixture["expected_result"]
    if fixture.get("expected_reason"):
        assert fixture["expected_reason"] in (result.reason or "")


def _make_session() -> ChainSession:
    now = datetime.now(timezone.utc)
    return ChainSession(
        chain_session_id="urn:concordia:chain-session:test",
        participants=["did:web:r.test", "did:web:w.test"],
        closure_predicate_ref="urn:concordia:predicate:test",
        state=ChainSessionState.OPEN,
        created_at=now,
        activation_deadline=now + timedelta(hours=1),
    )
