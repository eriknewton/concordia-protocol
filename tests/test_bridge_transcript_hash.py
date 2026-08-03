"""The Sanctuary bridge must emit a real transcript commitment, not None.

Regression test for the 2026-08-02 differential finding: the derivation read
`previous_hash`, but messages carry `prev_hash` (message.py:68), so
`.get()` silently returned None on every session and the bridge published a
null where a session commitment belongs. A field-name typo with no test is
invisible; this test is the missing check.
"""

from __future__ import annotations

import json

from concordia import Agent, BasicOffer
from concordia.message import compute_hash


def _agreed_session_transcript() -> list[dict]:
    seller = Agent("bridge_hash_seller")
    buyer = Agent("bridge_hash_buyer")
    terms = {"price": {"value": 10.0, "currency": "USD"}, "qty": {"value": 2}}
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    buyer.accept_session()
    seller.send_offer(BasicOffer(terms=terms))
    buyer.accept_offer()
    assert session.state.value == "agreed"
    return session.transcript


def test_transcript_hash_is_the_chain_head_not_none() -> None:
    transcript = _agreed_session_transcript()
    expected = compute_hash(transcript[-1])

    assert expected.startswith("sha256:")
    # The chain head commits the FINAL message (the acceptance), which the
    # predecessor-pointer `prev_hash` of that message does not.
    assert expected != transcript[-1]["prev_hash"]


def test_chain_head_changes_when_any_message_changes() -> None:
    """A commitment that cannot move is not a commitment."""
    transcript = _agreed_session_transcript()
    head = compute_hash(transcript[-1])

    tampered = json.loads(json.dumps(transcript[-1]))
    tampered["body"] = {**tampered.get("body", {}), "__tamper__": "x"}

    assert compute_hash(tampered) != head


def test_bridge_commit_emits_a_non_null_chain_head_end_to_end(make_agent) -> None:
    """The REAL producer: drive the actual MCP tool and read what it publishes.

    The helper-level tests above would pass even with the defect present,
    because the defect lived in the tool's derivation rather than in
    compute_hash. This test fails without the fix (it published None).
    """
    from concordia import mcp_server
    from concordia.mcp_server import handle_tool_call

    from tests.conftest import run_negotiation

    a = make_agent("e2e_bridge_seller")
    b = make_agent("e2e_bridge_buyer")

    config = handle_tool_call(
        "concordia_sanctuary_bridge_configure",
        {
            "agent_id": a.agent_id,
            "auth_token": a.auth_token,
            "enabled": True,
            "identity_mappings": [
                {"agent_id": a.agent_id, "sanctuary_id": "s1", "did": "did:sanc:s1"},
                {"agent_id": b.agent_id, "sanctuary_id": "s2", "did": "did:sanc:s2"},
            ],
        },
    )
    assert config.get("enabled"), config

    ctx = run_negotiation(a, b)
    session_id = ctx["session_id"]

    commit = handle_tool_call(
        "concordia_sanctuary_bridge_commit",
        {"session_id": session_id, "auth_token": ctx["init_token"]},
    )
    assert "error" not in commit, commit

    stored = mcp_server._store.get(session_id)
    expected = compute_hash(stored.session.transcript[-1])
    published = json.dumps(commit)

    assert expected.startswith("sha256:")
    assert expected in published, (
        "bridge commit payload does not carry the chain head; expected "
        f"{expected} in {published[:400]}"
    )


def test_bridge_derivation_uses_the_real_field_name() -> None:
    """`previous_hash` does not exist on a message; `prev_hash` does."""
    transcript = _agreed_session_transcript()
    last = transcript[-1]

    assert last.get("previous_hash") is None
    assert isinstance(last.get("prev_hash"), str)
    assert last["prev_hash"].startswith("sha256:")
