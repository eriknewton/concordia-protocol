"""Shared fixtures for Concordia integration tests."""

from __future__ import annotations

import os
import tempfile

# Isolate persisted session tokens in a per-test-run temp file so that
# running the suite never touches ~/.concordia/sessions.json on dev machines.
os.environ.setdefault(
    "CONCORDIA_SESSION_STORE",
    os.path.join(tempfile.gettempdir(), "concordia-test-sessions.json"),
)

from dataclasses import dataclass, field
from typing import Any

import pytest

from concordia.mcp_server import (
    handle_tool_call,
    _store,
    _auth,
    _attestation_store,
    _registry,
    _want_registry,
    _relay,
    _interaction_mgr,
    _bridge_config,
    _key_registry,
    _bundle_store,
    _scorer,
)
from concordia.signing import KeyPair


@dataclass
class SimulatedAgent:
    """An agent with its own identity, keys, and auth context."""
    agent_id: str
    key_pair: KeyPair
    auth_token: str  # agent-scoped token
    session_tokens: dict[str, str] = field(default_factory=dict)  # session_id -> token
    receipt_bundles: list[dict] = field(default_factory=list)

    def call_tool(self, name: str, **kwargs: Any) -> dict:
        """Call an MCP tool as this agent, injecting auth."""
        return handle_tool_call(name, kwargs)


@pytest.fixture
def make_agent():
    """Factory fixture that creates a SimulatedAgent with fresh keys and registers it."""

    def _make(agent_id: str, categories: list[str] | None = None) -> SimulatedAgent:
        kp = KeyPair.generate()
        # Register in the agent registry to get an auth token
        result = handle_tool_call("concordia_register_agent", {
            "agent_id": agent_id,
            "categories": categories or ["general"],
        })
        assert "error" not in result, f"Failed to register agent '{agent_id}': {result}"
        auth_token = result["auth_token"]
        return SimulatedAgent(
            agent_id=agent_id,
            key_pair=kp,
            auth_token=auth_token,
        )

    return _make


@pytest.fixture(autouse=True)
def clean_all_state(request):
    """Reset all global stores before each integration test."""
    # Only clean for integration tests or tests that use make_agent
    if "make_agent" not in request.fixturenames and not any(
        marker.name == "integration" for marker in request.node.iter_markers()
    ):
        yield
        return
    _store._sessions.clear()
    _auth._agent_tokens.clear()
    _auth._token_to_agent.clear()
    _auth._session_tokens.clear()
    _attestation_store._by_id.clear()
    _attestation_store._by_session.clear()
    _attestation_store._by_agent.clear()
    _attestation_store._counterparties.clear()
    _registry._agents.clear()
    _want_registry._wants.clear()
    _want_registry._haves.clear()
    _want_registry._matches.clear()
    _want_registry._agent_wants.clear()
    _want_registry._agent_haves.clear()
    _relay._sessions.clear()
    _relay._archives.clear()
    _relay._mailboxes.clear()
    _interaction_mgr._proposals.clear()
    _interaction_mgr._interactions.clear()
    _bridge_config.enabled = False
    _bridge_config.identity_map.clear()
    _bridge_config.did_map.clear()
    _key_registry.clear()
    _bundle_store._bundles.clear()
    _bundle_store._by_agent.clear()
    yield


def run_negotiation(
    agent_a: SimulatedAgent,
    agent_b: SimulatedAgent,
    terms: dict | None = None,
    rounds: int = 3,
    category: str = "electronics",
) -> dict[str, Any]:
    """Execute a complete negotiation and return the session context.

    Returns a dict with session_id, tokens, receipt, attestation.
    """
    if terms is None:
        terms = {
            "price": {"type": "numeric", "label": "Price USD", "unit": "USD"},
            "delivery": {"type": "string", "label": "Delivery timeline"},
        }

    # Open session
    result = handle_tool_call("concordia_open_session", {
        "initiator_id": agent_a.agent_id,
        "responder_id": agent_b.agent_id,
        "terms": terms,
    })
    session_id = result["session_id"]
    init_token = result["initiator_token"]
    resp_token = result["responder_token"]

    agent_a.session_tokens[session_id] = init_token
    agent_b.session_tokens[session_id] = resp_token

    # Multi-round negotiation
    prices = [1000, 800, 900]  # A proposes, B counters, A counters
    for i in range(min(rounds, len(prices))):
        if i % 2 == 0:
            # Initiator proposes/counters
            tool = "concordia_propose" if i == 0 else "concordia_counter"
            handle_tool_call(tool, {
                "session_id": session_id,
                "role": "initiator",
                "terms": {"price": {"value": prices[i]}, "delivery": {"value": "2 weeks"}},
                "auth_token": init_token,
                "reasoning": f"Round {i+1} offer from {agent_a.agent_id}",
            })
        else:
            handle_tool_call("concordia_counter", {
                "session_id": session_id,
                "role": "responder",
                "terms": {"price": {"value": prices[i]}, "delivery": {"value": "3 weeks"}},
                "auth_token": resp_token,
                "reasoning": f"Round {i+1} counter from {agent_b.agent_id}",
            })

    # Accept
    handle_tool_call("concordia_accept", {
        "session_id": session_id,
        "role": "responder",
        "auth_token": resp_token,
        "reasoning": "Terms acceptable",
    })

    # Generate receipt
    receipt_result = handle_tool_call("concordia_session_receipt", {
        "session_id": session_id,
        "auth_token": init_token,
        "category": category,
    })
    attestation = receipt_result.get("receipt", {})

    # Ingest attestation for both parties
    for agent in [agent_a, agent_b]:
        handle_tool_call("concordia_ingest_attestation", {
            "agent_id": agent.agent_id,
            "attestation": attestation,
            "auth_token": agent.auth_token,
        })

    return {
        "session_id": session_id,
        "init_token": init_token,
        "resp_token": resp_token,
        "attestation": attestation,
    }


def populated_reputation(
    agent: SimulatedAgent,
    make_agent_fn,
    n_sessions: int = 5,
) -> list[dict]:
    """Run N negotiations with random counterparties to build reputation."""
    results = []
    for i in range(n_sessions):
        counterparty = make_agent_fn(f"counterparty_{agent.agent_id}_{i}")
        ctx = run_negotiation(agent, counterparty, category=f"cat_{i % 3}")
        results.append(ctx)
    return results
