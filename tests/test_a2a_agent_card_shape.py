"""The Agent Card fragment must match the A2A extension mechanism, not our own shape.

WHY THIS FILE EXISTS. `RegisteredAgent.to_agent_card()` advertised itself as
"A2A-compatible" while emitting `capabilities` as an ARRAY of Concordia's own
capability dict. A2A's `capabilities` is an OBJECT holding an `extensions` array
of `AgentExtension` entries, so a card in the old shape parsed as having no
capabilities at all and Concordia was undiscoverable through the very mechanism
the method exists to use.

Nothing caught it because nothing tested it: the method had no test, and its
docstring cited SPEC.md section 10.1, which still described the pre-extension
shape. The code was faithful to a stale spec rather than to A2A.

These tests pin the SHAPE, which is the part that has to agree with somebody
else's parser. They are deliberately literal about field names.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from concordia.registry import (
    A2A_EXTENSION_URI,
    AgentCapabilities,
    RegisteredAgent,
)


def _card() -> dict:
    return RegisteredAgent(
        agent_id="seller-1",
        capabilities=AgentCapabilities(categories=["electronics"]),
    ).to_agent_card()


def test_capabilities_is_an_object_not_an_array() -> None:
    """The regression itself. An array here is unreadable to an A2A client."""
    card = _card()
    assert isinstance(card["capabilities"], dict), (
        "A2A `capabilities` is an AgentCapabilities OBJECT; emitting a list "
        "makes the card parse as having no capabilities"
    )
    assert not isinstance(card["capabilities"], list)


def test_declares_exactly_one_extension_under_the_pinned_uri() -> None:
    extensions = _card()["capabilities"]["extensions"]
    assert isinstance(extensions, list)
    assert len(extensions) == 1
    assert extensions[0]["uri"] == A2A_EXTENSION_URI


def test_extension_entry_carries_the_agent_extension_fields() -> None:
    entry = _card()["capabilities"]["extensions"][0]
    for field in ("uri", "description", "required", "params"):
        assert field in entry, f"AgentExtension field `{field}` missing"
    assert isinstance(entry["description"], str) and entry["description"]
    assert isinstance(entry["params"], dict)


def test_the_extension_is_not_marked_required() -> None:
    """A2A reserves `required: true` for extensions fundamental to the agent's
    core function or security, because a client that does not understand a
    required extension cannot talk to the agent at all. An agent that cannot
    negotiate should still be reachable."""
    assert _card()["capabilities"]["extensions"][0]["required"] is False


def test_matching_facets_survive_into_params() -> None:
    """The old shape's one virtue was that a counterparty could read the
    matching facets of section 7 off the card. They move into `params` rather
    than being dropped."""
    params = _card()["capabilities"]["extensions"][0]["params"]
    assert params["categories"] == ["electronics"]
    assert "roles" in params and "resolution_mechanisms" in params


def test_the_uri_is_not_under_the_official_a2a_namespace() -> None:
    """`https://a2a-protocol.org/extensions/` is reserved for artifacts that
    have graduated to official status in `a2aproject`. No Concordia extension
    has been filed or sponsored, so claiming that prefix would assert standing
    Concordia does not have."""
    assert not A2A_EXTENSION_URI.startswith("https://a2a-protocol.org/")
    assert A2A_EXTENSION_URI.startswith("https://concordiaprotocol.dev/")


def test_the_card_is_json_serializable() -> None:
    json.loads(json.dumps(_card()))


def test_spec_and_code_agree_on_the_uri() -> None:
    """CROSS-FILE CONTRACT. SPEC.md section 10.1 and `A2A_EXTENSION_URI` are one
    contract; a reader who copies the URI out of the spec must get the URI the
    code emits. This is the pin that catches an edit to one side only."""
    spec = (Path(__file__).resolve().parents[1] / "SPEC.md").read_text(encoding="utf-8")
    section = spec.split("### 10.1 A2A")[1].split("### 10.2")[0]
    uris = set(re.findall(r"https://concordiaprotocol\.dev/a2a-ext/[^\s\"`)]+", section))
    assert uris == {A2A_EXTENSION_URI}, (
        f"SPEC.md section 10.1 declares {uris or 'no URI'}; "
        f"registry.py declares {A2A_EXTENSION_URI}"
    )
