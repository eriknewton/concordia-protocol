"""Recursion-depth cap on the input sanitizers (M5).

The terms / metadata / relay-payload sanitizers recursed on attacker-controlled
nested JSON with no depth guard, so a deeply nested object drove Python toward
its recursion limit and raised RecursionError — which the MCP tools'
`except ValueError` does not catch (uncaught error / DoS). The cap rejects
input beyond MAX_SANITIZE_DEPTH before Python reaches its recursion limit.
"""

import pytest

from concordia.mcp_server import (
    _sanitize_terms,
    _sanitize_metadata,
    _sanitize_payload,
    MAX_SANITIZE_DEPTH,
)


def _nest(depth: int) -> dict:
    """A dict nested `depth` levels deep with a leaf string at the bottom."""
    d: dict = {"leaf": "value"}
    for _ in range(depth):
        d = {"k": d}
    return d


def _contains(obj, marker: str) -> bool:
    if isinstance(obj, dict):
        return any(_contains(v, marker) for v in obj.values()) or marker in obj.values()
    if isinstance(obj, list):
        return any(_contains(v, marker) for v in obj)
    return obj == marker


def test_deeply_nested_terms_rejected_before_recursion_limit():
    # ~2000 deep would raise RecursionError before the depth guard.
    with pytest.raises(ValueError, match="input nesting exceeds max depth"):
        _sanitize_terms(_nest(2000))


def test_deeply_nested_metadata_rejected_before_recursion_limit():
    with pytest.raises(ValueError, match="input nesting exceeds max depth"):
        _sanitize_metadata(_nest(2000))


def test_deeply_nested_payload_rejected_before_recursion_limit():
    with pytest.raises(ValueError, match="input nesting exceeds max depth"):
        _sanitize_payload(_nest(2000))


def test_deeply_nested_in_a_list_is_rejected():
    # Nesting reached through a list element is also depth-guarded.
    payload = {"items": [_nest(2000)]}
    with pytest.raises(ValueError, match="input nesting exceeds max depth"):
        _sanitize_payload(payload)


def test_nested_list_terms_sanitized_at_every_level():
    dirty = "alpha\x00\u200bbeta"
    terms = {"items": [[dirty], [{"note": dirty}], ["plain"]]}

    result = _sanitize_terms(terms)

    assert result == {"items": [["alphabeta"], [{"note": "alphabeta"}], ["plain"]]}


def test_nested_list_payload_sanitized_at_every_level():
    dirty = "hello\x00\u202eworld"
    payload = {"messages": [[dirty, {"inner": [dirty]}]]}

    result = _sanitize_payload(payload)

    assert result == {"messages": [["helloworld", {"inner": ["helloworld"]}]]}


def test_metadata_list_values_are_sanitized_recursively():
    dirty = "tier\x00\u200bgold"
    metadata = {"badges": [[dirty]]}

    result = _sanitize_metadata(metadata)

    assert result == {"badges": [["tiergold"]]}


def test_shallow_structure_is_preserved_unchanged():
    shallow = {"price": {"max": "100", "currency": "USD"}, "note": "ok"}
    result = _sanitize_terms(shallow)
    assert result["price"]["currency"] == "USD"
    assert result["note"] == "ok"


def test_structure_exactly_at_cap_is_not_over_truncated():
    # A structure shallower than the cap keeps its leaf.
    result = _sanitize_metadata(_nest(MAX_SANITIZE_DEPTH - 2))
    assert _contains(result, "value")  # leaf survived
