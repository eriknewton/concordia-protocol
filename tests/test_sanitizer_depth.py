"""Recursion-depth cap on the input sanitizers (M5).

The terms / metadata / relay-payload sanitizers recursed on attacker-controlled
nested JSON with no depth guard, so a deeply nested object drove Python toward
its recursion limit and raised RecursionError — which the MCP tools'
`except ValueError` does not catch (uncaught error / DoS). The cap truncates
beyond MAX_SANITIZE_DEPTH (fail closed by truncation), never raising.
"""

from concordia.mcp_server import (
    _sanitize_terms,
    _sanitize_metadata,
    _sanitize_payload,
    MAX_SANITIZE_DEPTH,
    _DEPTH_TRUNCATED,
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


def test_deeply_nested_terms_truncates_without_raising():
    # ~2000 deep would raise RecursionError before the fix.
    result = _sanitize_terms(_nest(2000))
    assert _contains(result, _DEPTH_TRUNCATED)


def test_deeply_nested_metadata_truncates_without_raising():
    result = _sanitize_metadata(_nest(2000))
    assert _contains(result, _DEPTH_TRUNCATED)


def test_deeply_nested_payload_truncates_without_raising():
    result = _sanitize_payload(_nest(2000))
    assert _contains(result, _DEPTH_TRUNCATED)


def test_deeply_nested_in_a_list_is_capped():
    # Nesting reached through a list element is also depth-guarded.
    payload = {"items": [_nest(2000)]}
    result = _sanitize_payload(payload)
    assert _contains(result, _DEPTH_TRUNCATED)


def test_shallow_structure_is_preserved_unchanged():
    shallow = {"price": {"max": "100", "currency": "USD"}, "note": "ok"}
    result = _sanitize_terms(shallow)
    assert not _contains(result, _DEPTH_TRUNCATED)
    assert result["price"]["currency"] == "USD"
    assert result["note"] == "ok"


def test_structure_exactly_at_cap_is_not_over_truncated():
    # A structure shallower than the cap keeps its leaf; the marker only appears
    # for nesting that exceeds MAX_SANITIZE_DEPTH.
    result = _sanitize_metadata(_nest(MAX_SANITIZE_DEPTH - 2))
    assert _contains(result, "value")  # leaf survived
    assert not _contains(result, _DEPTH_TRUNCATED)
