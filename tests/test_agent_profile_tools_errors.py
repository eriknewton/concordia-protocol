"""Edge coverage for agent profile MCP tool wrappers."""

from __future__ import annotations

import json

from concordia.agent_profile import AgentProfileStore
from concordia.agent_profile.tools import register_discovery_tools


class _MCP:
    def tool(self, **_kwargs):
        def decorator(func):
            return func

        return decorator


class _ExplodingProfileStore(AgentProfileStore):
    def get(self, _agent_id: str):
        raise RuntimeError("store unavailable")

    def search(self, **_kwargs):
        raise RuntimeError("search unavailable")


class _WantRegistry:
    def __init__(self, want):
        self.want = want

    def get_want(self, _want_id: str):
        return self.want


class _ExplodingWantRegistry:
    def get_want(self, _want_id: str):
        raise RuntimeError("registry unavailable")


def _tools(profile_store, want_registry):
    return register_discovery_tools(_MCP(), profile_store, want_registry)


def test_get_tool_reports_unexpected_store_error() -> None:
    tool = _tools(_ExplodingProfileStore(), _WantRegistry(None))["agent_profile_get"]

    result = json.loads(tool("agent-1"))

    assert result == {
        "success": False,
        "error": "store unavailable",
        "message": "Unexpected error: store unavailable",
    }


def test_search_tool_reports_store_error() -> None:
    tool = _tools(_ExplodingProfileStore(), _WantRegistry(None))["agent_discovery_search"]

    result = json.loads(tool(categories=["compute"]))

    assert result == {
        "success": False,
        "error": "search unavailable",
        "message": "Search failed: search unavailable",
    }


def test_recommend_tool_reports_missing_want_category() -> None:
    tool = _tools(AgentProfileStore(), _WantRegistry({"want_id": "want-1"}))[
        "agent_discovery_recommend"
    ]

    result = json.loads(tool("want-1"))

    assert result == {"error": "Want has no category field"}


def test_recommend_tool_reports_registry_error() -> None:
    tool = _tools(AgentProfileStore(), _ExplodingWantRegistry())[
        "agent_discovery_recommend"
    ]

    result = json.loads(tool("want-1"))

    assert result == {
        "success": False,
        "error": "registry unavailable",
        "message": "Recommendation failed: registry unavailable",
    }
