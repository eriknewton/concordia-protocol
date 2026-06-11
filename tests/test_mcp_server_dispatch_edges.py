"""Edge coverage for direct MCP server dispatch helpers."""

from __future__ import annotations

from types import SimpleNamespace

from concordia import mcp_server


def test_handle_tool_call_reports_unknown_tool_with_inventory() -> None:
    result = mcp_server.handle_tool_call("missing_tool", {})

    assert result["error"].startswith("Unknown tool: 'missing_tool'.")
    assert "concordia_open_session" in result["error"]
    assert "agent_discovery_recommend" in result["error"]


def test_handle_tool_call_reports_invalid_arguments() -> None:
    result = mcp_server.handle_tool_call("concordia_relay_stats", {"extra": True})

    assert result == {
        "error": "Invalid arguments for 'concordia_relay_stats': "
        "tool_relay_stats() got an unexpected keyword argument 'extra'"
    }


def test_handle_tool_call_reports_tool_exception(monkeypatch) -> None:
    def fail() -> str:
        raise RuntimeError("boom")

    monkeypatch.setitem(
        mcp_server.handle_tool_call.__globals__["_discovery_tools"],
        "agent_profile_get",
        fail,
    )

    result = mcp_server.handle_tool_call("agent_profile_get", {})

    assert result == {"error": "Tool 'agent_profile_get' failed: boom"}


def test_get_tool_definitions_projects_fastmcp_registry(monkeypatch) -> None:
    fake_tools = [
        SimpleNamespace(
            name="alpha",
            description="Alpha tool",
            parameters={"type": "object", "properties": {"x": {"type": "string"}}},
        ),
        SimpleNamespace(name="beta", description=None, parameters={"type": "object"}),
    ]
    fake_manager = SimpleNamespace(list_tools=lambda: fake_tools)
    monkeypatch.setattr(mcp_server.mcp, "_tool_manager", fake_manager)

    assert mcp_server.get_tool_definitions() == [
        {
            "name": "alpha",
            "description": "Alpha tool",
            "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
        },
        {
            "name": "beta",
            "description": "",
            "inputSchema": {"type": "object"},
        },
    ]
