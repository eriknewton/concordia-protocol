from pathlib import Path
import ast
import re

from concordia.mcp_server import get_tool_definitions


ROOT = Path(__file__).resolve().parents[1]
HELP_COUNT_RE = re.compile(r"(\d+)\s+MCP tools")


def _extract_help_count(help_text: str) -> int:
    match = HELP_COUNT_RE.search(help_text)
    assert match is not None, f"Could not find tool count in help text: {help_text[:200]}"
    return int(match.group(1))


def _mcp_server_decorator_count() -> int:
    tree = ast.parse((ROOT / "concordia" / "mcp_server.py").read_text())
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            func = decorator.func
            if isinstance(func, ast.Attribute) and func.attr == "tool":
                count += 1
    return count


def test_help_count_matches_runtime_registry() -> None:
    from concordia.__main__ import _build_help_text

    help_count = _extract_help_count(_build_help_text())
    runtime_count = len(get_tool_definitions())

    assert help_count == runtime_count, (
        f"Help string claims {help_count} tools but runtime registry has {runtime_count}. "
        "Help string must be regenerated when tool registrations change."
    )


def test_runtime_registry_at_least_as_large_as_mcp_server_decorators() -> None:
    decorator_count = _mcp_server_decorator_count()
    runtime_count = len(get_tool_definitions())

    assert runtime_count >= decorator_count, (
        f"Runtime registry ({runtime_count}) has fewer tools than "
        f"concordia.mcp_server @mcp.tool decorations ({decorator_count})."
    )
