from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def test_help_tool_count_matches_mcp_registrations() -> None:
    server_source = (ROOT / "concordia" / "mcp_server.py").read_text()
    help_source = (ROOT / "concordia" / "__main__.py").read_text()

    registered_tools = len(re.findall(r"^\s*@mcp\.tool\(", server_source, re.MULTILINE))
    advertised_count = re.search(r'"(\d+) MCP tools across', help_source)

    assert advertised_count is not None
    assert int(advertised_count.group(1)) == registered_tools
