"""Entry point for running the Concordia MCP server.

Usage:
    python -m concordia                     # stdio transport (default)
    python -m concordia --transport sse     # SSE transport
    python -m concordia --version           # print version and exit
    python -m concordia --help              # show help
    concordia-mcp-server                    # via pip install entry point
"""

import json
import sys


def _predicate_cli(argv: list[str]) -> bool:
    if len(argv) >= 3 and argv[1] == "predicate" and argv[2] == "verify":
        if len(argv) < 4:
            raise SystemExit("Usage: python -m concordia predicate verify <file>")
        from .predicate import verify_predicate

        with open(argv[3], encoding="utf-8") as handle:
            predicate = json.load(handle)
        print(json.dumps(verify_predicate(predicate).to_dict(), indent=2, sort_keys=True))
        return True
    return False


def _build_help_text() -> str:
    return (
        "Concordia MCP Server — structured negotiation protocol for autonomous agents\n"
        "\n"
        "Usage:\n"
        "  concordia-mcp-server                   Run on stdio transport (default)\n"
        "  concordia-mcp-server --transport sse   Run on SSE transport (HTTP)\n"
        "  python -m concordia                    Run on stdio transport (default)\n"
        "  python -m concordia --transport sse    Run on SSE transport (HTTP)\n"
        "  python -m concordia predicate verify <file>  Verify a signed predicate artifact\n"
        "\n"
        "59 MCP tools across 14 categories:\n"
        "  Negotiation (8)                    open, propose, counter, accept, reject, commit, status, public_view\n"
        "  Session Receipts (2)               receipt, receipt envelope\n"
        "  Competence Proofs (2)              generate, verify\n"
        "  Reputation (3)                     ingest attestation, query, score\n"
        "  Discovery (5)                      register, search, agent card, preferred badge, deregister\n"
        "  Agent Profiles (4)                 publish/get profiles, search, recommend\n"
        "  Want Registry (10)                 post/get/withdraw wants & haves, find matches, search, stats\n"
        "  Relay (10)                         create, join, send, receive, status, conclude, transcript, archive, list, stats\n"
        "  Adoption (5)                       propose protocol, respond, start degraded, message, efficiency report\n"
        "  Sanctuary Bridge (4)               configure, commit, attest, status\n"
        "  Receipt Bundles (3)                create, verify, list\n"
        "  Verascore Reporting (1)            report completed negotiations\n"
        "  Mandate Verification (1)           verify signed mandate credentials\n"
        "  Approval Receipt Verification (1)  verify signed approval receipts\n"
        "\n"
        "Tool registration: 55 in concordia.mcp_server plus 4 agent-profile discovery tools\n"
        "registered via register_discovery_tools(), for 59 active runtime tools.\n"
        "Predicate CLI verification is available separately via python -m concordia predicate verify <file>.\n"
        "\n"
        "Built on the official Python MCP SDK (mcp package).\n"
        "Install: pip install 'concordia-protocol[server]'\n"
    )


def main() -> None:
    if _predicate_cli(sys.argv):
        return

    if "--version" in sys.argv or "-V" in sys.argv:
        from importlib.metadata import version as pkg_version
        try:
            v = pkg_version("concordia-protocol")
        except Exception:
            v = "0.1.0"
        print(f"concordia-protocol {v}")
        return

    if "--help" in sys.argv or "-h" in sys.argv:
        print(_build_help_text())
        return

    try:
        from .mcp_server import mcp
    except ModuleNotFoundError as exc:
        if exc.name == "mcp":
            raise SystemExit(
                "The Concordia MCP server requires the server extra. "
                "Install with: pip install 'concordia-protocol[server]'"
            ) from exc
        raise

    transport = "stdio"
    if "--transport" in sys.argv:
        idx = sys.argv.index("--transport")
        if idx + 1 < len(sys.argv):
            transport = sys.argv[idx + 1]

    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
