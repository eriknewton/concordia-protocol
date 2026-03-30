"""Entry point for running the Concordia MCP server.

Usage:
    python -m concordia                     # stdio transport (default)
    python -m concordia --transport sse     # SSE transport
    python -m concordia --help              # show help
    concordia-mcp-server                    # via pip install entry point
"""

import sys

from .mcp_server import mcp


def main() -> None:
    if "--help" in sys.argv or "-h" in sys.argv:
        print(
            "Concordia MCP Server — structured negotiation protocol for autonomous agents\n"
            "\n"
            "Usage:\n"
            "  concordia-mcp-server                   Run on stdio transport (default)\n"
            "  concordia-mcp-server --transport sse   Run on SSE transport (HTTP)\n"
            "  python -m concordia                    Run on stdio transport (default)\n"
            "  python -m concordia --transport sse    Run on SSE transport (HTTP)\n"
            "\n"
            "48 MCP tools across 8 categories:\n"
            "  Negotiation (8)       open, propose, counter, accept, reject, commit, status, receipt\n"
            "  Reputation (3)        ingest attestation, query, score\n"
            "  Discovery (5)         register, search, agent card, preferred badge, deregister\n"
            "  Want Registry (10)    post/get/withdraw wants & haves, find matches, search, stats\n"
            "  Relay (10)            create, join, send, receive, status, conclude, transcript, archive, list, stats\n"
            "  Adoption (5)          propose protocol, respond, start degraded, message, efficiency report\n"
            "  Sanctuary Bridge (4)  configure, commit, attest, status\n"
            "  Receipt Bundles (3)   create, verify, list\n"
            "\n"
            "Built on the official Python MCP SDK (mcp package).\n"
            "Install: pip install concordia-protocol\n"
        )
        return

    transport = "stdio"
    if "--transport" in sys.argv:
        idx = sys.argv.index("--transport")
        if idx + 1 < len(sys.argv):
            transport = sys.argv[idx + 1]

    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
