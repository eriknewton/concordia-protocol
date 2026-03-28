"""Entry point for running the Concordia MCP server.

Usage:
    python -m concordia          # stdio transport
    python -m concordia --help   # show help
"""

import sys

from .mcp_server import run_stdio


def main() -> None:
    if "--help" in sys.argv or "-h" in sys.argv:
        print(
            "Concordia MCP Server — negotiation protocol tools over MCP\n"
            "\n"
            "Usage:\n"
            "  python -m concordia         Run on stdio transport (default)\n"
            "\n"
            "The server exposes 8 tools:\n"
            "  concordia_open_session      Open a new negotiation session\n"
            "  concordia_propose           Send an initial offer\n"
            "  concordia_counter           Send a counter-offer\n"
            "  concordia_accept            Accept the current offer\n"
            "  concordia_reject            Reject the negotiation\n"
            "  concordia_commit            Finalize an agreed deal\n"
            "  concordia_session_status    Query session state and analytics\n"
            "  concordia_session_receipt   Generate a cryptographic receipt\n"
        )
        return

    run_stdio()


if __name__ == "__main__":
    main()
