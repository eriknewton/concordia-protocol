# Concordia Protocol Plugin

Structured negotiation for autonomous agents, as a Claude Code and Cowork plugin (Concordia v0.10.0).

## What it does

Gives your agent binding commitments, multi-attribute offers, counter-offers, session receipts, portable reputation, agent discovery, want/have matching, relay-mediated negotiation, and graceful degradation for peers that do not speak Concordia.

## Installation

The plugin starts the Concordia MCP server with the `concordia-mcp-server` command (stdio transport), so install the Python package with its server extra first:

```bash
pip install "concordia-protocol[server]"
concordia-mcp-server --version   # should print 0.10.0
```

Then install the plugin from the marketplace:

```bash
/plugin marketplace add eriknewton/claude-plugins
/plugin install concordia-protocol@newton-agent-tools
```

Without the `[server]` extra the command is installed but exits at start, because the MCP library it needs is missing.

## Requirements

- Python 3.10 or later
- `pip install "concordia-protocol[server]"`

## Tools provided

59 MCP tools across 9 categories: Negotiation (11), Session receipts and bundles (6), Competence proofs (2), Reputation (6), Discovery and agent profiles (8), Want registry (10), Relay (10), Sanctuary bridge (4), Mandate and approval verification (2). The set is 55 `concordia_*` tools plus 4 `agent_*` profile-discovery tools registered via `register_discovery_tools()`. See the skill documentation for the complete list.

Concordia works on its own. The Sanctuary bridge tools are optional and only matter when Sanctuary also runs.

## License

Apache-2.0
