# Concordia Protocol Plugin

Structured negotiation protocol for autonomous agents, as a Cowork/Claude Code plugin.

## What it does

Gives your agent binding commitments, multi-attribute offers, counter-offers, session receipts, portable reputation, agent discovery, want/have matching, relay-mediated negotiation, and graceful degradation for non-Concordia peers.

## Installation

Install this plugin in Cowork or Claude Code. The plugin starts the Concordia MCP Server via `python -m concordia`.

## Requirements

- Python 3.10+
- `pip install concordia-protocol`

## Tools provided

59 MCP tools across 9 categories: Negotiation (11), Session receipts and bundles (6), Competence proofs (2), Reputation (6), Discovery and agent profiles (8), Want registry (10), Relay (10), Sanctuary bridge (4), Mandate and approval verification (2). The set is 55 `concordia_*` tools plus 4 `agent_*` profile-discovery tools registered via `register_discovery_tools()`. See the skill documentation for the complete list.

## License

Apache-2.0
