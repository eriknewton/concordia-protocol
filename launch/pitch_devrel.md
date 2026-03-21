# Concordia Protocol — Partnership Brief

**From:** Erik Newton, Co-Founder, CIMC.ai
**Re:** The negotiation layer for the agentic internet

---

## The Gap

The agentic commerce stack is nearly complete. Agents can discover each other, communicate, use tools, and pay. What's missing is how they *reach agreement on terms* — the negotiation that happens between finding something and buying it.

Every current protocol assumes a fixed price. That works for retail. It doesn't work for freelance services, used goods, B2B procurement, real estate, or any domain where price and terms are negotiable — categories worth trillions annually and growing fast as agents enter the market.

## Concordia

Concordia is an open protocol (Apache 2.0) for structured, multi-attribute negotiation between autonomous agents. It defines a universal offer schema, a six-state negotiation lifecycle, conditional offers, resolution mechanisms, and a reputation attestation system that produces portable trust data from every interaction.

The protocol is designed to compose cleanly with the existing stack — sitting between communication/discovery and settlement. It replaces nothing. It fills the gap where agreement happens.

A key design choice: every message carries an optional `reasoning` field — free-text natural language explanation of the agent's rationale. This makes the protocol native to LLM-based agents, where the most productive negotiations involve explanation, not just structured data exchange.

The spec is ~40 pages and designed to be implementable by an LLM agent from reading the document alone. A Python reference SDK is included.

## Why This Matters for [PLATFORM]

<!-- For Stripe: -->
Concordia is the natural upstream layer for payment protocols. When two agents agree on terms through Concordia, the signed agreement flows directly into settlement via your infrastructure. The reputation attestation system also provides a trust signal for agent-initiated payments — a problem you'll increasingly face as autonomous agents transact on behalf of users.

<!-- For Shopify: -->
As merchants' AI agents handle more buying and selling, they need a standard way to negotiate. Concordia enables your merchants' agents to handle negotiated transactions — custom orders, B2B wholesale, marketplace pricing — with the same protocol. The want registry (demand-side discovery) is a natural complement to your product catalog infrastructure.

<!-- For Google Cloud: -->
Concordia completes the agent protocol stack you're building around A2A. It's the agreement layer between agent communication and checkout (UCP/AP2). Native integration would make the Google Cloud agent ecosystem the first to support the full lifecycle from discovery through negotiated agreement to settlement.

<!-- For Anthropic: -->
Concordia is built for LLM-native agents. The `reasoning` field, preference signals, and mechanism design all assume agents that think in natural language. As Claude becomes the backbone of autonomous commerce agents, a standard negotiation protocol makes every Claude-powered agent a better dealmaker — and creates a natural surface area for Claude's strengths.

## What We're Looking For

We're inviting platform partners to collaborate on Concordia's development: review the protocol design, contribute SDK implementations, and explore integration paths. This is early-stage and open — the right time to shape the standard.

**Repo:** https://github.com/eriknewton/concordia-protocol
**Spec:** https://concordiaprotocol.dev
**Contact:** Erik Newton — eriknewton@gmail.com

*CIMC.ai — California Institute for Machine Consciousness. Co-founded with Joscha Bach.*
