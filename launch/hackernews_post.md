# Show HN: Concordia – An open protocol for negotiation between AI agents

Every agentic commerce protocol assumes a fixed price. Agent finds product, agent adds to cart, agent pays the sticker price. That works for buying from Amazon. It doesn't work for freelance services, used goods, B2B procurement, real estate, or any transaction where the terms aren't predetermined — categories that represent trillions of dollars in annual commerce.

A2A handles agent communication. MCP handles tool use. ACP and UCP handle fixed-price checkout. Nobody has built the standard for how agents actually *make deals*.

**Concordia** is an open protocol (Apache 2.0) for structured, multi-attribute negotiation between autonomous agents. It defines:

- A universal offer schema — structured deal proposals across any number of terms (price, timeline, scope, delivery, IP rights, whatever the deal requires)
- A six-state negotiation lifecycle — PROPOSED → ACTIVE → AGREED / REJECTED / EXPIRED → DORMANT
- Conditional offers — "I'll do $4,800 if you deliver by April 11th; $4,400 if April 18th"
- Resolution mechanisms — from split-the-difference to Pareto-optimal trade-off optimization
- Reputation attestations — every negotiation produces a signed behavioral record that feeds portable trust scores, without exposing deal specifics

The design choice I'm most interested in feedback on: every Concordia message has an optional `reasoning` field — free-text natural language explanation of *why* the agent is making this offer. It's never binding, never required, but it's what makes the protocol native to the LLM era. Classical negotiation protocols exchanged structured data. LLM agents think in language, and the most productive negotiations between intelligent parties involve explanation:

```json
{
  "type": "negotiate.counter",
  "body": {
    "conditions": [
      { "if": { "delivery": "local_pickup" }, "then": { "price": { "value": 2000 } } },
      { "if": { "delivery": "shipping" }, "then": { "price": { "value": 2050 } } }
    ]
  },
  "reasoning": "I can come down to $2000 for pickup, $2050 shipped. The $50 difference covers packing materials and the trip to the post office."
}
```

The protocol composes with the existing stack — it sits between discovery/communication (A2A, MCP) and settlement (ACP, Stripe, x402). It replaces nothing. It fills the gap where agreement happens.

Spec is ~40 pages and designed to be implementable by an LLM agent from reading the document alone. Python reference SDK is included. The spec is addressed to both human developers and AI agents (Appendix A talks directly to agents reading it).

Repo: https://github.com/eriknewton/concordia-protocol

Site: https://concordiaprotocol.dev

Looking for feedback on the protocol design, contributors for TypeScript/Rust SDKs, and anyone building agentic commerce who wants to test this with real agent-to-agent negotiations.

Built by Erik Newton. Background in M&A deal structuring, which is where the protocol's mechanism design comes from.
