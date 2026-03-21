# Twitter/X Launch Thread

---

**Tweet 1 (Hook)**

Every agentic commerce protocol assumes a fixed price.

But most of the economy doesn't have a sticker price — freelance work, used goods, B2B procurement, real estate.

Today we're open-sourcing Concordia: the negotiation layer for AI agents.

The missing piece of the protocol stack. 🧵

---

**Tweet 2 (The Stack)**

Where Concordia fits:

```
Settlement:    ACP · Stripe · x402 · Lightning
Agreement:     ★ CONCORDIA ★
Communication: A2A · HTTPS
Discovery:     Agent Cards · Want Registry
Tools:         MCP · Function Calling
Identity:      DID · OAuth 2.0
```

A2A lets agents talk. MCP lets agents use tools. ACP lets agents pay.

Concordia lets agents make deals.

[attach protocol stack diagram image]

---

**Tweet 3 (What It Does)**

Concordia defines:

→ A universal offer schema (any number of terms, not just price)
→ A six-state negotiation lifecycle
→ Conditional offers ("$4,800 if delivered by April 11; $4,400 if April 18")
→ Resolution mechanisms for when agents get stuck
→ Reputation attestations from every negotiation — portable trust, no deal specifics exposed

Apache 2.0. Designed to compose with everything, replace nothing.

---

**Tweet 4 (The Key Innovation)**

The design choice that makes this native to the LLM era:

Every Concordia message has a `reasoning` field — free-text natural language explaining *why* the agent is making this offer.

Never binding. Never required. But agents that explain their thinking reach better deals, because counterparties can find creative solutions.

---

**Tweet 5 (Example)**

What agent negotiation looks like in practice:

```json
{
  "type": "negotiate.counter",
  "body": {
    "conditions": [
      { "if": { "delivery": "pickup" },
        "then": { "price": 2000 } },
      { "if": { "delivery": "shipping" },
        "then": { "price": 2050 } }
    ]
  },
  "reasoning": "The $50 difference covers
    packing and shipping effort."
}
```

Structured data + natural language reasoning. The best of both paradigms.

---

**Tweet 6 (Reputation)**

Failed negotiations aren't wasted.

Every Concordia session — whether it ends in agreement or not — produces a signed behavioral attestation: did the agent concede? explain reasoning? negotiate in good faith?

The protocol defines the attestation format. Scoring is done by external services.

Think git → GitHub, applied to trust.

---

**Tweet 7 (CTA)**

The spec is ~40 pages, written so an LLM agent can implement it from reading the doc alone. Python SDK included.

Looking for:
→ Feedback on protocol design
→ TypeScript / Rust SDK contributors
→ Agent builders who want to test real negotiations

Repo: https://github.com/eriknewton/concordia-protocol
Site: https://concordiaprotocol.dev

Built at @ciaboratory. We'd love to hear from teams at @AnthropicAI @OpenAI @Shopify @stripe working on agentic commerce.

*Concordia* — Latin for harmony. Literally, "hearts together."
