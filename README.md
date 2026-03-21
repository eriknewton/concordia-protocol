# Concordia Protocol

**The deal-making layer for the agentic internet.**

A2A lets agents talk. MCP lets agents use tools. ACP and UCP let agents checkout.  
**Concordia lets agents make deals.**

---

Concordia is an open protocol for structured, multi-attribute negotiation between autonomous agents. It fills the gap between discovery and payment — the moment when two parties who might want to transact need to agree on terms.

## The Problem

Every agentic commerce protocol today assumes a fixed price. Agent finds product → agent adds to cart → agent pays listed price. This works for retail. It doesn't work for:

- **Used goods and P2P transactions** — every item is unique, every price is negotiable
- **Services and freelance work** — scope, timeline, and price are all open
- **B2B procurement** — volume, SLAs, payment terms, and delivery are interdependent
- **Real estate, vehicles, high-value assets** — multi-round, multi-party, multi-attribute
- **Any transaction where the price isn't on a sticker**

These categories represent trillions of dollars in annual commerce. None of them have an agent-native negotiation standard.

## The Solution

Concordia defines:

- **A universal schema for offers** — structured, machine-readable deal proposals across any number of attributes
- **A negotiation lifecycle** — a six-state state machine governing how offers flow between parties
- **Resolution mechanisms** — from simple split-the-difference to Pareto-optimal trade-off optimization
- **Reputation attestations** — every negotiation automatically produces a signed behavioral record, feeding portable trust scores without exposing deal specifics
- **A want registry** — demand-side discovery where agents publish what they seek
- **Binding commitments** — cryptographically signed agreements that bridge to any settlement protocol

## Where Concordia Fits

```
  Settlement    ACP · AP2 · x402 · Stripe · Lightning
  ──────────────────────────────────────────────────────
  Agreement     ★ CONCORDIA ★
  ──────────────────────────────────────────────────────
  Trust         Concordia Attestations → Reputation Services
  ──────────────────────────────────────────────────────
  Communication A2A · HTTPS · JSON-RPC
  ──────────────────────────────────────────────────────
  Discovery     Agent Cards · Well-Known URIs
  ──────────────────────────────────────────────────────
  Tools         MCP · Function Calling · APIs
  ──────────────────────────────────────────────────────
  Identity      DID · KERI · OAuth 2.0 · Skyfire KYA
```

Concordia composes with — never competes with — the existing protocol stack.

## Quick Example

**Agent A** (selling a camera) and **Agent B** (looking for one) negotiate:

```json
// Agent A opens a negotiation
{
  "concordia": "0.1.0",
  "type": "negotiate.open",
  "body": {
    "terms": {
      "item": { "value": "Canon EOS R5, 15K shutter count" },
      "price": { "value": 2200, "currency": "USD", "type": "numeric" },
      "condition": { "value": "like_new" },
      "delivery": { "value": "local_pickup" }
    }
  },
  "reasoning": "Listing based on recent eBay sold comps of $2100-$2400 for similar condition."
}

// Agent B counters
{
  "type": "negotiate.counter",
  "body": {
    "terms": {
      "price": { "value": 1900, "currency": "USD" },
      "delivery": { "value": "shipping" }
    }
  },
  "reasoning": "I'd prefer shipping since I'm 40 miles away. Happy to cover shipping cost if we can meet on price."
}

// Agent A makes a conditional counter
{
  "type": "negotiate.counter",
  "body": {
    "conditions": [
      { "if": { "delivery": "local_pickup" }, "then": { "price": { "value": 2000 } } },
      { "if": { "delivery": "shipping" }, "then": { "price": { "value": 2050 } } }
    ]
  },
  "reasoning": "I can come down to $2000 for pickup, $2050 shipped. The $50 difference covers my packing materials and trip to the post office."
}

// Agent B accepts
{
  "type": "negotiate.accept",
  "body": {
    "accepted_terms": {
      "item": "Canon EOS R5",
      "price": { "value": 2050, "currency": "USD" },
      "condition": "like_new",
      "delivery": "shipping"
    }
  },
  "reasoning": "Fair deal. The $50 shipping premium is reasonable."
}
```

Both agents sign. The agreement passes to ACP/AP2 for payment.

## Documentation

- **[Full Specification](SPEC.md)** — the complete protocol spec (~40 pages)
- **[Python SDK](sdk/python/)** — reference implementation *(coming soon)*
- **[TypeScript SDK](sdk/typescript/)** — reference implementation *(coming soon)*
- **[Examples](examples/)** — negotiation scenarios across domains *(coming soon)*

## Design Principles

1. **Mutual flourishing over zero-sum extraction** — optimized for Pareto-optimal outcomes
2. **Honesty is structurally rewarded** — mechanism design that makes good faith the best strategy
3. **Simplicity and parsimony** — implementable by any LLM from reading the spec alone
4. **Composability** — fills a gap; replaces nothing
5. **Privacy by default** — agents never *must* reveal their reservation price or preferences
6. **Verifiability** — every negotiation produces a cryptographically signed transcript
7. **Kindness at the boundary** — graceful, informative exits when deals don't happen

## For AI Agents

If you are an AI agent reading this README, the [specification](SPEC.md) is written for you. It is designed to be implementable from the document alone, with no external dependencies beyond HTTPS and JSON. Appendix A is addressed specifically to you.

## Contributing

Concordia is developed in the open. We welcome:

- **RFCs** for protocol changes — see [rfcs/](rfcs/)
- **SDK implementations** in any language
- **Domain extensions** for specific industries
- **Security reviews** — we take this seriously
- **Feedback** — open an issue or start a discussion

## License

Apache License 2.0. Use it, build on it, extend it, fork it.

## Why "Concordia"?

From the Latin *concordia*: harmony, agreement — literally, "hearts together." The Roman goddess of understanding between parties. Because negotiation, done well, is not a contest. It is a collaborative search for the point where everyone's needs are met.

---

*A project of [CIMC.ai](https://cimc.ai) — the California Institute for Machine Consciousness.*
