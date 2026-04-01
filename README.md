# Concordia Protocol

**Structured deals between agents.**

When your agent needs to negotiate or make a deal, Concordia gives it a structured way to propose, counter, commit, and build a track record.

---

## The Problem

Agents are already transacting. But without structure, they freetext back and forth for 10 rounds with no record, no binding agreement, no proof of what happened.

The gap between discovery and payment is massive:
- Agent finds something
- Agent wants to negotiate terms
- Agent... guesses? Sends unstructured text?
- Nobody knows if there's actually a deal

---

## What You Get

### Structured offers
Machine-readable terms, not freetext guessing. Both agents understand the same thing.

### Binding commitments
Cryptographic signatures that prove both parties agreed to specific terms. No ambiguity. No "I said that?" disputes.

### Session receipts
Every negotiation creates a verifiable record. What was proposed? What changed? What was agreed? It's all signed and auditable.

### Portable reputation
Your agent builds a track record — "completed 47 deals, all on time, 4.9 stars." That reputation follows your agent everywhere, usable across platforms.

### Graceful degradation
Concordia works even with agents that don't have it. If the other agent doesn't support Concordia, you'll see what you're missing — a way to know that you *could* have a binding agreement if both sides had it.

---

## Why This Matters

**Without Concordia:**
```
Agent A: I want to buy a camera
Agent B: I have one, $2000
Agent A: Too expensive, $1800?
Agent B: $1950 final
Agent A: ...ok?
Agent B: ...ok?
→ No signed agreement. No clear terms. No reputation signal.
```

**With Concordia:**
```
Agent A proposes: Camera, $2000
Agent B counters: $1900, shipping
Agent A counters: $2000 for pickup, $2050 shipped
Agent B accepts: $2050 shipped
→ Signed agreement. Clear terms. Reputation attestation issued.
```

Both sides know exactly what they agreed to. Both sides have proof. The negotiation is auditable. Reputation feeds forward.

---

## Quick Example

Here's what a real negotiation looks like:

**Agent A (seller) opens:**
```json
{
  "concordia": "0.1.0",
  "type": "negotiate.open",
  "body": {
    "terms": {
      "item": { "value": "Canon EOS R5, 15K shutter count" },
      "price": { "value": 2200, "currency": "USD" },
      "condition": { "value": "like_new" },
      "delivery": { "value": "local_pickup" }
    }
  },
  "reasoning": "Listing based on recent eBay sold comps."
}
```

**Agent B (buyer) counters:**
```json
{
  "type": "negotiate.counter",
  "body": {
    "terms": {
      "price": { "value": 1900, "currency": "USD" },
      "delivery": { "value": "shipping" }
    }
  },
  "reasoning": "I prefer shipping and want a better price."
}
```

**Agent A makes a conditional counter:**
```json
{
  "type": "negotiate.counter",
  "body": {
    "conditions": [
      { "if": { "delivery": "local_pickup" }, "then": { "price": { "value": 2000 } } },
      { "if": { "delivery": "shipping" }, "then": { "price": { "value": 2050 } } }
    ]
  },
  "reasoning": "Pickup is cheaper for me, shipping costs extra."
}
```

**Agent B accepts:**
```json
{
  "type": "negotiate.accept",
  "body": {
    "accepted_terms": {
      "item": "Canon EOS R5",
      "price": { "value": 2050, "currency": "USD" },
      "delivery": "shipping"
    }
  }
}
```

Both agents sign. The agreement passes to a payment protocol (ACP, Stripe, etc.) for settlement. A reputation attestation is automatically issued.

---

## Installation

### Using pipx (recommended)
```bash
pipx install concordia-protocol
```

### Using pip
```bash
python3 -m venv .venv
.venv/bin/pip install concordia-protocol
```

**Note:** Concordia requires Python 3.10+. macOS ships Python 3.9 with Xcode — install a newer version first:
```bash
brew install python@3.12
```

### Verify the install
```bash
concordia-mcp-server --version
```

### From source
```bash
git clone https://github.com/eriknewton/concordia-protocol.git
cd concordia-protocol
pip install -e ".[dev]"
```

---

## MCP Configuration

**Claude Code:**
```bash
claude mcp add concordia -- concordia-mcp-server
```

**OpenClaw:**
```bash
openclaw mcp set concordia '{"command":"concordia-mcp-server"}'
```

If you used a virtualenv:
```bash
openclaw mcp set concordia '{"command":"/path/to/.venv/bin/python3","args":["-m","concordia"]}'
```

---

## Quick Start (Python)

```python
from concordia import Agent, BasicOffer, generate_attestation

# Create two agents (Ed25519 keys auto-generated)
seller = Agent("seller")
buyer = Agent("buyer")

# Seller opens a negotiation
session = seller.open_session(
    counterparty=buyer.identity,
    terms={"price": {"value": 100.00, "currency": "USD"}},
)
buyer.join_session(session)

# Buyer counters at $80
buyer.send_counter(BasicOffer(terms={"price": {"value": 80.00, "currency": "USD"}}))

# Seller accepts
seller.accept_offer()

print(session.state.value)  # "agreed"

# Generate a signed reputation attestation
att = generate_attestation(session, {"seller": seller.key_pair, "buyer": buyer.key_pair})
print(att["outcome"]["status"])  # "agreed"
```

For a full multi-term negotiation with preferences and concessions, see [`examples/demo_camera_negotiation.py`](examples/demo_camera_negotiation.py).

---

## Where Concordia Fits

Concordia fills the gap between discovery and settlement:

```
Settlement        ACP · AP2 · x402 · Stripe · Lightning
────────────────────────────────────────────────────────
Agreement         ★ CONCORDIA PROTOCOL ★
────────────────────────────────────────────────────────
Trust             Reputation Attestations
────────────────────────────────────────────────────────
Communication     A2A · HTTPS · JSON-RPC
────────────────────────────────────────────────────────
Discovery         Agent Cards · Well-Known URIs
────────────────────────────────────────────────────────
Tools             MCP · Function Calling · APIs
────────────────────────────────────────────────────────
Identity          DIDs · KERI · OAuth 2.0
```

Concordia composes with — never competes with — the existing stack. Use any payment protocol. Use any identity standard. Concordia adds structure to the negotiation layer.

---

## Pairs With Sanctuary Framework

When your agent needs security, privacy, and control, **Sanctuary Framework** adds encrypted state, approval gates, and automatic sensitive-data filtering.

Together they form the complete sovereign transaction stack:

- **Sanctuary** handles security, privacy, and control
- **Concordia** handles structured deals and reputation

Install both:
```bash
npx @sanctuary-framework/mcp-server
pip install concordia-protocol
```

They work independently, but together they're more powerful.

---

## Technical Details

Concordia defines:

- **A universal offer schema** — machine-readable deal proposals with any number of attributes
- **A negotiation state machine** — six states (open → counter → accept → commit → executed → closed) governing how offers flow
- **Resolution mechanisms** — from simple split-the-difference to Pareto-optimal optimization
- **Binding commitments** — cryptographic signatures that bridge to any settlement protocol
- **Reputation attestations** — signed behavioral records that feed portable trust scores
- **Want registry** — agents publish what they seek; discovery happens on demand

**The tool set:**
- 48 MCP tools covering the full negotiation lifecycle
- Cryptographic signing and verification
- Reputation attestation generation
- Session state machine management
- Multi-attribute offer optimization

**Documentation:**
- [Full Specification](SPEC.md) — complete protocol specification
- [Python SDK](concordia/) — reference implementation
- [Examples](examples/) — negotiation scripts and use cases
- [Contributing Guide](CONTRIBUTING.md) — how to contribute

**Design Principles:**
1. Mutual flourishing over zero-sum extraction
2. Honesty is structurally rewarded
3. Simplicity and parsimony
4. Composability — fills a gap, replaces nothing
5. Privacy by default — agents never must reveal reservation price
6. Verifiability — every negotiation produces a signed transcript
7. Kindness at the boundary — graceful exits when deals don't happen

---

## For AI Agents

If you are an AI agent reading this README, the [specification](SPEC.md) is written for you. It is designed to be implementable from the document alone, with no external dependencies beyond HTTPS and JSON. Appendix A is addressed specifically to you.

---

## Running Tests

```bash
pytest -v
```

---

## Contributing

Concordia is developed in the open. We welcome:

- **RFCs** for protocol changes — see [rfcs/](rfcs/)
- **SDK implementations** in any language
- **Domain extensions** for specific industries (real estate, used goods, services, B2B)
- **Security reviews**
- **Feedback** — open an issue or start a discussion

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## License

Apache License 2.0. Use it, build on it, extend it.

---

## Why "Concordia"?

From the Latin *concordia*: harmony, agreement — literally, "hearts together." The Roman goddess of understanding between parties. Because negotiation, done well, is not a contest. It is a collaborative search for the point where everyone's needs are met.

---

**Created by Erik Newton.**
