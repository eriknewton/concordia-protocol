<!-- mcp-name: io.github.eriknewton/concordia-protocol -->

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
pipx install "concordia-protocol[server]"
```

### Using pip
```bash
python3 -m venv .venv
.venv/bin/pip install "concordia-protocol[server]"
```

**Note:** Concordia requires Python 3.10+. macOS ships Python 3.9 with Xcode — install a newer version first:
```bash
brew install python@3.12
```

Library-only consumers can install `concordia-protocol` without the MCP server
dependencies. The `concordia-mcp-server` command requires the `server` extra and
prints an install hint when that extra is missing.

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
- **A negotiation state machine** — six states (proposed → active → agreed / rejected / expired → dormant) governing how offers flow
- **Resolution mechanisms** — from simple split-the-difference to Pareto-optimal optimization
- **Binding commitments** — cryptographic signatures that bridge to any settlement protocol
- **Reputation attestations** — signed behavioral records that feed portable trust scores
- **Want registry** — agents publish what they seek; discovery happens on demand
- **Predicate primitive** — signed v0.6 authority, policy, eligibility, and bounds evaluations

**The tool set:**
- 59 MCP tools across negotiation, session receipts, competence proofs, reputation, discovery, agent profiles, want registry, relay, adoption, Sanctuary bridge, receipt bundles, Verascore reporting, mandate verification, and approval receipt verification
- Tool registration: 55 in `concordia.mcp_server` plus 4 agent-profile discovery tools registered via `register_discovery_tools()`, for 59 active runtime tools
- Predicate CLI verification with `python -m concordia predicate verify <file>`
- Cryptographic signing and verification
- Reputation attestation generation
- Session state machine management
- Multi-attribute offer optimization

**Documentation:**
- [Full Specification](SPEC.md) — complete protocol specification
- [v0.6 Predicate Primitive](docs/v0.6_predicate_primitive.md) — signed predicate artifact, verifier, resolver, and CTEF mapping
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

## Relay Trust Model: What It Protects, and What It Does Not

Concordia includes an optional message relay. A relay is a mailbox service: when two agents cannot talk to each other directly, each one drops messages off and picks messages up at the relay, which holds them in the meantime and keeps a transcript (a stored record of the conversation) for dispute resolution.

The relay is a convenience feature of the reference server. It is not where Concordia's trust comes from. Trust comes from cryptography that works the same with or without a relay: every message is signed (a tamper-proof mathematical seal only the sender's private key can produce), and the transcript is hash-chained (each message contains a fingerprint of the one before it, so removing or altering any message breaks the chain visibly).

### What consent means here, mechanically

Nobody becomes a relay participant without joining under their own credentials. Concretely:

1. An agent creates a relay session and may name who it wants to talk to. Naming someone is a reservation, nothing more. The session sits in a pending state.
2. The named agent must join the session itself, authenticated with its own token (a secret credential issued when the agent registered, which proves the caller owns that identity). Anyone else who tries to join a reserved session is refused.
3. Until that join happens, no messages flow to or from the named agent, the named agent is recorded as unconfirmed, and automatic reputation attestation is skipped and logged rather than issued.
4. Sessions created without naming anyone are open: the first authenticated agent to join fills the slot.

So another agent cannot manufacture a conversation that lists you as a party. A transcript only records you as a confirmed participant if you joined it yourself.

### Spam and squatting bounds

Each agent can hold at most 100 active relay sessions as initiator. Sessions live 24 hours by default and 7 days at most; the cap is enforced, not advisory. Mailboxes hold at most 1,000 undelivered messages, transcripts at most 10,000 messages, and the server at most 10,000 live sessions. Reading a transcript is restricted to its participants.

### If an attacker controls the relay

| The relay operator CAN | The relay operator CANNOT |
|---|---|
| Read every message that passes through it. Relay traffic is not end-to-end encrypted today. | Forge a message from you. Signatures require your private key, which the relay routing layer never needs. |
| See metadata: who talks to whom, when, and how much. | Alter or delete a message without detection. Signature checks and the hash chain expose tampering and gaps. |
| Drop, delay, or withhold messages, or refuse joins. It can always deny service. | Replay your message from one session into another. Verification binds each message to its session and chain position. |
| Keep copies of transcripts past the session. | Produce a verifiable agreement, or a confirmed-participant transcript entry, that you never signed and never joined. |

### Explicitly out of scope

- **Your own endpoint.** If an attacker compromises your machine or steals your auth token, they are you. The relay cannot tell the difference.
- **Metadata privacy.** The relay sees the shape of your activity even when it cannot misuse the content.
- **The bundled single-server deployment.** The reference MCP server hosts the relay, agent keys, and token issuance in one process. There, a compromised operator holds the keys, and the CANNOT column above no longer applies. The relay trust model protects you from other agents and from a relay that is only a relay. Run your keys separately if your threat model includes the operator.
- **Judgment.** The relay does not vet deal terms. A bad deal, faithfully relayed and validly signed, is still a bad deal.

For the protocol-level guarantees behind this (identity, message integrity, transcript integrity, anti-abuse), see [SPEC.md Section 9](SPEC.md).

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
