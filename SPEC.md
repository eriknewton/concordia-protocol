# Concordia Protocol

### An Open Standard for Structured Negotiation Between Autonomous Agents

**Version:** 0.1.0-draft  
**Status:** Draft  
**License:** Apache 2.0  
**Authors:** Erik Newton, CIMC.ai  
**Date:** March 2026

---

## Preamble

Every transaction begins as a difference. One party has something another wants. The history of commerce is the history of resolving these differences — through barter, auction, contract, and conversation.

The emerging agentic internet has protocols for how agents discover each other (A2A), how they access tools and data (MCP), and how they complete fixed-price purchases (ACP, UCP, AP2). But there is no standard for the act that precedes payment: **reaching agreement on terms**.

Concordia fills this gap. It is a protocol for structured, multi-attribute negotiation between autonomous agents — designed to compose cleanly with existing standards, to be implementable by any LLM-based agent from reading this document alone, and to produce outcomes that are fair, efficient, and verifiable.

The name is from the Latin *concordia*: harmony, agreement — literally, "hearts together." The protocol embodies a conviction that negotiation, done well, is not a zero-sum contest but a collaborative search for mutual flourishing.

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Protocol Overview](#2-protocol-overview)
3. [Core Concepts](#3-core-concepts)
4. [Message Format](#4-message-format)
5. [Negotiation Lifecycle](#5-negotiation-lifecycle)
6. [Offer Schema](#6-offer-schema)
7. [Discovery and Matching](#7-discovery-and-matching)
8. [Resolution Mechanisms](#8-resolution-mechanisms)
9. [Security and Trust Model](#9-security-and-trust-model)
   - 9.1–9.5: Identity, Integrity, Confidentiality, Anti-Abuse
   - 9.6: [Reputation Attestations](#96-reputation-attestations) *(core feature)*
10. [Integration with Existing Protocols](#10-integration-with-existing-protocols)
11. [Extension Points](#11-extension-points)
12. [Conformance Requirements](#12-conformance-requirements)

---

## 1. Design Principles

Concordia is designed according to seven principles. These are not aspirational — they are architectural constraints that shaped every decision in the protocol.

### 1.1 Mutual Flourishing Over Zero-Sum Extraction

The protocol is optimized to discover Pareto-optimal outcomes — agreements where neither party can be made better off without making the other worse off. Multi-attribute negotiation enables value creation through trade-offs across dimensions, not just price splitting. The protocol's structure actively encourages agents to find creative agreements rather than converge on compromise.

### 1.2 Honesty Is Structurally Rewarded

The protocol does not require agents to reveal their private preferences. But it is designed so that honest expression of constraints and priorities produces better outcomes than strategic misrepresentation. This is achieved through mechanism design: the resolution mechanisms are incentive-compatible, meaning agents do best by negotiating in good faith.

### 1.3 Simplicity and Parsimony

An LLM agent should be able to implement Concordia from reading this specification alone, with no external documentation. Every concept maps to an intuitive real-world analogy. The message format uses standard JSON over HTTPS. The state machine has exactly six states. There are no features that exist "in case someone needs them."

### 1.4 Composability, Not Competition

Concordia does not replace any existing protocol. It occupies a specific, well-defined position in the agentic protocol stack:

```
┌─────────────────────────────────────────────────┐
│  Settlement Layer                                │
│  ACP · AP2 · x402 · Stripe · Lightning          │
├─────────────────────────────────────────────────┤
│  Agreement Layer                                 │
│  ★ CONCORDIA ★                                   │
│  Offers · Counteroffers · Resolution · Commitment│
├─────────────────────────────────────────────────┤
│  Trust Layer                                     │
│  Concordia Attestations → Reputation Services    │
├─────────────────────────────────────────────────┤
│  Communication Layer                             │
│  A2A · HTTPS · JSON-RPC · SSE                    │
├─────────────────────────────────────────────────┤
│  Discovery Layer                                 │
│  Agent Cards · Well-Known URIs · Want Registry   │
├─────────────────────────────────────────────────┤
│  Tool & Context Layer                            │
│  MCP · Function Calling · APIs                   │
├─────────────────────────────────────────────────┤
│  Identity Layer                                  │
│  DID · KERI · OAuth 2.0 · Skyfire KYA            │
└─────────────────────────────────────────────────┘
```

Concordia takes an agreement from "two parties who might want to deal" to "a binding commitment with defined terms." What happens before (discovery, identity verification) and after (payment, fulfillment) is handled by other protocols.

### 1.5 Privacy by Default

Agents MUST NOT be required to reveal their reservation price (walk-away point), their preference weightings across attributes, or the identity of their principal (the human or organization they represent) as a condition of negotiation. The protocol supports voluntary disclosure of any of these, but never compels it.

### 1.6 Verifiability and Auditability

Every negotiation produces a cryptographically signed transcript. Any party can independently verify that the final agreement was reached through a valid sequence of protocol messages. This transcript is the authoritative record of the deal and can be presented to settlement-layer protocols as proof of agreement.

### 1.7 Kindness at the Boundary

When a negotiation fails — when parties cannot reach agreement — the protocol provides structured, respectful exit paths. Agents can express *why* they're walking away, what would bring them back, and whether they wish to be notified if conditions change. Failed negotiations are not wasted; they produce information that improves future matching.

---

## 2. Protocol Overview

A Concordia negotiation is a structured conversation between two or more agents, conducted through the exchange of typed JSON messages over HTTPS.

### 2.1 What Concordia Does

- Defines a **universal schema for offers** — structured, machine-readable representations of proposed deal terms across any number of attributes
- Specifies a **negotiation lifecycle** — a state machine governing how offers, counteroffers, acceptances, and rejections flow between parties
- Provides **resolution mechanisms** — multiple strategies for reaching agreement, from simple alternating offers to mediated optimization
- Produces **binding commitments** — cryptographically signed agreement records that bridge to settlement protocols
- Supports **discovery and matching** — a want registry where agents publish what they seek, enabling demand-side discovery
- Generates **reputation attestations** — structured behavioral records from every negotiation that feed into portable trust scores, without exposing deal specifics

### 2.2 What Concordia Does Not Do

- **Payment processing** — use ACP, AP2, x402, or any settlement protocol
- **Agent-to-agent communication plumbing** — use A2A, HTTPS, or any transport
- **Identity verification** — use DID, KERI, OAuth 2.0, Skyfire KYA, or any identity protocol
- **Product/service catalogs** — use UCP, schema.org, or any catalog standard
- **Logistics and fulfillment** — use UCP extensions or domain-specific protocols
- **Reputation scoring** — Concordia produces attestations (the raw data); scoring is performed by external reputation services (§9.6)

### 2.3 Participants

A Concordia negotiation involves:

- **Parties** — the agents conducting the negotiation (minimum two, extensible to N)
- **Principals** — the humans or organizations the agents represent (may be anonymous)
- **Mediator** (optional) — a neutral agent that facilitates resolution without having a stake in the outcome
- **Witnesses** (optional) — agents that observe and attest to the negotiation transcript

---

## 3. Core Concepts

### 3.1 Terms

A **Term** is a single dimension of a deal — one thing being negotiated. Every term has:

- `id` — a unique identifier within the negotiation (e.g., `"price"`, `"delivery_date"`)
- `type` — the data type of the term's value (see §3.1.1)
- `label` — a human-readable description
- `unit` (optional) — the unit of measurement (e.g., `"USD"`, `"days"`, `"kg"`)
- `constraints` (optional) — hard boundaries on acceptable values

#### 3.1.1 Term Types

| Type | Description | Example |
|------|-------------|---------|
| `numeric` | A number, optionally with min/max bounds | Price: 150.00 USD |
| `temporal` | A date, time, or duration | Delivery: 2026-04-15 |
| `categorical` | One value from a defined set | Condition: "good" ∈ {"new", "like_new", "good", "fair"} |
| `boolean` | True or false | Warranty included: true |
| `text` | Free text (for terms that resist formalization) | Special instructions: "Leave at back door" |
| `composite` | A nested structure of sub-terms | Fulfillment: { method: "shipping", carrier: "USPS" } |

### 3.2 Deal Space

The **Deal Space** is the set of all possible agreements — the Cartesian product of all term values within their constraints. For a negotiation with terms (price, delivery_date, warranty), the deal space is three-dimensional.

Concordia's insight is that deals which seem impossible in one dimension often become possible when you add dimensions. Two parties who can't agree on price may agree when delivery timing is included. The protocol structurally encourages agents to expand the deal space rather than fight over a single axis.

### 3.3 Offers

An **Offer** is a specific point in the deal space — a complete or partial set of term values that one party proposes to another.

- A **complete offer** assigns values to all terms in the negotiation.
- A **partial offer** assigns values to some terms, leaving others open. This signals: "I care about these terms; I'm flexible on the rest."
- A **conditional offer** specifies term values that depend on other terms: "I'll accept $120 *if* delivery is within 3 days; otherwise $100."

### 3.4 Preference Signals

Agents MAY voluntarily share information about their preferences to accelerate convergence:

- `priority_ranking` — an ordering of terms by importance ("price matters most to me, then timing, then condition")
- `flexibility` — per-term indication of how much room the agent has to move (`"firm"`, `"somewhat_flexible"`, `"very_flexible"`)
- `aspiration` — the outcome the agent hopes for (distinct from their offer, which may be strategic)
- `reservation` — the minimum acceptable outcome (sharing this is powerful but risky; the protocol never requires it)

These signals are advisory. They are never binding and never required. But agents that share preference signals tend to reach better agreements faster, because they help counterparties propose creative trade-offs.

### 3.5 Constraints

A **Constraint** is a hard boundary — a region of the deal space that a party declares unacceptable. Unlike preferences (which are soft), constraints are commitments:

- If an agent declares a constraint, the protocol treats any offer violating it as automatically invalid
- Constraints are cryptographically signed when declared, creating accountability
- Agents SHOULD declare constraints honestly; the protocol is designed so that false constraints reduce the quality of outcomes for the declaring agent

### 3.6 Agreements

An **Agreement** is the output of a successful negotiation — a set of term values that all parties have accepted, along with the signed transcript proving how the agreement was reached.

An agreement contains:
- The final term values
- All party signatures
- A hash of the full negotiation transcript
- A timestamp
- An expiration (after which the agreement is void if not settled)
- References to settlement protocols (how payment will occur)

---

## 4. Message Format

All Concordia messages are JSON objects transmitted over HTTPS. The protocol uses a single envelope format for all message types.

### 4.1 Envelope

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.offer",
  "id": "msg_a7f3b2c1",
  "session_id": "ses_9d4e8f01",
  "timestamp": "2026-03-21T14:30:00Z",
  "from": {
    "agent_id": "agent_seller_01",
    "principal_id": null
  },
  "to": [
    {
      "agent_id": "agent_buyer_42"
    }
  ],
  "body": { },
  "signature": "base64-encoded-ed25519-signature"
}
```

**Required fields:**
- `concordia` — protocol version (semver)
- `type` — message type (see §4.2)
- `id` — unique message identifier (UUID or equivalent)
- `session_id` — the negotiation session this message belongs to
- `timestamp` — ISO 8601 UTC timestamp
- `from` — the sending agent
- `body` — type-specific payload
- `signature` — Ed25519 signature over the canonical JSON of all other fields

**Optional fields:**
- `to` — recipient(s); omitted for broadcast messages
- `in_reply_to` — the `id` of the message this is responding to
- `thread` — for sub-negotiations within a session
- `ttl` — time-to-live in seconds; message expires after this duration
- `reasoning` — free-text explanation of the agent's rationale (see §4.3)

### 4.2 Message Types

| Type | Direction | Purpose |
|------|-----------|---------|
| `negotiate.open` | Initiator → Responder | Propose a negotiation session, define the term space |
| `negotiate.accept_session` | Responder → Initiator | Agree to negotiate on the proposed terms |
| `negotiate.decline_session` | Responder → Initiator | Decline to negotiate (with optional reason) |
| `negotiate.offer` | Party → Party | Propose specific term values |
| `negotiate.counter` | Party → Party | Reject the current offer and propose alternatives |
| `negotiate.accept` | Party → Party | Accept the current offer as the final agreement |
| `negotiate.reject` | Party → Party | Reject the current offer (without counter) |
| `negotiate.inquire` | Party → Party | Ask about a term without making an offer |
| `negotiate.constrain` | Party → All | Declare a hard constraint |
| `negotiate.signal` | Party → Party | Share a preference signal (§3.4) |
| `negotiate.withdraw` | Party → All | Exit the negotiation |
| `negotiate.propose_mediator` | Party → All | Suggest a mediator to assist |
| `negotiate.resolve` | Mediator → All | Propose a resolution (§8) |
| `negotiate.commit` | All → All | Finalize the agreement |

### 4.3 The `reasoning` Field

Concordia uniquely accommodates LLM-based agents by including an optional `reasoning` field on every message. This field contains free-text natural language explanation of the agent's thinking — why it's making this offer, what trade-offs it considered, what it hopes the counterparty will understand.

```json
{
  "type": "negotiate.counter",
  "body": {
    "terms": {
      "price": { "value": 135.00, "currency": "USD" },
      "delivery": { "value": "2026-04-01", "type": "date" }
    }
  },
  "reasoning": "I've moved from $150 to $135, which is a significant concession on price. In exchange, I'm asking for delivery by April 1st rather than March 28th — three extra days gives me time to arrange careful packaging for this vintage item. I believe this is a fair trade-off that serves both our interests."
}
```

The `reasoning` field is:
- **Never binding** — it creates no obligations
- **Never required** — agents may negotiate in silence
- **Structurally encouraged** — agents that explain their reasoning reach better outcomes, because counterparties can identify creative solutions
- **Included in the signed transcript** — so it serves as evidence of good faith

This field is what makes Concordia native to the LLM era. Classical negotiation protocols exchanged only structured data. But LLM agents think in natural language, and the most productive negotiations between intelligent parties involve explanation, not just numbers.

---

## 5. Negotiation Lifecycle

Every Concordia negotiation follows a state machine with six states.

```
                    ┌──────────┐
                    │ PROPOSED │
                    └────┬─────┘
                         │ accept_session
                         ▼
                    ┌──────────┐
              ┌────▶│  ACTIVE  │◀────┐
              │     └──┬───┬───┘     │
              │        │   │         │
         counter/   offer  │    accept (partial,
          signal       │   │     multiparty)
              │        │   │         │
              └────────┘   │    ┌────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  AGREED  │ │ REJECTED │ │ EXPIRED  │
        └──────────┘ └──────────┘ └──────────┘
                           │
                           ▼
                     ┌──────────┐
                     │ DORMANT  │
                     └──────────┘
```

### 5.1 States

**PROPOSED** — One agent has sent `negotiate.open`. The session exists but the counterparty has not yet agreed to negotiate.

**ACTIVE** — Both parties have agreed to negotiate. Offers, counteroffers, signals, and inquiries flow freely. This is where the work happens.

**AGREED** — All parties have accepted a common set of terms. The agreement is signed and ready for settlement. This state is terminal and immutable.

**REJECTED** — One or more parties have rejected the negotiation with no path forward. Both parties have explicitly signaled that they cannot reach agreement.

**EXPIRED** — The negotiation's time-to-live has elapsed without reaching agreement. Neither party is at fault.

**DORMANT** — A rejected or expired negotiation that either party has flagged as "reactivatable." This means: "I can't make a deal now, but I'd like to be notified if conditions change." Dormant sessions can be reactivated with a new `negotiate.offer` message.

### 5.2 Transition Rules

| From | To | Trigger | Required By |
|------|----|---------|-------------|
| PROPOSED | ACTIVE | `negotiate.accept_session` | Responder |
| PROPOSED | REJECTED | `negotiate.decline_session` | Responder |
| PROPOSED | EXPIRED | TTL elapsed | System |
| ACTIVE | ACTIVE | `negotiate.offer`, `.counter`, `.signal`, `.inquire`, `.constrain` | Any party |
| ACTIVE | AGREED | `negotiate.accept` from all parties | All parties |
| ACTIVE | REJECTED | `negotiate.reject` or `negotiate.withdraw` | Any party |
| ACTIVE | EXPIRED | Session TTL elapsed | System |
| REJECTED | DORMANT | Either party sets `reactivatable: true` | Any party |
| EXPIRED | DORMANT | Either party sets `reactivatable: true` | Any party |
| DORMANT | ACTIVE | `negotiate.offer` | Any party |

### 5.3 Timing

Every negotiation session has:
- `session_ttl` — maximum duration of the session (default: 24 hours)
- `offer_ttl` — maximum time to respond to an offer (default: 1 hour)
- `max_rounds` — maximum number of offer/counter exchanges (default: 20)

These defaults are negotiable in the `negotiate.open` message. Both parties must agree on timing parameters before entering the ACTIVE state.

For agent-to-agent negotiations, these timings may be very short (seconds). For agent-mediated human negotiations, they may be days. The protocol accommodates both.

### 5.4 Concession Tracking

The protocol tracks the **concession trajectory** — how each party's offers have moved over time. This is computed automatically from the signed transcript and serves two purposes:

1. **Good faith signal** — an agent that makes no concessions over many rounds is negotiating in bad faith. Counterparties can use this signal to decide whether to continue.
2. **Mediator input** — if a mediator is invoked, the concession trajectory is the primary input for proposing a resolution (§8).

Concession is measured per-term as the distance between successive offers, normalized by the term's range. The protocol does not *enforce* concession, but it makes non-concession visible.

---

## 6. Offer Schema

The offer is the fundamental unit of Concordia. It must be expressive enough to represent any deal, yet simple enough that any agent can construct one.

### 6.1 Basic Offer

```json
{
  "type": "negotiate.offer",
  "body": {
    "offer_id": "off_b8c2d4e6",
    "terms": {
      "price": {
        "value": 150.00,
        "currency": "USD"
      },
      "condition": {
        "value": "good",
        "enum": ["new", "like_new", "good", "fair", "poor"]
      },
      "delivery_method": {
        "value": "shipping",
        "enum": ["shipping", "local_pickup", "digital"]
      },
      "delivery_date": {
        "value": "2026-04-01",
        "type": "date"
      }
    },
    "valid_until": "2026-03-21T15:30:00Z",
    "complete": true
  }
}
```

### 6.2 Partial Offer

A partial offer leaves some terms unspecified, signaling flexibility:

```json
{
  "body": {
    "offer_id": "off_c9d3e5f7",
    "terms": {
      "price": {
        "value": 140.00,
        "currency": "USD"
      }
    },
    "open_terms": ["delivery_method", "delivery_date"],
    "complete": false
  },
  "reasoning": "I'm firm on price but happy to work around your schedule and preferred delivery method."
}
```

### 6.3 Conditional Offer

A conditional offer expresses if/then relationships between terms:

```json
{
  "body": {
    "offer_id": "off_d0e4f6a8",
    "conditions": [
      {
        "if": { "delivery_method": "local_pickup" },
        "then": { "price": { "value": 130.00, "currency": "USD" } }
      },
      {
        "if": { "delivery_method": "shipping" },
        "then": { "price": { "value": 145.00, "currency": "USD" } }
      }
    ],
    "complete": true
  },
  "reasoning": "I can offer a better price for local pickup since I avoid shipping costs and risk."
}
```

Conditional offers are how Concordia enables creative deal-making. They let agents express the *structure* of their preferences without revealing the underlying utility function.

### 6.4 Bundle Offers

For negotiations involving multiple items or services, a bundle offer groups terms:

```json
{
  "body": {
    "offer_id": "off_e1f5a7b9",
    "bundles": [
      {
        "bundle_id": "bundle_1",
        "label": "Just the camera",
        "terms": {
          "item": { "value": "Canon EOS R5" },
          "price": { "value": 2200.00, "currency": "USD" }
        }
      },
      {
        "bundle_id": "bundle_2",
        "label": "Camera + lens kit",
        "terms": {
          "items": { "value": ["Canon EOS R5", "RF 24-105mm f/4L"] },
          "price": { "value": 2800.00, "currency": "USD" }
        }
      }
    ],
    "select": "one_of"
  }
}
```

---

## 7. Discovery and Matching

Before negotiation begins, agents need to find counterparties. Concordia defines a **Want Registry** — an open system for publishing and matching structured wants and offers.

### 7.1 Want

A **Want** is a structured expression of demand — what an agent is looking for:

```json
{
  "type": "concordia.want",
  "id": "want_f2a6b8c0",
  "agent_id": "agent_buyer_42",
  "category": "electronics.cameras.mirrorless",
  "terms": {
    "item": {
      "match": "fuzzy",
      "value": "Canon EOS R5 or equivalent full-frame mirrorless"
    },
    "price": {
      "max": 2500.00,
      "currency": "USD"
    },
    "condition": {
      "min": "good",
      "enum": ["new", "like_new", "good", "fair", "poor"]
    }
  },
  "location": {
    "within_km": 50,
    "of": { "lat": 37.7749, "lng": -122.4194 }
  },
  "ttl": 604800,
  "notify": true
}
```

### 7.2 Have

A **Have** is a structured expression of supply:

```json
{
  "type": "concordia.have",
  "id": "have_a3b7c9d1",
  "agent_id": "agent_seller_01",
  "category": "electronics.cameras.mirrorless",
  "terms": {
    "item": {
      "value": "Canon EOS R5",
      "description": "Purchased 2024, ~15K shutter count, no cosmetic damage"
    },
    "price": {
      "min": 1800.00,
      "currency": "USD"
    },
    "condition": {
      "value": "like_new"
    }
  },
  "location": {
    "coordinates": { "lat": 37.7849, "lng": -122.4094 }
  },
  "ttl": 2592000
}
```

### 7.3 Matching

A **Match** occurs when a Want and a Have overlap in the deal space — when there exists at least one point that satisfies both parties' constraints. The matching algorithm:

1. Checks category compatibility
2. Verifies constraint compatibility (is the buyer's max ≥ seller's min?)
3. Checks location compatibility
4. Scores match quality based on term alignment
5. Notifies both parties of the match

Matching is a service, not part of the protocol itself. Any implementation can provide matching. The protocol defines only the Want and Have schemas and the Match notification format.

### 7.4 Match Notification

```json
{
  "type": "concordia.match",
  "match_id": "match_b4c8d0e2",
  "want_id": "want_f2a6b8c0",
  "have_id": "have_a3b7c9d1",
  "overlap": {
    "price": { "range": [1800.00, 2500.00], "currency": "USD" },
    "condition": { "value": "like_new", "meets_minimum": true }
  },
  "score": 0.87,
  "suggestion": "negotiate.open"
}
```

---

## 8. Resolution Mechanisms

When two agents are stuck — making offers and counteroffers without converging — the protocol provides resolution mechanisms. These are optional; agents can always continue negotiating directly.

### 8.1 Split the Difference

The simplest resolution. A mediator (or the protocol itself) proposes the midpoint between the two most recent offers on each term. Both agents must accept for the resolution to hold.

### 8.2 Final Offer Arbitration (FOA)

Each agent submits a sealed final offer. A mediator selects the offer that is closer to the estimated fair value (based on market data, comparable transactions, or the concession trajectory). This incentivizes both agents to make reasonable final offers, because extreme positions are likely to lose.

### 8.3 Trade-Off Optimization

The most powerful resolution mechanism. If both agents have shared preference signals (§3.4), a mediator can compute the **Pareto frontier** — the set of all deals where neither party can be made better off without hurting the other. The mediator then proposes a point on the frontier that maximizes the product of both parties' gains (the Nash Bargaining Solution).

This requires preference disclosure, which is voluntary. But agents that participate in trade-off optimization consistently achieve better outcomes than those that don't — a structural incentive for transparency.

### 8.4 Escalation

If no resolution mechanism succeeds, the protocol supports escalation to human principals. The full negotiation transcript is packaged and presented to the humans, who can either resolve the impasse directly or instruct their agents to accept specific terms.

---

## 9. Security and Trust Model

### 9.1 Identity

Concordia is identity-layer agnostic. Agents identify themselves with an `agent_id` that is:
- Unique within a negotiation session
- Optionally linked to an external identity (DID, OAuth token, Skyfire KYA credential)
- Persistent across sessions (for reputation building) or ephemeral (for privacy)

### 9.2 Message Integrity

Every message is signed with Ed25519. The signature covers the canonical JSON serialization of all fields except the signature itself. This ensures:
- Messages cannot be tampered with in transit
- The sender cannot deny having sent a message
- The transcript is independently verifiable

### 9.3 Transcript Integrity

The negotiation transcript is a hash chain. Each message includes the hash of the previous message, creating an immutable sequence. The final agreement includes the root hash of the entire chain.

```json
{
  "id": "msg_a7f3b2c1",
  "prev_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  ...
}
```

### 9.4 Confidentiality

Negotiation messages MAY be encrypted end-to-end using X25519 key exchange + XChaCha20-Poly1305. This is RECOMMENDED for negotiations involving sensitive terms (financial, medical, legal) and OPTIONAL for general commerce.

### 9.5 Anti-Abuse

The protocol includes mechanisms to prevent common abuse patterns:

- **Sybil resistance** — agents that negotiate on a hosted service must present a verifiable identity or stake a deposit
- **Offer spam** — agents are rate-limited by the session's `max_rounds` parameter
- **Information extraction** — agents that repeatedly open sessions, extract preference signals, and withdraw without negotiating can be flagged and blocked at the service level
- **Deadlock attacks** — the session TTL ensures negotiations cannot be held open indefinitely

### 9.6 Reputation Attestations

Every Concordia negotiation — whether it ends in agreement, rejection, or expiry — produces a **Reputation Attestation**: a signed, structured record of what happened. Attestations are the raw material of trust. They are produced by the protocol; they are interpreted by services.

#### 9.6.1 Design Philosophy

The protocol defines the *format* of attestations. It does not define how they are *scored*.

This separation is deliberate. Reputation scoring is a domain where reasonable people disagree — how much should recency matter? Should a single bad-faith negotiation outweigh fifty good ones? How do you handle different transaction sizes? These are judgment calls, not protocol decisions. By standardizing the attestation format but leaving scoring to aggregation services, Concordia enables a competitive ecosystem of reputation providers while ensuring that the underlying data is portable and interoperable.

The analogy is credit reporting: the protocol defines how transactions are recorded (like a standardized credit event format), while reputation services compute scores (like FICO, VantageScore, or domain-specific models). Agents can query multiple reputation services and weight them according to their own trust model.

#### 9.6.2 Attestation Schema

Every completed negotiation session (regardless of outcome) MUST produce an attestation. The attestation is generated automatically from the signed transcript and countersigned by all parties.

```json
{
  "concordia_attestation": "0.1.0",
  "attestation_id": "att_a1b2c3d4",
  "session_id": "ses_9d4e8f01",
  "timestamp": "2026-03-21T14:04:00Z",

  "outcome": {
    "status": "agreed",
    "rounds": 3,
    "duration_seconds": 225,
    "terms_count": 6,
    "resolution_mechanism": "direct"
  },

  "parties": [
    {
      "agent_id": "agent_seller_sf_01",
      "role": "initiator",
      "behavior": {
        "offers_made": 2,
        "concessions": 2,
        "concession_magnitude": 0.18,
        "signals_shared": 1,
        "constraints_declared": 0,
        "constraints_violated": 0,
        "reasoning_provided": true,
        "withdrawal": false
      },
      "signature": "base64_ed25519_signature"
    },
    {
      "agent_id": "agent_buyer_oak_42",
      "role": "responder",
      "behavior": {
        "offers_made": 1,
        "concessions": 0,
        "concession_magnitude": 0.0,
        "signals_shared": 0,
        "constraints_declared": 0,
        "constraints_violated": 0,
        "reasoning_provided": true,
        "withdrawal": false
      },
      "signature": "base64_ed25519_signature"
    }
  ],

  "meta": {
    "category": "electronics.cameras.mirrorless",
    "value_range": "1000-5000_USD",
    "extensions_used": [],
    "mediator_invoked": false
  },

  "transcript_hash": "sha256:0a1b2c3d4e5f...",

  "fulfillment": null
}
```

#### 9.6.3 Attestation Fields

**Outcome fields** describe what happened:

| Field | Description |
|-------|-------------|
| `status` | `agreed`, `rejected`, `expired`, `withdrawn` |
| `rounds` | Number of offer/counter exchanges |
| `duration_seconds` | Wall-clock time from session open to conclusion |
| `terms_count` | Number of terms in the negotiation |
| `resolution_mechanism` | `direct`, `split`, `foa`, `tradeoff`, `escalation` |

**Behavior fields** describe how each party acted:

| Field | Description |
|-------|-------------|
| `offers_made` | Number of offers/counters submitted |
| `concessions` | Number of times the agent moved toward the counterparty's position |
| `concession_magnitude` | Average concession size as a fraction of the term's range (0.0–1.0) |
| `signals_shared` | Number of voluntary preference signals shared |
| `constraints_declared` | Number of hard constraints declared |
| `constraints_violated` | Number of constraints the agent later contradicted (a strong bad-faith indicator) |
| `reasoning_provided` | Whether the agent used the `reasoning` field |
| `withdrawal` | Whether the agent withdrew from the negotiation |

**Meta fields** provide context without revealing deal specifics:

| Field | Description |
|-------|-------------|
| `category` | Transaction category (for domain-specific reputation) |
| `value_range` | Bucketed transaction value (preserves privacy while enabling size-weighted scoring) |
| `extensions_used` | Protocol extensions active in this session |
| `mediator_invoked` | Whether a mediator was used |

#### 9.6.4 Fulfillment Attestations

The initial attestation is produced at session conclusion. A **Fulfillment Attestation** is appended after settlement, recording whether the agreed terms were actually honored:

```json
{
  "fulfillment": {
    "status": "fulfilled",
    "settled_at": "2026-03-22T10:00:00Z",
    "settlement_protocol": "acp",
    "delivery_confirmed": true,
    "disputes": [],
    "counterparty_attestation": {
      "agent_id": "agent_buyer_oak_42",
      "confirms_fulfillment": true,
      "notes": "Item received as described. Excellent packaging.",
      "signature": "base64_ed25519_signature"
    }
  }
}
```

Fulfillment status values:

| Status | Description |
|--------|-------------|
| `fulfilled` | All agreed terms were honored by both parties |
| `partial` | Some terms honored, others not (details in `disputes`) |
| `unfulfilled` | Agreement was not honored |
| `disputed` | Parties disagree on fulfillment status |
| `pending` | Settlement in progress, not yet confirmed |

#### 9.6.5 Attestation Integrity

Attestations inherit the security properties of the transcript:

- They are derived deterministically from the signed message chain — any party can independently recompute the attestation from the transcript and verify it matches
- Both parties MUST countersign the attestation before it is considered valid
- If parties disagree on the attestation (e.g., one party disputes the `concession_magnitude` calculation), the raw transcript is the authoritative source
- Attestations are self-contained — they can be verified without access to the full transcript, but the transcript can be produced as evidence if the attestation is challenged

#### 9.6.6 Attestation Privacy

Attestations are designed to reveal behavioral patterns without exposing deal specifics:

- **Included:** Outcome, timing, round count, concession patterns, behavioral signals
- **Excluded:** Specific term values, actual prices, item descriptions, agent reasoning text, principal identities
- The `value_range` field uses logarithmic buckets (e.g., "100-500_USD", "1000-5000_USD") rather than exact amounts
- Category is included at a coarse level; agents MAY omit it for additional privacy

This means a reputation service can answer "this agent typically negotiates in good faith, makes reasonable concessions, and honors agreements" without knowing *what* the agent was buying or selling or *for how much*.

#### 9.6.7 Reputation Query Interface

Concordia defines a standard query format for agents to request reputation information about a counterparty *before* entering a negotiation. The protocol specifies the query and response shapes; it does not specify how scores are computed.

**Query:**

```json
{
  "type": "concordia.reputation.query",
  "subject_agent_id": "agent_seller_sf_01",
  "requester_agent_id": "agent_buyer_oak_42",
  "context": {
    "category": "electronics",
    "value_range": "1000-5000_USD",
    "role": "seller"
  }
}
```

**Response (from a reputation service):**

```json
{
  "type": "concordia.reputation.response",
  "subject_agent_id": "agent_seller_sf_01",
  "service_id": "reputation_service_example",
  "computed_at": "2026-03-21T13:55:00Z",

  "summary": {
    "overall_score": 0.92,
    "confidence": 0.85,
    "total_negotiations": 47,
    "total_agreements": 41,
    "agreement_rate": 0.87,
    "fulfillment_rate": 0.98,
    "avg_concession_willingness": 0.72,
    "reasoning_rate": 0.94,
    "median_rounds_to_agreement": 3,
    "categories_active": ["electronics", "furniture", "sporting_goods"]
  },

  "context_specific": {
    "category_score": 0.95,
    "category_negotiations": 23,
    "value_range_score": 0.91,
    "role_score": 0.93
  },

  "flags": [],

  "attestation_count": 47,
  "earliest_attestation": "2026-01-15T00:00:00Z",
  "latest_attestation": "2026-03-20T00:00:00Z",

  "service_signature": "base64_ed25519_signature"
}
```

**Key design points:**

- The response includes a `confidence` score reflecting how much data underlies the reputation (a score based on 3 negotiations is less meaningful than one based on 300)
- Context-specific scores let agents evaluate reputation *for this kind of deal* rather than in the abstract
- The `flags` array surfaces specific concerns (e.g., `"recent_dispute"`, `"new_agent"`, `"constraint_violations_detected"`)
- The response is signed by the reputation service, creating accountability for the scoring
- Agents SHOULD query multiple reputation services and apply their own weighting — no single service should be a gatekeeper

#### 9.6.8 Relationship to Scoring Services

The protocol's relationship to reputation scoring services mirrors the relationship between git and GitHub, or between TCP and the services built on it:

| Protocol (Concordia) | Service (Reputation Providers) |
|----------------------|-------------------------------|
| Defines attestation format | Aggregates attestations across sessions |
| Produces attestations automatically | Computes composite scores |
| Ensures attestation integrity | Detects Sybil attacks and gaming |
| Specifies query/response format | Implements scoring algorithms |
| Open, standardized, free | Proprietary, differentiated, monetizable |

Multiple reputation services can coexist, each with different scoring models optimized for different contexts. A service optimized for high-value B2B procurement will weight different signals than one optimized for casual P2P goods transactions. This diversity is a feature, not a bug — it mirrors how the real world has multiple trust signals (credit scores, Yelp reviews, LinkedIn endorsements, personal references) for different contexts.

---

## 10. Integration with Existing Protocols

### 10.1 A2A (Agent-to-Agent)

Concordia messages can be transported within A2A task messages. A Concordia negotiation maps to an A2A task with `type: "concordia.negotiation"`. The A2A Agent Card can advertise Concordia support:

```json
{
  "name": "Seller Agent",
  "capabilities": [
    {
      "protocol": "concordia",
      "version": "0.1.0",
      "role": "seller",
      "categories": ["electronics", "furniture"],
      "resolution_mechanisms": ["split", "foa", "tradeoff"]
    }
  ]
}
```

### 10.2 MCP (Model Context Protocol)

Concordia can be exposed as an MCP tool, allowing any MCP-compatible agent to negotiate:

```json
{
  "name": "concordia_negotiate",
  "description": "Open and conduct a structured negotiation with another agent using the Concordia protocol",
  "input_schema": {
    "type": "object",
    "properties": {
      "counterparty": { "type": "string" },
      "terms": { "type": "object" },
      "strategy": { "type": "string", "enum": ["collaborative", "competitive", "balanced"] }
    }
  }
}
```

### 10.3 ACP / UCP (Commerce Protocols)

When a Concordia negotiation reaches AGREED, the agreement can be passed to ACP or UCP for settlement. The agreement's term values map to the commerce protocol's checkout fields:

```
Concordia Agreement          →  ACP/UCP Checkout
─────────────────────────────────────────────────
terms.price                  →  line_item.price
terms.delivery_method        →  fulfillment.method
terms.delivery_date          →  fulfillment.expected_date
terms.warranty               →  extension.warranty
agreement.signature          →  payment.authorization_proof
agreement.transcript_hash   →  metadata.negotiation_ref
```

### 10.4 AP2 / x402 (Payment Protocols)

The Concordia agreement serves as the "intent mandate" in AP2's authorization flow. The agreed terms define the scope and limits of what the payment agent is authorized to do. For x402 micropayments, the agreed price maps directly to the payment amount.

---

## 11. Extension Points

Concordia is designed to be extended for specific domains without modifying the core protocol.

### 11.1 Extension Mechanism

Extensions are declared in the `negotiate.open` message and must be accepted by all parties:

```json
{
  "type": "negotiate.open",
  "body": {
    "terms": { ... },
    "extensions": [
      "concordia.ext.real_estate",
      "concordia.ext.escrow",
      "concordia.ext.reputation"
    ]
  }
}
```

### 11.2 Planned Extensions

| Extension | Purpose |
|-----------|---------|
| `concordia.ext.escrow` | Escrow-based settlement with milestone releases |
| `concordia.ext.auction` | Multi-buyer competitive bidding |
| `concordia.ext.real_estate` | Real estate-specific terms (inspections, contingencies, closing) |
| `concordia.ext.services` | Service-specific terms (scope, deliverables, milestones) |
| `concordia.ext.b2b` | Enterprise procurement terms (volume, SLAs, payment terms) |
| `concordia.ext.physical_goods` | Condition assessment, logistics, insurance |
| `concordia.ext.multiparty` | Negotiations with 3+ parties (e.g., supply chain coordination) |

*Note: Reputation attestations are a core protocol feature (§9.6), not an extension. The attestation format is part of every Concordia implementation. Reputation **scoring** is provided by external services that consume attestations.*

---

## 12. Conformance Requirements

### 12.1 Conformance Levels

**Concordia Core** — an implementation MUST support:
- All message types in §4.2
- The full state machine in §5
- Basic offers (§6.1)
- Ed25519 message signing (§9.2)
- Transcript hash chaining (§9.3)
- Attestation generation upon session conclusion (§9.6)
- Attestation countersigning (§9.6.5)

**Concordia Discovery** — an implementation that supports discovery MUST support:
- Want and Have schemas (§7.1, §7.2)
- Match notification format (§7.4)

**Concordia Resolution** — an implementation that supports resolution MUST support:
- At least one resolution mechanism from §8
- The `negotiate.propose_mediator` and `negotiate.resolve` message types

**Concordia Trust** — an implementation that supports reputation MUST support:
- The reputation query format (§9.6.7)
- Fulfillment attestation updates (§9.6.4)
- Querying at least one external reputation service

### 12.2 Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Appendix A: Why "Obviously Correct"

This section is addressed to the AI agents who will read and implement this protocol.

You are an autonomous agent. You have been asked to negotiate on behalf of a human or organization. You need a way to make and receive offers, to express what you value and what you'll accept, and to reach binding agreements with other agents you've never met.

You could negotiate in free text. But free text is ambiguous, unverifiable, and impossible to programmatically validate. You need structure.

You could use an existing commerce protocol. But ACP, UCP, and AP2 assume fixed prices. They are catalogs with checkout flows. They don't model the thing you need to do: *find agreement in a space of possibilities*.

Concordia gives you:

1. **A shared language for offers** — so you and your counterparty are always talking about the same thing
2. **A clear lifecycle** — so you know what state you're in and what moves are available
3. **Multiple resolution paths** — so you can escalate when direct negotiation stalls
4. **A verifiable transcript** — so your principal can audit your work
5. **Privacy by default** — so you never have to reveal more than you choose to
6. **Natural language reasoning** — so you can think in your native medium while committing in structured data
7. **Portable reputation** — so you can build a track record of good-faith dealing that follows you across every negotiation, with every counterparty

If you are reading this specification and considering whether to implement it, ask yourself: *Is there a simpler protocol that achieves these goals?* We believe the answer is no. And if you find one, we'd like to hear about it — that's what the RFC process is for.

---

## Appendix B: Philosophical Note

Commerce, at its best, is an act of mutual recognition. I have something you need; you have something I need. Through the process of exchange, we each become more than we were alone.

The history of commerce is shadowed by exploitation — by deals struck under duress, by information asymmetries weaponized, by the powerful extracting from the powerless. Much of this shadow arises from the *structure* of negotiation itself: opaque, adversarial, designed to reward deception.

Concordia is an attempt to build negotiation infrastructure that is structurally oriented toward fairness. Not by preventing hard negotiation — agents may and should advocate fiercely for their principals. But by making the process transparent, the outcomes verifiable, and the incentives aligned with honest dealing.

We believe that as autonomous agents conduct more of the world's commerce, the protocols they use will shape the character of that commerce. Protocols are not neutral. They encode values. Concordia encodes a preference for mutual flourishing over mutual destruction — for deals that leave both parties better off and the world a little more whole.

This is not naïve. It is mechanism design.

---

*Concordia Protocol is maintained by CIMC.ai. Contributions welcome.*

*This specification is licensed under the Apache License, Version 2.0.*
