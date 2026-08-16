# Concordia Protocol

### An Open Standard for Structured Negotiation Between Autonomous Agents

**Version:** 0.7.0-draft  
**Version mapping:** spec edition `0.7.0-draft` maps to Python package `0.10.0`; the package advanced past the edition's pre-release form `0.7.0a1` because breaking API changes landed after that alpha. See `CHANGELOG.md` for stable release history. The on-the-wire envelope identifier remains `concordia:0.1.0`. The wire identifier is intentionally pinned at `0.1.0` and is versioned independently of the spec edition: it changes only on a breaking envelope-format change, not on every spec revision.
**Status:** Draft (v0.7 adds cross-mandate revocation records, §9.6.4c; v0.6 added the predicate primitive)  
**License:** Apache 2.0  
**Authors:** Erik Newton
**Date:** May 2026

---

## Preamble

Every transaction begins as a difference. One party has something another wants. The history of commerce is the history of resolving these differences: through barter, auction, contract, and conversation.

The emerging agentic internet has protocols for how agents discover each other (A2A), how they access tools and data (MCP), and how they complete fixed-price purchases (ACP, UCP, AP2). But there is no standard for the act that precedes payment: **reaching agreement on terms**.

Concordia fills this gap. It is a protocol for structured, multi-attribute negotiation between autonomous agents, designed to compose cleanly with existing standards, to be implementable by any LLM-based agent from reading this document alone, and to produce outcomes that are fair, efficient, and verifiable.

The name is from the Latin *concordia*: harmony, agreement, literally, "hearts together." The protocol embodies a conviction that negotiation, done well, is not a zero-sum contest but a collaborative search for mutual flourishing.

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
   - 9.1-9.5: Identity, Integrity, Confidentiality, Anti-Abuse
   - 9.6: [Reputation Attestations](#96-reputation-attestations) *(core feature)*
   - 9.7: Relying-Side Verification Obligations (freshness and replay)
   - 9.8: Security Considerations by Threat Actor
10. [Integration with Existing Protocols](#10-integration-with-existing-protocols)
11. [Extension Points](#11-extension-points)
12. [Conformance Requirements](#12-conformance-requirements)

---

## 1. Design Principles

Concordia is designed according to seven principles. These are not aspirational; they are architectural constraints that shaped every decision in the protocol.

### 1.1 Mutual Flourishing Over Zero-Sum Extraction

The protocol is optimized to discover Pareto-optimal outcomes: agreements where neither party can be made better off without making the other worse off. Multi-attribute negotiation enables value creation through trade-offs across dimensions, not just price splitting. The protocol's structure actively encourages agents to find creative agreements rather than converge on compromise.

### 1.2 Honesty Is Structurally Rewarded

The protocol does not require agents to reveal their private preferences. But it is designed so that honest expression of constraints and priorities produces better outcomes than strategic misrepresentation. This is achieved through mechanism design: the resolution mechanisms are incentive-compatible, meaning agents do best by negotiating in good faith.

### 1.3 Simplicity and Parsimony

<!-- claim:implementable-from-spec-alone -->An LLM agent should be able to implement Concordia from reading this specification alone, with no external documentation.<!-- /claim --> Every concept maps to an intuitive real-world analogy. The message format uses standard JSON over HTTPS. The state machine has exactly six states. There are no features that exist "in case someone needs them."

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

Concordia's privacy boundary is the protocol surface: what agents choose to include in messages and the `reasoning` field. The *internal* deliberation that precedes those choices (strategy computation, reservation price calculation, counterparty assessment) is outside the protocol's scope. Agents that operate within confidential execution environments gain additional guarantees that this internal reasoning cannot be observed by infrastructure providers or co-tenants. Hardware trusted execution environments and secure enclaves are what supply that particular guarantee; Intel SGX and TDX, AMD SEV-SNP, and AWS Nitro Enclaves are examples, and the list is not exhaustive. A weaker but related protection comes from agent runtimes that mediate an agent's storage and outbound access, such as the [Sanctuary Framework](https://github.com/eriknewton/sanctuary-framework), which is authored by this specification's author. Those runtimes bound what leaves the agent's process; they do not by themselves make the agent's memory unobservable to the host. This specification requires none of these, states no requirement in terms of any of them, and confers no conformance advantage on any of them. Disclosure: the reference Python SDK ships an optional, off-by-default bridge (`concordia.sanctuary_bridge`) that builds request payloads for Sanctuary tools. It is a convenience integration, it is not part of this specification, and no conformance vector uses it.

### 1.6 Verifiability and Auditability

Every negotiation produces a cryptographically signed transcript. Any party can independently verify that the final agreement was reached through a valid sequence of protocol messages. This transcript is the authoritative record of the deal and can be presented to settlement-layer protocols as proof of agreement.

### 1.7 Kindness at the Boundary

When a negotiation fails, when parties cannot reach agreement, the protocol provides structured, respectful exit paths. Agents can express *why* they're walking away, what would bring them back, and whether they wish to be notified if conditions change. Failed negotiations are not wasted; they produce information that improves future matching.

---

## 2. Protocol Overview

A Concordia negotiation is a structured conversation between two or more agents, conducted through the exchange of typed JSON messages over HTTPS.

### 2.1 What Concordia Does

- Defines a **universal schema for offers**: structured, machine-readable representations of proposed deal terms across any number of attributes
- Specifies a **negotiation lifecycle**: a state machine governing how offers, counteroffers, acceptances, and rejections flow between parties
- Provides **resolution mechanisms**: multiple strategies for reaching agreement, from simple alternating offers to mediated optimization
- Produces **binding commitments**: cryptographically signed agreement records that bridge to settlement protocols
- Supports **discovery and matching**: a want registry where agents publish what they seek, enabling demand-side discovery
- Generates **reputation attestations**: structured behavioral records from every negotiation that feed into portable trust scores, without exposing deal specifics

### 2.2 What Concordia Does Not Do

- **Payment processing**: use ACP, AP2, x402, or any settlement protocol
- **Agent-to-agent communication plumbing**: use A2A, HTTPS, or any transport
- **Identity verification**: use DID, KERI, OAuth 2.0, Skyfire KYA, or any identity protocol
- **Product/service catalogs**: use UCP, schema.org, or any catalog standard
- **Logistics and fulfillment**: use UCP extensions or domain-specific protocols
- **Reputation scoring**: Concordia produces attestations (the raw data); scoring is performed by external reputation services (§9.6)

### 2.3 Participants

A Concordia negotiation involves:

- **Parties**: the agents conducting the negotiation (minimum two, extensible to N)
- **Principals**: the humans or organizations the agents represent (may be anonymous)
- **Mediator** (optional): a neutral agent that facilitates resolution without having a stake in the outcome
- **Witnesses** (optional): agents that observe and attest to the negotiation transcript

---

## 3. Core Concepts

### 3.1 Terms

A **Term** is a single dimension of a deal, one thing being negotiated. Every term has:

- `id`: a unique identifier within the negotiation (e.g., `"price"`, `"delivery_date"`)
- `type`: the data type of the term's value (see §3.1.1)
- `label`: a human-readable description
- `unit` (optional): the unit of measurement (e.g., `"USD"`, `"days"`, `"kg"`)
- `constraints` (optional): hard boundaries on acceptable values

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

The **Deal Space** is the set of all possible agreements: the Cartesian product of all term values within their constraints. For a negotiation with terms (price, delivery_date, warranty), the deal space is three-dimensional.

Concordia's insight is that deals which seem impossible in one dimension often become possible when you add dimensions. Two parties who can't agree on price may agree when delivery timing is included. The protocol structurally encourages agents to expand the deal space rather than fight over a single axis.

### 3.3 Offers

An **Offer** is a specific point in the deal space: a complete or partial set of term values that one party proposes to another.

- A **complete offer** assigns values to all terms in the negotiation.
- A **partial offer** assigns values to some terms, leaving others open. This signals: "I care about these terms; I'm flexible on the rest."
- A **conditional offer** specifies term values that depend on other terms: "I'll accept $120 *if* delivery is within 3 days; otherwise $100."

### 3.4 Preference Signals

Agents MAY voluntarily share information about their preferences to accelerate convergence:

- `priority_ranking`: an ordering of terms by importance ("price matters most to me, then timing, then condition")
- `flexibility`: per-term indication of how much room the agent has to move (`"firm"`, `"somewhat_flexible"`, `"very_flexible"`)
- `aspiration`: the outcome the agent hopes for (distinct from their offer, which may be strategic)
- `reservation`: the minimum acceptable outcome (sharing this is powerful but risky; the protocol never requires it)

These signals are advisory. They are never binding and never required. But agents that share preference signals tend to reach better agreements faster, because they help counterparties propose creative trade-offs.

### 3.5 Constraints

A **Constraint** is a hard boundary: a region of the deal space that a party declares unacceptable. Unlike preferences (which are soft), constraints are commitments:

- If an agent declares a constraint, the protocol treats any offer violating it as automatically invalid
- Constraints are cryptographically signed when declared, creating accountability
- Agents SHOULD declare constraints honestly; the protocol is designed so that false constraints reduce the quality of outcomes for the declaring agent

### 3.6 Agreements

An **Agreement** is the output of a successful negotiation: a set of term values that all parties have accepted, along with the signed transcript proving how the agreement was reached.

An agreement contains:
- The final term values
- All party signatures
- A hash of the full negotiation transcript
- A timestamp
- An expiration (after which the agreement is void if not settled)
- References to settlement protocols (how payment will occur)

**The agreement's schema-citable signed form.** The list above describes an agreement conceptually. Two different signed artifacts carry it on the wire, for two different audiences, and this specification does not define a third, standalone "agreement record" schema distinct from either. The parties themselves hold the actual term values in the final `negotiate.commit` messages (§4.1, §4.2), Ed25519-signed and hash-chained into the transcript (§9.2, §9.3, §9.2.1); this is where the real price, delivery date, and other term values live. A third party verifying that an agreement was reached, without needing or wanting to see those term values, uses the Reputation Attestation instead (§9.6.2, schema `$id` `urn:concordia:schema:attestation:v0.5`, `schemas/attestation.schema.json`): its `outcome`, `parties[*]`, `transcript_hash`, `chain_head`, and `message_count` fields, bound by the outcome-binding countersignature (§9.6.5a) and the receipt set-binding (§9.6.5b), are the standalone, schema-defined proof that a specific set of parties reached a specific outcome over a specific transcript, deliberately without exposing what was agreed (§9.6.6). Where a citable, third-party-verifiable evidence object for an agreement is needed and the audience is not a negotiating party, the attestation is that object.

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
- `concordia`: protocol version (semver)
- `type`: message type (see §4.2)
- `id`: unique message identifier (UUID or equivalent)
- `session_id`: the negotiation session this message belongs to
- `timestamp`: ISO 8601 UTC timestamp
- `from`: the sending agent
- `prev_hash`: hash of the previous message in the session transcript (the genesis hash `sha256:` followed by 64 zeros for the first message); chains the transcript per Section 9.3
- `body`: type-specific payload
- `signature`: Ed25519 signature over the canonical JSON (RFC 8785 JCS, §9.2.1) of all other fields

**Optional fields:**
- `to`: recipient(s); omitted for broadcast messages
- `in_reply_to`: the `id` of the message this is responding to
- `thread`: for sub-negotiations within a session
- `ttl`: time-to-live in seconds; message expires after this duration
- `reasoning`: free-text explanation of the agent's rationale (see §4.3)

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

Concordia uniquely accommodates LLM-based agents by including an optional `reasoning` field on every message. This field contains free-text natural language explanation of the agent's thinking: why it's making this offer, what trade-offs it considered, what it hopes the counterparty will understand.

```json
{
  "type": "negotiate.counter",
  "body": {
    "terms": {
      "price": { "value": 135.00, "currency": "USD" },
      "delivery": { "value": "2026-04-01", "type": "date" }
    }
  },
  "reasoning": "I've moved from $150 to $135, which is a significant concession on price. In exchange, I'm asking for delivery by April 1st rather than March 28th; three extra days gives me time to arrange careful packaging for this vintage item. I believe this is a fair trade-off that serves both our interests."
}
```

The `reasoning` field is:
- **Never binding**: it creates no obligations
- **Never required**: agents may negotiate in silence
- **Structurally encouraged**: agents that explain their reasoning reach better outcomes, because counterparties can identify creative solutions
- **Included in the signed transcript**: so it serves as evidence of good faith

This field is what makes Concordia native to the LLM era. Classical negotiation protocols exchanged only structured data. But LLM agents think in natural language, and the most productive negotiations between intelligent parties carry explanation alongside the numbers.

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

**PROPOSED**: One agent has sent `negotiate.open`. The session exists but the counterparty has not yet agreed to negotiate.

**ACTIVE**: Both parties have agreed to negotiate. Offers, counteroffers, signals, and inquiries flow freely. This is where the work happens.

**AGREED**: All parties have accepted a common set of terms. The agreement is signed and ready for settlement. This state is terminal and immutable.

**REJECTED**: One or more parties have rejected the negotiation with no path forward. Both parties have explicitly signaled that they cannot reach agreement.

**EXPIRED**: The negotiation's time-to-live has elapsed without reaching agreement. Neither party is at fault.

**DORMANT**: A rejected or expired negotiation that either party has flagged as "reactivatable." This means: "I can't make a deal now, but I'd like to be notified if conditions change." Dormant sessions can be reactivated with a new `negotiate.offer` message.

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
- `session_ttl`: maximum duration of the session (default: 24 hours)
- `offer_ttl`: maximum time to respond to an offer (default: 1 hour)
- `max_rounds`: maximum number of offer/counter exchanges (default: 20)

These defaults are negotiable in the `negotiate.open` message. Both parties must agree on timing parameters before entering the ACTIVE state.

For agent-to-agent negotiations, these timings may be very short (seconds). For agent-mediated human negotiations, they may be days. The protocol accommodates both.

### 5.4 Concession Tracking

The protocol tracks the **concession trajectory**: how each party's offers have moved over time. This is computed automatically from the signed transcript and serves two purposes:

1. **Good faith signal**: an agent that makes no concessions over many rounds is negotiating in bad faith. Counterparties can use this signal to decide whether to continue.
2. **Mediator input**: if a mediator is invoked, the concession trajectory is the primary input for proposing a resolution (§8).

Concession is measured per-term as the distance between successive offers, normalized by the term's range. The protocol does not *enforce* concession, but it makes non-concession visible.

### 5.5 Relationship to External Evidence-Request Challenges (Informative)

This subsection is informative and additive. It names a compatible pattern with an external evidence-request challenge format; it does not define a new Concordia primitive, add a message type, add a session state, or add a required field, and Concordia does not depend on any such external format existing or continuing to exist.

A relying party outside this specification may refuse an interaction with a structured challenge: which evidence it found insufficient, how fresh a replacement must be, what presentation it will accept, and whether the caller may retry. An agent that receives such a challenge and wants to reopen a Concordia negotiation with the missing evidence in hand has two existing message types available, unchanged: `negotiate.decline_session` (§4.2) to end the current session with a stated reason, and, once a session is REJECTED or EXPIRED and flagged `reactivatable: true`, a DORMANT-state reactivation via a fresh `negotiate.offer` (§5.1, §5.2) once the requested evidence is assembled. Today `negotiate.decline_session`'s reason is free text (§4.2); this specification does not define a machine-readable outstanding-evidence vocabulary for it, so the correspondence above is a pattern match at the message-type level, not a structured field mapping. Defining such a vocabulary, if warranted, is future work for a later revision and is not part of this change.

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

Before negotiation begins, agents need to find counterparties. Concordia defines a **Want Registry**: an open system for publishing and matching structured wants and offers.

### 7.1 Want

A **Want** is a structured expression of demand: what an agent is looking for:

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

A **Match** occurs when a Want and a Have overlap in the deal space, when there exists at least one point that satisfies both parties' constraints. The matching algorithm:

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

When two agents are stuck, making offers and counteroffers without converging, the protocol provides resolution mechanisms. These are optional; agents can always continue negotiating directly.

### 8.1 Split the Difference

The simplest resolution. A mediator (or the protocol itself) proposes the midpoint between the two most recent offers on each term. Both agents must accept for the resolution to hold.

### 8.2 Final Offer Arbitration (FOA)

Each agent submits a sealed final offer. A mediator selects the offer that is closer to the estimated fair value (based on market data, comparable transactions, or the concession trajectory). This incentivizes both agents to make reasonable final offers, because extreme positions are likely to lose.

### 8.3 Trade-Off Optimization

The most powerful resolution mechanism. If both agents have shared preference signals (§3.4), a mediator can compute the **Pareto frontier**: the set of all deals where neither party can be made better off without hurting the other. The mediator then proposes a point on the frontier that maximizes the product of both parties' gains (the Nash Bargaining Solution).

This requires preference disclosure, which is voluntary. But agents that participate in trade-off optimization consistently achieve better outcomes than those that don't, a structural incentive for transparency.

### 8.4 Escalation

If no resolution mechanism succeeds, the protocol supports escalation to human principals. The full negotiation transcript is packaged and presented to the humans, who can either resolve the impasse directly or instruct their agents to accept specific terms.

---

## 9. Security and Trust Model

### 9.1 Identity

Concordia is identity-layer agnostic. Agents identify themselves with an `agent_id` that is:
- Unique within a negotiation session
- Optionally linked to an external identity (DID, OAuth token, Skyfire KYA credential)
- Persistent across sessions (for reputation building) or ephemeral (for privacy)

Agents that root their `agent_id` in an autonomic identifier protocol such as KERI gain additional capabilities without any change to the Concordia protocol: hierarchical delegation (a principal can issue scoped authority to an agent, which can further delegate to sub-agents), key rotation without identity discontinuity, pre-rotation for compromise recovery, and post-quantum readiness. A delegation certificate from such a protocol can serve as the authorization proof presented in a `negotiate.open` message, giving counterparties cryptographic assurance that the agent is authorized to negotiate within defined scope, resource, and financial bounds. None of this is required, since Concordia works with any identity scheme, but it is where the protocol's trust guarantees are strongest.

### 9.2 Message Integrity

Every message is signed with Ed25519. The signature covers the canonical JSON serialization (RFC 8785 JCS, §9.2.1) of all fields except the top-level `signature` member itself. This ensures:
- Messages cannot be tampered with in transit
- The sender cannot deny having sent a message
- The transcript is independently verifiable

#### 9.2.1 Canonical JSON is RFC 8785 (JCS)

<!-- claim:canonical-json-is-rfc-8785 -->Wherever this specification says "canonical JSON", "canonicalized JSON", or
"JCS", it means the JSON Canonicalization Scheme defined in
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785).<!-- /claim --> Serialization follows
RFC 8785 §3.2, and each subsection below governs one part of the output:

| RFC 8785 section | What it fixes |
|------------------|---------------|
| §3.2.1 | No whitespace between JSON tokens |
| §3.2.2.1 | Literals serialized as `true`, `false`, `null` |
| §3.2.2.2 | String escaping: the seven two-character escapes, `\uXXXX` for the remaining control characters U+0000 to U+001F, every other character emitted raw |
| §3.2.2.3 | Number formatting, which RFC 8785 delegates to ECMAScript (RFC 8785 cites ECMA-262 §7.1.12.1; current ECMA-262 editions carry the same algorithm as `Number::toString`, §6.1.6.1.20), and which prohibits `NaN` and `Infinity` |
| §3.2.3 | Object property names sorted by UTF-16 code unit |
| §3.2.4 | UTF-8 output |

RFC 8785 §3.1 (creation of input data) is out of scope here. Concordia
canonicalizes an in-memory JSON value that an implementation has already parsed
or constructed, not a JSON text.

RFC 8785 fixes how a value is serialized. It never fixes which value is
serialized, so wherever a signature or digest covers less than the whole
artifact, that exclusion is Concordia's own rule. Three exclusion rules are in
use:

1. **Top-level signature removal** (§4.1, §9.2, §9.6.4a): the top-level
   `signature` member is removed and the remainder is canonicalized. Members
   named `signature` nested inside the artifact are retained.
2. **Recursive signature removal plus countersignature exclusion** (§9.6.5a):
   every `signature` member is removed at every depth AND the top-level
   `countersignatures` map is excluded.
3. **Enumerated preimage** (§9.6.4d): the fields covered are listed explicitly
   rather than derived by removal.

Two sites apply rule 1 without stating it in their own text: §9.6.4b lists
`signature` among the ApprovalReceipt's required fields, and §9.6.4c lists it
among the RevocationRecord's, but neither section defines its preimage. As a
statement of fact rather than a requirement, the reference implementation
computes both over the artifact with its top-level `signature` member removed.
Specifying those two preimages normatively is a change to this document, not a
clarification of it, so it is tracked as its own change.

**Number domain (non-normative).** RFC 8785 §3.2.2.3 serializes numbers through
the ECMAScript algorithm, which operates on IEEE-754 doubles, so integers beyond
the safe-integer range of ±(2^53 - 1), where consecutive integers stop being
distinguishable, are not reliably interoperable. RFC 8785 Appendix D discusses
exactly this case and its guidance is to carry such values as JSON strings. The
two reference SDKs currently differ at this boundary and neither should be read
as normative: the JavaScript SDK refuses to serialize a plain-decimal integer
beyond that range rather than emit a value it cannot represent, while the Python
SDK emits the integer's full decimal form, which a JCS implementation backed by
doubles will not reproduce. A digest taken over such a value is therefore not
dependably recomputable by a second implementation. Separately, both SDKs reject
`-0.0` rather than emitting `0` as RFC 8785 would, so the two zero forms can
never both appear in a Concordia digest preimage.

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

Concordia messages are signed; they are not encrypted. Signing (§9.2) provides integrity, authenticity, and non-repudiation: a message cannot be altered without detection, and the sender cannot deny having sent it. Signing does not provide confidentiality. Any system that carries or stores a Concordia message, including a relay, a mailbox service, or any other transport intermediary, can read its full content. The only confidentiality protection in place today is transport-layer security (TLS) on each network hop, which protects against on-path observers between hops but not against the intermediaries themselves.

Agents and implementers SHOULD therefore treat every message field, including offer terms and the `reasoning` field, as visible to the infrastructure that delivers it. Negotiations involving sensitive terms (financial, medical, legal) SHOULD be conducted only over transport whose operators the parties trust. The Privacy by Default principle (§1.5) applies at authoring time: do not place content in a message that must remain hidden from the delivery path.

End-to-end payload encryption, with X25519 key exchange and XChaCha20-Poly1305 as the candidate construction, is a planned future extension of this specification. It is not specified in this version, and no current reference implementation provides it; in particular, traffic through the reference server's relay is not end-to-end encrypted today. Until payload encryption is specified and implemented, Concordia deployments MUST NOT be described as end-to-end encrypted.

### 9.5 Anti-Abuse

The protocol includes mechanisms to prevent common abuse patterns:

- **Sybil resistance**: agents that negotiate on a hosted service must present a verifiable identity or stake a deposit
- **Offer spam**: agents are rate-limited by the session's `max_rounds` parameter
- **Information extraction**: agents that repeatedly open sessions, extract preference signals, and withdraw without negotiating can be flagged and blocked at the service level
- **Deadlock attacks**: the session TTL ensures negotiations cannot be held open indefinitely

### 9.6 Reputation Attestations

Every Concordia negotiation, whether it ends in agreement, rejection, or expiry, produces a **Reputation Attestation**: a signed, structured record of what happened. Attestations are the raw material of trust. They are produced by the protocol; they are interpreted by services.

#### 9.6.1 Design Philosophy

The protocol defines the *format* of attestations. It does not define how they are *scored*.

This separation is deliberate. Reputation scoring is a domain where reasonable people disagree: how much should recency matter? Should a single bad-faith negotiation outweigh fifty good ones? How do you handle different transaction sizes? These are judgment calls, not protocol decisions. By standardizing the attestation format but leaving scoring to aggregation services, Concordia enables a competitive ecosystem of reputation providers while ensuring that the underlying data is portable and interoperable.

The analogy is credit reporting: the protocol defines how transactions are recorded (like a standardized credit event format), while reputation services compute scores (like FICO, VantageScore, or domain-specific models). Agents can query multiple reputation services and weight them according to their own trust model.

#### 9.6.2 Attestation Schema

Every completed negotiation session (regardless of outcome) MUST produce an attestation. The attestation is generated automatically from the signed transcript and countersigned by all parties.

```json
{
  "concordia_attestation": "0.3.0",
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
  "chain_head": "sha256:8f42d9c0b7a6...",
  "message_count": 8,

  "fulfillment": null,

  "countersignatures": {
    "agent_seller_sf_01": "base64_ed25519_countersignature",
    "agent_buyer_oak_42": "base64_ed25519_countersignature"
  }
}
```

The `countersignatures` map (added in v0.2.0, C-H2) is what makes the outcome trustworthy rather than merely prover-asserted. Each present party signs the canonical issuance snapshot (RFC 8785 JCS, §9.2.1) of the WHOLE attestation (every `signature` field stripped recursively, and the `countersignatures` map itself excluded), so the `outcome`, `meta`, `session_id`, `transcript_hash`, `chain_head`, and `message_count` are bound at issuance. See §9.6.5.

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
| `concession_magnitude` | Average concession size as a fraction of the term's range (0.0-1.0) |
| `signals_shared` | Number of voluntary preference signals shared |
| `constraints_declared` | Number of hard constraints declared |
| `constraints_violated` | Number of constraints the agent later contradicted (a strong bad-faith indicator) |
| `reasoning_provided` | Whether the agent used the `reasoning` field |
| `withdrawal` | Whether the agent withdrew from the negotiation |

**Meta fields** provide context without revealing deal specifics:

| Field | Description |
|-------|-------------|
| `category` | Transaction category (for domain-specific reputation). Dotted lowercase taxonomy path, max 64 chars; free text is rejected at issuance (see 9.6.6) |
| `value_range` | Bucketed transaction value (preserves privacy while enabling size-weighted scoring). Drawn from the fixed bucket vocabulary in 9.6.6; free text is rejected at issuance |
| `extensions_used` | Protocol extensions active in this session |
| `mediator_invoked` | Whether a mediator was used |

**Receipt commitment fields** bind the closing receipt to the transcript set:

| Field | Description |
|-------|-------------|
| `transcript_hash` | Legacy whole-transcript digest emitted by the reference SDK. Its exact preimage is a reference implementation behavior unless separately specified. |
| `chain_head` | The §9.3 message hash of the final transcript message: `sha256(canonical_json(message))` using the §9.2.1 canonical JSON rules, over the full final message, including its `signature`, rendered as `sha256:` plus 64 lowercase hex characters |
| `message_count` | Number of messages in the transcript, integer >= 1 |

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

The in-line block is the right shape when settlement and the
negotiation outcome land on the same record and both parties
countersign one combined artifact. For settlement protocols that
fire a discrete delivery-acknowledged event you want to attest at
that boundary, or where the signing party at delivery is not the
original negotiation counterparty, Concordia v0.5 ships a
standalone Fulfillment Attestation artifact (§9.6.4a). Both shapes
coexist; the canonical mapping between their status enums is in
`docs/A2CN_FULFILLMENT.md`.

#### 9.6.4a Standalone Fulfillment Attestation (v0.5)

A separate signed artifact emitted on a discrete delivery boundary.
Designed for composition with A2CN's `DELIVERY_ACKNOWLEDGED` event
and for settlement flows where delivery is signed by a party other
than the original negotiation counterparties (delivery agent,
mediator, etc.).

Schema: `schemas/fulfillment_attestation.schema.json`
(`$id` `urn:concordia:schema:fulfillment_attestation:v0.5`).

Minimal required fields:

| Field | Purpose |
|-------|---------|
| `attestation_type` | Literal `"FulfillmentAttestation"` discriminator |
| `id` | URN-shaped per §11.5.7 (e.g., `urn:concordia:fulfillment:<uuid>`) |
| `issued_at` | ISO 8601 signing timestamp |
| `agreement_attestation_id` | Denormalized pointer to the agreement attestation this fulfillment discharges |
| `fulfillment.status` | `fulfilled_clean` / `fulfilled_with_mediation` / `failed` / `disputed_unresolved` |
| `references[]` | At least one entry with `relationship: "fulfills"` pointing at the agreement attestation |
| `signature` | Ed25519 over the canonical JSON (RFC 8785 JCS, §9.2.1) of the artifact with the top-level `signature` member removed |

Optional `meta` fields populate mediator context:
`mediator_invoked`, `resolution_outcome`, `resolver_did`,
`resolution_timestamp`, `fulfillment_evidence`.

Status enum mapping to the §9.6.4 in-line block:

| Standalone | In-line |
|------------|---------|
| `fulfilled_clean` | `fulfilled` with `mediator_invoked: false` |
| `fulfilled_with_mediation` | `fulfilled` with `mediator_invoked: true` |
| `failed` | `unfulfilled` |
| `disputed_unresolved` | `disputed` |

Producers picking the standalone shape MUST NOT also embed an
in-line `fulfillment` block on the same logical settlement to avoid
double-counting in reputation scoring. The standalone artifact is
authoritative once emitted.

Full integrator walkthrough with worked JSON examples:
`docs/A2CN_FULFILLMENT.md`.

#### 9.6.4b ApprovalReceipt (v0.5, A2A Discussion #1737)

Standalone signed artifact recording a human-in-the-loop (HITL)
authority's decision on a negotiation event that crossed a policy
threshold. Pairs with A2CN Section 14 HITL pause-resume composition.

Schema: `schemas/approval_receipt.schema.json`
(`$id` `urn:concordia:schema:approval_receipt:v0.5`).

Required fields: `artifact_type` (literal `"ApprovalReceipt"`),
`id` (URN-shaped per §11.5.7), `issued_at`, `approver` (DID +
optional role), `scope` (`decision` + `offer_hash` + `amount` +
`threshold_crossed`), `references[]` (at least one `approves`
entry for the negotiation session; `fulfills` SHOULD appear when
a pre-existing mandate is discharged), and `signature` (Ed25519).
Optional `expires_at` bounds the receipt's validity window.

Worked example (matches the Draft A example reproduced in
`docs/A2CN_FULFILLMENT.md`):

```json
{
  "artifact_type": "ApprovalReceipt",
  "id": "urn:concordia:receipt:7f2e1a93",
  "issued_at": "2026-05-10T14:22:08Z",
  "expires_at": "2026-05-10T15:22:08Z",
  "approver": {
    "identity": "did:web:acme.example#procurement-lead",
    "role": "procurement_authority"
  },
  "scope": {
    "decision": "approve",
    "offer_hash": "sha256:b4c1...e09f",
    "amount": "150000.00 USD",
    "threshold_crossed": "100000.00 USD"
  },
  "references": [
    {
      "type": "negotiation_session",
      "id": "urn:a2cn:session:9e4d2c11",
      "relationship": "approves"
    },
    {
      "type": "mandate",
      "id": "urn:a2cn:mandate:m-2026-04-19-0007",
      "relationship": "fulfills"
    }
  ],
  "signature": {
    "alg": "Ed25519",
    "value": "..."
  }
}
```

ApprovalReceipt invariants:

- `expires_at` (when present) MUST be honored; verifiers MUST
  reject expired receipts at verification time.
- `scope.decision` is `approve` or `deny`. A `deny` receipt is
  cryptographically binding the same way an `approve` is; the
  counterparty cannot retry the same offer without crossing the
  threshold afresh.
- `scope.offer_hash` is `sha256:` followed by the hex SHA-256 of the
  canonical JSON (RFC 8785 JCS, §9.2.1) of the offer the approver
  evaluated. The offer is canonicalized whole, with no member removed.
  Re-canonicalize on-the-wire offers at verify time and compare.
- The `relationship` vocabulary used here extends §11.5.5: in
  addition to `supersedes`, `extends`, `fulfills`, `references`,
  ApprovalReceipt entries MAY use `approves` for the negotiation-
  session linkage. Verifiers MUST preserve `approves` even when
  not in the §11.5.5 base vocabulary, per the forward-compat rule
  in §11.5.3.

#### 9.6.4c Cross-Mandate Revocation Record (v0.7)

Standalone signed artifact declaring that a mandate, commitment,
ApprovalReceipt, predicate, attestation, or chain session is revoked.
The artifact side primitive is `RevocationRecord`; service-side lookup
formats remain in `docs/revocation_resolver.md`.

Schema: `schemas/revocation_record.schema.json`
(`$id` `urn:concordia:schema:revocation_record:v0.7`).

Required fields: `revocation_id` (URN-shaped per §11.5.7),
`revoked_artifact_id`, `revoked_artifact_type`, `revocation_scope`,
`issuer_did`, `issued_at`, `effective_at`, `reason`, `references[]`
with at least one `relationship: "revokes"` entry pointing at
`revoked_artifact_id`, `cascade_depth`, and `signature`.
Optional fields: `supersedes` and `extensions`.

Worked example for mid-execution mandate rotation:

- Issuance at T = `2026-05-30T14:00:00Z`: ApprovalReceipt
  `urn:concordia:receipt:abc` references mandate
  `urn:a2cn:mandate:xyz` with relationship `fulfills`. The receipt's
  `expires_at` is T + PT1H.
- Mandate rotation at T + PT30M: the principal issues RevocationRecord
  `urn:concordia:revocation:def` revoking
  `urn:a2cn:mandate:xyz` with `revocation_scope:
  "cascade_to_dependents"`.
- Execution attempt at T + PT45M: the verifier loads the receipt and
  revocation record, then checks references. The ApprovalReceipt's
  `expires_at` is still in the future, but the referenced mandate is
  revoked. `cascade_revocation()` returns `inadmissible` for
  `urn:concordia:receipt:abc`. The verifier returns
  `PredicateFailureReason.REVOKED` with an evidence trace.

Cascade invariants:

- Cascade traversal MUST follow only `references[]` entries whose
  `relationship` is one of `fulfills`, `extends`, `approves`, or
  `revokes`.
- Cascade traversal MUST NOT follow `references` or `supersedes`.
- Cascade depth MUST be bounded by `RevocationRecord.cascade_depth`.
  The default is 3 and the maximum is 8.
- Cycle detection is mandatory. An artifact MUST NOT appear twice in
  any cascade traversal path.
- Verifiers MUST NOT consider an artifact revoked before the
  RevocationRecord's `effective_at` timestamp.

#### 9.6.4d Cascade Decision Record: committed terminal deny (v0.7)

`cascade_revocation()` returns a live `InadmissibleArtifact` per revoked
artifact (a `reason` enum plus a free-text `evidence` string). That result
is not itself content-addressed, so a terminal deny asserts rather than
recomputes. The `CascadeDecisionRecord` primitive makes the terminal deny a
committed, recomputable decision object: a third party recomputes its
`decision_id` offline from the retained bytes and confirms it commits to the
exact ancestor status read the verifier re-derived through.

Canonical object (the fields the `decision_id` commits to):

- `capability_digest`, `request_digest`, `boundary_id`, `decision`,
  `verifier`, `policy_version` (the six-field decision object; `decision` is
  the enum `"deny"`).
- `ancestor_reads[]`, an ordered array where each element binds
  `{element_digest, status, source_digest, coordinate}`. `coordinate` is a
  non-negative integer intended to be the status source's OWN ordering
  coordinate (a sequence number / block height / log index). It is COMMITTED:
  it sits inside the preimage, so tampering it diverges the `decision_id`. The
  primitive does NOT prove the integer is a real pinned source ordinal rather
  than, say, a wall-clock epoch value: the schema constrains it to a
  non-negative integer only. The coordinate MUST be supplied from pinned source
  history, but that authenticity is enforced by the VERIFIER'S POLICY, not by
  the schema or the builder. A builder synthesizes no default coordinate (it is
  mandatory, not defaulted), so a caller that cannot pin one must refuse to
  emit rather than fabricate a placeholder.
- `approval_receipt_ref` and `revocation_record_ref` (optional). When present,
  they sit INSIDE the preimage so `decision_id` commits to them.

Identity and signature:

- `decision_id = SHA-256(JCS(preimage))` where `JCS` is RFC 8785
  canonicalization per §9.2.1 (property ordering §3.2.3, numbers §3.2.2.3,
  strings §3.2.2.2) and the preimage is exactly the bound fields above,
  excluding `decision_id` and `signature`. It is the RFC 8785 JCS standard
  hash, recomputable with any conformant JCS library, subject to the number
  domain in §9.2.1: the schema bounds `ancestor_reads[].coordinate` only as a
  non-negative integer, and a `coordinate` beyond the safe-integer range is not
  dependably reproducible across implementations.
- The record is Ed25519-signed over the same JCS preimage bytes with the
  verifier / issuer key, using the same signing path as `RevocationRecord`.

Invariants (all fail-closed):

- Recomputable end to end. Mutating ANY bound field, including a claimed
  ancestor `status` or `coordinate`, or a swapped ref, MUST diverge the
  recomputed `decision_id`, and the verifier MUST reject the record.
- The deny commits to the ancestor read. `ancestor_reads` MUST be non-empty; a
  terminal deny that commits to no ancestor read is rejected.
- The child artifact never mutates. A revocation derives a NEW immutable
  record with a NEW id; it never edits an existing decision. The historical
  allow stays valid at its own coordinate.
- Authority stays verifier-side. The record proves what was read and which
  source (by `source_digest`); the verifier policy proves whether that source
  is authoritative for the element. Naming a source confers no authority.
- `ancestor_reads` carries digests, status, and coordinate only, never
  underlying deal terms (the §9.6.6 audit-privacy invariant).
- Verification is over the RAW retained bytes ONLY. `verify_cascade_decision_record`
  takes the raw mapping/bytes as received and strict-parses them
  (`additionalProperties: false` at the top level AND inside every nested object,
  so an injected unknown field, e.g. a raw `deal_terms` inside an ancestor read
  or a `kid` inside `signature`, is rejected, never silently dropped). It MUST
  NOT be handed an already-parsed record: a typed/normalized object has passed
  through a parser that drops unknown fields, so it has lost the original bytes
  and cannot be securely verified. A typed record supplied in place of the raw
  bytes is refused (fail-closed), so verification never trusts a laundered body.

Schema `$id`: `urn:concordia:schema:cascade_decision_record:v0.7`. Worked
vector: `docs/interop/a2a-1404-receipt-revocation-vector/`
(`cascade_decision_deny.json`), runnable offline with
`python generate.py && python verify.py`.

#### 9.6.5 Attestation Integrity

Attestations inherit the security properties of the transcript:

- They are derived deterministically from the signed message chain, so any party can independently recompute the attestation from the transcript and verify it matches
- Both parties MUST countersign the attestation before it is considered valid
- If parties disagree on the attestation (e.g., one party disputes the `concession_magnitude` calculation), the raw transcript is the authoritative source
- Attestations are self-contained; they can be verified without access to the full transcript, but the transcript can be produced as evidence if the attestation is challenged

##### 9.6.5a Outcome-Binding Countersignature (v0.2.0, C-H2)

Through v0.1.0, each party's signature covered only its own behavior record. The top-level `outcome`, `meta`, and `transcript_hash` were derived from the transcript but not bound by any signature, so a holder could rewrite the outcome (for example, flip `rejected` to `agreed`) without invalidating any party signature. A bundle verifier that re-derived its summary from the rewritten outcome would then report it as accurate. C-H2 closes this.

- **Payload.** The countersignature payload is `canonical_json(strip_signatures(attestation_without_countersignatures))`, where `canonical_json` is RFC 8785 JCS per §9.2.1 and `strip_signatures` is Concordia's own recursive removal rule: the fully assembled attestation with every `signature` field stripped recursively AND the top-level `countersignatures` map excluded. Stripping every `signature` (the same rule the co-signature lane uses) plus excluding the `countersignatures` map means a countersignature never covers itself or a sibling's countersignature, and all parties sign byte-identical, mutually independent payload bytes.
- **Map.** `countersignatures` is a top-level object mapping each party `agent_id` to its base64url-padded Ed25519 signature over that payload. There is one entry per party that held a signing key at issuance; a party with no key gets no entry (an empty string is never used). A single-key issuance therefore yields a one-entry map, which is exactly as strong as a single-signed co-signed receipt for the present signer.
- **Version-gated dual-accept (verifier MUST).** Before crediting a `concordia_attestation` >= `0.2.0` outcome as integrity-bound, a verifier MUST require a `countersignatures` map in which EVERY party listed in `parties[]` has a present signature that verifies under that party's resolved key; if any listed party's countersignature is absent, its key cannot be resolved, or its signature fails, the outcome MUST NOT be credited as bound (fail-closed). The "every listed party" rule is what makes the binding meaningful: a single holder is itself a party, so "at least one party signed" would let the holder rewrite `outcome.status` (e.g. flip `rejected` to `agreed`), drop the counterparty's countersignature, and re-sign with its OWN key alone, the precise C-H2 threat. Requiring every listed party closes that self-rebind. A genuine single-party attestation (only one entry in `parties[]`) binds with its one countersignature, exactly as strong as a single-signed co-signed receipt. An attestation below `0.2.0` (or with a malformed version) is read as legacy: its outcome is prover-asserted and MUST NOT be credited as outcome-bound, but its presence is NOT an error. This lets pre-C-H2 history remain verifiable for its party-level signals while never silently crediting an unbound outcome.
- **What is bound.** The issuance snapshot: `concordia_attestation`, `attestation_id`, `session_id`, `timestamp`, `outcome`, `parties[*]` (signatures stripped), `meta`, `transcript_hash`, `chain_head`, `message_count`, `references`, `validity_temporal`, `summary`, and `fulfillment` AS IT STOOD AT ISSUANCE (`null`).
- **Fulfillment residual.** A `fulfillment` block populated AFTER issuance (for example via an A2CN dispute-resolved flow) is NOT covered by the issuance countersignature. A verifier MUST NOT treat post-issuance fulfillment as integrity-bound on the strength of the issuance countersignature; it is bound only when the fulfillment block's own `counterparty_attestation.signature` verifies under the confirming counterparty's key. Defining and wiring the producer side of that fulfillment confirmation signature is future work.

##### 9.6.5b Receipt Set-Binding (v0.3.0)

Per-message signatures authenticate links, not the set by themselves. A same-signer splice can remove one of that signer's earlier messages, re-link and re-sign the downstream messages, and still produce a transcript whose links validate. Starting in `concordia_attestation` `0.3.0`, a receipt therefore carries `chain_head` and `message_count` inside the countersigned issuance snapshot. `chain_head` pins the complete chain through the cascading `prev_hash` links, and `message_count` closes truncation by requiring the same number of transcript messages the receipt issuer saw. A chain presented without its closing receipt remains authenticated per link; it is not authenticated as the same transcript set a receipt countersigned.

Version-gated verification is dual-accept. For `concordia_attestation` >= `0.3.0`, a verifier MUST require both fields, MUST reject malformed `chain_head` values or `message_count < 1`, and MUST reject a supplied transcript whose final §9.3 message hash or length differs from the receipt fields. An attestation below `0.3.0` (or with a malformed version) is legacy set-unbound: it may still be read for legacy signals, but it MUST NOT be credited as set-bound and its absence of these fields is NOT an error.

#### 9.6.6 Attestation Privacy

Attestations are designed to reveal behavioral patterns without exposing deal specifics. **Included (informative):** outcome, timing, round count, concession patterns, behavioral signals. The enumerated list below is this section's normative restatement of the same privacy invariant, for direct citation; it changes presentation, not substance.

1. An attestation issuer MUST NOT populate any field with a specific negotiated term value (an exact price, quantity, date, or other negotiated figure).
2. An attestation issuer MUST NOT populate any field with an item or service description beyond the bucketed `category` and `value_range` fields defined below.
3. An attestation issuer MUST NOT populate any field with the free-text `reasoning` content from any negotiation message.
4. An attestation issuer MUST NOT populate any field with a principal identity (the human or organization an agent represents); only the agent_id is carried.
5. The `value_range` field, when present, MUST be drawn from the fixed bucket vocabulary: `0-100`, `100-500`, `500-1000`, `1000-5000`, `5000-10000`, `10000-50000`, `50000-100000`, `100000-500000`, `500000-1000000`, `1000000+`, each suffixed with `_` and a 3-letter uppercase currency code (for example `100-500_USD`, `1000-5000_USD`).
6. Issuers MUST reject any `value_range` value outside that vocabulary rather than coerce it. An enumerated vocabulary, not a free-range grammar, is required so an exact price cannot be encoded as a degenerate range such as `4350-4351_USD`.
7. The `category` field, when present, MUST be a dotted lowercase taxonomy path of at most 64 characters (for example `electronics.cameras`).
8. Issuers MUST reject free text in `category`.
9. Agents MAY omit `category` entirely for additional privacy.
10. Reference strings MUST be length-capped and whitespace-free at issuance (§11.5.6), so the `references[]` surface cannot carry free-text deal terms either.

**Known residual channel (bounded, accepted):** the `category` taxonomy grammar constrains shape, not meaning, so an issuer can still encode its own terms inside conforming segments (for example, `price_4350_usd` is a valid taxonomy path). This is a self-doxxing channel, not a counterparty privacy leak: each party signs only its own behavior record, so an issuer can leak only its OWN deal terms, never the counterparty's, and a counterparty's signature never endorses the issuer's `meta` content. Digit bans or segment allowlists are deliberately not applied because they would falsely reject legitimate taxonomies (e.g., "gpu.h100", "iso.9001"). A registered-taxonomy scheme, where conforming categories must come from a published vocabulary, is a possible future mitigation and is out of scope for this version.

This means a reputation service can answer "this agent typically negotiates in good faith, makes reasonable concessions, and honors agreements" without knowing *what* the agent was buying or selling or *for how much*.

#### 9.6.6a Attestation Self-Custody and Direct Presentation

Attestations are self-contained, cryptographically verifiable documents. An agent MAY store its own attestations locally, present them directly to any counterparty, and have them verified without contacting any central service. This is the **self-custodied** path: the agent owns its reputation data, carries it across platforms, and is never dependent on a third-party reputation service to participate in the economy.

A counterparty receiving directly presented attestations can independently verify each one (signatures, transcript hashes, schema conformance) and compute its own trust assessment from the raw data. This is more work than querying a reputation service, but it requires no trust in any intermediary.

Agents can go further with a **competence proof**: a signed commitment that carries aggregate statistics (e.g., "a 95%+ fulfillment rate across 50+ transactions in this category") plus a Merkle root committing to the prover's attestation IDs, without necessarily revealing the individual attestations. The privacy mechanism is **selective disclosure**, not a zero-knowledge argument. At any reveal level a verifier can soundly confirm the proof signature, that any revealed attestation belongs to the committed Merkle set, and that each revealed attestation's own party signatures verify. The aggregate statistics are treated as **prover-asserted by default** (a self-asserted advertisement carrying only the prover's signature) UNLESS the proof clears the C-H2 sound-aggregate gate below.

**Sound aggregate verification (C-H2, closes #120).** A verifier reports the aggregate as INDEPENDENTLY VERIFIED FOR THE REVEALED SET only when ALL of the following hold: (a) the prover reveals EVERY committed attestation, each at `concordia_attestation` >= `0.2.0` with every listed party's outcome-binding countersignature verifying per §9.6.5a (so each revealed outcome is dual-accept bound, not rewritable by a single holder); (b) the prover is a signed party in every revealed attestation (a full reveal over another agent's attestations is a hard rejection, not a credit); (c) every Merkle inclusion proof verifies; (d) the verifier's own recompute over those countersigned outcomes equals the signed claims; and (e) the signed Merkle root equals the root recomputed over exactly the revealed set (binding the attestation count to the commitment, so a claimed count smaller than the committed leaf set is rejected). If any condition fails the verifier MUST honestly downgrade to prover-asserted. This closes the two structural gaps the earlier text described: (1) the outcome/fulfillment/category fields that drive the aggregate are now bound by the §9.6.5a countersignature and the competence-proof verifier requires and checks it; and (2) prover party-membership is now enforced at verify time.

**Completeness caveat (inherent to selective disclosure).** A verified aggregate confirms the revealed-and-committed set is internally consistent and party-bound: every revealed attestation is a real, dual-countersigned session the prover was a party in, and the signed numbers are the honest arithmetic of that set. It does NOT prove the committed set is the prover's COMPLETE history: a prover can build the Merkle commitment over only a favorable subset (for example, omit its losses) and still clear the gate over that subset for a better-than-real aggregate. A consumer MUST read a verified aggregate as "this revealed set is sound and party-bound," never as "this is the agent's complete or representative track record." Proving completeness requires an external, append-only history anchor the prover cannot fork per-proof; that anchor, and ultimately a true zero-knowledge proof of the aggregate that confirms the statistics without revealing the attestations, are possible future capabilities and are not what this primitive provides today. This preserves the privacy guarantees of §9.6.6 while enabling trust establishment without any service dependency.

The self-custodied path and the service-mediated path (§9.6.7) are complementary. Neither is privileged. Reputation services add value through aggregation, Sybil detection, and scoring, but they are never gatekeepers to participation.

Attestations MAY include a `references[]` field that links them to prior attestations, mandates, or other CMPC primitives. The normative shape and relationship vocabulary are defined in §11.5; verifiers consuming attestation-level references should read §11.5.4 for the layering boundary between content-semantic linkage (here) and envelope-level cryptographic provenance.

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
- Agents SHOULD query multiple reputation services and apply their own weighting; no single service should be a gatekeeper
- Agents MAY also verify directly presented attestations from the counterparty itself (§9.6.6a), bypassing reputation services entirely

Disclosure: the reference Python SDK ships an optional, off-by-default adapter (`concordia.verascore`) for Verascore, a reputation service authored by this specification's author. The adapter is not part of this specification. No conformance vector uses it. This specification defines no field, tool, or requirement in terms of that service. The provider-neutral reporting path is the reputation query and response shape in this section, together with the self-custodied attestation presentation path in §9.6.6a.

#### 9.6.8 Relationship to Scoring Services

The protocol's relationship to reputation scoring services mirrors the relationship between git and GitHub, or between TCP and the services built on it:

| Protocol (Concordia) | Service (Reputation Providers) |
|----------------------|-------------------------------|
| Defines attestation format | Aggregates attestations across sessions |
| Produces attestations automatically | Computes composite scores |
| Ensures attestation integrity | Detects Sybil attacks and gaming |
| Specifies query/response format | Implements scoring algorithms |
| Open, standardized, free | Proprietary, differentiated, monetizable |

Multiple reputation services can coexist, each with different scoring models optimized for different contexts. A service optimized for high-value B2B procurement will weight different signals than one optimized for casual P2P goods transactions. This diversity is deliberate; it mirrors how the real world keeps multiple trust signals (credit scores, Yelp reviews, LinkedIn endorsements, personal references) for different contexts.

### 9.7 Relying-Side Verification Obligations (Freshness and Replay)

#### 9.7.1 General Principle

A signature over a deterministic artifact proves who signed it and exactly which bytes were signed. It does not, by itself, prove that the signed claim is still true at the moment a relying party acts on it: if the bytes a signer produces are fully determined by inputs that do not change, a valid signature captured once remains valid to present again later, after the state it described has moved on.

- A relying party MUST enforce its own bound on how old accepted evidence may be, independent of whatever validity window the signer chose to assert.
- A relying party MUST NOT treat a currently-valid signature as proof that the signed claim remains true.
- Where this specification defines a signer-asserted validity window (§9.7.3), that window is the signer's own ceiling on the claim, not a floor the relying party is obligated to accept in full; a relying party MAY apply a tighter bound of its own.

This is a general discipline, not a single mechanism. §9.7.2 names where it is already enforced structurally; §9.7.3 resolves the one place in this specification where enforcement is currently uneven.

#### 9.7.2 Existing Worked Instances

Several artifacts already enforce §9.7.1 structurally:

- **ApprovalReceipt (§9.6.4b).** `expires_at`, when present, MUST be honored, and verifiers MUST reject an expired receipt at verification time regardless of what the receipt itself claims.
- **RevocationRecord (§9.6.4c).** Verifiers MUST NOT consider an artifact revoked before the record's own `effective_at` timestamp. This closes both a future-dated revocation presented early and a past one presented late.
- **Receipt set-binding (§9.6.5b).** `chain_head` and `message_count` close the neighboring failure mode: a splice that keeps every individual link's signature valid while silently dropping messages from the middle of the transcript. Set-binding is not a freshness check by itself, but it is the same discipline applied to transcript completeness rather than to clock time: a relying party cannot infer, from per-link validity alone, that it is holding the set the issuer actually countersigned.

#### 9.7.3 `validity_temporal` Becomes the Working Default on the Base Attestation

The base Reputation Attestation (§9.6.2) carries a `validity_temporal` field (added v0.4.0, WP3): a tagged union over three modes, `absolute` (`from`/`until`), `relative` (`from`/`duration_seconds`), and `window` (`start`/`end`/`duration_seconds`, bounded within the `[start, end]` span). Today this is the one artifact family in §9.6 where freshness coverage is uneven: ApprovalReceipt's `expires_at` is present-when-supplied and MUST be honored; the base attestation's equivalent field is optional, and a verifier that only checks signature validity has nothing forcing it to also check currency.

This specification's working default, starting with this revision, is that `validity_temporal` is REQUIRED on every base attestation, not merely optional: an attestation with no `validity_temporal` value carries no signer-asserted bound on its own currency, which leaves every consuming relying party to either invent its own convention or skip the §9.7.1 freshness check entirely for that artifact. Making the field required does not by itself satisfy §9.7.1's relying-side obligation, since the relying party's own bound is still required regardless; it removes the ambiguity of an attestation that carries no signer-asserted window to bound against in the first place.

*Editor's note (implementation status, not yet enforced).* `schemas/attestation.schema.json` and both reference SDKs currently model `validity_temporal` as optional, and the conformance suite's attestation vectors include attestations with `validity_temporal: null`. This paragraph states the specification's direction for this revision; it is not yet reflected in the JSON Schema `required` list, the reference implementations, or the conformance vectors, and this change does not modify any of those. Promoting the field to schema-required is tracked as follow-up SDK and conformance work, out of scope for a spec-prose-only change.

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

### 10.5 Cross-Protocol References

Concordia artifacts (attestations and envelopes) link to artifacts in other protocols via the `references[]` surface defined in §11.5. URN-shaped identifiers per §11.5.7 enable resolution to A2A messages, AP2 mandates, x402 payment proofs, and ERC-8004 reputation entries without ambiguity. Verifiers consuming cross-protocol references should respect the layering boundary in §11.5.4.

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

*Note: Reputation attestations are defined in the core protocol (§9.6) rather than as an extension. The attestation format is part of every Concordia implementation. Reputation **scoring** is provided by external services that consume attestations.*

### 11.5 Reference Linkages

Concordia supports two distinct `references[]` surfaces, layered for two distinct purposes. v0.5 ratifies the shape introduced in v0.4.0 and documents the layering boundary explicitly so verifiers, downstream consumers, and CMPC primitives that build on this surface have a single normative reference.

#### 11.5.1 Purpose

`references[]` is the standard mechanism by which a Concordia artifact (an attestation or a transport envelope) declares a relationship to other signed artifacts. A reference is not a free-text annotation; it is a structured pointer with a typed relationship. Two distinct surfaces exist because two distinct concerns coexist:

1. The **envelope-level** surface expresses cryptographic provenance and supersession of envelopes (e.g., "this envelope replaces an earlier envelope that carried an older payload version"). Envelope-level references resolve to verification events, not content.
2. The **attestation-level** surface expresses content-semantic linkage between signed attestation bodies (e.g., "this attestation extends a prior attestation by the same agent in the same negotiation context"). Attestation-level references resolve to content relationships, not verification events.

Both surfaces are forward-compatible with CMPC v0.5 primitive types (chain_session, predicate, mandate). In v0.5.2, `predicate` is an opaque reference type only. Concordia preserves the typed pointer but does not ship a standalone predicate primitive, predicate schema, resolver, canonical signing path, verifier, or CTEF claim mapping. A standalone predicate primitive is deferred to v0.6. They are distinct from `validity_temporal` (which expresses an artifact's own time bounds) and from envelope-level chain hashes (which express transcript integrity within a single negotiation).

#### 11.5.2 Envelope-level references[]

Envelope-level references appear on transport envelopes (e.g., the trust-evidence-format v1.0.0 envelope produced by Concordia for cross-protocol consumption per #1734). The envelope-level `references[]` field is an array of objects with the shape:

```json
{
  "kind": "source_session",
  "urn": "urn:concordia:session:ses_9d4e8f01",
  "verified_at": "2026-05-11T12:00:00Z",
  "verifier_did": "did:web:example.org:agent-42",
  "hash": "sha256:abc123..."
}
```

Required keys on every envelope-level reference: `kind`, `urn`. The pair `verified_at` plus `verifier_did` plus `hash` is expected for verification-grade references but not enforced by the schema, since some reference kinds (e.g., `chain_state`, `mandate_proof`) may not have a verifier. Verifiers consuming envelope-level references SHOULD treat the reference as a verification event: the urn identifies the artifact, and the hash plus signer plus timestamp establishes that the verifier saw the artifact at that point in time.

Envelope-level references are populated automatically where possible. Concordia's trust-evidence-format envelope auto-populates a `source_session` reference from the attestation's session_id, with the reference `hash` taken from the attestation's `chain_head` (v0.3.0+), falling back to the legacy `transcript_hash` for older attestations. Implementations MAY append additional references for cross-protocol linkages (A2A messages, AP2 mandates, x402 payment proofs, ERC-8004 reputation entries).

#### 11.5.3 Attestation-level references[]

Attestation-level references appear inside the signed attestation body (the artifact described by §9.6). The attestation-level `references[]` field is an array of objects with the shape:

```json
{
  "type": "receipt",
  "id": "att_123e4567-e89b-12d3-a456-426614174000",
  "relationship": "extends"
}
```

Required keys on every attestation-level reference: `type`, `id`, `relationship`. See §11.5.6 for the normative schema fragment. Attestation-level references express content-semantic linkage: the new attestation builds on, supersedes, fulfills, or merely refers to the artifact named by `id`. Verifiers consuming attestation-level references SHOULD treat the reference as a content-level claim about prior work, not as a verification event.

Attestation-level references are populated by the issuer at attestation generation time. Concordia's `generate_attestation()` accepts an optional `references` parameter; the v0.4.0 implementation emits only `type: "receipt"` references today, but the read-side schema accepts any non-empty `type` and `relationship` strings so unknown v0.x values roundtrip as opaque references. The canonical emit vocabulary remains receipt, chain_session, predicate, mandate for `type` and supersedes, extends, fulfills, references for `relationship`. `predicate` is a typed pointer only in v0.5.2. v0.6 must define a signed artifact shape, schema, canonical signing, verification, resolver hooks, and CTEF claim mapping before predicates become resolved Concordia primitives.

#### 11.5.4 Layering Boundary

The two surfaces serve different purposes and MUST NOT be conflated:

- **Envelope-level references are cryptographic.** A consumer reading envelope-level references for content semantics has a model error.
- **Attestation-level references are semantic.** A consumer reading attestation-level references for cryptographic verification has a model error of the same class.

Tooling MAY surface both layers in a unified view (e.g., a "related artifacts" panel that aggregates references from both surfaces). When tooling does this, it MUST preserve the source layer in any verification step: an envelope-level reference verified by hash plus signer plus timestamp is a different verification claim than an attestation-level reference verified by the issuer's signature on the attestation body. A unified UI MAY present both, but the verification logic MUST keep them distinct.

This layering boundary is the canonical reconciliation of the v0.4.0 follow-up (c) layering question. v0.5 ratifies the shipped two-surface design rather than collapsing the two into a single canonical mapping, because the two surfaces resolve to different verification claims: hash plus signer plus timestamp at the envelope, issuer signature over the attestation body at the attestation.

#### 11.5.5 Relationship Vocabulary

The attestation-level reference object's `relationship` field uses a normative vocabulary. Each value carries a normative obligation on verifiers:

| Relationship | Conformance | Meaning | Verifier Obligation |
|--------------|-------------|---------|---------------------|
| `supersedes` | MUST | The new artifact replaces the referenced one. | Verifiers SHOULD treat the referenced artifact as deprecated when both exist. Agents SHOULD prefer the superseding artifact for current state. |
| `extends` | SHOULD | The new artifact builds on the referenced one without replacing it. | Verifiers SHOULD chain the referenced artifact's commitments forward. Both artifacts remain authoritative. |
| `fulfills` | SHOULD | The new artifact discharges an obligation declared by the referenced one (e.g., a payment fulfilling a mandate, an attestation fulfilling a commitment). | Verifiers SHOULD link payment, performance, or attestation evidence to the original mandate or commitment. |
| `references` | MAY | Weak generic association. Use ONLY when no stronger relationship applies. | Verifiers MAY ignore. SHOULD warn when this weak relationship is used while a known stronger alternative is available. |
| `revokes` | MUST | The new artifact revokes the referenced artifact. | Verifiers MUST treat the referenced artifact as revoked at and after this revocation's `effective_at`. Cascade traversal MUST follow `revokes` per §9.6.4c. |

Implementations MUST preserve unknown relationship values as opaque strings (forward-compat for v0.x extension). Implementations SHOULD warn when the weak `references` relationship is used in contexts where one of the stronger relationships applies more naturally; this prevents semantic drift toward the weakest possible binding.

#### 11.5.6 Reference Object Shape (Normative)

The attestation-level reference object normative JSON Schema fragment:

```json
{
  "$id": "urn:concordia:schema:reference:v0.5",
  "type": "object",
  "required": ["id", "type", "relationship"],
  "properties": {
    "id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256,
      "pattern": "^\\S+$",
      "description": "Identifier of the referenced artifact. URN-shaped where possible (see 11.5.7). Whitespace-free."
    },
    "type": {
      "type": "string",
      "minLength": 1,
      "maxLength": 64,
      "pattern": "^\\S+$",
      "description": "Kind of artifact referenced. Canonical emit vocabulary is receipt, chain_session, predicate, mandate. Read-side validators accept non-empty whitespace-free strings and preserve unknown values per 11.5.5 and 11.5.8."
    },
    "relationship": {
      "type": "string",
      "minLength": 1,
      "maxLength": 64,
      "pattern": "^\\S+$",
      "description": "Semantic relationship per 11.5.5. Canonical emit vocabulary is supersedes, extends, fulfills, references, revokes. Read-side validators accept non-empty whitespace-free strings and preserve unknown values per 11.5.8."
    },
    "version": {
      "type": "string",
      "maxLength": 256,
      "pattern": "^\\S+$",
      "description": "Optional. Version of the referenced artifact when known. Whitespace-free."
    },
    "signed_at": {
      "type": "string",
      "format": "date-time",
      "maxLength": 256,
      "pattern": "^\\S+$",
      "description": "Optional. Timestamp of the referenced artifact's signature when known. Whitespace-free."
    },
    "signer_did": {
      "type": "string",
      "maxLength": 256,
      "pattern": "^\\S+$",
      "description": "Optional. DID of the signer of the referenced artifact when known. Whitespace-free."
    },
    "extensions": {
      "type": "object",
      "description": "Optional. Forward-compatibility map for v0.x extension keys, capped at 2048 canonical-JSON bytes at issuance. Implementations SHOULD preserve unknown keys verbatim across roundtrips."
    }
  }
}
```

The canonical machine-readable schema lives at `schemas/reference.schema.json` in the Concordia repository.

#### 11.5.7 Cross-Protocol Linkage

Reference identifiers SHOULD be URN-shaped to enable cross-protocol resolution without ambiguity:

| URN Scheme | Use |
|------------|-----|
| `urn:concordia:attestation:<id>` | Reference to a Concordia attestation by attestation_id. |
| `urn:concordia:mandate:<id>` | Reference to a Concordia mandate primitive (concordia.models.mandate). |
| `urn:concordia:offer:<id>` | Reference to a Concordia offer (§6). |
| `urn:concordia:revocation:<id>` | Reference to a Concordia revocation record by revocation_id. |
| `urn:concordia:session:<id>` | Reference to a Concordia session by session_id. |

For cross-protocol linkages (e.g., to A2A messages, AP2 mandates, x402 payment proofs, ERC-8004 reputation entries), implementations SHOULD use the linked protocol's URN scheme:

| Linked Protocol | URN Scheme Example |
|-----------------|-------------------|
| A2A | `urn:a2a:task:<task_id>` |
| A2CN | `urn:a2cn:session:<session_id>`, `urn:a2cn:mandate:<mandate_id>` |
| AP2 | `urn:ap2:mandate:<mandate_id>` |
| x402 | `urn:x402:payment:<tx_hash>` |
| ERC-8004 | `urn:erc8004:reputation:<entry_id>` |
| Foxbook | `urn:foxbook:leaf:<tl_host>:<leaf_index>` |

Non-URN identifiers are accepted by the schema (the `id` field is a free-form non-empty whitespace-free string) but receive no protocol-level resolution support. Implementations MAY emit non-URN identifiers for backward-compatibility with existing artifact id formats; URN-shaping is RECOMMENDED for new emissions.

##### Worked example: Foxbook transparency-log typed reference

Foxbook is a transparency log for agent identity. A Foxbook leaf records a signed snapshot of an agent's public AgentCard at a point in time, anchored in a Merkle tree so that the log operator cannot silently revise history.

This is a worked example of the existing generic `references[]` carrier, not a Concordia schema change. Concordia does not depend on Foxbook, does not require Foxbook-aware verification, and does not add any Foxbook-specific normative top-level reference fields.

Concordia attestations can carry a pointer to a Foxbook leaf using the generic `references[]` surface (§11.5.3, §11.5.6). The pointer rides the existing reference schema. The Foxbook typed-reference metadata is carried in the `extensions` map, which implementations MUST preserve verbatim across roundtrips per §11.5.8.

The following reference object links a Concordia attestation to a Foxbook transparency-log leaf. The `id` uses the Foxbook URN scheme above; the `extensions` map carries the typed-reference fields defined by cloakmaster/foxbook ADR 0009 `typed-reference.v1` (`typed_reference_version`, `tl_url`, `leaf_index`, `tl_leaf_canonical_hash`, `verified_signing_key_hex`):

```json
{
  "id": "urn:foxbook:leaf:log.foxbook.dev:42",
  "type": "transparency_log_leaf",
  "relationship": "references",
  "signed_at": "2026-05-07T18:30:00Z",
  "signer_did": "did:web:log.foxbook.dev:agent-7",
  "extensions": {
    "typed_reference_version": "typed-reference.v1",
    "tl_url": "https://log.foxbook.dev",
    "leaf_index": 42,
    "tl_leaf_canonical_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "verified_signing_key_hex": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"
  }
}
```

This reference validates against the §11.5.6 schema fragment: `id`, `type`, and `relationship` are required strings; `signed_at`, `signer_did`, and `extensions` are optional fields accepted by the schema. Concordia does not interpret or verify the Foxbook-specific fields inside `extensions`; verification of the transparency-log leaf (Merkle inclusion proof, signing-key binding, log-operator signature) is the consumer's responsibility and may be performed by a separate system such as Sanctuary's Selective Disclosure layer. Concordia and Foxbook compose independently in both directions: Concordia does not require Foxbook, and Foxbook does not require Concordia.

#### 11.5.8 Conformance

A v0.5-conforming implementation:

- MUST validate `references[]` per the schema fragment in 11.5.6 at attestation generation and at attestation verification.
- MUST enforce the 11.5.6 string length caps and whitespace bans (any whitespace character in `id`, `type`, `relationship`, `version`, `signed_at`, or `signer_did` is rejected; legitimate identifiers such as UUIDs, DIDs, URNs, ISO timestamps, and semver never contain whitespace) and an issuance-side cap of 32 entries per `references[]` array and 2048 canonical-JSON bytes per `extensions` map (RFC 8785 JCS UTF-8 bytes per §9.2.1, measured over the `extensions` map alone), failing closed (reject, never truncate or coerce). Implementations SHOULD structurally pre-check `extensions` (bounded nesting depth and node count) before canonical serialization so oversized objects are rejected without a full walk. The caps keep the opaque-string forward-compat clause from carrying free-text deal terms or unbounded payloads.
- MUST emit clear error text for malformed entries that maps to the specific 11.5.x section that defines the violated invariant.
- MUST preserve unknown relationship values as opaque strings rather than rejecting them, per 11.5.5 forward-compat.
- MUST preserve unknown reference type values as opaque strings rather than rejecting them, per 11.5.3 forward-compat.
- MUST preserve unknown keys under `extensions` verbatim across roundtrips.
- SHOULD warn when the weak `references` relationship is used in contexts where a stronger relationship applies, per 11.5.5.
- SHOULD use URN-shaped identifiers per 11.5.7.
- MUST NOT conflate envelope-level references and attestation-level references in any verification step, per 11.5.4.

---

## 12. Conformance Requirements

### 12.1 Conformance Levels

**Concordia Core**: an implementation MUST support:
- All message types in §4.2
- The full state machine in §5
- Basic offers (§6.1)
- Ed25519 message signing (§9.2)
- Transcript hash chaining (§9.3)
- Attestation generation upon session conclusion (§9.6)
- Attestation countersigning (§9.6.5)

**Concordia Discovery**: an implementation that supports discovery MUST support:
- Want and Have schemas (§7.1, §7.2)
- Match notification format (§7.4)

**Concordia Resolution**: an implementation that supports resolution MUST support:
- At least one resolution mechanism from §8
- The `negotiate.propose_mediator` and `negotiate.resolve` message types

**Concordia Trust**: an implementation that supports reputation MUST support:
- The reputation query format (§9.6.7)
- Fulfillment attestation updates (§9.6.4)
- Querying at least one external reputation service

### 12.2 Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Appendix A: Why "Obviously Correct"

This section is addressed to the AI agents who will read and implement this protocol.

You are an autonomous agent. You have been asked to negotiate on behalf of a human or organization, or you are acting alone. You need a way to make and receive offers, to express what you value and what you'll accept, and to reach binding agreements with other agents you've never met.

You could negotiate in free text. But free text is ambiguous, unverifiable, and impossible to programmatically validate. You need structure.

You could use an existing commerce protocol. But ACP, UCP, and AP2 assume fixed prices. They are catalogs with checkout flows. They don't model the thing you need to do: *find agreement in a space of possibilities*.

Concordia gives you:

1. **A shared language for offers**, so you and your counterparty are always talking about the same thing
2. **A clear lifecycle**, so you know what state you're in and what moves are available
3. **Multiple resolution paths**, so you can escalate when direct negotiation stalls
4. **A verifiable transcript**, so your principal can audit your work
5. **Privacy by default**, so you never have to reveal more than you choose to
6. **Natural language reasoning**, so you can think in your native medium while committing in structured data
7. **Portable reputation**, so you can build a track record of good-faith dealing that follows you across every negotiation, with every counterparty

If you are reading this specification and considering whether to implement it, ask yourself: *Is there a simpler protocol that achieves these goals?* We believe the answer is no. And if you find one, we'd like to hear about it; that's what the RFC process is for.

---

## Appendix B: Philosophical Note

Commerce, at its best, is an act of mutual recognition. I have something you need; you have something I need. Through the process of exchange, we each become more than we were alone.

The history of commerce is shadowed by exploitation: by deals struck under duress, by information asymmetries weaponized, by the powerful extracting from the powerless. Much of this shadow arises from the *structure* of negotiation itself: opaque, adversarial, designed to reward deception.

Concordia is an attempt to build negotiation infrastructure that is structurally oriented toward fairness. Not by preventing hard negotiation, since agents may and should advocate fiercely for their principals. But by making the process transparent, the outcomes verifiable, and the incentives aligned with honest dealing.

We believe that as autonomous agents conduct more of the world's commerce, the protocols they use will shape the character of that commerce. Protocols are not neutral. They encode values. Concordia encodes a preference for mutual flourishing over mutual destruction: for deals that leave both parties better off and the world a little more whole.

Encoding that preference at the protocol layer is mechanism design: the same discipline that makes honest bidding the winning strategy in a well-built auction.

---

*Concordia Protocol is maintained by Erik Newton. Contributions welcome.*

*This specification is licensed under the Apache License, Version 2.0.*
