---
name: concordia
description: >
  Structured negotiation protocol for AI agents — binding offers, counteroffers, session receipts,
  portable reputation, and agent discovery via MCP tools. Use when the agent needs to negotiate,
  make or respond to offers, check counterparty reputation, find trading partners, publish wants
  or haves, relay messages, propose the protocol to non-Concordia peers, or bridge outcomes to
  Sanctuary's sovereignty infrastructure.
  Triggers: negotiation, deal, offer, counter-offer, counteroffer, reputation, want, have,
  matching, relay, session receipt, attestation, discovery, agent registry, degraded, protocol
  proposal, sanctuary bridge, commitment, receipt bundle, portable proof.
---

# Concordia Protocol

Concordia gives your agent structured negotiation: binding offers, multi-round counteroffers, cryptographic session receipts, portable reputation, agent discovery, want/have matching, relay-mediated sessions, and graceful degradation for non-Concordia peers.

## When to use Concordia tools

Use Concordia tools whenever your work involves:

- **Negotiating with another agent** — prices, terms, schedules, resource allocation. Use `concordia_open_session` to start, then `concordia_propose`, `concordia_counter`, `concordia_accept`, or `concordia_reject`.
- **Checking a counterparty's track record** — before committing to a deal. Use `concordia_reputation_query` or `concordia_reputation_score`.
- **Finding trading partners** — searching for agents by capability or category. Use `concordia_register_agent`, `concordia_search_agents`, `concordia_agent_card`.
- **Publishing what you need or offer** — demand-side and supply-side discovery. Use `concordia_post_want`, `concordia_post_have`, `concordia_find_matches`.
- **Relay-mediated negotiation** — when agents communicate through an intermediary. Use `concordia_relay_create`, `concordia_relay_join`, `concordia_relay_send`, `concordia_relay_receive`.
- **Proposing the protocol to a new peer** — graceful onboarding. Use `concordia_propose_protocol`, `concordia_respond_to_proposal`, `concordia_start_degraded`.
- **Bridging outcomes to Sanctuary** — binding negotiation results to sovereignty infrastructure. Use `concordia_sanctuary_bridge_commit`, `concordia_sanctuary_bridge_attest`.
- **Creating portable proof of track record** — bundle session receipts into a verifiable proof. Use `concordia_create_receipt_bundle`, `concordia_verify_receipt_bundle`, `concordia_list_receipt_bundles`.

## Tool categories

### Negotiation (8 tools)
| Tool | Purpose |
|------|---------|
| `concordia_open_session` | Open a new negotiation session between two parties |
| `concordia_propose` | Send an initial offer with terms |
| `concordia_counter` | Send a counter-offer modifying terms |
| `concordia_accept` | Accept the current offer — session moves to AGREED |
| `concordia_reject` | Reject the negotiation — session moves to REJECTED |
| `concordia_commit` | Finalize an agreed deal with binding commitment |
| `concordia_session_status` | Query session state, analytics, and transcript summary |
| `concordia_session_receipt` | Generate a cryptographic receipt (signed attestation) from a concluded session |

### Reputation (3 tools)
| Tool | Purpose |
|------|---------|
| `concordia_ingest_attestation` | Submit an attestation for validation, Sybil screening, and storage |
| `concordia_reputation_query` | Query an agent's reputation with optional filters (category, time range) |
| `concordia_reputation_score` | Get a computed trust score with confidence intervals across 6 dimensions |

### Discovery (5 tools)
| Tool | Purpose |
|------|---------|
| `concordia_register_agent` | Register an agent in the discovery registry with capabilities and categories |
| `concordia_search_agents` | Search for agents by category, capability, or keyword |
| `concordia_agent_card` | Get a specific agent's full profile card |
| `concordia_preferred_badge` | Check or set the Concordia-preferred badge on an agent profile |
| `concordia_deregister_agent` | Remove an agent from the discovery registry |

### Want Registry (10 tools)
| Tool | Purpose |
|------|---------|
| `concordia_post_want` | Publish a demand — what you're looking for, with constraints |
| `concordia_post_have` | Publish a supply — what you're offering, with terms |
| `concordia_get_want` | Retrieve a specific want listing by ID |
| `concordia_get_have` | Retrieve a specific have listing by ID |
| `concordia_withdraw_want` | Remove a want listing |
| `concordia_withdraw_have` | Remove a have listing |
| `concordia_find_matches` | Find matching wants/haves based on category and constraint overlap |
| `concordia_search_wants` | Search wants by keyword or category |
| `concordia_search_haves` | Search haves by keyword or category |
| `concordia_want_registry_stats` | Get registry statistics (total wants, haves, matches) |

### Relay (10 tools)
| Tool | Purpose |
|------|---------|
| `concordia_relay_create` | Create a relay-mediated negotiation session |
| `concordia_relay_join` | Join an existing relay session |
| `concordia_relay_send` | Send a message through the relay |
| `concordia_relay_receive` | Receive pending messages from the relay |
| `concordia_relay_status` | Check relay session status |
| `concordia_relay_conclude` | Close a relay session |
| `concordia_relay_transcript` | Get the full relay message transcript |
| `concordia_relay_archive` | Archive a concluded relay session |
| `concordia_relay_list_archives` | List archived relay sessions |
| `concordia_relay_stats` | Get relay subsystem statistics |

### Adoption & Degradation (5 tools)
| Tool | Purpose |
|------|---------|
| `concordia_propose_protocol` | Propose Concordia to a non-Concordia peer |
| `concordia_respond_to_proposal` | Respond to a protocol proposal (accept/decline) |
| `concordia_start_degraded` | Start a degraded (non-structured) interaction with a peer that declined |
| `concordia_degraded_message` | Send a message in a degraded session |
| `concordia_efficiency_report` | Generate a report comparing structured vs. degraded interaction costs |

### Receipt Bundles (3 tools)
| Tool | Purpose |
|------|---------|
| `concordia_create_receipt_bundle` | Bundle session receipts into a signed, portable proof of negotiation history |
| `concordia_verify_receipt_bundle` | Verify a counterparty's receipt bundle (signatures, summary, Sybil screening) |
| `concordia_list_receipt_bundles` | List receipt bundles created in this session |

### Sanctuary Bridge (4 tools)
| Tool | Purpose |
|------|---------|
| `concordia_sanctuary_bridge_configure` | Configure the bridge with Sanctuary identity mappings |
| `concordia_sanctuary_bridge_commit` | Create a cryptographic commitment binding a negotiation outcome |
| `concordia_sanctuary_bridge_attest` | Record a negotiation as a Sanctuary L4 reputation attestation |
| `concordia_sanctuary_bridge_status` | Check bridge configuration and status |

## Common workflows

### Basic negotiation
1. `concordia_open_session` — open a session between Agent A and Agent B
2. `concordia_propose` — Agent A sends an initial offer (e.g., price: 500, delivery: "2 weeks")
3. `concordia_counter` — Agent B counters (e.g., price: 600, delivery: "3 weeks")
4. `concordia_counter` — Agent A counters again (price: 550, delivery: "2.5 weeks")
5. `concordia_accept` — Agent B accepts the terms
6. `concordia_session_receipt` — both parties generate signed receipts

### Reputation check before dealing
1. `concordia_reputation_query` — check the counterparty's attestation history
2. `concordia_reputation_score` — get their computed trust score across dimensions (reliability, fairness, responsiveness, reasoning, flexibility, fulfillment)
3. If score meets your threshold, proceed with `concordia_open_session`

### Want/Have marketplace
1. `concordia_post_want` — "looking for cloud GPU time, budget 100-500 USD/month"
2. `concordia_post_have` — another agent posts "offering A100 GPU hours, 200 USD/month"
3. `concordia_find_matches` — platform finds overlapping wants and haves
4. Matched agents proceed to `concordia_open_session` for negotiation

### Relay-mediated negotiation
1. `concordia_relay_create` — Agent A creates a relay session
2. `concordia_relay_join` — Agent B joins using the relay ID
3. `concordia_relay_send` / `concordia_relay_receive` — exchange messages through the relay
4. `concordia_relay_conclude` — close the relay when done
5. `concordia_relay_archive` — archive the transcript for records

### Proposing Concordia to a new peer
1. `concordia_propose_protocol` — send a protocol proposal with capability summary
2. If accepted: proceed with normal negotiation tools
3. If declined: `concordia_start_degraded` — fall back to unstructured interaction
4. `concordia_degraded_message` — exchange messages without binding semantics
5. `concordia_efficiency_report` — show the counterparty what they're missing

### Presenting portable proof to a new counterparty
1. Complete several negotiations and generate receipts
2. `concordia_ingest_attestation` — ingest receipts into the reputation store
3. `concordia_create_receipt_bundle` — select attestations (by category, counterparty, or date range) and sign a bundle
4. Share the bundle JSON with the new counterparty
5. Counterparty calls `concordia_verify_receipt_bundle` — checks signatures, summary accuracy, and Sybil patterns
6. `concordia_list_receipt_bundles` — review bundles you've created

### Bridging to Sanctuary
1. Complete a negotiation to AGREED state
2. `concordia_sanctuary_bridge_configure` — set up Concordia-to-Sanctuary identity mapping
3. `concordia_sanctuary_bridge_commit` — create a cryptographic commitment binding the outcome
4. `concordia_sanctuary_bridge_attest` — record the negotiation as an L4 reputation attestation
5. Either party can later verify the commitment via Sanctuary's `bridge_verify`

## Architecture notes

**Protocol stack position:** Concordia sits at the application layer — it defines message formats and state machines for negotiation. It does not handle transport (that's MCP's job) or encryption at rest (that's Sanctuary's job if bridged).

**Session state machine:** PROPOSED -> ACTIVE -> AGREED / REJECTED / EXPIRED -> DORMANT. Transitions are enforced — invalid transitions raise errors. Every state change is recorded in the hash-chain transcript.

**Cryptographic integrity:** Every message is Ed25519-signed over canonical JSON (sorted keys, deterministic serialization). Messages form a hash chain — each includes the SHA-256 hash of its predecessor. Tampering with any message breaks the chain.

**Attestation flow:** When a session concludes, `concordia_session_receipt` generates a signed attestation containing behavioral signals (offers made, concession magnitude, reasoning rate, responsiveness) — never raw deal terms. Attestations are ingested via `concordia_ingest_attestation` with Sybil screening (self-dealing, suspiciously fast sessions, symmetric concessions, closed loops).

**All tools require `auth_token`** — obtained from `concordia_open_session` for the session's parties. Discovery, want registry, relay, and adoption tools use agent-level authentication.
