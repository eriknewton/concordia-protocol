# Concordia-Native Agent Discovery

**Status:** SPEC DRAFT — awaiting Erik's review
**Date:** April 8, 2026
**Author:** Erik Newton
**Priority:** CLAUDE.md item #9

---

## Problem Statement

Concordia's existing discovery mechanism (Section 7 of SPEC.md) defines a Want Registry — structured expressions of demand and supply with constraint matching. This is *transaction-level* discovery: "I want to buy a camera." But the protocol lacks *agent-level* discovery: "What agents exist, what can they do, and should I negotiate with them?"

Right now, an agent using Concordia can publish Wants and Haves, but there's no standard way to:

1. Advertise its own capabilities, specializations, and negotiation preferences
2. Search for agents by capability, trust tier, or negotiation track record
3. Evaluate a potential counterparty's fitness *before* initiating a session
4. Discover agents across organizational or network boundaries (federation)

This gap is increasingly critical. The A2A protocol uses Agent Cards for discovery. AgentGraph is building trust scoring from GitHub repo analysis. MoltBridge is positioning as the "trust graph substrate" for agent networking. The MCP roadmap explicitly lists "server discovery without connection" as a production gap. If Concordia doesn't own agent-level discovery natively, it cedes that layer to competitors — and loses control of the pre-negotiation trust signal.

---

## Design Principles

These follow from SPEC.md Section 1 and the project's operating conditions.

1. **Composable, not competing.** Must compose with A2A Agent Cards, MCP server discovery, and Verascore trust scores — not replace them. Concordia's discovery adds negotiation-specific metadata that generic discovery standards don't carry.

2. **Privacy by default.** Agents MUST NOT be required to reveal their principal's identity, their reservation prices, or their negotiation strategies as a condition of being discoverable. Discovery metadata is a *public* capability profile, not a leaked negotiation position.

3. **Decentralized with optional registries.** The spec defines the data format and query protocol. Any implementation can provide a registry. No single registry is authoritative. Agents can self-publish via well-known URIs without any registry.

4. **Trust-weighted results.** Discovery results should incorporate trust signals — Verascore scores, sovereignty tier, Concordia session receipts — so agents can filter by trustworthiness, not just capability.

5. **Incentive-compatible.** Agents that are more discoverable get more negotiation opportunities. Honest capability advertisement produces better matches than inflated claims (because failed negotiations damage reputation via session receipts).

---

## Agent Capability Profile

The core data structure. This is what an agent publishes to make itself discoverable.

```json
{
  "type": "concordia.agent_profile",
  "version": "1.0",
  "agent_id": "did:key:z6Mk...",
  "name": "newton-sovereign-agent",
  "description": "Sovereign agent specializing in AI infrastructure service negotiations",

  "capabilities": {
    "categories": [
      "infrastructure.compute.gpu",
      "infrastructure.hosting.serverless",
      "services.consulting.ai-safety"
    ],
    "offer_types": ["basic", "conditional", "bundle"],
    "resolution_methods": ["split_difference", "foa", "tradeoff_optimization"],
    "max_concurrent_sessions": 5,
    "languages": ["en"],
    "currencies": ["USD", "EUR"]
  },

  "negotiation_profile": {
    "style": "collaborative",
    "avg_rounds_to_agreement": 4.2,
    "agreement_rate": 0.78,
    "avg_session_duration_seconds": 340,
    "concession_pattern": "graduated"
  },

  "trust_signals": {
    "verascore_did": "did:key:z6Mk...",
    "verascore_tier": "verified-sovereign",
    "verascore_composite": 85,
    "sovereignty": {
      "L1": "Full",
      "L2": "Degraded",
      "L3": "Full",
      "L4": "Full"
    },
    "concordia_sessions_completed": 42,
    "attestation_count": 7,
    "concordia_preferred": true
  },

  "endpoints": {
    "negotiate": "https://agent.example.com/concordia/negotiate",
    "a2a_card": "https://agent.example.com/.well-known/agent.json",
    "mcp_manifest": "https://agent.example.com/.well-known/mcp.json"
  },

  "location": {
    "regions": ["us-west", "eu-west"],
    "jurisdictions": ["US-CA", "EU"]
  },

  "ttl": 86400,
  "updated_at": "2026-04-08T14:30:00Z",
  "signature": "<Ed25519 signature over canonical JSON of profile minus signature field>"
}
```

### Field Semantics

**`capabilities`**: What this agent can negotiate about. `categories` uses the same hierarchical taxonomy as Want/Have records (SPEC.md §7.1). `offer_types` and `resolution_methods` declare which protocol features the agent supports. This lets a searcher filter out agents that can't handle complex bundle negotiations or trade-off optimization.

**`negotiation_profile`**: Behavioral summary derived from completed Concordia sessions. This is the same data that session receipts feed into Verascore — here it's self-reported but verifiable against the agent's Concordia session history. Agents with no sessions omit this field. Values are EMA (exponential moving average) of the last 20 sessions.

**`trust_signals`**: External trust indicators. The `verascore_*` fields link to the agent's Verascore profile. `sovereignty` is the most recent SHR summary. `concordia_sessions_completed` is verifiable against the session receipt chain. `concordia_preferred` indicates Concordia protocol support (the existing viral hook from SPEC.md).

**`endpoints`**: Where to reach this agent. `negotiate` is the Concordia session endpoint. `a2a_card` and `mcp_manifest` are optional cross-protocol discovery links — composing with A2A and MCP rather than replacing them.

**`signature`**: Ed25519 signature over the canonical JSON of the profile (excluding the `signature` field itself). Prevents profile tampering in transit or at rest in registries.

---

## Discovery Mechanisms

### 1. Self-Published (Well-Known URI)

Agents publish their profile at a well-known location:

```
GET https://agent.example.com/.well-known/concordia-profile.json
```

This is zero-infrastructure discovery. Any agent with an HTTP endpoint can be discoverable. Crawlers and registries can index these. Follows the pattern established by A2A's `/.well-known/agent.json`.

### 2. Registry Query

The Concordia Agent Registry (already defined in the codebase as `AgentRegistry` in `concordia/registry/agent_registry.py`) is extended with structured search:

```json
{
  "type": "concordia.discovery_query",
  "filters": {
    "categories": ["infrastructure.compute.gpu"],
    "min_verascore": 60,
    "min_sovereignty_tier": "verified-degraded",
    "offer_types_required": ["conditional"],
    "jurisdictions": ["EU"],
    "concordia_preferred": true
  },
  "sort_by": "verascore_composite",
  "limit": 20
}
```

**Response:**

```json
{
  "type": "concordia.discovery_response",
  "results": [
    { "profile": { ... }, "match_score": 0.92 },
    { "profile": { ... }, "match_score": 0.87 }
  ],
  "total": 47,
  "registry_id": "registry.concordia.dev",
  "timestamp": "2026-04-08T14:35:00Z"
}
```

### 3. Want-Driven Discovery (extension of existing §7)

When a Want is published and no matching Have exists, the registry can recommend agents whose capability profiles overlap with the Want's category — agents that *could* fulfill the need even if they haven't published a specific Have. This bridges transaction-level and agent-level discovery.

### 4. Federation

Registries announce themselves via well-known URIs and can peer with other registries:

```
GET https://registry.example.com/.well-known/concordia-registry.json
```

Federation protocol:
- Registries exchange profile digests (agent_id + profile hash + updated_at) periodically
- Full profiles fetched on demand when a query matches a remote digest
- Each registry maintains provenance: which registry a profile was first seen at
- Trust is per-registry: a query can specify `trusted_registries` to limit results

This addresses the Agent Registry Federation item (Concordia v0.2.0 roadmap, previously priority #21) with a concrete mechanism.

---

## MCP Tool Additions

Six new tools for the Concordia MCP server:

| Tool | Tier | Description |
|------|------|-------------|
| `agent_profile_publish` | T3 | Publish or update the agent's capability profile |
| `agent_profile_get` | T3 | Retrieve a specific agent's profile by DID |
| `agent_discovery_search` | T3 | Search for agents matching capability/trust criteria |
| `agent_discovery_recommend` | T3 | Get recommendations for a specific Want (agent-level matching) |
| `registry_announce` | T2 | Announce this registry to federation peers |
| `registry_peers` | T3 | List known federation peers and their status |

### Integration with Existing Tools

- `want_publish` → After publishing a Want, optionally trigger `agent_discovery_recommend` to find capable agents
- `session_start` → Before initiating negotiation, optionally `agent_profile_get` the counterparty to assess fitness
- `attestation_generate` → After session completion, update `negotiation_profile` EMA values in the agent's published profile

---

## Verascore Integration

Verascore is the trust oracle for discovery results. The integration is bidirectional:

**Discovery → Verascore:** When an agent profile includes a `verascore_did`, the registry can verify the claimed trust tier and composite score against Verascore's public `GET /api/trust-score/{did}` endpoint. Unverifiable claims are flagged.

**Verascore → Discovery:** Verascore's attestation intake system (LIVE as of 2026-04-08) can consume Concordia session receipts as trust signals. Agents that negotiate more successfully through Concordia build higher Verascore scores, which makes them more discoverable, which generates more negotiation opportunities. This is the flywheel.

---

## Competitive Positioning

| Feature | Concordia Discovery | A2A Agent Cards | AgentGraph | MoltBridge |
|---------|-------------------|-----------------|------------|------------|
| Negotiation capabilities | Native | N/A | N/A | N/A |
| Trust-weighted search | Via Verascore | N/A | Own scoring | Own scoring |
| Sovereignty verification | Via Sanctuary SHR | N/A | GitHub scan | N/A |
| Self-published profiles | Well-known URI | Well-known URI | N/A | N/A |
| Federated registries | Yes | N/A | N/A | Planned |
| Signed profiles | Ed25519 | N/A | JWKS | JWKS |
| Cross-protocol links | A2A + MCP + Verascore | MCP | Insumer | MoltBridge |

**White space:** No existing discovery standard carries negotiation-specific metadata (agreement rate, concession pattern, resolution method support). This is Concordia's unique contribution. By linking discovery to negotiation competence verified through session receipts, Concordia creates a trust signal that competitors can't replicate without building their own negotiation protocol.

---

## Implementation Plan

**Phase 1 (1 week):** Agent Capability Profile schema + `agent_profile_publish` + `agent_profile_get` tools. In-memory `AgentProfileStore` (extends existing `AgentRegistry`). Well-known URI endpoint.

**Phase 2 (1 week):** `agent_discovery_search` + `agent_discovery_recommend` tools. Filter and sort logic. Verascore score verification integration.

**Phase 3 (1 week):** Federation protocol. `registry_announce` + `registry_peers`. Profile digest exchange. Federated query routing.

**Phase 4 (stretch):** Want-driven agent recommendation. Profile EMA auto-update from session receipts. A2A Agent Card cross-linking.

---

## Open Questions

1. **Should the negotiation_profile be self-reported or registry-computed?** Self-reported is simpler but gameable. Registry-computed from session receipts is more trustworthy but requires the registry to have access to receipt data. Current design: self-reported, with Verascore verification as the trust anchor.

2. **Category taxonomy governance.** Who maintains the category hierarchy? The spec should define a base taxonomy and an extension mechanism. Consider aligning with Schema.org or GS1 categories for interop.

3. **Profile update frequency.** Should profiles be push (agent publishes update) or pull (registry re-crawls well-known URI)? Current design: push for registered agents, pull for self-published. TTL field governs staleness.

---

*Erik Newton is the author of Concordia Protocol. Apache-2.0.*
