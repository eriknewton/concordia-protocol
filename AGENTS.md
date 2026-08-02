# AGENTS.md: Concordia Security and Sovereignty Review Context

This file is guidance for any AI coding agent working in this codebase. Read it before making any changes.

This file follows the open `AGENTS.md` standard and is read natively by a wide range of AI coding agents (Codex, Cursor, GitHub Copilot, Aider, Gemini, and others). Claude Code reads it via the `@AGENTS.md` import in `CLAUDE.md`.

### Attribution Rule (MANDATORY)

**No public-facing document, README, blog post, plugin manifest, package metadata, or software artifact may reference or attribute CIMC as author or creator of Concordia.** Erik Newton is the sole author. CIMC may be mentioned in internal/biographical context only.

---

## WHAT THIS TOOL IS

**Concordia** is a Python SDK and MCP server (~14,000 lines of code across `concordia/`, 59 tools exposed via FastMCP) implementing a structured multi-attribute negotiation protocol for autonomous agents. Version 0.10.0 release line.

What it concretely does:

- Defines a six-state session lifecycle: PROPOSED -> ACTIVE -> AGREED / REJECTED / EXPIRED -> DORMANT. State transitions are enforced by a strict transition table.
- Supports four offer types (Basic, Partial, Conditional, Bundle) and fourteen message types covering negotiation, information exchange, and resolution.
- Every message is Ed25519-signed over canonical JSON (sorted keys, deterministic serialization). Messages form a hash chain: each message includes the SHA-256 hash of its predecessor (the `prev_hash` field), creating a tamper-evident transcript.
- Generates reputation attestations from concluded sessions, that is, behavioral records (offers made, concession magnitude, reasoning rate, responsiveness) without exposing deal terms.
- Includes a Want Registry (demand-side discovery with constraint matching), Agent Registry (capability advertising), message relay service, competence proofs, and graceful degradation for non-Concordia peers.
- Negotiation, attestation, want-registry, and agent-registry state in the reference implementation is in-memory (Python dicts) with size caps; there is no persistent database for that state. **One exception:** per-session authentication tokens are persisted to a local JSON file (`~/.concordia/sessions.json`) by default so responder clients can reconnect; the write is atomic, the file is chmod `0600`, tokens carry a 24h TTL, and agent tokens are never persisted. The store path is overridable via the `CONCORDIA_SESSION_STORE` environment variable. Any production deployment of the in-memory stores requires swapping storage backends.

### The Sanctuary bridge (optional)

Concordia ships an optional bridge to **Sanctuary Framework**, a separate project. The bridge lives in `concordia/sanctuary_bridge.py`: it is a payload builder that produces correctly-shaped requests for Sanctuary's commitment and reputation tools. It does NOT directly call Sanctuary; it generates payloads that a client forwards. This keeps Concordia testable without a running Sanctuary server, and it means Concordia never depends on Sanctuary at runtime. When a Concordia negotiation reaches AGREED, the outcome can be canonically serialized and handed to a client, which may forward it to Sanctuary for commitment and attestation. The bridge introduces no new cryptographic primitives.

---

## WHAT THIS TOOL MUST NEVER DO

These are hard constraints. Violation of any of these is a security defect.

1. **Never transmit user data to an external endpoint without explicit, confirmed user intent.** Concordia's reference server makes no external API calls at runtime and emits no telemetry. The relay is an explicit, user-initiated mailbox feature; it is not end-to-end encrypted today, and that limit is documented rather than hidden.

2. **Never persist agent-generated output that the user cannot inspect, export, or delete.** Negotiation, attestation, and registry state is in-memory and ephemeral by design. The one durable artifact is the per-session auth-token file at `~/.concordia/sessions.json` (atomic write, `0600`, 24h TTL); it is a plain JSON file the user can inspect or delete, and its path is overridable via `CONCORDIA_SESSION_STORE`. If a persistent storage backend is added for the in-memory stores, this constraint must carry forward.

3. **Never assume trust across the Concordia-Sanctuary bridge boundary.** Concordia's bridge produces payloads but never directly modifies any external system's state, and Concordia never implicitly elevates another tool's trust level. Trust is established cryptographically (signature verification, commitment recomputation, terms-hash matching), never through a shared secret or implicit channel.

4. **Never silently degrade to a less-secure behavior on error.** If signature verification fails, the message must be rejected, not accepted without verification. If a message's `prev_hash` does not chain to the live transcript tip, the message must be rejected, not appended. Concordia must never describe relay traffic as end-to-end encrypted while payload encryption is unimplemented.

5. **Never expose private keys in any MCP response, log entry, error message, or diagnostic output.** Ed25519 private keys exist only in memory for signing operations and must never appear in any tool response or log. This applies to Concordia agent key pairs.

6. **Never allow Concordia attestations to include raw deal terms.** Attestations record behavioral signals (offers_made, concession_magnitude, reasoning_provided), not the actual prices, quantities, or terms of a negotiation. This is a privacy invariant. The `value_range` field uses an enumerated logarithmic bucket vocabulary, never an exact amount, and issuers must reject any other value rather than coerce it.

---

## ARCHITECTURE IN ONE PAGE

### Entry Point

| Tool | Entry Point | What It Starts |
|------|------------|----------------|
| Concordia | `concordia/__main__.py` | Parses `--transport`, calls `mcp.run()` from `mcp_server.py` (FastMCP) |

### Core Data Flow

```
Tool call from agent harness
  -> FastMCP dispatcher (mcp_server.py)
  -> Auth check (auth.py: agent/session bearer tokens; session tokens persisted to ~/.concordia/sessions.json)
  -> Session state machine (session.py: validate transition, append to hash-chain transcript, enforce prev_hash chain tip)
  -> Signing (signing.py: Ed25519 sign over canonical JSON)
  -> In-memory stores (SessionStore, AttestationStore, WantRegistry, AgentRegistry, NegotiationRelay)
  -> [Optional] Sanctuary bridge payload generation (sanctuary_bridge.py)
```

### Auth and Trust Model

**Identity and signing.** Ed25519 key pairs per agent. Messages are signed over canonical JSON (sorted keys, deterministic serialization). The transcript is a hash chain: every message carries `prev_hash`, the SHA-256 hash of the previous message, and `session.py` enforces it against the live chain tip on apply.

**Authentication.** `auth.py` issues two token scopes: agent tokens (reissued each registration, never persisted) and session tokens (per session and role, persisted to `~/.concordia/sessions.json` with a 24h TTL so a responder can reconnect). The persisted file is written atomically and chmod `0600`.

**Reputation integrity.** Sybil detection on reputation attestations flags self-dealing, suspiciously fast sessions, symmetric concessions, and closed loops. These are heuristics that apply scoring penalties, not hard rejections.

**Bridge boundary.** Concordia does not call any external tool directly; it produces payloads a client forwards. Trust across the bridge is cryptographic, not a shared secret.

### Key Third-Party Dependencies

- `cryptography` (>=42.0): Ed25519 signing and verification
- `jsonschema` (>=4.20): Message and attestation schema validation
- `mcp` (>=1.0): FastMCP server SDK

No blockchain libraries. No external API calls at runtime. No telemetry.

---

## SOVEREIGNTY PROPERTIES THIS SYSTEM IS DESIGNED TO GUARANTEE

These are testable assertions. Each should be verifiable by inspection or automated test.

**Negotiation integrity:**

1. "Every Concordia message is Ed25519-signed and hash-chained via `prev_hash`. Tampering with any message breaks the chain." *(Tested: signing and message hash-chain tests.)*
2. "Session state transitions are enforced by a strict transition table. Invalid transitions raise `InvalidTransitionError`." *(Tested: session state-machine tests.)*
3. "A message whose `prev_hash` does not match the current transcript tip is rejected, not appended."
4. "Reputation attestations contain behavioral signals only, never raw deal terms."
5. "The attestation `value_range` field accepts only enumerated logarithmic buckets; any other value is rejected rather than coerced, so an exact price cannot be encoded as a degenerate range."

**Identity sovereignty:**

6. "Private keys never appear in any MCP tool response."
7. "Agent and session authentication use random 256-bit bearer tokens; session tokens persist only to the local `0600` JSON file and expire after 24h."

**Bridge integrity:**

8. "Bridge payloads use canonical serialization (sorted keys, deterministic JSON) so identical outcomes always produce identical commitment hashes."
9. "Non-finite numbers (NaN, Infinity) in outcome terms are rejected at canonicalization time to prevent commitment ambiguity."

**Intended but not yet provided:**

10. "End-to-end payload encryption (X25519 + XChaCha20-Poly1305 is the candidate construction)." *(Specified as a future extension only; no reference implementation provides it, and relay traffic is not end-to-end encrypted today.)*
11. "A verifiable competence proof that binds aggregate outcomes into the signed material and enforces prover party-membership, and ultimately a zero-knowledge proof of the aggregate." *(The current competence proof uses selective disclosure over a Merkle commitment; its aggregate statistics are always prover-asserted, never independently verified.)*

---

## KNOWN COMPLEXITY AND RISK AREAS

**Slow down and inspect carefully in these areas:**

1. **Canonical serialization.** Concordia's `canonical_json` in `signing.py` must produce byte-identical output across runs and must match any independent reimplementation (for example, a consumer verifying a bridge commitment in another language). Any divergence breaks signature and bridge-commitment verification. Edge cases to watch: Unicode normalization, floating-point representation, key ordering in nested objects, handling of `null`/`None`.

2. **In-memory state model.** The reference implementation stores negotiation, attestation, and registry state in Python dicts with size caps (for example, 10K sessions, 100K attestations). There is no persistence, no crash recovery, and no transaction isolation for that state. Any production deployment must swap these stores, and the swap surface is wide: `SessionStore`, `AttestationStore`, `WantRegistry`, `AgentRegistry`, and `NegotiationRelay` all hold independent in-memory state. Note the deliberate exception: per-session auth tokens in `auth.py` are persisted to `~/.concordia/sessions.json`.

3. **Sybil detection heuristics.** Concordia's `SybilSignals` in `reputation/store.py` flags self-dealing, suspiciously fast sessions, symmetric concessions, and closed-loop trading. These are heuristics, not proofs. A sophisticated attacker can craft sessions that evade all four signals. The scorer applies penalties but does not reject flagged attestations outright; the scoring weights are tunable and their security properties are not formally analyzed.

4. **Competence-proof aggregate trust.** A competence proof carries prover-asserted aggregate statistics plus a Merkle root over attestation IDs. The privacy mechanism is selective disclosure, not a zero-knowledge argument, and the aggregate statistics are always prover-asserted, never independently verified at any reveal level. Consumers must treat the aggregate as a self-signed advertisement, not a confirmed count. Do not let a refactor present these numbers as verified.

5. **Relay trust boundary.** The optional relay is a mailbox, not the source of trust. Relay traffic is not end-to-end encrypted today, and a compromised relay operator can read content and metadata and can deny service, but cannot forge, alter, or replay a signed message without detection. In the bundled single-server deployment the relay, agent keys, and token issuance live in one process, so a compromised operator holds the keys; run keys separately if the operator is in your threat model.

6. **Session-token persistence.** `auth.py` writes session tokens to disk (`~/.concordia/sessions.json`) atomically with `0600` permissions and a 24h TTL. Inspect changes here carefully: the file must never widen its permissions, must never persist agent tokens, and a corrupt or unreadable file must not block server startup (load is best-effort).

---

## REVIEW CONTEXT

A structured security review completed 2026-03-28 with all Critical and High findings resolved; the security-review branch was merged and published. Concordia has continued to ship released versions on PyPI since. The detailed review artifacts are retained in a private coordinator workspace and are not part of this public repository.
