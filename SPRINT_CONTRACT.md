# SPRINT_CONTRACT.md — SEC-007: Add Caller Authentication to Concordia MCP Endpoint

**Date:** 2026-03-28
**Finding:** SEC-007 (Critical) — Concordia has zero caller authentication
**Branch:** `security-review`
**Scope:** Concordia codebase only. No Sanctuary changes.

---

## ARCHITECTURE DECISION

### a) Threat Model

**Who are the callers?** MCP clients connecting to the Concordia server over stdio or SSE transport. Each client claims an identity by passing `agent_id`, `role`, `initiator_id`, `responder_id`, or `from_agent` as a plain string parameter.

**What are they claiming?** That they are authorized to act as a specific agent in a negotiation session, registry operation, relay exchange, or reputation query.

**What is the harm if a caller lies?**

1. **Session hijacking.** A caller claims `role: "initiator"` in a session they don't own. They can send offers, accept deals, or reject sessions on behalf of the real initiator.
2. **Message interception.** A caller claims another agent's `agent_id` in `concordia_relay_receive`. All queued messages for the real agent are dequeued and delivered to the attacker. The real agent sees nothing.
3. **Agent deregistration.** A caller deregisters another agent from the discovery registry, removing their market presence.
4. **Fabricated reputation.** A single caller creates a session between two fabricated IDs, drives both sides to agreement, generates an attestation, and ingests it — manufacturing legitimate-looking reputation from nothing.
5. **Want/Have registry manipulation.** A caller withdraws another agent's Wants or Haves.

**Current state:** Zero authentication. Every identity claim is trusted at face value. The only defense is the Sybil detector, which flags but does not block.

### b) Available Authentication Mechanisms

| Mechanism | Feasibility | Notes |
|---|---|---|
| **Bearer tokens (session-scoped + agent-scoped)** | High | Server generates 256-bit random tokens at registration/session-creation time. Tokens returned to the caller. Subsequent calls must include the token. Simple, stateless validation. No changes to MCP protocol needed — token is just another tool parameter. |
| **Cryptographic signatures per call** | Low for this sprint | Would require the MCP client (agent harness) to hold a signing key and sign each tool call. Concordia already generates keypairs server-side, so the client doesn't have the private key. Redesigning key custody is out of scope. |
| **KERI-based identity** | Out of scope | No KERI infrastructure exists in either codebase. |
| **Allowlist by transport** | Insufficient | Stdio is single-client by nature, but SSE can serve multiple clients. An allowlist doesn't solve impersonation within a single client that fabricates multiple agent IDs. |
| **Session tokens + HMAC** | Over-engineered | HMAC adds complexity without meaningful benefit over random bearer tokens for this threat model. |

**Chosen mechanism:** Bearer tokens (256-bit random, hex-encoded), issued at two scopes:

1. **Agent-scoped token** — issued by `concordia_register_agent`. Required for all subsequent calls that reference that `agent_id` in non-session contexts (deregister, relay, want/have, reputation ingest).
2. **Session-scoped tokens** — issued by `concordia_open_session`. One token per role (initiator token, responder token). Required for all session-bound tool calls (`propose`, `counter`, `accept`, `reject`, `commit`, `session_status`, `session_receipt`).

This is transport-level authentication, not cryptographic identity verification. It prevents trivial impersonation from a second MCP client but does not prove the caller possesses a specific private key.

### c) Minimum Viable Fix

1. Add an `AuthTokenStore` class that maps tokens to (scope, identity) pairs.
2. On `concordia_register_agent`: generate and return an agent token. Store the mapping.
3. On `concordia_open_session`: generate and return one token per role. Store the mappings.
4. Add an `auth_token` parameter to every tool that requires identity verification.
5. Before executing any identity-dependent tool handler, validate the token against the claimed identity. If missing or invalid, return an error immediately.
6. Read-only tools that don't claim an identity (`search_agents`, `agent_card`, `search_wants`, `search_haves`, `find_matches`, `want_registry_stats`, `reputation_query`, `reputation_score`, `relay_stats`, `relay_list_archives`, `efficiency_report`) do NOT require tokens. They are public queries.
7. Deny-by-default: if a tool requires a token and none is provided, the call fails.

### d) Backwards Compatibility

The `auth_token` parameter is added as a required parameter to identity-dependent tools. This is a **breaking change by design** — the entire point of SEC-007 is that unauthenticated access must be denied. There is no backwards-compatible way to close this vulnerability.

Existing tests will be updated to pass tokens. A helper function `_get_auth_token_from_response()` will be added to the test utilities.

---

## FILES TO MODIFY

### New file: `concordia/auth.py`
- `AuthTokenStore` class: token generation, storage, validation
- `generate_token() -> str`: 256-bit random, hex-encoded
- `register_agent_token(agent_id: str) -> str`: creates and stores an agent-scoped token
- `register_session_tokens(session_id: str, initiator_id: str, responder_id: str) -> tuple[str, str]`: creates initiator and responder tokens
- `validate_agent_token(agent_id: str, token: str) -> bool`
- `validate_session_token(session_id: str, role: str, token: str) -> bool`
- `get_agent_id_for_token(token: str) -> str | None`: reverse lookup

### Modified file: `concordia/mcp_server.py`
- Import `AuthTokenStore` and instantiate global `_auth`
- `tool_register_agent` (~line 856): generate and return agent token
- `tool_open_session` (~line 286): generate and return session tokens (initiator_token, responder_token)
- All identity-dependent tools: add `auth_token` parameter, validate before execution
- Specifically, these tools gain `auth_token`:
  - Session tools: `concordia_propose` (356), `concordia_counter` (398), `concordia_accept` (448), `concordia_reject` (494), `concordia_commit` (538), `concordia_session_status` (583), `concordia_session_receipt` (647)
  - Registry: `concordia_deregister_agent` (994)
  - Relay: `concordia_relay_create` (1461), `concordia_relay_join` (1503), `concordia_relay_send` (1527), `concordia_relay_receive` (1572)
  - Want/Have: `concordia_post_want` (1134), `concordia_post_have` (1195), `concordia_withdraw_want` (1289), `concordia_withdraw_have` (1307)
  - Attestation: `concordia_ingest_attestation` (726)
  - Degradation: `concordia_propose_protocol` (1018), `concordia_respond_to_proposal` (1049), `concordia_start_degraded` (1091), `concordia_degraded_message` (1325)

### New file: `tests/test_authentication.py`
- Regression tests per RT-05 specification

### Modified file: `tests/test_mcp_server.py` (and other test files as needed)
- Update all calls to identity-dependent tools to include valid auth tokens

---

## BEHAVIOR: BEFORE

Any MCP client can:
- Open sessions between any two agent IDs
- Send offers, accept, reject on behalf of any role in any session
- Deregister any agent from the registry
- Read any agent's relay messages
- Post wants/haves as any agent
- Ingest attestations without restriction

No token, signature, or credential is required for any operation.

## BEHAVIOR: AFTER

**Authenticated operations** (require valid `auth_token`):
- Session operations require the session-scoped token for the claimed role
- Registry deregistration requires the agent token from registration
- Relay create/join/send/receive require agent tokens
- Want/Have post/withdraw require agent tokens
- Attestation ingestion requires an agent token
- Degradation tools require agent tokens

**Public operations** (no token required):
- `concordia_search_agents`, `concordia_agent_card`, `concordia_preferred_badge`
- `concordia_search_wants`, `concordia_search_haves`, `concordia_find_matches`, `concordia_want_registry_stats`
- `concordia_get_want`, `concordia_get_have`
- `concordia_reputation_query`, `concordia_reputation_score`
- `concordia_relay_status`, `concordia_relay_transcript`, `concordia_relay_archive`, `concordia_relay_list_archives`, `concordia_relay_stats`
- `concordia_efficiency_report`
- `concordia_open_session` (returns tokens — this is the entry point)
- `concordia_register_agent` (returns token — this is the entry point)

**Denied operations** (missing or wrong token):
- Return `{"error": "Authentication required: invalid or missing auth_token for <identity>"}`.
- No tool handler logic executes. The denial happens before any state mutation.

---

## REGRESSION TEST (tests/test_authentication.py)

Assertions:

1. `test_session_tool_rejects_no_token` — Call `concordia_propose` with valid session_id but no auth_token. Expect error response.
2. `test_session_tool_rejects_wrong_token` — Call `concordia_propose` with wrong token. Expect error response.
3. `test_session_tool_accepts_correct_token` — Call `concordia_propose` with correct initiator token. Expect success.
4. `test_session_token_role_isolation` — Initiator token cannot act as responder and vice versa.
5. `test_deregister_rejects_wrong_agent_token` — Register agent A and agent B. Try to deregister A with B's token. Expect error.
6. `test_relay_receive_rejects_wrong_agent` — Agent A's token cannot receive agent B's messages.
7. `test_open_session_returns_tokens` — `concordia_open_session` response includes `initiator_token` and `responder_token`.
8. `test_register_agent_returns_token` — `concordia_register_agent` response includes `auth_token`.
9. `test_public_tools_require_no_token` — `concordia_search_agents`, `concordia_reputation_score` work without tokens.
10. `test_want_withdraw_rejects_wrong_agent` — Agent A's token cannot withdraw agent B's wants.

---

## DEFINITION OF DONE

The evaluator will grade PASS if and only if ALL of these criteria are met:

1. **All 441 existing tests pass** (no decrease in test count, no failures).
2. **All 10 regression tests pass.**
3. **Unauthenticated calls to identity-dependent tools return error responses** without executing handler logic.
4. **Wrong-token calls to identity-dependent tools return error responses** without executing handler logic.
5. **Correct-token calls succeed** as before.
6. **Public/read-only tools continue to work without tokens.**
7. **No new dependencies added** — only stdlib `secrets` module for token generation.
8. **Token values are 256-bit (64 hex chars).**
9. **Tokens are not logged or included in error messages** (only the fact of failure is reported).
10. **The fix does not modify any cryptographic code** (signing.py, session.py hash chain, etc.).

---

## PROMPT INJECTION CONSIDERATION

This fix adds an `auth_token` parameter to tool calls. The token value is a random hex string, not user-controlled content. The validation is a constant-time string comparison, not a parse or eval. The error message on failure is a static template with the claimed identity interpolated — the identity string is user-controlled but is only used in a JSON string value, not in any executable context. No new prompt injection surface is introduced.

The existing prompt injection surface (SEC-ADD-01, SEC-ADD-02) is not addressed by this sprint and remains open.
