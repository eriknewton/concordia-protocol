# SPRINT_RESULT.md — SEC-007: Add Caller Authentication to Concordia MCP Endpoint

**Date:** 2026-03-28
**Finding:** SEC-007 (Critical)
**Branch:** `security-review`

---

## WHAT CHANGED AND WHY

### Problem
Concordia had zero caller authentication. Any MCP client could connect and impersonate any agent identity by passing an arbitrary `agent_id` or `role` string. This enabled session hijacking, message interception via relay, unauthorized agent deregistration, fabricated reputation attestations, and want/have registry manipulation.

### Solution
Added bearer-token authentication at two scopes:

1. **Agent-scoped tokens** — issued by `concordia_register_agent`, required for registry, relay, want/have, attestation, and degradation operations.
2. **Session-scoped tokens** — issued by `concordia_open_session` (one per role), required for all negotiation tool calls.

Tokens are 256-bit cryptographically random hex strings. Validation uses constant-time comparison (`hmac.compare_digest`) to prevent timing side-channels.

### Authentication Mechanism

| Scope | Issued by | Required for | Validated by |
|---|---|---|---|
| Agent-scoped | `concordia_register_agent` | deregister, relay ops, want/have post/withdraw, attestation ingest, degradation tools | `_auth.validate_agent_token(agent_id, token)` |
| Session-scoped (initiator) | `concordia_open_session` | propose, counter, accept, reject, commit, status, receipt (as initiator) | `_auth.validate_session_token(session_id, role, token)` |
| Session-scoped (responder) | `concordia_open_session` | same tools (as responder) | same |

Public read-only tools (search, get, stats, reputation query/score) require no token.

---

## FILES CHANGED

### New files
- **`concordia/auth.py`** (113 lines) — `AuthTokenStore` class with token generation, registration, validation, and revocation. Uses only stdlib (`secrets`, `hmac`).
- **`tests/test_authentication.py`** (247 lines) — 17 regression tests covering all 10 test scenarios from the sprint contract.

### Modified files
- **`concordia/mcp_server.py`** — Added `AuthTokenStore` import and global `_auth` instance. Added `auth_token` parameter and validation to 24 identity-dependent tools. Added token issuance to `concordia_register_agent` and `concordia_open_session`. Added `_auth_error()` helper. Added ownership verification to `withdraw_want` and `withdraw_have`.
- **`tests/test_mcp_server.py`** — Updated all 63 tests to pass auth tokens. Updated fixtures to clear auth state.
- **`tests/test_relay.py`** — Updated all relay MCP tool tests to register agents and pass tokens.
- **`tests/test_reputation.py`** — Updated all reputation MCP tool tests to register agents and pass tokens.
- **`tests/test_want_registry.py`** — Updated all want/have MCP tool tests to register agents and pass tokens.
- **`tests/test_discovery.py`** — Updated deregistration and degradation tests to register agents and pass tokens.
- **`tests/test_sanctuary_bridge.py`** — Updated bridge lifecycle tests to pass session tokens.

---

## FULL TEST SUITE OUTPUT

```
458 passed in 0.41s
```

- **441 original tests:** all pass (no decrease)
- **17 new regression tests:** all pass

Breakdown of new tests:
- `TestNoToken` (3): propose, accept, session_status reject empty token
- `TestWrongToken` (2): propose, reject reject wrong token
- `TestCorrectToken` (2): propose with initiator token, counter with responder token
- `TestRoleIsolation` (2): initiator token cannot act as responder, and vice versa
- `TestDeregisterAuth` (2): wrong agent's token rejected, correct token accepted
- `TestRelayAuth` (1): relay_receive rejects wrong agent's token
- `TestTokenIssuance` (2): open_session and register_agent return 256-bit hex tokens
- `TestPublicTools` (2): search_agents and reputation_score work without tokens
- `TestWantAuth` (1): withdraw_want rejects wrong agent's token

---

## NEW RISK INTRODUCED

1. **Token storage is in-memory.** If the Concordia server restarts, all tokens are lost. Active sessions become inaccessible. This matches Concordia's existing design (all state is in-memory), but it means tokens do not survive process restart. Mitigation: this is consistent with the existing architecture and is documented.

2. **Token in tool parameters.** Auth tokens are passed as MCP tool parameters, which means they appear in the MCP transport stream. If the transport is not encrypted (e.g., stdio over a local pipe), this is low risk. If SSE transport is used over HTTP (not HTTPS), tokens could be intercepted. Mitigation: this is a transport-layer concern, not an application-layer one. The same risk exists for all MCP tool parameters.

3. **No token rotation.** Tokens are fixed for the lifetime of a session or agent registration. There is no mechanism to rotate a token without re-registering. Mitigation: acceptable for v0.1.0; token rotation can be added as a follow-up.

4. **`withdraw_want`/`withdraw_have` API change.** These tools now require `agent_id` and `auth_token` parameters that they didn't have before. This is a broader API change than other tools (which already had identity params). The ownership check is new behavior.

---

## ADJACENT FINDINGS NOTICED (NOT FIXED)

1. **SEC-008 (deregistration ownership):** Now fully addressed by this sprint — deregistration requires the correct agent token. This was a downstream finding of SEC-007.

2. **SEC-009 (relay message interception):** Now fully addressed — relay_receive requires the correct agent token.

3. **SEC-015 (want/have registry manipulation):** Now fully addressed — post and withdraw operations require agent tokens, and withdraw additionally verifies ownership.

4. **`concordia_relay_conclude`, `concordia_relay_archive`:** These tools do NOT require auth tokens currently. They take `relay_session_id` but no agent identity. If these tools should be restricted, they need a separate fix to determine who should be authorized to conclude/archive a relay session.

5. **`concordia_efficiency_report`:** Takes an `interaction_id` but no agent identity. Currently public. May need auth if interaction data is considered sensitive.

6. **Session token scope does not cover `concordia_session_list`:** The `handle_tool_call` dispatch for listing all sessions is unrestricted. This returns summary data (session_id, state, agent IDs) for all sessions. May want to restrict in a multi-tenant deployment.

---

## SPRINT CONTRACT CRITERIA ASSESSMENT

| Criterion | Status | Evidence |
|---|---|---|
| All 441 existing tests pass | **PASS** | 441 original + 17 new = 458 total, all passing |
| All 10+ regression tests pass | **PASS** | 17 regression tests, all passing |
| Unauthenticated calls return error | **PASS** | TestNoToken: 3 tests verify empty token is rejected |
| Wrong-token calls return error | **PASS** | TestWrongToken + TestRoleIsolation + TestDeregisterAuth + TestRelayAuth + TestWantAuth: 8 tests |
| Correct-token calls succeed | **PASS** | TestCorrectToken + TestDeregisterAuth: 3 tests; all 441 existing tests also verify this |
| Public tools work without tokens | **PASS** | TestPublicTools: 2 tests |
| No new dependencies | **PASS** | Only stdlib `secrets` and `hmac` used |
| Tokens are 256-bit (64 hex chars) | **PASS** | TestTokenIssuance verifies `len(token) == 64` |
| Tokens not in error messages | **PASS** | `_auth_error()` only includes identity string, never token value |
| No cryptographic code modified | **PASS** | `signing.py`, `session.py` hash chain untouched |

**Overall assessment: All sprint contract criteria are met. PASS.**
