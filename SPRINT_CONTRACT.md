# SPRINT CONTRACT — HP-16 + HP-17 (Paired)

**Finding IDs:** HP-16, HP-17
**Titles:**
- HP-16: `concordia_relay_transcript` exposes full session transcripts to unauthenticated callers
- HP-17: `concordia_relay_conclude` allows unauthenticated callers to terminate any relay session

**Date:** 2026-03-28
**Branch:** `security-review`
**Baseline test count:** 479

---

## Architecture Decision

### a) Root cause — not the symptom

Both `tool_relay_transcript` and `tool_relay_conclude` in `concordia/mcp_server.py` were implemented without the `auth_token` parameter and the corresponding `_auth.validate_agent_token()` gate that was added to the other 24 identity-dependent tools during the SEC-007 fix (commit `1ca20f3` + `0db7992`). The root cause is identical for both: these two tools were missed during the SEC-007 auth sweep. Every other relay tool (`relay_create`, `relay_join`, `relay_send`, `relay_receive`) already has auth gating — these two are the remaining gaps.

### b) Smallest change that closes the vulnerability

Add an `agent_id` parameter and an `auth_token` parameter (agent-scoped, Annotated type matching the existing pattern) to both tool functions, and gate each on `_auth.validate_agent_token()` before any business logic executes.

For `tool_relay_transcript`: the `agent_id` parameter already exists but is optional and unverified. Make it required and validate the caller's identity via auth token before passing `agent_id` through to the relay's `get_transcript()` which already does participant-checking.

For `tool_relay_conclude`: add a new required `agent_id` parameter as the identity anchor for auth validation. After authentication, the relay layer's `conclude_session()` handles the business logic.

### c) Interactions with other findings

- **SEC-007** (zero caller authentication, closed PASS): HP-16 and HP-17 are residual gaps from the SEC-007 fix. This sprint closes both.
- **SEC-009** (relay message interception, closed as collateral from SEC-007): HP-16 is a related but distinct gap — transcript access vs. individual message interception.
- No other finding interactions.

### d) New risk introduced

Minimal. The change follows the exact same auth pattern used by the other 24 identity-dependent tools. The only behavioral change is that callers who previously called these tools without tokens will now receive authentication errors. This is the intended security improvement.

Existing tests in `test_relay.py` that call `tool_relay_conclude` and `tool_relay_transcript` without auth tokens will need updating to supply valid tokens.

---

## Fix Specification

### Files to modify

1. **`concordia/mcp_server.py`**
   - `tool_relay_conclude` (lines ~1737-1749): add `agent_id` + `auth_token` parameters, add `_auth.validate_agent_token()` gate
   - `tool_relay_transcript` (lines ~1760-1773): make `agent_id` required, add `auth_token` parameter, add `_auth.validate_agent_token()` gate

2. **`tests/test_relay.py`**
   - Update `test_relay_conclude` to supply valid `agent_id` + `auth_token`
   - Update `test_relay_transcript` to supply valid `agent_id` + `auth_token`
   - Update `test_relay_archive` and `test_relay_archive_active_fails` which call `tool_relay_conclude` without auth
   - Update `test_relay_list_archives` and `test_full_relay_lifecycle` if they call the affected tools

3. **`tests/test_authentication.py`**
   - Add `TestRelayTranscriptAuth` and `TestRelayConcludeAuth` regression test classes

### Behavior before

- `tool_relay_conclude(relay_session_id, reason)` — no `agent_id` or `auth_token`. Any caller can conclude any relay session.
- `tool_relay_transcript(relay_session_id, agent_id=None, limit=None)` — `agent_id` is optional and unverified. Any caller reads any session transcript by omitting `agent_id`.

### Behavior after

- `tool_relay_conclude(relay_session_id, agent_id, auth_token, reason)` — requires `agent_id` + `auth_token`. Token validated via `_auth.validate_agent_token()`. Only authenticated participants can conclude sessions.
- `tool_relay_transcript(relay_session_id, agent_id, auth_token, limit=None)` — `agent_id` is required. Token validated via `_auth.validate_agent_token()`. Only authenticated participants can read transcripts.

### Regression tests

**Tests to write in `tests/test_authentication.py`:**

1. `test_relay_transcript_rejects_invalid_auth` — call `tool_relay_transcript` with a valid relay session and agent_id but wrong auth_token. Assert error contains "Authentication required".
2. `test_relay_transcript_accepts_valid_auth` — register agents, create relay, send a message, call `tool_relay_transcript` with a valid participant token. Assert transcript returned with count > 0.
3. `test_relay_conclude_rejects_invalid_auth` — call `tool_relay_conclude` with a valid relay session and agent_id but wrong auth_token. Assert error contains "Authentication required".
4. `test_relay_conclude_accepts_valid_auth` — register agents, create relay, call `tool_relay_conclude` with valid participant token. Assert concluded is True.

### Prompt injection

These tools do not accept free-text that reaches a model prompt. The `reason` parameter in `tool_relay_conclude` is stored in relay session metadata but never reaches any LLM. No prompt injection surface.

---

## Definition of Done

The evaluator will grade PASS if:

1. Both `tool_relay_transcript` and `tool_relay_conclude` require `agent_id` + `auth_token` parameters
2. Both tools validate the token via `_auth.validate_agent_token()` before any business logic
3. Both tools return the standard `_auth_error()` response on validation failure
4. Existing tests in `test_relay.py` pass (updated to supply auth tokens)
5. New regression tests in `test_authentication.py` verify rejection of invalid tokens for both tools
6. Full test suite count ≥ 479 (no regressions, new tests added)
7. Only `concordia/mcp_server.py`, `tests/test_relay.py`, and `tests/test_authentication.py` are modified
