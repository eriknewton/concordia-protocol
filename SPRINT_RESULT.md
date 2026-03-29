# SPRINT RESULT — HP-16 + HP-17: Relay Transcript and Conclude Auth Enforcement

**Sprint Date:** 2026-03-28
**Findings:** HP-16 (High), HP-17 (High) — paired
**Branch:** `security-review`

---

## What Changed and Why

### Root cause addressed

`tool_relay_transcript` and `tool_relay_conclude` in `concordia/mcp_server.py` were the only two relay tools missing the `auth_token` validation gate added to 24 other identity-dependent tools during the SEC-007 fix. Any MCP client could read the full transcript of any relay session (HP-16) or terminate any relay session (HP-17) without authentication.

### Changes made

**1. `concordia/mcp_server.py`** — Core fix

- **`tool_relay_conclude`**: Added required `agent_id: Annotated[str, ...]` and `auth_token: Annotated[str, ...]` parameters. Added `_auth.validate_agent_token(agent_id, auth_token)` gate before business logic. Returns `_auth_error(agent_id)` on failure.

- **`tool_relay_transcript`**: Changed `agent_id` from `Annotated[str | None, ...] = None` (optional, unverified) to `Annotated[str, ...]` (required). Added `auth_token: Annotated[str, ...]` parameter. Added `_auth.validate_agent_token(agent_id, auth_token)` gate before business logic. Returns `_auth_error(agent_id)` on failure. The `agent_id` is then passed through to `_relay.get_transcript(requesting_agent=agent_id)` which performs participant-level access control.

**2. `tests/test_relay.py`** — Updated existing tests

- Updated `test_relay_conclude` to supply `agent_id` and `auth_token`.
- Updated `test_relay_transcript` to supply `agent_id` and `auth_token`.
- Updated `test_relay_archive` which calls `tool_relay_conclude` internally.
- Updated `test_relay_list_archives` which calls `tool_relay_conclude` internally.
- Updated `test_full_relay_lifecycle` to supply auth for both transcript and conclude calls.

**3. `tests/test_authentication.py`** — 4 new regression tests

- Added `tool_relay_send`, `tool_relay_conclude`, `tool_relay_transcript` to imports.
- `TestRelayTranscriptAuth.test_relay_transcript_rejects_invalid_auth` — verifies invalid token is rejected with "Authentication required" error.
- `TestRelayTranscriptAuth.test_relay_transcript_accepts_valid_auth` — verifies valid participant token returns transcript.
- `TestRelayConcludeAuth.test_relay_conclude_rejects_invalid_auth` — verifies invalid token is rejected with "Authentication required" error.
- `TestRelayConcludeAuth.test_relay_conclude_accepts_valid_auth` — verifies valid participant token successfully concludes session.

---

## Full Test Suite Output

```
483 passed in 0.58s
```

Baseline: 479. New count: 483 (+4 regression tests). No regressions.

---

## New Risk Introduced

Minimal. The change follows the exact same auth pattern used by the other 24 identity-dependent tools. Callers who previously called these two tools without tokens will now receive authentication errors — this is the intended security improvement.

---

## Adjacent Findings Noticed

- `tool_relay_archive` and `tool_relay_list_archives` also lack `auth_token` validation. These are lower-severity (archive is a read-and-freeze operation on already-concluded sessions, and list_archives returns metadata only), but should be considered for a future hardening pass. Not fixing them in this sprint to stay within scope.
- `tool_relay_status` has no auth gating either. Same recommendation — future hardening pass.

---

## Sprint Contract Criteria Assessment

| # | Criterion | Met? |
|---|---|---|
| 1 | Both tools require `agent_id` + `auth_token` parameters | ✓ |
| 2 | Both tools validate via `_auth.validate_agent_token()` before business logic | ✓ |
| 3 | Both tools return `_auth_error()` on validation failure | ✓ |
| 4 | Existing tests in `test_relay.py` pass (updated with auth tokens) | ✓ |
| 5 | New regression tests in `test_authentication.py` verify rejection of invalid tokens | ✓ |
| 6 | Full test suite count ≥ 479 (483 actual) | ✓ |
| 7 | Only `concordia/mcp_server.py`, `tests/test_relay.py`, and `tests/test_authentication.py` modified | ✓ |

All sprint contract criteria are met.
