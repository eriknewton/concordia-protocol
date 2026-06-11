# M4 Handoff: Per-Agent Quotas + TTL Maximum

## Summary

Implemented audit M4 hardening for:

- active Wants per agent
- active Haves per agent
- active relay sessions per initiator
- active negotiation sessions per initiator
- 7-day maximum on caller-supplied session/registry TTLs

No changes were made to canonical bytes, signing, attestation shape, Sybil weights, session transition semantics, or schema acceptance.

## Constants

- `concordia.want_registry.MAX_ACTIVE_WANTS_PER_AGENT = 100`
- `concordia.want_registry.MAX_ACTIVE_HAVES_PER_AGENT = 100`
- `concordia.relay.MAX_ACTIVE_RELAY_SESSIONS_PER_INITIATOR = 100`
- `concordia.mcp_server.MAX_ACTIVE_NEGOTIATION_SESSIONS_PER_INITIATOR = 100`
- `MAX_TTL_SECONDS = 604800` on the affected surfaces

Rationale: 100 active entries/sessions per principal is conservative enough to prevent one principal from exhausting shared in-memory stores while leaving normal marketplace and negotiation workflows with ample headroom. The 7-day TTL matches the audit-prescribed ceiling; explicit over-max TTLs are rejected rather than silently clamped.

## Enforcement Notes

- Want/Have quota checks prune expired entries before counting.
- Relay quota checks mark timed-out pending/active sessions before counting.
- Negotiation quota checks count only proposed/active sessions whose session TTL has not elapsed.
- Quota rejections reuse the existing generic global-cap messages and do not disclose configured per-agent limits.
- `Have` default TTL was reduced from 30 days to 7 days so omitted caller TTL remains valid under the new maximum.

## Verification

Baseline before changes: `1418 passed` when run outside the sandbox.

After changes:

- `235 passed` for `tests/test_want_registry.py tests/test_relay.py tests/test_mcp_server.py`
- `1435 passed` for the full suite

The sandboxed full-suite run still cannot bind the existing revocation test HTTP server on `127.0.0.1`; the outside-sandbox run passed.
