## Summary

- Add per-agent live quotas for Wants, Haves, relay sessions as initiator, and negotiation sessions as initiator.
- Reject caller-supplied TTLs above 7 days on M4-covered session/registry surfaces.
- Add regression coverage for quota hits, expired entries not counting, cross-agent isolation, and TTL max boundaries.

## Audit Finding

Addresses `Review/Concordia/Concordia_Security_Audit_2026-06-09.md` M4 (MED): global caps existed, but one principal could monopolize shared stores until TTL, and relevant caller-set TTLs had no maximum.

## Notes

- Quota errors reuse existing generic cap messages and do not leak per-agent limit values.
- Quota checks count only live entries. Expired Wants/Haves are pruned; timed-out relay sessions are marked before counting; negotiation sessions with elapsed TTL are excluded.
- The Want Registry `Have` default TTL is now 7 days so default Have publication remains valid under the new maximum.

## Tests

- `.venv/bin/python -m pytest tests/test_want_registry.py tests/test_relay.py tests/test_mcp_server.py` -> `235 passed`
- `.venv/bin/python -m pytest` -> `1435 passed`
