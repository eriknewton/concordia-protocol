## Summary

Fixes the M6 relay consent finding from `Review/Concordia/Concordia_Security_Audit_2026-06-09.md` using the approved Option A design in `Review/Concordia/Concordia_M6_Relay_Consent_Design_2026-06-11.md`.

- Makes pre-named relay responders reservations, not active participants.
- Adds `RelayParticipant.confirmed` and serializes it through session/archive dicts.
- Requires the reserved responder's authenticated `concordia_relay_join` before activation.
- Rejects a different agent trying to claim a reserved responder slot.
- Blocks pre-join message exchange with an unconfirmed reserved responder.
- Fails closed for relay `auto_attest` by recording/logging a skip when a session concludes with an unconfirmed responder.

## Breaking Change

`concordia_relay_create(responder_id=...)` now returns a `pending` relay session with `responder.confirmed=false`.

Clients that treated pre-named responder sessions as immediately `active` must call `concordia_relay_join` as the named responder before exchanging relay messages.

## Tests

- Baseline: `1438 passed` with `.venv/bin/python -m pytest` before changes.
- Final: `1445 passed` with `.venv/bin/python -m pytest`.
- JS SDK relay parity: no relay create/join surface exists in the JS SDK; see `M6_HANDOFF.md` for file evidence.
