# M6 Relay Consent Handoff

## Implemented

- `RelayParticipant.confirmed` added.
- Initiators are created with `confirmed=True`.
- `create_session(responder_id=X)` now creates a `PENDING` session with `responder.confirmed=False` and `responder.connected=False`.
- `join_session()` activates a reserved session only when `agent_id` matches the reserved responder.
- Open pending sessions with no responder still use the existing first-join-fills behavior.
- Relay message routing now refuses sends from or to unconfirmed reserved responders, so pre-join messages are not created as bilateral transcript entries.
- Archives now include serialized `initiator` and `responder` participant dicts, including `confirmed`.
- `RelayParticipant.from_dict()` and `TranscriptArchive.from_dict()` round-trip `confirmed`.
- Relay conclusion/timeout records `metadata["auto_attest_skipped"]` and logs when `auto_attest=True` but the responder is unconfirmed.

## Validation

- Baseline before edits: `1438 passed` via `.venv/bin/python -m pytest`.
- Final after edits: `1445 passed` via `.venv/bin/python -m pytest`.
- Sandbox note: the first sandboxed baseline failed only the three local HTTP revocation tests because binding `127.0.0.1:0` was denied; rerun with approved escalation passed.
- Focused relay suite after final edits: `87 passed` via `.venv/bin/python -m pytest tests/test_relay.py`.

## JS SDK

No JS SDK relay create/join path exists to update.

Evidence:

- `js-sdk/src/index.ts:1` begins exports for canonicalization; `js-sdk/src/index.ts:38` exports predicate APIs. There is no relay export in the SDK index.
- `js-sdk/src/session/index.ts:1` exports only session message/hash-chain primitives and `Session`; no relay API is exported there.
- `js-sdk/src/session/session.ts:1` identifies the file as the direct negotiation session/state machine port of `concordia/session.py`, not the relay service.
- `rg -n "relay|Relay|concordia_relay|create_session|join_session|responder_id" js-sdk/src js-sdk/tests js-sdk/README.md js-sdk/CHANGELOG.md` returned no matches.

`npm test` was attempted from `js-sdk`, but this prepared worktree has no installed JS dev dependencies: `vitest: command not found`. Per the worker prompt, I did not install dependencies or use network.

## Notes

- This intentionally preserves the accepted breaking behavior: pre-named responders now see `pending` until the named responder joins.
- `confirmed` is archive/session state only. It was not added to signed attestation payloads or canonical signing structures.
- Existing relay `auto_attest` remains a relay option rather than a complete attestation emission pipeline in this codebase; this patch adds the fail-closed skip/log guard at conclusion/timeout so an unconfirmed responder cannot flow into that path.
