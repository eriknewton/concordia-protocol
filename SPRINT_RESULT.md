# SPRINT RESULT — SEC-014: Attestation Signature Verification Is Mandatory

**Sprint Date:** 2026-03-28
**Finding:** SEC-014 (High)
**Branch:** `security-review`

---

## What Changed and Why

### Root cause addressed

The `AttestationStore.ingest()` method in `concordia/reputation/store.py` accepted an optional `public_keys` parameter defaulting to `None`. When `None` (the default, and how `tool_ingest_attestation` at mcp_server.py:787 called it), the `_validate()` method emitted a warning ("Signature verification will be skipped") but accepted the attestation anyway. This meant any well-formed attestation with syntactically valid strings in the `signature` fields — regardless of cryptographic validity — was accepted and scored. An attacker could inflate or deflate any agent's reputation by submitting attestations with fake signatures.

### Changes made

**1. `concordia/reputation/store.py`** — Core fix

- Changed `ingest()` signature: replaced `public_keys: dict[str, Any] | None = None` with `public_key_resolver: Callable[[str], Ed25519PublicKey | None]` (mandatory, no default).
- Changed `_validate()` signature: same replacement.
- **Deleted** the "warn and skip" code path (old lines 332-338) that emitted a warning when public keys were not provided.
- **Replaced** with mandatory verification: for every party with a signature, call `public_key_resolver(agent_id)`. If it returns `None`, add to errors and reject. If `verify_signature()` returns `False`, add to errors and reject.
- Added imports for `Callable` from `typing` and `Ed25519PublicKey` from `cryptography`.

**2. `concordia/mcp_server.py`** — Resolver wiring in `tool_ingest_attestation()`

- Builds a `_resolve_attestation_key()` closure that looks up the attestation's `session_id` in the session store (`_store`), extracts the `SessionContext`, and maps party agent_ids to their Ed25519 public keys.
- If the session_id is not found (e.g., attestation from an unknown source), the resolver returns `None` for all agents — the attestation is rejected (fail-closed).
- Passes the resolver to `_attestation_store.ingest(attestation, public_key_resolver=resolver)`.

**3. `tests/test_reputation.py`** — Updated existing tests

- Updated `_make_attestation()` helper to produce properly-signed attestations using real Ed25519 key pairs (via a shared `_KEY_REGISTRY`).
- Added `_test_resolver()` function backed by the key registry.
- Updated all `store.ingest(att)` calls to `store.ingest(att, _test_resolver)`.
- Updated MCP tool integration tests (`TestReputationMcpTools`) to create real sessions via `_create_session_and_receipt()` helper that drives sessions to AGREED and generates properly-signed receipts.

**4. `tests/test_security.py`** — Updated existing tests

- Added `_sec_get_key()`, `_sec_resolver()`, `_sec_null_resolver()`, and `_make_signed_att()` helpers.
- Updated empty-signature, whitespace-signature, and MAX_ATTESTATIONS tests to pass resolvers.

**5. `tests/test_attestation_signature_verification.py`** — 10 new regression tests

---

## Full Test Suite Output

```
479 passed in 0.59s
```

Baseline: 469. New count: 479 (+10 regression tests). No regressions.

---

## Cluster Contract Conformance

| SEC-005 Requirement | SEC-014 Implementation | Status |
|---|---|---|
| Callback: `(id) => Key \| null` | `Callable[[str], Ed25519PublicKey \| None]` | ✓ |
| Mandatory, not optional | Required parameter, no default | ✓ |
| Null → rejection | Adds error and rejects attestation | ✓ |
| Structured rejection info | `ValidationResult.errors` with per-party messages | ✓ |

This closes the signature verification cluster (SEC-005, SEC-010, SEC-014). All three findings now enforce the same mandatory resolver pattern with no fallback.

---

## New Risk Introduced

- All callers of `ingest()` must provide a `public_key_resolver`. The only production caller (`tool_ingest_attestation`) wires one via the session store. Tests must also provide resolvers. This is intentional per the cluster contract.
- Attestations from sessions not in the server's session store (e.g., from external sources or after restart) will be rejected because the resolver returns `None`. This is the correct fail-closed behavior. The in-memory session store is a reference implementation limitation; a production deployment with persistent storage would resolve keys from its backing store.

---

## Adjacent Findings Noticed

- The `generate_attestation()` function in `attestation.py:92-96` sets `party_record["signature"] = ""` when a key pair is not available for a party. This empty signature will now be caught by the schema validation (empty-signature check) and the attestation will be rejected during ingestion. This is correct behavior — attestations without valid signatures should not be storable.
- The Sybil detector flags suspicious patterns but still does not block. SEC-014 addresses the more fundamental issue: unverified attestations are no longer accepted at all.

---

## Sprint Contract Criteria Assessment

| # | Criterion | Met? |
|---|---|---|
| 1 | `ingest()` has mandatory `public_key_resolver` | ✓ |
| 2 | `_validate()` has mandatory `public_key_resolver` | ✓ |
| 3 | Invalid signatures rejected with errors | ✓ |
| 4 | Unknown agent_ids (resolver returns `None`) rejected with errors | ✓ |
| 5 | Old "skip verification" warning path deleted | ✓ |
| 6 | Resolver follows SEC-005 cluster contract | ✓ |
| 7 | `tool_ingest_attestation` wires resolver from session store | ✓ |
| 8 | All 10 regression tests pass | ✓ |
| 9 | Full test suite >= 469 (479 actual) | ✓ |
| 10 | Conforms to SEC-005 cluster contract and SEC-010 pattern | ✓ |

All sprint contract criteria are met.
