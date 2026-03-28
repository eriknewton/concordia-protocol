# SPRINT RESULT — SEC-010: Session State Machine Never Verifies Signatures

**Sprint Date:** 2026-03-28
**Finding:** SEC-010 (High)
**Branch:** `security-review`

---

## What Changed and Why

### Root cause addressed

The `Session.apply_message()` method in `concordia/session.py` accepted any message dict and appended it to the hash-chained transcript without ever verifying the Ed25519 signature. The `verify_signature()` function existed in `signing.py:95-108` but was dead code — never called from any session lifecycle path. This meant an attacker with MCP transport access could inject messages with forged or absent signatures, and those messages would be accepted as legitimate, advance session state, and become permanent parts of the cryptographic transcript.

### Changes made

**1. `concordia/session.py`** — Core fix

- Added `InvalidSignatureError` exception class alongside `InvalidTransitionError`.
- Added `_party_keys: dict[str, Ed25519PublicKey]` registry to `Session.__init__()` for storing party public keys.
- Updated `add_party()` to accept an optional `public_key` parameter and store it in `_party_keys`.
- Changed `apply_message()` signature to require a mandatory `public_key_resolver: Callable[[str], Ed25519PublicKey | None]` parameter.
- Added signature verification block at the top of `apply_message()`, before any state transition, transcript append, or behavioral tracking:
  1. Extracts `agent_id` from `message["from"]["agent_id"]` — rejects if missing.
  2. Extracts `signature` from `message["signature"]` — rejects if missing or empty.
  3. Calls `public_key_resolver(agent_id)` — rejects if `None` (unknown identity).
  4. Calls `verify_signature()` — rejects if signature invalid.
- All rejections raise `InvalidSignatureError` with a descriptive message identifying the failure mode.

**2. `concordia/agent.py`** — Resolver wiring

- Updated `open_session()` to pass `self.key_pair.public_key` when calling `session.add_party()`.
- Updated `join_session()` to pass `self.key_pair.public_key` when calling `session.add_party()`.
- Updated `_send()` to pass `self._public_key_resolver` when calling `session.apply_message()`.
- Added `_public_key_resolver()` method that resolves agent_ids: returns own public key for self, looks up `session._party_keys` for counterparties, returns `None` for unknown identities.

**3. `concordia/__init__.py`** — Export

- Added `InvalidSignatureError` to imports and `__all__`.

**4. `tests/test_session_signature_verification.py`** — 10 new regression tests

---

## Full Test Suite Output

```
469 passed in 0.47s
```

Baseline: 459. New count: 469 (+10 regression tests). No regressions.

---

## Cluster Contract Conformance

| SEC-005 Requirement | SEC-010 Implementation | Status |
|---|---|---|
| Callback: `(id) => Key \| null` | `Callable[[str], Ed25519PublicKey \| None]` | ✓ |
| Mandatory, not optional | Required parameter, no default | ✓ |
| Null → rejection | Raises `InvalidSignatureError` | ✓ |
| Structured rejection info | Descriptive error messages per failure mode | ✓ |

---

## New Risk Introduced

- All callers of `apply_message()` must provide a resolver. The only production caller (`Agent._send()`) wires one. Tests that call `apply_message()` directly must also provide a resolver. This is intentional — the cluster contract mandates no bypass.
- The `_party_keys` registry requires agents to register their public keys via `add_party()`. If a party is added without a key and sends a message, the resolver returns `None` and the message is rejected. This is the correct fail-closed behavior.

---

## Adjacent Findings Noticed

- **SEC-014** (attestation signature verification optional): The same pattern — mandatory `public_key_resolver`, null → rejection — should be applied to `AttestationStore.ingest()`. The `ingest()` method currently has an optional `public_keys` parameter; it should become mandatory per the cluster contract.
- The `validate_chain()` function in `message.py:88-105` still only verifies hash chaining, not signatures. A future enhancement could add signature verification to chain validation, but this is outside the scope of SEC-010 (which targets `apply_message()`, the live path where messages enter the session).

---

## Sprint Contract Criteria Assessment

| # | Criterion | Met? |
|---|---|---|
| 1 | `apply_message()` has mandatory `public_key_resolver` | ✓ |
| 2 | Invalid signatures raise `InvalidSignatureError`, state unchanged | ✓ |
| 3 | Unknown agent_ids (resolver returns `None`) raise `InvalidSignatureError` | ✓ |
| 4 | Missing signatures raise `InvalidSignatureError` | ✓ |
| 5 | Resolver follows SEC-005 cluster contract | ✓ |
| 6 | All regression tests pass (10/10) | ✓ |
| 7 | Full test suite >= 459 (469 actual) | ✓ |
| 8 | `Agent._send()` correctly wires resolver | ✓ |
| 9 | No coupling of `Session` to key storage | ✓ |

All sprint contract criteria are met.
