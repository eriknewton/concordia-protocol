# SPRINT CONTRACT — SEC-010: Session State Machine Never Verifies Signatures

**Sprint Date:** 2026-03-28
**Finding:** SEC-010 (High)
**Branch:** `security-review`
**Cluster:** Second of three (SEC-005, SEC-010, SEC-014) — this sprint conforms to the resolver pattern established by SEC-005.

---

## Cluster Contract Conformance

SEC-005 (Import skips signature verification, Sanctuary TypeScript) established the verification pattern for the entire signature verification cluster. This sprint implements the identical pattern in the Concordia Python codebase. Conformance point-by-point:

| SEC-005 Cluster Contract Requirement | SEC-010 Implementation |
|---|---|
| Callback signature: `(identifier: string) => PublicKey \| null` | `public_key_resolver: Callable[[str], Ed25519PublicKey \| None]` — same semantic shape in Python |
| Verification is **mandatory, not optional** | `public_key_resolver` is a required parameter on `apply_message()` — no default value, no `Optional` type |
| Null return from resolver → **rejection, not warning** | If resolver returns `None`, raise `InvalidSignatureError` — hard rejection, message not appended to transcript |
| Response includes structured rejection counts | `InvalidSignatureError` raised with descriptive message identifying the failure mode (unknown identity vs. invalid signature) |

The SEC-005 evaluator explicitly noted: "A future implementer working on SEC-010 or SEC-014 can follow this pattern without reading the SEC-005 implementation." This contract follows that pattern exactly.

---

## Architecture Decision

### a) Root cause — not the symptom

The `apply_message()` method in `session.py:115-155` validates state transitions and tracks behavioral signals, but never calls `verify_signature()` from `signing.py`. The root cause is identical to SEC-005: the session module has no concept of identity resolution. It receives messages with a `from.agent_id` field and a `signature` field but has no mechanism to resolve the agent_id to a public key for verification. The `verify_signature()` function exists and is correctly implemented (`signing.py:95-108`) but is dead code — never called from any session lifecycle path.

### b) Smallest change that closes the vulnerability

Add a mandatory `public_key_resolver` callback parameter to `Session.apply_message()`:

```python
def apply_message(
    self,
    message: dict[str, Any],
    public_key_resolver: Callable[[str], Ed25519PublicKey | None],
) -> SessionState:
```

Before any state transition or transcript append:
1. Extract `agent_id` from `message["from"]["agent_id"]`
2. Extract `signature` from `message["signature"]`
3. Call `public_key_resolver(agent_id)`. If it returns `None`, raise `InvalidSignatureError` (unknown identity — hard rejection per cluster contract).
4. Call `verify_signature(message, signature, public_key)`. If it returns `False`, raise `InvalidSignatureError` (invalid signature — hard rejection).
5. Only if both checks pass: proceed with transition validation, transcript append, and behavioral tracking.

Add a new `InvalidSignatureError` exception class in `session.py` alongside `InvalidTransitionError`.

Update `Agent._send()` to pass a resolver callback when calling `apply_message()`. The `Agent` class already has access to both parties' key pairs (its own and the counterparty's via the session's `parties` mapping), so the resolver wiring is straightforward.

### c) Interactions with other findings

- **SEC-005** (closed, PASS): Established the cluster pattern. This sprint conforms to it.
- **SEC-014** (attestation signature verification optional): Third in cluster. Will follow the same mandatory resolver pattern on `AttestationStore.ingest()`.
- **SEC-007** (Concordia zero caller authentication, closed): The auth layer added by SEC-007 is orthogonal — it authenticates the MCP *caller*, while SEC-010 verifies the cryptographic *message signature*. Both are required: SEC-007 prevents impersonation at the transport layer, SEC-010 prevents forged messages at the protocol layer.

### d) New risk introduced

- All callers of `apply_message()` must now provide a `public_key_resolver`. The only production caller is `Agent._send()` (agent.py:298). Tests that call `apply_message()` directly must also provide a resolver. This is the **correct** behavior — the cluster contract mandates that verification cannot be bypassed.
- Messages with missing `signature` or `from` fields will now raise `InvalidSignatureError` instead of `KeyError`. This is a strictness improvement, not a regression.

---

## Fix Specification

### Files to modify

1. **`concordia/session.py`** — `apply_message()` method (lines 115-155)
   - Add `public_key_resolver` required parameter
   - Add `InvalidSignatureError` exception class
   - Add signature verification block before state transition
   - Add import for `verify_signature` from `.signing`
   - Add import for `Ed25519PublicKey` from `cryptography`
   - Add import for `Callable` from `typing`

2. **`concordia/agent.py`** — `_send()` method (lines 276-299)
   - Wire `public_key_resolver` callback using `self.key_pair.public_key` and counterparty keys
   - The Agent has access to its own key pair; for the resolver, it needs to map agent_ids to public keys from the session's party list

3. **`concordia/__init__.py`** — Export `InvalidSignatureError`

### Behavior before

`apply_message()` accepts any message dict, validates only the state transition, appends to transcript, and tracks behavior. Messages with invalid, absent, or forged signatures are accepted and become permanent parts of the hash-chained transcript.

### Behavior after

`apply_message()` requires a `public_key_resolver` callback. Before any state transition:
- If `message["signature"]` is missing or empty: raises `InvalidSignatureError`
- If `public_key_resolver(agent_id)` returns `None`: raises `InvalidSignatureError` (unknown identity)
- If `verify_signature()` returns `False`: raises `InvalidSignatureError` (invalid signature)
- Session state is unchanged on any rejection — no transcript append, no behavioral tracking

### Regression tests

New file: `tests/test_session_signature_verification.py`

Tests:
1. **Valid signed message accepted** — create a session with properly signed messages, verify state transitions work as before.
2. **Forged signature rejected** — create a valid message, tamper with the signature, verify `InvalidSignatureError` raised and session state unchanged.
3. **Missing signature rejected** — create a message with no `signature` field, verify rejection.
4. **Unknown agent_id rejected** — create a message with a valid signature but an agent_id the resolver doesn't recognize, verify rejection.
5. **Resolver returning None rejected** — verify that a resolver that returns `None` causes rejection, matching cluster contract.
6. **Wrong key rejected** — sign a message with key A but have the resolver return key B's public key, verify rejection.
7. **State unchanged on rejection** — verify that after any rejection, session state, transcript length, and round count are all unchanged.

### Prompt injection

`apply_message()` processes message dicts that contain user-controlled content (body, reasoning fields). These fields are stored in the transcript and used for behavioral tracking but never reach any model prompt. No prompt injection surface.

### Definition of done (evaluator criteria)

1. `apply_message()` has a **mandatory** `public_key_resolver` parameter (not optional, no default).
2. Messages with invalid signatures raise `InvalidSignatureError` — session state unchanged.
3. Messages with unknown agent_ids (resolver returns `None`) raise `InvalidSignatureError`.
4. Messages with missing signatures raise `InvalidSignatureError`.
5. The resolver follows the SEC-005 cluster contract: `Callable[[str], PublicKey | None]`, mandatory, null → rejection.
6. All 7 regression tests pass.
7. Full test suite count >= 459 (no decrease from baseline).
8. `Agent._send()` correctly wires the resolver.
9. The fix does not couple `Session` to any specific key storage — the resolver is a pure callback.
