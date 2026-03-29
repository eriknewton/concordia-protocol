# SPRINT CONTRACT — SEC-014: Attestation Signature Verification Is Optional

**Sprint Date:** 2026-03-28
**Finding:** SEC-014 (High)
**Branch:** `security-review`
**Cluster:** Third and final of three (SEC-005, SEC-010, SEC-014) — this sprint conforms exactly to the resolver pattern established by SEC-005 and implemented by SEC-010.

---

## Cluster Contract Conformance

SEC-005 (Import skips signature verification, Sanctuary TypeScript) established the verification pattern for the entire signature verification cluster. SEC-010 (Session state machine never verifies signatures, Concordia Python) implemented the same pattern for session messages. This sprint closes the cluster by applying the identical pattern to attestation ingestion.

| SEC-005 Cluster Contract Requirement | SEC-014 Implementation |
|---|---|
| Callback signature: `(identifier: string) => PublicKey \| null` | `public_key_resolver: Callable[[str], Ed25519PublicKey \| None]` — identical to SEC-010 |
| Verification is **mandatory, not optional** | `public_key_resolver` is a required parameter on `ingest()` — no default value, no `Optional` type |
| Null return from resolver → **rejection, not warning** | If resolver returns `None`, add to errors and reject — hard failure, not the current warning |
| Response includes structured rejection counts | `ValidationResult.errors` list contains specific failure messages per party |

The SEC-010 sprint result explicitly noted: "The same pattern — mandatory `public_key_resolver`, null → rejection — should be applied to `AttestationStore.ingest()`." This contract follows that directive exactly.

---

## Architecture Decision

### a) Root cause — not the symptom

The `AttestationStore.ingest()` method in `store.py:163-175` accepts an optional `public_keys` parameter defaulting to `None`. The `_validate()` method (store.py:277-362) checks for signatures but when `public_keys` is `None`, it only emits a warning (store.py:332-338) and proceeds to accept the attestation. The only production caller — `tool_ingest_attestation()` at mcp_server.py:787 — calls `ingest(attestation)` without passing any public keys.

The root cause is identical to SEC-005 and SEC-010: verification machinery exists (`verify_signature()` is called when keys are provided, store.py:339-356) but is gated behind an optional parameter, making the secure path opt-in rather than mandatory.

### b) Smallest change that closes the vulnerability

Replace the optional `public_keys: dict[str, Any] | None = None` parameter on both `ingest()` and `_validate()` with a mandatory `public_key_resolver: Callable[[str], Ed25519PublicKey | None]`:

```python
def ingest(
    self,
    attestation: dict[str, Any],
    public_key_resolver: Callable[[str], Ed25519PublicKey | None],
) -> tuple[bool, ValidationResult]:
```

In `_validate()`, replace the "warn-if-no-keys" block (store.py:329-338) with mandatory verification:
1. For each party with a signature, call `public_key_resolver(agent_id)`.
2. If resolver returns `None` → add error (not warning), reject attestation.
3. If `verify_signature()` returns `False` → add error, reject attestation.
4. No fallback path. No "skip verification" code path.

In `tool_ingest_attestation()`, wire a resolver that looks up public keys from the session store (`_store`) using the attestation's `session_id` to find the `SessionContext` and extract the parties' public keys.

### c) Interactions with other findings

- **SEC-005** (closed, PASS): Established the cluster pattern. This sprint conforms to it.
- **SEC-010** (closed, PASS): Second in cluster. Implemented the same pattern on `Session.apply_message()`. This sprint mirrors SEC-010's approach for `AttestationStore.ingest()`.
- **SEC-007** (closed, PASS): The auth layer added by SEC-007 authenticates the MCP caller. SEC-014 verifies the cryptographic signatures within the attestation data itself. Both are required: SEC-007 prevents impersonation at the transport layer, SEC-014 ensures attestation content integrity at the data layer.

### d) New risk introduced

- All callers of `ingest()` must now provide a `public_key_resolver`. Existing tests that call `ingest()` without one will fail at the type level. This is the correct behavior per the cluster contract — verification cannot be bypassed.
- Attestations from sessions not in the session store (e.g., from external sources or after server restart) will be rejected because the resolver cannot find their keys. This is the correct fail-closed behavior. A future enhancement could allow callers to explicitly provide keys, but the default must be mandatory verification.

---

## Fix Specification

### Files to modify

1. **`concordia/reputation/store.py`** — `ingest()` and `_validate()` methods
   - Change `public_keys: dict[str, Any] | None = None` to `public_key_resolver: Callable[[str], Ed25519PublicKey | None]` (mandatory, no default)
   - In `_validate()`: remove the "warn and skip" code path. Always call resolver for each party, reject on `None`.
   - Add imports for `Callable` from `typing` and `Ed25519PublicKey` from `cryptography`

2. **`concordia/mcp_server.py`** — `tool_ingest_attestation()` (line 787)
   - Build a resolver function that looks up public keys from the session store using `attestation["session_id"]`
   - Pass the resolver to `_attestation_store.ingest(attestation, public_key_resolver=resolver)`

3. **`tests/test_attestation_signature_verification.py`** — New regression test file

### Behavior before

`ingest()` accepts an optional `public_keys` dict. When called from `tool_ingest_attestation()`, no keys are passed. The `_validate()` method emits a warning ("Signature verification will be skipped") and accepts the attestation. Any well-formed attestation with syntactically valid base64 strings in signature fields is accepted and scored regardless of cryptographic validity.

### Behavior after

`ingest()` requires a mandatory `public_key_resolver` callback. For every party in the attestation:
- If `public_key_resolver(agent_id)` returns `None`: validation fails with error (unknown identity — hard rejection)
- If `verify_signature()` returns `False`: validation fails with error (invalid signature — hard rejection)
- No "skip verification" code path exists
- Attestations with unverifiable signatures are rejected, not stored, not scored

### Regression tests

New file: `tests/test_attestation_signature_verification.py`

Tests:
1. **Valid signed attestation accepted** — create an attestation with real Ed25519 signatures, provide a resolver that returns correct public keys, verify acceptance.
2. **Forged signature rejected** — create a valid attestation, tamper with one signature, verify rejection with error message identifying the party.
3. **Unknown agent_id rejected** — provide a resolver that returns `None` for one party's agent_id, verify rejection.
4. **Resolver returning None for all parties rejected** — resolver always returns `None`, verify all parties flagged.
5. **Wrong key rejected** — sign with key A, resolver returns key B's public key, verify rejection.
6. **Store unchanged on rejection** — verify that after rejection, store count is unchanged, no indexes updated.
7. **No fallback to warning** — verify that the old "signatures present but public_keys not provided" warning path no longer exists.
8. **MCP tool wires resolver correctly** — verify that `tool_ingest_attestation` passes a functioning resolver to `ingest()`.

### Prompt injection

`ingest()` processes attestation dicts containing party behavioral data, transaction categories, and metadata. These fields are stored but never reach any model prompt. No prompt injection surface.

### Definition of done (evaluator criteria)

1. `ingest()` has a **mandatory** `public_key_resolver` parameter (not optional, no default).
2. `_validate()` has a **mandatory** `public_key_resolver` parameter (not optional, no default).
3. Attestations with invalid signatures are rejected with errors — not warnings, not accepted.
4. Attestations with unknown agent_ids (resolver returns `None`) are rejected with errors.
5. The old "Signature verification will be skipped" warning code path is deleted — no fallback.
6. The resolver follows the SEC-005 cluster contract: `Callable[[str], Ed25519PublicKey | None]`, mandatory, null → rejection.
7. `tool_ingest_attestation` in mcp_server.py wires a resolver that resolves keys from the session store.
8. All regression tests pass.
9. Full test suite count >= 469 (no decrease from baseline).
10. The fix conforms point-by-point to the SEC-005 cluster contract and the SEC-010 implementation pattern.
