---
type: build-summary
status: shipped
review_status: pending
last_updated: 2026-04-15
title: "mandate_verification primitive — Concordia v0.4.0"
commit: 4266269
branch: mandate-verification-v04
---

# Mandate Verification Build Summary

## Overview

Shipped MCP tool `concordia_verify_mandate` (tool #58) in commit `4266269` on 2026-04-14. The primitive verifies signed mandate credentials — authorization documents that allow agents to act within specified constraints on behalf of an issuer. Five-check verification pipeline: issuer signature (EdDSA/ES256), three-mode temporal validity, JSON Schema constraint compliance, delegation chain integrity, and fail-closed revocation. 832 tests passing (753 baseline + 79 new), zero regressions. Closes the mandate_verification planning item for Concordia v0.4.0.

## Files in the commit

| File | Lines | Change |
|------|-------|--------|
| `concordia/models/__init__.py` | +1 | Re-export models package |
| `concordia/models/mandate.py` | +441 | `Mandate`, `ValidityWindow`, `DelegationLink`, `MandateVerificationResult` dataclasses; `TemporalMode` and `MandateStatus` enums; `MANDATE_JSON_SCHEMA` (Draft 2020-12); serialization helpers (`to_dict`, `from_dict`) |
| `concordia/mandate.py` | +440 | Verification engine: `sign_mandate`, `sign_delegation`, `validate_mandate_schema`, `validate_constraints`, `check_temporal_validity`, `verify_delegation_chain`, `check_revocation`, `verify_mandate` (full five-check pipeline) |
| `concordia/mcp_server.py` | +98 | New tool registration (`concordia_verify_mandate`), imports, base64url key reconstruction for EdDSA and ES256, delegation key map deserialization |
| `concordia/__init__.py` | +21 | Public exports: `Mandate`, `ValidityWindow`, `DelegationLink`, `TemporalMode`, `MandateStatus`, `MandateVerificationResult`, `sign_mandate`, `verify_mandate`, `validate_constraints`, `ES256KeyPair` |
| `tests/test_mandate.py` | +1077 | 79 new tests across 9 categories |
| `tests/test_mcp_server.py` | +3/-3 | Tool count assertion bumped 57 -> 58 |
| `Review/Concordia/Mandate_Verification_BUILD_SUMMARY.md` | +101 | This file (stub written in commit, replaced post-hoc) |

**Total: +2,182 / -3 lines across 8 files.**

## MCP tool surface

**Name:** `concordia_verify_mandate`

**Inputs:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `mandate` | `dict` | Yes | The mandate credential to verify |
| `issuer_public_key_b64` | `str` | Yes | Base64url-encoded issuer public key |
| `algorithm` | `str` | No (default `"EdDSA"`) | Signing algorithm: `EdDSA` or `ES256` |
| `sequence_key` | `str \| None` | No | Sequence key for sequence-mode validity |
| `state_active` | `bool \| None` | No | Whether state condition is active (state_bound mode) |
| `action` | `dict \| None` | No | Action dict to validate against mandate constraints |
| `delegation_keys` | `dict \| None` | No | Map of `agent_id -> base64url public key` for chain verification |
| `check_revocation` | `bool` | No (default `true`) | Whether to check revocation endpoint |

**Output:** JSON string containing a `MandateVerificationResult`:
- `valid` (bool) — overall pass/fail
- `mandate_id`, `issuer`, `subject` — identity fields from the mandate
- `checks` (dict) — per-check pass/fail: `schema`, `issuer_signature`, `temporal`, `constraints`, `delegation`, `revocation`
- `errors` (list[str]) — failure reasons
- `warnings` (list[str]) — non-fatal warnings

**Fail-closed behavior:** The tool returns `valid: false` on any check failure and stops execution at the first failing check (fail-fast). If the revocation endpoint is unreachable, verification fails rather than silently degrading (per CLAUDE.md constraint #5). Invalid public key encoding returns a JSON error object, not an exception.

## Verification behavior

### 1. Issuer signature (EdDSA / ES256)

Signs and verifies over all mandate fields except `signature` using canonical JSON (sorted keys, deterministic serialization via `concordia.signing.canonical_json`). Supports two algorithms:
- **EdDSA** — Ed25519 via `cryptography.hazmat.primitives.asymmetric.ed25519`
- **ES256** — ECDSA P-256 via `cryptography.hazmat.primitives.asymmetric.ec` with SHA-256

Public keys are transmitted as base64url-encoded bytes. ES256 keys use X9.62 uncompressed point format.

### 2. Three-mode temporal validity

Aligned with issue #1734 consensus:

- **`sequence`** — Mandate is valid for a specific session/transaction identified by `sequence_key`. Verification checks that the provided sequence key matches the mandate's key.
- **`windowed`** — Mandate is valid between `not_before` and `not_after` ISO 8601 timestamps. Verification checks current time falls within the window.
- **`state_bound`** — Mandate is valid while a named condition (e.g., `"escrow_open"`) is active. Caller passes `state_active` bool; if `false`, mandate is invalid.

### 3. JSON Schema constraint compliance

Mandate constraints are expressed as JSON Schema (Draft 2020-12). Verification validates:
1. The constraints themselves are well-formed JSON Schema (via `Draft202012Validator.check_schema`)
2. If an `action` dict is provided, it satisfies the constraints (via `jsonschema.validate`)

### 4. Delegation chain walking

Verifies an ordered list of `DelegationLink` objects from root issuer to final subject:
- Chain root's `delegator` must match the mandate's `issuer`
- Chain tail's `delegate` must match the mandate's `subject`
- Each link's `delegator` must match the previous link's `delegate` (continuity)
- Each link's signature is verified against the delegator's public key from the `delegation_keys` map
- Empty chain = direct mandate, always valid

Per-link signatures allow mixed-algorithm chains (e.g., link 0 EdDSA, link 1 ES256).

### 5. Fail-closed revocation

Checks mandate ID against an HTTP revocation list endpoint (JSON `{"revoked_ids": [...]}`) using `urllib.request` (stdlib). Three failure modes, all fail-closed:
- Mandate ID found in `revoked_ids` -> revoked
- Endpoint unreachable (`URLError`, `HTTPError`) -> verification fails
- Malformed response (`JSONDecodeError`) -> verification fails

Configurable timeout (default 5s). Can be disabled via `check_revocation: false`.

## Test breakdown

| Category | Count | Coverage |
|----------|-------|----------|
| Schema validation | 10 | Valid/invalid mandate dicts, edge cases |
| Signing roundtrip (EdDSA + ES256) | 6 | Sign-then-verify for both algorithms |
| Temporal validity (3 modes) | 13 | Each mode's happy path, expired, not-yet-valid, missing fields |
| Constraint compliance | 8 | Valid/invalid schemas, action validation, empty constraints |
| Delegation chain | 10 | Valid chains, broken continuity, missing keys, mixed algorithms |
| Revocation | 4 | Revoked, not-revoked, unreachable endpoint, malformed response |
| Full verification integration | 14 | End-to-end verify_mandate with various combinations |
| Model serialization | 9 | to_dict/from_dict roundtrips for all model classes |
| MCP tool integration | 5 | Tool registration, parameter handling, key deserialization |

**Total: 79 new tests. 832 suite total (753 baseline + 79 new). 0 failures.**

## Dependencies

**No new external dependencies.** Revocation check uses `urllib.request` (stdlib). Signature verification uses the existing `cryptography` dependency. Constraint validation uses the existing `jsonschema` dependency. ES256 support reuses `ES256KeyPair` added in the trust-evidence-format work.

## Open questions for v0.4.0 planning

1. **Scope restriction narrowing** — Delegation links carry optional `scope_restriction` dicts but verification only checks chain integrity (signatures + continuity), not whether scope correctly narrows at each hop.
2. **Max delegation depth** — No explicit limit on chain length. Consider capping at ~10 links.
3. **Revocation caching** — Every verification hits the endpoint. Short TTL cache may be needed for production.
4. **Mandate storage** — Primitive is verification-only (stateless). A `MandateStore` for indexing received mandates is a separate decision.
