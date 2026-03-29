# SPRINT_EVAL.md — SEC-007: Independent QA Evaluation

**Date:** 2026-03-28
**Evaluator posture:** Skeptical QA — did not write this code, does not trust self-assessment.
**Finding:** SEC-007 — Concordia Has Zero Caller Authentication: Any MCP Client Can Impersonate Any Agent
**Branch:** `security-review`

---

## 1. ROOT CAUSE

**Question:** The finding is that any MCP client can impersonate any agent — zero caller authentication. Does the fix address the root cause?

**Verdict: PASS.**

The root cause was that every identity-dependent tool accepted `agent_id`, `role`, `initiator_id`, `responder_id`, or `from_agent` as plain trusted strings with no authentication binding. The fix introduces bearer-token authentication at two scopes (agent-scoped and session-scoped) via a new `AuthTokenStore` class in `concordia/auth.py`.

I independently traced the validation path for representative tools:

- `tool_propose` (line 378): `auth_token` is a required parameter. Line 389 calls `_auth.validate_session_token(session_id, role, auth_token)` — this is the **first executable line** of the handler, before `_store.get()` (line 391) or any state mutation. If validation fails, `_auth_error()` returns immediately.
- `tool_deregister_agent` (line 1044): `auth_token` is required. Line 1049 validates via `_auth.validate_agent_token(agent_id, auth_token)` before `_registry.deregister()` at line 1051.
- `tool_relay_receive` (line 1669): `auth_token` required. Line 1676 validates before any relay interaction.

I confirmed via grep that **24 identity-dependent tools** have `auth_token` validation, and in every case the validation precedes any state access or mutation. An unauthenticated caller receives `{"error": "Authentication required: invalid or missing auth_token for '<identity>'."}` — an explicit rejection, not a missing-parameter error. The error message is produced by `_auth_error()` (line 224), which uses a static template that does not leak the expected token value.

The `_auth_error` function interpolates the identity string into the error message. This identity string is user-controlled (it's the claimed `agent_id` or role). The interpolation is into a JSON string value via `json.dumps`, not into any executable context. This is safe.

---

## 2. TOKEN SECURITY

### 2a. Cryptographically secure source

**Verdict: PASS.**

`generate_token()` at `auth.py:23` uses `secrets.token_hex(32)`, which produces 256 bits (64 hex characters) from the OS CSPRNG (`os.urandom` under the hood). This is not `random.random()`, not `uuid4()`, not `hashlib`. The `secrets` module is the stdlib-recommended source for security-sensitive randomness.

### 2b. Constant-time comparison

**Verdict: PASS.**

`validate_agent_token()` at `auth.py:69` uses `hmac.compare_digest(expected, token)`. `validate_session_token()` at `auth.py:111` uses the same. `get_any_session_role()` at `auth.py:117` also uses `hmac.compare_digest`. All three validation paths use constant-time comparison. No equality operator (`==`) is used for token comparison anywhere in `auth.py`.

### 2c. Token revocation

**Verdict: CONDITIONAL PASS.**

`revoke_agent_token()` at `auth.py:55-59` removes the token from both `_agent_tokens` and `_token_to_agent` dicts. It is called from `tool_deregister_agent` (mcp_server.py:1052) after successful deregistration. A revoked token would fail `validate_agent_token()` because the `_agent_tokens.get(agent_id)` lookup returns `None` at line 67, causing the function to return `False`.

However, **there is no test that verifies a revoked token is rejected.** `TestDeregisterAuth.test_deregister_accepts_correct_token` (test_authentication.py:226-232) calls deregister with the correct token and asserts `removed: True`, but does not attempt to use the revoked token afterward. This is a gap — the revocation code path is untested.

Additionally, there is no revocation mechanism for session-scoped tokens. Once issued, session tokens remain valid for the lifetime of the in-memory store. This is consistent with Concordia's in-memory architecture (sessions themselves are ephemeral), but it means a leaked session token cannot be invalidated without restarting the server.

Re-registration of the same `agent_id` (line 44-53 of auth.py) does correctly revoke the old token and issue a new one — the old token is removed from `_token_to_agent` at line 50. This is good defensive behavior.

### 2d. Token unpredictability

**Verdict: PASS.**

Tokens are `secrets.token_hex(32)` — 256 bits of OS-level randomness. No sequential component, no timestamp, no agent_id derivation. Tokens cannot be inferred or predicted.

---

## 3. REGRESSION TESTS

**File:** `tests/test_authentication.py` (312 lines, 17 tests in 9 test classes)

**Verdict: CONDITIONAL PASS.**

**Present and verified:**

| Test Scenario | Test(s) | Verified |
|---|---|---|
| No token → rejected | `TestNoToken` (3 tests): propose, accept, session_status with `auth_token=""` | PASS — all assert `"error" in result` and `"Authentication required" in result["error"]` |
| Wrong token → rejected | `TestWrongToken` (2 tests): propose and reject with fabricated 64-char hex | PASS |
| Correct token → succeeds | `TestCorrectToken` (2 tests): propose with initiator, counter with responder | PASS |
| Role isolation | `TestRoleIsolation` (2 tests): initiator token as responder and vice versa | PASS |
| Cross-agent deregistration rejected | `TestDeregisterAuth` (2 tests) | PASS |
| Cross-agent relay receive rejected | `TestRelayAuth` (1 test) | PASS |
| Token issuance verified | `TestTokenIssuance` (2 tests): 64-char hex, distinct tokens | PASS |
| Public tools without tokens | `TestPublicTools` (2 tests): search_agents, reputation_score | PASS |
| Cross-agent want withdrawal rejected | `TestWantAuth` (1 test) | PASS |

**Missing:**

- **No revoked-token test.** There is no test that: (1) registers an agent, (2) deregisters the agent (which revokes the token), (3) attempts to use the revoked token and asserts rejection. The revocation code path (`revoke_agent_token`) is exercised only as a side effect of deregistration but never verified to actually block subsequent use.

**Full test suite (independently executed):**

```
458 passed in 0.42s
```

441 original + 17 new = 458. All passing. Matches the sprint result claim.

---

## 4. SCOPE CREEP CHECK

**Sprint result claims SEC-008, SEC-009, and SEC-015 are closed as collateral.**

### SEC-008 (Agent deregistration has no ownership verification)

**Verdict: Legitimate collateral closure.**

SEC-008's root cause was that `concordia_deregister_agent` accepted any `agent_id` without verifying the caller owned it. The fix adds `auth_token` validation at mcp_server.py:1049 — the caller must present the token that was issued when that agent was registered. This directly and naturally addresses SEC-008 as a consequence of the authentication layer. No separate, unrelated code was needed.

### SEC-009 (Relay: any agent can read any other agent's messages)

**Verdict: Legitimate collateral closure.**

SEC-009's root cause was that `concordia_relay_receive` trusted the `agent_id` parameter. The fix adds `auth_token` validation at mcp_server.py:1676 — the caller must present the agent token matching the claimed `agent_id`. This directly addresses SEC-009. The `TestRelayAuth.test_relay_receive_rejects_wrong_agent` test (line 238-255) explicitly tests this scenario.

### SEC-015 (Want/Have registry has no identity verification)

**Verdict: Legitimate collateral closure.**

SEC-015's root cause was that `post_want`, `post_have`, `withdraw_want`, and `withdraw_have` accepted `agent_id` without verification. The fix adds `auth_token` validation to all four tools (lines 1281, 1331, 1407, 1435 of mcp_server.py). Additionally, `withdraw_want` and `withdraw_have` now perform ownership verification — they check that the authenticated agent actually owns the want/have being withdrawn. The `TestWantAuth` test (line 289-311) verifies cross-agent withdrawal is rejected.

**All three collateral closures are natural consequences of the authentication layer. No unrelated changes were bundled.**

---

## 5. PUBLIC SURFACE

**Question:** Can the tools left open be used to exfiltrate private state or manipulate identity-dependent data?

**Verdict: CONDITIONAL PASS.**

The sprint contract and result identify these tools as public (no token required):

**Safe public tools (read-only, no private data):**
- `concordia_search_agents`, `concordia_agent_card`, `concordia_preferred_badge` — return public registry data (agent_id, roles, categories). No private keys, no tokens, no deal terms.
- `concordia_search_wants`, `concordia_search_haves`, `concordia_find_matches`, `concordia_want_registry_stats`, `concordia_get_want`, `concordia_get_have` — return public marketplace data.
- `concordia_reputation_query`, `concordia_reputation_score` — return public reputation data. Attestations by design contain behavioral signals only, not deal terms (per CLAUDE.md §8).
- `concordia_relay_stats` — returns aggregate statistics only.
- `concordia_efficiency_report` — returns interaction analysis by `interaction_id`. Requires knowing the ID, which is opaque.

**Entry points (must be public to bootstrap):**
- `concordia_open_session` — creates a session and returns tokens. This must be public because it is the token issuance point. A caller can open sessions between any two agent IDs, but this is by design — the authentication prevents *impersonation within* sessions, not session creation. This is consistent with the sprint contract's threat model.
- `concordia_register_agent` — registers an agent and returns a token. Same reasoning.

**Tools with residual risk (not token-gated, flagged by sprint result):**
- `concordia_relay_conclude` — any caller can conclude any relay session. Requires knowing the `relay_session_id`.
- `concordia_relay_archive` — any caller can archive any concluded relay session.
- `concordia_relay_transcript` — access control is optional (the `agent_id` parameter is `None` by default). If omitted, the full transcript is returned to any caller. This is a **data exposure risk**: relay transcripts contain negotiation messages that may include sensitive terms and strategies.
- `concordia_relay_list_archives` — returns archive metadata for all participants.
- `concordia_relay_status` — returns session details including participant IDs.
- `concordia_session_list` (if it exists) — sprint result notes this is unrestricted.
- `concordia_sanctuary_bridge_commit` — generates commitment payloads including agreed terms. No auth check. Requires knowing the session ID.
- `concordia_sanctuary_bridge_attest` — accepts arbitrary attestation dicts with no auth check.

The sprint result *does* disclose items 4-6 under "ADJACENT FINDINGS NOTICED (NOT FIXED)" which is appropriate transparency. However, `relay_transcript` without a mandatory `agent_id` and auth check is a meaningful data exposure path, and `sanctuary_bridge_commit`/`sanctuary_bridge_attest` operating without tokens means the bridge boundary remains unauthenticated — partially undermining the sovereignty model described in CLAUDE.md §4.

These are **not regressions** introduced by this sprint — they are pre-existing gaps that the sprint did not claim to fix. They should be tracked as follow-up findings.

---

## 6. PROMPT INJECTION

**Question:** Does any authentication input path accept user-controlled strings that could reach a model prompt unsanitized?

**Verdict: PASS.**

The sprint contract addresses this at section "PROMPT INJECTION CONSIDERATION." I verified independently:

1. The `auth_token` parameter is a random hex string. Validation is `hmac.compare_digest(expected, token)` — a byte comparison, not a parse or eval.
2. The `_auth_error()` helper at line 224-232 interpolates the `identity` string (user-controlled) into a JSON string value via `json.dumps()`. This is a data serialization path, not a prompt construction path. The resulting JSON is returned as the MCP tool response. No part of the authentication flow constructs prompts, calls LLMs, or feeds user input into any execution context beyond string formatting.
3. The `_canonical_role()` method at line 78-85 normalizes role strings via `.lower()` and string comparison. No eval, no regex, no dynamic dispatch on the role value.
4. Token storage uses `dict[str, str]` and `dict[tuple[str, str], str]` — Python dicts with string keys and values. No serialization to external stores, no SQL, no command construction.

No new prompt injection surface is introduced. The existing prompt injection surface (acknowledged in the sprint contract as "SEC-ADD-01, SEC-ADD-02") remains open and is out of scope for this sprint.

---

## GRADE: CONDITIONAL PASS

The fix correctly addresses the SEC-007 root cause. Token generation is cryptographically sound, validation uses constant-time comparison, and all 24 identity-dependent tools are gated. The test suite passes at 458/458. The collateral closures of SEC-008, SEC-009, and SEC-015 are legitimate. No prompt injection surface is introduced.

**Conditions for full PASS (must be addressed before SEC-007 can be marked RESOLVED):**

1. **Add a revoked-token regression test.** A test must: register an agent, deregister the agent (triggering `revoke_agent_token`), then attempt an identity-dependent operation with the revoked token and assert rejection. Without this test, the revocation path is unverified. This is a test-only change — no source code modification needed.

2. **Document the relay transcript/conclude/archive auth gap as a tracked finding.** `concordia_relay_transcript` with no mandatory `agent_id` exposes full relay transcripts to any caller who knows the session ID. `concordia_relay_conclude` allows any caller to terminate any relay session. These are pre-existing gaps, not regressions from this sprint, but they should be tracked explicitly (e.g., as SEC-025 or similar) rather than left as informal notes in SPRINT_RESULT.md.

**Non-blocking observations for follow-up:**

- Session tokens have no revocation mechanism. A leaked session token remains valid until server restart. Acceptable for v0.1.0 but should be addressed before production deployment.
- `concordia_sanctuary_bridge_commit` and `concordia_sanctuary_bridge_attest` operate without authentication. Since these generate payloads for Sanctuary (which independently verifies cryptographically), the risk is limited to information disclosure of agreed terms and potential spam. Still, token-gating these tools would be consistent with the authentication model.
- No token rotation mechanism exists. Re-registration is the only way to get a new agent token. Acceptable for v0.1.0.
- The `concordia_open_session` tool allows any caller to open sessions between arbitrary agent IDs. This is acknowledged in the threat model as a design choice (authentication prevents impersonation *within* sessions). However, it means a single MCP client can still create sessions and drive one side to completion using the issued tokens. The Sybil detector remains the only defense against fabricated reputation from self-dealing sessions.

---

## SEC-007 CONDITIONAL PASS — Follow-Up Resolution (2026-03-28)

**Evaluator:** Targeted re-check of the two conditions from the CONDITIONAL PASS evaluation.

**CONDITION 1 — Revocation test: PASS**

`test_revoked_token_rejected_after_deregistration()` in `tests/test_authentication.py` (line 234) satisfies all four requirements:
- (a) Registers `agent_a` via `tool_register_agent` and captures `auth_token` ✓
- (b) Confirms the token works by calling `tool_post_want` and asserting success ✓
- (c) Deregisters `agent_a` via `tool_deregister_agent` (which triggers `revoke_agent_token`) and asserts `removed is True` ✓
- (d) Attempts `tool_post_want` with the revoked token and asserts `"Authentication required"` in the error, plus explicitly asserts `"not found"` is NOT in the error ✓

Full test suite: **459/459 passed** (up from 458 at original evaluation — the new revocation test accounts for the +1).

**CONDITION 2 — Relay gaps logged: PASS**

HP-16 and HP-17 are present in REMEDIATION_PLAN.md Section 2 (High Priority):
- **HP-16** correctly identifies `concordia_relay_transcript` as exposing full session transcripts to unauthenticated callers and prescribes adding `auth_token`/`agent_id` validation ✓
- **HP-17** correctly identifies `concordia_relay_conclude` as allowing any caller to terminate any relay session and prescribes the same auth gating ✓
- Both entries use the standard format (`Finding`, `Remediation`, `Effort`, `Dependencies`) consistent with HP-14/HP-15 and other Section 2 entries ✓
- Both reference SEC-007 evaluator condition 2 as provenance ✓

**OVERALL GRADE: PASS**

Both conditions from the CONDITIONAL PASS have been resolved. SEC-007 may be marked RESOLVED.

---

# SPRINT_EVAL.md — SEC-010: Independent QA Evaluation

**Date:** 2026-03-28
**Evaluator posture:** Skeptical QA — did not write this code, does not trust self-assessment.
**Finding:** SEC-010 — Concordia Session State Machine Does Not Verify Message Signatures
**Branch:** `security-review`

---

## 1. ROOT CAUSE

**Question:** Does the fix make verification mandatory on every message application, or only on some paths? Is there any code path where a message is accepted into the state machine without signature verification?

**Verdict: PASS.**

I traced the execution path in `session.py:139-220`. The `apply_message()` method has the following structure:

1. Lines 164-187: **Signature verification block** — runs first, before any state change.
   - Line 165-168: Extracts `agent_id` from `message["from"]["agent_id"]`. If missing → `InvalidSignatureError`.
   - Line 171-175: Extracts `signature` from `message["signature"]`. If missing or empty → `InvalidSignatureError`.
   - Line 177-181: Calls `public_key_resolver(agent_id)`. If `None` → `InvalidSignatureError`.
   - Line 183-187: Calls `verify_signature(message, signature, public_key)`. If `False` → `InvalidSignatureError`.
2. Lines 189-220: State transition, transcript append, and behavioral tracking — only reachable if all four verification checks pass.

All four rejection paths raise `InvalidSignatureError` before any of the following occur: `_TRANSITIONS` lookup (line 193), `self.transcript.append()` (line 202), `_track_behavior()` (line 210), or `self.state = new_state` (line 214). There is no early return, no try/except that swallows errors, and no conditional bypass.

I verified callers of `apply_message()`:
- **Production:** Only `Agent._send()` at `agent.py:298` calls `session.apply_message(msg, self._public_key_resolver)`. The resolver is always passed.
- **Tests:** All 10 test methods in `test_session_signature_verification.py` pass a resolver argument. The method signature has no default value for `public_key_resolver`, so calling without it would raise `TypeError`.
- **MCP server:** `mcp_server.py` never calls `apply_message()` directly. It reads `session.transcript` for display/validation but never appends to it.

I also checked for direct transcript manipulation outside `apply_message()`. The only `transcript.append` in the codebase is at `relay.py:368`, but that operates on a `RelaySession` object (a completely separate dataclass from `session.py`'s `Session` class), not the protocol session.

**Conclusion:** There is no code path where a message enters the `Session` state machine without passing all four signature verification checks.

---

## 2. CLUSTER CONTRACT CONFORMANCE

**Question:** Does SEC-010 conform to the SEC-005 mandatory resolver pattern?

**Verdict: PASS.**

### 2a. `public_key_resolver` is required, not optional

At `session.py:142`:
```python
public_key_resolver: Callable[[str], Ed25519PublicKey | None],
```
No default value. No `Optional` wrapper. No `= None`. Calling `apply_message(msg)` without a resolver raises `TypeError: apply_message() missing 1 required positional argument: 'public_key_resolver'`. Verified by inspection — this is enforced by Python's function signature mechanics.

### 2b. Unresolvable agent_id raises `InvalidSignatureError`, not a warning

At `session.py:178-181`:
```python
if public_key is None:
    raise InvalidSignatureError(
        f"Unknown agent identity '{agent_id}' — resolver returned None"
    )
```
This is a hard rejection — `raise`, not `warnings.warn()` or `logging.warning()`. No message is appended to the transcript, no state transition occurs.

### 2c. `Session` has no import of or reference to any specific key store

I verified `session.py` imports:
- `from .signing import KeyPair, verify_signature` — cryptographic primitives, not storage
- `from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey` — type annotation only
- `from typing import Callable` — type annotation only

No import of `AuthTokenStore`, no import of any registry or store module. The `_party_keys` dict is an internal convenience cache populated via `add_party()` — it is not a key store. The `public_key_resolver` callback is the sole mechanism for key resolution, and it is injected by the caller (Agent), not by Session itself.

**Conclusion:** All three cluster contract requirements are met point-for-point.

---

## 3. HASH CHAIN INTEGRITY

**Question:** Does the fix intercept forged messages before they reach the hash chain?

**Verdict: PASS.**

The critical ordering in `apply_message()`:
1. **Line 164-187:** Signature verification (all four checks)
2. **Line 202:** `self.transcript.append(message)` — this is the hash chain append

If any verification check fails, `InvalidSignatureError` is raised at lines 168, 174, 180, or 185. The exception propagates immediately — Python does not execute subsequent lines after a `raise`. Line 202 (`transcript.append`) is unreachable on any rejection path.

I confirmed this with the test `TestStateUnchangedOnRejection.test_state_unchanged_on_forged_signature` (test file lines 230-269):
- Applies a valid OPEN message (transcript length = 1)
- Attempts a forged ACCEPT_SESSION message
- Asserts `InvalidSignatureError` raised
- Asserts `len(session.transcript) == transcript_len_before` (still 1)
- Asserts `session.state == state_before` (still PROPOSED)
- Asserts `session.round_count == round_count_before`

**Conclusion:** Forged messages are rejected before any transcript append or state transition. The hash chain cannot be poisoned by unsigned or mis-signed messages.

---

## 4. REGRESSION TESTS

**File:** `tests/test_session_signature_verification.py` (287 lines, 10 tests in 7 test classes)

### Tests present and verified:

| Required Test | Test Class/Method | Verified |
|---|---|---|
| (a) Valid signature accepted | `TestValidSignedMessageAccepted`: `test_full_negotiation_with_signatures` (end-to-end via Agent API) + `test_apply_message_with_valid_signature` (direct) | PASS |
| (b) Forged signature rejected before state change | `TestForgedSignatureRejected.test_tampered_signature_rejected` — flips 8 bytes of signature, asserts `InvalidSignatureError` with "Invalid signature" | PASS |
| (c) Missing signature rejected | `TestMissingSignatureRejected`: `test_no_signature_field` (del msg["signature"]) + `test_empty_signature_string` (msg["signature"] = "") | PASS |
| (d) Unknown agent_id rejected | `TestUnknownAgentRejected.test_unknown_agent_id_rejected` — "agent_unknown" not in resolver, asserts "Unknown agent identity" | PASS |

Additional tests beyond the minimum:
- `TestResolverReturningNone` — explicit null-resolver test (cluster contract)
- `TestWrongKeyRejected` — sign with key_a, verify with key_b
- `TestStateUnchangedOnRejection` — two tests: forged sig + missing from field, both verify state/transcript/round unchanged

### Full test suite:

```
469 passed in 0.47s
```

Independently executed. Baseline was 459. New count: 469 (+10 regression tests). No failures, no skips, no warnings.

**Verdict: PASS.**

---

## 5. SCOPE

**Question:** Does commit `7059089` touch exactly 6 files?

**Verdict: PASS.**

`git show --stat 7059089` output confirms exactly 6 files:

| File | Change |
|---|---|
| `SPRINT_CONTRACT.md` | 219 ++/-- |
| `SPRINT_RESULT.md` | 134 ++/-- |
| `concordia/__init__.py` | 3 ++/- |
| `concordia/agent.py` | 21 ++/- |
| `concordia/session.py` | 87 ++/-- |
| `tests/test_session_signature_verification.py` | 286 +++ (new file) |

6 files changed, 524 insertions, 226 deletions. No scope creep. No unrelated files modified.

---

## 6. NEW RISK: `InvalidSignatureError` EXPORT

**Question:** Does exporting `InvalidSignatureError` from `__init__.py` expose internal implementation details that could help an attacker craft bypass attempts?

**Verdict: PASS (no risk).**

`InvalidSignatureError` at `session.py:34-35`:
```python
class InvalidSignatureError(Exception):
    """Raised when a message has an invalid, missing, or unverifiable signature."""
```

This is a plain `Exception` subclass with no methods, no attributes, no internal state, and no reference to any cryptographic primitive. It is semantically identical to `InvalidTransitionError` (which was already exported). The class name and docstring reveal only that signature verification exists — which is a public API contract, not an implementation secret.

The error messages raised in `apply_message()` identify four failure modes: missing from.agent_id, missing signature, unknown identity (resolver returned None), and invalid signature. These messages help legitimate callers debug integration issues. They do not reveal: the signing algorithm, key lengths, canonical serialization format, or any internal verification logic. An attacker gains no advantage from knowing that invalid signatures are rejected — that is the expected behavior of any signature verification system.

For comparison, `InvalidTransitionError` already reveals that state transition validation exists. `InvalidSignatureError` reveals the same level of information about signature verification.

**Conclusion:** The export is safe. No internal implementation details are exposed.

---

## GRADE: PASS

The fix correctly addresses the SEC-010 root cause. Signature verification is mandatory on every code path through `apply_message()` — there is no bypass. The implementation conforms point-for-point to the SEC-005 cluster contract (required resolver, null = rejection, zero coupling to key storage). Forged messages are intercepted before any transcript append or state transition, preserving hash chain integrity. The regression tests cover all four required scenarios plus three additional edge cases. The commit scope is clean (exactly 6 files). The `InvalidSignatureError` export introduces no security risk.

No conditions. No follow-up required for this finding.

---

# SPRINT_EVAL.md — SEC-014: Independent QA Evaluation

**Date:** 2026-03-28
**Evaluator posture:** Skeptical QA — did not write this code, does not trust self-assessment.
**Finding:** SEC-014 — Concordia Attestation Signature Verification Is Optional
**Branch:** `security-review`

---

## 1. ROOT CAUSE

**Question:** The finding is that attestation signature verification was optional — a `None` default on `public_keys` silently skipped verification. Does the fix eliminate every optional or fallback path?

**Verdict: PASS.**

I read `AttestationStore.ingest()` (store.py:165-246) and `_validate()` (store.py:280-372) directly. The diff between `e60b711~1` and `e60b711` confirms:

**Deleted:** The entire "warn and skip" block (old lines 332-338) is gone. This was the code that emitted `"Signatures are present but public_keys not provided. Signature verification will be skipped."` and accepted the attestation anyway. It is not commented out, not behind a flag — it is deleted from the file.

**Deleted:** The old `public_keys: dict[str, Any] | None = None` optional parameter on both `ingest()` and `_validate()`. Replaced with `public_key_resolver: Callable[[str], Ed25519PublicKey | None]` — no default value.

**Deleted:** The conditional `elif public_keys:` branch that only verified signatures when the optional dict was provided. Replaced with unconditional verification: every party's signature is verified on every call.

I confirmed with `grep -rn "public_keys" concordia/reputation/store.py concordia/mcp_server.py` — zero hits. The old parameter name is gone entirely.

I confirmed with `grep -rn "Signature verification will be skipped" concordia/` — zero hits. The warning string is gone from the entire codebase.

The new verification logic (store.py:337-366) is unconditional:
1. For each party with a signature, call `public_key_resolver(agent_id)`.
2. If resolver returns `None` → `errors.append(...)` — hard rejection.
3. If `verify_signature()` returns `False` → `errors.append(...)` — hard rejection.
4. If verification raises exception → `errors.append(...)` — hard rejection.
5. No else, no fallback, no skip.

**Conclusion:** Every optional and fallback path is eliminated. Verification is unconditional.

---

## 2. CLUSTER CONTRACT CONFORMANCE

**Question:** Does SEC-014 conform to the established pattern from SEC-005 and SEC-010?

**Verdict: PASS.**

### 2a. `public_key_resolver` is a required parameter with no default value

At `store.py:168`:
```python
public_key_resolver: Callable[[str], Ed25519PublicKey | None],
```
At `store.py:283`:
```python
public_key_resolver: Callable[[str], Ed25519PublicKey | None],
```

No default value on either method. Calling `ingest(att)` without a resolver raises `TypeError`. This is confirmed by `test_ingest_requires_resolver_argument` (test_attestation_signature_verification.py:222-226), which asserts `pytest.raises(TypeError)`.

### 2b. Resolver returning `None` raises a hard error, not a warning

At `store.py:349-353`:
```python
if public_key is None:
    errors.append(
        f"Unknown agent identity '{agent_id}' — "
        "resolver returned None, signature cannot be verified"
    )
```

This is a hard error added to the errors list. When any error is present, `_validate()` returns `ValidationResult(valid=False, ...)` at line 368-372. Back in `ingest()`, line 184 returns `(False, validation)` — the attestation is rejected, never stored.

For comparison: SEC-010 uses `raise InvalidSignatureError(...)` — same effect (rejection), different mechanism (exception vs error accumulation). Both are contextually appropriate: SEC-010 validates a single message and fails immediately; SEC-014 validates multiple parties and accumulates all errors for diagnostic completeness. The net result is identical: unknown identities cause rejection.

### 2c. `AttestationStore` has zero coupling to any specific key store

I verified `store.py` imports:
- `from ..signing import KeyPair, verify_signature` — cryptographic primitives only
- `from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey` — type hint only
- `from typing import Any, Callable` — type hints only

No import of `AuthTokenStore`, session store, agent registry, or any storage module. The `public_key_resolver` callback is the sole key access mechanism, injected by the caller.

In `mcp_server.py`, the resolver (`_resolve_attestation_key`, lines 795-802) looks up keys from the session store's `SessionContext`. This wiring is in the MCP layer, not in `AttestationStore` — the store itself remains completely agnostic about where keys come from.

**Conclusion:** All three cluster contract requirements are met.

---

## 3. REPUTATION INTEGRITY

**Question:** Does the fix intercept forged attestations before they reach the scoring path — before any reputation update occurs?

**Verdict: PASS.**

I traced the execution path in `ingest()`:

1. **Line 183:** `validation = self._validate(attestation, public_key_resolver)` — signature verification happens here.
2. **Line 184-185:** If `not validation.valid`, return `(False, validation)` immediately.
3. **Lines 190-209:** Deduplication and capacity checks — only reachable if validation passed.
4. **Lines 211-217:** Sybil detection — only reachable if validation passed.
5. **Lines 219-244:** Store the attestation (update indexes) — only reachable if validation passed.

An attestation with a forged or unverifiable signature fails at step 1-2. It never reaches:
- The `_by_id` dict (primary storage, line 233)
- The `_by_agent` index (agent lookup, line 237)
- The `_counterparties` index (Sybil data, line 241)
- The Sybil detection engine (line 213)

The scoring engine (`concordia/reputation/scorer.py`) reads from `AttestationStore.get_by_agent()` — which queries `_by_id` via `_by_agent`. Since forged attestations never enter `_by_id`, they cannot influence scores.

Confirmed by `test_store_unchanged_on_rejection` (test_attestation_signature_verification.py:185-202): after ingesting one valid attestation and then attempting a forged one, `store.count() == 1`, `store.agent_count("agent_alpha") == 1`, `store.agent_count("agent_beta") == 1`. The forged attestation left no trace.

**Conclusion:** Forged attestations are rejected before any storage or scoring path. Reputation manipulation via fake signatures is no longer possible.

---

## 4. EXISTING TEST UPDATES

**Question:** Were existing tests updated to use properly-signed attestations, or were they deleted/skipped to make the suite pass?

**Verdict: PASS.**

I ran `git diff e60b711~1..e60b711 -- tests/test_reputation.py | grep "^-.*def test_"` — zero output. No test functions were deleted from `test_reputation.py`.

I ran `git diff e60b711~1..e60b711 -- tests/test_security.py | grep "^-.*def test_"` — zero output. No test functions were deleted from `test_security.py`.

I checked for `@pytest.mark.skip`, `@pytest.mark.xfail`, and `skip()` calls across all test files — none found (the only `skip` references are in `test_sanctuary_bridge.py` for the unrelated `BridgeResult.skipped_reason` field and in the SEC-014 regression test that verifies the old skip-warning path is gone).

The diff for `test_reputation.py` shows the `_make_attestation()` helper was rewritten to produce properly-signed attestations using real Ed25519 key pairs via a `_KEY_REGISTRY` and `_get_key()` helper. A `_test_resolver()` function was added. All `store.ingest(att)` calls were updated to `store.ingest(att, _test_resolver)`. The test functions themselves — their names, their assertions, their coverage — are preserved.

The diff for `test_security.py` shows helpers `_sec_get_key()`, `_sec_resolver()`, `_sec_null_resolver()`, and `_make_signed_att()` were added. Existing tests were updated to pass resolvers. No test logic was removed.

Full suite independently executed:

```
479 passed in 0.50s
```

Baseline: 469. New count: 479 (+10 regression tests). No regressions, no skips, no failures.

**Conclusion:** All existing tests were updated, not deleted or skipped. The suite passes at 479/479.

---

## 5. SCOPE

**Question:** Does commit `e60b711` touch only the expected files?

**Verdict: PASS.**

`git show --stat e60b711` confirms 7 files:

| File | Change |
|---|---|
| `SPRINT_CONTRACT.md` | 124 ++/-- |
| `SPRINT_RESULT.md` | 85 ++/-- |
| `concordia/mcp_server.py` | 21 ++/- |
| `concordia/reputation/store.py` | 80 ++/-- |
| `tests/test_attestation_signature_verification.py` | 263 +++ (new file) |
| `tests/test_reputation.py` | 213 ++/-- |
| `tests/test_security.py` | 142 ++/-- |

7 files changed, 662 insertions, 266 deletions.

Expected files: `store.py` (core fix), `mcp_server.py` (resolver wiring), new regression test file, updated existing test files, sprint contract, sprint result. All present. No unexpected files. No scope creep.

---

## 6. CLUSTER CLOSURE

**Question:** Across SEC-005, SEC-010, and SEC-014, is the resolver pattern consistent?

**Verdict: PASS.**

| Requirement | SEC-005 (Sanctuary TS) | SEC-010 (session.py) | SEC-014 (store.py) |
|---|---|---|---|
| Parameter name | `public_key_resolver` | `public_key_resolver` | `public_key_resolver` |
| Callback signature | `(id) => Key \| null` | `Callable[[str], Ed25519PublicKey \| None]` | `Callable[[str], Ed25519PublicKey \| None]` |
| Mandatory (no default) | Yes (by contract) | Yes — no default | Yes — no default |
| Null → rejection | Yes (by contract) | `raise InvalidSignatureError` | `errors.append` + reject |
| Invalid sig → rejection | Yes | `raise InvalidSignatureError` | `errors.append` + reject |
| Key store coupling | Zero | Zero | Zero |

The error reporting mechanism differs between SEC-010 (exceptions) and SEC-014 (error accumulation), but this is contextually appropriate: SEC-010 validates a single message and fails fast; SEC-014 validates multiple parties and collects all errors. The net effect — rejection, no state change, no fallback — is identical in both.

The SEC-005 SPRINT_EVAL.md established the three requirements (mandatory resolver, null = rejection, zero coupling). SEC-010's evaluation confirmed conformance. SEC-014 meets all three requirements identically.

**Conclusion:** The signature verification cluster is consistent across all three implementations. No inconsistencies found. The cluster is closed.

---

## GRADE: PASS

The fix correctly addresses the SEC-014 root cause. The old "warn and skip" path is fully deleted — not commented out, not behind a flag. The `public_key_resolver` is mandatory on both `ingest()` and `_validate()` with no default value. Resolver returning `None` produces a hard rejection. Forged attestations are intercepted before any storage or scoring path, eliminating the reputation manipulation attack. All existing tests were updated (none deleted or skipped). The suite passes at 479/479. The commit touches exactly 7 expected files with no scope creep. The resolver pattern is consistent across all three cluster findings (SEC-005, SEC-010, SEC-014).

No conditions. No follow-up required. This closes the signature verification cluster.
