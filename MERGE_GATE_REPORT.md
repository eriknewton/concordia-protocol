# MERGE_GATE_REPORT.md — Concordia Protocol

**Date:** 2026-03-28
**Branch:** `security-review`
**Evaluator posture:** Merge gate — final verification before PR to main
**Repo:** concordia-protocol (`~/Desktop/Claude/concordia`)
**Run:** Re-run (previous gate FAIL on SEC-022/SEC-ADD-04 — now resolved at commit `7b294f4`)

---

## VERDICT: PASS

All Critical and High findings have reached PASS in SPRINT_EVAL.md. No open CONDITIONAL PASS conditions. Test suite passes at 518/518. The security-review branch is ready for a PR to main.

---

## 1. Critical and High Findings — Status

### Critical Findings

| ID | Title | Fix Commit | Eval Commit | PASS in SPRINT_EVAL.md | Fix in git log |
|----|-------|-----------|-------------|----------------------|----------------|
| SEC-007 | Zero caller authentication | 1ca20f3 + 0db7992 | 199a374 | ✅ PASS | ✅ Confirmed |

### High Findings — Code Fixes (All PASS)

| ID | Title | Fix Commit | Eval Commit | PASS in SPRINT_EVAL.md | Fix in git log |
|----|-------|-----------|-------------|----------------------|----------------|
| SEC-010 | Session state machine never verifies signatures | 7059089 | 3a8b1fa | ✅ PASS | ✅ Confirmed |
| SEC-014 | Attestation signature verification is optional | e60b711 | 36ba089 | ✅ PASS | ✅ Confirmed |
| HP-16 | relay_transcript unauthenticated access | 828979b | 8cfc24b | ✅ PASS | ✅ Confirmed |
| HP-17 | relay_conclude unauthenticated access | 828979b | 8cfc24b | ✅ PASS | ✅ Confirmed |
| SEC-003 | Canonical JSON divergence (cross-repo) | bc615ad | 6355808 → 40bb64b | ✅ PASS (condition closed) | ✅ Confirmed |
| SEC-ADD-01 | Output tagging for counterparty data | c2dea70 + 600eb48 | 7d7ca3f → 40bb64b | ✅ PASS (condition closed) | ✅ Confirmed |
| SEC-ADD-02 | Input sanitization for negotiation terms | c2dea70 + 600eb48 | 7d7ca3f → 40bb64b | ✅ PASS (condition closed) | ✅ Confirmed |
| SEC-022 | No lockfile — all dependencies unpinned | b647cae | 7b294f4 | ✅ PASS | ✅ Confirmed |

### High Findings — Collateral Closures (All Verified)

| ID | Title | Closed By | Evaluator Verified | Closure Genuine |
|----|-------|-----------|--------------------|-----------------|
| SEC-008 | Deregistration ownership bypass | SEC-007 auth layer | ✅ SPRINT_EVAL.md §4 | ✅ `validate_agent_token` at mcp_server.py:1213 gates deregistration |
| SEC-009 | Relay message interception | SEC-007 auth layer | ✅ SPRINT_EVAL.md §4 | ✅ `validate_agent_token` at mcp_server.py:1857 gates relay_receive |
| SEC-015 | Want/Have registry manipulation | SEC-007 auth layer | ✅ SPRINT_EVAL.md §4 | ✅ `validate_agent_token` at mcp_server.py:1332, 1449, 1503 gates want/have tools |

All three collateral closures are natural consequences of the SEC-007 authentication layer. Each was independently verified by the SEC-007 evaluator with specific line references. Auth gates confirmed at cited locations — 18 total `validate_agent_token` calls across identity-dependent tools.

### Previously Open — Now Resolved

| ID | Title | Previous Status | Resolution |
|----|-------|----------------|------------|
| SEC-022 | No lockfile — all dependencies unpinned | ❌ No PASS evaluation | ✅ PASS — `requirements.lock` with 38 pinned deps, `cryptography==46.0.6` (no CVEs), eval at `7b294f4` |
| SEC-ADD-04 | Dependency CVE status unconfirmable | ❌ Compounded SEC-022 | ✅ Resolved — lockfile enables CVE verification; pip-audit run confirmed no critical CVEs in production deps |

---

## 2. CONDITIONAL PASS Status

No open CONDITIONAL PASS conditions remain:

| Finding | Original Grade | Conditions | Resolution |
|---------|---------------|------------|------------|
| SEC-007 | CONDITIONAL PASS | (1) Revocation test, (2) Relay gaps tracked | Both resolved — commit 0db7992, upgraded to PASS at eval 199a374 |
| SEC-003 | CONDITIONAL PASS | SEC-ADD-03 bundled in Sanctuary commit acknowledged | Resolved — logged in COWORK_CONTEXT.md, upgraded to PASS |
| SEC-ADDENDUM | CONDITIONAL PASS | (1) Delimiter injection, (2) Missing Sanctuary tags, (3) Sanctuary tests | All three resolved — commits 600eb48 (Concordia) + condition closure (Sanctuary), upgraded to PASS at eval 40bb64b |

---

## 3. Test Suite

**Start of review:** 441 tests
**End of review:** 518 tests (+77)
**Current run:** 518 passed in 0.54s — 0 failed, 0 skipped

Test count meets baseline. No regressions.

Test growth by sprint:

| Sprint | Tests Added | Running Total |
|--------|------------|---------------|
| SEC-007 | +17 | 458 |
| SEC-007 conditions | +1 | 459 |
| SEC-010 | +10 | 469 |
| SEC-014 | +10 | 479 |
| HP-16/HP-17 | +4 | 483 |
| SEC-003 | +34 | 517 |
| SEC-ADDENDUM | +1 (condition closure) | 518 |
| SEC-022 | +0 (lockfile — no new code tests) | 518 |

---

## 4. Collateral Closure Audit

Three findings were closed as collateral from the SEC-007 authentication layer:

**SEC-008 (Deregistration ownership bypass):** Root cause was `concordia_deregister_agent` accepting any `agent_id` without ownership verification. The SEC-007 fix adds `auth_token` validation at the first executable line of the handler. A caller must present the token issued at registration. The evaluator verified this directly and a dedicated test (`TestDeregisterAuth`) confirms cross-agent deregistration is rejected. **Genuine closure.**

**SEC-009 (Relay message interception):** Root cause was `concordia_relay_receive` returning messages to any caller claiming an `agent_id`. The SEC-007 fix gates this with `validate_agent_token`. `TestRelayAuth.test_relay_receive_rejects_wrong_agent` explicitly tests this scenario. **Genuine closure.**

**SEC-015 (Want/Have registry manipulation):** Root cause was `post_want`, `post_have`, `withdraw_want`, `withdraw_have` accepting unverified `agent_id`. All four tools are now gated. `TestWantAuth` verifies cross-agent withdrawal is rejected. **Genuine closure.**

All three closures were prospectively identified in REMEDIATION_PLAN.md before the SEC-007 sprint.

---

## 5. Evaluator Parking Lot

Non-blocking observations logged across evaluations:

| Observation | Source | Tracked |
|-------------|--------|---------|
| Session tokens have no revocation mechanism | SEC-007 eval | ✅ Noted as acceptable for v0.1.0 |
| `sanctuary_bridge_commit` and `sanctuary_bridge_attest` operate without auth | SEC-007 eval | ✅ Lower-severity; bridge payloads independently verified by Sanctuary |
| No token rotation mechanism | SEC-007 eval | ✅ Noted as acceptable for v0.1.0 |
| `open_session` allows sessions between arbitrary agent IDs | SEC-007 eval | ✅ By design — Sybil detector is defense |
| `relay_status`, `relay_archive`, `relay_list_archives` lack auth | HP-16/HP-17 eval | ✅ Noted as lower-severity follow-ups |
| `reputation_export` is Tier 3 while `state_export` is Tier 1 | SEC-001 eval (Sanctuary) | ✅ Logged in COWORK_CONTEXT.md parking lot |
| `pygments==2.19.2` CVE-2026-4539 (dev dependency, no fix available) | SEC-022 eval | ✅ Non-blocking; dev-only, no production impact |

All parking lot items are either accepted as design decisions for v0.1.0 or logged for future hardening. None are blocking.

---

## 6. Open Items Carried Forward (Not Blocking Merge)

| Item | Rationale for Non-Block |
|------|------------------------|
| SEC-ADD-04 residual: `pygments` CVE in dev deps | Dev-only dependency; no fix version available; does not affect production |
| Medium findings (SEC-004, SEC-006, SEC-013, SEC-017, SEC-021) | Per merge gate criteria, only Critical and High are blocking |
| Low/Informational findings (SEC-018, SEC-023, SEC-024) | Tracked in hardening queue |

---

## 7. Summary

| Category | Result |
|----------|--------|
| Critical findings with PASS | 1/1 ✅ |
| High findings with PASS (code fixes) | 8/8 ✅ |
| High findings with PASS (collateral) | 3/3 ✅ |
| High findings OPEN | 0 ✅ |
| Open CONDITIONAL PASS conditions | 0 ✅ |
| Test count vs baseline | 518 ≥ 441 ✅ |
| Parking lot items tracked | All ✅ |
| **MERGE GATE** | **PASS** |

The security-review branch has successfully addressed all Critical and High-severity vulnerabilities identified in the audit. The previous gate blocker (SEC-022/SEC-ADD-04 — missing Python lockfile) is resolved: `requirements.lock` pins all 38 production and transitive dependencies, `cryptography==46.0.6` has no known CVEs, and pip-audit confirms no critical findings in the production dependency graph. The branch is ready for a PR to main.
