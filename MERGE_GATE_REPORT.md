# MERGE_GATE_REPORT.md — Concordia Protocol

**Date:** 2026-03-28
**Branch:** `security-review`
**Evaluator posture:** Merge gate — final verification before PR to main
**Repo:** concordia-protocol (`~/Desktop/Claude/concordia`)

---

## VERDICT: FAIL

Two High-severity findings (SEC-022, SEC-ADD-04) have no PASS evaluation. All other Critical and High findings pass. See Section 6 for the specific remediation required before re-running the gate.

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

### High Findings — Collateral Closures (All Verified)

| ID | Title | Closed By | Evaluator Verified | Closure Genuine |
|----|-------|-----------|--------------------|-----------------|
| SEC-008 | Deregistration ownership bypass | SEC-007 auth layer | ✅ SPRINT_EVAL.md §4 | ✅ `validate_agent_token` at mcp_server.py:1213 gates deregistration |
| SEC-009 | Relay message interception | SEC-007 auth layer | ✅ SPRINT_EVAL.md §4 | ✅ `validate_agent_token` at mcp_server.py:1857 gates relay_receive |
| SEC-015 | Want/Have registry manipulation | SEC-007 auth layer | ✅ SPRINT_EVAL.md §4 | ✅ `validate_agent_token` at mcp_server.py:1332, 1449, 1503 gates want/have tools |

All three collateral closures are natural consequences of the SEC-007 authentication layer. Each was independently verified by the SEC-007 evaluator with specific line references. I confirmed the auth gates exist at the cited locations via grep — 18 total `validate_agent_token` calls across identity-dependent tools.

### High Findings — OPEN (No PASS)

| ID | Title | Status | Location |
|----|-------|--------|----------|
| SEC-022 | Concordia has no lockfile — all dependencies unpinned | ❌ No PASS evaluation | REMEDIATION_PLAN.md H-08 (hardening queue) |
| SEC-ADD-04 | Dependency CVE status unconfirmable due to missing lockfile | ❌ No PASS evaluation | REMEDIATION_PLAN.md H-08 (compounds SEC-022) |

**SEC-022 / SEC-ADD-04 analysis:** These findings are about the absence of a Python lockfile (`requirements.txt`, `poetry.lock`, or `uv.lock`). Without a lockfile, `pip install` on different dates resolves different dependency versions, making builds non-reproducible and CVE status unverifiable. The finding is classified High in SECURITY_AUDIT.md because the `cryptography` library (Ed25519 implementation) is unpinned. REMEDIATION_PLAN.md places this in Section 4 (H-08, hardening queue) as an operational/tooling fix rather than a code vulnerability — but the merge gate criteria require all High findings to reach PASS regardless of fix category.

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
**Current run:** 518 passed in 0.55s — 0 failed, 0 skipped

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

All parking lot items are either accepted as design decisions for v0.1.0 or logged for future hardening. None are blocking.

---

## 6. Items Required Before Re-Running Gate

**SEC-022 / SEC-ADD-04 — Generate a Python lockfile for Concordia.**

To resolve both findings:
1. Generate a lockfile pinning exact dependency versions (e.g., `pip freeze > requirements.txt`, or use `uv lock` / `poetry lock`)
2. Verify the pinned `cryptography` version has no open CVEs
3. Commit the lockfile to `security-review`
4. Run an evaluator session confirming the lockfile exists, pins all direct and transitive dependencies, and the pinned versions are free of known CVEs

Estimated effort: Small (< 2 hours). This is an operational fix, not a code change.

**Alternative path:** If SEC-022 is formally reclassified to Medium (with documented rationale that the in-memory-only, pre-production nature of Concordia v0.1.0-draft mitigates the supply chain risk), the gate can PASS without the lockfile. This reclassification must be logged in both SECURITY_AUDIT.md and REMEDIATION_PLAN.md.

---

## 7. Summary

| Category | Result |
|----------|--------|
| Critical findings with PASS | 1/1 ✅ |
| High findings with PASS (code fixes) | 7/7 ✅ |
| High findings with PASS (collateral) | 3/3 ✅ |
| High findings OPEN | 2 (SEC-022, SEC-ADD-04) ❌ |
| Open CONDITIONAL PASS conditions | 0 ✅ |
| Test count vs baseline | 518 ≥ 441 ✅ |
| Parking lot items tracked | All ✅ |
| **MERGE GATE** | **FAIL** |

The security-review branch has successfully addressed all code-level Critical and High vulnerabilities. The sole blocking issue is the absence of a Python lockfile (SEC-022 + SEC-ADD-04), which is an operational/tooling gap rather than a code vulnerability. Resolution requires either generating a lockfile or formally reclassifying SEC-022 to Medium with documented rationale.
