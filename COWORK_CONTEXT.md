# COWORK_CONTEXT.md — Concordia Protocol Project State

**Branch:** `main`
**Last updated:** 2026-03-29

---

## Security Review — COMPLETE

All Critical and High security findings PASS. Merged `security-review` -> `main` via PR #1.

| ID | Title | Grade |
|----|-------|-------|
| SEC-007 | Zero caller authentication on MCP endpoints | PASS |
| SEC-010 | Signature verification bypass in session state machine | PASS |
| SEC-014 | Attestation signature verification optional | PASS |
| HP-16 + HP-17 | Missing auth_token on relay_transcript / relay_conclude | PASS |
| SEC-003 | Canonical JSON for cross-repo signature verification | PASS |
| SEC-ADDENDUM | Prompt injection defenses | PASS |
| SEC-022 | Concordia has no lockfile — all dependencies unpinned | PASS |
| SEC-ADD-04 | Automated CVE scanning in CI | PASS |

**Merge gate:** PASS (commit `823bfdd`)

---

## Current State (2026-03-29)

**Version:** 0.1.0 (pre-release)
**Tests:** 587 passing
**CI:** Fix pushed for pip-audit CVE ignore (commit `870ec2f`)

### Recent changes (this session)

- **Auth gates added (H-16 through H-21):** All six hardening items resolved:
  - H-16: `relay_status` — now requires agent_id + auth_token, verifies participant
  - H-17: `relay_archive` — now requires agent_id + auth_token, verifies participant
  - H-18: `relay_list_archives` — now requires agent_id + auth_token, scoped to caller's sessions
  - H-19: `bridge_configure` — now requires agent_id + auth_token
  - H-20: `bridge_commit` — now requires session-scoped auth_token
  - H-21: `bridge_attest` — now requires agent_id + auth_token, verifies caller is attestation party
- **8 new regression tests** added for auth rejection cases
- **CI fix:** pip-audit now ignores CVE-2026-4539 (pygments, no fix available)

---

## Open Items

- **pygments CVE-2026-4539** — dev dependency, no fix version available. Tracked in KNOWN_ISSUES.md and GitHub issue #4. pip-audit ignores it in CI.
- **PyPI publish** — pip publish pipeline is built but package not yet published. Needs trusted publisher configured on pypi.org.
- **Plugin marketplace** — Plugin skeleton exists in `plugin/` but not submitted.

---

## Test Baseline

| Milestone | Test count |
|-----------|-----------|
| Audit start | 441 |
| Post-audit | 518 |
| Post-four-stage build | 579 |
| Post-auth-gates | 587 |
