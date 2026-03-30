# Known Issues

This file summarizes open items tracked from the security review conducted in March 2026.
All items are logged in detail in `REMEDIATION_PLAN.md` on the `security-review` branch.

## Security Posture

All Critical and High security findings from the March 2026 audit have been resolved and
independently evaluated. The merge gate was passed with 518/518 tests passing (+77 regression
tests added during the review).

## Open Items

### Hardening Items (REMEDIATION_PLAN.md Section 4)

- ~~**SEC-ADD-04** — Automated CVE scanning~~ — RESOLVED: pip-audit added to CI (commit `2487873`), CVE-2026-4539 ignored (commit `870ec2f`)
- ~~**Relay tool auth gaps (H-16 through H-18)**~~ — RESOLVED: auth gates added to `relay_status`, `relay_archive`, `relay_list_archives` with participant verification
- ~~**Bridge tool auth gaps (H-19 through H-21)**~~ — RESOLVED: auth gates added to `sanctuary_bridge_configure`, `sanctuary_bridge_commit`, `sanctuary_bridge_attest`
- **`pygments` dev dependency** — CVE-2026-4539, no fix available. pip-audit ignores this CVE in CI.

## Signature Verification Architecture

New tools processing agent-signed data should follow the mandatory resolver pattern established
in SEC-005/SEC-010/SEC-014: mandatory `public_key_resolver` callback, null return = hard
rejection, zero coupling to key storage. See `concordia/auth.py` for reference.

## Contributing

If you discover a security issue not listed here, please open a private security advisory
on GitHub rather than a public issue.
