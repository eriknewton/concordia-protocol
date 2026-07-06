# Security Policy

Concordia is trust infrastructure for autonomous agents, so we take security
reports seriously and welcome responsible disclosure of vulnerabilities.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue
for a security problem.

- **Preferred:** open a private advisory through GitHub's
  [Security Advisories](https://github.com/eriknewton/concordia-protocol/security/advisories/new)
  on this repository. This keeps the report confidential until a fix is ready.
- If you cannot use GitHub Security Advisories, contact the maintainer,
  [Erik Newton](https://github.com/eriknewton), through GitHub, or by email at
  eriknewton@gmail.com.

Please include enough detail for us to reproduce and assess the issue:

- Affected version, package, and component
- A description of the vulnerability and its impact, including what an attacker
  could do
- Steps to reproduce, or a proof of concept
- Suggested remediation, if you have one
- Whether you intend to publish; we will coordinate disclosure timing

If you email and do not receive an acknowledgment within the window below,
please follow up. The first message may have been filtered.

## Disclosure timeline

We aim to keep you informed at every stage and to move quickly:

- **Acknowledge:** within **2 business days** of receiving your report.
- **Triage:** within **5 business days** we confirm the issue, assess severity,
  and tell you whether it is in scope.
- **Fix and release:** we ship a fix or mitigation as fast as the severity
  warrants. We target **30 days** for high-severity issues and move faster for
  critical ones; lower-severity issues are batched into the next release.
- **Public advisory:** we publish a GitHub Security Advisory once a patched
  version is available and has reached reasonable adoption.

### Handling steps

For each valid report we follow the same path:

1. **Acknowledge** the report and open a private advisory thread with you.
2. **Triage:** reproduce, confirm severity, and identify affected versions.
3. **Fix:** develop and test a patch privately, with regression coverage.
4. **Release:** cut a patched version and publish the package.
5. **Advisory:** publish a public GitHub Security Advisory crediting the
   reporter (with permission) once the fix is available.

## Coordinated disclosure

We follow a **90-day coordinated-disclosure** timeline by default: acknowledge,
triage, fix, release, then public advisory after the patched version reaches
reasonable adoption, typically 14 to 30 days post-release. If you would like a
different timeline, such as a faster public advisory for a high-severity issue,
let us know in your report and we will align.

## Researcher credit

We are happy to credit security researchers who responsibly disclose
vulnerabilities. If you would like public credit, tell us in your report and we
will name you in the advisory and release notes. We will not name a researcher
without explicit permission.

## Scope

This policy covers the Concordia Protocol Python SDK and MCP server, the
JavaScript SDK, and the published packages (`concordia-protocol` on PyPI and
`@concordia-protocol/sdk` on npm).

In scope:

- Cryptographic implementation correctness, including signature verification,
  canonical JSON serialization, hash-chain integrity, and predicate or mandate
  validation
- Authentication, authorization, and trust-boundary handling across the
  negotiation, attestation, and mandate flows
- Data exposure beyond the documented surfaces, including any leak of raw deal
  terms through an attestation
- Resource-exhaustion and denial-of-service paths reachable through the public
  API or schema validators

Out of scope:

- Findings against forks or third-party deployments
- Theoretical attacks without a reproduction or proof of concept
- Social engineering against the maintainer
- Findings already publicly disclosed; cross-reference the CVE or advisory
- Best-practice recommendations without a concrete exploit path

Issues in third-party dependencies should be reported to the relevant upstream
project. If a dependency issue affects Concordia users, we still want to hear
about it so we can audit our usage and pin a patched version.

## Supported versions

Concordia is pre-1.0 and under active development. Security fixes are applied to
the latest released version. Pin to a known-good release and upgrade promptly
when a security release is published.
