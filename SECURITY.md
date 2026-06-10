# Security Policy

Concordia is trust infrastructure for autonomous agents, so we take security
reports seriously and want to make them easy to file.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue
for a security problem.

- **Preferred:** open a private advisory through GitHub's
  [Security Advisories](https://github.com/eriknewton/concordia-protocol/security/advisories/new)
  on this repository. This keeps the report confidential until a fix is ready.
- If you cannot use GitHub Security Advisories, contact the maintainer,
  [Erik Newton](https://github.com/eriknewton), through GitHub.

Please include enough detail to reproduce: affected version, a description of
the issue, and a proof of concept if you have one.

## What to expect

- We aim to acknowledge a report within a few business days.
- We will work with you on a fix and coordinate a disclosure timeline.
- With your permission, we will credit you when the fix is published.

## Scope

This policy covers the Concordia Protocol Python SDK and MCP server, the
JavaScript SDK, and the published packages
(`concordia-protocol` on PyPI). Issues in third-party dependencies should be
reported to the relevant upstream project; if a dependency issue affects
Concordia users, we still want to hear about it.

## Supported versions

Concordia is pre-1.0 and under active development. Security fixes are applied
to the latest released version. Pin to a known-good release and upgrade
promptly when a security release is published.
