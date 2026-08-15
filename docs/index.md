# Concordia documentation index

A table of contents for the Concordia Protocol documentation. The `docs/`
directory holds the deep-dive and reference material; the repository root holds
the spec, the governance files, and the contributor entry points.

## Start here

| Document | What it covers |
| --- | --- |
| [README](../README.md) | What Concordia is, the negotiation lifecycle, and how to install both SDKs. |
| [SPEC](../SPEC.md) | The normative protocol specification: messages, signing, attestations, mandates, and predicates. |
| [Assurance matrix](../ASSURANCE_MATRIX.md) | Generated, evidence-bounded status for agreement integrity, authority, voluntariness, justice, payload confidentiality, and metadata privacy. |
| [CONTRIBUTING](../CONTRIBUTING.md) | How to set up the repo, run the tests, and open a change. |
| [AGENTS](../AGENTS.md) | Repository guide for AI coding agents working in this codebase. |
| [Interop vectors](interop/) | Runnable worked vectors for the artifact-identity and verification path. Each ships the fixture bytes, a deterministic generator, and a `verify.py` that checks the vector offline against those bytes, so a second implementer can check a record's identity with an independent RFC 8785 JCS library and no Concordia code. The conformance levels themselves are defined in [SPEC §12](../SPEC.md#12-conformance-requirements). |

## Reference and deep dives (this directory)

| Document | What it covers |
| --- | --- |
| [A2A composition](A2A_COMPOSITION.md) | How Concordia composes with the A2A agent-to-agent protocol. |
| [A2CN fulfillment](A2CN_FULFILLMENT.md) | The A2CN fulfillment-attestation flow and dispute-resolution adapter. |
| [Assurance roadmap](ASSURANCE_ROADMAP.md) | Generated proof backlog and dependencies for the six assurance dimensions. |
| [Claim vocabulary](CLAIM_VOCABULARY.md) | Generated definitions that keep signatures, authority, voluntariness, justice, confidentiality, and metadata privacy distinct. |
| [Conformance claims](CONFORMANCE.md) | Generated executable-claim status sourced from `docs/claims.yaml`. |
| [Conformance implementations](../conformance/IMPLEMENTATIONS.md) | Registered first-party runners and the bounded external reproduction record. |
| [Efficiency report deployment](EFFICIENCY_REPORT_DEPLOYMENT.md) | Deployment notes for the efficiency-reporting surface. |
| [CMPC revocation](cmpc_revocation.md) | The CMPC revocation model for mandates and credentials. |
| [Revocation resolver](revocation_resolver.md) | The injectable revocation-resolver hook and its contract. |
| [v0.6 migration](v0.6_migration.md) | Migration guide for the v0.6 release. |
| [v0.6 predicate primitive](v0.6_predicate_primitive.md) | The signed-predicate primitive introduced in v0.6. |

## Governance and security

| Document | What it covers |
| --- | --- |
| [SECURITY](../SECURITY.md) | How to report a vulnerability, the disclosure timeline, and supported versions. |
| [Code of Conduct](../CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 community standards and enforcement. |
| [CODEOWNERS](../.github/CODEOWNERS) | Routes review requests and signals ownership; merges are gated on required status checks, not on required review. |
| [LICENSE](../LICENSE) | Apache License, Version 2.0. |
| [NOTICE](../NOTICE) | Apache-2.0 Section 4(d) attribution notice. |
| [CHANGELOG](../CHANGELOG.md) | Release history for the Python SDK and MCP server. |

## JavaScript SDK

| Document | What it covers |
| --- | --- |
| [js-sdk README](../js-sdk/README.md) | Install, quickstart, and the public API surface of `@concordia-protocol/sdk`. |
| [js-sdk CHANGELOG](../js-sdk/CHANGELOG.md) | Release history for the TypeScript SDK. |
