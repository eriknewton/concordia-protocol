# Concordia Implementations Registry

This registry records reported Concordia conformance runner runs and single-record recomputes. A row is a measurement with a linkable method and date. It does not approve, rank, or endorse an implementation.

## Implementations

| Implementation | Language | Author | Scope | Result | Method | Date | Link |
|---|---|---|---|---|---|---|---|
| Concordia reference runner, first-party | Python | Erik Newton | runner | `[SUMMARY] positive=47 mutation=1460 canary=4 ok=1511 fail=0` | Clean-room runner over `conformance/vectors/manifest.json` using RFC 8785, PyNaCl, JSON Schema, and the Python standard library. Reported result reads no `conformance/diag/`. | 2026-08-02 | [`conformance/reference-runner/runner.py`](reference-runner/runner.py) |
| Concordia reference runner JS, first-party | Node.js | Erik Newton | runner | `[SUMMARY] positive=47 mutation=1460 canary=4 ok=1511 fail=0` | Runner over `conformance/vectors/manifest.json` using Node.js, `node:crypto`, and Ajv draft 2020-12. Reported result reads no `conformance/diag/`. | 2026-08-02 | [`conformance/reference-runner-js/runner.mjs`](reference-runner-js/runner.mjs) |
| AgentID (`haroldmalikfrimpong-ops`) | Not reported | AgentID (`haroldmalikfrimpong-ops`) | single-record recompute | FulfillmentAttestation digest matched `sha256:47ec4298e210d3aa18832b30f8cc087b84bfebf1f664eced187918de085bf508`; Ed25519 signature valid; tamper rejected; privacy shape held; `charge_ref` byte-matched. | Third-party RFC 8785 JCS over the attestation minus `signature`, then SHA-256 and Ed25519 verify against `public_key_b64url`. | 2026-07-20 | [A2A #1920 comment 17706287](https://github.com/a2aproject/A2A/discussions/1920#discussioncomment-17706287) |

The two first-party runner rows execute the same manifest to the same summary line. Divergence count: 0 vectors.

## Start Here

`decision-object-v1` is the smallest profile: RFC 8785 JCS plus SHA-256. It is roughly 20 lines in most languages. Add profiles one at a time against the vectors.

## How To Get Listed

Run the full suite or a clearly named subset with your own runner. Publish the summary line and method somewhere linkable, including whether the run read `conformance/diag/` before producing its result. Then open an implementation report with the GitHub issue template.

First-party rows are labeled as first-party. Other rows should name the author, covered profiles, method, date, and result. A registry row records what was measured at that link on that date.
