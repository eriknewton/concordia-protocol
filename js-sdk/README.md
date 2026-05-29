# @concordia-protocol/sdk

TypeScript reference implementation of the Concordia Protocol -- signed
agreement primitives for autonomous agents.

Status: alpha. Currently ships the canonical JSON serializer and the Ed25519
signing layer (key generation, sign, and verify over canonical JSON), both
with byte-level signature parity against the Python reference implementation.
Remaining primitives (mandate, predicate, attestation, session-receipt) ship
in subsequent alpha releases.

Apache-2.0. Spec at https://github.com/eriknewton/concordia-protocol.
