# @concordia-protocol/sdk

TypeScript reference implementation of the Concordia Protocol -- signed
agreement primitives for autonomous agents.

Status: alpha. Currently ships the canonical JSON serializer, the Ed25519
signing layer (key generation, sign, and verify over canonical JSON), the
foundational types layer (session, message, term, and outcome enumerations plus
the core data structures and their serialization), and the v0.6 signed
predicate primitive (sign, verify, write-validation, and the type-profile
deterministic-semantics gate), all with byte-level parity against the Python
reference implementation. Remaining primitives (mandate, attestation,
session-receipt, lifecycle) ship in subsequent alpha releases.

Apache-2.0. Spec at https://github.com/eriknewton/concordia-protocol.
