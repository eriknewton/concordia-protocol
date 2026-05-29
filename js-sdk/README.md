# @concordia-protocol/sdk

TypeScript reference implementation of the Concordia Protocol -- signed
agreement primitives for autonomous agents.

Status: alpha. Currently ships the canonical JSON serializer, the Ed25519
signing layer (key generation, sign, and verify over canonical JSON), the
foundational types layer (session, message, term, and outcome enumerations plus
the core data structures and their serialization), the v0.6 signed
predicate primitive (sign, verify, write-validation, and the type-profile
deterministic-semantics gate), the mandate credential models (the
`TemporalMode` / `MandateStatus` enumerations, the `DelegationLink`,
`ValidityWindow`, and `Mandate` data structures with their serialization, and
the mandate JSON-schema constants), the mandate verification engine (mandate
and delegation signing, schema and constraint validation, delegation-scope
composition, temporal-validity checking, delegation-chain verification, and the
full `verifyMandate` over all five checks), the session lifecycle (the
six-state negotiation state machine PROPOSED -> ACTIVE -> AGREED / REJECTED /
EXPIRED -> DORMANT with its strict transition table, signature-verified message
application, behavioral-signal tracking, and the hash-chain transcript helpers),
and the reputation attestation (the signed behavioral record produced from a
concluded session: `generateAttestation`, the 4-line receipt summary, the
whole-transcript hash, and the three-mode temporal-validity checks, with the
attestation carrying behavioral signals only and never the raw deal terms),
all with byte-level parity against the Python reference implementation. The
mandate revocation-endpoint network fetch is deferred (an injectable hook covers
the no-revocation outcome); the remaining primitive (the approval-receipt
verifier) ships in a subsequent alpha release.

Apache-2.0. Spec at https://github.com/eriknewton/concordia-protocol.
