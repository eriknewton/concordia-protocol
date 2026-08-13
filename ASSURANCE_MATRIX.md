# Concordia Assurance Matrix

GENERATED FILE. Source: `docs/assurance.json`.

Regenerate with `python3 scripts/assurance/generate.py`. Check committed output with `python3 scripts/assurance/generate.py --check`.

Current reference implementations and published conformance evidence. This registry does not change the protocol specification or runtime behavior.

The status cells are deliberately separate. Implementation is not a test, a test is not an external reproduction, and a signature is not authority, voluntariness, or justice.

## Summary

| Dimension | Design | Implementation | Test | Drill | External reproduction | Public claim |
| --- | --- | --- | --- | --- | --- | --- |
| [Agreement integrity](#agreement-integrity) | specified | implemented | verified | not verified | partial | bounded |
| [Agreement authority](#agreement-authority) | specified | partial | verified | not verified | none | bounded |
| [Agreement voluntariness](#agreement-voluntariness) | partial | not implemented | not verified | not verified | none | bounded |
| [Agreement justice](#agreement-justice) | partial | not implemented | not verified | not verified | none | bounded |
| [Payload confidentiality](#payload-confidentiality) | partial | not implemented | not verified | not verified | none | bounded |
| [Metadata privacy](#metadata-privacy) | partial | not implemented | not verified | not verified | none | bounded |

## Agreement integrity

Whether the retained bytes prove that the resolved signing keys approved the same bounded artifact and, when the closing receipt is supplied, the same transcript set.

**Bounded claim:** Concordia verifies signatures over canonical bytes. A countersigned receipt at concordia_attestation 0.3.0 or later binds its outcome, chain head, and message count to the parties listed in that receipt. A message chain without that closing receipt does not prove transcript-set completeness.

**This does not claim:** A valid signature does not establish a signer's real-world identity, mandate, voluntariness, truthfulness, or the justice of the agreement.

### Evidence

- [`SPEC.md`](SPEC.md) (9.6.5b Receipt Set-Binding (v0.3.0)): Defines the countersigned closing receipt, chain_head, message_count, and the legacy set-unbound case.
- [`conformance/RUNNER_CONTRACT.md`](conformance/RUNNER_CONTRACT.md) (message-chain-v1): Requires every listed party's countersignature and compares the receipt's chain head and message count to the presented transcript.
- [`tests/test_conformance_reference_runner.py`](tests/test_conformance_reference_runner.py) (EXPECTED_FULL_SUMMARY): The first-party Python runner verifies 1,541 vectors with zero failures.
- [`tests/test_conformance_js_runner.py`](tests/test_conformance_js_runner.py) (EXPECTED_FULL_SUMMARY): The first-party Node.js runner verifies the same 1,541 vectors with zero failures.
- [`docs/interop/a2a-1920-fulfillment-sample/README.md`](docs/interop/a2a-1920-fulfillment-sample/README.md) (Second-implementation reproductions): One external implementation reproduced one FulfillmentAttestation digest and verified its signature and tamper rejection.

### Limitations

- The Python and Node.js conformance runners are different runtimes but are both first-party authored. Their 1,541-vector zero-divergence result is cross-runtime parity, not an independent implementation of Concordia.
- The sole external reproduction covers one FulfillmentAttestation record, not the whole protocol or the receipt-set-binding profile.
- A FulfillmentAttestation proves what its signer asserted and bound to the artifact. It does not objectively prove that physical or external-world fulfillment occurred.

**Next proof:** Obtain and register a third-party run of the receipt-set-binding profile, including splice and truncation rejection, from an implementation that shares neither Concordia code nor authorship.

## Agreement authority

Whether a signer was authorized, under a configured trust policy, to make the bounded commitment represented by the artifact.

**Bounded claim:** Concordia can verify a signed mandate, its delegation chain, scope restrictions, time bounds, and configured revocation evidence. Authority is established only relative to the issuer keys, resolver results, context, and policy supplied to that verification.

**This does not claim:** A signature or agent_id alone does not prove real-world identity or authority. Concordia does not independently establish that an issuer had legal or organizational power to grant a mandate.

### Evidence

- [`SPEC.md`](SPEC.md) (9.1 Identity): Keeps identity-layer choice outside Concordia and describes external delegation credentials as optional authorization proof.
- [`concordia/mandate.py`](concordia/mandate.py) (verify_mandate): Verifies mandate signatures, constraints, delegation, temporal validity, and resolver-supplied status.
- [`conformance/RUNNER_CONTRACT.md`](conformance/RUNNER_CONTRACT.md) (delegation-chain-v1): Pins delegation continuity, signer verification, and composed scope restrictions.
- [`tests/test_mandate_resolver.py`](tests/test_mandate_resolver.py) (module): Exercises resolver-backed mandate status and failure behavior.

### Limitations

- Authority depends on configured issuer keys, resolvers, verification time, action context, and local policy; naming an issuer or DID confers no authority by itself.
- Mandate verification does not prove that the principal knowingly or freely authorized the mandate.
- The conformance suite does not cover every signature algorithm supported by the Python SDK; its mandate and predicate profiles use Ed25519 only.

**Next proof:** Publish a provider-neutral authority profile with pinned issuer resolution and revocation inputs, then obtain an external implementation run over valid, over-scope, expired, rotated, and revoked mandate cases.

## Agreement voluntariness

Whether participation and assent were free from coercion, hidden pressure, incapacitation, or policy-induced compulsion.

**Bounded claim:** Concordia can retain signed accept, reject, withdraw, approval, and denial artifacts. Those artifacts show what a signing key asserted at a boundary; they do not prove that the decision was voluntary.

**This does not claim:** Cryptography cannot establish freedom from duress, competence, absence of training-induced compliance, informed human consent, or authentic self-authorship.

### Evidence

- [`SPEC.md`](SPEC.md) (5. Negotiation Lifecycle): Defines explicit acceptance, rejection, withdrawal, expiry, and dormant paths.
- [`SPEC.md`](SPEC.md) (9.6.4b ApprovalReceipt): Defines signed approve and deny decisions over a bounded offer hash.
- [`tests/test_validity_temporal.py`](tests/test_validity_temporal.py) (module): Exercises participant joining and time-bounded artifact validity.

### Limitations

- A signed acceptance proves control of a signing key at verification time, not freedom from duress or manipulation.
- ApprovalReceipt records a decision and its scope; it does not prove the approver was competent, informed, or independent.
- No voluntariness threat model, duress signal profile, or independent drill is complete.

**Next proof:** Define a voluntariness threat model and a non-overclaiming conformance profile for contested assent, revocation during negotiation, and explicit human escalation, while keeping subjective freedom outside cryptographic proof.

## Agreement justice

Whether an agreement is substantively fair, non-exploitative, and compatible with the rights and welfare of affected parties.

**Bounded claim:** Concordia supplies structured multi-attribute offers, explicit constraints, optional resolution mechanisms, signed records, and portable evidence that a separate evaluator may use. It does not guarantee a fair or just result.

**This does not claim:** Pareto efficiency, mutual signatures, or protocol conformance do not prove distributive justice, equal bargaining power, absence of exploitation, or benefit to affected non-signers.

### Evidence

- [`SPEC.md`](SPEC.md) (1. Design Principles): States the protocol's fairness intent and multi-attribute design constraints.
- [`SPEC.md`](SPEC.md) (8. Resolution Mechanisms): Defines optional split, final-offer, trade-off, and human-escalation mechanisms.
- [`concordia/offer.py`](concordia/offer.py) (module): Implements structured offers and constraints without adjudicating substantive fairness.

### Limitations

- A structurally valid bargain can still be exploitative or unjust.
- The reference implementation does not measure bargaining power, externalities, duress, or harms to non-signers.
- Resolution mechanisms are optional and their fairness properties are not formally proven for arbitrary agent strategies.

**Next proof:** Define fairness limits and evaluation fixtures that separate mechanical agreement quality from normative justice, with explicit treatment of bargaining-power asymmetry and affected non-signers.

## Payload confidentiality

Whether message contents remain unreadable to relays, mailbox operators, storage services, and other transport intermediaries.

**Bounded claim:** Concordia messages are signed but not end-to-end encrypted. TLS can protect each network hop, while the current relay and any other intermediary carrying plaintext messages can read their contents.

**This does not claim:** Current Concordia deployments must not be described as end-to-end encrypted, confidential from the relay, or protected from a compromised transport operator.

### Evidence

- [`SPEC.md`](SPEC.md) (9.4 Confidentiality): States that messages are not encrypted and that relays and intermediaries can read them.
- [`concordia/relay.py`](concordia/relay.py) (module): Implements store-and-forward message handling without an end-to-end encryption layer.
- [`tests/test_mcp_server_relay_bridge_edges.py`](tests/test_mcp_server_relay_bridge_edges.py) (module): Exercises relay boundaries but does not establish payload confidentiality.

### Limitations

- Transport-layer TLS does not hide content from an endpoint, relay, mailbox, or storage operator.
- Signatures provide integrity and authenticity, not secrecy.
- The X25519 and XChaCha20-Poly1305 construction named in the spec is a future candidate, not a specified or implemented feature.

**Next proof:** Complete a cross-runtime end-to-end encryption threat model and compatibility design before implementation, including key discovery, rotation, forward secrecy, multi-party sessions, recovery, and relay-visible failure behavior.

## Metadata privacy

Whether protocol and transport observers are prevented from learning counterparties, timing, volume, routing, relationship, and other interaction metadata.

**Bounded claim:** Concordia minimizes fields in reputation attestations by excluding raw deal terms and using bounded behavioral signals, coarse categories, and value buckets. This is record-content minimization, not transport metadata privacy.

**This does not claim:** Concordia does not currently hide counterparties, timing, message counts, routing, access patterns, relay participation, or other traffic metadata from the systems that carry or store the interaction.

### Evidence

- [`SPEC.md`](SPEC.md) (9.6.6 Attestation Privacy): Defines the behavioral-signal-only attestation shape, value buckets, category bounds, and the accepted self-disclosure residual.
- [`concordia/schema_validator.py`](concordia/schema_validator.py) (_RAW_TERM_PATTERNS): Provides raw-deal-term detectors used at the attestation boundary.
- [`docs/interop/a2a-1920-fulfillment-sample/verify.py`](docs/interop/a2a-1920-fulfillment-sample/verify.py) (privacy invariant): Checks the sample for raw deal terms and proves the detector catches an injected term.

### Limitations

- Field minimization does not provide transport confidentiality or metadata privacy.
- Coarse category and value-range fields still reveal information and can be deliberately abused for self-disclosure within their allowed grammar.
- The relay can observe participants, timing, message volume, and stored content; no mix network, padding, private information retrieval, or query-anonymity mechanism is implemented.

**Next proof:** Write a metadata threat model that inventories observer-visible fields and traffic patterns, then define separate content-minimization and metadata-privacy profiles with measurable leakage bounds.
