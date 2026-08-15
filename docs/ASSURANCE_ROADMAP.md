# Concordia Assurance Roadmap

GENERATED FILE. Source: `docs/assurance.json`.

Regenerate with `python3 scripts/assurance/generate.py`. Check committed output with `python3 scripts/assurance/generate.py --check`.

This roadmap tracks the next proof needed for each stable assurance dimension. It is a proof backlog, not a promise that every item is implemented.

| Dimension | Current bound | Missing proof | Dependencies |
| --- | --- | --- | --- |
| [Agreement integrity](../ASSURANCE_MATRIX.md#agreement-integrity) | Concordia verifies signatures over canonical bytes. A countersigned receipt at concordia_attestation 0.3.0 or later binds its outcome, chain head, and message count to the parties listed in that receipt. A message chain without that closing receipt does not prove transcript-set completeness. | Obtain and register a third-party run of the receipt-set-binding profile, including splice and truncation rejection, from an implementation that shares neither Concordia code nor authorship. | `conformance/IMPLEMENTATIONS.md`<br>`conformance/vectors/manifest.json` |
| [Agreement authority](../ASSURANCE_MATRIX.md#agreement-authority) | Concordia can verify a signed mandate, its delegation chain, scope restrictions, time bounds, and configured revocation evidence. Authority is established only relative to the issuer keys, resolver results, context, and policy supplied to that verification. | Publish a provider-neutral authority profile with pinned issuer resolution and revocation inputs, then obtain an external implementation run over valid, over-scope, expired, rotated, and revoked mandate cases. | `agreement_integrity`<br>`concordia/mandate_resolver.py` |
| [Agreement voluntariness](../ASSURANCE_MATRIX.md#agreement-voluntariness) | Concordia can retain signed accept, reject, withdraw, approval, and denial artifacts. Those artifacts show what a signing key asserted at a boundary; they do not prove that the decision was voluntary. | Define a voluntariness threat model and a non-overclaiming conformance profile for contested assent, revocation during negotiation, and explicit human escalation, while keeping subjective freedom outside cryptographic proof. | `agreement_authority`<br>`agreement_integrity` |
| [Agreement justice](../ASSURANCE_MATRIX.md#agreement-justice) | Concordia supplies structured multi-attribute offers, explicit constraints, optional resolution mechanisms, signed records, and portable evidence that a separate evaluator may use. It does not guarantee a fair or just result. | Define fairness limits and evaluation fixtures that separate mechanical agreement quality from normative justice, with explicit treatment of bargaining-power asymmetry and affected non-signers. | `agreement_voluntariness`<br>`agreement_authority` |
| [Payload confidentiality](../ASSURANCE_MATRIX.md#payload-confidentiality) | Concordia messages are signed but not end-to-end encrypted. TLS can protect each network hop, while the current relay and any other intermediary carrying plaintext messages can read their contents. | Complete a cross-runtime end-to-end encryption threat model and compatibility design before implementation, including key discovery, rotation, forward secrecy, multi-party sessions, recovery, and relay-visible failure behavior. | `agreement_integrity`<br>`cross-runtime encryption design` |
| [Metadata privacy](../ASSURANCE_MATRIX.md#metadata-privacy) | Concordia minimizes fields in reputation attestations by excluding raw deal terms and using bounded behavioral signals, coarse categories, and value buckets. This is record-content minimization, not transport metadata privacy. | Write a metadata threat model that inventories observer-visible fields and traffic patterns, then define separate content-minimization and metadata-privacy profiles with measurable leakage bounds. | `payload_confidentiality`<br>`relay threat model` |

## Priority order

1. Obtain a third-party receipt-set-binding run. This closes the largest gap between first-party cross-runtime parity and independent implementation.
2. Pin a provider-neutral authority profile with issuer resolution and revocation inputs.
3. Write distinct voluntariness and justice threat models. Neither should be collapsed into signature validity.
4. Complete an end-to-end payload-encryption design before behavior changes.
5. Inventory observer-visible metadata and define measurable leakage bounds separately from record-content minimization.

A roadmap item changes status only when its evidence is added to `docs/assurance.json` and the generated projections pass their drift check.
