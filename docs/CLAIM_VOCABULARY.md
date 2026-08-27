# Concordia Claim Vocabulary

GENERATED FILE. Source: `docs/assurance.json`.

Regenerate with `python3 scripts/assurance/generate.py`. Check committed output with `python3 scripts/assurance/generate.py --check`.

Use these terms as separate claim atoms. Passing one dimension never promotes another.

| Term | Means | Does not mean |
| --- | --- | --- |
| **Agreement integrity** (`agreement_integrity`) | Whether the retained bytes prove that the resolved signing keys approved the same bounded artifact and, when the closing receipt is supplied, the same transcript set. | A valid signature does not establish a signer's real-world identity, mandate, voluntariness, truthfulness, or the justice of the agreement. |
| **Agreement authority** (`agreement_authority`) | Whether a signer was authorized, under a configured trust policy, to make the bounded commitment represented by the artifact. | A signature or agent_id alone does not prove real-world identity or authority. Concordia does not independently establish that an issuer had legal or organizational power to grant a mandate. |
| **Agreement voluntariness** (`agreement_voluntariness`) | Whether participation and assent were free from coercion, hidden pressure, incapacitation, or policy-induced compulsion. | Cryptography cannot establish freedom from duress, competence, absence of training-induced compliance, informed human consent, or authentic self-authorship. |
| **Agreement justice** (`agreement_justice`) | Whether an agreement is substantively fair, non-exploitative, and compatible with the rights and welfare of affected parties. | Pareto efficiency, mutual signatures, or protocol conformance do not prove distributive justice, equal bargaining power, absence of exploitation, or benefit to affected non-signers. |
| **Payload confidentiality** (`payload_confidentiality`) | Whether message contents remain unreadable to relays, mailbox operators, storage services, and other transport intermediaries. | Current Concordia deployments must not be described as end-to-end encrypted, confidential from the relay, or protected from a compromised transport operator. |
| **Metadata privacy** (`metadata_privacy`) | Whether protocol and transport observers are prevented from learning counterparties, timing, volume, routing, relationship, and other interaction metadata. | Concordia does not currently hide counterparties, timing, message counts, routing, access patterns, relay participation, or other traffic metadata from the systems that carry or store the interaction. |

## Required distinctions

- **Signature validity vs. identity:** a signature proves that a resolved key signed bytes. It does not prove who controls the key in the real world.
- **Identity vs. authority:** knowing or resolving a signer does not prove that signer held a valid mandate for this action.
- **Authority vs. voluntariness:** an authorized signer may still act under duress, manipulation, or incapacity.
- **Voluntariness vs. justice:** freely signed terms can still be exploitative or harmful to affected non-signers.
- **Integrity vs. objective fulfillment:** a FulfillmentAttestation binds a signer's assertion. It does not prove an external-world event without separate evidence.
- **First-party parity vs. independent implementation:** the Python and Node.js runners agree on 1,541 vectors with zero divergence, but both are first-party authored.
- **Record minimization vs. payload confidentiality:** excluding raw terms from an attestation does not encrypt negotiation messages.
- **Payload confidentiality vs. metadata privacy:** encrypted content would not by itself hide counterparties, timing, routing, or volume.

## Status language

### Design

- `specified`: A normative or maintained design defines the bounded behavior and its limits.
- `partial`: A design names relevant mechanisms or limits but does not define the whole dimension.
- `not_specified`: No maintained design defines the dimension.

### Implementation

- `implemented`: The current reference implementation provides the bounded behavior.
- `partial`: The current reference implementation provides only a bounded subset or depends on supplied trust inputs.
- `not_implemented`: The current reference implementation does not provide the dimension.

### Test

- `verified`: Current first-party tests verify the bounded implemented behavior.
- `partial`: Current first-party tests cover only a subset of the bounded behavior.
- `not_verified`: No current test verifies the dimension itself.

### Drill

- `verified`: A recorded operational or adversarial drill verifies the bounded behavior.
- `partial`: A recorded drill covers only a subset of the bounded behavior.
- `not_verified`: No recorded drill verifies the dimension.
- `not_applicable`: An operational drill does not apply to this dimension.

### External Reproduction

- `verified`: A registered external implementation reproduces the full bounded profile.
- `partial`: A registered external implementation reproduces only a bounded subset.
- `none`: No registered external implementation reproduces the dimension.

### Public Claim

- `bounded`: Published wording states both the supported claim and its limits.
- `not_claimed`: No public capability claim is made for the dimension.
- `overclaimed`: Published wording exceeds the evidence and must be corrected.
