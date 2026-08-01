# Concordia Conformance Runner Contract v1-draft

This contract defines the vector format and the verification profiles a
conforming runner implements. A runner needs an RFC 8785 JSON Canonicalization
Scheme implementation, SHA-256, Ed25519, and a JSON-Schema draft 2020-12
validator. It does not need the Concordia SDK.

<!-- claim:conformance-vectors-verify-without-our-sdk -->
The conformance vectors verify without the Concordia SDK: the reference
runner installs only RFC 8785, PyNaCl, JSON Schema, and the Python standard
library, then executes the public vector manifest.
<!-- /claim -->

## Suite Layout

The generated suite lives under `conformance/vectors/`.

- `manifest.json` indexes every generated vector and pins the expected counts.
- `fixtures/` contains verbatim copies of the source JSON fixtures.
- `schemas/` contains frozen schema inputs for the signed artifact types.
- `positive/` contains vectors that a conforming runner must accept.
- `mutation/` contains the converted mutation battery.
- `canary/` contains runner-discrimination vectors.

Diagnostic bytes live outside the vector tree under `conformance/diag/`.
Conformance runs MUST NOT read `conformance/diag/`. The diagnostic files exist
only to debug a failing runner after the runner has already produced its result.

## Vector Format

Each vector is one JSON object:

```json
{
  "schema_version": "concordia-conformance-vector/v1-draft",
  "id": "pos-1404-approval-receipt",
  "title": "A short human-readable title",
  "source_fixture": "a2a-1404-receipt-revocation-vector",
  "record_type": "approval_receipt",
  "verification_profile": "receipt-v1",
  "input": {},
  "context": {},
  "expected": "accept",
  "expected_reason_class": null,
  "notes": ""
}
```

Required fields:

- `schema_version`: exactly `concordia-conformance-vector/v1-draft`.
- `id`: stable ASCII identifier, unique in the suite.
- `title`: short description.
- `source_fixture`: source fixture directory name.
- `record_type`: one of `decision_object`, `approval_receipt`,
  `revocation_record`, `cascade_decision_record`,
  `fulfillment_attestation`, `attestation`, `predicate`, `mandate`, or
  `cosign_receipt`, `conditional_commitment`, `atomic_activation_proof`,
  `unwind_record`, `closure_predicate`, `chain_session`, or
  `chain_session_transition`, `agent_profile`, `competence_proof`,
  `receipt_bundle`, or `message_chain`. `decision_object` is an unsigned support object
  used by the `decision-object-v1` digest profile.
- `verification_profile`: one of the profiles below.
- `input`: the full JSON object being checked. It is inline, never a file path.
- `context`: extra public data needed by the selected profile.
- `expected`: `accept` or `reject`.

Optional fields:

- `expected_reason_class`: coarse diagnostic class. Runners may report it, but
  pass or fail is judged only on `expected`.
- `notes`: explanatory text. It is not an input to verification.

Runners MUST reject malformed vectors before evaluating the profile. Runners
MUST NOT infer behavior from file names. The profile id and fields inside the
vector are the only dispatch inputs.

## Common Operations

`JCS(x)` means RFC 8785 canonical JSON bytes for `x`.

`SHA256-JCS(x)` means `sha256:` followed by lowercase hex SHA-256 over `JCS(x)`.

For signatures, remove the top-level `signature` member before canonicalizing
unless the selected profile states a different preimage. Decode signature and
public key values as base64url. Padding may be present or absent.

Signature values appear in three envelope forms:

1. Dict envelope:

   ```json
   {"alg": "Ed25519", "value": "<base64url signature>"}
   ```

2. Bare string with sibling algorithm:

   ```json
   {"algorithm": "EdDSA", "signature": "<base64url signature>"}
   ```

   The selected profile states the required sibling algorithm. Phase 2 A1
   mandate and predicate vectors use only `EdDSA`; `ES256` is out of scope.

3. Bare string with profile-implied Ed25519:

   ```json
   {"signature": "<base64url signature>"}
   ```

   Attestation party signatures, attestation countersignatures, and cosign
   counterparty signatures use this form.

`StripSignaturesRecursive(x)` means recursively walking objects and arrays and
removing every object member whose key is exactly `signature`, at every depth.
It preserves all other members and all array order.

`CosignJCS(x)` means `JCS(StripSignaturesRecursive(x))`.

Attestation countersignatures use `CosignJCS(input without top-level
countersignatures)`. This is intentionally different from the top-level
signature-removal rule used by the Phase 1 profiles and by `predicate-v1` /
`mandate-v1`.

JSON pointers in this contract use RFC 6901. A missing pointer is a failed
check. Equality compares JSON values after parsing, not string rendering.

Date-time assertion: for this suite's pinned schemas, validators MUST assert
`format: "date-time"`. The value must parse as ISO 8601 using the Python SDK
rule of replacing `Z` with `+00:00` before parsing, and the parsed value MUST
carry explicit timezone information. This rule is scoped only to `date-time`;
all other JSON Schema formats remain annotations unless a profile states a
separate explicit check.

Allowed `expected_reason_class` values are `schema`, `signature`, `digest`,
`binding`, `temporal`, `privacy`, and `transition`.

## Profiles

### `decision-object-v1`

Inputs:

- `input`: the decision object.
- `context.expected_decision_id`: `sha256:<64 lowercase hex chars>`.

Checks, in order:

1. Compute `SHA256-JCS(input)`.
2. Compare it to `context.expected_decision_id`.
3. Accept only if they are equal.

### `offer-binding-v1`

This profile covers positive digest and equality checks that bind support
objects to committed fields. It exists to make those checks explicit without
using filename heuristics.

Inputs:

- `input`: the object named by the vector.
- `context.checks`: non-empty array of check objects.
- `context` may also carry support objects, such as `offer`, `capability`,
  `decision_object`, `receipt`, or `revocation_record`.

Allowed check object forms:

```json
{
  "kind": "jcs-sha256",
  "source": "input",
  "expected": "sha256:..."
}
```

```json
{
  "kind": "json-pointer-equal",
  "left": {"object": "input", "pointer": "/scope/decision"},
  "right": {"object": "context.decision_object", "pointer": "/decision"}
}
```

Checks, in order:

1. For `jcs-sha256`, resolve `source`. `input` refers to the vector input.
   `context.<name>` refers to that named context member. Compute
   `SHA256-JCS(source)` and compare it to `expected`.
2. For `json-pointer-equal`, resolve both sides and compare the parsed JSON
   values for equality.
3. Reject unknown check kinds.
4. Accept only if every listed check passes.

### `receipt-v1`

Inputs:

- `input`: an ApprovalReceipt object.
- `context.offer`: the offer object the receipt commits to.
- `context.now`: deterministic ISO 8601 timestamp for temporal checks.
- `context.public_keys_b64url.issuer`: Ed25519 public key for the receipt
  signer.

Signature envelope:

```json
{"alg": "Ed25519", "value": "<base64url signature>"}
```

Checks, in order:

1. Validate `input` against `approval_receipt.schema.json`.
2. Require at least one reference with `relationship: "approves"` and `type` of
   `negotiation_session` or `a2cn:negotiation_session`.
3. Require `signature.alg == "Ed25519"`.
4. Verify Ed25519 over `JCS(input without /signature)` under
   `context.public_keys_b64url.issuer`.
5. Parse `expires_at` and require it is greater than or equal to `context.now`.
6. Compute `SHA256-JCS(context.offer)` and compare it to
   `/scope/offer_hash`.
7. Accept only if all checks pass.

### `revocation-v1`

Inputs:

- `input`: a RevocationRecord object.
- `context.public_keys_b64url.issuer`: Ed25519 public key for the revocation
  issuer.

Signature envelope:

```json
{"alg": "EdDSA", "value": "<base64url signature>"}
```

Checks, in order:

1. Validate `input` against `revocation_record.schema.json`.
2. Require a reference whose `relationship` is `revokes` and whose `id` equals
   `/revoked_artifact_id`.
3. Require `signature.alg == "EdDSA"`.
4. Verify Ed25519 over `JCS(input without /signature)` under
   `context.public_keys_b64url.issuer`.
5. Accept only if all checks pass.

### `cascade-decision-v1`

Inputs:

- `input`: a CascadeDecisionRecord object.
- `context.public_keys_b64url.issuer`: Ed25519 public key for the issuer.
- `context.expected_decision_id`: optional `sha256:<hex>` form of the expected
  decision id. The record stores the bare hex value at `/decision_id`.

Signature envelope:

```json
{"alg": "EdDSA", "value": "<base64url signature>"}
```

Checks, in order:

1. Validate `input` against `cascade_decision_record.schema.json`.
2. Require the schema to reject unknown top-level keys and unknown keys inside
   each `ancestor_reads[]` item.
3. Build the preimage by removing top-level `decision_id` and `signature`.
4. Compute lowercase hex SHA-256 over `JCS(preimage)` and compare it to
   `/decision_id`.
5. If `context.expected_decision_id` is present, require
   `sha256:` plus `/decision_id` to equal it.
6. Require `signature.alg == "EdDSA"`.
7. Verify Ed25519 over `JCS(preimage)` under
   `context.public_keys_b64url.issuer`.
8. Accept only if all checks pass.

### `fulfillment-attestation-v1`

Inputs:

- `input`: a FulfillmentAttestation object.
- `context.public_key_b64url`: Ed25519 public key for the signer.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over
  `JCS(input without /signature)`.
- `context.seed_ed25519_ascii`: optional public test seed. If present, it must
  be exactly 32 UTF-8 bytes and must re-derive `context.public_key_b64url`.
- `context.signature_b64url`: optional expected signature string.
- `context.join_keys`: optional object with `charge_ref` and `action_ref`.
- `context.forbid_raw_deal_terms`: optional boolean.

Signature envelope:

```json
{"alg": "Ed25519", "value": "<base64url signature>"}
```

Checks, in order:

1. Validate `input` against `fulfillment_attestation.schema.json`.
2. Require at least one reference with `relationship: "fulfills"` whose `id`
   equals `/agreement_attestation_id`.
3. Require `signature.alg == "Ed25519"`.
4. Verify Ed25519 over `JCS(input without /signature)` under
   `context.public_key_b64url`.
5. If `context.canonical_sha256` is present, compare it to SHA-256 over that
   same preimage.
6. If `context.seed_ed25519_ascii` is present, derive the Ed25519 public key
   from the seed and compare it to `context.public_key_b64url`.
7. If `context.signature_b64url` is present, re-sign the preimage with the
   public test seed and compare it to both `context.signature_b64url` and
   `/signature/value`.
8. If `context.join_keys.charge_ref` is present, compare it to `/charge_ref`.
9. If `context.join_keys.action_ref` is present, compare it to `/action_ref`.
10. If `context.forbid_raw_deal_terms` is true, scan every key and every string
    value in `input` except `/signature/value`. Reject if any of these six
    case-insensitive regular expressions matches (they are the SPEC 9.6.6 raw
    deal-term detectors, reproduced verbatim):

    ```
    [$€£¥]\s*\d
    \b(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|CNY|INR)\s*\d
    \b\d+(?:[.,]\d+)?\s*(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|CNY|INR)\b
    \bprice\s*:
    \b(?:qty|quantity)\s*[:=]?\s*\d+\b
    \b\d+\s*(?:units?|items?|pcs|pieces)\b
    ```
11. Accept only if all checks pass.

### `attestation-v1`

Inputs:

- `input`: a reputation Attestation object.
- `context.public_keys_b64url`: object mapping each party `agent_id` to that
  party's Ed25519 public key.
- `context.expected_verified_parties`: optional array of party `agent_id`
  values expected to verify.
- `context.forbid_raw_deal_terms`: optional boolean.

Signature envelope:

```json
{"signature": "<base64url signature>"}
```

Each party signature covers that party's own party object with only that
party object's top-level `signature` member removed.

Checks, in order:

1. If `context.forbid_raw_deal_terms` is true, scan every key and every string
   value in `input` except signature values. Reject with reason class
   `privacy` if any SPEC 9.6.6 raw-deal-term detector listed in
   `fulfillment-attestation-v1` matches.
2. Validate `input` against `attestation.schema.json`.
3. Require `context.public_keys_b64url` to contain an Ed25519 public key for
   every `parties[]` entry's `agent_id`.
4. For each `parties[]` entry, verify Ed25519 over
   `JCS(party without /signature)` under that party's public key.
5. If `context.expected_verified_parties` is present, require the sorted
   verified party set to equal it.
6. Accept only if all checks pass.

### `attestation-countersign-v1`

Inputs:

- `input`: a reputation Attestation object with a `countersignatures` map.
- `context.public_keys_b64url`: object mapping each countersigner `agent_id`
  to that party's Ed25519 public key.
- `context.countersigners`: non-empty array of `agent_id` values that MUST
  countersign.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over the
  countersignature preimage.

Signature envelope:

```json
{"countersignatures": {"<agent_id>": "<base64url signature>"}}
```

Checks, in order:

1. Validate `input` against `attestation.schema.json`.
2. Build the countersignature preimage as
   `CosignJCS(input without top-level countersignatures)`, where
   `StripSignaturesRecursive` removes every `signature` member at every depth.
3. If `context.canonical_sha256` is present, compare it to SHA-256 over that
   preimage.
4. For each `context.countersigners[]` value, require a signature at
   `input.countersignatures[agent_id]` and a public key at
   `context.public_keys_b64url[agent_id]`.
5. Verify each countersignature as Ed25519 over the shared preimage.
6. Accept only if all checks pass.

### `predicate-v1`

Inputs:

- `input`: a signed Predicate object.
- `context.public_key_b64url`: Ed25519 public key for the signer.
- `context.now`: deterministic ISO 8601 timestamp for lifecycle checks.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over
  `JCS(input without /signature)`.

Signature envelope:

```json
{"algorithm": "EdDSA", "signature": "<base64url signature>"}
```

Checks, in order:

1. Validate `input` against `predicate.json`. The schema's
   `urn:concordia:schema:reference:v0.5` reference resolves to the frozen
   `reference.schema.json` in the vector schema tree.
2. Require `/algorithm == "EdDSA"`. `ES256` predicates are out of scope for
   Phase 2 A1 vectors.
3. Build the preimage as `JCS(input without /signature)`.
4. If `context.canonical_sha256` is present, compare it to SHA-256 over that
   preimage.
5. Verify Ed25519 over the preimage under `context.public_key_b64url`.
6. Require `/status == "active"` and `/expires_at >= context.now`.
7. Accept only if all checks pass.

### `mandate-v1`

Inputs:

- `input`: a signed Mandate object.
- `context.issuer_public_key_b64url`: Ed25519 public key for `/issuer`.
- `context.now`: deterministic ISO 8601 timestamp for temporal checks.
- `context.action`: optional action object to validate against the mandate's
  effective constraints.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over
  `JCS(input without /signature)`.

Signature envelope:

```json
{"algorithm": "EdDSA", "signature": "<base64url signature>"}
```

Checks, in order:

1. Validate `input` against `mandate.schema.json`.
2. Require `/algorithm == "EdDSA"`. `ES256` mandates are out of scope for
   Phase 2 A1 vectors.
3. Build the preimage with `canonicalize_mandate`: `JCS(input without
   /signature)`.
4. If `context.canonical_sha256` is present, compare it to SHA-256 over that
   preimage.
5. Verify Ed25519 over the preimage under
   `context.issuer_public_key_b64url`.
6. Require `/status` to be absent or `"active"`.
7. Enforce the three mandate validity modes:
   `windowed` requires `not_before <= context.now <= not_after`; `sequence`
   requires `context.sequence_key == /validity/sequence_key`; `state_bound`
   requires `context.state_active == true`.
8. Require `/constraints` to be a valid JSON Schema. If `context.action` is
   present, validate it against `/constraints`.
9. Accept only if all checks pass.

### `delegation-chain-v1`

Inputs:

- `input`: a signed Mandate object with a non-empty `delegation_chain`.
- `context.issuer_public_key_b64url`, `context.now`, `context.action`, and
  `context.canonical_sha256`: same as `mandate-v1`.
- `context.delegation_public_keys_b64url`: object mapping each link delegator
  identifier to that delegator's Ed25519 public key.

Checks, in order:

1. Run `mandate-v1` checks 1 through 7.
2. Require a non-empty `/delegation_chain`.
3. Require the first link's `/delegator` to equal mandate `/issuer`.
4. Require the final link's `/delegate` to equal mandate `/subject`.
5. For each link after the first, require its `/delegator` to equal the
   previous link's `/delegate`.
6. For each link, require `/algorithm == "EdDSA"`, require a public key for
   `/delegator`, and verify Ed25519 over `JCS(link without /signature)`.
7. Compose effective constraints from mandate `/constraints` plus each
   `scope_restriction`. A scope restriction is either a JSON Schema object or
   the legacy `{"max_spend": number}` shorthand, which means an object schema
   requiring `max_spend <= number`.
8. If `context.action` is present, validate it against the effective
   constraints.
9. Accept only if all checks pass.

### `cosign-v1`

Inputs:

- `input`: a counterparty co-signed receipt object.
- `context.counterparty_did`: expected counterparty `did:key`.
- `context.publisher_did`: publisher DID, which must differ from the
  counterparty DID.
- `context.counterparty_public_key_b64url`: raw 32-byte Ed25519 public key.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over the cosign
  preimage.

Signature envelope:

```json
{"parties": [{"agent_id": "<did>", "signature": "<base64url signature>"}]}
```

Checks, in order:

1. Require `context.counterparty_did` to be an Ed25519 `did:key` that decodes
   to `context.counterparty_public_key_b64url`.
2. Re-derive the DID as `did:key:z<base64url(0xed01 || public_key)>`, with no
   base64 padding, and require it to equal `context.counterparty_did`.
3. Require `context.publisher_did != context.counterparty_did`.
4. Require exactly one `parties[]` entry with `agent_id` equal to the
   counterparty DID, and require that entry to contain a non-empty bare-string
   `signature`.
5. Build the preimage as `CosignJCS(input)`, recursively stripping every
   `signature` member at every depth.
6. If `context.canonical_sha256` is present, compare it to SHA-256 over that
   preimage.
7. Verify the counterparty signature as Ed25519 over the preimage.
8. Accept only if all checks pass.

### `conditional-commitment-v1`

Inputs:

- `input`: a ConditionalCommitment object.
- `context.public_key_b64url`: Ed25519 public key for the commitment signer.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over
  `JCS(input without /signature)`.

Signature envelope:

```json
{"algorithm": "EdDSA", "signature": "<base64url signature>"}
```

Checks, in order:

1. Validate `input` against `conditional_commitment.schema.json`.
2. Require `/algorithm == "EdDSA"`.
3. Build the preimage as `JCS(input without /signature)`.
4. If `context.canonical_sha256` is present, compare it to SHA-256 over that
   preimage.
5. Verify Ed25519 over the preimage under `context.public_key_b64url`.
6. Accept only if all checks pass.

### `atomic-activation-proof-v1`

Inputs:

- `input`: an AtomicActivationProof object.
- `context.public_key_b64url`: Ed25519 public key for the proof signer.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over
  `JCS(input without /signature)`.

Signature envelope:

```json
{"algorithm": "EdDSA", "signature": "<base64url signature>"}
```

Checks, in order:

1. Validate `input` against `atomic_activation_proof.schema.json`.
2. Require `/algorithm == "EdDSA"`.
3. Build the preimage as `JCS(input without /signature)`.
4. If `context.canonical_sha256` is present, compare it to SHA-256 over that
   preimage.
5. Verify Ed25519 over the preimage under `context.public_key_b64url`.
6. Accept only if all checks pass.

### `unwind-record-v1`

Inputs:

- `input`: an UnwindRecord object.
- `context.public_key_b64url`: Ed25519 public key for the unwind signer.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over
  `JCS(input without /signature)`.

Signature envelope:

```json
{"algorithm": "EdDSA", "signature": "<base64url signature>"}
```

Checks, in order:

1. Validate `input` against `unwind_record.schema.json`.
2. Require `/algorithm == "EdDSA"`.
3. Build the preimage as `JCS(input without /signature)`.
4. If `context.canonical_sha256` is present, compare it to SHA-256 over that
   preimage.
5. Verify Ed25519 over the preimage under `context.public_key_b64url`.
6. Accept only if all checks pass.

### `closure-predicate-v1`

Inputs:

- `input`: a ClosurePredicate object.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over
  `JCS(input without /signature)`.
- `context.digest_checks`: optional array of committed digest checks. The
  P2-A3 vectors use:

  ```json
  {
    "kind": "jcs-sha256-pointer",
    "source": "context.chain_session",
    "target": {"object": "input", "pointer": "/references/0/digest"}
  }
  ```

Signature envelope:

None for this profile. The schema has a non-empty `/signature` field because
the fixture shape carries one, but `closure-predicate-v1` does not verify it
and does not include it in the canonical digest. There is no dedicated
ClosurePredicate signer in the SDK.

Checks, in order:

1. Validate `input` against `closure_predicate.schema.json`.
2. Build the canonical preimage as `JCS(input without /signature)`.
3. If `context.canonical_sha256` is present, compare it to SHA-256 over that
   preimage.
4. For each `context.digest_checks[]` entry with
   `kind: "jcs-sha256-pointer"`, resolve `source`, compute `SHA256-JCS(source)`,
   resolve `target`, and require equality.
5. Accept only if all checks pass.

### `chain-session-v1`

Inputs:

- `input`: a ChainSession object.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over `JCS(input)`.

Checks, in order:

1. Validate `input` against `chain_session.schema.json`.
2. If `context.canonical_sha256` is present, compare it to `SHA256-JCS(input)`.
3. Accept only if all checks pass.

### `chain-session-transition-v1`

Inputs:

- `input.initial_session`: a full ChainSession object before the attempted
  transition.
- `input.attempt_transition`: target state string.
- `input.transition_now`: deterministic ISO 8601 timestamp for precondition
  checks.
- `input.expected`: optional source-fixture expectation, either `ok` or
  `InvalidTransitionError`. The vector's top-level `expected` remains
  authoritative.

Legal state-transition table:

| From | Legal targets |
|---|---|
| `PROPOSED` | `OPEN` |
| `OPEN` | `ACTIVATED`, `DISSOLVED`, `EXPIRED` |
| `ACTIVATED` | none |
| `DISSOLVED` | none |
| `EXPIRED` | none |

Preconditions:

1. `PROPOSED -> OPEN` requires `len(commitments) == len(participants)`.
2. `OPEN -> ACTIVATED` requires `activation_proof_id` and
   `transition_now < activation_deadline`.
3. `OPEN -> DISSOLVED` requires `unwind_record_id`.
4. `OPEN -> EXPIRED` requires `transition_now >= activation_deadline` and no
   `activation_proof_id`.

Checks, in order:

1. Validate `input.initial_session` against `chain_session.schema.json`.
2. Require `input.attempt_transition` to appear in the legal-target set for
   `input.initial_session.state`.
3. Require the matching transition preconditions above.
4. Accept only if all checks pass.

### `agent-profile-v1`

Inputs:

- `input`: an AgentCapabilityProfile object.
- `context.public_key_b64url`: Ed25519 public key for the profile signer.
- `context.canonical_fields`: the exact top-level field list inside
  `AgentCapabilityProfile.to_canonical_dict()`.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over the
  canonical profile bytes.

Signature envelope:

```json
{"signature": "<base64url signature>"}
```

The signed canonical form is exactly:

```text
type, version, agent_id, name, description, capabilities,
negotiation_profile, trust_signals, endpoints, location, ttl, updated_at
```

`signature` and `verified` are excluded. `verified` is store-local. Unknown
top-level keys are rejected by this conformance profile. Unknown keys under
`trust_signals` are tolerated and ignored for canonicalization, matching the
#149 / #151 forward-compatibility lane. Unknown keys inside each
`trust_signals.reputation[]` assertion are also ignored; reputation assertions
are additive provider records, and only `provider`, `subject_did`, `tier`, and
`composite` are in the canonical assertion.

Checks, in order:

1. Require `context.canonical_fields` to equal the exact list above.
2. Build the canonical dict from the fields above. For `trust_signals`, ignore
   unknown trust-signal keys and drop `null` optional known keys. For
   `trust_signals.reputation[]`, ignore unknown assertion keys and drop `null`
   optional assertion keys.
3. Reject unknown keys in signed nested objects other than the two tolerance
   lanes above.
4. If `context.canonical_sha256` is present, compare it to SHA-256 over
   `JCS(canonical_dict)`.
5. Verify Ed25519 over `JCS(canonical_dict)` under
   `context.public_key_b64url`.
6. Accept only if all checks pass.

### `competence-proof-v1`

Inputs:

- `input`: a CompetenceProof object.
- `context.public_key_b64url`: Ed25519 public key for `/agent_id`.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over the
  signable proof form.

Signature envelope:

```json
{"agent_signature": "<base64url signature>"}
```

The signable proof form is the CompetenceProof signing dict: all top-level
members except `agent_signature` and `concordia_competence_proof`. This matches
the SDK signable form (`to_dict_for_signing()`).

Merkle inclusion proof semantics match the SDK `verify_merkle_proof` helper:

1. Empty root rejects.
2. Start with `SHA-256(attestation_id UTF-8)` as lowercase hex.
3. Read `proof.index`, defaulting to `0` if absent.
4. Read `proof.proof`, defaulting to `[]` if absent.
5. For each sibling hash in order, concatenate `current || sibling` when the
   current index is even, otherwise `sibling || current`, hash that UTF-8 hex
   concatenation with SHA-256, then integer-divide the index by 2.
6. The proof is valid only if the final hex digest equals
   `/attestation_merkle_root`.

Checks, in order:

1. Require `proof_id`, `agent_id`, `created_at`, `claims`,
   `attestation_merkle_root`, `attestation_count`, `merkle_proofs`,
   `revealed_attestations`, and `agent_signature`.
2. Require `/claims/total_negotiations == /attestation_count`.
3. For every revealed attestation, find a Merkle proof whose
   `/attestation_id` equals the revealed attestation's `/attestation_id`.
4. Verify each inclusion proof against `/attestation_merkle_root` using the
   ordered Merkle semantics above. A proof/root mismatch rejects with reason
   class `binding`.
5. Build the signable form by removing top-level `agent_signature` and
   `concordia_competence_proof`.
6. If `context.canonical_sha256` is present, compare it to SHA-256 over
   `JCS(signable)`.
7. Verify Ed25519 over `JCS(signable)` under `context.public_key_b64url`.
8. Accept only if all checks pass.

### `receipt-bundle-v1`

Inputs:

- `input`: a ReceiptBundle object.
- `context.public_key_b64url`: Ed25519 public key for `/agent_id`.
- `context.canonical_sha256`: optional `sha256:<hex>` digest over the
  signable bundle form.

Signature envelope:

```json
{"agent_signature": "<base64url signature>"}
```

Checks, in order:

1. Validate `input` against `receipt_bundle.schema.json`.
2. Build the signable form by removing top-level `agent_signature` and
   `concordia_receipt_bundle`.
3. If `context.canonical_sha256` is present, compare it to SHA-256 over
   `JCS(signable)`.
4. Verify Ed25519 over `JCS(signable)` under `context.public_key_b64url`.
5. Accept only if all checks pass.

### `message-chain-v1`

Inputs:

- `input.messages`: a non-empty array of session envelope messages.
- `context.public_keys_b64url`: object mapping each message sender
  `agent_id` to that sender's Ed25519 public key.
- `context.expected_message_count`: optional exact message count.
- `context.expected_message_hashes`: optional array of expected full-message
  hashes after signature insertion.

Signature envelope:

```json
{"signature": "<base64url signature>"}
```

`GENESIS_HASH` is `sha256:` followed by 64 zero characters. `MessageHash(m)` is
`sha256:` plus lowercase hex SHA-256 over `JCS(m)`, including the message's
`signature` field. Each message signature itself covers `JCS(message without
top-level signature)`.

Checks, in order:

1. Require the input object to contain only `messages`.
2. If `context.expected_message_count` is present, require it to equal
   `len(input.messages)`.
3. Require `input.messages[0].prev_hash == GENESIS_HASH`.
4. For each subsequent message, require `/prev_hash` to equal
   `MessageHash(previous_message)`. A stale, forked, deleted, or spliced link
   rejects with reason class `binding`.
5. For each message, resolve `/from/agent_id` in
   `context.public_keys_b64url`.
6. Verify Ed25519 over `JCS(message without top-level signature)` under the
   sender's public key.
7. If `context.expected_message_hashes` is present, recompute
   `MessageHash(message)` for every message and require exact array equality.
8. Accept only if all checks pass.

#### Chain position

The chain-position vectors exercise whole-chain attacks over a four-message
synthetic chain. A conforming runner walks messages in array order: it first
requires the first `prev_hash` to equal `GENESIS_HASH`, then requires every
later `prev_hash` to equal `MessageHash(previous_message)`, and only then
verifies each message signature. Deletion, reorder, and genesis-substitution
attacks reject with reason class `binding` when this linkage walk fails.

The current profile does not intrinsically commit to the complete message set.
It enforces completeness only when `context.expected_message_count` or
`context.expected_message_hashes` is supplied. Therefore the re-signed deletion
splice vector is a tolerated accept: the remaining messages form a
self-consistent signed chain, but the deleted message is not recoverable from
per-message signatures alone.

## Decisions

### D1: Normativize Raw Verification

The mutation battery has one accepted mutation because the SDK typed path
re-fills a dataclass default when `cascade_depth` is dropped from
`revocation_A`. That is SDK behavior, not protocol conformance. Conformance
profiles verify raw JSON mappings. Under raw rules, that mutation changes the
canonical bytes and must reject.

Consequence: the generated mutation suite uses raw conformance verification
and pins its current per-battery split in `manifest.json`. The existing SDK
batteries remain SDK-behavior coverage where they exist. Any divergence between
raw profile verification and an SDK typed path must be named here or the
generator fails.

### D2: Keep Tolerated Accepts Byte-Pinned

Accepted mutation vectors are permitted only when the accepted field is outside
the selected profile's signed and checked semantics, and every accepted vector
must carry a non-empty justification note. Current tolerated lanes are:

- Extra members in the `signature` object of ApprovalReceipt and
  FulfillmentAttestation, because those schema objects allow additional
  properties and the signature block is outside its own signed preimage.
- AgentProfile unknown `trust_signals` keys and unknown reputation assertion
  keys, matching the #149 / #151 forward-compatibility lane.
- AgentProfile `verified`, because it is store-local and excluded from
  `to_canonical_dict()`.
- CompetenceProof `concordia_competence_proof`, because it is excluded from the
  signable proof form.
- ReceiptBundle `concordia_receipt_bundle` scalar value changes that remain
  schema-valid, because the version marker is excluded from the signable bundle
  form.

The schemas under `conformance/vectors/schemas/` are frozen copies for this
suite. Tightening a schema changes published fixture behavior and belongs in a
separate phase. Any new accepted mutation without a named tolerance is a
generator error.

## Scope Limits

Phase 1 covers four signed artifact types:

- ApprovalReceipt
- RevocationRecord
- CascadeDecisionRecord
- FulfillmentAttestation

The positive C1 vectors also include the unsigned #1404 decision object because
it is the digest source for the approval receipt evidence.

Phase 2 A1 adds synthetic, deterministic coverage for reputation Attestations,
Attestation countersignatures, Predicates, Mandates, Mandate delegation chains,
and counterparty cosigned receipts. Phase 2 A1 deliberately keeps `ES256`
mandate and predicate vectors out of scope; all new signing vectors are Ed25519
or EdDSA over Ed25519.

Phase 2 A3 adds synthetic, deterministic coverage for the CMPC bilateral set:
ConditionalCommitment, AtomicActivationProof, UnwindRecord, ClosurePredicate,
ChainSession, and the ten ChainSession transition fixtures. ClosurePredicate is
schema plus canonical digest plus committed digest checks only; this suite does
not invent a closure-signature verification rule.

Phase 2 A4 adds the remaining signed long-tail profiles: AgentProfile,
CompetenceProof, ReceiptBundle, and the session MessageChain. The MessageChain
profile uses a three-message synthetic chain and checks `prev_hash` linkage from
`GENESIS_HASH` before verifying each message signature.

Phase 2 B adds a four-message MessageChain position class that covers deletion
splice, deletion splice plus downstream re-signing, reorder, genesis
substitution, and the `canary-chain-splice` runner-discrimination vector.

The Verascore publish envelope is out of scope because it is a vendor adapter
surface, not a Concordia conformance profile. A2CN adapter messages are also
out of scope for this suite; they are adapter-specific composition surfaces,
not core conformance vectors.

The generated manifest pins the exact counts for fixtures, schemas, positive
section vectors, mutation vectors, canaries, and diagnostic canonical bytes.
The clean-room reference runner is the executable form of this contract.
