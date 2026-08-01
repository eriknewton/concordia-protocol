# Concordia Conformance Runner Contract v1-draft

This contract defines the Phase 1 vector format and the verification profiles a
conforming runner implements. A runner needs an RFC 8785 JSON Canonicalization
Scheme implementation, SHA-256, Ed25519, and a JSON-Schema draft 2020-12
validator. It does not need the Concordia SDK.

<!-- claim:conformance-vectors-verify-without-our-sdk -->
The Phase 1 conformance vectors verify without the Concordia SDK: the reference
runner installs only RFC 8785, PyNaCl, JSON Schema, and the Python standard
library, then executes the public vector manifest.
<!-- /claim -->

## Suite Layout

The generated suite lives under `conformance/vectors/`.

- `manifest.json` indexes every generated vector and pins the expected counts.
- `fixtures/` contains verbatim copies of the source JSON fixtures.
- `schemas/` contains frozen schema inputs for the four signed artifact types.
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
  `revocation_record`, `cascade_decision_record`, or
  `fulfillment_attestation`. The signed artifact schema set is the four latter
  artifact types. `decision_object` is an unsigned support object used by the
  `decision-object-v1` digest profile.
- `verification_profile`: one of the six profiles below.
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

JSON pointers in this contract use RFC 6901. A missing pointer is a failed
check. Equality compares JSON values after parsing, not string rendering.

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

## Decisions

### D1: Normativize Raw Verification

The mutation battery has one accepted mutation because the SDK typed path
re-fills a dataclass default when `cascade_depth` is dropped from
`revocation_A`. That is SDK behavior, not protocol conformance. Conformance
profiles verify raw JSON mappings. Under raw rules, that mutation changes the
canonical bytes and must reject.

Consequence: the full mutation suite target for later phases is 220 rejects and
2 tolerated accepts. The existing SDK battery remains SDK-behavior coverage and
continues to assert 219 rejects and 3 accepted mutations through its typed path.
The divergence is intentional and documented here so the two count lines cannot
be mistaken for drift.

### D2: Keep the Two Tolerated Accepts Byte-Pinned

The remaining accepted mutations inject an extra member into the `signature`
object of the ApprovalReceipt and FulfillmentAttestation fixtures. Those schema
objects allow additional properties, and the signature block is outside its own
signed preimage. The extra member cannot alter a signed field.

The schemas under `conformance/vectors/schemas/` are frozen copies for this
suite. Tightening those two signature schemas would change published fixture
behavior, so it is deferred to a later phase. The two vectors will carry
`expected: "accept"` and a tolerated-escape note when the mutation set lands.

## Scope Limits

Phase 1 covers four signed artifact types:

- ApprovalReceipt
- RevocationRecord
- CascadeDecisionRecord
- FulfillmentAttestation

The positive C1 vectors also include the unsigned #1404 decision object because
it is the digest source for the approval receipt evidence. Phase 1 does not
cover the other signed artifact shapes in the SDK, bare-string signature
envelopes, chain-position vectors, or schema tightening.

The generated suite contains 11 positive vectors, 222 mutation vectors, and
three canary vectors. The clean-room reference runner is the executable form of
this contract.
