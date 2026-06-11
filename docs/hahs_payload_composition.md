# Concordia §9.6.4b ApprovalReceipt with HAHS payload composition

## Why

Concordia v0.5.1 §9.6.4b ApprovalReceipt is the canonical carrier for
third-party authority attestations on a negotiation event. HAHS v1
("Hashes-as-Histories", HiveTrust's hire-time scope ceiling schema) is one
canonical substantive payload that rides inside the ApprovalReceipt envelope
when the third-party authority is HiveTrust attesting hire-time scope.

This document is the integrator-facing composition guide. The authoritative
Concordia carrier shape is at `SPEC.md` §9.6.4b. The authoritative HAHS payload
shape is at
`https://hivetrust.onrender.com/.well-known/schemas/hahs-v1.json`
(verbatim title: "HAHS — Hashes-as-Histories v1").

## Composition pattern

ApprovalReceipt is the carrier. HAHS is the payload.

The ApprovalReceipt remains a Concordia artifact with the fields and
verification rules defined in §9.6.4b. HAHS supplies the third-party authority
claim that the receipt is carrying. Integrators should keep those layers
separate:

```text
Concordia ApprovalReceipt
  id: urn:concordia:receipt:<id>
  approver.identity: did:hive:hivetrust-issuer-001
  scope.hahs_payload_hash: sha256:<jcs-canonical-hahs-payload>
  scope.hahs_schema: https://hivetrust.onrender.com/.well-known/schemas/hahs-v1.json
  references:
    - negotiation session approved by the authority
    - mandate, policy, or other artifact fulfilled by the receipt
  extensions:
    hahs_v1:
      policy_id: ...
      policy_version: ...
      scope: ...
      composed_scope: ...
      receipt_hash: ...
      signature: ...
```

The `approver.identity` field carries the HAHS issuer DID when HiveTrust is the
third-party authority. The `scope` object carries an opaque, content-hash
reference to the HAHS payload. The HAHS payload itself may ride inside an
extension block or as a separately referenced artifact, depending on the
transport envelope.

When embedding HAHS directly, treat the embedded block as opaque to Concordia
except for fields explicitly copied into the ApprovalReceipt scope. Concordia
verification checks the carrier, expiry, signature, references, and revocation
state. HAHS verification checks the payload schema, canonical signature,
issuer key, revocation witness, and continuity-layer fields.

When referencing HAHS by artifact hash, keep the ApprovalReceipt stable:

```json
{
  "artifact_type": "ApprovalReceipt",
  "id": "urn:concordia:receipt:7f2e1a93",
  "issued_at": "2026-05-10T14:22:08Z",
  "expires_at": "2026-05-10T15:22:08Z",
  "approver": {
    "identity": "did:hive:hivetrust-issuer-001",
    "role": "third_party_authority"
  },
  "scope": {
    "decision": "approve",
    "offer_hash": "sha256:b4c1...e09f",
    "amount": "150000.00 USD",
    "threshold_crossed": "100000.00 USD",
    "hahs_schema": "https://hivetrust.onrender.com/.well-known/schemas/hahs-v1.json",
    "hahs_payload_hash": "sha256:9a67...4d21"
  },
  "references": [
    {
      "type": "negotiation_session",
      "id": "urn:a2cn:session:9e4d2c11",
      "relationship": "approves"
    },
    {
      "type": "mandate",
      "id": "urn:a2cn:mandate:m-2026-04-19-0007",
      "relationship": "fulfills"
    }
  ],
  "signature": {
    "alg": "Ed25519",
    "value": "..."
  }
}
```

## Cross-references

- Concordia §9.6.4b ApprovalReceipt:
  `../SPEC.md#964b-approvalreceipt-v05-a2a-discussion-1737`
- Concordia §11.5.7 URN catalog:
  `../SPEC.md#1157-cross-protocol-linkage`
- HAHS v1 schema:
  `https://hivetrust.onrender.com/.well-known/schemas/hahs-v1.json`
- A2A Discussion #1734 row #7 of the v0.3.3 cross-extension matrix:
  `https://github.com/a2aproject/A2A/discussions/1734`
- AEOESS agent-governance-vocabulary cross-references appear inside the HAHS
  schema itself.

## URN namespace discipline

Concordia §11.5.7 defines Concordia-owned namespace segments under
`urn:concordia:` for Concordia artifacts and records. In v0.7.0a1 those
segments are `attestation`, `mandate`, `offer`, `revocation`, and `session`.
HAHS-internal references, such as a chain-time policy cascade event, a HAHS
revocation epoch, or a HAHS rotation witness, MUST use a HAHS-owned namespace
prefix to avoid collision with future Concordia namespace additions.

Recommended forms:

- `urn:hahs:cascade:<id>` for HAHS-internal cascade events
- `urn:hahs:epoch:<id>` for HAHS continuity-layer epochs
- `urn:hivetrust:cascade:<id>` as an alternate HiveTrust-issuer-scoped form

Do not mint `urn:concordia:cascade:<id>` for HAHS-internal events. That segment
is not defined by Concordia §11.5.7 and would make a HAHS continuity reference
look like a Concordia protocol artifact.

Concordia verifiers accept any URN-shaped identifier per the §11.5.7
forward-compatibility rule. Non-Concordia URN namespaces are stored opaquely
without protocol-level resolution, so HAHS-internal URNs do not require
Concordia spec changes.

## Verifier obligations

- `ApprovalReceipt.expires_at` MUST be honored per §9.6.4b.
- HAHS receipt revocation MUST cascade through any `RevocationRecord`
  referencing the HAHS payload's `policy_id` or `receipt_hash`, consistent with
  the Concordia v0.7.0a1 cross-mandate revocation surface.
- The HAHS canonical `revocation_witness` URL pattern is
  `https://hivetrust.onrender.com/v1/audit/revocation/{policy_id}/{attestation_id}`
  using the HiveTrust primary host.
- The hive-gamification mirror is NOT a canonical resolution path for HAHS
  receipts.
- Verifiers MUST preserve HAHS payload fields they do not understand. Concordia
  carrier validation is not a HAHS schema validation substitute.
- Verifiers SHOULD bind any copied `scope.hahs_payload_hash` to the canonical
  HAHS body using RFC 8785 JCS before trusting copied fields.

## Hive-side payload details

### Canonicalization

- All receipts canonicalize per **RFC 8785 JCS** before signing. No leading/trailing whitespace, sorted keys, no insignificant zeros.
- Hash domain: `sha256(jcs(payload))`. The `sha:` field on the receipt envelope is hex-lowercase, no `0x` prefix.

### Key material

- Issuer: `did:hive:hivetrust-issuer-001`
- Algorithm: `ed25519`
- Pubkey (multibase ed25519): `i6-Wo01AwSD1eAhSSC3e3VCTEYFXehGNOVdC5iobuBc`
- Resolves via `https://thehiveryiq.com/.well-known/issuers/index.json`

### Composition envelope

When a Concordia §9.6.4b receipt references a HAHS receipt, the reference shape is:

```json
{
  "ref": {
    "urn": "urn:hahs:<class>:<id>",
    "sha": "<jcs-sha256-hex>",
    "issuer": "did:hive:hivetrust-issuer-001",
    "anchor": {
      "chain": "base",
      "tx": "0x...",
      "merkle_root": "0x...",
      "batch_index": 0
    }
  }
}
```

The `anchor` block is optional pre-finalization (batch state machine: open → rooted → finalized). Verifiers should accept `rooted` as proof of inclusion; `finalized` is required for settlement triggers.

### Reference implementations

- TS: `@hive-protocol/sdk` (npm) — `Receipt.verify()` + `Receipt.compose()`
- Python: `hive-py` (PyPI) — `hive.receipts.verify` + `hive.receipts.compose`
- Anchor worker (open spec, closed impl): https://thehiveryiq.com/sdk/anchor/

Last revised by: Steve Rotzin (HiveTrust) and Erik Newton (Concordia) 2026-05-25.

## Not in scope here

- HAHS schema specification. It lives at the canonical HiveTrust URL, and
  HiveTrust is authoritative for that payload shape.
- Live signing infrastructure. The HiveTrust pubkey endpoint is canonical at
  `https://hivetrust.onrender.com/v1/audit/pubkey`.
- A production HAHS-payload-signed fixture. That belongs in a follow-up PR once
  HiveTrust provides a signed sample over the live issuer key.
- Concordia primitive changes, spec changes, or a version bump.

## Authors

Erik Newton (Concordia Protocol). Composition pattern co-confirmed with Steve
Rotzin (`@srotzin`, HiveTrust) on 2026-05-22.
