# A2CN Fulfillment-Attestation Integration

Integrator-facing walkthrough for emitting a Concordia-shaped
**Fulfillment Attestation** when an A2CN session reaches
`DELIVERY_ACKNOWLEDGED`. Pairs with `schemas/fulfillment_attestation.schema.json`
and SPEC.md §9.6.4. Adds the v0.5 `ApprovalReceipt` artifact type for
HITL pause-resume composition with A2CN Section 14 (per A2A
Discussion #1737).

A2CN cross-protocol references use the SPEC.md §11.5.7 URN forms
`urn:a2cn:session:<session_id>` and `urn:a2cn:mandate:<mandate_id>` in new
artifacts. Older `a2cn:*` identifiers remain readable for compatibility.

## Two fulfillment shapes — when to use which

Concordia v0.5 supports two fulfillment-recording patterns. They are
NOT alternatives — they cover different boundaries.

### 1. In-line fulfillment block on a reputation attestation (SPEC §9.6.4)

The original pattern. ONE attestation per session; the `fulfillment`
field starts `null` and is populated after settlement. Both parties
countersign the COMBINED attestation. Status enum:
`fulfilled | partial | unfulfilled | disputed | pending`.

Use this when:

- Settlement and the negotiation outcome land on the same record.
- Both counterparties are willing to countersign one combined
  artifact.
- You're a Concordia-native flow without a discrete delivery event.

### 2. Standalone Fulfillment Attestation (v0.5, this doc)

A separate signed artifact. Emitted on a discrete delivery boundary
(e.g., A2CN's `DELIVERY_ACKNOWLEDGED`). Links back to the agreement
attestation via `references[]` with `relationship: "fulfills"`.
Status enum: `fulfilled_clean | fulfilled_with_mediation | failed | disputed_unresolved`.

Use this when:

- The settlement protocol fires a discrete delivery-acknowledged
  event you want to attest at that boundary.
- The fulfillment is signed by a different party (e.g., a delivery
  agent or a mediator) than the negotiation counterparties.
- You're A2CN-integrating and want the fulfillment artifact to map
  cleanly to a single A2CN session-state transition.

## Status enum mapping

When a verifier consumes both shapes, the mappings are:

| Standalone (`fulfillment.status`) | In-line block (§9.6.4) |
|---|---|
| `fulfilled_clean` | `fulfilled` with `mediator_invoked: false` |
| `fulfilled_with_mediation` | `fulfilled` with `mediator_invoked: true` |
| `failed` | `unfulfilled` |
| `disputed_unresolved` | `disputed` |

`partial` from §9.6.4 has no exact analog in the standalone enum;
producers SHOULD represent partial outcomes as `fulfilled_with_mediation`
with `meta.resolution_outcome` carrying a short label (e.g.,
`partial_refund`). v0.6 may add a `fulfilled_partial` status if
operator demand warrants.

## DELIVERY_ACKNOWLEDGED → Fulfillment Attestation flow

```
A2CN session                          Concordia
============                          =========

[ACTIVE]
  ...negotiation messages...
  → agreement reached
  → AgreementAttestation signed       ← Concordia attestation #1 (no
                                        fulfillment block yet)

[AWAITING_DELIVERY]
  ...payment + delivery off-band...

DELIVERY_ACKNOWLEDGED event fires
  →                                   FulfillmentAttestation built:
                                        - attestation_type: "FulfillmentAttestation"
                                        - id: urn:concordia:fulfillment:<uuid>
                                        - issued_at: now()
                                        - agreement_attestation_id: <id of #1>
                                        - fulfillment.status: per outcome
                                        - references[]: at least one
                                          entry with relationship "fulfills"
                                          pointing at the agreement
                                          attestation, plus optional
                                          references to A2CN session,
                                          delivery evidence, mediator
                                          decision
                                        - signature: Ed25519 over the
                                          canonicalized JSON

[COMPLETED]
```

## Minimal required fields (Christian's checklist)

Every Concordia-shaped Fulfillment Attestation MUST carry:

1. `attestation_type` — literal `"FulfillmentAttestation"`
2. `id` — URN-shaped per SPEC §11.5.7
3. `issued_at` — ISO 8601
4. `agreement_attestation_id` — denormalized pointer
5. `fulfillment.status` — one of the four enum values
6. `references[]` — at least one entry with `relationship: "fulfills"`
7. `signature` — Ed25519 over canonicalized JSON

Optional `meta` fields (populate when applicable):

- `meta.mediator_invoked` (boolean — MUST be `true` if `status` is `fulfilled_with_mediation`)
- `meta.resolution_outcome` (short label)
- `meta.resolver_did`
- `meta.resolution_timestamp`
- `meta.fulfillment_evidence` (array of URN-shaped pointers)

The full schema is `schemas/fulfillment_attestation.schema.json` (`$id`
`urn:concordia:schema:fulfillment_attestation:v0.5`).

## Worked example — fulfilled_clean

```json
{
  "attestation_type": "FulfillmentAttestation",
  "id": "urn:concordia:fulfillment:f0e1d2c3-b4a5-4796-8877-665544332211",
  "issued_at": "2026-05-11T18:42:00Z",
  "agreement_attestation_id": "att_4f8e7d6c5b4a39280102030405060708",
  "fulfillment": {
    "status": "fulfilled_clean",
    "settled_at": "2026-05-11T18:30:00Z"
  },
  "references": [
    {
      "type": "attestation",
      "id": "att_4f8e7d6c5b4a39280102030405060708",
      "relationship": "fulfills"
    },
    {
      "type": "chain_session",
      "id": "urn:a2cn:session:9e4d2c11",
      "relationship": "references"
    }
  ],
  "meta": {
    "mediator_invoked": false
  },
  "signature": {
    "alg": "Ed25519",
    "value": "<base64-ed25519-signature>"
  }
}
```

## Worked example — fulfilled_with_mediation

```json
{
  "attestation_type": "FulfillmentAttestation",
  "id": "urn:concordia:fulfillment:aa11bb22-cc33-dd44-ee55-ff6677889900",
  "issued_at": "2026-05-13T09:15:00Z",
  "agreement_attestation_id": "att_9a8b7c6d5e4f30210405060708090a0b",
  "fulfillment": {
    "status": "fulfilled_with_mediation",
    "settled_at": "2026-05-13T09:00:00Z"
  },
  "references": [
    {
      "type": "attestation",
      "id": "att_9a8b7c6d5e4f30210405060708090a0b",
      "relationship": "fulfills"
    },
    {
      "type": "chain_session",
      "id": "urn:a2cn:session:7c2a1b09",
      "relationship": "references"
    }
  ],
  "meta": {
    "mediator_invoked": true,
    "resolution_outcome": "partial_refund",
    "resolver_did": "did:web:mediator.example#authority-1",
    "resolution_timestamp": "2026-05-13T08:55:00Z",
    "fulfillment_evidence": [
      "urn:a2cn:delivery_receipt:5a4b3c2d",
      "urn:concordia:mediator_decision:mediator-2026-05-12-0042"
    ]
  },
  "signature": {
    "alg": "Ed25519",
    "value": "<base64-ed25519-signature>"
  }
}
```

## Worked example — failed (delivery not honored)

```json
{
  "attestation_type": "FulfillmentAttestation",
  "id": "urn:concordia:fulfillment:de4d-beef-0000-1111",
  "issued_at": "2026-05-20T14:00:00Z",
  "agreement_attestation_id": "att_bbccddee0011223344556677aabbccdd",
  "fulfillment": {
    "status": "failed",
    "settled_at": "2026-05-20T13:55:00Z"
  },
  "references": [
    {
      "type": "attestation",
      "id": "att_bbccddee0011223344556677aabbccdd",
      "relationship": "fulfills"
    },
    {
      "type": "chain_session",
      "id": "urn:a2cn:session:e7f60a11",
      "relationship": "references"
    }
  ],
  "meta": {
    "mediator_invoked": false,
    "resolution_outcome": "delivery_window_elapsed"
  },
  "signature": {
    "alg": "Ed25519",
    "value": "<base64-ed25519-signature>"
  }
}
```

## ApprovalReceipt — HITL pause-resume composition

For A2CN Section 14 HITL flows (operator pauses negotiation when an
amount crosses a policy threshold; operator approves or denies; A2CN
resumes), Concordia v0.5 ships a separate artifact: **ApprovalReceipt**.
Schema: `schemas/approval_receipt.schema.json` (`$id`
`urn:concordia:schema:approval_receipt:v0.5`). Spec section: SPEC.md
§9.6.4b.

Worked example (matches A2A Discussion #1737 Draft A):

```json
{
  "artifact_type": "ApprovalReceipt",
  "id": "urn:concordia:receipt:7f2e1a93",
  "issued_at": "2026-05-10T14:22:08Z",
  "expires_at": "2026-05-10T15:22:08Z",
  "approver": {
    "identity": "did:web:acme.example#procurement-lead",
    "role": "procurement_authority"
  },
  "scope": {
    "decision": "approve",
    "offer_hash": "sha256:b4c1...e09f",
    "amount": "150000.00 USD",
    "threshold_crossed": "100000.00 USD"
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

### ApprovalReceipt invariants

- `expires_at` is mandatory at v0.5; verifiers MUST reject expired
  receipts at verification time.
- `scope.decision` is `approve` or `deny`. A `deny` receipt is
  cryptographically binding the same way an `approve` is — the
  counterparty cannot retry the same offer without crossing the
  threshold afresh.
- `scope.offer_hash` is the sha256 of the canonicalized offer the
  approver evaluated. Re-canonicalize on-the-wire offers at verify
  time and compare.
- `references[]` SHOULD carry `relationship: "approves"` for the
  negotiation session and `relationship: "fulfills"` for any
  pre-existing mandate the approval discharges.

## Cross-references

- `schemas/fulfillment_attestation.schema.json` — Fulfillment Attestation schema
- `schemas/approval_receipt.schema.json` — ApprovalReceipt schema
- `SPEC.md` §9.6.4 — In-line fulfillment block (original pattern)
- `SPEC.md` §9.6.4a — Standalone Fulfillment Attestation (v0.5)
- `SPEC.md` §9.6.4b — ApprovalReceipt (v0.5)
- `SPEC.md` §11.5 — Reference linkages (envelope vs. attestation level)
- `SPEC.md` §11.5.5 — Relationship vocabulary (`supersedes`, `extends`,
  `fulfills`, `references`)
- `SPEC.md` §11.5.7 — URN schemes for cross-protocol linkage
- A2A Discussion #1737 Draft A — public commit underlying v0.5
  ApprovalReceipt + Fulfillment Attestation work
