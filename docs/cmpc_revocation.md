# CMPC Revocation

`RevocationRecord` is the artifact-side primitive for v0.7 cross-mandate
promise-chain revocation. It is signed, portable, and can be verified without a
live resolver. `docs/revocation_resolver.md` describes service-side probe
formats. The two compose: a verifier can query a resolver, receive a signed
RevocationRecord, and evaluate the cascade locally.

## Record Shape

```python
from concordia.cmpc import RevocationRecord

record = RevocationRecord(
    revocation_id="urn:concordia:revocation:def",
    revoked_artifact_id="urn:a2cn:mandate:xyz",
    revoked_artifact_type="mandate",
    revocation_scope="cascade_to_dependents",
    issuer_did="did:web:principal.example",
    issued_at="2026-05-30T14:30:00Z",
    effective_at="2026-05-30T14:30:00Z",
    reason="policy_rotated",
    references=[
        {
            "id": "urn:a2cn:mandate:xyz",
            "type": "mandate",
            "relationship": "revokes",
        }
    ],
)
```

Sign and verify:

```python
from concordia.cmpc import sign_revocation_record, verify_revocation_record
from concordia.signing import KeyPair

key_pair = KeyPair.generate()
signed = sign_revocation_record(record, key_pair)
assert verify_revocation_record(signed, key_pair.public_key)
```

## Cascade Evaluation

```python
from concordia.cmpc import CandidateArtifact, cascade_revocation

receipt = CandidateArtifact(
    artifact_id="urn:concordia:receipt:abc",
    artifact_type="approval_receipt",
    references=[
        {
            "id": "urn:a2cn:mandate:xyz",
            "type": "mandate",
            "relationship": "fulfills",
        }
    ],
)

result = cascade_revocation(signed, [receipt])
for item in result.inadmissible:
    print(item.artifact_id, item.reason, item.evidence)
```

Cascade traversal follows only `fulfills`, `extends`, `approves`, and
`revokes`. It does not follow `references` or `supersedes`. Depth is bounded by
`cascade_depth`, default 3 and max 8. Cycle detection is mandatory.

## Verifier Integration

Predicates and ApprovalReceipts accept an optional `revocation_records` mapping
keyed by revoked artifact id.

```python
from concordia.predicate import verify_predicate

result = verify_predicate(
    predicate,
    revocation_records={
        signed.revoked_artifact_id: signed,
    },
)
assert result.failure_reason == "revoked"
```

```python
from concordia.approval_receipt import verify_approval_receipt

result = verify_approval_receipt(
    receipt,
    offer,
    issuer_public_key=issuer_public_key,
    revocation_records={
        signed.revoked_artifact_id: signed,
    },
)
assert result.failure_reason == "revoked"
```

## giskard09 Scenario

The conformance fixture at
`tests/fixtures/revocation/giskard09-mid-execution-rotation.json` captures the
mid-execution rotation case:

1. At `2026-05-30T14:00:00Z`, ApprovalReceipt
   `urn:concordia:receipt:abc` references mandate `urn:a2cn:mandate:xyz` via
   `fulfills`.
2. At `2026-05-30T14:30:00Z`, the principal issues RevocationRecord
   `urn:concordia:revocation:def` revoking the mandate.
3. At `2026-05-30T14:45:00Z`, the receipt has not expired, but the mandate is
   revoked. The cascade result marks the receipt inadmissible with
   `PredicateFailureReason.REVOKED`.
