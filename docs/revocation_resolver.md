# Predicate Revocation Resolver

v0.6 keeps `revocation_endpoint` as a URL string in the predicate schema. The response shape below is an implementation recommendation, not protocol schema. It is the proposed v0.7 convergence target after two runtimes implement it.

## Per-Id JSON Probe

```json
{
  "predicate_id": "urn:concordia:predicate:pred_001",
  "status": "revoked",
  "revoked_at": "2026-05-14T12:00:00Z",
  "reason": "issuer_policy_revocation"
}
```

Resolvers should treat `status: "revoked"` or a non-null `revoked_at` as revoked.

## Status-List-2021-Compatible Variant

```json
{
  "predicate_id": "urn:concordia:predicate:pred_001",
  "status_list_credential": "https://issuer.example/status/2026/list.json",
  "status_list_index": "9238",
  "status_purpose": "revocation"
}
```

Resolvers can dereference the status-list credential and map a set bit to revoked.

## CRL-Compatible Variant

```json
{
  "predicate_id": "urn:concordia:predicate:pred_001",
  "crl": "https://issuer.example/predicates/revocations.crl",
  "serial": "pred_001"
}
```

Resolvers can check the CRL serial list and surface `revoked_at` when the CRL source provides it.

## Composition with RevocationRecord (v0.7+)

The per-id JSON probe response MAY include a signed
`urn:concordia:revocation:<id>` artifact in addition to the existing `status`
and `revoked_at` fields.

```json
{
  "predicate_id": "urn:concordia:predicate:pred_001",
  "status": "revoked",
  "revoked_at": "2026-05-14T12:00:00Z",
  "reason": "issuer_policy_revocation",
  "revocation_record": {
    "revocation_id": "urn:concordia:revocation:rev_001",
    "revoked_artifact_id": "urn:concordia:predicate:pred_001",
    "revoked_artifact_type": "predicate",
    "revocation_scope": "single_artifact",
    "issuer_did": "did:web:issuer.example",
    "issued_at": "2026-05-14T12:00:00Z",
    "effective_at": "2026-05-14T12:00:00Z",
    "reason": "issuer_policy_revocation",
    "references": [
      {
        "id": "urn:concordia:predicate:pred_001",
        "type": "predicate",
        "relationship": "revokes"
      }
    ],
    "cascade_depth": 3,
    "signature": {
      "alg": "EdDSA",
      "value": "..."
    }
  }
}
```

This is backward compatible. Existing clients can continue to use `status` and
`revoked_at`. v0.7+ clients can verify the signed RevocationRecord and run the
cross-mandate cascade locally.
