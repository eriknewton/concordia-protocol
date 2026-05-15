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
