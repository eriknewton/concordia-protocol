# A2A #1404 worked vector: recomputable decision_id + negative revocation vector

A byte-checkable conformance vector for the A2A capability-authorization SEP
thread (#1404). It shows two things a third party can reproduce offline from
the retained JSON in this directory:

1. A recomputable **`decision_id`**: `SHA-256` over the RFC 8785 JCS
   serialization of a canonical object binding six fields
   (`capability_digest`, `request_digest`, `boundary_id`, `verifier`,
   `policy_version`, `decision`), carried by a shipped Concordia
   **ApprovalReceipt**, Ed25519-signed, offline-verifiable from bytes.
2. A **negative revocation vector**: a parent delegation `A` and a child
   delegation `B` where `B` derives an allowed decision through `A`; a single
   status write marks `A` revoked; re-verifying the **unchanged** `B` through
   Concordia's cascade verifier yields a terminal `deny` / `revoked` /
   `no-effect` result, with the ancestor status read named in the receipt's
   evidence refs. Revocation stays propagation-free / content-addressed.

Everything uses only shipped Concordia v0.7.0a1 primitives and the shipped
RFC 8785 JCS canonicalizer. Nothing here patches or extends the SDK.

## Files

| File | What it is |
|------|------------|
| `generate.py` | Deterministic generator (fixed seeds). Rewrites every file below. |
| `verify.py` | Offline byte-check: recompute `decision_id`, sign/verify PASS, one-byte tamper REJECT, revoke, child re-verify REJECT. |
| `offer.json` | The request/offer the approver evaluated. Drives `request_digest`. |
| `capability.json` | The authorized capability. Drives `capability_digest`. |
| `decision_object.json` | The six-field #1404 decision object. `decision_id = SHA-256(JCS(this))`. |
| `approval_receipt.json` | Child delegation `B`: a shipped ApprovalReceipt carrying the decision object in its `approves` reference `extensions`. |
| `delegation_A.json` | Parent delegation `A`: a shipped ApprovalReceipt. |
| `delegation_B_candidate.json` | `B` projected as a cascade candidate artifact (references `A` via `fulfills`). Not a rewrite of `B`; the same id. |
| `revocation_A.json` | The single status write: a shipped RevocationRecord revoking `A`, scope `cascade_to_dependents`. |
| `vector.json` | Recomputable expectations: seeds, public keys, the load-bearing hashes. |

## Reproduce it

From a checkout with Concordia installed (`pip install -e .` at repo root, or
`pip install concordia==0.7.0a1`):

```
cd docs/interop/a2a-1404-receipt-revocation-vector
python generate.py      # regenerates the fixture bytes from fixed seeds
python verify.py        # byte-checks everything; exit 0 == all PASS
```

`generate.py` is fully deterministic: the Ed25519 keys come from the fixed
32-byte ASCII seeds recorded in `vector.json`
(`a2a-1404-approver-seed-000000001`,
`a2a-1404-revoc-issuer-seed-00001`), so rerunning it reproduces the same
bytes, the same signatures, and the same `decision_id`.

The receipt and delegation A carry a deliberately far-future `expires_at` (year
2126) against a contemporary `issued_at` (2026-05-10, recorded in the bytes), so
the vector verifies at any wall-clock time without a stale-expiry failure. This
is a fixture-stability choice, not a claim that a real procurement grant runs a
century; a production receipt sets a realistic window.

## The load-bearing hash values

```
decision_id        = sha256:15f84f2cf53ba52a6d0ba7d859d7c1a7bb6c21cfd5be7d036d2d998fd2eec28e
capability_digest  = sha256:dddfb8f55c9ff12ccd3ff0a5b065956b3a508b4be38eee74ad90c91c74aca932
request_digest     = sha256:2cf9882e0ceee36278318a376117cc03da510c6994c3679a57eb4777dc8e06cb
receipt.offer_hash = sha256:2cf9882e0ceee36278318a376117cc03da510c6994c3679a57eb4777dc8e06cb
```

`decision_id` is `SHA-256` of the RFC 8785 JCS bytes of `decision_object.json`.
Because JCS sorts object keys, the field order you write them in does not
matter; the hash is stable.

## Honest field mapping: native vs wrapped

The A2A #1404 decision object binds six fields. The shipped Concordia
ApprovalReceipt (`schemas/approval_receipt.schema.json`) natively carries
**two** of them; the other four are carried in a wrapper. This is stated
plainly so nobody reads the receipt as having fields it does not have.

| #1404 field | Where it lives in the receipt | Native? |
|-------------|-------------------------------|---------|
| `decision` | `scope.decision` (enum `approve` / `deny`) | **native** |
| `request_digest` | `scope.offer_hash` (`sha256:` of the JCS offer) | **native** |
| `capability_digest` | `references[0].extensions.a2a_1404_decision_object.capability_digest` | wrapped |
| `boundary_id` | `references[0].extensions.a2a_1404_decision_object.boundary_id` | wrapped |
| `verifier` | `references[0].extensions.a2a_1404_decision_object.verifier` | wrapped |
| `policy_version` | `references[0].extensions.a2a_1404_decision_object.policy_version` | wrapped |

The wrapper is the `extensions` object on the receipt's `approves` reference,
which the shipped schema explicitly permits (`extensions: { "type": "object" }`
on reference items, plus `additionalProperties: true`). It carries the full
six-field `a2a_1404_decision_object`, the precomputed
`a2a_1404_decision_id`, and `a2a_1404_evidence_refs`.

`verify.py` does not take the wrapper on faith. It asserts the equality that
makes the mapping honest:

- `receipt.scope.decision == decision_object.decision`
- `receipt.scope.offer_hash == decision_object.request_digest`
- `extensions.a2a_1404_decision_id == "sha256:" + SHA-256(JCS(decision_object))`

So the two native fields and the wrapped object are cross-checked against each
other. A receipt whose native `scope` disagreed with its embedded decision
object would fail this vector.

### The `verifier` field, specifically

`#1404`'s `verifier` is the identity of the policy verifier. The shipped
receipt has a native `approver.identity`, which in this sample is the same DID
(`did:web:acme.example#procurement-lead`). We still treat `verifier` as
**wrapped**, not native, because the receipt's `approver` is semantically "the
human/authority who approved," which is not guaranteed to equal "the policy
verifier" in every deployment. Conflating them would be an overclaim, so the
decision object carries `verifier` explicitly and `approver.identity` is left
as its native analog.

## The negative revocation vector

- **Parent `A`** (`delegation_A.json`) is a signed ApprovalReceipt.
- **Child `B`** (`approval_receipt.json`) references `A`. As a cascade
  candidate (`delegation_B_candidate.json`) it references `A` with the cascade
  relationship `fulfills`.
- The **single status write** is `revocation_A.json`: a RevocationRecord over
  `A` with scope `cascade_to_dependents`. That is the only mutation.
- Re-running the shipped `cascade_revocation` verifier over the **unchanged**
  `B` returns `B` in the inadmissible set with reason `revoked`. `B` is never
  rewritten; the terminal result flips solely because `A`'s status changed.
- The ancestor status read is **named** in
  `references[0].extensions.a2a_1404_evidence_refs.ancestor_status_read`
  (`urn:concordia:revocation:a2a-1404-A`). The revocation is content-addressed
  and propagation-free: no field inside `B` is touched to make `B`
  inadmissible.

## What `verify.py` proves (the exact sequence)

1. `decision_id` recomputes from the bytes of `decision_object.json`.
2. The native `scope` fields equal the decision object's `decision` /
   `request_digest` (mapping is checkable).
3. The signed receipt `B` verifies through the shipped
   `verify_approval_receipt`: **PASS**.
4. Flipping one byte of the signed body flips the shipped verifier to
   **REJECT** (`signature_invalid`).
5. The RevocationRecord verifies under the issuer key.
6. After the single status write, the shipped `cascade_revocation` marks the
   unchanged child `B` inadmissible/`revoked`: **REJECT**.

Author: Erik Newton.
