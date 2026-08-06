# A2A #1734 worked vector: a signed receipt that binds its decision context

A byte-checkable conformance vector for the trust-evidence-format thread
(#1734), covering the `context_digest` field that giskard09 added to
`decision-binding-ref-v1.0`. It shows two things a third party can reproduce
offline from the retained JSON in this directory.

**1. giskard09's published vectors recompute under an independent
canonicalizer.** Their four conformance vectors (`cd-001` .. `cd-004`), both of
their published context sets, and the four inline fixtures in
`decision-binding-ref-v1.0.md` are recomputed here with Concordia's own RFC
8785 JCS implementation, and again with the independent `rfc8785` reference
library. Canonical bytes are compared as well as digests, because equal digests
over different bytes would be a collision claim rather than an agreement. The
retained copy of their fixture lives at
[`docs/external/giskard09-decision-binding-context-digest-v1/`](../../external/giskard09-decision-binding-context-digest-v1/),
byte-verbatim and pinned by SHA-256.

**2. The binding survives being signed.** A shipped Concordia ApprovalReceipt
carries a `decision_binding_ref` preimage, `context_digest` included, inside its
`approves` reference. A verifier holding the presented context set recomputes
`SHA-256(JCS(assembled_context))` and compares it against the value the receipt
signed. Presenting a context set with one artifact silently dropped diverges and
must be rejected (`CONTEXT_SET_MISMATCH`). Substituting the smaller set's digest
into the receipt, and re-deriving the ref so the artifact stays internally
consistent, is the forgery a digest-only check accepts; the Ed25519 signature
covers the embedded preimage, so the shipped verifier rejects it.

Everything uses shipped Concordia primitives and the shipped RFC 8785 JCS
canonicalizer. Nothing here patches or extends the SDK.

## Files

| File | What it is |
|------|------------|
| `generate.py` | Deterministic generator (fixed seed). Rewrites every file below. |
| `verify.py` | Offline byte-check: recompute giskard09's vectors, recompute this fixture's digests, verify the signed receipt through the shipped verifier, `CONTEXT_SET_MISMATCH` on a dropped artifact, stale-digest substitution REJECT, one-byte tamper REJECT, and seed-derived key and signature. Exit 0 == all PASS. |
| `offer.json` | The action the approver evaluated. Drives both `scope.offer_hash` and `action_ref`. |
| `assembled_context.json` | The context set that fed the decision. Drives `context_digest`. Taken verbatim from giskard09's `context_full`. |
| `assembled_context_dropped_artifact.json` | The same set with one memory silently dropped. The `CONTEXT_SET_MISMATCH` case. |
| `decision_binding_preimage.json` | The four-field preimage per `decision-binding-ref-v1.0`. `decision_binding_ref = SHA-256(JCS(this))`. |
| `approval_receipt.json` | A shipped ApprovalReceipt carrying the preimage and the ref in its `approves` reference `extensions`. |
| `vector.json` | Recomputable expectations: the PUBLIC test-only signing seed (`signing_seeds_PUBLIC_test_only_do_not_reuse`, never reuse), the public key, every published hash, and the cross-check values. |

## Reproduce it

From a checkout with Concordia installed (`pip install -e .` at repo root):

```
cd docs/interop/a2a-1734-context-digest-receipt
python generate.py      # regenerates the fixture bytes from the fixed seed
python verify.py        # byte-checks everything; exit 0 == all PASS
```

`generate.py` is fully deterministic: the Ed25519 key comes from the fixed
32-byte ASCII seed recorded in `vector.json`. Rerunning it produces
byte-identical output, so a drifted byte shows up as a diff rather than as a
different signature over content nobody compared.

The same artifacts are also exercised as conformance vectors
(`pos-1734-receipt-signed-binding`, `pos-1734-context-digest-recomputes`,
`pos-1734-decision-binding-ref-recomputes`, and the
`binding-1734-context-set-mismatch` reject vector) by both reference runners
under [`conformance/`](../../../conformance/), and by
`tests/test_a2a_1734_context_digest_interop.py` in CI.

## Native versus wrapped fields

The receipt carries two kinds of binding and they are different in kind. Read
the table before citing any value from this fixture.

| Field | Kind | Meaning |
|-------|------|---------|
| `scope.offer_hash` | native | Concordia's own binding to the action. The shipped verifier recomputes it and rejects the receipt when it diverges. |
| `scope.decision` | native | The approver's decision, enforced by the receipt schema. |
| `extensions.a2a_1734_decision_binding_ref` | wrapped | `SHA-256(JCS(preimage))` per `decision-binding-ref-v1.0`. Recomputed by `verify.py` and by the conformance vectors, and covered by the receipt signature. It is not a field the shipped Concordia verifier knows about. |
| `extensions.a2a_1734_decision_binding_preimage` | wrapped | The four-field preimage. Every field of it is derivable from bytes in this directory. |
| `extensions.a2a_1734_decision_binding_spec` | wrapped | A pointer to the external spec, at a pinned commit. |

`action_ref` inside the preimage is `SHA-256(JCS(offer.json))`, the same digest
`scope.offer_hash` carries. That equality is a binding `verify.py` checks rather
than a coincidence the fixture relies on.

## What this fixture does not claim

- It is **not** third-party verification of Concordia. giskard09 authored the
  vectors; this repository authored the recompute and the receipt. Two
  independently authored artifacts agreeing is evidence about the
  canonicalization, and it is a weaker claim than an outside audit.
- The receipt's preimage is this fixture's own, keyed to giskard09's published
  derivation and sharing their `context_digest`. It is a different action from
  their `cd-001`, so its `decision_binding_ref` is a different value, by
  construction. `verify.py` recomputes their `cd-001` ref separately, from the
  retained bytes.
- `context_digest` proves that a set of artifacts was present in a decision's
  input. It resolves neither attribution nor steering: which artifact caused
  which part of the outcome stays an open question, the same way `action_ref`
  proves content without proving intent.

## Privacy

The receipt binds a digest of the context set. It carries no artifact content
and no artifact identifiers; those live in `assembled_context.json`, which a
verifier is presented separately and which the receipt commits to only by hash.
Concordia's privacy invariant applies here the same way it applies to
attestations, and `tests/test_a2a_1734_context_digest_interop.py` asserts it.

Author: Erik Newton.
