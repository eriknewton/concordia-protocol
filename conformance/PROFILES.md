# Concordia Conformance Profiles

## `receipt-transcript-binding-v1`

Normative sources:

- `SPEC.md` Section 9.6.5b, Receipt Set-Binding.
- `conformance/RUNNER_CONTRACT.md`, `message-chain-v1`, Receipt Set-Binding
  (`claim:receipt-set-binding`).

The profile name identifies the receipt set-binding check already exercised by
the public suite. A conforming verifier follows `message-chain-v1` when the
input carries both `messages` and `receipt`.

Checks covered by this profile:

- message-chain links and message signatures;
- receipt party signatures and countersignatures;
- `message_count` against the presented transcript length;
- `chain_head` against the final message hash;
- legacy receipts below attestation 0.3.0 reported as `legacy_set_unbound`;
  set-bound credit starts at attestation 0.3.0.

Vectors:

- positive: `pos-synthetic-receipt-set-binding`;
- mutations: `mut-synthetic-receipt-set-binding-0001` through
  `mut-synthetic-receipt-set-binding-0004`;
- canary: `canary-receipt-set-unchecked`.

Reference implementations:

- Python: `conformance/reference-runner/runner.py`;
- Node.js: `conformance/reference-runner-js/runner.mjs`.

The executable claim is `receipt-set-binding` in `docs/claims.yaml`.
`scripts/claims/receipt_set_binding_vectors.py` checks that the named vectors
exist and exercise the binding.
