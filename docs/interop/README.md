# Concordia interop fixtures

Byte-checkable worked vectors that a third party can reproduce and verify
offline against the shipped Concordia SDK. Each directory ships the fixture
bytes, a deterministic `generate.py`, a `verify.py` that round-trips the bytes
through the shipped verifier, and a README with the honest field mapping.

| Directory | A2A thread | What it proves |
|-----------|------------|----------------|
| [`a2a-1404-receipt-revocation-vector/`](a2a-1404-receipt-revocation-vector/) | #1404 (capability-authorization SEP) | Recomputable `decision_id = SHA-256(JCS(six-field object))` on a shipped ApprovalReceipt, plus a negative revocation vector: revoke parent `A` with one status write, unchanged child `B` re-verifies to `revoked` through the shipped cascade verifier. |
| [`a2a-1920-fulfillment-sample/`](a2a-1920-fulfillment-sample/) | #1920 (v0.4 transactional per-action receipts) | A shipped-shape FulfillmentAttestation keyed on `charge_ref` / `action_ref`, behavioral-signal + hash-reference only, with the SPEC §9.6.6 privacy invariant proven by scanning the artifact with the SDK's own raw-term detectors. |

Every fixture is deterministic (fixed Ed25519 seeds, documented in each
directory's expectations file) and uses only shipped Concordia v0.7.0a1
primitives and the shipped RFC 8785 JCS canonicalizer. No fixture patches or
extends the SDK.

**Recorded values are expectations, never sources.** Every digest a fixture
publishes is recomputed from the fixture bytes by that fixture's `verify.py`
and compared, and the load-bearing digests are additionally cross-checked
against the independent `rfc8785` reference library in CI
(`tests/test_interop_fixtures.py`). A published digest that no verifier derives
would be an answer key rather than a test: a regressed implementation deriving
the wrong value would go uncaught, because nothing would compare.

## Run all verifiers

```
for d in docs/interop/*/; do
  [ -f "$d/verify.py" ] && (cd "$d" && python verify.py) || true
done
```

Author: Erik Newton.
