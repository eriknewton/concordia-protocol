## Summary

Fixes audit finding L1 from `Review/Concordia/Concordia_Security_Audit_2026-06-09.md`: ES256 ECDSA signature malleability could allow `(r, n-s)` substitution, changing transcript chain hashes because Concordia hashes the `signature` field.

- Normalizes Python ES256 signatures to low-S when signing.
- Rejects high-S ES256 signatures before cryptographic verification.
- Applies the same ES256 handling to the trust-evidence envelope path that bypasses `sign_message`.
- Adds regression coverage for low-S acceptance, high-S rejection, signer output canonicalization, and `(r, n-s)` malleation rejection.

## JS SDK parity

No JS SDK ES256 implementation was changed because the SDK is EdDSA-only for signing:

- `js-sdk/src/crypto/signing.ts:1-23` documents the crypto layer as Ed25519 only and explicitly says ES256 is out of scope.
- `js-sdk/src/mandate/engine.ts:48-53` documents ES256 as deferred.
- `js-sdk/src/mandate/engine.ts:113-123` rejects ES256 signing rather than implementing a partial second-curve path.

## Tests

- `.venv/bin/python -m pytest tests/test_signing.py tests/test_envelope.py` -> `87 passed`
- `.venv/bin/python -m pytest` -> `1438 passed`

Note: the first full-suite run inside the sandbox failed only because three revocation tests bind a local `127.0.0.1` HTTP server and the sandbox denied socket binding. The rerun outside the sandbox passed.
