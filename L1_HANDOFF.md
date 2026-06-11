# L1 Handoff: ES256 Low-S Enforcement

Starting HEAD: `c920813c5b632a44a2969b8425d1051092b1bc36`

## What Changed

- Added P-256 order constants and ES256 DER helpers in `concordia/signing.py`.
- `sign_message(..., alg="ES256")` now normalizes ECDSA signatures to low-S.
- `verify_signature(..., alg="ES256")` now rejects high-S signatures before calling `public_key.verify`.
- `concordia/envelope.py` now uses the same low-S normalization/rejection for its direct ES256 envelope signing and verification path.
- Documented the low-S requirement in the `concordia.signing` module docstring because transcript hashes include the signature field.

## Boundaries Honored

- Did not change `compute_hash`.
- Did not change canonical JSON/canonical bytes.
- Did not change the EdDSA path.
- Did not push, open a PR, or merge.

## JS SDK Parity

The JS SDK has no ES256 signing path to patch:

- `js-sdk/src/crypto/signing.ts:1-23` is Ed25519-only and explicitly says ES256 is out of scope.
- `js-sdk/src/mandate/engine.ts:48-53` says ES256 is deferred until the crypto layer ports it.
- `js-sdk/src/mandate/engine.ts:113-123` rejects ES256 signing fail-closed.

## Verification

- Targeted: `.venv/bin/python -m pytest tests/test_signing.py tests/test_envelope.py` -> `87 passed`
- Full suite: `.venv/bin/python -m pytest` -> `1438 passed`

The sandboxed full-suite attempt produced 3 environmental failures in `tests/test_mandate.py::TestRevocation` because socket binding to `127.0.0.1` was denied. The same command passed outside the sandbox.
