# JS SDK Attestation Schema §9.6 Build Result

Date: 2026-06-08
Branch: `feat/js-sdk-attestation-schema-9.6`

## 2026-06-08 invariant #8 hardening update

- Closed the JS SDK attestation schema object graph with `additionalProperties: false` at the attestation root, outcome, party, behavior, meta, fulfillment, fulfillment dispute/counterparty, reference, reference extensions, and validity-temporal variant objects.
- Mirrored the same closure into the shipped Python SDK schema (`schemas/attestation.schema.json`) and the root schema copy (`attestation.schema.json`), preserving the required byte-for-byte sync.
- Kept back-compat for legitimate generated attestations by explicitly allowing the existing non-term `summary` field and known non-term reference extension keys already covered by fixtures.
- Hardened JS `$ref` handling for malformed JSON Pointers and cyclic refs so bad refs fail closed without relying on stack overflow.
- Added reject-path tests for top-level raw terms, `outcome.agreed_terms`, per-party raw price fields, and `references[].extensions` term payloads in both JS and Python.
- Added missing JS P3 reject tests for missing, malformed, external, and cyclic `$ref`, plus `oneOf` multiple-match rejection.

## 2026-06-08 gates

- `cd js-sdk && npm run typecheck`: passed.
- `cd js-sdk && npm test`: passed. 10 files, 840 passed, 2 skipped.
- `.venv/bin/pytest`: passed with local socket permission for revocation tests. 1257 passed.

## What changed

- Added minimal Draft 2020-12 `$ref` support for intra-document JSON Pointer refs (`#/...`) in `js-sdk/src/internal/jsonschema.ts`.
- Added `oneOf` support to the internal validator, sufficient for §9.6 fulfillment and temporal-validity schema variants.
- Added bundled `ATTESTATION_SCHEMA` for §9.6 reputation attestations in `js-sdk/src/validation/schemas.ts`.
- Added and exported `validateAttestation` / `isValidAttestation` through the JS SDK validation surface and package root.
- Added tests for:
  - Python-produced `validate_attestation` boundary fixture parity.
  - Valid §9.6 attestation acceptance.
  - Valid in-line fulfillment acceptance through `$ref` + `oneOf`.
  - Malformed / unknown attestation rejection.
  - Invalid date-time rejection through the Python-parity format checker.
  - Invalid `references[]` rejection through `$ref`.
  - Invalid `validity_temporal` and `fulfillment` `oneOf` rejection.
  - Direct internal `$ref` / `oneOf` behavior.

## Gates

From `js-sdk/`:

- `npm install`: passed. npm reported existing audit findings: 3 moderate, 1 critical.
- `npm run typecheck`: passed.
- `npm test`: passed. 10 test files passed, 831 tests passed, 2 skipped.

## §9.6 semantics interpreted

- `$ref` support is intentionally scoped to same-document JSON Pointer refs because §9.6 only uses `#/$defs/...`; unsupported external refs throw instead of silently under-validating.
- Python `validate_attestation` emits `UserWarning`s for schema-valid but non-canonical reference type/relationship values. The JS validation API returns error lists only, so this port preserves fail-closed schema behavior and does not add a warning side channel.
- The schema keeps attestation content limited to behavioral signals and metadata. No raw prices, quantities, or negotiated term values were added.
