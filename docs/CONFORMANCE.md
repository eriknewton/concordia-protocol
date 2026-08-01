# Concordia Conformance Claims

GENERATED FILE. Source: `docs/claims.yaml`.

Regenerate with:

```bash
python scripts/claims/generate_conformance.py
```

Check committed output with:

```bash
python scripts/claims/generate_conformance.py --check
```

This file is a projection of the claims manifest.
Every listed claim has a manifest check. The check is the failure point when the claim stops matching the repository.

## Claims

### `implementable-from-spec-alone`

Claim:

> An LLM agent should be able to implement Concordia from reading this specification alone, with no external documentation.

Stated in: `SPEC.md`

Enforced by: `scripts/claims/no_external_normative_deps.py`

Verify:

```bash
python scripts/claims/no_external_normative_deps.py
```

### `canonical-json-is-rfc-8785`

Claim:

> Wherever this specification says "canonical JSON", "canonicalized JSON", or "JCS", it means the JSON Canonicalization Scheme defined in [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785).

Stated in: `SPEC.md`

Enforced by: `scripts/claims/rfc_sections_cited.py`

Verify:

```bash
python scripts/claims/rfc_sections_cited.py
```

### `offline-no-issuer-callback`

Claim:

> No network, no regeneration, no issuer callback:

Stated in: `README.md`

Enforced by: `scripts/claims/offline_resolution.py`

Verify:

```bash
python scripts/claims/offline_resolution.py
```

### `verification-without-our-code`

Claim:

> What the vectors do establish is that the parts they cover are checkable without our code and without asking us.

Stated in: `README.md`

Enforced by: CI job `clean-room-verify`

Verify:

```bash
pip install rfc8785 pynacl
python scripts/claims/clean_room_verify.py docs/interop/
```

### `fixture-digests-recomputed`

Claim:

> Every digest a fixture publishes is recomputed from the fixture bytes by that fixture's `verify.py` and compared, and the digests used for signature and revocation checks are additionally cross-checked against the independent `rfc8785` reference library in CI (`tests/test_interop_fixtures.py`).

Stated in: `docs/interop/README.md`

Enforced by: `scripts/claims/fixture_verifiers_recompute.py`

Verify:

```bash
python scripts/claims/fixture_verifiers_recompute.py
```

### `conformance-vectors-verify-without-our-sdk`

Claim:

> The Phase 1 conformance vectors verify without the Concordia SDK: the reference runner installs only RFC 8785, PyNaCl, JSON Schema, and the Python standard library, then executes the public vector manifest.

Stated in: `conformance/RUNNER_CONTRACT.md`

Enforced by: CI job `conformance-clean-room`

Verify:

```bash
pip install rfc8785 pynacl jsonschema
python conformance/reference-runner/runner.py conformance/vectors/
```
