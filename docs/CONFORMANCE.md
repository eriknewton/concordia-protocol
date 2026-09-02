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

<!-- not-a-claim -->

## What this document covers

This page lists the conformance claims Concordia makes about itself and the check that enforces
each one. It is generated from `docs/claims.yaml`. A claim reaches this page only after something
exists that fails when the claim stops matching the repository. The suite behind it is specified
in `conformance/RUNNER_CONTRACT.md`, with more than a thousand vectors executed by two reference
runners in independent languages, and `README.md` carries a copy-paste verification block.

Three things sit outside it.

**Scoring.** Concordia defines how a negotiation record is formed, signed, and verified. How any
service turns those records into a reputation score, including which signals it weights, how it
decays them, and what it forgives, is outside this specification. This page makes no statement
about any scoring model, including Verascore's, a service written by the author of this
specification (see Disclosure below).

**Enforcement.** Concordia describes artifacts and how to verify them. Whether an agent runtime
confines what an agent can reach at execution time is a separate concern, handled by separate
software. Nothing in the specification requires any particular runtime.

**Stewardship.** As of 2026-08-01, Concordia has one editor, Erik Newton. This page describes the
specification's checkable properties and takes no position on how the specification should be
governed in future.

## Disclosure

The author of this specification also authors Verascore, a reputation service that consumes
Concordia records, and Sanctuary, an agent runtime. The reference Python SDK ships an optional,
off-by-default adapter for Verascore (`concordia.verascore`), disclosed in `SPEC.md` §9.6.7. No
conformance runner imports or invokes it, and the clean-room CI jobs assert the Concordia SDK
itself is absent from the runner's import path. Agent-profile vectors do carry legacy field names
beginning `verascore_`, with `reputation.example` as their sample provider: the SDK retains those
fields for signature compatibility with records issued before its provider-neutral reputation
fields landed, and the specification defines none of them.

None of this asks to be taken on trust. CI executes every check on this page from a fresh checkout
on every push, page generation fails if a referenced CI job disappears, and the adapter and field
statements above can be checked by grepping a clone.

## Where independence stands, as of 2026-08-01

Both shipped implementations, the Python SDK and the TypeScript SDK, are written by the author of
this specification. One separate implementation has byte-reproduced one published vector, and that
reproduction is recorded in `docs/interop/`. A full independent implementation of the
specification does not exist today. Closing that gap is deliberately cheap: the smallest profile
in `conformance/IMPLEMENTATIONS.md` is roughly 20 lines in most languages, and a reported
conformance run gets a registry row.

This section carries a date because it describes a state that is expected to change.

<!-- /not-a-claim -->


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

> The conformance vectors verify without the Concordia SDK: the reference runner installs only RFC 8785, PyNaCl, JSON Schema, and the Python standard library, then executes the public vector manifest.

Stated in: `conformance/RUNNER_CONTRACT.md`

Enforced by: CI job `conformance-clean-room`

Verify:

```bash
pip install rfc8785 pynacl jsonschema
python conformance/reference-runner/runner.py conformance/vectors/
```

### `vectors-verify-under-two-independent-runners`

Claim:

> The same conformance vector manifest is executed to the same totals by two first-party-authored reference runners in independent languages: Python and Node.js. This is not third-party verification.

Stated in: `conformance/RUNNER_CONTRACT.md`

Enforced by: CI job `conformance-clean-room-js`

Verify:

```bash
npm ci --prefix conformance/reference-runner-js
node conformance/reference-runner-js/runner.mjs conformance/vectors/
```

### `receipt-set-binding`

Claim:

> A 0.3.0 receipt binds the transcript set, chain head and message count, inside its countersigned preimage, and the conformance suite rejects splice and truncation against it.

Stated in: `conformance/RUNNER_CONTRACT.md`

Enforced by: `scripts/claims/receipt_set_binding_vectors.py`

Verify:

```bash
python scripts/claims/receipt_set_binding_vectors.py
```

### `adapter-not-exercised`

Claim:

> No conformance vector or reference runner imports or invokes the optional `concordia.verascore` adapter.

Stated in: `conformance/RUNNER_CONTRACT.md`

Enforced by: `scripts/claims/adapter_not_exercised.py`

Verify:

```bash
python scripts/claims/adapter_not_exercised.py
```

### `erdl-v15-runner-pins-its-corpus`

Claim:

> The runner's CLI refuses any vector file whose SHA-256 is not the pinned upstream digest, and writes no submission envelope for either a refused input or a completed run with failed outcome/accounting invariants. A substituted same-version corpus and a red run therefore fail closed before a publishable artifact is produced.

Stated in: `conformance/erdl-do-v1.5/README.md`

Enforced by: CI job `test`

Verify:

```bash
pip install -e ".[dev]"
npm ci --prefix conformance/reference-runner-js
pip install pip-audit && pip-audit --requirement requirements.lock --ignore-vuln CVE-2026-4539
pytest -v
bash scripts/test-floor.sh
```
