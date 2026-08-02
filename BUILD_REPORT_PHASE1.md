# Chain Completeness B - Phase 1 Build Report

Date: 2026-08-02
Worktree: `/Users/eriknewton/Code/Claude/Concordia-worktrees/chain-completeness-b`
Scope executed: Step 1 and Phase 1 only.

No git commands were run.

## Step 1 Probes

All required pre-edit probes were executed and saved under `probes/`:

- `probes/step1-receipt-fields.txt`: current public SDK receipt had `transcript_hash` present and `chain_head` / `message_count` absent. Result: PASS.
- `probes/step1-bridge-chain-head.txt`: bridge-derived value equaled `compute_hash(session.transcript[-1])` and was `sha256:` prefixed. Result: PASS.
- `probes/step1-resigned-splice.txt`: same-signer re-signed splice passed `validate_chain`, while the original and spliced final message hashes differed. Result: PASS.

## Phase 1 Changes

- Updated SPEC attestation fields to define `chain_head` and `message_count`, including the honest-window note: link signatures authenticate links, and the closing receipt binds the set.
- Bumped Python and JS attestation version constants to `0.3.0`.
- Python issuer now adds `chain_head = compute_hash(session.transcript[-1])` and `message_count = len(session.transcript)` inside the countersigned attestation preimage.
- Python verifier now version-gates receipt set-binding:
  - `>=0.3.0` requires well-formed `chain_head` and `message_count`.
  - If a transcript is supplied, head and count mismatches invalidate the receipt.
  - `<0.3.0` is reported as `legacy_set_unbound`.
- Receipt-bundle verification now evaluates set-binding state for bundled attestations.
- Envelope `source_session.hash` now prefers the receipt `chain_head`, falling back to legacy `transcript_hash`.
- JS SDK mirrors the version bump, issuance fields, and version-gated `verifyReceiptSetBinding` helper.
- Schema copies and conformance fixtures/vectors/docs were regenerated and pinned to the new mutation totals.
- Tests cover the re-signed splice differential, truncation rejection, missing/malformed field rejection, legacy set-unbound reporting, JS parity, and envelope bridge consistency.

## Fail-Before Evidence

Saved transcripts:

- `probes/fail-before-python.txt`: temporarily reverted Python issuance to `0.2.0` and omitted the new fields. The new tests failed: version assertion, missing `chain_head`, and truncated transcript over-accepted as legacy.
- `probes/fail-before-js.txt`: temporarily reverted the JS `ATTESTATION_VERSION` constant to `0.2.0`. The Python-fixture parity test failed: expected `0.3.0`, received `0.2.0`.

After restoring from backups:

- Python targeted receipt-binding tests: `3 passed`.
- JS parity test: `1 passed | 203 skipped`.

## Gate Results

Saved gate transcripts:

- `probes/gate-pytest.txt`: `.venv/bin/python -m pytest -q`
  - Result in sandbox: `4 failed, 1900 passed, 1 skipped`.
  - Remaining failures are the prompt-declared ambient localhost-bind cases in `tests/test_mandate.py`:
    - `TestRevocation::test_not_revoked`
    - `TestRevocation::test_revoked`
    - `TestRevocation::test_invalid_json_response`
    - `TestRevocationEndpointSSRFGuard::test_redirect_to_internal_is_blocked`
  - Each fails with `PermissionError: [Errno 1] Operation not permitted` while binding `127.0.0.1`.
- `probes/gate-mypy-strict.txt`: `.venv/bin/mypy --strict concordia`
  - Result: nonzero, 34 strictness errors in `concordia/agent_profile/tools.py` and `concordia/mcp_server.py`.
  - No errors reported in Phase 1 files.
- `probes/gate-mypy-strict-phase1-files.txt`: strict mypy on Phase 1 Python files
  - Result: `Success: no issues found in 3 source files`.
- `probes/gate-mypy-configured.txt`: `.venv/bin/mypy concordia`
  - Result: `Success: no issues found in 58 source files`.
- `probes/gate-conformance-vectors-check.txt`: `.venv/bin/python scripts/conformance/generate_vectors.py --check`
  - Result: `[OK] conformance vectors match generated output`.
- `probes/gate-conformance-doc-check.txt`: `.venv/bin/python scripts/claims/generate_conformance.py --check`
  - Result: `[OK] docs/CONFORMANCE.md matches generated output`.
- `probes/gate-claims-run.txt`: `.venv/bin/python scripts/claims/run.py`
  - Result: `[OK] executable claims gate passed (7 claims)`.
- `probes/gate-reference-runner-python.txt`: Python clean-room conformance runner with dependency-only `PYTHONPATH` and `-S`
  - Result: `[SUMMARY] positive=47 mutation=1480 canary=4 ok=1531 fail=0`.
- `probes/gate-reference-runner-node.txt`: Node clean-room conformance runner
  - Result: `[SUMMARY] positive=47 mutation=1480 canary=4 ok=1531 fail=0`.
- `probes/gate-js-typecheck.txt`: `npm --prefix js-sdk run typecheck`
  - Result: passed.
- `probes/gate-js-test.txt`: `npm --prefix js-sdk test`
  - Result: `14 passed`, `1197 passed | 2 skipped`.

## Stop Boundary

Phase 2 was not executed. No binding vectors, new canary, runner-contract update, or new claim row from Phase 2 were added.
