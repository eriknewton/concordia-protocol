RESULT_VERDICT: FIXES_STAGED

1. `verify_attestation()` now requires keyword-only `expected_session_id` and `expected_party_ids`, passes optional `revocation_checker`, never infers step-8 inputs, and runs transcript set-binding when supplied; mismatches set `valid=False` with unchanged `terminal_state`.
2. Legacy below-0.5.0 wrapper results now keep `terminal_state="legacy"` while old checks remain in `errors`.
3. Delegated structural errors land in `schema_errors`, countersignature failures in `signature_errors`, and `set_binding_state` uses `bound/error/legacy_set_unbound`.
4. Current-version splice/truncation tests are restored; separate legacy set-binding tests remain.
5. Member-path diagnostics are truncated with `...`; 8000-character probe is bounded.
6. `is_valid_now()` now uses closed `[from, until]`.
7. `verify_attestation_artifact(str)` encodes with `surrogatepass`; lone-surrogate string returns `not-bound`.
8. `validate_attestation()` catches overflow/value parsing as validation errors; numeric counter test added.
9. `tests/probe_round1.py` renamed to collected `tests/test_probe_round1.py`; 12 probe tests collect and pass.
10. Issuance rejects boolean `duration_seconds`.
11. CHANGELOG states the pre-1.0 breaking wrapper API change and the round behavior changes.

Fail-before witness against detached `a9515312`: missing expectations accepted, other-session wrapper returned `valid=True/bound-only`, surrogate string raised `UnicodeEncodeError`, endpoint validity rejected, long diagnostic was 8040 chars, bool duration accepted.

Evidence: targeted attestation suite `81 passed`; full suite `3 failed, 2281 passed, 15 skipped`, with only the pre-existing JS runner `ajv` failures; `.venv/bin/python -m mypy concordia` clean; import smoke clean; `check-ai-tells.sh CHANGELOG.md` clean; nothing staged. Note: temporary base worktree filesystem copy is gone, but sandbox could not prune its non-existent worktree metadata under `/Users/eriknewton/Code/Claude/Concordia/.git`.
