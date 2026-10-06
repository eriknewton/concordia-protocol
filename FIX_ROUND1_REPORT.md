RESULT_VERDICT: FIXES_STAGED

CHANGES:
1. Verifier is fail-closed for parser and structure exceptions: raw nesting pre-scan, iterative depth, string surrogate rejection, numeric bounds, typed comparisons, and bounded `not-bound` diagnostics. Fail-before: new terminal/probe tests failed on c74b44b9 with 19 failed, 20 passed.
2. Removed the 0.5.x carve-out: `fulfillment`, reference `extensions`, and `window` now terminate `not-bound`; schema and `validate_attestation` agree. 0.5.0 clean vector verifies `current`.
3. `verify_attestation` delegates 0.5.0+ well-formed artifacts to the -00 procedure and maps terminal state without exception-type leaks; sub-0.5.0 remains legacy-only.
4. Reference strings now use NFC, forbidden control/format ranges, and UTF-8 octet caps; schema copies and conformance schema pins match.
5. Version and timestamp regexes use ASCII digits; `0.5.1٠` is `not-bound`.
6. Absolute lifetime uses exact interval precision; 7776000.999 seconds is rejected.
7. Step 8 requires `expected_session_id` and `expected_party_ids`; wrong session or party set is `not-bound`.
8. Issuance fails when any listed party lacks a signing key; agent callers/tests updated.
9. Restored and expanded terminal, probe, schema, countersign, temporal, revocation, duplicate-name, size/depth, and exception tests. Probe states printed twelve `not-bound`; countersign positive vector is now 0.6.0. Mutation counts before/after: 1488 total, 1449 reject, 39 accept.
10. SPEC and CHANGELOG describe the -00 floor, malformed-version rule, reference-string checks, and no 0.5.x carve-out. Follow-up: `receipt_bundle.py` `_OUTCOME_BINDING_MIN = (0, 2)` remains out of scope.

VERIFY:
`pytest -q`: 2261 passed, 15 skipped, 3 pre-existing JS-runner failures from missing `ajv`. `mypy concordia`: clean. `check-ai-tells.sh`: clean. Changes are unstaged.
