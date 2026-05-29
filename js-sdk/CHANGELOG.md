# Changelog

## 0.0.1-alpha.3 -- 2026-05-XX

Signed predicate primitive (Concordia v0.6). Ports `concordia/predicate.py`
plus the two unported dependencies it strictly requires: the
`predicate_type_profiles` registry (the four built-in profiles: authority_gate,
procurement_eligibility, policy_gate, non_deterministic_test, plus the
approval_gate / jcs_edge aliases) and the `attestation._validate_reference`
helper (the session-independent piece of the attestation layer). The full
attestation generator, mandate, session-receipt, and lifecycle remain deferred.

`signPredicate` reproduces Python's full sign path byte-for-byte: it defaults
`algorithm` to `EdDSA` (and rejects anything else, matching the v0.6 reference
signer), injects `metadata.issuer_public_key_b64`, runs write-validation, and
signs the canonical bytes -- producing the Python-identical Ed25519 signature.
`verifyPredicate` reproduces Python's exact check order (schema, profile
condition, resolver bindings, signature, lifecycle, subject binding, reference
binding) and its `failure_reason` / per-check map. The ordering is load-bearing:
a predicate whose `status` is changed to `revoked` after signing fails the
SIGNATURE check (status is inside the signed bytes), so its reason is
`bad_signature`, not `revoked` -- the Python-generated fixtures capture that.

The type-profile deterministic-semantics gate emits validation errors
byte-identical to Python's `jsonschema` (Draft 2020-12) output for the built-in
profile schemas, including Python `repr`-formatted values and the
schema-property declaration order, without pulling in a general JSON-schema
engine. `validateReference` matches `_validate_reference` exactly, including the
SPEC clause citations in error text and the forward-compat preservation of
unknown `type` / `relationship` vocabularies as opaque strings.

Parity is enforced by fixtures generated directly from Python
(`scripts/gen-predicate-fixtures.py`): 8 sign+verify cases, 10 verification
failure cases (one per failure reason and lifecycle path), 13 type-profile
cases, 9 write-validation cases, 14 reference cases, 6 strict-dict condition
cases, 10 metadata-coercion cases, 11 ISO-8601 error-string cases, and a
deferred-revocation boundary fixture. Reuses the existing canonicalizer
(`canonicalizePredicate`) and Ed25519 crypto layers; no primitives are
reimplemented.

Hardened against four fail-open / diagnostic parity gaps found in adversarial
review, each now pinned by a Python-generated edge fixture:

- **Strict-dict `condition`.** The condition check now matches Python's
  `isinstance(condition, dict)` exactly (a plain-object prototype test), so a
  class instance, `Date`, or `Map` condition is rejected with
  "condition must be an object" / "condition must be a non-empty object" as
  Python rejects it. The previous loose `typeof === "object"` check accepted
  these (a fail-open).
- **Strict metadata coercion.** `signPredicate` reproduces Python's
  `dict(metadata or {})`: a falsy metadata (`{}`, `""`, `0`, `false`, `[]`,
  `null`) collapses to an empty object, while a truthy non-mapping (`5`, `3.5`,
  `true`, a non-empty string, a non-empty array) is rejected (Python's
  `dict(...)` raises). The previous spread silently coerced `5` to `{}`.
- **Reference diagnostics.** `validateReference` now reports the correct Python
  `type(ref).__name__` for every JSON type (`int`/`float`/`bool`/`NoneType`/
  `list`/`str`) and fails closed on non-JSON inputs: a `function` is named
  `function` (was mislabeled `dict`), and a `Date`/`Map` is rejected (the prior
  loose object test accepted them).
- **ISO-8601 error strings.** Malformed `issued_at` / `expires_at` now surface
  CPython's exact `datetime.fromisoformat` text -- `Invalid isoformat string:
  '<value>'` for structurally-malformed input (using the post-`Z`->`+00:00`
  string CPython quotes), and field-range messages (`month must be in 1..12`,
  `hour must be in 0..23`, `day is out of range for month` with the proper
  Gregorian leap rule, etc.) -- instead of a generic placeholder.

**Deferred:** the `revocation_records` / `now` verification path
(Python `verify_predicate`'s referenced-artifact revocation check) is NOT ported
in this PR. It strictly depends on the unported `concordia.cmpc` cross-mandate
revocation module (the `RevocationRecord` type, its canonical form, schema, and
signing). It is deferred to a future PR pending the `concordia.cmpc` port rather
than half-implemented; the parity boundary is pinned by a Python-generated
fixture (`deferred_revocation`) and an `it.skip` test that documents the
expected REVOKED outcome once the module lands.

## 0.0.1-alpha.2 -- 2026-05-XX

Foundational types layer. Ports `concordia/types.py`: the session, message,
term, flexibility, and outcome enumerations (8 enums, every value
byte-identical to the Python member values that cross the wire) plus the core
data structures (`Term`, `PreferenceSignal`, `AgentIdentity`, `TimingConfig`,
`BehaviorRecord`) with their serialization. `agentIdentityToDict` and
`behaviorRecordToDict` reproduce the Python `to_dict()` output exactly,
including conditional `principal_id` omission and decimal rounding. `pyRound`
reproduces CPython's `round(value, ndigits)` exactly: it rounds the exact
binary value of the double half-to-EVEN (banker's rounding) via integer
arithmetic, matching Python on every binary half-tie where a naive decimal
half-up would diverge (e.g. `0.125` -> `0.12`, `123.625` -> `123.62`), and on
large-magnitude `ndigits` without overflow. Parity is enforced by fixtures
generated directly from Python (8 enum maps, 8 behavior cases, and 121
round-parity vectors, of which 44 are exact binary half-ties that catch a
half-up regression).

## 0.0.1-alpha.1 -- 2026-05-XX

Crypto primitives. Ed25519 key generation, sign, and verify over canonical
JSON, ported from the Python reference (`concordia/signing.py`) with
byte-level signature parity. Signatures and public keys are URL-safe base64
with padding, matching Python's `base64.urlsafe_b64encode`. The top-level
`signature` field is stripped before signing. Parity is enforced by signing
fixtures generated directly from Python (8 message vectors plus tamper cases).

Verification is strict and fail-closed, matching Python's `verify_signature`
accept/reject contract: a signature must be correctly-padded URL-safe base64
that decodes to exactly 64 bytes. Unpadded signatures are rejected (Python's
`base64.urlsafe_b64decode` raises on missing padding), closing a fail-open gap
where Node's lenient base64url decoder accepted them. Canonicalization is also
fail-closed on lossy large integers: an integer beyond
`Number.MAX_SAFE_INTEGER` that JavaScript would render in plain-decimal form is
rejected (it cannot be represented distinctly and would diverge from Python's
arbitrary-precision integer formatting); pass such values as strings. Large
values that render in exponential form (e.g. `1e+30`) are unaffected and remain
byte-identical across both languages.

## 0.0.1-alpha.0 -- 2026-05-XX

Initial alpha. Canonicalizer parity with Python reference for 13 v0.6
predicate fixture vectors and 20 DELTA-20 fixture vectors.

Subsequent alpha releases will add mandate, predicate, attestation,
session-receipt, and the 6-state session lifecycle.
