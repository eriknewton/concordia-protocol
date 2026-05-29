# Changelog

## 0.0.1-alpha.6 -- 2026-05-XX

Mandate verification engine (the second half of the mandate layer). Ports the
includable slice of `concordia/mandate.py` on top of the merged mandate models
and Ed25519 crypto: `signMandate` / `signDelegation`, `validateMandateSchema`,
`validateConstraints`, `scopeRestrictionToSchema`,
`composeEffectiveConstraints`, `checkTemporalValidity`,
`verifyDelegationChain`, and the full `verifyMandate` over all five checks
(issuer signature, validity window, constraint compliance, delegation-chain
integrity, revocation status), in Python's exact check order.

`signMandate` / `signDelegation` reuse the merged Ed25519 `sign()` over the same
canonical payload Python signs (the `to_dict()` minus `signature`), so the
base64url signature is byte-identical to Python `sign_mandate` /
`sign_delegation`. `verifyMandate` reproduces Python's per-check boolean map (in
insertion order), `errors`, `warnings`, and `failure_reason` exactly; the result
serializes (via `mandateVerificationResultToDict`) byte-for-byte with Python's
`MandateVerificationResult.to_dict()`.

The schema and constraint validation drives `ajv` (already a dependency) but
reproduces CPython `jsonschema`'s accept/reject AND message text. Two parity
properties are load-bearing and pinned by Python-generated fixtures:

- **No format assertion.** CPython `jsonschema.validate` does NOT check `format`
  by default, so a malformed `date-time` `issued_at` or non-URI
  `revocation_endpoint` PASSES schema validation. ajv runs with
  `validateFormats: false` to match; asserting formats would reject inputs
  Python accepts (a fail-closed divergence).
- **CPython message text.** ajv's native error strings differ entirely from
  CPython jsonschema's. The engine translates ajv's structured error (keyword +
  params) into CPython's message templates (`'issuer' is a required property`,
  `'RS256' is not one of ['EdDSA', 'ES256']`, `{} should be non-empty`,
  `123 is not of type 'string'`, `0 is less than the minimum of 1`, etc.), with
  every embedded value rendered via CPython `repr()`. Each string is pinned by a
  fixture, so an unhandled keyword fails the test loudly rather than diverging
  silently.

Strict, fail-closed semantics throughout: `validateConstraints` treats only a
truthy non-empty constraints dict as compliant; `scopeRestrictionToSchema`
rejects a `{"max_spend": true}` shorthand (a bool is not an `int|float` in
Python) and fails closed on unknown shorthands; `verifyDelegationChain` and the
`verifyMandate` signature check verify EdDSA only and treat a wrong-length or
ES256 signature as invalid (never accept-without-verify); `checkTemporalValidity`
surfaces CPython's exact `datetime.fromisoformat` text on a malformed window
bound.

`verifyDelegationChain` gates each link on its declared `algorithm` BEFORE the
Ed25519 check, mirroring Python `verify_signature(..., alg=link.algorithm)`. A
link marked `algorithm:"ES256"` (or any non-EdDSA value) is rejected fail-closed
with the same `Invalid signature at delegation link {i}` error Python emits. This
closes a fail-open where a link claiming ES256 but carrying a genuine Ed25519
signature would have passed an EdDSA-only verifier that ignored the algorithm
field, returning `valid=true` for a mandate Python rejects.

**Known parity residual (fail-closed, unreachable):** `checkTemporalValidity`
parses ISO-8601 bounds via `Date.parse` to emulate CPython `fromisoformat`.
Accept/reject and error text match CPython for normal timestamps, but exotic or
invalid UTC offsets diverge: CPython 3.12 accepts an out-of-range offset minute
like `+00:99` (normalizing it), whereas `Date.parse` returns `NaN`, so the TS
engine treats the timestamp as malformed and REJECTS. That is TS being stricter
on an invalid offset, never looser (no fail-open); CPython's own behavior here is
version-dependent (3.9 != 3.12), and real Concordia timestamps are normal `...Z`
/ `+HH:MM`. Full CPython-`fromisoformat` offset parity is deliberately not chased
(a version-coupled rabbit hole on inputs that do not occur). Same posture as the
predicate ISO/parse-boundary residuals. A second, lower residual: an
`anyOf`/`oneOf` constraint-schema failure can surface a branch-local jsonschema
message where CPython emits the top-level "not valid under any of the given
schemas". This is a message-TEXT-only divergence on a composed-schema shape;
accept/reject (boolean) parity is preserved and it is fail-closed -- documented,
not chased.

Parity is enforced by fixtures generated directly from Python
(`scripts/gen-mandate-engine-fixtures.py`, wired into
`scripts/sync-fixtures-from-python.mjs`): 2 sign_mandate + 2 sign_delegation
signature vectors, 29 schema error-string cases, 11 constraint cases (including
a type-UNION violation rendered as `'a', 'b'` not the Python list repr, and
single- vs multi-key `additionalProperties` with the correct `was`/`were` verb
agreement and `sorted(extras, key=str)` ordering), 8 scope-restriction cases, 6
compose cases, 13 temporal cases (all three modes and their edges), 11
delegation-chain cases (root/tail mismatch, chain break, missing key, missing
signature, tampered field, and an `algorithm:"ES256"`-marked link carrying a
genuine Ed25519 signature that MUST be rejected), and 19 end-to-end
`verifyMandate` cases (happy path, action pass/violate, tampered/wrong-key/
missing signature, schema-invalid, revoked status, temporal edges, sequence and
state binding context, delegation chain valid / bad-signature /
unsupported-scope). The generator imports `jsonschema` + `cryptography` (the
engine's own deps) and runs under Python 3.12.

**Deferred:** the revocation-endpoint network fetch (`check_revocation`, Python's
`urllib` GET) is NOT ported in this PR. `verifyMandate` accepts an injectable
`revocationChecker` hook. With no hook injected, `checkRevocationStatus: false`
(or no endpoint) reproduces Python's "endpoint not checked" outcome exactly;
`checkRevocationStatus: true` + an endpoint set + no hook is the deferred network
path and throws (no fail-open) rather than silently passing. The boundary is
pinned by a Python-generated fixture (`deferred_revocation_case`) plus tests: a
live test asserting the throw and the injected-hook outcomes, and an `it.skip`
test documenting the ported-fetch result once a future PR adds the default
fetch. ES256 mandate/delegation signing and chain verification are likewise
deferred, matching the EdDSA-only crypto layer (the engine throws on ES256
signing and treats ES256 signatures as invalid on verify). Reuses the merged
Ed25519 crypto, mandate models, and canonicalizer; no cryptographic primitives
are reimplemented.

## 0.0.1-alpha.5 -- 2026-05-XX

Parse-boundary hardening for untrusted-JSON ingest. Adds `parseJsonStrict`, a
JSON parse that fails closed on any bare integer literal outside the JS
safe-integer range (|value| > 2^53 - 1) before it reaches a lossy double. This
closes the residual the canonicalizer's large-integer guard documented but
could not reach: a bare integer >= ~1e21 written in plain decimal parses to a
double that `String()`s in exponential form, slipping past the post-parse guard,
while a Python peer holding the same token as an arbitrary-precision integer
emits full decimal and the canonical bytes diverge. `parseJsonStrict` inspects
the source literal rather than the parsed value, so it catches the >= 1e21 case
as well as the 16-19 digit cases the canonicalizer already caught. Float and
exponential literals (`1.5`, `1e+30`), safe integers, and big integers carried
as JSON strings are all accepted unchanged; the legitimate `1e+30` predicate
limit (fixture vector_08) still round-trips byte-identically. `signJson` and
`verifyJson` route the signing and verification ingest through this guard, so an
unsafe integer is rejected at signing/verification time rather than producing
bytes that silently diverge from Python. Malformed JSON still raises the native
`SyntaxError`; the unsafe-integer rejection is a `CanonicalizationError`,
matching the canonicalizer guard's fail-closed posture. The check is a lexical
scan rather than a `JSON.parse` reviver because the reviver's source-text
`context` argument is only available on Node 21+/ES2025, and the package
supports Node >= 20. KNOWN RESIDUALS (fail-CLOSED, unreachable in real data):
the ingest path is stricter than Python on `-0` (rejected; Python normalizes to
0) and on an integer written with a redundant exponent (`9007199254740992e0`,
rejected to avoid emitting int-vs-float-divergent canonical bytes) -- both
rooted in the canonicalizer's deliberate fail-closed guards.

## 0.0.1-alpha.4 -- 2026-05-XX

Mandate credential models (the data layer). Ports the data half of
`concordia/models/mandate.py`: the `TemporalMode` and `MandateStatus`
enumerations (values byte-identical to the Python member values that cross the
wire), the `DelegationLink`, `ValidityWindow`, and `Mandate` data structures
with their `to_dict()` / `from_dict()` serialization, the
`MandateVerificationResult` data carrier (the result the deferred verifier will
populate), and the static `MANDATE_JSON_SCHEMA` and `CONSTRAINT_PATTERNS`
constants.

Each `*ToDict` reproduces the Python `to_dict()` output exactly: snake_case wire
keys, the same insertion order, and the same conditional-omission rules. The
not-None vs truthiness distinction is load-bearing and pinned by fixtures: an
empty `constraints` / `metadata` / `delegation_chain` is OMITTED (Python's
`if self.x:` truthiness guard), whereas an empty-string `revocation_endpoint` /
`revoked_at` / `failure_reason` is EMITTED (Python's `if x is not None` guard),
and `validity.max_uses = 0` is emitted rather than dropped. `mandateFromDict`
reproduces Python's unknown-status FAIL-SAFE (an unrecognized `status` silently
defaults to `active`, matching the reference's `try MandateStatus(...) except
ValueError -> ACTIVE`), the required-field `KeyError` text (`'delegator'`,
`'delegate'`, `'mode'`), and the unknown-mode `ValueError`
(`'<value>' is not a valid TemporalMode`). `createMandate` mirrors
`Mandate.create` (`urn:concordia:mandate:{uuid4}` id, Python
`%Y-%m-%dT%H:%M:%SZ` whole-second UTC timestamp) and accepts an injectable clock
for deterministic output.

Parity is enforced by fixtures generated directly from Python
(`scripts/gen-mandate-fixtures.py`, wired into
`scripts/sync-fixtures-from-python.mjs`): 2 enums, 5 delegation `to_dict` cases,
6 validity `to_dict` cases, 8 mandate `to_dict` cases (covering every
conditional branch and the not-None/truthiness edges), 4 mandate `from_dict`
round-trips (including the unknown-status fail-safe), 4 verification-result
`to_dict` cases, `from_dict` error-string cases, and byte-identical canonical
JSON for the two static schema constants. The generator imports only stdlib
model code, so it runs under any Python 3.9+ (unlike the predicate/signing
generators, which need 3.12). Reuses the existing canonicalizer
(`canonicalizeJcs`); no primitives are reimplemented.

**Deferred to the engine PR** (the second half of the mandate layer, mirroring
`concordia/mandate.py`): mandate signing (`sign_mandate` / `sign_delegation`),
the jsonschema-based `validate_mandate_schema` / `validate_constraints`, the
delegation-scope composition (`compose_effective_constraints` /
`_scope_restriction_to_schema`), temporal-validity checking, delegation-chain
verification, the urllib revocation-endpoint I/O (`check_revocation`), and the
full `verify_mandate`. These depend on a JSON-schema engine, network I/O, and
the mandate signing path; they are deferred rather than half-implemented.

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
