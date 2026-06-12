# Changelog

## Unreleased

L3 attestation-input hardening (port of Python PR #95; security audit
2026-06-09 finding L3). `generateAttestation` previously emitted
caller-supplied `category` / `value_range` free text verbatim and passed
`references[]` strings through uncapped, letting an issuer stuff raw deal
terms into a signed attestation (SPEC 9.6.6 privacy invariant: behavioral
signals only, never deal terms). BREAKING for issuers that passed free-form
values; validation is issuance-side only, so verification and reads of
previously issued attestations are unchanged.

- **value_range bucket vocabulary.** Enumerated 1-5-10 logarithmic buckets
  (`0-100` ... `1000000+`) suffixed with a shape-validated 3-letter uppercase
  currency code. Anchored so a trailing newline cannot slip past (Python `\Z`
  == JS non-multiline `$`, pinned by test).
- **category taxonomy grammar.** Dotted lowercase taxonomy path, max 64 chars.
- **references[] caps.** Max 32 entries (count-capped via Python `len()`
  semantics BEFORE iteration); `type`/`relationship` capped at 64 chars, `id`
  at 256, `version`/`signed_at`/`signer_did` at 256; every string field bans
  whitespace; `extensions` is depth/node pre-checked (max depth 8, max 256
  nodes) BEFORE canonicalization, then capped at 2048 canonical-JSON UTF-8
  BYTES (never UTF-16 length).
- **Fail-closed, no-echo errors.** Invalid input throws (`AttestationError` /
  `ReferenceValidationError`) with Python-byte-identical text; nothing is
  coerced and the rejected value is never echoed back.
- **Documented JS/Python strictness decisions.** Whitespace ban is the UNION
  of Python `\s` and JS `\s` (adds U+001C..U+001F and U+0085 beyond JS;
  U+FEFF beyond Python); length caps count code points (Python `len`);
  exotic objects (`Date`/`Map`) inside `extensions` are rejected instead of
  silently serializing as `{}`. All in the stricter, fail-closed direction.
- **Snapshot semantics for reference validation** (adversarial-review fix).
  `validateReference` (and `generateAttestation`'s `references[]` handling)
  now reads input via property descriptors and validates a detached
  plain-data SNAPSHOT, which is what callers get back. Getters are NEVER
  executed (a throwing getter previously leaked its attacker-controlled
  error text verbatim, violating the no-echo invariant); accessor
  properties, non-enumerable own properties, symbol keys, array holes,
  non-index array properties, and array subclasses are rejected outright
  (none is representable in Python's plain-dict model, closing the TOCTOU
  where an accessor-backed object validated as one value and serialized as
  another); any foreign throw (Proxy traps, revoked proxies) is converted
  to a sanitized error carrying neither the caught text nor any input. The
  canonical byte cap is measured over the snapshot, i.e. over exactly the
  bytes a later serialization emits. Frozen plain data remains accepted.

Pinned by regenerated Python-generated parity fixtures (48 `l3_meta_cases`,
count-cap strictness cases, 26 new shared-reference cases) plus a dedicated
rejection-class suite (`tests/attestation-l3.test.ts`, 98 tests).

## 0.0.1-alpha.10 -- 2026-06-01

Python-parity hardening: three fail-open fixes discovered during cross-language
adversarial testing. Each fix makes the JS SDK strictly more correct (fail-closed
where it previously accepted inputs Python rejects).

- **Mandate naive-datetime temporal validity (#42).** `checkTemporalValidity`
  now rejects naive (timezone-less) ISO-8601 timestamps in validity window
  bounds, matching Python's `datetime.fromisoformat` behavior under the
  mandate engine's strict temporal checks. Previously accepted silently
  (fail-open).
- **Attestation RFC-822 timestamp parse (#43).** `validateValidityTemporal`
  in the attestation layer now rejects RFC-822-style timestamps (e.g.
  `Mon, 01 Jan 2026 00:00:00 GMT`) that `Date.parse` accepted but Python's
  `datetime.fromisoformat` rejects. Fail-closed: only strict ISO-8601 with
  explicit timezone offset is accepted, matching Python exactly.
- **Attestation window-span exact-microsecond (#44).** The window-span
  duration bound check now uses exact microsecond comparison matching
  Python's `timedelta` arithmetic, closing a sub-second rounding edge where
  the JS SDK could accept a window Python rejects.

All three fixes are pinned by Python-generated fixtures that assert the exact
accept/reject boundary.

## 0.0.1-alpha.9 -- 2026-05-XX

JSON Schema validation and ApprovalReceipt verification. Ports
`concordia/schema_validator.py` (the validate-against-jsonschema surface) and
`concordia/approval_receipt.py` (the consumer) on top of the merged crypto,
canonicalizer, and internal `pyRepr` layers:

- `validateMessage` / `isValidMessage` -- validate a Concordia message envelope
  (SPEC §4.1) and return the ordered `"{json_path}: {message}"` error list.
- `validateApprovalReceipt` / `isValidApprovalReceipt` -- validate an
  ApprovalReceipt against `approval_receipt.schema.json` (the 7c prerequisite).
- `validateFulfillmentAttestation` / `isValidFulfillmentAttestation` -- validate a
  standalone FulfillmentAttestation against its schema PLUS the companion local
  equality invariant (every `fulfills`-relationship reference id must equal
  `agreement_attestation_id`).
- `verifyApprovalReceipt` -- the full ApprovalReceipt verifier (schema, the
  `approves` negotiation-session reference, the Ed25519 signature against a
  caller-supplied issuer key, the `expires_at` window, and the canonical
  `offer_hash` match), returning the typed `ApprovalReceiptResult` with the same
  `failure_reason` constants, `checks` map, and ordering as Python.

WHY A HAND-PORTED VALIDATOR (not ajv, the mandate engine's approach): this
surface returns the FULL ORDERED error list from CPython
`Draft202012Validator.iter_errors`, not the single best-match message the engine
needed. CPython yields errors per node in the schema's KEY-INSERTION ORDER
(verified empirically), with a specific `json_path` shape and CPython-`repr()`-
rendered message text -- none of which ajv reproduces byte-for-byte. So this layer
adds an internal `iterErrors` (`src/internal/jsonschema.ts`) that re-implements
the `iter_errors` traversal for the ported keyword subset (`type`, `enum`,
`const`, `required`, `properties`, `additionalProperties`, `patternProperties`,
`items`, `contains`, `allOf`, `if`/`then`/`else`, `minItems`/`maxItems`,
`minLength`/`maxLength`, `pattern`, `minimum`/`maximum`/`exclusiveMinimum`/
`exclusiveMaximum`, `format`). It SHARES the CPython `pyRepr` renderer with the
mandate engine via `src/internal/py-repr.ts` (the engine's private duplicate was
removed in this PR -- behavior-neutral, its 110 tests still pass).

FORMAT CHECKING is load-bearing for accept/reject parity: Python registers a
custom `FormatChecker` and PASSES it to `validate_message` /
`validate_approval_receipt`, so a bad `date-time` (e.g. a naive, tz-less
timestamp) is REJECTED -- the OPPOSITE of the mandate engine, which ran formats
OFF. `validate_fulfillment_attestation` passes NO checker (its `format` keywords
are inert), matched here.

DEFERRED -- `validate_attestation` (the §9.6 reputation-attestation schema). That
schema uses `$ref` / `$defs` / `oneOf` (which the internal validator does not yet
support) and a companion `_warn_on_noncanonical_references` that depends on
`REFERENCE_TYPES` / `REFERENCE_RELATIONSHIPS` constants not yet ported. It is out
of scope for this slice, pinned by a `deferred_attestation` boundary fixture and
a skipped test that documents the expected Python output for the follow-up.

Byte-level parity against the Python reference is the load-bearing property and is
pinned by Python-generated fixtures (`scripts/gen-schema-validator-fixtures.py`,
which drives the REAL `concordia.schema_validator` + `concordia.approval_receipt`;
receipts are signed with deterministic seeded Ed25519 keys so the JS suite
verifies the SAME Python signatures with the SAME keys): 21 message + 23
approval-receipt-schema + 13 fulfillment + 10 approval-receipt-verify cases, each
asserting the EXACT ordered error list / typed result Python emits. Robustness
cases confirm a non-object top-level input reports the root `type` error rather
than throwing (fail-closed).

## 0.0.1-alpha.8 -- 2026-05-XX

Reputation attestation (the signed behavioral record produced from a concluded
negotiation). Ports `concordia/attestation.py` on top of the merged session,
crypto, types, and predicate layers: `generateAttestation` (over a concluded
`Session`), `generateReceiptSummary` (the 4-line plaintext receipt),
`computeTranscriptHash` (the whole-transcript digest), `validateValidityTemporal`
and `isValidNow` (the three-mode temporal-validity tagged union), plus the
`ATTESTATION_VERSION` / `VALIDITY_TEMPORAL_MODES` constants and the
`AttestationError` type. The attestation-level `references[]` validator
(`validateReference`) is REUSED from the merged predicate layer rather than
re-ported.

PRIVACY INVARIANT (load-bearing): an attestation records behavioral signals only
(`offers_made`, `concession_magnitude`, `reasoning_provided`, ...) and NEVER the
raw deal terms (prices, quantities, the term values themselves). The only
term-derived number that ever reaches the attestation is `outcome.terms_count`,
the COUNT of negotiated dimensions, not their values. The port mirrors Python
exactly: it copies each party's `behaviorRecordToDict(...)` and never reads
`session.terms` except to take its length, so there is no code path that copies
a term value into the attestation. A dedicated test serializes the whole
attestation over real negotiations and asserts that no negotiated value
(1000 / 900 / 850 / 10 / 12) leaks anywhere.

Byte-level parity against the Python reference is the load-bearing property and
is pinned by Python-generated fixtures (`scripts/gen-attestation-fixtures.py`,
which drives the REAL `concordia.attestation` over a REAL concluded
`concordia.session`; the per-party signatures are real Ed25519 `sign_message`
outputs under deterministic seeded keys, so the JS suite verifies the SAME
Python signatures with the SAME keys):

- **Whole-object parity.** Each case replays a Python-signed transcript through
  the JS `Session`, generates the attestation, and asserts the ENTIRE object is
  byte-identical to Python's: header fields, `outcome` (with the conditional
  `terms_count` omission at zero terms and Python's insertion order), per-party
  behavioral records and their signatures, `transcript_hash`, `meta`, normalized
  `references`, `validity_temporal`, and the `summary`. The non-deterministic
  `attestation_id` / `timestamp` (not part of the signed per-party bytes) are
  captured from Python and injected as overrides so even those fields compare
  exactly.
- **Signing payload.** Each party's signature is over `{agent_id, role,
  behavior}` (no `signature` key at signing time), matching Python's
  `sign_message`. An agent absent from the supplied key map gets an
  empty-string signature, exactly as Python.
- **Transcript hash.** `computeTranscriptHash` concatenates the canonical-JSON
  bytes of every transcript message and takes ONE SHA-256 over the
  concatenation (distinct from the per-message `computeHash`), returning
  `sha256:<hex>` byte-identical to Python's `_compute_transcript_hash`.
- **Rejection text.** A non-terminal, non-EXPIRED session raises
  `AttestationError` with the exact Python `ValueError` text
  (`Cannot generate attestation for session in state <state>`).
- **Temporal validity.** `validateValidityTemporal` normalizes the three modes
  (`absolute` / `relative` / `window`) and rejects malformed input with
  Python-identical error strings (mode-not-in-tuple, missing-keys list,
  ordering, the positive-int `duration_seconds` check using Python's
  `isinstance(int)` semantics where a float is rejected, and the window-span
  bound). `isValidNow` reproduces the inclusive-start / exclusive-end
  containment and the window-tail-fits rule. A naive (no-offset) ISO 8601
  timestamp is treated as UTC, matching Python's naive-datetime rule.
- **Receipt summary.** `generateReceiptSummary` reproduces the 4-line format
  exactly: the DID-shortening rule (`unknown` for empty, `...<last 12>` for
  long), the `category -> topic -> N/A` fallback under Python `or` truthiness,
  the uppercased outcome status (`UNKNOWN` when absent), and the
  `sha256:`-prefix-stripped first-16-hex-chars transcript-hash line.

## 0.0.1-alpha.7 -- 2026-05-XX

Session lifecycle (the six-state negotiation state machine). Ports the
self-contained slice of `concordia/session.py` on top of the merged crypto,
types, and canonicalizer: the `Session` class with the
PROPOSED -> ACTIVE -> AGREED / REJECTED / EXPIRED -> DORMANT lifecycle, the
strict §5.2 transition table, `applyMessage` (signature-verify then
transition-validate then transcript-append then behavioral tracking),
`expire`, `makeDormant`, `getBehavior`, `durationSeconds`, and the `prevHash` /
`terms` / `isTerminal` accessors. The hash-chain transcript helpers it depends
on -- `computeHash`, `GENESIS_HASH`, and `validateChain` from
`concordia/message.py` -- ship alongside it. The `computeConcession` static
helper is exported for direct testing.

Byte-level parity against the Python reference is the load-bearing property and
is pinned by Python-generated fixtures (`scripts/gen-session-fixtures.py`, whose
messages are real signed envelopes built with deterministic seeded keys, so the
JS suite verifies the SAME Python signatures with the SAME keys):

- **Transition table.** The legal `(fromState, messageType) -> toState` set is
  identical to Python's `_TRANSITIONS`; an illegal pair raises
  `InvalidTransitionError` with the exact Python message text
  (`Cannot apply <type> in state <state>`). Every Python-legal transition is
  exercised and every off-table pair in a 6x14 grid is asserted to reject.
- **Signature contract (SEC-010 / SEC-005).** A mandatory resolver maps
  `agentId -> public key | null`; a missing `from.agent_id`, a missing
  `signature`, an unresolved identity, a tampered payload, and a flipped
  signature byte each raise `InvalidSignatureError` with Python-identical text,
  fail-closed (never accepted). Verification runs BEFORE the transition check,
  matching Python's ordering.
- **Enum-coercion text.** An unknown `type` value raises with CPython's
  `MessageType(...)` `ValueError` text (`<repr> is not a valid MessageType`)
  before the transition lookup; a missing `type` key throws like Python's
  `message["type"]` `KeyError`. The `<repr>` rendering uses full CPython
  `repr()` quote-selection + escaping (shared with the mandate layer via
  `src/internal/py-repr.ts`): a string is single-quoted by default, switches to
  double quotes when it contains `'` and not `"`, and backslash-escapes the
  active quote / backslash / `\t` / `\n` / `\r` -- so e.g.
  `type="negotiate.o'ops"` renders `"negotiate.o'ops"` exactly as Python does.
  The astral-codepoint printability residual (Unicode-DB-version-dependent,
  fail-closed, unreachable for the fixed `MessageType` enum) is documented in
  the helper, matching the predicate/mandate treatment.
- **Non-mapping `body` is rejected (fail closed).** Python reads
  `message.get("body", {}).get(...)` ONLY for OPEN / OFFER / COUNTER, so a
  present-but-non-mapping `body` (a list, string, number, bool, or `null`)
  raises `AttributeError` there and the message is REJECTED. `applyMessage`
  matches this exactly: it throws `InvalidMessageError` rather than silently
  coercing a non-mapping body to `{}` (which would accept inputs Python
  rejects). An ABSENT body uses the `{}` default (accepted), a mapping body
  (including `{}`) is accepted, and message types that never read `body` (e.g.
  SIGNAL) accept any body shape -- all asserted against Python-generated
  accept/reject vectors.
- **No per-append `prev_hash` check (intentional parity).** `applyMessage` does
  NOT validate `message.prev_hash` against the current chain head on each
  append, because Python's `apply_message` does not either: chain integrity is
  enforced by the separate `validateChain` (`validate_chain`) over the whole
  transcript, not per-append. Adding a per-append guard would reject messages
  Python accepts and break parity, so it is deliberately omitted; the append
  site carries a comment recording this.
- **Behavioral accumulation.** `offersMade` / `concessions` / `roundCount` /
  `signalsShared` / `constraintsDeclared` / `withdrawal` / `reasoningProvided`
  and the running-average `concessionMagnitude` reproduce Python's accumulation
  arithmetic bit-for-bit (asserted with `Object.is`), including treating JS
  boolean term values as numeric (`true`->1, `false`->0) the way Python's
  `isinstance(v, (int, float))` is True for `bool`, the `prev == 0` division
  guard, and the missing-term / no-overlap skips. The raw magnitude rounds to 4
  places via the merged `pyRound` in `behaviorRecordToDict`, also asserted.
- **`terms` null-preservation.** `dict.get("terms")` semantics: an absent
  `terms` body becomes `null`, an explicit `null` stays `null`, a present
  mapping is kept verbatim.
- **`durationSeconds`.** Truncates toward zero and clamps at 0
  (`max(0, int(delta))`), driven by an injectable clock so the wall-clock value
  is deterministic under test.
- **Hash chain.** `computeHash` returns `sha256:<hex>` over the FULL message
  (the `signature` field is NOT stripped, unlike the signing payload),
  byte-identical to Python `compute_hash`; `validateChain` reproduces the
  genesis-anchor + per-link checks.

The reputation attestation generator (`concordia/attestation.py`) is deferred to
a follow-up release: `generate_attestation` consumes a concluded `Session`, so it
layers on top of this primitive. The `ApprovalReceipt` verifier
(`concordia/approval_receipt.py`) is also deferred, as it depends on the
not-yet-ported `schema_validator` module.

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
