# Changelog

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
