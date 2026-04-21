# Changelog

All notable changes to the Concordia Protocol reference implementation are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.4.0] - 2026-04-20 — CMPC-ready receipt primitives + Verascore auto-hook

### Added

- **WP1 — `resolve_algorithm()` env-var precedence helper.** Single helper
  in `concordia.signing` that resolves the JWS algorithm by precedence:
  explicit arg > `CONCORDIA_JWS_ALG` env var > `EdDSA` default.
  ES256 signing/verification itself (`ES256KeyPair`,
  `sign_message(alg="ES256")`, `verify_signature(alg="ES256")`, cross-
  algorithm rejection) was already shipped in the pre-v0.4.0 trust-
  evidence-format envelope and mandate primitive work; this WP adds
  only the missing env-var layer.
- **WP2 — generalized `references[]` on attestations.** Top-level
  `references` array on `generate_attestation()` output with shape
  `{type, id, relationship}`. `type` ∈
  `{receipt, chain_session, predicate, mandate}`. `relationship` ∈
  `{supersedes, extends, fulfills, references}`. `chain_session`,
  `predicate`, and `mandate` are reserved for CMPC primitives in v0.5
  and accepted today as opaque refs so v0.5 is a pure add rather than
  a breaking schema change. Distinct from the envelope-level
  `{kind, urn, verified_at, verifier_did, hash}` #1734 shape — both
  coexist at different layers.
- **WP3 — three-mode `validity_temporal` on attestations.** Optional
  tagged union with modes `absolute`/`relative`/`window`:
  `{mode: "absolute", from, until}`,
  `{mode: "relative", from, duration_seconds}`, or
  `{mode: "window", start, end, duration_seconds}`. Adds
  `concordia.is_valid_now(attestation)` helper. Attestations without
  the field return `True` (no temporal constraint). Distinct from
  `models/mandate.py::ValidityWindow` (`sequence`/`windowed`/
  `state_bound`, #1734 envelope shape); unification is v0.5+.
- **WP5 — Verascore post-transition auto-hook.**
  `Session.on_terminal` is a publicly assignable
  `Callable[[Session], None]` that fires exactly once when a session
  reaches AGREED / REJECTED / EXPIRED. Exceptions inside the callback
  are swallowed — reputation reporting never blocks a transition.
  `concordia.make_verascore_auto_hook(key_pair, agent_did, ...)`
  produces a callback gated by `VERASCORE_ENABLED=true`. Endpoint
  precedence: explicit arg > `VERASCORE_ENDPOINT` env > default
  `https://verascore.ai`. Default `report_on=("agreed",)`; widen to
  `("agreed", "rejected", "expired")` as desired. Payload carries
  `session_id` as the Verascore-side idempotency key
  (`prisma.concordiaReceipt.upsert({where: {sessionId}})`).
- **WP6 — `docs/A2A_COMPOSITION.md` alignment.** Rewrote the
  "Verascore as the reputation layer" paragraph to describe the v0.4.0
  auto-hook surface accurately — reporting is opt-in via
  `VERASCORE_ENABLED`, idempotency is keyed on `session_id`, receipts
  are the substrate.

### Deferred

- **WP4 — `mandate_verification`** (build-plan work package) — deferred
  to v0.4.1 pending A2CN mandate-shape coordination with cmagorr1.
  A standalone mandate primitive already ships (`concordia.mandate`)
  and is orthogonal to WP4's attestation-side verification path.

### Test baseline

- Pre-v0.4.0 baseline: 832 tests.
- v0.4.0 shipped: 885 tests (+53 across WP1/WP2/WP3/WP5).
- Zero regressions in pre-v0.4.0 tests.

## [0.2.1] - 2026-04-04 — Security remediation pass

### Security

- **DELTA-09 — session_public_view defaults to PRIVATE.** Sessions
  now carry a `public: bool = False` flag; session_public_view
  redacts counterparty `agent_id`s to role-only stubs unless the
  session has been explicitly marked public.
- **DELTA-10 — responder UI (respond.html) HTTPS enforcement.** The
  static responder UI refuses to submit to an `http://` API base
  unless the page origin is localhost or `?dev=1` is passed, enforces
  same-origin lock between page and API base, and shows a persistent
  red warning banner on plaintext HTTP.
- **DELTA-18 — JWK shape validation in respond.html.** Private-key
  import now checks `kty==="OKP"`, `crv==="Ed25519"`, and that both
  `d` and `x` are non-empty strings before calling
  `crypto.subtle.importKey`.
- **DELTA-20 — canonicalization test vectors.** New pytest module
  asserts Python `canonical_json` and the JS `canonicalJson` embedded
  in respond.html produce byte-identical output across 20 shared
  vectors (unicode, floats, nested objects, arrays, null, key
  ordering, escapes). 40 assertions total.

## [0.2.0] - 2026-04-04

### Added (Phase E: zero-friction improvements)

- **Receipt summary** — one-line human-readable summary of a Concordia session
  receipt bundle (`ReceiptBundle.summary()`), suitable for UI rendering and
  agent-to-agent status exchange.
- **`session_public_view` MCP tool** — exposes a redacted view of a session
  (state, participants, message count, terms hash) without revealing raw deal
  terms. Enables lightweight discovery without breaching the "attestations
  never contain deal terms" privacy invariant.
- **Session persistence** — sessions can now be serialized to and restored
  from disk, making responder agents runnable across restarts.
- **Responder UI** — minimal static responder interface (`concordia/static/`)
  for manual session acceptance during demos and first-handshake debugging.
- **Efficiency doc** — `docs/EFFICIENCY.md` explaining how Concordia's structured
  offers reduce round-trips vs. free-form negotiation.

### Changed

- Version bumped to `0.2.0`.

## [0.1.1] - 2026-04-01

### Fixed

- Minor documentation and packaging fixes.

## [0.1.0] - 2026-03-30

### Added

- Initial public release. 50 MCP tools, 625 passing tests.
- Ed25519-signed messages, hash-chained transcripts, six-state session lifecycle,
  four offer types, Sanctuary bridge payload builder.
- Published to PyPI via OIDC trusted publisher.
