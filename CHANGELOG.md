# Changelog

All notable changes to the Concordia Protocol reference implementation are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
