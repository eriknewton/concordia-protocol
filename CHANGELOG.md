# Changelog

All notable changes to the Concordia Protocol reference implementation are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
