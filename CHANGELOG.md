# Changelog

All notable changes to the Concordia Protocol reference implementation are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.7.0a1] - 2026-06-DD

### Added

- **RevocationRecord primitive.** Adds `RevocationRecord` and
  `RevocationScope` to `concordia.cmpc.types` for artifact-side revocation.
- **RevocationRecord schema and validator.** Adds
  `schemas/revocation_record.schema.json` plus
  `validate_revocation_record()` with Draft 2020-12 validation.
- **RevocationRecord signing and verification.** Adds
  `sign_revocation_record()`, `verify_revocation_record()`, and
  `canonicalize_revocation_record()` using RFC 8785 JCS canonical bytes.
- **Cross-mandate cascade verifier.** Adds `cascade_revocation()` plus
  `CandidateArtifact`, `CascadeResult`, and `InadmissibleArtifact`.
- **Predicate verifier integration.** `verify_predicate()` accepts optional
  `revocation_records` and returns `PredicateFailureReason.REVOKED` for
  revoked references.
- **ApprovalReceipt verifier integration.** `verify_approval_receipt()`
  accepts optional `revocation_records` and returns `revoked` for revoked
  referenced mandates or sessions.
- **Revocation conformance fixtures.** Adds single-artifact, cascade-mandate,
  and `giskard09-mid-execution-rotation` fixture vectors.
- **SPEC and integrator docs.** Adds SPEC §9.6.4c, the
  `urn:concordia:revocation:<id>` URN row, the `revokes` relationship value,
  `docs/cmpc_revocation.md`, and a RevocationRecord composition note in
  `docs/revocation_resolver.md`.

### Changed

- None.

### Removed

- None.

## [0.6.0] - 2026-05-16

### Added

- **v0.6 Predicate Primitive (`urn:concordia:predicate:<id>`).** Signed
  authority artifact evaluating authority/scope/policy/eligibility/bounds
  conditions. Composes with mandate, attestation, and ApprovalReceipt
  without coupling. RFC 8785 JCS canonicalization via
  `concordia.canonicalization.canonicalize_predicate()` produces the
  signing bytes; EdDSA (Ed25519) is the v0.6 reference signer
  (`concordia.predicate.sign_predicate`). Verification surface
  (`verify_predicate`) returns a stable `PredicateVerificationResult`
  consumable by policy gates. 13 executable canonicalization fixture
  vectors at `tests/fixtures/predicate_canonical/` (vectors 1-12 plus
  `vector_13_deterministic_gate_failure`).
- **JavaScript canonical-JSON parity verifier (`scripts/js-parity/`).**
  Proves byte-level parity with the Python canonicalizer across all 13
  predicate fixture vectors, giving non-Python implementers an
  executable conformance check.
- **`PredicateVerificationResult` with 8 stable failure reasons.**
  `PredicateFailureReason` enum in `concordia.predicate`:
  `schema_invalid`, `bad_signature`, `expired`, `revoked`,
  `unknown_authority`, `ref_mismatch`, `wrong_subject`, `resolver_miss`.
  Result also carries per-check booleans (`schema`, `profile_condition`,
  `resolver_binding`, `signature`, `lifecycle`, `subject_binding`,
  `reference_binding`) for policy-readable introspection.
- **Type-profile registry with deterministic-semantics gate (Q5
  forward-compat protection).** `concordia.predicate_type_profiles`
  ships four profiles: `authority_gate`, `policy_gate`,
  `procurement_eligibility`, and `non_deterministic_test` (the explicit
  forward-compat holdout that rejects predicates whose `condition`
  cannot be evaluated deterministically). Unknown `type` values
  validate cleanly today but verifiers MAY refuse to act on
  non-deterministic conditions per the v0.6 profile-gate semantics.
- **CTEF mapping for predicate evaluation.**
  `concordia.ctef.predicate_to_ctef_claim()` emits a CTEF claim with
  `claim_subtype: "predicate_evaluation"`, `artifact_ref` set to the
  `predicate_id` URN, allowing predicate outcomes to flow into the
  CTEF audit substrate alongside mandate and attestation claims.
- **ApprovalReceipt compose-when-present.** Predicate verification
  invokes the ApprovalReceipt verifier via `importlib` only when a
  `receipt`-typed `fulfills` reference is present
  (`_call_approval_receipt_verifier` in `concordia.predicate`). Absent
  module surfaces a `warnings` entry rather than a hard failure,
  preserving the non-dependency principle between primitives.
- **Standalone Fulfillment Attestation artifact (SPEC §9.6.4a).** New
  v0.5 artifact type emitted on a discrete delivery boundary (e.g.,
  A2CN `DELIVERY_ACKNOWLEDGED`). Distinct from the in-line
  `fulfillment` block on a reputation attestation (§9.6.4) — the
  standalone shape links back to the agreement attestation via
  `references[]` with `relationship: "fulfills"` and uses the
  A2CN-aligned status enum (`fulfilled_clean`,
  `fulfilled_with_mediation`, `failed`, `disputed_unresolved`).
  Schema at `schemas/fulfillment_attestation.schema.json` (`$id`
  `urn:concordia:schema:fulfillment_attestation:v0.5`).
- **Adds ApprovalReceipt artifact type and example for HITL
  pause-resume composition with A2CN Section 14 (per A2A Discussion
  #1737).** Schema at `schemas/approval_receipt.schema.json` (`$id`
  `urn:concordia:schema:approval_receipt:v0.5`). Spec coverage at
  SPEC §9.6.4b with the Draft A worked example reproduced verbatim
  so public-draft readers and the in-tree spec line up. Extends the
  §11.5.5 relationship vocabulary with `approves` (artifact-specific;
  preserved by the §11.5.3 forward-compat rule).
- **`docs/A2CN_FULFILLMENT.md`.** Integrator walkthrough for emitting
  a Fulfillment Attestation on `DELIVERY_ACKNOWLEDGED`, the canonical
  mapping between the standalone shape and the §9.6.4 in-line block,
  and the v0.5 ApprovalReceipt shape with worked JSON examples for
  each status enum value.

### Changed

- **Reference read-side forward compatibility.** `schemas/reference.schema.json`
  and the embedded attestation reference schema now accept non-empty
  strings for `type` and `relationship`, while documenting the canonical
  emit vocabulary. Non-canonical values are preserved and warned on per
  SPEC §11.5.5 and §11.5.8.
- **A2CN DISPUTE_RESOLVED validation and application guards.** The parser
  now uses Draft 2020-12 validation with a `FormatChecker`, enforces exact
  64-character hexadecimal `transaction_record_hash` values, and rejects
  semantic misbinding before applying mediated fulfillment to an attestation.
- **Predicate reference slot scope.** SPEC §11.5 now states that
  `predicate` is an opaque reference type only in v0.5.2. The standalone
  predicate primitive is deferred to v0.6 pending signed artifact shape,
  schema, canonical signing, verification, resolver hooks, and CTEF claim
  mapping.
- **SPEC §9.6.4 in-line fulfillment block.** Added cross-reference
  to the new §9.6.4a standalone Fulfillment Attestation shape, with
  guidance on which pattern to pick. Both shapes coexist; the
  canonical status-enum mapping is in `docs/A2CN_FULFILLMENT.md`.
  Producers MUST NOT emit both a standalone artifact and an in-line
  block for the same logical settlement (double-counting risk for
  reputation scorers).
- **Test baseline.** 1,126 pytest pass on the v0.6 predicate primitive
  merge (PR #20), up from the v0.5.0 release-cycle baseline. No
  regressions in pre-v0.6 surfaces.

### Documentation

- **v0.6 Predicate Primitive spec draft.**
  `Review/Concordia/V0.6_Predicate_Primitive_Spec_Draft_2026-05-14.md`
  captures the predicate shape, condition profiles, canonicalization
  rules, verification surface, and composition contracts with mandate,
  attestation, and ApprovalReceipt. Public-draft promotion follows the
  v0.6.0 PyPI cut.

## [0.5.0] - 2026-05-11: references[] ratification + Python SDK alignment

### Spec ratification (Beta-1, PR #6)

- **SPEC §11.5 Reference linkages.** Normative spec for the two-layer
  `references[]` shape shipped in v0.4.0. Layering boundary documented
  explicitly: envelope-level references are cryptographic (provenance,
  supersession of envelopes); attestation-level references are semantic
  (content linkage between attestations). Verifiers MUST NOT conflate
  the two surfaces in any verification step.
- **Relationship vocabulary normative.** Four-value vocabulary with
  RFC 2119 conformance levels: `supersedes` (MUST), `extends` (SHOULD),
  `fulfills` (SHOULD), `references` (MAY, weak generic association;
  use only when no stronger relationship applies).
- **Cross-protocol URN linkage.** SPEC §11.5.7 defines URN schemes for
  Concordia artifacts (`urn:concordia:attestation`, `urn:concordia:mandate`,
  `urn:concordia:offer`, `urn:concordia:session`) and references the
  linked-protocol URN schemes for A2A, AP2, x402, and ERC-8004.
- **`schemas/reference.schema.json`.** Canonical machine-readable schema
  for the attestation-level reference object. `$id`
  `urn:concordia:schema:reference:v0.5`. Required keys `id`, `type`,
  `relationship`. Optional keys `version`, `signed_at`, `signer_did`,
  and a forward-compatibility `extensions` map for v0.x extension
  preservation.
- **Optional reference-object fields on attestations.** `version`,
  `signed_at`, `signer_did`, and `extensions` keys are now schema-allowed
  on each attestation-level reference entry. v0.4.x emitters that omit
  these continue to validate cleanly.
- `schemas/attestation.schema.json` `$id` bumped to
  `urn:concordia:schema:attestation:v0.5`. Embedded `reference` `$def`
  mirrors `schemas/reference.schema.json`.
- Root `attestation.schema.json` synced byte-for-byte with
  `schemas/attestation.schema.json`.
- SPEC.md frontmatter bumped to `0.5.0-draft`.
- §9.6 and §10 cross-link to §11.5 for layered reference semantics.

### Python SDK alignment (Beta-2, this PR)

- `pyproject.toml` version bumped from `0.4.0` to `0.5.0`.
- `concordia.__version__` bumped from `0.4.0` to `0.5.0`.
- `concordia.attestation._validate_reference()` error text aligned with
  SPEC §11.5 section references for operator legibility (citing
  §11.5.6 for shape and §11.5.5 for relationship vocabulary).
- `concordia.attestation._validate_reference()` now preserves unknown
  `type` and `relationship` values as opaque strings per SPEC §11.5.8
  MUST forward-compat clause. v0.4.x callers passing only canonical
  values are unchanged. Callers passing extension values previously got
  `ValueError` and now roundtrip cleanly. This is strictly more
  permissive; existing tests pass unchanged.
- Optional reference-object fields (`version`, `signed_at`,
  `signer_did`, `extensions`) are now passed through `_validate_reference()`
  on the attestation generation path so callers can roundtrip extension
  data per SPEC §11.5.6.
- `concordia.attestation.generate_attestation()` docstring updated to
  point at SPEC §11.5 with one-line summary of the layering boundary.
- `concordia.envelope.build_trust_evidence_envelope()` envelope-level
  reference validation cites SPEC §11.5.2 in its error text and inline
  comments document the §11.5.4 layering boundary.

### Closed

- Foxbook ADR 0009 (#73) ratification commitment for v0.5 references[]
  extension as the formal vehicle.
- v0.4.0 follow-up (c) layering reconciliation. Resolution: Option iii,
  document the layering boundary explicitly. Both envelope-level and
  attestation-level surfaces remain; the boundary between them is now
  normative.
- v0.4.0 follow-up (b) CHANGELOG backfill (this entry consolidates the
  Beta-1 + Beta-2 surface; Beta-3 PR will add the published-tarball
  release notes).

### Notes

No breaking API changes. v0.4.0-shaped attestations continue to
validate cleanly against the v0.5 JSON Schema (forward-compat is
structural: every v0.4 reference is a valid v0.5 reference; the v0.5
optional fields are additive and absent on v0.4 emissions).

Beta-3 (separate PR) cuts the PyPI v0.5.0 release with tag and
GitHub Release.

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

## [0.3.1] - 2026-04-12: MCP Registry metadata + trust-evidence-format envelope + mandate primitive

### Added

- **MCP Registry metadata.** `server.json` manifest for MCP Registry
  submission with ownership tag in README. Submission docs and
  awesome-mcp-servers PR template at `review/`. (`c2d6176`)
- **Trust-evidence-format v1.0.0 envelope export.** New `concordia.envelope`
  module producing signed TEF v1.0.0 envelopes with ES256 signing support
  alongside existing EdDSA. Three MCP tools added:
  `concordia_export_tef_envelope`, `concordia_verify_tef_envelope`,
  `concordia_list_tef_envelopes`. 542 envelope tests. (`e7c69de`)
- **Mandate primitive.** `concordia.mandate` and `concordia.models.mandate`
  modules implementing the `Mandate` model (schema URN
  `urn:concordia:schema:mandate:v1`). SD-JWT-adjacent structure with
  three-mode validity (`sequence`/`windowed`/`state_bound`), delegation
  chains, revocation endpoints, and constraint patterns
  (`max_spend`/`allowed_categories`/`geographic_bounds`/`temporal_budget`).
  Three MCP tools: `concordia_create_mandate`, `concordia_verify_mandate`,
  `concordia_revoke_mandate`. 1,077 mandate tests. (`4266269`)

### Changed

- Version bumped to `0.3.1`. (`cce3fc6`)

## [0.3.0] - 2026-04-09: Agent discovery + Verascore reporting + bridge auto-load

### Added

- **Agent discovery Phase 1.** `concordia.agent_profile` package with
  `AgentProfile` model and `ProfileStore` for capability-based search and
  filtering. 86 discovery tests. (`ae8621b`)
- **Agent discovery Phase 2.** Four MCP tools: `concordia_register_agent`,
  `concordia_search_agents`, `concordia_get_agent_profile`,
  `concordia_update_agent_profile`. Version bump to 0.3.0. (`d83b75b`)
- **`concordia_verascore_report` tool.** Push negotiation receipts to
  Verascore with Ed25519-signed payloads. Auth token required,
  fulfillment_status validated, session must be terminal. (`9eed527`)
- **Bridge config auto-load.** Sanctuary bridge configuration now
  auto-loads from `~/.concordia/bridge-config.json` at startup.
  Manual configuration via `concordia_sanctuary_bridge_configure`
  still works. (`bbe48b5`)

### Changed

- **CI: production PyPI publish workflow.** OIDC trusted publisher
  workflow on `v*` tags for automated releases. (`b9b6447`)

### Test baseline

- v0.3.0 shipped: 715+ tests (96 new across agent discovery Phase 1
  and Phase 2, zero regressions).

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
