# Concordia Protocol — Next Four Stages: Claude Code Build Prompt

**Date:** 2026-03-29
**For:** Claude Code session operating on the Concordia repo at `~/Desktop/Claude/Concordia`
**Context:** This prompt assumes you are working in the Concordia Protocol repository with the codebase as it exists today. Read CLAUDE.md and SERVICE_ARCHITECTURE.md before beginning. The viral strategy document lives in the sibling Sanctuary repo at `~/Desktop/Claude/Sanctuary/Sanctuary_Concordia_Viral_Strategy.md` — read it for strategic context but do not modify it.

---

## Current State (Do Not Rebuild)

The following is already built and working. Do not recreate or significantly restructure any of it:

- **45 MCP tools** in `concordia/mcp_server.py` via FastMCP (negotiation, reputation, discovery, want registry, relay, adoption/degradation, sanctuary bridge)
- **518 tests** across 17 test files, all passing
- **Full Python SDK**: session lifecycle (6-state machine), Ed25519 signing with canonical JSON (cross-platform compatible with Sanctuary's TypeScript implementation), hash-chain transcripts, multi-offer types (basic, partial, conditional, bundle), attestation generation with Sybil detection, reputation scoring (6 weighted dimensions + confidence intervals), query handler (§9.6.7), discovery registry, want registry with matching, negotiation relay, graceful degradation, protocol meta-negotiation, sanctuary bridge
- **Build system**: Hatchling via `pyproject.toml`, package name `concordia-protocol`, version `0.1.0`, Python 3.10–3.12
- **CI**: GitHub Actions matrix (3.10/3.11/3.12) with pip-audit CVE scanning in `.github/workflows/ci.yml`
- **Security review**: Complete. All Critical and High findings PASS. `security-review` branch merged to `main` (PR #1). You are working on `main`.
- **Launch materials**: HN post, dev partnership brief, Twitter thread in `launch/`
- **Entry point**: `python -m concordia` (stdio default, SSE optional), `.mcp.json` configured

**Test baseline: 518.** This number must never decrease. Each stage adds tests; the count must monotonically increase. Run `pytest -v` after every stage.

---

## Stage 1: pip Publish Pipeline

**Goal:** Make `pip install concordia-protocol` work from PyPI. Mirror the pattern Sanctuary used for npm publish.

### What to build

1. **Add a `[project.scripts]` entry point** to `pyproject.toml`:
   ```toml
   [project.scripts]
   concordia-mcp-server = "concordia.__main__:main"
   ```
   This gives users a `concordia-mcp-server` CLI command after install, parallel to Sanctuary's `npx @sanctuary-framework/mcp-server`.

2. **Update `concordia/__main__.py`** — the `--help` text currently says "8 tools." Update it to reflect the actual 45 tools, organized by group (Negotiation, Reputation, Discovery, Want Registry, Relay, Adoption, Sanctuary Bridge). Keep it concise — one line per group with tool count.

3. **Add a GitHub Actions publish workflow** at `.github/workflows/publish.yml`:
   ```yaml
   name: Publish to PyPI

   on:
     release:
       types: [published]

   jobs:
     publish:
       runs-on: ubuntu-latest
       environment: pypi
       permissions:
         id-token: write  # Trusted publisher (OIDC)
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-python@v5
           with:
             python-version: "3.12"
         - run: pip install build
         - run: python -m build
         - uses: pypa/gh-action-pypi-publish@release/v1
   ```
   Use PyPI trusted publishing (OIDC) — no API tokens needed. The repo owner configures the trusted publisher on pypi.org.

4. **Add a TestPyPI workflow** at `.github/workflows/test-publish.yml` that triggers on pushes to `main` and publishes to TestPyPI. Same structure but with `repository-url: https://test.pypi.org/legacy/`.

5. **Verify the build locally** by running:
   ```bash
   pip install build
   python -m build
   pip install dist/concordia_protocol-0.1.0-py3-none-any.whl
   concordia-mcp-server --help
   python -c "from concordia import Session, Agent, KeyPair; print('Import OK')"
   ```

6. **Add `long_description` handling** — `pyproject.toml` already has `readme = "README.md"`. Verify that `README.md` renders correctly on PyPI by running `pip install twine && twine check dist/*`.

### Acceptance criteria
- `python -m build` produces a clean wheel and sdist
- `pip install concordia-protocol` from the built wheel works
- `concordia-mcp-server` CLI launches the MCP server
- All 518 tests still pass
- CI workflow files are syntactically valid YAML

---

## Stage 2: Cowork / Claude Code Plugin Packaging

**Goal:** Package Concordia as a one-click installable plugin, following the exact pattern established by Sanctuary's plugin at `~/Desktop/Claude/Sanctuary/plugin/`.

### Reference implementation (Sanctuary's plugin structure)

```
plugin/
├── .mcp.json                    # MCP server launch config
├── .claude-plugin/
│   └── plugin.json              # Plugin metadata
├── README.md                    # Installation docs
└── skills/
    └── concordia/
        ├── SKILL.md             # Tool documentation + workflows
        └── references/          # Optional reference materials
```

### What to build

1. **Create `plugin/.mcp.json`** — use `python -m concordia` as the launch command. This is the simplest approach that works everywhere Python is installed, and matches the existing `.mcp.json` at the repo root:
   ```json
   {
     "mcpServers": {
       "concordia": {
         "command": "python",
         "args": ["-m", "concordia"],
         "env": {}
       }
     }
   }
   ```
   The plugin README should note that `pip install concordia-protocol` is a prerequisite. Once `uvx` becomes standard in Claude Code environments, the `.mcp.json` can be updated to `uvx --from concordia-protocol concordia-mcp-server` for zero-install usage.

2. **Create `plugin/.claude-plugin/plugin.json`**:
   ```json
   {
     "name": "concordia-protocol",
     "version": "0.1.0",
     "description": "Structured negotiation protocol for autonomous agents. Gives your agent binding commitments, multi-attribute offers, session receipts, portable reputation, and discovery — as MCP tools.",
     "author": {
       "name": "CIMC.ai",
       "homepage": "https://github.com/eriknewton/concordia-protocol"
     },
     "license": "Apache-2.0",
     "keywords": [
       "negotiation",
       "protocol",
       "agents",
       "commerce",
       "reputation",
       "mcp",
       "a2a"
     ]
   }
   ```

3. **Create `plugin/README.md`** — brief installation and overview. Mirror Sanctuary's plugin README structure: what it does (one paragraph), installation (one line), requirements (Python 3.10+, `pip install concordia-protocol`), tool groups with counts, license.

4. **Create `plugin/skills/concordia/SKILL.md`** — this is the critical file. It teaches Claude (and Cowork users) when and how to use the tools. Structure:

   ```markdown
   ---
   name: concordia
   description: Structured negotiation protocol for AI agents — binding offers, counteroffers, session receipts, portable reputation, and agent discovery via MCP tools.
   ---

   # When to use Concordia tools

   [Use cases organized by scenario: starting a negotiation, responding to offers, checking reputation, finding counterparties, publishing wants/haves, using the relay, proposing the protocol to non-Concordia peers]

   # Tool categories

   | Category | Tools | Count |
   |----------|-------|-------|
   | Negotiation | open_session, propose, counter, accept, reject, commit, session_status, session_receipt | 8 |
   | Reputation | ingest_attestation, reputation_query, reputation_score | 3 |
   | Discovery | register_agent, search_agents, agent_card, concordia_preferred_badge, deregister_agent | 5 |
   | Want Registry | post_want, post_have, get_want, get_have, withdraw_want, withdraw_have, find_matches, search_wants, search_haves, want_registry_stats | 10 |
   | Relay | relay_create, relay_join, relay_send, relay_receive, relay_status, relay_conclude, relay_transcript, relay_archive, relay_list_archives, relay_stats | 10 |
   | Adoption | propose_protocol, respond_to_proposal, start_degraded, degraded_message, efficiency_report | 5 |
   | Sanctuary Bridge | sanctuary_bridge_configure, sanctuary_bridge_commit, sanctuary_bridge_attest, sanctuary_bridge_status | 4 |

   # Common workflows

   [Step-by-step: basic negotiation, reputation check before dealing, posting a want and getting matches, relay-mediated negotiation, proposing Concordia to a new peer, bridging to Sanctuary]

   # Architecture notes

   [Brief: protocol stack position, session state machine, attestation flow, canonical JSON signing]
   ```

   Write the SKILL.md with real tool names (prefixed `concordia_` as they appear in the MCP server), concrete examples, and the trigger phrases that should activate it (negotiation, deal, offer, counter-offer, reputation, want, have, matching, relay, session receipt, attestation).

### Acceptance criteria
- Plugin directory follows Sanctuary's exact structure
- `.mcp.json` launches the Concordia MCP server successfully
- `plugin.json` metadata is complete and accurate
- SKILL.md covers all 45 tools with usage guidance
- A Claude Code or Cowork user installing this plugin gets working negotiation tools

---

## Stage 3: Portable Session Receipts

**Goal:** Implement the "session receipts as portable proof" mechanism described in Viral Strategy item #18. The attestation machinery exists but lacks the portability layer — the ability for an agent to export a bundle of its negotiation history, and for a counterparty to verify that bundle independently.

### What exists today
- `concordia_session_receipt` tool generates a signed attestation from a concluded session
- Attestations conform to `attestation.schema.json` with Ed25519 signatures from both parties
- `concordia_ingest_attestation` validates schema, signatures, deduplication, and Sybil signals
- Reputation scorer aggregates attestations into trust scores
- §9.6.6a in the spec defines self-custody and direct presentation of attestations
- Sanctuary bridge can optionally export attestations to Sanctuary's L4 reputation

### What's missing

There is no mechanism for an agent to:
1. **Bundle** multiple attestations into a single portable reputation proof
2. **Export** that bundle as a self-contained, verifiable JSON document
3. **Verify** a received bundle from a counterparty (signature validation, Sybil screening, summary accuracy check)

### What to build

1. **`concordia/receipt_bundle.py`** — new module implementing portable receipt bundles:

   ```python
   @dataclass
   class ReceiptBundle:
       """A portable, self-contained collection of session receipts.

       An agent carries this as proof of negotiation history.
       Any counterparty can verify it without contacting a reputation service.
       """
       bundle_id: str
       agent_id: str
       created_at: str  # ISO 8601 UTC
       attestations: list[dict]  # List of full attestation dicts
       summary: BundleSummary  # Precomputed aggregate stats
       agent_signature: str  # Ed25519 signature over the bundle
   ```

   **`BundleSummary`** precomputes what a verifier cares about:
   - `total_negotiations: int`
   - `agreements: int`
   - `agreement_rate: float`
   - `avg_concession_magnitude: float`
   - `fulfillment_rate: float`
   - `unique_counterparties: int`
   - `categories: list[str]`
   - `earliest: str` (ISO timestamp)
   - `latest: str` (ISO timestamp)
   - `reasoning_rate: float`

   Key methods:
   - `ReceiptBundle.create(agent_id, attestations, key_pair)` — builds bundle, computes summary, signs
   - `ReceiptBundle.to_dict()` / `ReceiptBundle.from_dict(data)` — serialization
   - `ReceiptBundle.to_json()` — canonical JSON for portability
   - `verify_bundle(bundle_dict, resolve_key)` — verifies: (a) bundle signature matches agent's public key, (b) each attestation's party signatures are valid, (c) the agent_id appears as a party in every attestation, (d) summary statistics match the attestations (no inflated claims), (e) attestations are not duplicated
   - `screen_bundle(bundle_dict)` — Sybil screening: flags bundles where counterparty diversity is suspiciously low, timing patterns are anomalous, or concession patterns are symmetric

2. **Add 3 new MCP tools** to `mcp_server.py`:

   - **`concordia_create_receipt_bundle`** — Agent selects which attestations to include (all, by category, by date range, by counterparty), tool builds and signs the bundle and returns it as JSON
   - **`concordia_verify_receipt_bundle`** — Counterparty submits a received bundle; tool verifies signatures, validates summary, screens for Sybil, returns trust assessment
   - **`concordia_list_receipt_bundles`** — List bundles the agent has created in this session

3. **Add a `receipt_bundle.schema.json`** in `schemas/` defining the JSON schema for the bundle format. This is the portability contract — any system that can validate against this schema can verify a Concordia receipt bundle.

4. **Tests** — add `tests/test_receipt_bundle.py`:
   - Bundle creation from valid attestations
   - Bundle signature verification (valid, tampered, wrong key)
   - Summary accuracy (computed stats match attestation data)
   - Sybil screening (low diversity, symmetric patterns, self-dealing)
   - Round-trip serialization (create → export → import → verify)
   - Edge cases: empty bundle, single attestation, mixed outcomes (agreed + rejected)
   - MCP tool integration tests through `handle_tool_call`
   - Verify that an agent can only bundle attestations where it appears as a party
   - Freshness: bundles older than a configurable threshold get flagged

5. **Update `plugin/skills/concordia/SKILL.md`** from Stage 2 to include the new receipt bundle tools.

### Design constraints
- Receipt bundles must be pure JSON — no binary formats, no platform-specific encoding
- Verification must work offline — no network calls to reputation services
- The bundle schema must be forward-compatible (use `additionalProperties: true` at the top level)
- Use canonical JSON (`concordia.signing.canonical_json`) for all signature operations, maintaining cross-platform compatibility with Sanctuary's TypeScript implementation
- Follow the existing auth pattern — all MCP tools require `auth_token` parameter

### Acceptance criteria
- An agent can create a bundle from its completed sessions, export it as JSON, and a different agent can verify it
- Summary statistics are deterministically recomputable from the attestations (no trust required in the summary)
- Sybil screening catches the same patterns as the ingestion pipeline (self-dealing, suspiciously fast, symmetric concessions, closed loops)
- All existing 518 tests still pass
- New tests cover all the above scenarios

---

## Stage 4: Multi-Agent Integration Test Harness

**Goal:** Validate the entire system end-to-end with real multi-agent negotiation scenarios running through the MCP tool interface. This is the "live testing with real agent pairs" step — not a public arena yet, but a comprehensive integration test suite that proves two (or more) agents can discover each other, negotiate, reach agreement, generate receipts, build reputation, and present portable proof.

### What exists today
- `test_mcp_server.py` has a `TestFullLifecycle` class with basic flows (open → propose → accept, multi-round, rejection)
- `test_reputation.py` has `test_end_to_end_reputation_flow`
- All tests call tool functions directly (not through MCP transport)
- No tests simulate two independent agents with separate keys, tokens, and perspectives

### What to build

1. **`tests/test_integration.py`** — a new integration test module with scenarios that simulate real multi-agent interactions:

   **Test infrastructure:**
   ```python
   @dataclass
   class SimulatedAgent:
       """An agent with its own identity, keys, and auth context."""
       agent_id: str
       key_pair: KeyPair
       auth_tokens: dict[str, str]  # session_id → token
       receipt_bundles: list[dict]

       def call_tool(self, name: str, **kwargs) -> dict:
           """Call an MCP tool as this agent, injecting auth."""
           ...
   ```

   **Scenario 1: Full negotiation lifecycle**
   - Agent A and Agent B register in the discovery registry
   - Agent A searches for agents in a category, finds Agent B
   - Agent A checks Agent B's reputation (should be empty/new)
   - Agent A opens a session with Agent B
   - Multi-round negotiation: propose → counter → counter → accept
   - Both parties generate session receipts
   - Both parties ingest attestations into the reputation service
   - Both parties' reputation scores are now queryable
   - Agent A creates a receipt bundle from the session

   **Scenario 2: Want/Have matching → negotiation**
   - Agent A posts a Want ("looking for electronics, budget 500-1000 USD")
   - Agent B posts a Have ("selling camera, asking 800 USD")
   - Match is found
   - Agents negotiate through the matched Want/Have context
   - Session concludes with agreement

   **Scenario 3: Relay-mediated negotiation**
   - Agent A creates a relay session
   - Agent B joins the relay
   - Full negotiation conducted through relay_send/relay_receive
   - Session concludes, transcript archived

   **Scenario 4: Graceful degradation (Concordia meets non-Concordia)**
   - Agent A proposes Concordia protocol to Agent B
   - Agent B declines (simulating a non-Concordia peer)
   - Agent A starts a degraded interaction
   - Multiple degraded message rounds
   - Efficiency report shows the cost of not using Concordia

   **Scenario 5: Reputation-informed negotiation**
   - Run 5 negotiations between Agent A and various counterparties (Agents B, C, D, E, F)
   - Agent G checks Agent A's reputation before negotiating
   - Reputation score reflects the history accurately
   - Agent A creates and presents a receipt bundle to Agent G
   - Agent G verifies the bundle

   **Scenario 6: Sanctuary bridge (if configured)**
   - Configure the Sanctuary bridge with identity mappings
   - Run a negotiation to agreement
   - Bridge generates commitment and reputation payloads
   - Verify payloads match expected Sanctuary tool input format

   **Scenario 7: Adversarial — Sybil attempt**
   - Agent X creates multiple identities and negotiates with itself
   - Attestations are ingested
   - Sybil detection flags the pattern
   - Reputation score includes Sybil penalty
   - Receipt bundle from Agent X is flagged during verification

2. **`tests/conftest.py`** — shared fixtures for integration tests:
   - `make_agent(agent_id)` — creates a SimulatedAgent with fresh keys
   - `clean_all_state()` — autouse fixture that resets all global stores (sessions, auth, registry, want registry, relay, reputation)
   - `run_negotiation(agent_a, agent_b, rounds=3)` — helper that executes a complete negotiation and returns the session context
   - `populated_reputation(agent, n_sessions=5)` — helper that runs N negotiations with random counterparties to build up reputation

3. **Test runner configuration** — add a pytest marker so integration tests can be run separately:
   ```toml
   # In pyproject.toml
   [tool.pytest.ini_options]
   testpaths = ["tests"]
   markers = [
       "integration: end-to-end multi-agent integration tests",
   ]
   ```

### Design constraints
- Integration tests must be deterministic (no random behavior that could cause flaky tests)
- Each test must be independent (no shared state between tests — the autouse fixture handles cleanup)
- Tests call tool functions directly (not over MCP transport) — this is about validating the protocol logic, not the transport layer
- Use realistic data: real product categories, plausible price ranges, meaningful term structures
- Every assertion should test something a real user would care about (not implementation details)

### Acceptance criteria
- All 7 scenarios pass
- Integration tests can be run independently via `pytest -m integration`
- All existing 518 tests still pass
- Total test count exceeds 560 (integration tests add ~50+ new test functions)
- No test takes more than 5 seconds individually
- The test harness is reusable for future scenarios

---

## Execution Order and Dependencies

```
Stage 1: pip publish pipeline
    ↓ (package must be installable for plugin to reference it)
Stage 2: Plugin packaging
    ↓ (plugin SKILL.md must be updated with Stage 3 tools)
Stage 3: Portable session receipts
    ↓ (receipt bundles are used in integration test scenarios)
Stage 4: Integration test harness
```

**Run all tests after each stage.** The test baseline is 518. Each stage adds tests; the count must monotonically increase.

**After all four stages**, update `SERVICE_ARCHITECTURE.md` build order to mark items 4–5 as DONE and update the tool count from "11 MCP tools" to the actual count (currently 45, will be 48 after Stage 3).

---

## Files You Will Create or Modify

### New files
- `.github/workflows/publish.yml`
- `.github/workflows/test-publish.yml`
- `plugin/.mcp.json`
- `plugin/.claude-plugin/plugin.json`
- `plugin/README.md`
- `plugin/skills/concordia/SKILL.md`
- `concordia/receipt_bundle.py`
- `schemas/receipt_bundle.schema.json`
- `tests/test_receipt_bundle.py`
- `tests/test_integration.py`
- `tests/conftest.py`

### Modified files
- `pyproject.toml` (add scripts entry, pytest markers)
- `concordia/__init__.py` (export ReceiptBundle)
- `concordia/__main__.py` (update help text)
- `concordia/mcp_server.py` (add 3 receipt bundle tools)
- `SERVICE_ARCHITECTURE.md` (update build order status)

### Do not modify
- `concordia/signing.py` — canonical JSON and Ed25519 are stable
- `concordia/reputation/` — the scoring engine is complete
- `concordia/session.py` — the state machine is complete
- `attestation.schema.json` — the attestation format is stable
- Any existing test file — only add new tests

---

*End of build prompt. Begin with Stage 1.*
