---
review_status: pending
title: "mandate_verification primitive — Concordia v0.4.0"
date: 2026-04-14
branch: mandate-verification-v04
---

# Mandate Verification Build Summary

## What was built

New MCP tool `concordia_verify_mandate` (tool #58) that verifies signed mandate credentials — authorization documents that allow agents to act within specified constraints on behalf of an issuer.

Five verification checks, executed in order (fail-fast):

1. **Issuer signature** — EdDSA (Ed25519) or ES256 (P-256 ECDSA) over canonical JSON
2. **Temporal validity** — three-mode model aligned with #1734 consensus:
   - `sequence` — valid for a specific session/transaction key
   - `windowed` — valid between `not_before` and `not_after` timestamps
   - `state_bound` — valid while a named condition holds
3. **Constraint schema compliance** — mandate constraints are JSON Schema; optionally validate a proposed action against them
4. **Delegation chain** — verify an ordered chain of signed delegation links from root issuer to final subject
5. **Revocation status** — fail-closed check against an HTTP revocation list endpoint (unreachable = denied, per CLAUDE.md constraint #5)

## Files added/modified

| File | Change |
|------|--------|
| `concordia/models/__init__.py` | New package |
| `concordia/models/mandate.py` | Mandate model, ValidityWindow, DelegationLink, JSON Schema, enums |
| `concordia/mandate.py` | Verification engine (sign, verify, temporal, constraints, delegation, revocation) |
| `concordia/mcp_server.py` | +1 MCP tool (`concordia_verify_mandate`), imports, handler map, docstring |
| `concordia/__init__.py` | New exports (Mandate, verify_mandate, etc.) |
| `tests/test_mandate.py` | 79 new tests |
| `tests/test_mcp_server.py` | Tool count bump 57 → 58 |

## Test delta

| Metric | Before | After |
|--------|--------|-------|
| Total tests | 753 | 832 |
| New tests | — | +79 |
| Failures | 0 | 0 |

Test breakdown (79 tests):
- Schema validation: 10
- Signing roundtrip (EdDSA + ES256): 6
- Temporal validity (3 modes): 13
- Constraint compliance: 8
- Delegation chain: 10
- Revocation: 4
- Full verification integration: 14
- Model serialization: 9
- MCP tool integration: 5

## Schema decisions

1. **JSON Schema for constraints** — mandate constraints use JSON Schema (Draft 2020-12) rather than a custom format. This means any agent can express constraints with a standard vocabulary, and action validation is just `jsonschema.validate(action, constraints)`.

2. **Delegation uses per-link signatures** — each link in the delegation chain has its own signature, allowing independent verification and mixed-algorithm chains.

3. **No new external dependencies** — revocation check uses `urllib.request` (stdlib). No SD-JWT dependency; the model is structurally aligned without coupling.

4. **Fail-closed revocation** — per CLAUDE.md constraint #5, unreachable revocation endpoints cause verification to fail rather than silently degrade.

## Open questions

1. **Scope restriction enforcement** — delegation links carry optional `scope_restriction` dicts, but verification currently only checks chain integrity (signatures + continuity), not whether scope restrictions narrow correctly at each hop. Should we add constraint-narrowing validation?

2. **Max delegation depth** — no explicit limit on chain length. Should we cap at e.g. 10 links to prevent abuse?

3. **Revocation caching** — currently every verification hits the revocation endpoint. Should we add a short TTL cache for production deployments?

4. **Mandate storage** — the primitive is verification-only (stateless). Should we add a `MandateStore` for indexing received mandates, or leave that to the deployer?

## 10-line usage snippet

```python
from concordia import (
    Mandate, ValidityWindow, TemporalMode,
    sign_mandate, verify_mandate, KeyPair,
)

issuer_key = KeyPair.generate()
mandate = Mandate.create(
    issuer="did:concordia:corp-treasury",
    subject="did:concordia:procurement-agent",
    constraints={"type": "object", "properties": {
        "max_spend": {"type": "number", "maximum": 10000}
    }, "required": ["max_spend"]},
    validity=ValidityWindow(
        mode=TemporalMode.WINDOWED,
        not_before="2026-04-14T00:00:00Z",
        not_after="2026-04-21T00:00:00Z",
    ),
)
mandate = sign_mandate(mandate, issuer_key)
result = verify_mandate(mandate, issuer_key.public_key,
                        action={"max_spend": 5000})
assert result.valid  # True — signature valid, in window, under budget
```
