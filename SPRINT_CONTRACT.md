# SPRINT_CONTRACT.md — SEC-003: Canonical JSON Divergence (Cross-Repo)

**Sprint Date:** 2026-03-28
**Finding ID:** SEC-003
**Repos:** Sanctuary (TypeScript) + Concordia (Python)
**Scope:** Coordinated fix — both repos must produce byte-identical canonical JSON

This is a copy of the unified sprint contract. The primary copy lives in the Sanctuary repo.
See Sanctuary/SPRINT_CONTRACT.md for the full pre-implementation analysis (Step 1 a/b/c).

---

## Summary of Divergence

1. **Number formatting**: V8 formats `1.0` as `"1"`, Python as `"1.0"` — different bytes, different hash
2. **Unicode**: `sanctuary_bridge.py` uses `json.dumps` default (ASCII-escapes non-ASCII), diverging from both TypeScript and `canonical_json`
3. **Negative zero**: Python rejects, TypeScript silently coerces — asymmetric validation
4. **Inconsistent canonical function usage**: Both repos have paths that bypass their own canonical serializer

## Concordia Changes

| File | Change |
|------|--------|
| `concordia/signing.py` | Rewrite `canonical_json` with manual recursive builder + ECMAScript number formatter |
| `concordia/sanctuary_bridge.py:113` | Replace `json.dumps()` with `canonical_json().decode("utf-8")` |
| `tests/test_signing.py` | Add cross-language canonical JSON test vectors |
| `tests/test_sanctuary_bridge.py` | Add test verifying bridge uses canonical_json |

## Definition of Done
1. `canonical_json` produces byte-identical output to TypeScript's `stableStringify` for all shared test vectors
2. `sanctuary_bridge.py` uses `canonical_json` — no vanilla `json.dumps` on commitment paths
3. Both repos reject `-0.0`
4. Full test suite passes: ≥483 tests
