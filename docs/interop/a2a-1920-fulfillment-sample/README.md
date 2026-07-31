# A2A #1920 sample FulfillmentAttestation (transactional per-action)

A byte-checkable sample for the A2A v0.4 transactional per-action receipts
thread (#1920). It is a shipped-shape Concordia **FulfillmentAttestation**
that:

- **composes** on a shared `charge_ref` / `action_ref` join key (the same
  string that keys the upstream per-action charge receipt), so a verifier
  joins the two artifacts by exact match without either carrying the other's
  contents;
- carries **only behavioral signals and hash references**, never the
  underlying action terms (amount, item, counterparty prices). This is the
  SPEC §9.6.6 privacy invariant, and the verify script proves it holds by
  scanning the whole artifact with Concordia's shipped raw-deal-term
  detectors.

It uses only shipped Concordia v0.7.0a1 surfaces: the Ed25519 signer, the
RFC 8785 JCS canonicalizer, and the shipped
`validate_fulfillment_attestation` verifier
(`schemas/fulfillment_attestation.schema.json`).

## Files

| File | What it is |
|------|------------|
| `generate.py` | Deterministic generator (fixed seed). Rewrites the two files below. |
| `verify.py` | Offline byte-check: shipped-verifier PASS, signature PASS, `canonical_sha256` recomputed and compared (plus an independent `rfc8785` cross-check), one-byte tamper REJECT, privacy-invariant scan, join-key match. |
| `fulfillment_attestation.json` | The signed sample artifact. |
| `sample.json` | Recomputable expectations: seed, public key, join keys, signature, canonical hash. |

Every value `sample.json` publishes is an expectation the verifier re-derives
from the artifact bytes, never an input it reads as truth: `canonical_sha256` is
recomputed and compared, the signature string is compared against the
artifact's own signature member, and the public key is re-derived from the
published seed. A recorded digest that no verifier derives is an answer key,
not a test.

## Reproduce it

```
cd docs/interop/a2a-1920-fulfillment-sample
python generate.py      # regenerates the sample from a fixed seed
python verify.py        # byte-checks everything; exit 0 == all PASS
```

The Ed25519 key comes from the fixed 32-byte ASCII seed
`a2a-1920-settlement-agent-seed01` (recorded in `sample.json`), so rerunning
`generate.py` reproduces the same bytes and the same signature.

## Load-bearing values

```
charge_ref       = urn:a2a:charge:2026-05-10-tx-88f01c
action_ref       = urn:a2a:action:2026-05-10-deliver-88f01c
canonical sha256 = sha256:47ec4298e210d3aa18832b30f8cc087b84bfebf1f664eced187918de085bf508
signature b64url = sLNIOmz8qhx3scaDXgxc9G_G2jemSZUI1ckdYhbNV7s6RJ0NSydt9J7nn1A8I_AbrUBL1yBWQXMKu-PX7MZgAA==
```

`canonical sha256` is `SHA-256` of the RFC 8785 JCS bytes of the artifact with
the detached `signature` field removed (the same bytes the Ed25519 signature
covers).

## Field placement (all schema-allowed)

`schemas/fulfillment_attestation.schema.json` sets `additionalProperties: true`
at the top level and on `references[]` items, so the composition keys and the
behavioral block ride on the stock shape without a schema change.

| Content | Where | Why it is safe |
|---------|-------|----------------|
| Composition join keys | top-level `charge_ref`, `action_ref` | exact-match join surface; opaque URNs, no terms |
| Coarse outcome | `fulfillment.status` (`fulfilled_clean`) + `settled_at` | shipped enum; carries no amounts |
| Behavioral signals | `meta.behavioral_signals` | bounded booleans + small counts (`settlement_attempts`, `disputes_raised`), no terms |
| Hash references | `references[].id` | urn / `sha256:` pointers to the agreement attestation, the charge receipt, and off-band delivery evidence; the referenced bytes are not inlined |

## The privacy invariant, proven

The behavioral-signal-only rule (SPEC §9.6.6) is not asserted; it is checked.
`verify.py` recursively walks every string key and value in the artifact
(excluding the opaque detached signature) and matches each against the shipped
`_RAW_TERM_PATTERNS` from `concordia.schema_validator` (the same currency /
price / quantity detectors the SDK uses). The sample contains no raw term, so
the scan finds nothing. As a negative control the script injects
`"price: 150000 USD"` into a copy and confirms the same scan catches it, so a
PASS is meaningful rather than vacuous.

## What `verify.py` proves (the exact sequence)

1. The sample passes the shipped `validate_fulfillment_attestation` (schema +
   the `fulfills`-reference equality invariant): **PASS**.
2. The Ed25519 signature verifies over the shipped canonical JSON: **PASS**.
3. Flipping one byte of the signed body flips the signature to **REJECT**.
4. Privacy invariant: no raw deal terms anywhere in the artifact (**PASS**),
   and the same scan does catch an injected term (negative control).
5. The `charge_ref` / `action_ref` join keys are present and match
   `sample.json`.

## Second-implementation reproductions

An independent implementation reproduced the load-bearing digest with its own
RFC 8785 JCS canonicalizer, so a reader can diff two canonicalizers against the
one digest with no shared SDK and no issuer callback.

| Implementation | Method | Result | Date | Source |
|----------------|--------|--------|------|--------|
| AgentID (`haroldmalikfrimpong-ops`) | Independent RFC 8785 JCS over the attestation minus `signature`, then SHA-256, then Ed25519 verify against `public_key_b64url` | Canonical digest matched `sha256:47ec4298…085bf508`; Ed25519 signature VALID over those bytes; a one-byte tamper of the signed body flips to REJECT; privacy shape holds (behavioral signals plus hash refs, no terms); `charge_ref` (`urn:a2a:charge:2026-05-10-tx-88f01c`) byte-matches on both sides | 2026-07-20 | [A2A #1920 comment 17706287](https://github.com/a2aproject/A2A/discussions/1920#discussioncomment-17706287) |

The full digest is
`sha256:47ec4298e210d3aa18832b30f8cc087b84bfebf1f664eced187918de085bf508`.
Concordia's shipped canonicalizer, the independent `rfc8785` reference library,
and AgentID's independent recompute all land on that same value, which confirms
the published hash is the RFC 8785 JCS standard digest and not a
Concordia-specific artifact. Only the `charge_ref` URN join key is expected to
byte-match across the two artifacts; each side keeps its own `action_ref`
representation (Concordia's opaque URN handle for correlation, AgentID's content
digest for tamper-binding), which is the complementary-by-design seam recorded
in the thread.

Author: Erik Newton.
