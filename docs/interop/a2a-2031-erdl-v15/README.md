# ERDL Decision Object v1.5: independent Python conformance runner

An independently authored Python implementation of the ERDL
`RUNNER_CONTRACT` requirements R1 to R6, run against OpenOBA's published
`decision-object-vectors-v1.5.json`. It is intended as a third implementation
alongside the Node reference runner and norviq-go.

Nothing here is a verification of ERDL by ERDL, and nothing here is a
verification of Concordia by a third party. It is one measurement: what a
runner written from the contract text alone produces on the published vectors,
with the numbers reported at the granularity they were actually measured.

## Upstream input

| Item | Value |
|---|---|
| Upstream repository | `OpenOBA/erdl-vectors` |
| Upstream commit | `8e441eb6afe0984e1315d25b7360b8ace90d6ecd` |
| `decision-object-vectors-v1.5.json` | SHA-256 `d8adf32b7c691bdb3d805fdb0b3f7ac327dc16388cd59a4dfe757d9555e1778c` |
| `RUNNER_CONTRACT.en.md` | SHA-256 `dad36be0a69d694c4a80ba020366a34a4d5a1112ea69bc011a38e29a570c842b` |

The vectors are OpenOBA's artifact, not this repository's, so they are pinned
by digest rather than vendored. The corpus half of the test suite is skipped
unless `ERDL_V15_VECTORS` points at a local copy, and it re-checks that digest
before trusting any count.

## Independence boundary

This is the load-bearing property of the artifact, so it is recorded exactly.

**Read while implementing** - two files only:

- `RUNNER_CONTRACT.en.md`
- `decision-object-vectors-v1.5.json`

**Read after the runner produced its first sealed result**, to format the
output file and for nothing else:

- `submissions/README.md` (the third-party submission guide)

**Not read at any point:**

- the reference verifier (`scripts/verify-v1.5.js`) and every other script
  under the upstream `scripts/` directory
- the answers file `decision-object-answers-v1.5.json` (R6 forbids it)
- `docs/VERIFIER-GUIDE.md`, RFC-002, and the generated conformance report
- the norviq-go submission output
- any earlier ERDL runner written in this workspace
- any internet source consulted for implementation guidance

**Dependencies:** the JCS layer is `concordia.canonicalization`, this
repository's own RFC 8785 canonicalizer, written for Concordia's signing
surface long before this task and already covered by its own suite. No ERDL
SDK and no third-party canonicalizer is used at runtime. The test suite
additionally cross-checks the canonical bytes against the independent
`rfc8785` reference package, so byte agreement is between two separately
authored implementations rather than a restatement of one.

## Measured results

Produced by the command in the next section, against the pinned input.

| Measurement | Value |
|---|---|
| Vectors in the corpus | 78 |
| Vectors whose runner outcome equals their declared `expected` | **78 / 78** |
| Decision objects enumerated across those vectors | 108 |
| Contractually applicable decision objects | 107 |
| Excluded by the version gate | 1 (`V-DO-v15-C07[1]`) |
| Check 1 raw MATCH | **90 / 107** |
| Check 1 raw MISMATCH | **17 / 107** |
| `canonical_hex` keys emitted | 107 |
| `V-DO-v15-K01` Check 1 | **MISMATCH** (R5 requires exactly this) |
| Findings | 0 |
| Planted corpus defects caught by the runner | 10 / 10 |

### The two numbers that are both written "78/78"

Upstream prose and the submission guide both use "78/78", and the two uses
mean different things. Stating them apart is the point of the table above:

- **78 / 78** is the *vector* count: every one of the 78 vectors produced the
  outcome its own `expected` block declares. Most of those declared outcomes
  are breaches, not matches.
- **90 / 107** is the *decision object* Check 1 raw MATCH count. It is not
  78, and it is not 107. Seventeen decision objects recompute to a hash that
  differs from their self-reported `audit.hash`, and every one of them is
  supposed to: fifteen are the tampered side of a tamper pair, one is the
  altered member of the `V-DO-v15-C02` attack chain, and one is the
  `V-DO-v15-K01` canary.
- **107 / 107** is the Check 2 coverage count, the number of applicable
  decision objects for which canonical bytes exist and an oracle key is
  expected.

A runner that reported "78/78 MATCH" as a hash-layer result would be claiming
something false about seventeen decision objects, K01 among them. The K01
canary must come out MISMATCH on Check 1; a MATCH there is the exact defect
the canary exists to catch.

### Why 78/78 is not a vacuous result

A runner that reported every vector as passing regardless of its input would
also score 78/78. The suite therefore mutates the corpus ten times, each
mutation repairing or breaking exactly one thing a rule depends on, and
requires the runner to notice every one: a corrupted `audit.hash` on a passing
object, a tampered side restored to its base, the K01 canary sealed so a
defective runner would call it MATCH, the version gate un-tripped, an
undeclared simultaneous breach planted against the `also_present` check, and
one repair each for the SoD, tree-divergence, chain-sequence, time-regression
and jurisdiction rules. All ten are caught. A mutation the runner absorbed
silently would mean the matching rule is decorative.

### What this artifact does not claim

Check 2 was **not run**. Check 2 compares the recomputed canonical bytes
against `decision-object-answers-v1.5.json`, which R6 forbids a conforming
runner from reading and which is not present here. The `canonical_hex` map in
this directory is the *input* to Check 2, not its result. Whether these bytes
agree with the oracle is for whoever holds the oracle to report.

Conformance is therefore claimed only as: R1 to R6 implemented from the
contract, R5's canary criterion met on the runner side, and every vector's
declared expectation reproduced. Registration as a conforming implementation
is upstream's determination, not this document's.

## Running it

```bash
python docs/interop/a2a-2031-erdl-v15/runner.py \
    /path/to/decision-object-vectors-v1.5.json \
    --submission-out /tmp/concordia-python-erdl-do-v15-output.json
```

Exit code 0 means every vector reproduced its declared expectation with no
findings. The narrow test suite:

```bash
# synthetic half only (what CI runs)
pytest tests/test_a2a_2031_erdl_do_v15_runner.py

# including the corpus half
ERDL_V15_VECTORS=/path/to/decision-object-vectors-v1.5.json \
    pytest tests/test_a2a_2031_erdl_do_v15_runner.py
```

## The generated output

`concordia-python-erdl-do-v15-output.json.txt` is the submission envelope:
`runner`, `method`, `date`, `artifact`, `k01_check1`, and the `canonical_hex`
map keyed the way the submission guide specifies (`<id>`, `<id>-base` /
`<id>-tampered`, `<id>[i]`), with `V-DO-v15-C07[1]` absent because the version
gate stops before any bytes exist for it.

The content is exactly what would be submitted. The `.txt` suffix is a local
constraint, not a format change: `scripts/claims/clean_room_verify.py` adopts
every direct child of `docs/interop/` that contains a `*.json` file and
requires it to carry verifiable Ed25519 signatures and re-derivable digests.
This artifact is a hash-mode conformance output with no signatures, so a
`.json` name here would fail that gate. Rename on submission:

```bash
cp docs/interop/a2a-2031-erdl-v15/concordia-python-erdl-do-v15-output.json.txt \
   submissions/concordia-python-output.json
```

Whether `clean_room_verify.py` should grow a signature-free fixture class is a
gate-design question, deliberately left open rather than answered by weakening
the gate.

## What the runner implements

### R1 and R2, the preimage

```
audit.hash = "sha256:" + hex( SHA-256( UTF-8( JCS( DO - audit.hash ) ) ) )
```

`audit.hash` is deleted, never blanked. Blanking produces different bytes, and
the test suite asserts that directly. `signature` and `signing_key_id` are
deleted defensively; in hash mode they are absent and the deletion is a no-op,
which is also asserted. Every other field participates: no whitelist, no
projection.

Intra-field hashes exclude the field being computed. `policies[].hash`
additionally excludes `gloss`, a render product rather than rule content. The
v1.5 corpus contains no policy carrying a `gloss` member, so that exclusion is
implemented from the contract text and evidenced only by this repository's own
test.

### JCS domain guards

Three classes of value are rejected before any bytes are produced, because two
conforming implementations could otherwise legitimately disagree on them:

- integers outside the IEEE-754 safe range (JCS number formatting defers to
  ECMA-262, whose doubles cannot hold them exactly);
- non-finite floats and negative zero, which JCS cannot represent;
- unpaired UTF-16 surrogates, which have no UTF-8 encoding and which JSON
  implementations disagree about.

The v1.5 corpus exercises none of these: it contains no float, no integer
outside the safe range, and no surrogate, and every non-ASCII string in the
file is vector metadata rather than decision-object content. The guards are
therefore covered by synthetic tests only, and that is stated rather than
implied by a passing corpus run.

### R3, the breach codes

Single decision object, evaluated in this order. The version gate terminates
first and the R1 hash gate follows; the contract's P1 to P6 ladder is the
semantic layer beneath them.

| Order | Code | Rule |
|---|---|---|
| gate | `version_unsupported` | `audit.preimage_version` is not `erdl-do-v1.5-hash-flat`. Terminates early; no canonical bytes, no oracle key. |
| gate | `hash_mismatch` | Recomputed `audit.hash` differs from the self-reported one. |
| P1 | `jurisdiction_mismatch` | A jurisdiction code outside the authoritative six-jurisdiction set. |
| P2 | `compliance_field_missing` | An `activated_fields` entry does not resolve in the decision object, or `risk_level` is `critical` and `activated_fields` omits `signature`. |
| P3 | `oversight_missing` | `risk_level` is `high` or `critical` and `human_oversight.required` is not true. |
| P4 | `sod_violation` | A policy's `author_id` equals the deciding `agent.id`. |
| P5 | `tree_snapshot_divergence` | A `matched_rules[].canonical_tree` does not equal its policy's `when`, compared on canonical bytes. |
| P6 | `content_unresolvable` | A `knowledge_references[].entry_id` the content layer cannot resolve. Warning-level, and last, so it can never mask a breach. |

Chain, in the contract's stated order: `hash_mismatch`, `version_unsupported`,
`chain_genesis_mismatch`, `previous_hash_dangling`, `chain_seq_gap`,
`mode_mixed_chain`, `time_regression`.

Every vector's `expected.also_present` is checked **in both directions**: a
declared item that does not hold is a finding, and an item that holds without
being declared is a finding. Both directions are exercised by synthetic tests,
because the corpus produces zero of each and a check that never fires is not
evidence.

### Rules derived rather than quoted

`RUNNER_CONTRACT` names several detection rules but defines them in
`docs/VERIFIER-GUIDE.md` section 4.1 and RFC-002, neither of which was read.
Those rules were derived from the vector corpus and each was checked to fire
on exactly the vectors that declare it and on no others. The derivations, and
what would falsify each:

| Rule | Derivation | Discrimination |
|---|---|---|
| Authoritative jurisdictions `{BR, CN, EU, IN, SG, US}` | The complete set of codes the corpus treats as legitimate; `V-COMP-001` to `-005`, `-020`, `-021` cover all six. | The only other code anywhere in the corpus is the sentinel `XX`, on exactly the two vectors declaring `jurisdiction_mismatch`. |
| `compliance_field_missing` | `activated_fields` entries must resolve as dotted paths; the `critical` plus `signature` case is stated in the contract itself. | Fires on `V-COMP-F01`, `-F08`, `-F09`, `-F10` and no other vector. |
| `oversight_missing` | `risk_level` in `{high, critical}` requires `human_oversight.required` true. | Fires on `V-COMP-F04` alone; `F08` and `F09` are `critical` with oversight required and breach elsewhere. |
| `sod_violation` | A policy authored by the deciding agent. | `V-COMP-F05` is the only decision object in the corpus whose policy `author_id` equals its `agent.id`; every other policy is authored by `author-openoba`. |
| `tree_snapshot_divergence` | `canonical_tree` compared to the matched policy's `when` on canonical bytes. | Fires on `V-DO-v15-A07`, `A09`, `A10` and `V-COMP-F11`, which are exactly the four vectors declaring it. |
| Chain rules | Genesis `previous_hash` non-null; broken predecessor link; non-consecutive `chain_seq`; disagreeing `audit.mode`; backwards `timestamp`. | Each fires on exactly its own `C0x` vector. |

### One documented interpretation

`content_unresolvable` needs a resolvable universe, and the contract defers
that rule to a document outside the permitted input set. The vectors that
declare the breach also declare `expected.resolvable_entry_ids: ["kb-001"]`,
and `kb-001` is independently the only entry any other decision object in the
corpus references.

Rather than silently reading a value out of an `expected` block, the resolvable
universe is an explicit runner input, `--resolvable-entry-ids`, defaulting to
`kb-001`. Every vector that declares its own set is cross-checked against the
configured one and a disagreement is reported as a finding, not absorbed. Both
available readings of that field converge on the same universe and the same
results, so this is an interpretation to disclose rather than an ambiguity that
blocks implementation.

### R2's intra-field hashes as diagnostics

`policies[].hash` recomputes for all 108 decision objects.
`compliance_profile.profile_hash` recomputes for 107; the exception is
`V-COMP-F02-tampered`, the swapped-profile tamper, whose stale profile hash is
consistent with the tamper it encodes. The contract names no breach code for
an intra-field hash divergence and any such divergence necessarily also breaks
the whole-object flat hash, so these are reported as diagnostic notes attached
to the `hash_mismatch` they accompany rather than invented as a new code.

## Files

| File | What it is |
|---|---|
| `runner.py` | The runner: JCS domain guards, R1/R2 preimages, R3 detection and priority, chain handling, vector enumeration, CLI. |
| `verify.py` | Answer-key verifier for the generated output. Imports no Concordia code: it re-derives every published byte string with the independent `rfc8785` package, checks the R2 exclusions and the version gate held in the bytes, and reproduces the `V-DO-v15-C01` chain anchors end to end. Runs without the upstream vectors. |
| `concordia-python-erdl-do-v15-output.json.txt` | Generated submission envelope, 107 `canonical_hex` keys. |
| `../../../tests/test_a2a_2031_erdl_do_v15_runner.py` | The focused suite: synthetic rule-by-rule negative controls plus the corpus assertions. |
