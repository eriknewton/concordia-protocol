# ERDL Decision Object v1.5: independent Python hash-layer runner

An independently authored Python runner for the ERDL `RUNNER_CONTRACT` hash,
field and chain layer, run against OpenOBA's published
`decision-object-vectors-v1.5.json`.

**Status: independent submission candidate.** This is not a conforming runner
and this document does not declare conformance. R4 makes conformance the
conjunction of Check 1 and Check 2, and Check 2 compares recomputed canonical
bytes against an answers file that R6 forbids a submitting runner from reading.
Check 2, agreement with the oracle, and registration are upstream's to run and
to record. What is here is one measurement plus the `canonical_hex` map that
Check 2 consumes.

Nothing here is a verification of ERDL by ERDL, and nothing here is a
third-party check of Concordia. It is one measurement: what a runner written
from the contract text alone produces on the published vectors, with the
numbers reported at the granularity they were actually measured.

## Upstream input

| Item | Value |
|---|---|
| Upstream repository | `OpenOBA/erdl-vectors` |
| Upstream commit | `8e441eb6afe0984e1315d25b7360b8ace90d6ecd` |
| `decision-object-vectors-v1.5.json` | SHA-256 `d8adf32b7c691bdb3d805fdb0b3f7ac327dc16388cd59a4dfe757d9555e1778c` |
| `RUNNER_CONTRACT.en.md` | SHA-256 `dad36be0a69d694c4a80ba020366a34a4d5a1112ea69bc011a38e29a570c842b` |

The vectors are OpenOBA's artifact, not this repository's, so they are pinned
by digest rather than vendored.

<!-- claim:erdl-v15-runner-pins-its-corpus -->The runner's CLI refuses any vector file whose SHA-256 is not the pinned
upstream digest, and writes no submission output when it refuses, so a
substituted same-version corpus fails closed before any number is produced.<!-- /claim -->
There is no override flag: a named escape hatch would make every number below
conditional on a promise that it was not used. The failure mode this guards
against is specific. A substituted file still declares
`preimage_version: erdl-do-v1.5-hash-flat`, still parses, and still produces
plausible counts, so version agreement on its own is not evidence that a
published number describes the pinned input. The corpus half of the test suite
asserts the same digest before trusting any count, and the submitted envelope's
`method` string names it, so the artifact carries the identity of the corpus it
describes.

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

The same boundary held for the correction described at the end of this
document: the fixes were made from the contract text, the vector file, and the
review findings, with none of the files above opened.

**Dependencies:** the JCS layer is `concordia.canonicalization`, this
repository's own RFC 8785 canonicalizer, written for Concordia's signing
surface long before this task and already covered by its own suite. No ERDL
SDK and no third-party canonicalizer is used at runtime. The test suite
additionally cross-checks the canonical bytes against the `rfc8785` reference
package, which was authored separately from Concordia's canonicalizer, so byte
agreement is between two implementations rather than a restatement of one.
`rfc8785` is a declared dev dependency in `pyproject.toml`
(`[project.optional-dependencies] dev`), which is what the `test` CI job
installs, so the module-level import in the suite cannot become a collection
error.

## Measured results

Produced by the command in the next section, against the pinned input.

| Measurement | Value |
|---|---|
| Vectors in the corpus | 78 |
| Vectors whose compared `expected` fields all reproduced | **78 / 78** |
| Decision objects enumerated across those vectors | 108 |
| Contractually applicable decision objects | 107 |
| Excluded by the version gate | 1 (`V-DO-v15-C07[1]`) |
| Check 1 raw MATCH | **90 / 107** |
| Check 1 raw MISMATCH | **17 / 107** |
| `canonical_hex` keys emitted | 107 |
| `V-DO-v15-K01` Check 1 | **MISMATCH** (R5 requires exactly this) |
| Findings | 0 |
| Excused diagnostics (recorded, printed) | 1 |
| Planted corpus defects caught by the runner | 17 / 17 |

### Which parts of `expected` the 78/78 counts

The row above says "compared `expected` fields" rather than "outcome equals
`expected`" because those are different statements and only the narrower one
was measured. The runner compares four subkeys: `type`, `breach`,
`also_present`, and `resolvable_entry_ids`. Census of `expected` subkeys across
the 78 vectors:

```
type 78 | note 23 | breach 35 | required_fields 21 | checks 14 |
resolvable_entry_ids 2 | also_present 2
```

`expected.note` (prose), `expected.required_fields` (21 vectors) and
`expected.checks` (14 vectors) are not compared. `required_fields` and `checks`
are named by the contract nowhere in the permitted input set, so comparing them
would mean guessing a semantics; the contract's own instruction is that a
runner implements from the contract rather than from inference. Measured
consequence, so the omission is bounded rather than open: resolving every
`required_fields` entry against every decision object of every vector that
declares one leaves 0 unresolved, and on the 7 vectors where `required_fields`
is a strict superset of `compliance_profile.activated_fields`
(`V-COMP-006`, `-008`, `-010`, `-011`, `-014`, `-016`, `-019`) all 7 declare
`expected.type: MATCH`. Comparing them would change no outcome.

### The two numbers that are both written "78/78"

Upstream prose and the submission guide both use "78/78", and the two uses
mean different things. Stating them apart is the point of the table above:

- **78 / 78** is the *vector* count: every one of the 78 vectors produced the
  outcome its own `expected` block declares, on the four subkeys named above.
  Most of those declared outcomes are breaches, not matches.
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
also score 78/78. The suite therefore mutates the corpus seventeen times, each
mutation repairing or breaking exactly one thing a rule depends on, and
requires the runner to notice every one.

Ten of them break the corpus as it stands: a corrupted `audit.hash` on a
passing object, a tampered side restored to its base, the K01 canary sealed so
a defective runner would call it MATCH, the version gate un-tripped, an
undeclared simultaneous breach planted against the `also_present` check, and
one repair each for the SoD, tree-divergence, chain-sequence, time-regression
and jurisdiction rules.

Seven more were added after review, on paths the corpus itself does not reach:
a P6 and a P5 breach planted inside a chain member with the chain re-anchored,
a P6 warning planted on a tamper pair's base side, a stale
`compliance_profile.profile_hash` and a stale `policies[].hash` on a pair's
base side, a stale `profile_hash` re-sealed so Check 1 still passes, and
`jurisdictions` replaced by a bare string sentinel. All seventeen are caught.
A mutation the runner absorbed in silence would mean the matching rule is
decorative.

### What this artifact does not claim

**Check 2 was not run.** Check 2 compares the recomputed canonical bytes
against `decision-object-answers-v1.5.json`, which R6 forbids a conforming
runner from reading and which is not present here. The `canonical_hex` map in
this directory is the *input* to Check 2, not its result. Whether these bytes
agree with the oracle is for whoever holds the oracle to report. The contract
is explicit that passing only one of the two gates is not conformance, so no
conformance claim is made here at all.

**R3's time-anchoring codes are not implemented.** R3 names three groups a
runner must expose. This runner implements two: the single-decision-object
P1 to P6 ladder and the chain priority order. The third,
`clock_drift_detected` and `timestamp_anchor_missing`, R3 introduces as "(with
the signature layer)". The contract states no detection rule for either, the
document it defers detection rules to (`docs/VERIFIER-GUIDE.md` section 4.1) is
outside the permitted input set, and the v1.5 corpus is a hash-mode corpus:
107 of its 108 decision objects declare `audit.mode: "hash"`, and the single
`"signature"`-mode member exists only to trip `mode_mixed_chain` on
`V-DO-v15-C08`. Nothing in the permitted inputs could falsify a guess at those
two rules, so they are declared absent rather than guessed. The runner names
them in `UNIMPLEMENTED_R3_CODES`, prints them in its summary, and records them
in the submitted `method` string.

The scope claimed is therefore: the hash, field and chain layer of the
`RUNNER_CONTRACT`, measured on the pinned v1.5 corpus, with R5's canary
criterion met on the runner side and each vector's compared `expected` fields
reproduced. Conformance and registration are upstream's determination.

## Running it

```bash
python conformance/erdl-do-v1.5/runner.py \
    /path/to/decision-object-vectors-v1.5.json \
    --submission-out /tmp/concordia-python-erdl-do-v15-output.json
```

Exit 0 means every vector reproduced its compared expectations with no
findings. Exit 2 means the supplied vector file is not the pinned corpus and
nothing was measured or written. The narrow test suite:

```bash
# synthetic half only (what CI runs)
pytest tests/test_a2a_2031_erdl_do_v15_runner.py

# including the corpus half
ERDL_V15_VECTORS=/path/to/decision-object-vectors-v1.5.json \
    pytest tests/test_a2a_2031_erdl_do_v15_runner.py
```

## The generated output, and why it lives here

`concordia-python-erdl-do-v15-output.json` is the submission envelope: the six
keys the submission guide fixes (`runner`, `method`, `date`, `artifact`,
`k01_check1`, `canonical_hex`), with the `canonical_hex` map keyed the way the
guide specifies (`<id>`, `<id>-base` / `<id>-tampered`, `<id>[i]`) and
`V-DO-v15-C07[1]` absent because the version gate stops before any bytes exist
for it. Rename on submission:

```bash
cp conformance/erdl-do-v1.5/concordia-python-erdl-do-v15-output.json \
   submissions/concordia-python-output.json
```

### The placement decision

An earlier revision of this artifact lived in `docs/interop/` and carried a
`.json.txt` suffix so that `scripts/claims/clean_room_verify.py`, which adopts
every direct child of `docs/interop/` containing a `*.json` file, would not
adopt it. That was the wrong fix. Naming a JSON file `.txt` to stay outside a
glob is evasion of a gate rather than a placement decision, whatever the
rationale printed next to it, and it left the submitted artifact under a name
no submission accepts.

The artifact is now a real `.json` file in `conformance/`, this repository's
existing home for conformance runners and their vectors, next to
`reference-runner/` and `reference-runner-js/`. `docs/interop/` was the wrong
directory on its own terms: it is a fixture directory whose contract, stated in
its own README, is that each child ships fixture bytes, a deterministic
`generate.py`, a `verify.py` that round-trips the bytes through the shipped
Concordia verifier, and Ed25519 signatures with re-derivable digests. This
artifact is a hash-mode conformance output about a third party's corpus, with
no signature layer at all, so the interop gate's rule is the right rule applied
to the wrong kind of thing.

Confirmed rather than assumed, since the earlier revision's rationale rested on
it: `clean_room_verify.py:531-538` adopts by `child.is_dir() and any(...
child.rglob("*.json"))`, and `verify_fixture` raises when a fixture has no
signature field. Placing the real `.json` back under `docs/interop/` and
running the gate in a clean-room virtualenv produces
`[FAIL] a2a-2031-erdl-v15: no signature fields found`, exit 1. The gate is
unchanged by this commit, and no override, allowlist entry, or skip file was
added to it.

Two consequences of the move, recorded rather than left to be discovered:

1. `conformance/` is compared against generated output by
   `scripts/conformance/generate_vectors.py --check`, which flags any file it
   did not generate. `erdl-do-v1.5` is added to that check's excluded
   directories, alongside `reference-runner` and `reference-runner-js`, which
   are excluded for the same reason: they are hand-written, not generated. The
   check's subject, `conformance/vectors/`, is untouched.
2. `docs/**/*.md` is the scan scope of the executable-claims prose gate, so
   moving this README out of `docs/` would have removed it from that gate as a
   side effect. It is put back in scope through the mechanism the gate already
   provides for files outside `docs/`, a claim in `docs/claims.yaml` naming
   this file in `stated_in`, which is how `conformance/RUNNER_CONTRACT.md` is
   already covered.

This directory is an ERDL-side artifact. It is not a Concordia conformance
result and does not appear in `conformance/IMPLEMENTATIONS.md`, which records
runs against Concordia's own vector manifest.

## What the runner implements

### R1 and R2, the preimage

```
audit.hash = "sha256:" + hex( SHA-256( UTF-8( JCS( DO - audit.hash ) ) ) )
```

`audit.hash` is deleted, not blanked. Blanking produces different bytes, and
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

### The structural shape guard

Every P1 to P6 detector returns nothing when the container it reads is absent
or the wrong type. That is correct for a detector, which must not invent a
breach code the contract does not define, and wrong for the runner as a whole:
without a guard a structurally broken decision object walks the entire semantic
ladder and comes out clean. The sharpest case is `jurisdictions` set to a bare
string such as `"XX"`, since `str` is a `Sequence` in Python and a scalar
sentinel would be read as a jurisdiction list.

The runner therefore checks the shape of every decision object first and
reports a divergence as a finding, which fails the run closed, rather than as
an invented breach code. Every requirement in the guard is a measured property
of all 108 objects in the pinned corpus rather than a guess at the schema:
`audit`, `agent`, `compliance_profile`, `evaluation` and `human_oversight` are
objects, `policies` and `matched_rules` and `jurisdictions` and
`activated_fields` are lists, `timestamp`, `audit.preimage_version`,
`audit.mode`, `agent.id` and `risk_level` are strings, `audit.chain_seq` is an
integer, `human_oversight.required` is a boolean, each policy carries a string
`id` and `author_id` and an object `when`, and each matched rule carries a
string `rule_id` and an object `canonical_tree`. The timestamp and chain
sequence requirements are what keep the chain order detectors from silently
skipping malformed inputs. Members the corpus does not carry everywhere
(`knowledge_references`, `profile_hash`, `policies[].hash`) are type checked
only when present. All 108 objects pass, so the guard adds no finding to the
measurement above.

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
| P6 | `content_unresolvable` | A `knowledge_references[].entry_id` the content layer cannot resolve. Warning-level, and last, so it cannot mask a breach. |

Chain, in the contract's stated order: `hash_mismatch`, `version_unsupported`,
`chain_genesis_mismatch`, `previous_hash_dangling`, `chain_seq_gap`,
`mode_mixed_chain`, `time_regression`.

Not implemented: `clock_drift_detected` and `timestamp_anchor_missing`. See
"What this artifact does not claim" above.

#### Priority is a property of the vector, not of object order

A vector can hold more than one decision object, and its breaches are collected
across all of them into one set and ranked once. Ranking within each object and
concatenating the results, which an earlier revision did, let a low-priority
code on whichever object came first outrank a high-priority code on the second:
a P6 warning on a tamper pair's base side would be reported as the vector's
primary breach while the tampered side's `hash_mismatch` was demoted to
`also_present`. The corpus does not contain such a vector, so this was reachable
only by planting one, which the suite now does.

#### A chain member's semantic breaches are merged, not dropped

The chain detectors lift `hash_mismatch` and `version_unsupported` from the
members so the chain priority order can rank them. A member's own P1 to P6
findings are part of the vector's R3 surface too, so they are merged into the
chain result and ranked by the concatenation of the two stated orders: every
chain code outranks every semantic code, each order is preserved inside itself,
and `content_unresolvable` stays last overall. An earlier revision computed
those member findings and then discarded them, which reported a chain carrying
a planted P5 or P6 as a clean MATCH with zero findings. R3 forbids a silent
pass, and that was one.

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

`time_regression` compares timestamps as strings. Every timestamp in the corpus
is `YYYY-MM-DDTHH:MM:SS.mmmZ`, so lexicographic order is chronological order
here; a corpus mixing UTC offsets would need a parse first. Recorded as a
bounded assumption, since no vector exercises it.

### One documented interpretation

`content_unresolvable` needs a resolvable universe, and the contract defers
that rule to a document outside the permitted input set. The vectors that
declare the breach also declare `expected.resolvable_entry_ids: ["kb-001"]`,
and `kb-001` is independently the only entry any other decision object in the
corpus references.

Rather than reading a value out of an `expected` block in silence, the
resolvable universe is an explicit runner input, `--resolvable-entry-ids`,
defaulting to `kb-001`. Every vector that declares its own set is cross-checked
against the configured one and a disagreement is reported as a finding, not
absorbed. Both available readings of that field converge on the same universe
and the same results, so this is an interpretation to disclose rather than an
ambiguity that blocks implementation.

### R2's intra-field hashes

`policies[].hash` recomputes for all 108 decision objects.
`compliance_profile.profile_hash` recomputes for 107; the exception is
`V-COMP-F02-tampered`, the swapped-profile tamper, whose stale profile hash is
the tamper that vector encodes.

The contract names no breach code for an intra-field hash divergence, so none
is invented: a divergence is reported as a diagnostic note, and a note is a
finding. That is a change from an earlier revision of this document, which
justified treating such notes as suppressible by asserting that an intra-field
divergence "necessarily also breaks the whole-object flat hash". That assertion
is false, and this repository's own test refutes it.
`compliance_profile.profile_hash` and `policies[].hash` are ordinary fields
inside the decision object, so a stale value participates in the R1 preimage as
itself; once the emitter recomputes `audit.hash` afterwards, Check 1 passes
with the divergence still inside.
`test_intra_field_hash_divergence_survives_a_matching_flat_hash` plants exactly
that and asserts `check1 == "MATCH"` with no `hash_mismatch`. The empirical
case, `V-COMP-F02-tampered`, accompanies a `hash_mismatch` only because that
tamper did not re-seal `audit.hash`. The note is the only surface for the
divergence, which is why it is a finding.

The single exception is recorded in `KNOWN_INTRA_FIELD_EXCEPTIONS`, keyed to
one oracle key and one field name with its reason, and the run prints it under
`excused diagnostics` rather than dropping it. An earlier revision suppressed
notes for every tamper pair, which made an identical defect a finding on a
single-object vector and silent on a pair.

## Files

| File | What it is |
|---|---|
| `runner.py` | The runner: pinned-input binding, JCS domain guards, R1/R2 preimages, the shape guard, R3 detection and priority, chain handling, vector enumeration, CLI. |
| `verify_envelope.py` | A self-consistency check for the generated envelope, not an answer-key verifier. It holds no oracle and reads no vectors. It imports no Concordia code: it re-derives every published byte string with the `rfc8785` reference package, checks the R2 exclusions and the version gate held in those bytes, enforces the submission key grammar, and reproduces the `V-DO-v15-C01` chain anchors end to end. Its `k01_check1` assertion is a check on a self-reported envelope field, not a re-derivation of R5. |
| `concordia-python-erdl-do-v15-output.json` | Generated submission envelope, 107 `canonical_hex` keys. |
| `../../tests/test_a2a_2031_erdl_do_v15_runner.py` | The focused suite: synthetic rule-by-rule negative controls plus the corpus assertions. |

### What `verify_envelope.py` cannot show

Recorded because a check whose boundary is not stated reads as stronger than it
is. `rfc8785.dumps(json.loads(raw)) == raw` is a fixed-point test, which any
well-formed subset of a decision object also passes, so the script cannot
detect over-deletion or projection of fields beyond the three R2 fields and
`audit` presence. The `V-DO-v15-C01` chain anchoring is the one place the
binding is end to end: hashing a member's published preimage bytes has to
reproduce a `previous_hash` carried inside the next member, a value that was
never an input to the script. That covers 2 links. It cannot re-derive R5,
because the published preimage is the artifact with `audit.hash` deleted, so
there is no stored hash left to compare against; R5 evidence is the runner
recomputing Check 1 against the pinned corpus.

### Residual limits

- CI runs the synthetic half of the suite, so it cannot detect drift between
  `runner.py` and the committed envelope: regenerating needs the corpus, which
  is not vendored. Partly mitigated by the synthetic assertions on the preimage
  projection and on agreement with `rfc8785`, which catch a projection or
  serialization change. A semantic change that alters no synthetic assertion
  and is not re-measured would go unnoticed until the corpus half runs.
- `verify_envelope.py` takes the envelope path as an argument, so it survives
  the rename to `submissions/concordia-python-output.json`, but its
  `EXPECTED_KEY_COUNT = 107` is specific to this corpus.

## Correction history

The first revision of this artifact was reviewed adversarially by two
independent reviewers and did not clear the gate. Every published number
reproduced exactly, and the defects were on paths the corpus does not reach
plus claim precision. This revision, in the same branch:

| Was | Now |
|---|---|
| Chain members' P1 to P6 breaches computed, then discarded | Merged into the chain result under a combined priority |
| Breaches ranked per object, then concatenated | Collected across the vector and ranked once |
| Intra-field notes suppressed for every pair vector | One recorded exception keyed to `V-COMP-F02-tampered` and one field, printed rather than dropped |
| "any such divergence necessarily also breaks the whole-object flat hash" | Corrected; the repository's own test refutes it |
| R3 described as implemented | Time-anchoring codes declared unimplemented, in the runner, the summary, the envelope and here |
| "R1 to R6 implemented", conformance framing | Independent submission candidate; Check 2, oracle agreement and registration pending upstream |
| Any vector file accepted at the CLI | Bound to the pinned SHA-256, fail closed, no opt-out |
| `.json.txt` in `docs/interop/` | A real `.json` in `conformance/erdl-do-v1.5/` |
| `verify.py`, called an answer-key verifier | `verify_envelope.py`, an envelope self-consistency check |
| Key grammar accepting nearly any string | Three key shapes, pair completeness, chain contiguity |
| Structurally broken objects passing the ladder in silence | Shape guard, fails the run closed |
| Doubled key prefix in finding text | Single prefix |
| "outcome equals their declared `expected`" | Narrowed to the four compared subkeys, with the census |
| `rfc8785` import undeclared in the diff | Confirmed as a declared dev dependency, stated here and in the suite |
| 10 planted-defect mutations | 17, covering the newly reachable paths |
