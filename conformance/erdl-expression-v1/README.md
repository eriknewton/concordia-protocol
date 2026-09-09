# ERDL expression layer: an independent Python runner

A Python implementation of the ERDL expression kernel, written from the ERDL
v2.1 specification and the expression-runner contract, and run against
OpenOBA's published `v-engine-vectors.json`.

**Status: independent submission candidate, re-measured 2026-09-09 against the
240-vector corpus.** This is not a conforming runner and this document does not
declare conformance. ER4 makes conformance a
value-identical recomputation checked against an answer oracle that ER9 forbids
a submitting runner from reading, so the cross-verification and the registry
entry are upstream's to run and to record. What is here is one measurement plus
the per-vector result map that the cross-verification consumes.

Nothing here is a verification of ERDL by ERDL, and nothing here is a
third-party check of Concordia. It is one measurement: what a runner written
from the specification text alone produces on the published vectors, with the
open questions listed rather than resolved by inspection of another
implementation.

## Independence boundary

The neutrality of this submission rests on what was read while writing it, so
the boundary is recorded here and repeated verbatim in the submission file's
`method` field.

**Read:**

* `erdl-spec.md` v2.1 and its English translation, sections 5 (the three
  writing projections, the 34-node kernel, the gloss templates), 7 (evaluation
  semantics, the E1 to E12 constraints, the deterministic-semantics rules) and
  appendices A and B.
* `EXPRESSION-RUNNER-CONTRACT.md`, ER1 through ER9.
* `v-engine-vectors.json`, for the vector shapes and the published compile
  targets. The file ships no expected values.
* `submissions/README.md` in `OpenOBA/erdl-vectors`, for the shape of a
  submission envelope.

**Not read, at any point:**

* The reference engine, `scripts/v-engine.mjs`.
* The in-repo verifier scripts, `verify-v-engine.mjs`,
  `verify-v-engine-full.mjs` and `verify-v-engine-reverse.mjs`, which the
  contract itself describes as a second source of the reference implementation
  rather than a third party.
* The vector generator, `generate-v-engine.mjs`.
* `@openoba/erdl`, `erdl-formal`, and any other OpenOBA engine or library.
* The answer oracle `v-engine-answers.json`, which ER9 forbids.

No ERDL package is a dependency of this runner. It is standard-library Python
with no third-party imports at all, and it imports nothing from Concordia, so
the non-dependency between Concordia and any other project is preserved.

## What is implemented

| Surface | Contents |
|---|---|
| Expression kernel | the 34 nodes in 10 groups: value, logic, comparison, set, string, existence and measure, quantifier, arithmetic, time, aggregate |
| Simple compiler | the 30 operators, 28 conditions and 2 stateful modifiers, with the exists guard the specification's compile table requires |
| Decision-table compiler | cells in the six comparison operators, in both the specification's row shape and the corpus's, compiled to a logical AND in column order, row order as precedence, the empty row to literal true, and the row decision checked against the section 6 enumeration |
| gloss renderer | the frozen per-node templates from spec v2.1 section 5.5, English canonical, with the Chinese column kept as a presentation-only projection |
| Constraints | E1 to E5 and E7 to E12 |

Arithmetic runs on exact rationals (`fractions.Fraction`), with a single
half-even rounding to scale 14 at the reported value, which is what E2 and
section 7.3(c) require. No binary float appears anywhere: the corpus loader
parses numeric literals through `Decimal`, the kernel refuses a float outright,
and the submission writer emits numbers as exact decimal tokens rather than
through a float encoder, so `1e21 + 1` is written as `1000000000000000000001`
rather than rounded away.

## Layout

```
conformance/erdl-expression-v1/
  README.md      this file
  RESULTS.md     the measurement, the counts, and every recorded ambiguity
  runner.py      the CLI
  erdl_expr/     the kernel: values, errors, limits, times, evaluator,
                 simple, gloss, temporal, results
  tests/         one module per node group, plus sentinels, limits, gloss,
                 submission format, and the whole-corpus run
  output/        the generated submission file, plus the same measurement in
                 the alternate decimal-string number encoding
```

## Running it

The vector file is OpenOBA's artifact rather than this repository's, so it is
referenced by digest instead of vendored. Fetch it from
`OpenOBA/erdl-vectors` first.

Evaluate the corpus and print the counts:

```
python3 conformance/erdl-expression-v1/runner.py /path/to/v-engine-vectors.json --date 2026-09-09
```

Regenerate the submission file:

```
python3 conformance/erdl-expression-v1/runner.py /path/to/v-engine-vectors.json \
  --date 2026-09-09 \
  --submission-out conformance/erdl-expression-v1/output/concordia-python-expression-output.json
```

Both flags below were opened by ambiguities the specification has since
settled, and both are kept because the alternate form is still useful:

* `--number-format {json-number,decimal-string}` selects how a reported number
  is encoded. Contract ER3 settles this on `json-number`, which is what the
  submission carries; the envelope records which encoding it holds. The
  decimal-string form is regenerated alongside it because the same repository's
  CHANGELOG describes the oracle's numbers the other way, and a decimal string
  is the only form that stays exact past `2**53 - 1`. See RESULTS.md A1.
* `--gloss-language {en,zh}` selects the gloss template column. Spec v2.1 pins
  section 5.5 to English as canonical, so `en` is what a reported value
  carries and `zh` is a presentation projection. See RESULTS.md A4.

## Running the tests

The suite lives inside this directory rather than under the repository's
`tests/` tree, so it needs its own invocation:

```
pytest conformance/erdl-expression-v1
mypy --strict conformance/erdl-expression-v1/erdl_expr \
     conformance/erdl-expression-v1/runner.py \
     conformance/erdl-expression-v1/tests
```

The corpus module skips unless `ERDL_V_ENGINE_VECTORS` points at a local copy
of the vector file. Everything else runs without it, because every case is
derived from the specification text rather than from the corpus.

## Author

Erik Newton.
