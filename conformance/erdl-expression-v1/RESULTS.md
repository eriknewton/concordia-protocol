# ERDL expression layer: measured results

One measurement, taken on 2026-09-09 against OpenOBA's published
`v-engine-vectors.json` (SHA-256
`3ee30466cc6d95ddd99bc412cfc88b2f2dd3f890b8687b8f12043cc40074c902`, 240
vectors, `vector_version` v2.0.0, `spec` erdl-spec-v2.1).

This replaces the 2026-09-07 measurement, which was taken against the 239-vector
corpus before the v1.6.0 revision. The sources this round was read against, at
the exact commits:

| Source | Repository | Commit |
|---|---|---|
| `v-engine-vectors.json`, `EXPRESSION-RUNNER-CONTRACT.md`, `scripts/verify-v-engine-submission.mjs`, `CHANGELOG.md` | `OpenOBA/erdl-vectors` (`master`) | `97e0c00723aec526983cea5804e148680b3e0539` |
| `erdl-spec.en.md` (sections 5, 7, 8, appendix E) | `OpenOBA/erdl-landing` (`main`) | `dcb7a554c00c047d849899a6327ef6e37d7a39de` |

The independence boundary is unchanged and is restated in the submission's
`method` field: the reference engine (`scripts/v-engine.mjs`), the in-repo
verifier scripts, the generator, `@openoba/erdl`, `erdl-formal` and the answer
oracle `v-engine-answers.json` were not opened, imported, vendored or consulted
in this round either. The one file read that was not read in the first round is
`scripts/verify-v-engine-submission.mjs`, and only for its envelope contract
and its comparison rule; it carries no node semantics.

This is not a conformance declaration. ER4 is settled by a cross-verification
run against an oracle this runner is forbidden to read (ER9), and registration
is upstream's to record. What is here is the result of evaluating every vector
with an implementation written from the specification and the contract, plus
the questions the specification left open and the reading each one was given.

## What changed since the 2026-09-07 measurement

Six of the 240 result objects differ from the previous envelope. Nothing in the
evaluator's numeric model, its `errored` assignment or its folding changed.

| Vector | Change | Cause |
|---|---|---|
| `V-ENGINE-E10-003` | new, `true` | the corpus's new E10 in-membership NFC vector; the kernel already NFC-normalized both sides of `in`, so it evaluated correctly with no code change |
| `V-GLOSS-005` | `cat is in [a, b]` to `cat in [a, b]` | spec v2.1 reworded the section 5.5 `in` template |
| `V-GLOSS-008` | `age is between 16 and 60` to `age is in the inclusive range 16 to 60` | reworded `between` template |
| `V-GLOSS-009` | `every item in items satisfies: ...` to `all elements in items satisfy "..."` | reworded `all` template |
| `V-GLOSS-011` | `date plus 2 years duration` to `date plus 2 years` | `date_add` template became `{A} plus {B} {unit}`, two slots rather than one pre-joined duration string |
| `V-GLOSS-012` | `the sum of nums` to `sum of nums` | reworded `aggregate(sum)` template |

Fifteen English templates were reworded in the 2026-09-09 spec revision
(`in`, `match`, `length`, `between`, `all`, `any`, `none`, `epoch_ms`,
`date_add`, `date_part` and the five `aggregate` forms). Only five of
them are reachable from the twelve `V-GLOSS` vectors, but all fifteen were
transcribed, and `tests/test_gloss.py` now pins the whole English table by
full-set equality rather than by spot check, so a later drift fails a test
instead of silently changing a reported string.

## The number question, answered

The maintainer asked whether this runner's JSON-number choice is load-bearing
for the evaluator or a serialization-level detail, citing `V-ENGINE-E2-007`
(`add(1e21, 1)`) reading `1e+21` in the submitted envelope.

**It is serialization-level here, and the `1e+21` is a reader-side artifact,
not something this runner ever wrote.** The evidence is three facts that can
each be checked directly:

1. **The evaluator has no binary float in it at all.** The corpus loader parses
   numeric literals with `parse_float=Decimal` (`erdl_expr/values.py`,
   `load_json_exact`), the value domain is `fractions.Fraction`, and rounding
   happens exactly once, at the reported value, in `fixed_point_int`. That is
   what spec E2 and section 7.3(c) require: *"intermediate computation uses
   high-precision bounded rationals (e.g. 128-bit integer numerator or
   denominator); only output nodes round to scale=14 + half-even string
   serialization."* `1e21 + 1` is computed exactly, as an exact rational, in
   both the previous round and this one.
2. **The bytes in the submitted envelope are already the exact digits.** The
   2026-09-07 file that was submitted upstream contains
   `"value": 1000000000000000000001`. The writer never routes a number through
   the JSON encoder's float path; it emits the exact decimal token through a
   sentinel and unquotes it (`erdl_expr/results.py`, `dumps`).
3. **`1e+21` is what a double-typed reader recovers, on either side.** The
   value is above `2**53 - 1`, so `JSON.parse` in Node turns those exact digits
   into the double `1e21`, and `JSON.stringify` prints `1e+21`. Reading the
   submitted file back in Node reproduces the maintainer's observation exactly,
   from a file that carries the exact digits.

The consequence worth acting on is on the verifier's side, not the runner's.
`scripts/verify-v-engine-submission.mjs` compares
`JSON.stringify(actual.value) === JSON.stringify(expected.value)`, and both
operands have already been through `JSON.parse`. Above `2**53 - 1` that
comparison is between two doubles: it will agree on `E2-007` whatever the two
implementations actually computed, and it would equally agree if one of them
had genuinely lost the `+1`. That is precisely the case RFC 8785 section 3.1
recommends a JSON string for, and it is the reason ambiguity A1 stayed open
rather than being closed on the first round.

`tests/test_submission_format.py::test_an_exact_integer_beyond_the_double_range_is_a_reader_side_bound`
pins all of this, so the distinction between "what the file carries" and "what a
double-typed reader recovers" cannot quietly collapse again.

## Cross-verification status

`scripts/verify-v-engine-submission.mjs` **does not run standalone.** It reads
`v-engine-answers.json`, which is gitignored and absent from a fresh clone of
`OpenOBA/erdl-vectors` at `97e0c00`; the only local way to produce it is
`npm run generate:vengine`, which runs the reference engine. Generating the
oracle and then consulting it is what ER9 forbids, so it was not done, and this
runner reports no cross-verification result. That check is upstream's to run,
which is what the contract says it is for.

What was checked locally is the envelope's **shape** against the verifier's own
consumption path: the verifier was run against an answers file synthesized from
this runner's own output, which exercises the real code path (`layer` gate, id
coverage, per-entry `value` / `value_type` / `errored` access) and reports
`240/240 passed`, exit 0. That proves the envelope parses and is complete under
the verifier's reader. It proves nothing about semantics, and is recorded here
as a shape check rather than as a result.

## Coverage

| Family | Vectors | Evaluated |
|---|---:|---:|
| Node kernel (34 nodes, 10 groups) | 136 | 136 |
| Constraints E1 to E11 | 52 | 52 |
| Simple compilation (28 operators, 2 modifiers) | 30 | 30 |
| gloss rendering | 12 | 12 |
| gloss integrity (tamper pairs) | 4 | 4 |
| Projection equivalence | 6 | 6 |
| **Total** | **240** | **240** |

### Node groups

| Group | Vectors | Group | Vectors |
|---|---:|---|---:|
| value | 12 | quantifier | 12 |
| logic | 12 | arithmetic | 20 |
| comparison | 24 | time | 20 |
| set | 4 | aggregate | 4 |
| string | 16 | existence and measure | 12 |

### Constraint vectors

| Constraint | Vectors | Constraint | Vectors |
|---|---:|---|---:|
| E1 (purity) | 3 | E8 (empty-array folding) | 5 |
| E2 (fixed point) | 8 | E9 (UTC, no clock read) | 5 |
| E3 (evaluation errors) | 6 | E10 (NFC) | 3 |
| E4 (resource limits) | 6 | E11 (missing-field collapse) | 13 |
| E5 (load-time exclusivity) | 3 | | |

### Reported values

| Measure | Count |
|---|---:|
| `value_type` boolean | 184 |
| `value_type` number | 37 |
| `value_type` string | 19 |
| `errored` true (E12 fold to false) | 53 |
| value true | 67 |

The 53 errored vectors break down by warning code as: 24 `type_mismatch`, 6
`division_by_zero`, 6 `invalid_date`, 5 `not_an_array`, 5 `resource_limit`, 4
`arity`, 2 `regex_unsafe`, 1 `schema_violation`. Every one of them reports
`value: false`, because E12 folds an evaluation error to false at tier 3 and
above, which is the whole expression projection.

A14, settled in fix-round 2, moved six vectors out of this count and into a
plain, unwarned `errored: false`: `V-ENGINE-gt-003`, `-gte-003`, `-lt-003`,
`-lte-003`, `V-ENGINE-E3-002` and `V-ENGINE-between-003`. Their `value` did
not change (all six were already `false`); only `errored` and the
`type_mismatch` warning were removed. That is the whole of the 59-to-53 and
30-to-24 drops above.

A further 16 vectors carry a warning without being errors, because a recorded
safe fold is not an evaluation error: 9 `safe_fold_empty_array` (the E8
quantifier fold on `V-ENGINE-all-002`, `-any-004`, `-none-002` and
`V-ENGINE-E8-001` to `-003`, plus the section 7.3(e) avg, min and max folds on
`V-ENGINE-aggregate-004` and `V-ENGINE-E8-004` and `-005`), 6
`safe_fold_undefined_result` and 1 `safe_fold_non_scalar_result`. Their
`errored` flag is false and their value is false.

## Independent confirmation available without an oracle

The corpus publishes the compiled tree for each Simple operator and for each
decision-table projection. Those are inputs, not expected evaluation results,
so comparing against them costs nothing under ER9. This runner's own compiler
reproduces all 28 Simple compile targets and all 3 decision-table compile
targets byte for byte, including the exists guard on every `not_*`, `length_*`
and `count_*` composition and its absence on `not_exists`. That is the one
independent check the corpus makes possible, and it passes.

## Ambiguities

Each row is a place where the specification text supports more than one
reading. The chosen reading is the one the constraint text supports, and none
of them was settled by consulting the reference engine or the oracle.

### A1. How a reported number is encoded: SETTLED by the contract, with one residual

* **Settled 2026-09-09 in favour of the reading this runner already shipped.**
* **Affects:** the 37 vectors whose `value_type` is number.
* **Settled reading (chosen, unchanged):** a JSON number, rendered from the
  scale-14 fixed-point value with trailing zeros trimmed.
* **What settles it:** the contract now says so outright, in both languages, at
  `97e0c00`. `EXPRESSION-RUNNER-CONTRACT.md` ER3: *"`value` with `value_type:
  "number"` is a JSON number (decimal) ... **not** a decimal string. The
  decimal-string form (spec section 8.2) governs `canonical_tree` literals only,
  not the result object. `"1e21 + 1"` reports `1000000000000000000001` (a JSON
  number), never `1e+21`."* The zh-CN contract, synced later the same day, says
  the same thing in the same words. That is exactly reading 1, including the
  worked example, so the shipped envelope keeps `number_format: "json-number"`.
* **Residual, and the reason this row is not simply closed:** the same
  repository's `CHANGELOG.md` for v1.6.0 describes the ER3 change as *"numbers
  serialized as decimal strings (RFC 8785 section 3.1)"*, which is the opposite
  of what both contract files say. The two statements cannot both describe the
  answer oracle. The stake is real rather than cosmetic: the submission
  verifier compares `JSON.stringify` of two already-parsed values, so above
  `2**53 - 1` a JSON number is compared as a double on both sides and cannot
  distinguish an exact result from a lost one, which is the situation RFC 8785
  section 3.1 recommends a string for. A decimal string is byte-exact at any
  magnitude and would make that comparison meaningful.
* **What this runner does about it:** it ships both encodings of the same
  measurement, so whichever the oracle carries can be cross-verified without
  another round trip. `output/concordia-python-expression-output.json` is the
  submission and carries JSON numbers per ER3.
  `output/concordia-python-expression-output.decimal-string.json` is the same
  240 results with every number quoted, produced by the same run through
  `--number-format decimal-string`. It is an alternate encoding for the
  maintainer's convenience, not a second submission.

### A2. A non-scalar value at the root

* **Affects:** `V-ENGINE-var-001` (`{"var": "$"}` returns the fact object).
* **Reading 1 (chosen):** fold to `false` with a `safe_fold_non_scalar_result`
  warning and `errored: false`.
* **Reading 2:** report `true`, on the grounds that the object is present.
* **Why 1:** ER3 admits only number, string and boolean, so the value has to
  fold. E11 and section 7.3(b) make false the direction of every safe fold, and
  a fold that produced true would let a value a condition cannot consume
  satisfy a rule.

### A3. Where the E12 error fold is taken

* **Affects:** `V-ENGINE-not-003` and `V-ENGINE-exists-003` are the two vectors
  that distinguish the readings; the fold applies to all 53 errored vectors
  (see "Reported values" above: 24 `type_mismatch` + 6 `division_by_zero` + 6
  `invalid_date` + 5 `not_an_array` + 5 `resource_limit` + 4 `arity` + 2
  `regex_unsafe` + 1 `schema_violation` = 53).
* **Reading 1 (chosen):** once, at the top of the evaluation. Any error folds
  the whole result to `false`.
* **Reading 2:** at the erroring node, so evaluation continues around it. Under
  that reading `not(div(1,0))` is `not(false)`, which is `true`, and
  `exists(div(1,0))` is `exists(false)`, which is also `true`.
* **Why 1:** section 5.2 names a bare `not` over a false-by-absence operand as
  a fail-open, and that is the reason the Simple compiler carries an exists
  guard. An error that can be flipped to true by a `not` is the same shape.
  E12's "fail-close" wording for tier 2 and below is about the decision the
  evaluation feeds, which is a top-level notion, so the fold is read as
  top-level in both directions.

### A4. Which gloss language the reported string uses: SETTLED, English

* **Settled 2026-09-09 in favour of the reading this runner already shipped.**
* **Affects:** the 12 `V-GLOSS` vectors.
* **Settled reading (chosen, unchanged):** English.
* **What settles it:** spec v2.1's 2026-09-09 revision pins section 5.5 to
  English as canonical and demotes the Chinese column to "a presentation-only
  optional projection", and the corpus's own expected gloss values became
  English-only in the same revision. The bilingual table that made this a
  question is gone. `--gloss-language zh` survives as that presentation
  projection and is still tested, but it is no longer a live reading of what a
  reported value carries.
* **What did change:** the same revision reworded fifteen English templates.
  The spec's own revision-history line for this change reads: "§5.5 aligns
  gloss template wording to the renderer" (`erdl-spec.en.md`, Revision
  History, v2.1, 2026-09-09). That is the spec describing why upstream
  changed the wording; this runner transcribed the resulting section 5.5
  table from the spec text and never opened, read or consulted
  `scripts/v-engine.mjs` or any other renderer to produce it. The fifteen
  templates are transcribed and pinned; see "What changed since the
  2026-09-07 measurement" above.
* **Bound worth stating separately:** G3 requires gloss to use the Entity
  `display_name` rather than a raw field path. The corpus carries no Entity
  declarations, so there is no display name to substitute and the raw path is
  what renders. That is a limit of the input, not a decision to skip G3.

### A5. Month and year addition at a month end

* **Affects:** `V-ENGINE-date_add-002` (one month after 2024-01-31).
* **Reading 1 (chosen):** clamp to the last valid day, giving 2024-02-29.
* **Reading 2:** overflow into the following month, giving 2024-03-02.
* **Why 1:** section 7.3(f) calls this UTC calendar arithmetic and states no
  overflow rule. It also forbids implicit rounding of a duration on the grounds
  that "add 1.5 months" has no business meaning, which reads as a preference
  for the calendar reading of a month over an arithmetic one. A result that
  lands in March is not "one month after January" in the business sense the
  section appeals to.

### A6. The numbering of `date_part` `day_of_week`

* **Affects:** `V-ENGINE-date_part-002`, though both readings agree on it.
* **Reading 1 (chosen):** ISO 8601, Monday 1 through Sunday 7.
* **Reading 2:** zero-based with Sunday 0, the numbering a JavaScript
  `getUTCDay` produces.
* **Why 1:** section 7.3(f) names the unit and not the numbering, and ISO 8601
  is the standard the rest of the time surface is written against. The two
  readings differ only on Sunday, and the corpus vector is a Saturday, which
  both number 6, so this ambiguity does not affect the measurement.

### A7. What a gloss integrity vector reports

* **Affects:** the 4 `V-GLOSS-INTEGRITY` vectors.
* **Reading 1 (chosen):** the boolean property under test, that rendering the
  tampered tree produces different text from rendering the original.
* **Reading 2:** the gloss string of the untampered tree, with the tampered
  tree ignored.
* **Why 1:** the vectors carry a `tampered_tree` that reading 2 would never
  look at, and their scenario text names a change ("tree literal tamper to
  gloss change"). G2 makes that change the verifiable property.

### A8. A quantifier over a missing field

* **Affects:** `V-ENGINE-all-004` and `V-ENGINE-none-004`.
* **Reading 1 (chosen):** silent `false`, no warning, `errored: false`.
* **Reading 2:** a `type_mismatch` warning, by analogy with the aggregate rule.
* **Why 1:** section 7.3(e) states the type-mismatch rule for the `over` of
  `aggregate` and enumerates missing, scalar and object there. It names
  `aggregate` and only `aggregate`. With no equivalent sentence for the
  quantifiers, E11 governs and a missing field collapses at the leaf. A present
  non-array under a quantifier is still an error, which is what
  `V-ENGINE-all-003` exercises.

### A9. A `between` whose operand is present but not numeric: SETTLED, silent false

* **Settled 2026-09-07, fix-round 2, chained from A14.** The prior entry chose
  the evaluation-error reading; that reading is retracted along with A14's.
* **Affects:** `V-ENGINE-between-003`.
* **Settled reading (chosen):** a silent false, `errored: false`, no
  `type_mismatch` warning.
* **Retracted reading:** an evaluation error, folding to false with a
  `type_mismatch` warning.
* **Why:** section 5.2 says a non-numeric `between` returns false ("between
  仅数值 ... 非数值返回 false"), which fixes the value but, read alone, says
  nothing about whether a warning is recorded. `between` is an ordered
  comparison written as a closed interval, so it takes whatever the ordered
  comparisons take, and A14 settles those: silent false, on the strength of
  the §5.2 worked example and the §7.3(a) table contrast, not the corpus's own
  filing. The reported value is false under both readings; only `errored`
  differs.

### A10. A regex with a nested quantifier

* **Affects:** `V-ENGINE-match-003` and `V-ENGINE-E4-006`, which carry the same
  pattern `(a+)+$` against the subject `aaaa`.
* **Reading 1 (chosen):** reject the pattern as outside the safe subset, giving
  an evaluation error that folds to false.
* **Reading 2:** run it, in which case the subject matches and the value is
  true.
* **Why 1:** E4 caps regex steps at 10000 and section 7.3(d) asks for a
  deterministic engine or a safe syntax subset. `V-ENGINE-E4-006` is a
  resource-limit vector whose scenario names the nested quantifier as a ReDoS
  case, which reads as a case the runner is expected to detect. A step counter
  would have to start running the pathological match to discover it is
  pathological, so the syntactic guard is the form the constraint can actually
  take.
* **Bound worth stating:** the guard covers four families: backreferences,
  lookaround, a quantified group containing a quantifier (`(a+)+`), and a
  quantified group whose alternation branches can begin on the same character
  (`(ab|a)*`). The last family is checked conservatively, so a quantified
  alternation over anything but plain literals (a character class, a nested
  group, `.`, a class escape) is refused rather than analysed. Refusal folds
  the rule to false, which is the safe direction. What the guard still does not
  do is bound a pattern it admits: E4's step ceiling is approximated by the
  syntactic rule plus the section 7.3(d) input-length limit, because Python's
  `re` exposes no step budget. A deterministic matcher would remove the
  approximation and is the honest next step, not a defect in the reading.

### A11. A missing or null value at the root

* **Affects:** `V-ENGINE-field-003`, `V-ENGINE-field-004`, `V-ENGINE-var-003`,
  `V-ENGINE-var-004`, `V-ENGINE-literal-004`, `V-ENGINE-E11-001`.
* **Reading 1 (chosen):** fold to `false` with `errored: false` and a
  `safe_fold_undefined_result` warning.
* **Reading 2:** treat it as an evaluation error.
* **Why 1:** E11 makes a missing field the normal case in agent context and
  requires safe failure rather than an exception. An error would make a Guard
  at tier 2 or below fail closed on a fact object that simply did not carry the
  field, which is the outcome E11 exists to prevent. Note that
  `V-ENGINE-field-003` traverses into a scalar (`a.b` where `a` is a number)
  and is treated as missing for the same reason.

### A12. What a projection vector reports

* **Affects:** the 6 `V-PROJ` vectors, though both readings agree on all of
  them.
* **Reading 1 (chosen):** the shared evaluation result of the two trees, after
  asserting that they agree.
* **Reading 2:** a boolean saying the two projections agree.
* **Why 1:** E7 makes the agreement an invariant of the runner rather than a
  property of the vector, so a disagreement is a defect and is raised rather
  than reported. All six vectors evaluate to true under either reading, so this
  ambiguity does not affect the measurement.

### A13. A non-boolean operand to a logic node

* **Affects:** `V-ENGINE-and-004` (`{"and": [1, true]}`) and `V-ENGINE-or-004`
  (`{"or": [0, false]}`).
* **Reading 1 (chosen):** a type mismatch, folding to false.
* **Reading 2:** host-language truthiness, making 1 true and 0 false, so the
  `and` would be true.
* **Why 1:** section 5.2 forbids implicit type conversion outright, and E11's
  own vectors establish that a boolean compared against a number is false
  rather than coerced. A runner that borrowed truthiness here would also have
  to explain why `eq(false, 100)` is false.

### A14. Whether a cross-type ordered comparison is an evaluation error: SETTLED, silent false, CONFIRMED upstream

* **Settled 2026-09-07, fix-round 2. Confirmed correct by the spec maintainer
  on 2026-09-09**, and now written into the spec: section 7.3(a)'s table row
  reads "Type-mismatched comparison | returns false (no implicit conversion;
  not an error, errored=false)", and the new warning-asymmetry note names
  `gt-003` and `E3-002` as the vectors that carry `warnings=[]`. The reading
  below was reached from the spec text before that annotation existed; the
  annotation states it directly. The prior entry chose the E3
  evaluation-error reading; that reading is retracted. The evidence below was
  reweighed against the direct fixing sentences and the fixing sentences win.
* **Affects:** `V-ENGINE-gt-003`, `-gte-003`, `-lt-003`, `-lte-003`,
  `V-ENGINE-E3-002` and, through A9, `V-ENGINE-between-003`. Value: false
  under both readings; only `errored` differs, and ER4 compares `errored`.
* **Settled reading:** a silent false, `errored: false`, no `type_mismatch`
  warning, on the same path as `eq` and `ne`. `_ordered`
  (`erdl_expr/evaluator.py`) and `_between` (`erdl_expr/evaluator.py`) both
  return `False` directly rather than raising `EvalError`.
* **Retracted reading:** an E3 evaluation error, recorded and folded to false
  by E12, with equality (`eq`, `ne`) across types taking the silent-false path
  instead.
* **Why the silent-false reading:** section 5.2's own worked example is
  explicit about the value AND the record, not just the value: `"100" gt 50`
  "恒为 false" ("`\"100\" gt 50` is always false"), stated flatly with no
  mention of an error. The same section's comparison bullet reads "跨类型返回
  false" ("cross-type returns false"), and its `between` bullet reads
  "between 仅数值 ... 非数值返回 false" ("between is numeric-only ...
  non-numeric returns false"): three independent fixing sentences, none of
  which says "and is recorded as an evaluation error." Section 7.3(a)'s table
  is the deciding contrast: the row for this exact case reads "类型不匹配的比较
  | 返回 false（禁止隐式转换）" ("Type-mismatched comparison | returns false (no
  implicit conversion)"), full stop, while the very next row in the same
  table, a different case, arithmetic on a missing field, reads "返回 false
  （条件）或 EvaluationError（算术表达式）" ("returns false (condition) OR
  EvaluationError (arithmetic expression)"). The table's author names
  EvaluationError explicitly exactly when a row means it, and does not name it
  for the type-mismatched-comparison row. A table that can say "or
  EvaluationError" and chooses not to on the adjacent row is not silent by
  omission; it is silent on purpose.
* **What the retracted reading got wrong:** it read the ER9 corpus filing
  (`V-ENGINE-E3-002` grouped with the E3 constraint vectors) as deciding
  `errored`, but a vector's *filing* under a constraint section is the corpus
  author's cross-reference, not a second, independent fixing sentence: the
  spec's own worked example and table already fix the record, and this runner
  is built from the specification text, not from inferring intent behind the
  corpus's own organization (which ER9 in any case forbids treating as an
  oracle). Filed-under-E3 is consistent with a silent false too: E3 lists
  every evaluation-error *candidate* the spec discusses, and the constraint
  text there restates the same "returns false" language rather than adding a
  new EvaluationError sentence for this case.
* **Why it is principled and not only textual:** treating a type mismatch the
  same way across `eq`/`ne` and the ordered family is the simpler invariant,
  one fail-safe direction (false) for every cross-type comparison, rather than
  a split where only the equality family gets a quiet answer and the ordered
  family gets a loud one for the same underlying defect (an author comparing
  values that were never the same type). The reading is applied at one site
  (`_ordered`) plus `_between`, which is a closed interval written as two
  ordered comparisons, so all five operators cannot drift apart.

### A15. When `rate` first fires: CONFIRMED upstream

* **Confirmed correct by the spec maintainer on 2026-09-09.** No change.
* **Affects:** `V-ENGINE-SIMPLE-rate-001` and `V-ENGINE-SIMPLE-within-001`.
* **Reading 1 (chosen):** the check is "the window holds at least N recorded
  events", so a sequence of N records followed by a check reports true.
* **Reading 2:** the check is "the window holds more than N recorded events",
  so N records followed by a check reports false and an (N+1)-th record is
  needed first.
* **Why 1:** the section 5.2 row is "`rate: N/window` | N | first N times:
  record + false | from the (N+1)-th time: true", and its supporting
  constraints are "post-counting (count only when the positive condition
  holds)" and "record timing in the under-limit branch". Reading those three
  together: the first N INVOCATIONS each record and return false, so when the
  (N+1)-th invocation runs its check the window already holds exactly N
  events. "True from the (N+1)-th invocation" and "true once the window holds
  N" are therefore the same rule stated from different ends, not an off-by-one
  between them. `within` is the same rule with N fixed at 1: "first: record +
  false; from the 2nd time in window: true", so one recorded event makes the
  next check true. The corpus separates record from check as distinct
  `state_ops`, which is why the distinction is visible at all, and its two
  vectors are `record` three times then `checkRate` with `maxCount` 3, and
  `record` once then `checkWithin`. Both are the (N+1)-th invocation.
* **What changed:** nothing in the code. The reading is now pinned by a test
  that replays the operator's own invocation loop rather than calling the
  check directly, so a later edit cannot slide the boundary without failing.

### A16. Whether the E8 fold is recorded as well as taken

* **Affects:** 9 vectors (`V-ENGINE-all-002`, `-any-004`, `-none-002`,
  `V-ENGINE-E8-001` to `-005`, `V-ENGINE-aggregate-004`).
* **Reading 1 (chosen):** record it. An empty-array quantifier fold and the
  avg, min and max empty-array folds each attach a `safe_fold_empty_array`
  warning, with `errored` false.
* **Reading 2:** fold silently, since ER4 does not compare warnings.
* **Why 1:** section 7.3(b) states the fold and the record in one sentence:
  `all/any/none(empty)` "all fold to false, preventing 'nothing to check yet
  judged as allowed', **and record the safe fold in the audit record**". A
  reading that takes the first half and drops the second leaves the result
  object unable to distinguish "the array was empty" from "every element
  failed the predicate", which is the one thing an auditor of a false verdict
  needs to know. The empty-sum identity for `sum` and the zero for `count` are
  ordinary results rather than folds under section 7.3(e), so they record
  nothing.
* **Effect on the envelope:** these 9 vectors are the warning attachments the
  previous (2026-09-07) round added; they are not among the six result objects
  that changed this round (see "What changed since the 2026-09-07
  measurement" above). Their `value` and `errored` are unchanged, so the ER4
  comparison surface is untouched.

### A17. Whether a warned-but-not-EvaluationError type mismatch sets `errored`

* **Opened 2026-09-09**, by the v2.1 revision that introduced the `errored`
  flag as a specified field rather than an inferred one.
* **Affects:** 5 vectors whose `errored` differs between the readings:
  `V-ENGINE-contains-003`, `-starts_with-003`, `-ends_with-003`,
  `-length-003`, `-aggregate-003`. Their `value` is `false` under both
  readings, so only `errored` is in question, and ER4 compares `errored`.
* **SETTLED 2026-09-09 by the upstream maintainer (reading 2 adopted).**
  haoran-tang-ch, A2A discussion #2031
  (https://github.com/a2aproject/A2A/discussions/2031#discussioncomment-18375034):
  the reference engine's authority is `errored: false` with the
  `type_mismatch` warning still recorded; these nodes are warned, not silent;
  only comparison and `between` are silent. Spec section 7.3(a) now carries an
  explicit clause (upstream `fb428b7`) and the v1.6.0 changelog line was
  corrected (`34f47df`). The runner was changed accordingly (`evaluator.py`,
  `_string`, `_length`, `_aggregate`) and the five vectors now report
  `errored: false`; the submission was regenerated with exactly those five
  entries changed. The reasoning below is kept as the record of why reading 1
  was held before the clause existed.
* **Reading 1 (held until settled):** `errored: true`.
  E3 now reads *"Evaluation errors are recorded as eval_warnings with
  errored=true"*. That sentence does not license the converse: "records an
  eval_warning" and "is an evaluation error" are not the same predicate in
  this runner's own envelope, which carries 16 warned, `errored: false`
  safe-folds elsewhere (A16). What supports reading 1 for these five vectors
  specifically is narrower: section 7.3(a)'s warning-asymmetry note states
  that comparison nodes and `between` fold "silently (no warning)", whereas
  `in`, the string nodes, `length` and `aggregate` "record a `type_mismatch`
  warning", and contract ER8 independently names a non-array `aggregate` an
  evaluation error, which is the one cross-check available for that vector.
* **Complicating evidence:** `CHANGELOG.md` v1.6.0 (`erdl-vectors` commit
  `97e0c00`) states the warning semantics as *"comparison / string
  type-mismatch → silent false; quantifier over a missing field → silent
  false (E11)"*. Four of the five affected vectors are string nodes
  (`contains`, `starts_with`, `ends_with`, `length`), and this line reads them
  into the same silent-false, `errored: false` group as comparisons, which is
  reading 2, not reading 1. Only `aggregate-003` has the independent ER8
  support cited above; the four string vectors rest on the section 7.3(a)
  warning-asymmetry note alone, against this changelog line.
* **Reading 2:** `errored: false` with the warning still recorded. Appendix E's
  new glossary row enumerates the errored-true cases as "division by zero /
  invalid date / arity / type-mismatched arithmetic", and a string or `length`
  type mismatch is on none of those four; the changelog line above reads the
  same way for the string nodes.
* **Why 1:** the glossary enumeration cannot be exhaustive, because ER8 places
  a non-array `aggregate` inside the errored set and the enumeration does not
  list it. Read as illustrative, the enumeration and E3 agree; read as
  exhaustive, it contradicts ER8. Reading 1 is the one that leaves no sentence
  in the contract false for `aggregate-003`; for the four string vectors it is
  the weaker reading, held only because a per-node exception (string nodes
  behave like comparisons, not like `in`) is not stated anywhere in the spec
  or contract text read for this round.
* **What would settle it:** one sentence saying whether "records a
  `type_mismatch` warning" implies `errored: true`, or naming the warned
  non-arithmetic nodes as errored-false.

### A18. Whether a missing field reaching a time node is an error

* **Opened 2026-09-09**, for the same reason as A17.
* **Affects:** 5 vectors, all with the corpus's `null` scenario:
  `V-ENGINE-days_between-004`, `-epoch_ms-004`, `-date_add-004`,
  `-date_part-004`, `-month_last_day-004`. `value` is `false` under both
  readings.
* **Reading 1 (chosen, unchanged):** `errored: true` with a `type_mismatch`
  warning, treating a time node like an arithmetic one. Section 7.3(a)'s table
  makes arithmetic on a missing field an EvaluationError when the tree is an
  arithmetic expression rather than a condition, and these five trees are
  value-producing expressions of exactly that shape; ER3 also lists "invalid
  date" among the errored cases, and an absent base is not a valid date.
* **Reading 2:** `errored: false`, on ER4's "null/missing-field propagation
  (E11) are normal false results, not errors" (`EXPRESSION-RUNNER-CONTRACT.md`
  ER4). The spec's node taxonomy counts time and arithmetic as separate
  groups, so the section 7.3(a) row about "arithmetic" may not reach them.
* **Why 1:** the section 7.3(a) row is about the shape of the tree (expression
  versus condition), not about which of the ten node groups the operator was
  filed under, and a date computation is the same shape as an arithmetic one.
  Applying E11's leaf collapse instead would mean `days_between` on an absent
  date reports the same clean `false` as a comparison against an absent field,
  which loses the distinction an auditor needs.
* **What would settle it:** naming time nodes explicitly in the section 7.3(a)
  row, in either direction.

### A19. How a list literal renders in gloss

* **Opened 2026-09-09.** Not previously recorded, and reachable now that gloss
  values are compared as English strings.
* **Affects:** `V-GLOSS-005` and, through the tamper pair, the boolean of
  `V-GLOSS-INTEGRITY-004`.
* **Reading 1 (chosen, unchanged):** bracketed and comma-separated, so
  `["a","b"]` renders `[a, b]` and the whole vector reads `cat in [a, b]`.
* **Reading 2:** any other list form the renderer happens to use, for example
  a bare comma list or quoted members.
* **Why 1:** section 5.5's table gives `literal` the template `{value}` and
  says nothing about an array literal, so the bracketed JSON-like form is the
  reading that stays closest to `{value}` while keeping the member boundary
  visible; a bare comma list would make a two-member set indistinguishable
  from one member containing a comma.
* **Why it is worth a row:** `in` is one of the five templates reworded on
  2026-09-09, so this is the one `V-GLOSS` vector whose expected string depends
  on a rendering detail the template table does not specify. If it mismatches,
  the list form is where to look, not the `in` wording.

## What the tests cover

The suite is 141 tests, 135 of which run without the corpus. One module per
node group covers the semantics from the specification text; `test_sentinels.py` covers
E2, E8, E10, E11 and E12; `test_limits.py` covers E4 and the regex subset;
`test_simple_compile.py` covers the 30 Simple operators, the decision-table
compiler and the two stateful modifiers; `test_gloss.py` covers the frozen
templates; `test_submission_format.py` covers the ER3 shape and the numeric
encoding. `test_corpus.py` runs all 240 vectors and asserts the result shape,
and skips when `ERDL_V_ENGINE_VECTORS` is unset, because the corpus is
OpenOBA's artifact rather than this repository's.

Three sentinels are shown failing before they pass, using a `Semantics` object
whose fields default to the specification's mandate: half-even rounding
(planting half-up moves `round(0.5)` to 1 and `round(2.5)` to 3), the E8
empty-array fold (disabling it restores vacuous truth, so `all` over an empty
array becomes true), and the E11 leaf collapse (disabling it makes every
predicate over a missing field report errored). The corpus runner refuses to
run with anything but the default semantics, so a test instrument cannot reach
a published artifact.

Planting half-up as the shipped default, rather than as a test parameter, fails
`test_e2_half_even_sentinel_fails_under_a_planted_half_up_mode`,
`test_round_is_half_even_at_the_reporting_scale` and
`test_the_corpus_runner_refuses_a_planted_semantics`, and restoring half-even
returns the suite to 141 passing.

Two tests were added in this round, both pinning a distinction the 2026-09-09
exchange showed can be lost. `test_the_english_templates_are_the_frozen_section_5_5_table`
compares the whole English template table for equality against the section 5.5
transcription, because a parity test that names only the rows it happens to
check cannot notice a row that went missing.
`test_an_exact_integer_beyond_the_double_range_is_a_reader_side_bound` asserts
both halves of the number question at once: the envelope's bytes for
`1e21 + 1` are the exact digits, and the same value collapses in any reader
that parses JSON numbers into doubles.

## Defects found and fixed in the 2026-09-09 re-run

* The gloss renderer carried the pre-revision section 5.5 templates. Fifteen
  English templates were reworded upstream on 2026-09-09; five of them are
  reachable from the `V-GLOSS` vectors, so five reported strings were wrong
  against the current spec. All fifteen were retranscribed and the whole table
  is now pinned by a full-set equality test.
* `date_add` built its duration by joining the amount and the unit before
  substitution, which happened to produce the right English text under the old
  template and would not survive the new two-slot form. The template now owns
  the spacing, which is the only difference between the English and Chinese
  renderings of that node.
* No defect was found in the numeric model, the `errored` assignment or the
  folding. The `1e+21` reading that prompted this round is a property of a
  double-typed reader, not of the envelope; see "The number question, answered".

## Defects found and fixed in the fix round

* The E4 array ceiling was enforced only against arrays written into the tree.
  An array arriving in the fact object was never measured, so a three-node rule
  could walk a fact array of any length through a quantifier, an aggregate, an
  `in` or a `length`. The ceiling is now enforced where a fact value is lifted
  into the kernel's value domain, which is the one point every fact array
  passes through, nested arrays included; the four consuming sites keep their
  own check because a list can also be produced by the tree.
* The array walker reused the depth walker's child helper, which flattens an
  operand list into the operator's children. That is right for depth and wrong
  for the array ceiling: after flattening there is no list left to measure, so
  an over-long operand list was capped only by the node count. The walker now
  measures every list before descending into it.
* The regex safe subset covered nested quantifiers but admitted ambiguous
  quantified alternation (`(ab|a)*`), which is exponential for the same reason.
  It is now refused with a `regex_unsafe` warning, and the refusal is asserted
  against a subject that would not finish if the pattern were run.
* The decision-table compiler produced equality cells only, which is all the
  corpus exercises and a fraction of what section 5.4 defines. Cells naming any
  of the six comparison operators now compile, in the section's own row shape
  (`when: [["gte", 10000]]`) as well as the corpus's, and a row decision is
  checked against the section 6 enumeration.
* A regex subject over the input-length limit reported `type_mismatch`. The
  subject is a valid string that is merely too long to match under the step
  ceiling, so it now reports `resource_limit`. No corpus vector reaches it.

## Defects found and fixed during the build

* The resource-limit walker counted an operand list as a level of the tree, so
  every compiled Simple composition with an exists guard measured seven deep
  and tripped the Grade A depth ceiling. All 15 guarded operators reported a
  resource-limit error instead of a verdict. Fixed by treating an operand list
  and an operand payload as syntax rather than as tree levels, with the
  distinction and its reason recorded at the traversal.
* The submission writer checked for its number sentinel after substitution
  rather than before. A string value carrying the marker would have been
  unquoted by the substitution and left no residue to detect, so the check
  would have passed on corrupted output. Fixed by scanning the payload before
  serializing.

## Author

Erik Newton.
