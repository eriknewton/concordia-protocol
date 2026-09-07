# ERDL expression layer: measured results

One measurement, taken on 2026-09-07 against OpenOBA's published
`v-engine-vectors.json` (SHA-256
`bcfe424fdebaecee11ce81ce3097ccaee0d9db0cc99f5a2d9624f4b3c8bd9ac8`, 239
vectors, `vector_version` v2.0.0, `spec` erdl-spec-v2.1).

This is not a conformance declaration. ER4 is settled by a cross-verification
run against an oracle this runner is forbidden to read (ER9), and registration
is upstream's to record. What is here is the result of evaluating every vector
with an implementation written from the specification and the contract, plus
the questions the specification left open and the reading each one was given.

## Coverage

| Family | Vectors | Evaluated |
|---|---:|---:|
| Node kernel (34 nodes, 10 groups) | 136 | 136 |
| Constraints E1 to E11 | 51 | 51 |
| Simple compilation (28 operators, 2 modifiers) | 30 | 30 |
| gloss rendering | 12 | 12 |
| gloss integrity (tamper pairs) | 4 | 4 |
| Projection equivalence | 6 | 6 |
| **Total** | **239** | **239** |

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
| E3 (evaluation errors) | 6 | E10 (NFC) | 2 |
| E4 (resource limits) | 6 | E11 (missing-field collapse) | 13 |
| E5 (load-time exclusivity) | 3 | | |

### Reported values

| Measure | Count |
|---|---:|
| `value_type` boolean | 183 |
| `value_type` number | 37 |
| `value_type` string | 19 |
| `errored` true (E12 fold to false) | 53 |
| value true | 66 |

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

### A1. How a reported number is encoded

* **Affects:** the 37 vectors whose `value_type` is number.
* **Reading 1 (chosen):** a JSON number. ER3 writes the schema as
  `"value": <number|string|boolean>` paired with `"value_type"`, which reads as
  the JSON type of `value` matching `value_type`.
* **Reading 2:** a decimal string. E2 says "fixed-point decimal scale=14 +
  half-even + string serialization", and section 8.2 canonicalizes numbers as
  fixed-point decimal strings.
* **Why 1:** section 8.2 governs the canonical tree, not the result object, so
  the only text about the result object is ER3's type pairing. Numbers are
  emitted at their exact scale-14 value with trailing zeros trimmed, and never
  through a binary float, so `1e21 + 1` is written as
  `1000000000000000000001` rather than `1e+21`. Reading 2 is one flag away:
  `--number-format decimal-string` regenerates the whole file with every number
  quoted, and the envelope records which encoding it carries.

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
  that distinguish the readings; the fold applies to all 59 errored vectors.
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

### A4. Which gloss language the reported string uses

* **Affects:** the 12 `V-GLOSS` vectors.
* **Reading 1 (chosen):** English.
* **Reading 2:** Chinese.
* **Why 1:** section 5.5's template table is bilingual and marks neither
  language subordinate, so the corpus is the only tiebreaker available, and its
  own `scenario` text is written in English throughout. Reading 2 is one flag
  away: `--gloss-language zh` regenerates every gloss from the Chinese column
  of the same frozen table, and both columns are implemented and tested.
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

### A14. Whether a cross-type ordered comparison is an evaluation error: SETTLED, silent false

* **Settled 2026-09-07, fix-round 2.** The prior entry chose the E3
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

### A15. When `rate` first fires

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
* **Effect on the envelope:** these 9 vectors are the only ones whose result
  object changed in this round. Their `value` and `errored` are unchanged, so
  the ER4 comparison surface is untouched.

## What the tests cover

The suite is 137 tests and runs without the corpus. One module per node group
covers the semantics from the specification text; `test_sentinels.py` covers
E2, E8, E10, E11 and E12; `test_limits.py` covers E4 and the regex subset;
`test_simple_compile.py` covers the 30 Simple operators, the decision-table
compiler and the two stateful modifiers; `test_gloss.py` covers the frozen
templates; `test_submission_format.py` covers the ER3 shape and the numeric
encoding. `test_corpus.py` runs all 239 vectors and asserts the result shape,
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
returns the suite to 137 passing.

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
