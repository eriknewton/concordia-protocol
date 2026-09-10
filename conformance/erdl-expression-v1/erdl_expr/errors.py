"""Evaluation-error signalling for the ERDL expression kernel.

ERDL E3 records evaluation errors as eval_warnings and defers the folding
direction to E12; E12 folds tier 3 to 5 to false. The expression projection is
tier >= 3 by definition (spec section 5.1), so every error in this kernel folds
the whole evaluation to false.

The fold is taken ONCE, at the top of the evaluation, rather than at the
erroring node. A node-local fold would let `not(<error>)` come out true, which
is the fail-open shape section 5.2 names as the reason the Simple compiler has
to wrap `not_*` in an exists guard. Folding at the top makes an error
unconditionally safe.
"""

from __future__ import annotations

from typing import Final


class EvalError(Exception):
    """An E3 evaluation error, carrying the warning code E3 records."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


#: Warning codes. ER4 compares `value` and `errored` only, so these codes are
#: diagnostic rather than normative; they are kept stable so a reader can tell
#: two different mistakes apart in the submission file.
DIVISION_BY_ZERO: Final[str] = "division_by_zero"
TYPE_MISMATCH: Final[str] = "type_mismatch"
INVALID_DATE: Final[str] = "invalid_date"
ARITY: Final[str] = "arity"
NOT_AN_ARRAY: Final[str] = "not_an_array"
REGEX_UNSAFE: Final[str] = "regex_unsafe"
RESOURCE_LIMIT: Final[str] = "resource_limit"
SCHEMA_VIOLATION: Final[str] = "schema_violation"
UNKNOWN_NODE: Final[str] = "unknown_node"

#: Non-error folds. These are recorded so the audit shows the fold happened
#: (spec section 7.3(b) requires the safe fold to be recorded) but they are NOT
#: evaluation errors, so they leave `errored` false.
SAFE_FOLD_EMPTY: Final[str] = "safe_fold_empty_array"
SAFE_FOLD_NON_SCALAR: Final[str] = "safe_fold_non_scalar_result"
SAFE_FOLD_UNDEFINED: Final[str] = "safe_fold_undefined_result"

#: E5 (spec §7.2, "`when` and `expr` MUST NOT coexist"); the corpus's E5-01
#: vector expresses the violation as `expr` coexisting with the Simple triple
#: (`field`/`operator`/`value`) rather than as `when`+`expr` on a rule object,
#: which is the same load-time exclusivity check applied one level down.
#: EXPRESSION-RUNNER-CONTRACT.md (b56c1c2), "Constraint vectors (E4/E5)":
#: E5 vectors are constraint-verification vectors whose `expected` "records
#: whether the constraint was correctly detected/triggered ... E5 `value:
#: true` = violation detected", not an evaluation result -- so this code is
#: NOT folded through E12 like an ordinary EvalError (see
#: `evaluate_tree`'s dedicated branch); it reports the violation itself as
#: a literal boolean `true`.
LOAD_EXCLUSIVITY_VIOLATION: Final[str] = "expr_load_exclusivity_violation"
