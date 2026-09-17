"""An independent Python implementation of the ERDL expression layer.

Written from the ERDL v2.1 specification and the expression-runner contract
(ER1 to ER9) alone. The reference engine, the in-repo verifier scripts and the
formal model were not read for the implementation. One disclosed exception on
2026-09-09: the answer oracle was generated once (by running the upstream
generator, which executes the reference engine) and read once for a diagnosis;
the evaluator was not changed from it and the one tag it suggested was reverted.
The package README and RESULTS.md A21 record that boundary in the form the
submission's `method` field carries.
"""

from __future__ import annotations

from .evaluator import DEFAULT_SEMANTICS, Evaluator, Outcome, Semantics, evaluate_tree
from .gloss import render
from .simple import compile_decision_table, compile_simple
from .temporal import TemporalState, run_state_ops
from .values import SCALE, UNDEFINED, decimal_string, fixed_point_int

__all__ = [
    "DEFAULT_SEMANTICS",
    "Evaluator",
    "Outcome",
    "SCALE",
    "Semantics",
    "TemporalState",
    "UNDEFINED",
    "compile_decision_table",
    "compile_simple",
    "decimal_string",
    "evaluate_tree",
    "fixed_point_int",
    "render",
    "run_state_ops",
]
