#!/usr/bin/env python3
"""Generate foundational-types parity fixtures FROM the Concordia Python reference.

Run from the repo root (or anywhere with `concordia` importable). Emits a JSON
document to stdout. The JS test suite (tests/types.test.ts) asserts that the
TypeScript types layer produces structurally identical enum value maps and
`to_dict()` output, and that its `pyRound` helper reproduces Python's built-in
`round(value, ndigits)` exactly.

This is the parity source of truth: every expected value here comes straight
from `concordia.types` (enum `.value`, dataclass `to_dict()`) and Python's
built-in `round`, never hand-authored. Synced into the JS test surface by
scripts/sync-fixtures-from-python.mjs.
"""

from __future__ import annotations

import json
import random
import sys
from fractions import Fraction

from concordia import types as ctypes


def _enum_values(enum_cls) -> dict[str, str]:
    """Map each enum member NAME to its serialized VALUE, as Python emits it."""
    return {member.name: member.value for member in enum_cls}


def main() -> None:
    # ------------------------------------------------------------------
    # Enum value maps: name -> value for every enum the types layer ports.
    # ------------------------------------------------------------------
    enums = {
        "SessionState": _enum_values(ctypes.SessionState),
        "MessageType": _enum_values(ctypes.MessageType),
        "TermType": _enum_values(ctypes.TermType),
        "Flexibility": _enum_values(ctypes.Flexibility),
        "OutcomeStatus": _enum_values(ctypes.OutcomeStatus),
        "ResolutionMechanism": _enum_values(ctypes.ResolutionMechanism),
        "FulfillmentStatus": _enum_values(ctypes.FulfillmentStatus),
        "PartyRole": _enum_values(ctypes.PartyRole),
    }

    # ------------------------------------------------------------------
    # AgentIdentity.to_dict(): the principal_id key is present only when a
    # non-None principal is set. Both branches are captured.
    # ------------------------------------------------------------------
    agent_identity_cases = []
    for kwargs in (
        {"agent_id": "agent-a"},
        {"agent_id": "agent-b", "principal_id": "principal-x"},
        {"agent_id": "did:concordia:agent:42", "principal_id": None},
    ):
        identity = ctypes.AgentIdentity(**kwargs)
        agent_identity_cases.append(
            {"input": kwargs, "expected_dict": identity.to_dict()}
        )

    # ------------------------------------------------------------------
    # TimingConfig defaults: the dataclass field defaults the JS factory must
    # reproduce.
    # ------------------------------------------------------------------
    default_timing = ctypes.TimingConfig()
    timing_defaults = {
        "session_ttl": default_timing.session_ttl,
        "offer_ttl": default_timing.offer_ttl,
        "max_rounds": default_timing.max_rounds,
    }

    # ------------------------------------------------------------------
    # BehaviorRecord defaults + to_dict() cases, including rounding edge cases
    # for concession_magnitude (4 places) and response_time_avg_seconds (2).
    # ------------------------------------------------------------------
    default_behavior = ctypes.BehaviorRecord()
    behavior_defaults = {
        "offers_made": default_behavior.offers_made,
        "concessions": default_behavior.concessions,
        "concession_magnitude": default_behavior.concession_magnitude,
        "signals_shared": default_behavior.signals_shared,
        "constraints_declared": default_behavior.constraints_declared,
        "constraints_violated": default_behavior.constraints_violated,
        "reasoning_provided": default_behavior.reasoning_provided,
        "withdrawal": default_behavior.withdrawal,
        "response_time_avg_seconds": default_behavior.response_time_avg_seconds,
    }

    behavior_record_cases = []
    behavior_inputs = [
        {},  # all defaults
        {
            "offers_made": 5,
            "concessions": 2,
            "concession_magnitude": 0.123456789,
            "signals_shared": 3,
            "constraints_declared": 1,
            "constraints_violated": 0,
            "reasoning_provided": True,
            "withdrawal": False,
            "response_time_avg_seconds": 12.3456,
        },
        # rounding edge: full-precision near-tie values for both rounded fields
        {"concession_magnitude": 0.12345, "response_time_avg_seconds": 2.675},
        {"concession_magnitude": 0.12355, "response_time_avg_seconds": 1.005},
        {
            "concession_magnitude": 0.999999,
            "response_time_avg_seconds": 99999.999,
        },
        {"concession_magnitude": 0.00005, "response_time_avg_seconds": 0.005},
        # EXACT binary half-ties routed through to_dict() so the end-to-end
        # serialization path exercises round-half-to-even, not just the isolated
        # pyRound vectors. concession_magnitude rounds at 4 places, so 0.03125
        # is an exact tie there (-> 0.0312); response_time_avg_seconds rounds at
        # 2 places, so 0.125 is an exact tie there (-> 0.12). A half-up impl
        # would emit 0.0313 / 0.13 and fail this case.
        {"concession_magnitude": 0.03125, "response_time_avg_seconds": 0.125},
        {"concession_magnitude": 1.03125, "response_time_avg_seconds": 123.625},
    ]
    for kwargs in behavior_inputs:
        record = ctypes.BehaviorRecord(**kwargs)
        behavior_record_cases.append(
            {"input": kwargs, "expected_dict": record.to_dict()}
        )

    # ------------------------------------------------------------------
    # round() parity sample: a broad random + adversarial vector set proving
    # the JS pyRound helper reproduces Python's built-in round(value, n)
    # exactly across the value ranges BehaviorRecord produces.
    #
    # CPython's round() is round-half-to-EVEN on the exact binary value of the
    # double, NOT decimal round-half-up. The fixture MUST therefore carry the
    # exact binary half-ties (k / 2^m, which land exactly on a .5 boundary at
    # some decimal place) so a regression to a half-up implementation (e.g.
    # parseFloat(value.toFixed(n))) is CAUGHT. Every expected value here comes
    # straight from Python's round(); none is hand-authored.
    # ------------------------------------------------------------------
    round_parity = []

    def _add(value: float, ndigits: int) -> None:
        round_parity.append(
            {"value": value, "ndigits": ndigits, "expected": round(value, ndigits)}
        )

    # Explicit half-tie literals confirmed to diverge under decimal half-up.
    # round-half-to-even sends each to the EVEN neighbor; a half-up impl would
    # send them the other way, so these are the regression tripwires.
    #   0.125   @2 -> 0.12   (half-up: 0.13)
    #   123.625 @2 -> 123.62 (half-up: 123.63)
    #   0.03125 @4 -> 0.0312 (half-up: 0.0313)
    #   99.90625@4 -> 99.9062(half-up: 99.9063)
    for value, ndigits in (
        (0.125, 2),
        (123.625, 2),
        (0.625, 2),
        (0.0625, 2),
        (2.5, 0),
        (0.5, 0),
        (0.03125, 4),
        (99.90625, 4),
        (1.03125, 4),
    ):
        _add(value, ndigits)

    # Systematic EXACT-binary half-tie classes at n=2 and n=4. half-to-even and
    # half-up can only disagree on a value whose stored double sits EXACTLY on a
    # decimal midpoint. That requires a dyadic rational (denominator a power of
    # two) that also equals odd / (2 * 10^n) -- i.e. the binary-exact .xx5 /
    # .xxxx5 boundaries. Decimal literals like 0.005 do NOT qualify (their
    # double is a near-tie, not an exact one). We generate dyadic candidates and
    # keep only the verified exact ties, so every vector here is a genuine
    # tripwire that a half-up implementation gets wrong.
    def _is_exact_decimal_tie(x: float, ndigits: int) -> bool:
        scaled = Fraction(x) * (10 ** ndigits)  # exact value of the double * 10^n
        return scaled.denominator == 2 and scaled.numerator % 2 == 1

    for ndigits, max_k in ((2, 7), (4, 14)):
        seen = 0
        # i / 2^k for small k yields the binary-exact .xx5 / .xxxx5 ties.
        for k in range(1, max_k + 1):
            for i in range(1, 2 ** k * 3 + 1):  # cover [0, 3.0)
                value = i / (2 ** k)
                if _is_exact_decimal_tie(value, ndigits):
                    _add(value, ndigits)
                    seen += 1
                    if seen >= 18:
                        break
            if seen >= 18:
                break

    # Large-|ndigits| vectors. The final scale step must NOT materialize
    # 10^|ndigits| as a double: for |ndigits| >= 309 that overflows to Infinity
    # and a naive `Number(rounded) / Number(10n ** BigInt(|ndigits|))` yields
    # NaN. CPython's round() returns the original (or signed-zero) value here,
    # because ndigits far exceeds the precision of a double. The decimal-string
    # scale path reproduces it exactly. Expecteds come straight from Python's
    # round(); -0.0 (e.g. round(-1.23, -400)) is preserved because the JS test
    # compares with Object.is.
    for value, ndigits in (
        (1.2345, 400),     # was NaN under the overflow bug; Python -> 1.2345
        (1.23, 309),       # first overflow boundary; Python -> 1.23
        (1.5, 309),
        (1.5, 400),
        (1.2345, 50),      # mid-range positive ndigits, no overflow
        (123.456, 30),
        (-1.23, -400),     # negative huge ndigits; Python -> -0.0 (signed)
        (1.23, -400),      # Python -> 0.0
        (0.1, -310),       # Python -> 0.0
        (-0.1, -310),      # Python -> -0.0 (signed)
        (12345.678, -10),  # mid-range negative ndigits
        (12345.678, -3),
    ):
        _add(value, ndigits)

    # Decimal near-ties (NOT exact binary halves): values like 2.675 / 1.005
    # whose stored double is just under/over the decimal midpoint. Both
    # implementations should agree here; included to pin that the fix did not
    # over-correct away-from-even on non-ties.
    for literal in ("2.675", "1.005", "0.005", "0.015", "0.025", "0.12345", "0.12355"):
        f = float(literal)
        _add(f, 2)
        _add(f, 4)

    # A modest seeded-random sample across the two BehaviorRecord value scales,
    # plus a few negatives to exercise the sign path (Python preserves -0.0).
    rng = random.Random(20260529)
    for _ in range(20):  # concession_magnitude scale (0..1)
        _add(rng.uniform(0, 1), 4)
    for _ in range(20):  # response_time_avg_seconds scale
        _add(rng.uniform(0, 100000), 2)
    for _ in range(10):  # negatives (defensive: pyRound is sign-correct)
        _add(rng.uniform(-1000, 0), 2)

    doc = {
        "_comment": (
            "Generated by js-sdk/scripts/gen-types-fixtures.py from "
            "concordia.types. Enum values, to_dict() output, and round() "
            "expectations are Python-produced; do not edit by hand."
        ),
        "enums": enums,
        "agent_identity_cases": agent_identity_cases,
        "timing_defaults": timing_defaults,
        "behavior_defaults": behavior_defaults,
        "behavior_record_cases": behavior_record_cases,
        "round_parity": round_parity,
    }

    json.dump(doc, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
