"""The Guard state manager for the two stateful Simple modifiers.

Section 5.2 keeps `within` and `rate` out of the expression tree: the tree stays
a pure function (E1) and the sliding-window counts live here, entering the audit
record as `temporal_state`. E9 forbids reading the wall clock, so the caller
supplies the instant; the corpus's state operations carry no timestamps, so they
all land on the same injected instant, which is inside every window they name.

Truth table (section 5.2, "stateful operator truth semantics"):

* `rate: N/window` is false for the first N events and true from the N+1th.
* `within: window` is false the first time and true from the second inside the
  window, which is the deduplication reading.

Failure mode a reader should know about: counting BEFORE the check inverts both
operators. Section 5.2 requires post-counting, so `record` and `check` are
separate operations here and a check never records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TemporalState:
    """Sliding-window event history, keyed by the section 5.2 isolation key."""

    #: `within` keys on field+operator+value; `rate` additionally on the rate
    #: string. Callers pass the composed key; this class does not compose it,
    #: so a caller that reuses one key across two operators is visible as a
    #: shared history rather than hidden behind an internal convention.
    events: dict[str, list[int]] = field(default_factory=dict)
    #: The injected evaluation instant in epoch milliseconds. Never `now()`.
    now_ms: int = 0

    def record(self, key: str) -> None:
        self.events.setdefault(key, []).append(self.now_ms)

    def _in_window(self, key: str, window_ms: int) -> int:
        floor = self.now_ms - window_ms
        return sum(1 for stamp in self.events.get(key, []) if stamp > floor)

    def check_rate(self, key: str, max_count: int, window_ms: int) -> bool:
        """True once the window holds at least `max_count` recorded events."""
        return self._in_window(key, window_ms) >= max_count

    def check_within(self, key: str, window_ms: int) -> bool:
        """True when the window already holds a recorded event (deduplication)."""
        return self._in_window(key, window_ms) >= 1

    def snapshot(self) -> dict[str, int]:
        """The `temporal_state` the audit record carries."""
        return {key: len(stamps) for key, stamps in sorted(self.events.items())}


def run_state_ops(operations: list[dict[str, Any]]) -> bool:
    """Replay a corpus `state_ops` sequence and return the last check's verdict.

    A sequence with no check has nothing to report and is a malformed vector
    rather than a false, so it raises instead of folding.
    """
    state = TemporalState()
    verdict: bool | None = None
    for operation in operations:
        name = operation.get("op")
        key = str(operation.get("key", ""))
        if name == "recordRate" or name == "recordWithin":
            state.record(key)
        elif name == "checkRate":
            verdict = state.check_rate(key, int(operation["maxCount"]), int(operation["windowMs"]))
        elif name == "checkWithin":
            verdict = state.check_within(key, int(operation["windowMs"]))
        else:
            raise ValueError(f"unknown state operation: {name!r}")
    if verdict is None:
        raise ValueError("state_ops sequence contains no check operation")
    return verdict
