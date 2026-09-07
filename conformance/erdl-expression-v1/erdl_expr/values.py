"""Runtime value model for the ERDL expression kernel.

The kernel's numeric domain is an exact rational (`fractions.Fraction`), never a
binary float. ERDL spec section 7.3(c) requires intermediate computation to use
high-precision bounded rationals and to round only at output nodes, so an exact
rational is the only representation that satisfies the constraint by
construction rather than by a precision setting that could be tuned wrong.
Rounding to scale 14 with half-even happens exactly once, in
:func:`fixed_point_int`, and every caller that produces a reported number goes
through it.

Reference: ERDL spec v2.1 sections 7.2 (E2, E10) and 7.3(c).
"""

from __future__ import annotations

import json
import unicodedata
from decimal import Decimal
from fractions import Fraction
from typing import Any, Final, Union

#: ERDL E2 fixes the reported scale at 14 decimal places. It is not
#: configurable: a runner that reported at another scale would produce values
#: that are not comparable with any other runner's, which is the whole point of
#: the constraint.
SCALE: Final[int] = 14

#: Rounding mode identifiers. ROUND_HALF_EVEN is the E2 mandate; ROUND_HALF_UP
#: exists ONLY so the test suite can plant the wrong mode and show that the E2
#: sentinel catches it. Nothing in the shipped evaluation path selects it, and
#: the CLI exposes no flag for it.
ROUND_HALF_EVEN: Final[str] = "ROUND_HALF_EVEN"
ROUND_HALF_UP: Final[str] = "ROUND_HALF_UP"


class Undefined:
    """The E11 missing-field sentinel.

    Distinct from JSON ``null``: E11 gives them different behaviour at an
    equality leaf (a missing field equals ``null``; a present ``null`` field
    also equals ``null``, but a present non-null value does not), and only
    ``exists`` is allowed to sense the difference between missing and present.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "UNDEFINED"

    def __bool__(self) -> bool:
        # Truthiness is never used to make a semantic decision in this kernel;
        # every branch tests the type explicitly. Defined only so an accidental
        # boolean context cannot silently read as true.
        return False


UNDEFINED: Final[Undefined] = Undefined()

#: The kernel's runtime value domain. `list` and `dict` occur as intermediate
#: values (an array under a quantifier or an aggregate, the fact root under
#: `var: "$"`); they are not reportable, and results.py folds them.
Value = Union[Undefined, None, bool, Fraction, str, "list[Any]", "dict[str, Any]"]


def nfc(text: str) -> str:
    """Apply the E10 string normalization.

    Every string entering the value domain passes through here, both literals
    from the tree and values read out of the fact object, so a decomposed
    context value and a precomposed literal compare equal.
    """
    return unicodedata.normalize("NFC", text)


def is_number(value: object) -> bool:
    """True for a kernel number.

    `bool` is a subclass of `int` in Python but is NOT a number here: ERDL
    forbids implicit type conversion, so `eq(false, 100)` must be false rather
    than a numeric comparison against zero.
    """
    return isinstance(value, Fraction) and not isinstance(value, bool)


def to_fraction(value: object) -> Fraction:
    """Convert a JSON-parsed numeric literal to the exact rational domain.

    `Decimal` is exact for every decimal literal the vectors carry, and
    `Fraction(Decimal)` is a lossless conversion, so `0.1` becomes exactly one
    tenth rather than the nearest binary double.
    """
    if isinstance(value, bool):
        raise TypeError("bool is not a number in the ERDL value domain")
    if isinstance(value, Fraction):
        return value
    if isinstance(value, int):
        return Fraction(value)
    if isinstance(value, Decimal):
        return Fraction(value)
    raise TypeError(f"not a numeric literal: {value!r}")


def round_to_int(value: Fraction, rounding: str = ROUND_HALF_EVEN) -> int:
    """Round an exact rational to an integer under the named mode.

    Implemented on integer arithmetic rather than via `decimal` so that a
    non-terminating rational (1/3, 2/7) is rounded from its exact value and not
    from a truncated decimal expansion, which is what "no rounding in
    intermediates" (E2) requires.
    """
    numerator, denominator = value.numerator, value.denominator
    quotient, remainder = divmod(numerator, denominator)  # floor; remainder >= 0
    doubled = 2 * remainder
    if doubled > denominator:
        return quotient + 1
    if doubled < denominator:
        return quotient
    # Exact tie. The two candidates are `quotient` (below) and `quotient + 1`.
    if rounding == ROUND_HALF_EVEN:
        return quotient if quotient % 2 == 0 else quotient + 1
    if rounding == ROUND_HALF_UP:
        # Half away from zero, the mode a naive implementation reaches for.
        return quotient if value < 0 else quotient + 1
    raise ValueError(f"unknown rounding mode: {rounding}")


def fixed_point_int(value: Fraction, rounding: str = ROUND_HALF_EVEN) -> int:
    """The scale-14 fixed-point integer for a rational.

    This integer is the equality unit the expression-runner contract names for
    `value_type: "number"` (ER4), so two runners agree on a number exactly when
    this integer agrees.
    """
    return round_to_int(value * (10**SCALE), rounding)


def decimal_string(value: Fraction, rounding: str = ROUND_HALF_EVEN) -> str:
    """Render a rational as its scale-14 fixed-point decimal, zeros trimmed.

    Trailing fractional zeros are trimmed because they carry no information at a
    fixed scale: "0.3" and "0.30000000000000" denote the same scale-14 integer,
    and the trimmed form is what a reader and a JSON number parser both expect.
    """
    scaled = fixed_point_int(value, rounding)
    sign = "-" if scaled < 0 else ""
    magnitude = abs(scaled)
    unit = 10**SCALE
    whole, fraction = divmod(magnitude, unit)
    # 14 = SCALE: the fractional part is that many digits wide before trimming.
    digits = str(fraction).rjust(SCALE, "0").rstrip("0")
    if not digits:
        return f"{sign}{whole}"
    return f"{sign}{whole}.{digits}"


def load_json_exact(text: str) -> Any:
    """Parse JSON with numeric literals kept exact.

    `parse_float=Decimal` is the argument the whole precision claim rests on.
    The default float parse would turn the literal `0.1` into a binary
    approximation before the kernel ever sees it, and no amount of exact
    arithmetic downstream can recover the decimal the vector actually wrote.
    """
    return json.loads(text, parse_float=Decimal)
