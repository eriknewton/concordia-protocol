"""UTC date handling for the five ERDL time nodes.

Spec section 7.3(f) fixes the whole surface: a date-only string parses as UTC
midnight, a date-time parses per ISO 8601 with whole-second precision (no
fractional seconds), a missing timezone suffix means UTC, component extraction
always takes UTC components, and serialization is ISO 8601 UTC in the
`toISOString` shape.

E9 forbids reading the wall clock, so nothing in this module calls `now()`.
A time node that needed the current instant would take it from an injected
`as_of`, which the vector corpus never supplies and this runner therefore never
invents.
"""

from __future__ import annotations

import calendar
import datetime as dt
import re
from typing import Final

from .errors import INVALID_DATE, TYPE_MISMATCH, EvalError

#: Milliseconds in a day. 86400000 = 24 * 60 * 60 * 1000; section 7.3(f) divides
#: by exactly this and floors, so a leap second or a DST offset never enters.
MS_PER_DAY: Final[int] = 24 * 60 * 60 * 1000

_DATE_ONLY = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
_DATE_TIME = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(Z|[+-]\d{2}:\d{2})?$"
)

#: The units `date_add` accepts. `years` and `months` are calendar units and go
#: through the clamping path below; the rest are exact durations.
ADD_UNITS: Final[frozenset[str]] = frozenset(
    {"years", "months", "weeks", "days", "hours", "minutes", "seconds"}
)

#: The units `date_part` extracts. `day_of_week` is ISO-8601 numbered
#: (1 = Monday through 7 = Sunday); see the note in `date_part`.
PART_UNITS: Final[frozenset[str]] = frozenset(
    {
        "year",
        "month",
        "day",
        "hour",
        "minute",
        "second",
        "day_of_week",
        "day_of_year",
        "quarter",
    }
)


def parse_utc(text: object) -> dt.datetime:
    """Parse an ERDL date or date-time into an aware UTC datetime.

    Failure mode this guards: a lenient parser that accepts `2026-1-1`, a
    fractional-second suffix, or a trailing space produces a value that is
    plausible but disagrees with every other runner. Anything the two patterns
    do not match is an invalid date, not a best effort.
    """
    if not isinstance(text, str):
        raise EvalError(TYPE_MISMATCH, "time node operand is not a string")
    date_only = _DATE_ONLY.match(text)
    if date_only:
        year, month, day = (int(part) for part in date_only.groups())
        try:
            return dt.datetime(year, month, day, tzinfo=dt.timezone.utc)
        except ValueError as exc:
            raise EvalError(INVALID_DATE, text) from exc
    stamped = _DATE_TIME.match(text)
    if not stamped:
        raise EvalError(INVALID_DATE, text)
    year, month, day, hour, minute, second = (int(part) for part in stamped.groups()[:6])
    offset_text = stamped.group(7)
    if offset_text in (None, "Z"):
        offset = dt.timedelta(0)
    else:
        sign = 1 if offset_text[0] == "+" else -1
        offset = sign * dt.timedelta(hours=int(offset_text[1:3]), minutes=int(offset_text[4:6]))
    try:
        naive = dt.datetime(year, month, day, hour, minute, second, tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise EvalError(INVALID_DATE, text) from exc
    # An offset says "this local reading is `offset` ahead of UTC", so UTC is the
    # reading minus the offset. Adding it here is the classic sign inversion.
    return naive - offset


def epoch_ms(moment: dt.datetime) -> int:
    """Milliseconds since the Unix epoch, as an exact integer."""
    delta = moment - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    return (delta.days * MS_PER_DAY) + (delta.seconds * 1000) + (delta.microseconds // 1000)


def to_iso(moment: dt.datetime) -> str:
    """Serialize in the `toISOString` shape section 7.3(f) names."""
    return (
        f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}"
        f"T{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}"
        f".{moment.microsecond // 1000:03d}Z"
    )


def add_units(base: dt.datetime, unit: str, amount: int) -> dt.datetime:
    """UTC calendar arithmetic for `date_add`.

    Month and year addition CLAMPS to the last valid day of the target month:
    one month after 2024-01-31 is 2024-02-29, not 2024-03-02. See RESULTS.md
    ambiguity A5; the spec calls this "UTC calendar arithmetic" and gives no
    overflow rule, and a clamping reading is the one that keeps "add one month"
    inside the month it names.
    """
    if unit == "years":
        return _shift_months(base, amount * 12)
    if unit == "months":
        return _shift_months(base, amount)
    if unit == "weeks":
        return base + dt.timedelta(weeks=amount)
    if unit == "days":
        return base + dt.timedelta(days=amount)
    if unit == "hours":
        return base + dt.timedelta(hours=amount)
    if unit == "minutes":
        return base + dt.timedelta(minutes=amount)
    if unit == "seconds":
        return base + dt.timedelta(seconds=amount)
    raise EvalError(TYPE_MISMATCH, f"unknown date_add unit: {unit}")


def _shift_months(base: dt.datetime, months: int) -> dt.datetime:
    total = (base.year * 12) + (base.month - 1) + months
    year, month_index = divmod(total, 12)
    month = month_index + 1
    last_day = calendar.monthrange(year, month)[1]
    return base.replace(year=year, month=month, day=min(base.day, last_day))


def month_last_day(base: dt.datetime) -> dt.datetime:
    """The last day of the base's UTC month, time components preserved."""
    last_day = calendar.monthrange(base.year, base.month)[1]
    return base.replace(day=last_day)


def date_part(base: dt.datetime, unit: str) -> int:
    """Extract a UTC component.

    `day_of_week` is ISO-numbered (Monday 1 through Sunday 7). RESULTS.md
    records this as ambiguity A6: the spec names the unit but not the numbering,
    and a zero-based Sunday-first numbering is the other live reading. The two
    agree on every day except Sunday.
    """
    if unit == "year":
        return base.year
    if unit == "month":
        return base.month
    if unit == "day":
        return base.day
    if unit == "hour":
        return base.hour
    if unit == "minute":
        return base.minute
    if unit == "second":
        return base.second
    if unit == "day_of_week":
        return base.isoweekday()
    if unit == "day_of_year":
        return base.timetuple().tm_yday
    if unit == "quarter":
        return ((base.month - 1) // 3) + 1
    raise EvalError(TYPE_MISMATCH, f"unknown date_part unit: {unit}")
