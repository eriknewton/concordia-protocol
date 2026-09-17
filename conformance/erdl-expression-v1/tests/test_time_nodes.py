"""Time group: days_between, epoch_ms, date_add, date_part, month_last_day.

Every case is UTC (section 7.3(f)) and none of them reads a clock (E9).
"""

from __future__ import annotations

from .helpers import assert_errored, assert_number, assert_string, dec


def test_days_between_is_a_floored_utc_day_difference() -> None:
    assert_number({"days_between": ["2026-01-01", "2026-01-11"]}, "10")
    assert_number({"days_between": ["2026-01-01", "2026-01-01"]}, "0")
    # Two seconds across a midnight boundary is still zero days: the rule is a
    # millisecond difference divided by 86400000 and floored, not a calendar
    # date subtraction.
    assert_number({"days_between": ["2026-01-01T23:59:59", "2026-01-02T00:00:01"]}, "0")


def test_epoch_ms_treats_a_bare_datetime_as_utc_and_honours_an_offset() -> None:
    assert_number({"epoch_ms": "1970-01-01"}, "0")
    bare = {"epoch_ms": "2026-01-01T12:30:45"}
    zulu = {"epoch_ms": "2026-01-01T12:30:45Z"}
    assert_number(bare, "1767270645000")
    assert_number(zulu, "1767270645000")
    # +08:00 means the local reading is eight hours ahead of UTC, so the UTC
    # instant is eight hours earlier. Adding the offset instead of subtracting
    # it is the classic sign inversion, and it lands 57600000 ms away.
    assert_number({"epoch_ms": "2026-01-01T12:30:45+08:00"}, "1767241845000")


def test_date_add_returns_an_iso_utc_string() -> None:
    assert_string(
        {"date_add": {"unit": "years", "base": "2024-01-15", "amount": 2}},
        "2026-01-15T00:00:00.000Z",
    )
    assert_string(
        {"date_add": {"unit": "days", "base": "2024-01-15", "amount": 20}},
        "2024-02-04T00:00:00.000Z",
    )


def test_month_addition_clamps_to_the_last_day_of_the_target_month() -> None:
    # One month after 31 January 2024 is 29 February, not 2 March. See
    # RESULTS.md ambiguity A5: the spec calls this UTC calendar arithmetic and
    # states no overflow rule, and an overflow reading would move the result
    # into the following month.
    assert_string(
        {"date_add": {"unit": "months", "base": "2024-01-31", "amount": 1}},
        "2024-02-29T00:00:00.000Z",
    )


def test_a_non_integer_duration_is_rejected_rather_than_rounded() -> None:
    # Section 7.3(f) forbids implicit rounding here: "add 1.5 months" has no
    # business meaning, so half-even would invent one.
    assert_errored(
        {"date_add": {"unit": "months", "base": "2024-01-15", "amount": dec("1.5")}},
        code="type_mismatch",
    )


def test_date_part_extracts_utc_components() -> None:
    assert_number({"date_part": {"unit": "year", "arg": "2026-08-15"}}, "2026")
    assert_number({"date_part": {"unit": "month", "arg": "2026-08-15"}}, "8")
    # ISO numbering, Monday 1 through Sunday 7; 2026-08-15 is a Saturday.
    assert_number({"date_part": {"unit": "day_of_week", "arg": "2026-08-15"}}, "6")


def test_month_last_day_returns_the_month_end() -> None:
    assert_string({"month_last_day": "2024-02-10"}, "2024-02-29T00:00:00.000Z")
    assert_string({"month_last_day": "2026-01-10"}, "2026-01-31T00:00:00.000Z")
    assert_string({"month_last_day": "2026-02-10"}, "2026-02-28T00:00:00.000Z")


def test_an_unparseable_date_is_an_error_and_a_missing_one_is_a_type_mismatch() -> None:
    assert_errored({"days_between": ["not-a-date", "2026-01-11"]}, code="invalid_date")
    assert_errored({"epoch_ms": "not-a-date"}, code="invalid_date")
    assert_errored({"epoch_ms": {"field": "missing"}}, {}, "type_mismatch")


def test_a_lenient_date_form_is_refused() -> None:
    # A parser that accepted these would produce plausible values that no other
    # runner agrees with. Fractional seconds are excluded by section 7.3(f)
    # ("whole-second precision"), and an unpadded month is not ISO 8601.
    assert_errored({"epoch_ms": "2026-1-1"}, code="invalid_date")
    assert_errored({"epoch_ms": "2026-01-01T00:00:00.500Z"}, code="invalid_date")
    assert_errored({"epoch_ms": "2026-02-30"}, code="invalid_date")
