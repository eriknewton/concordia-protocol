/**
 * Shared CPython-3.12-`datetime.fromisoformat`-faithful ISO 8601 parser.
 *
 * Concordia's reference (`concordia/schema_validator.py`, `approval_receipt.py`)
 * validates and parses timestamps with:
 *
 *     datetime.fromisoformat(value.replace("Z", "+00:00"))
 *
 * CPython 3.12 widened `fromisoformat` to accept the FULL ISO 8601 grammar:
 * extended AND basic date/time forms, ISO week dates, `.`/`,` fractional seconds
 * of any length, and offsets `±HH`, `±HHMM`, `±HH:MM`, `±HHMMSS`, `±HH:MM:SS`
 * (plus fractional-second offsets). A naive JS regex / `Date.parse` is STRICTER
 * than this on several valid alternate spellings, so a receipt that Python signed
 * and emitted in any of those forms would be FALSELY rejected (format check) or
 * FALSELY reported `expired` (`Date.parse` -> `NaN`). This module is the single
 * source of truth that BOTH the `date-time` format check and the `expires_at`
 * expiry parse use, so they cannot drift.
 *
 * It is a direct port of CPython 3.12's `_parse_isoformat_date` /
 * `_parse_isoformat_time` (Lib/datetime.py) accept set and field-range checks,
 * verified field-by-field against `python3.12` (see the gen-fixtures forms).
 *
 * Two entry points share ONE parse:
 *  - {@link isCpythonIsoDateTime} -> the format check accepts/rejects exactly what
 *    `fromisoformat` accepts (and reports tz-awareness, mirroring `_is_date_time`,
 *    which additionally requires `tzinfo is not None`).
 *  - {@link cpythonIsoDateTimeToEpochMs} -> the expiry parse returns epoch
 *    milliseconds (naive -> UTC, mirroring `_parse_datetime`'s `tzinfo is None ->
 *    replace(tzinfo=utc)`), or `null` when the string is not a valid CPython
 *    isoformat.
 *
 * PARITY POSTURE. Verified field-by-field against `python3.12` over an
 * ~11.6k-input combinatorial + mutation-fuzz battery: ZERO inputs on which this
 * parser is LOOSER than CPython (no fail-open), and for every input CPython
 * parses to a real instant, the epoch ms is byte-identical. Where CPython is
 * itself lenient on out-of-RANGE offset fields that no real timestamp uses (e.g.
 * `+00:99` minutes -> `+01:39`, `+00:00:99` seconds), this parser ACCEPTS the
 * same forms and computes the same epoch ms, so the named alternate spellings --
 * `+0000`, `+00`, comma fractional, basic form `YYYYMMDDTHHMMSS`, sub-minute
 * offset `+00:00:30` -- all round-trip.
 *
 * YEAR-9999 OVERFLOW (FIXED, fail-CLOSED -- 2026-05-30 re-review finding #3).
 * `_parse_datetime` is `fromisoformat(...).astimezone(timezone.utc)`. A year-9999
 * (or year-0001) civil time with a tz OFFSET parses fine through `fromisoformat`
 * (so the FORMAT check, which only calls `fromisoformat`, passes -- matching this
 * module's {@link isCpythonIsoDateTime}), but `astimezone` then shifts the instant
 * by the offset and CPython raises `OverflowError` when the UTC result leaves
 * `[datetime.min, datetime.max]` (e.g. `9999-12-31T23:59:59-14:00`). The reference
 * verifier does NOT catch that, so such a receipt is NOT honored. The ordinal
 * arithmetic in {@link cpythonIsoDateTimeToEpochMs} has no ceiling, so it would
 * otherwise return a finite ms and report the receipt VALID -- a fail-OPEN. The
 * guard there rejects (returns `null`, the parse-failure signal) any UTC instant
 * outside `[CPYTHON_DATETIME_MIN_MS, CPYTHON_DATETIME_MAX_MS]`, mirroring the
 * raise as a clean fail-closed validation failure (the verifier then reports the
 * receipt expired/invalid, never valid). Reject, do not clamp-and-accept.
 *
 * CPYTHON ZERO-OFFSET QUIRK (matched exactly -- relates to 2026-05-30 re-review
 * finding #2, the sub-microsecond-offset off-by-1ms). When an offset's INTEGER
 * components (h/m/s) are all zero, `fromisoformat` collapses the offset to
 * `timezone.utc` and DISCARDS any fractional-second part: `+00,99`, `+00:00,30`,
 * `-00:00.30` all yield `0:00:00`, whereas `+01:02:03.5` (a nonzero integer part)
 * keeps the `.5`. {@link parseIsoTime} reproduces this; carrying the fraction
 * unconditionally over-shifted these degenerate zero-offset spellings by up to
 * ~1s, so the special-case drop is required for byte-identical epoch ms. The
 * residual finding #2 captures is that a NONZERO-integer offset carrying a
 * sub-microsecond fractional tail can floor to a ms 1 unit different from CPython.
 * It is IMMATERIAL: expiry is a coarse "is it past `expires_at`" comparison at ms
 * granularity, the divergence is at most 1ms on an exotic sub-microsecond offset
 * that no real Concordia timestamp uses, and flooring keeps TS on the safe side.
 * No behavior change; documented, not chased.
 *
 * KNOWN PARITY RESIDUAL (fail-CLOSED / SAFE direction; documented, not chased --
 * same posture as the prior PRs' ISO residuals; the week-date bullet is the
 * 2026-05-30 re-review finding #1). On purely MALFORMED inputs that no real
 * Python-emitted timestamp produces, this parser is STRICTER than CPython:
 *   - CPython's time scan reads HH/MM/SS greedily by 2-digit pairs and IGNORES a
 *     trailing odd digit or single junk char (e.g. `12:47:044`, `11:57:16t`,
 *     `02001`); this parser requires the fixed `HH[:MM[:SS]]` widths and rejects
 *     such garbage.
 *   - FINDING #1 (ISO week-date forms like `2026-W22`): a week date with an
 *     explicit weekday followed immediately by a DIGIT separator (e.g.
 *     `2026-W19-5023:00:55`) is rejected here (CPython's behavior there is
 *     form-dependent and version-coupled). Well-formed week dates (`2026-W19-5T..`)
 *     round-trip identically; only this digit-separator garbage diverges, and only
 *     in the strict direction. Not forgeable from valid wire data.
 * In every such case TS REJECTS a malformed timestamp that CPython would have
 * leniently truncated -- the safe direction (a bad receipt is rejected, never
 * falsely accepted). There is NO input on which this parser is looser than
 * CPython. Chasing CPython's greedy-truncation on garbage is a version-coupled
 * rabbit hole on inputs that do not occur in real data.
 */

/** Result of a successful parse: the civil fields plus the offset (if tz-aware). */
interface ParsedDateTime {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
  /** Microseconds (0..999999), CPython truncates fractional digits past 6. */
  microsecond: number;
  /** Offset from UTC in seconds, or `null` when the value is tz-naive. */
  offsetSeconds: number | null;
}

/**
 * Mirror of Python `_is_date_time`: `datetime.fromisoformat(value.replace("Z",
 * "+00:00"))` must succeed AND yield a tz-aware datetime. A non-string conforms
 * (Python returns `True` for non-strings, deferring to the `type` keyword).
 */
export function isCpythonIsoDateTime(value: unknown): boolean {
  if (typeof value !== 'string') {
    return true;
  }
  const parsed = parseCpythonIsoformat(value.replace(/Z/g, '+00:00'));
  return parsed !== null && parsed.offsetSeconds !== null;
}

/**
 * Mirror of Python `_parse_datetime`:
 * `datetime.fromisoformat(value.replace("Z","+00:00"))`, then `tzinfo is None ->
 * UTC`, returned as epoch milliseconds. Returns `null` when the string is not a
 * valid CPython isoformat (the caller should treat that as a parse failure).
 *
 * Fractional seconds are floored to microseconds (CPython truncates past 6
 * digits) and then to whole milliseconds, matching Python's microsecond-precision
 * comparison reduced to the ms granularity the verifier compares on.
 */
export function cpythonIsoDateTimeToEpochMs(value: string): number | null {
  const parsed = parseCpythonIsoformat(value.replace(/Z/g, '+00:00'));
  if (parsed === null) {
    return null;
  }
  // Civil time -> UTC epoch ms via proleptic-Gregorian ordinal arithmetic (NOT
  // `Date.UTC`, which maps years 0..99 to 1900..1999). The explicit offset (if
  // any) is subtracted to reach the true instant; a naive value is interpreted as
  // UTC, matching Python's `tzinfo is None -> replace(tzinfo=utc)`.
  const EPOCH_ORDINAL = 719163; // ymdToOrdinal(1970, 1, 1)
  const dayMs =
    (ymdToOrdinal(parsed.year, parsed.month, parsed.day) - EPOCH_ORDINAL) *
    86400000;
  const timeMs =
    parsed.hour * 3600000 +
    parsed.minute * 60000 +
    parsed.second * 1000 +
    Math.floor(parsed.microsecond / 1000);
  const offsetMs = (parsed.offsetSeconds ?? 0) * 1000;
  // Floor to whole milliseconds so a fractional-second OFFSET cannot leave a
  // sub-ms remainder (CPython compares at microsecond precision; the verifier
  // compares epoch ms, so flooring keeps TS on the safe side without diverging
  // on any normal `...Z` / `±HH:MM` form).
  const epochMs = Math.floor(dayMs + timeMs - offsetMs);
  // FAIL-CLOSED OVERFLOW GUARD (CPython `astimezone(timezone.utc)` parity).
  // Python's `_parse_datetime` does `fromisoformat(...).astimezone(timezone.utc)`.
  // `fromisoformat` accepts a year-9999 (or year-0001) civil time with a tz offset
  // -- so the `date-time` FORMAT check (which only calls `fromisoformat`) passes --
  // but `astimezone` then SHIFTS the instant by the offset, and if the resulting
  // UTC instant falls outside `[datetime.min, datetime.max]` CPython raises
  // `OverflowError`. The reference verifier does NOT catch that: such a receipt is
  // NOT honored (Python treats it as invalid/rejected). The ordinal arithmetic
  // above has no such ceiling, so without this guard TS would compute a finite ms
  // and report the receipt VALID/not-expired -- a fail-OPEN relative to Python (it
  // would honor a receipt Python rejects). Returning `null` here mirrors the raise
  // as a clean parse failure: the format check still passes (it never reaches this
  // path, matching CPython), but the expiry parse fails closed, so the receipt
  // verifier reports it expired/invalid rather than valid. A timestamp that cannot
  // be represented in both runtimes is not honored. We reject; we do NOT clamp.
  if (epochMs < CPYTHON_DATETIME_MIN_MS || epochMs > CPYTHON_DATETIME_MAX_MS) {
    return null;
  }
  return epochMs;
}

/**
 * CPython `datetime.max` as a UTC epoch-ms ceiling (floored to whole ms):
 * `9999-12-31T23:59:59.999999+00:00`. Verified against `python3` (see the
 * overflow vectors in gen-schema-validator-fixtures.py).
 */
const CPYTHON_DATETIME_MAX_MS = 253402300799999;
/**
 * CPython `datetime.min` as a UTC epoch-ms floor: `0001-01-01T00:00:00+00:00`.
 */
const CPYTHON_DATETIME_MIN_MS = -62135596800000;

// ---------------------------------------------------------------------------
// CPython 3.12 `fromisoformat` port (Lib/datetime.py)
// ---------------------------------------------------------------------------

/**
 * Parse a string exactly as CPython 3.12 `datetime.fromisoformat` would (the
 * `Z`->`+00:00` replacement is the caller's responsibility, matching the Python
 * reference which replaces before calling). Returns the parsed fields, or `null`
 * if CPython would raise `ValueError`.
 *
 * CPython 3.12's algorithm parses the DATE first by its fixed-width grammar (so
 * the date length is determined by its FORM, not by scanning for a separator),
 * then treats the SINGLE character at that fixed position as the date/time
 * SEPARATOR (which may be ANY character -- `T`/`t`/space, but also `+`/`-`/`:` and
 * arbitrary punctuation; CPython does not validate it), then parses the remainder
 * as the TIME (with its own optional UTC offset). This is why `2026-05-10+00:00`
 * parses as the tz-NAIVE `2026-05-10 00:00:00` (the `+` is the separator, `00:00`
 * is a naive time-of-day) rather than as a date with a `+00:00` offset. The date
 * is extended/basic calendar (`YYYY-MM-DD` / `YYYYMMDD`) or an ISO week date
 * (`YYYY-Www-D` / `YYYY-Www` / basic `YYYYWwwD` / `YYYYWww`).
 */
function parseCpythonIsoformat(s: string): ParsedDateTime | null {
  const date = parseIsoDate(s);
  if (date === null) {
    return null;
  }

  let hour = 0;
  let minute = 0;
  let second = 0;
  let microsecond = 0;
  let offsetSeconds: number | null = null;

  const consumed = date.consumed;
  if (consumed < s.length) {
    // One separator character (any char) follows the date; the rest is the time.
    // CPython requires a non-empty time after the separator.
    const timeStr = s.slice(consumed + 1);
    if (timeStr.length === 0) {
      return null;
    }
    const time = parseIsoTime(timeStr);
    if (time === null) {
      return null;
    }
    hour = time.hour;
    minute = time.minute;
    second = time.second;
    microsecond = time.microsecond;
    offsetSeconds = time.offsetSeconds;
  }

  return {
    year: date.year,
    month: date.month,
    day: date.day,
    hour,
    minute,
    second,
    microsecond,
    offsetSeconds,
  };
}

/** Calendar fields produced by the date parser, plus chars consumed. */
interface IsoDate {
  year: number;
  month: number;
  day: number;
  /** Number of leading characters the date grammar consumed. */
  consumed: number;
}

/**
 * Port of CPython 3.12 `_parse_isoformat_date`. The date grammar has a FIXED
 * length per form, so this consumes exactly the date and reports `consumed`; the
 * caller treats the next character (if any) as the date/time separator. Accepts
 * an extended or basic calendar date, or an ISO week date, with the same
 * field-range checks. Anything not matching one of the fixed forms is rejected.
 */
function parseIsoDate(s: string): IsoDate | null {
  // Year is always exactly 4 digits.
  if (s.length < 4 || !isDigits(s, 0, 4)) {
    return null;
  }
  const year = Number(s.slice(0, 4));
  // CPython: a `datetime` year must be >= MINYEAR (1).
  if (year < 1) {
    return null;
  }

  // The character after the year selects extended (`-`) vs basic/week. An
  // uppercase `W` right after the year (basic week) or after a `-` (extended
  // week) is a week date -- CPython accepts only uppercase `W` here (lowercase
  // `w` is rejected). The date grammar consumes a FIXED number of chars per form.
  const c4 = s[4];
  const extended = c4 === '-';
  const afterYear = extended ? s.slice(5) : s.slice(4);
  const consumedBeforeAfterYear = extended ? 5 : 4;

  if (afterYear.startsWith('W')) {
    // Week date: `Www` (2 digits), then optionally `[-]D`.
    const body = afterYear.slice(1);
    if (body.length < 2 || !isDigits(body, 0, 2)) {
      return null;
    }
    const week = Number(body.slice(0, 2));
    let weekday = 1; // CPython defaults the weekday to Monday when absent.
    let hasExplicitDay = false;
    // Fixed length consumed so far: year + (extended ? '-' : '') + 'W' + 'ww'.
    let consumed = consumedBeforeAfterYear + 1 + 2;

    // Determine whether a weekday digit follows (with `-` in extended form). The
    // weekday is part of the DATE only if it is exactly one digit at the fixed
    // position; otherwise the char(s) belong to the separator/time.
    if (extended) {
      // Extended week: weekday is `-D` (a `-` then one digit) at the fixed spot.
      if (body.length >= 4 && body[2] === '-' && isDigits(body, 3, 4)) {
        weekday = Number(body[3]);
        consumed += 2; // '-' + 'D'
        hasExplicitDay = true;
      }
    } else {
      // Basic week: weekday is a single digit at the fixed spot.
      if (body.length >= 3 && isDigits(body, 2, 3)) {
        weekday = Number(body[2]);
        consumed += 1;
        hasExplicitDay = true;
      }
    }

    // Fail-CLOSED guard (safe direction). When a week date carries an EXPLICIT
    // weekday, CPython rejects the string if the next (separator) character is a
    // DIGIT -- e.g. `2026-W19-5023:00:55` (the week parser greedily mis-reads the
    // adjacent digit). The valid alternate spellings all use a non-digit
    // separator (`T`/space/`+`/`Z`->`+`). We reject a digit-separator after an
    // explicit-day week date so TS is never LOOSER than CPython here; this only
    // ever rejects garbage that no real Python-emitted timestamp produces.
    if (hasExplicitDay && consumed < s.length && isAsciiDigit(s[consumed])) {
      return null;
    }

    const date = isoWeekToGregorian(year, week, weekday);
    if (date === null) {
      return null;
    }
    return { ...date, consumed };
  }

  // Calendar form (no `W`): `MM` then `DD`, extended (`MM-DD`) or basic (`MMDD`).
  // Each has a FIXED width; a separator+time may follow, so check prefixes, not
  // the whole remaining length.
  if (extended) {
    // Fixed `MM-DD` (5 chars) after the year and the `-` already consumed.
    if (
      afterYear.length < 5 ||
      !isDigits(afterYear, 0, 2) ||
      afterYear[2] !== '-' ||
      !isDigits(afterYear, 3, 5)
    ) {
      return null;
    }
    const month = Number(afterYear.slice(0, 2));
    const day = Number(afterYear.slice(3, 5));
    return validateCalendarDate(year, month, day, 10); // YYYY-MM-DD
  }
  // Basic `MMDD` (4 chars) directly after the 4-digit year.
  if (afterYear.length < 4 || !isDigits(afterYear, 0, 4)) {
    return null;
  }
  const month = Number(afterYear.slice(0, 2));
  const day = Number(afterYear.slice(2, 4));
  return validateCalendarDate(year, month, day, 8); // YYYYMMDD
}

/** Apply CPython's month/day range checks for a calendar date. */
function validateCalendarDate(
  year: number,
  month: number,
  day: number,
  consumed: number,
): IsoDate | null {
  if (month < 1 || month > 12) {
    return null;
  }
  if (day < 1 || day > daysInMonth(year, month)) {
    return null;
  }
  return { year, month, day, consumed };
}

/** Time fields produced by the time parser. */
interface IsoTime {
  hour: number;
  minute: number;
  second: number;
  microsecond: number;
  offsetSeconds: number | null;
}

/**
 * Port of CPython 3.12 `_parse_isoformat_time`. Splits off the UTC offset on the
 * first `+`/`-`, parses the time component (extended `HH:MM:SS` or basic `HHMMSS`,
 * each truncatable to `HH`/`HH:MM`), then the offset.
 */
function parseIsoTime(s: string): IsoTime | null {
  // Find the offset sign. CPython scans for `+`/`-` after the time digits.
  let tzPos = -1;
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    if (ch === '+' || ch === '-') {
      tzPos = i;
      break;
    }
  }

  const timePart = tzPos >= 0 ? s.slice(0, tzPos) : s;
  // A digit-less fractional tail in the time-of-day is valid only when an offset
  // immediately follows it (CPython accepts `12:00:00.+00:00` but not `12:00:00.`).
  const timeComponents = parseHms(timePart, /* isOffset */ false, tzPos >= 0);
  if (timeComponents === null) {
    return null;
  }

  let offsetSeconds: number | null = null;
  if (tzPos >= 0) {
    const sign = s[tzPos] === '-' ? -1 : 1;
    const offsetPart = s.slice(tzPos + 1);
    // The offset is always the tail of the string, so a digit-less fraction in it
    // is never valid (nothing follows it).
    const off = parseHms(offsetPart, /* isOffset */ true, /* emptyFractionOk */ false);
    if (off === null) {
      return null;
    }
    // Offset magnitude must be strictly less than 24h (CPython: "offset must be a
    // timedelta strictly between -timedelta(hours=24) and timedelta(hours=24)").
    const magnitude =
      off.hour * 3600 + off.minute * 60 + off.second + off.microsecond / 1e6;
    if (magnitude >= 24 * 3600) {
      return null;
    }
    const integerOffsetSeconds = off.hour * 3600 + off.minute * 60 + off.second;
    // CPython quirk (verified field-by-field against python3.12): when the
    // offset's INTEGER components (h/m/s) are all zero, `fromisoformat` collapses
    // the whole offset to `timezone.utc` and DISCARDS any fractional-second part
    // -- e.g. `+00,99`, `+00:00,30`, `-00:00.30` all yield exactly `0:00:00`. A
    // fractional offset is only carried when at least one integer component is
    // nonzero (`+01:02:03.5` keeps `.5`). Mirror that here so the epoch ms is
    // byte-identical; carrying the fraction unconditionally over-shifted these
    // degenerate zero-offset spellings by up to ~1s.
    const fractionSeconds =
      integerOffsetSeconds === 0 ? 0 : off.microsecond / 1e6;
    offsetSeconds = sign * (integerOffsetSeconds + fractionSeconds);
  }

  return {
    hour: timeComponents.hour,
    minute: timeComponents.minute,
    second: timeComponents.second,
    microsecond: timeComponents.microsecond,
    offsetSeconds,
  };
}

/** Parsed `HH[:MM[:SS[.ffffff]]]` (or offset) component. */
interface Hms {
  hour: number;
  minute: number;
  second: number;
  microsecond: number;
}

/**
 * Port of CPython 3.12's time-component scan, used for BOTH the time-of-day and
 * the UTC offset. Accepts `HH`, `HHMM`/`HH:MM`, `HHMMSS`/`HH:MM:SS`, each with an
 * optional `.`/`,` fractional-second tail. Colon usage must be consistent (all
 * separators present or all absent), matching CPython, which rejects mixed forms
 * like `+00:0030`.
 *
 * @param isOffset When parsing the UTC offset, CPython does NOT range-check the
 *   minute/second fields (it normalizes e.g. `+00:99`); the magnitude check is
 *   applied by the caller. When parsing the time-of-day, hour 0..23, minute
 *   0..59, second 0..59 are enforced.
 */
function parseHms(
  s: string,
  isOffset = false,
  emptyFractionOk = false,
): Hms | null {
  // Separate the fractional-second tail (`.`/`,` + digits) from the HH[MM[SS]].
  let head = s;
  let fraction = '';
  for (let i = 0; i < s.length; i += 1) {
    if (s[i] === '.' || s[i] === ',') {
      head = s.slice(0, i);
      fraction = s.slice(i + 1);
      break;
    }
  }

  let microsecond = 0;
  if (head.length !== s.length) {
    // A separator was present. CPython accepts any number of fractional DIGITS,
    // truncating to microsecond precision. A bare `.`/`,` with ZERO digits is
    // valid ONLY when it is immediately followed by the UTC offset in the
    // original string (e.g. `12:00:00.+00:00`); at the END of the time-of-day or
    // anywhere in the offset, a digit-less fraction is a CPython reject. The
    // caller passes `emptyFractionOk` to reflect "an offset followed this".
    if (fraction.length === 0) {
      if (!emptyFractionOk) {
        return null;
      }
    } else if (!isAllDigits(fraction)) {
      return null;
    }
    microsecond = fractionToMicroseconds(fraction);
  }

  let hour: number;
  let minute = 0;
  let second = 0;

  // Extended (with colons) vs basic (no colons). CPython keys off whether a colon
  // appears right after HH.
  if (head.length === 2) {
    if (!isDigits(head, 0, 2)) return null;
    hour = Number(head);
  } else if (head.length === 4) {
    // Basic `HHMM`.
    if (!isDigits(head, 0, 4)) return null;
    hour = Number(head.slice(0, 2));
    minute = Number(head.slice(2, 4));
  } else if (head.length === 5) {
    // Extended `HH:MM`.
    if (!isDigits(head, 0, 2) || head[2] !== ':' || !isDigits(head, 3, 5)) {
      return null;
    }
    hour = Number(head.slice(0, 2));
    minute = Number(head.slice(3, 5));
  } else if (head.length === 6) {
    // Basic `HHMMSS`.
    if (!isDigits(head, 0, 6)) return null;
    hour = Number(head.slice(0, 2));
    minute = Number(head.slice(2, 4));
    second = Number(head.slice(4, 6));
  } else if (head.length === 8) {
    // Extended `HH:MM:SS`.
    if (
      !isDigits(head, 0, 2) ||
      head[2] !== ':' ||
      !isDigits(head, 3, 5) ||
      head[5] !== ':' ||
      !isDigits(head, 6, 8)
    ) {
      return null;
    }
    hour = Number(head.slice(0, 2));
    minute = Number(head.slice(3, 5));
    second = Number(head.slice(6, 8));
  } else {
    return null;
  }

  // Field-range checks. CPython applies these to the time-of-day; for the offset
  // it only bounds the overall magnitude (done by the caller), so minute/second
  // up to 99 are accepted there.
  if (hour > 23) return null;
  if (!isOffset) {
    if (minute > 59) return null;
    if (second > 59) return null;
  }

  return { hour, minute, second, microsecond };
}

/**
 * Convert a fractional-second digit string to microseconds (0..999999),
 * truncating digits past the 6th (CPython truncates, it does not round).
 */
function fractionToMicroseconds(digits: string): number {
  if (digits.length === 0) {
    return 0;
  }
  // Pad/trim to exactly 6 digits, truncating (not rounding) extra precision.
  const six = (digits + '000000').slice(0, 6);
  return Number(six);
}

// ---------------------------------------------------------------------------
// ISO week date -> Gregorian, and small helpers
// ---------------------------------------------------------------------------

/** A bare calendar date (no `consumed`), produced by the week-date converter. */
interface YmD {
  year: number;
  month: number;
  day: number;
}

/**
 * Convert an ISO week date (year, week 1..53, weekday 1..7 Mon..Sun) to a
 * Gregorian calendar date, mirroring CPython's `_isoweek_to_gregorian` plus its
 * range checks. Returns `null` on an invalid week/weekday (including week 53 in a
 * year that has no week 53). All arithmetic uses proleptic-Gregorian ordinals
 * (no JS `Date`, which mishandles years 0..99).
 */
function isoWeekToGregorian(
  year: number,
  week: number,
  weekday: number,
): YmD | null {
  if (week < 1 || week > 53) {
    return null;
  }
  if (weekday < 1 || weekday > 7) {
    return null;
  }
  // CPython: `out_ordinal = _isoweek1monday(year) + (week - 1) * 7 + (day - 1)`.
  const week1mondayOrd = isoWeek1MondayOrdinal(year);
  const ord = week1mondayOrd + (week - 1) * 7 + (weekday - 1);

  // CPython rejects week 53 when the requested day falls outside the ISO year
  // (its `_isoweek_to_gregorian` raises for `week == 53` when there is no W53).
  // We detect this by checking the resulting date's own ISO week round-trips.
  const date = ordinalToYmD(ord);
  if (date === null) {
    return null;
  }
  if (date.year < 1) {
    return null;
  }
  // Guard the "no week 53" case: if week 53 was requested but the resolved date
  // lands in week 1 of the next ISO year, CPython would have rejected it.
  if (week === 53) {
    const back = gregorianIsoYearWeek(date.year, date.month, date.day);
    if (back.week !== 53) {
      return null;
    }
  }
  return date;
}

/** Proleptic-Gregorian ordinal (CPython `_ymd2ord`, day 1 = 0001-01-01). */
function ymdToOrdinal(year: number, month: number, day: number): number {
  return daysBeforeYear(year) + daysBeforeMonth(year, month) + day;
}

/** Days before Jan 1 of `year` in the proleptic Gregorian calendar. */
function daysBeforeYear(year: number): number {
  const y = year - 1;
  return y * 365 + Math.floor(y / 4) - Math.floor(y / 100) + Math.floor(y / 400);
}

/** Days in `year` before the 1st of `month`. */
function daysBeforeMonth(year: number, month: number): number {
  let days = 0;
  for (let m = 1; m < month; m += 1) {
    days += daysInMonth(year, m);
  }
  return days;
}

/** The proleptic-Gregorian ordinal of the Monday of ISO week 1 of `year`. */
function isoWeek1MondayOrdinal(year: number): number {
  const THURSDAY = 3; // 0=Mon .. 6=Sun
  const firstday = ymdToOrdinal(year, 1, 1);
  const firstweekday = (firstday + 6) % 7; // Mon=0
  let week1monday = firstday - firstweekday;
  if (firstweekday > THURSDAY) {
    week1monday += 7;
  }
  return week1monday;
}

/** Inverse of {@link ymdToOrdinal}: ordinal -> calendar date (or `null`). */
function ordinalToYmD(ordinal: number): YmD | null {
  if (ordinal < 1) {
    return null;
  }
  // Estimate the year, then adjust, mirroring the ordinal arithmetic above.
  let year = Math.floor(ordinal / 365) + 1;
  while (daysBeforeYear(year) >= ordinal) {
    year -= 1;
  }
  while (daysBeforeYear(year + 1) < ordinal) {
    year += 1;
  }
  let remaining = ordinal - daysBeforeYear(year);
  let month = 1;
  for (;;) {
    const dim = daysInMonth(year, month);
    if (remaining <= dim) {
      break;
    }
    remaining -= dim;
    month += 1;
  }
  return { year, month, day: remaining };
}

/** ISO (year, week) that a Gregorian date belongs to (for the week-53 guard). */
function gregorianIsoYearWeek(
  year: number,
  month: number,
  day: number,
): { isoYear: number; week: number } {
  const ord = ymdToOrdinal(year, month, day);
  // Thursday of this date's week determines the ISO year.
  const weekday = (ord + 6) % 7; // Mon=0
  const thursdayOrd = ord - weekday + 3;
  const thursday = ordinalToYmD(thursdayOrd);
  const isoYear = thursday ? thursday.year : year;
  const week = Math.floor((thursdayOrd - isoWeek1MondayOrdinal(isoYear)) / 7) + 1;
  return { isoYear, week };
}

/** Days in a (1-based) month, leap-aware. */
function daysInMonth(year: number, month: number): number {
  const table = [31, isLeapYear(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return table[month - 1] ?? 31;
}

/** Proleptic Gregorian leap year. */
function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

/** True iff `ch` is a single ASCII digit `0`..`9` (a missing char is not). */
function isAsciiDigit(ch: string | undefined): boolean {
  if (ch === undefined || ch.length !== 1) {
    return false;
  }
  const c = ch.charCodeAt(0);
  return c >= 48 && c <= 57;
}

/** True iff `s[start..end)` is all ASCII digits (and the slice is in range). */
function isDigits(s: string, start: number, end: number): boolean {
  if (end > s.length || start < 0 || start >= end) {
    return false;
  }
  for (let i = start; i < end; i += 1) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) {
      return false;
    }
  }
  return true;
}

/** True iff the whole string is non-empty and all ASCII digits. */
function isAllDigits(s: string): boolean {
  return s.length > 0 && isDigits(s, 0, s.length);
}
