#!/usr/bin/env python3
"""Generate CPython repr() / json.dumps() parity fixtures for the JS internals.

Run from the repo root (or anywhere; stdlib-only, no `concordia` import). Emits
a JSON document to stdout. The JS test suite (tests/py-render.test.ts) asserts
that `src/internal/py-repr.ts` (pyRepr) and `src/internal/py-json.ts`
(pyJsonDumps) produce byte-identical renderings.

This is the parity source of truth: every expected string comes straight from
this interpreter's `repr(value)` / `json.dumps(value, sort_keys=True)`, never
hand-authored. Synced into the JS test surface by
scripts/sync-fixtures-from-python.mjs.

INPUT ENCODING. The vector inputs ride inside this JSON document, but the value
space under test is wider than JSON (floats vs ints, non-finite floats), so
inputs are encoded with two tags the JS test decodes:

- `{"$nonfinite": "nan" | "inf" | "-inf"}` -> NaN / Infinity / -Infinity.
- `{"$float": <number>}` -> a Python FLOAT at that position. The JS decoder
  unwraps the number and (for json_cases) registers the enclosing object key
  in the FloatConstraintMap / sets rootIsFloat, mirroring how the schema
  bundle marks float-sourced constraint locations for pyJsonDumps.

Everything else is plain JSON. Vector dicts never use a literal "$float" /
"$nonfinite" key, and dict keys avoid integer-like strings in repr_cases
(JS objects enumerate integer-like keys first, which would shuffle insertion
order in transport -- a JS object-semantics artifact, not a repr concern).

VALUE-SPACE MAPPING (matches the modules' documented contracts):
- repr_cases: integral numbers are Python INTs (a JSON wire number carries no
  int/float tag; the JS module renders integral numbers as Python int repr).
  Only non-integral floats appear as floats. The fixtures stay inside the
  range where CPython float repr == JS String(n) (no 1e16 / 1e-5 exponent
  switchover; the JS test pins those documented residuals separately).
- json_cases: floats are tagged explicitly so the trailing-".0" int/float
  distinction is exercised through the FloatConstraintMap machinery. Array
  ELEMENTS are never integral floats (the registry cannot mark them; the JS
  test pins that documented residual separately).
"""

from __future__ import annotations

import json
import math
import sys

NAN = float("nan")
INF = float("inf")


def enc(v):
    """Encode a vector input for JSON transport (see module docstring)."""
    if isinstance(v, bool) or v is None or isinstance(v, (int, str)):
        return v
    if isinstance(v, float):
        if math.isnan(v):
            return {"$nonfinite": "nan"}
        if v == INF:
            return {"$nonfinite": "inf"}
        if v == -INF:
            return {"$nonfinite": "-inf"}
        return {"$float": v}
    if isinstance(v, list):
        return [enc(x) for x in v]
    if isinstance(v, dict):
        for k in v:
            assert isinstance(k, str) and not k.startswith("$"), k
        return {k: enc(x) for k, x in v.items()}
    raise TypeError(f"unencodable vector input: {type(v)!r}")


# ---------------------------------------------------------------------------
# pyRepr vectors: expected == repr(value)
# ---------------------------------------------------------------------------

REPR_VALUES = [
    # -- strings: quote selection ------------------------------------------
    ("empty_string", ""),
    ("plain_ascii", "hello"),
    ("inner_spaces", " a b "),
    ("single_quote_switches_to_double", "it's"),
    ("double_quote_keeps_single", 'say "hi"'),
    ("both_quotes_escapes_single", "a'b\"c"),
    ("quote_and_backslash", "it's a \\ \"test\""),
    ("backslash_only", "a\\b"),
    # -- strings: named escapes --------------------------------------------
    ("named_escapes_tab_nl_cr", "a\tb\nc\rd"),
    # -- strings: Cc controls (\xNN form below 0x100) ----------------------
    ("nul_control", "\x00"),
    ("bell_control", "\x07"),
    ("vertical_tab", "\x0b"),
    ("unit_separator", "\x1f"),
    ("del_control_x7f", "\x7f"),
    ("c1_control_x9c", "\x9c"),
    ("nel_u0085", "\x85"),
    # -- strings: separators (Zs/Zl/Zp) vs plain space ---------------------
    ("plain_space_printable", "a b"),
    ("nbsp_u00a0_vs_space", "a\xa0b c"),
    ("ogham_space_u1680", "\u1680"),
    ("line_para_separators", "\u2028\u2029"),
    # -- strings: Cf format / zero-width chars (\uNNNN form) ---------------
    ("zero_width_space_u200b", "x\u200by"),
    ("zero_width_joiner_u200d", "\u200d"),
    ("bom_ufeff", "\ufeff"),
    # -- strings: printable non-ASCII stays literal ------------------------
    ("latin1_printable_kept", "caf\xe9"),
    ("x100_boundary_printables", "\xff\u0100"),
    ("bmp_cjk_printables", "\uff5f\u4e2d"),
    # -- strings: Cn noncharacter ------------------------------------------
    ("noncharacter_uffff", "\uffff"),
    # -- strings: Cs lone surrogate (one \uNNNN escape both sides) ---------
    ("lone_surrogate_ud800", "\ud800"),
    # -- strings: astral plane (code-point iteration, \UNNNNNNNN form) -----
    ("astral_printable_kept", "\U0001f600"),
    ("astral_private_use_co", "\U000f0000"),
    ("astral_format_tag_cf", "\U000e0020"),
    ("astral_mixed_with_controls", "a\U0001f600\x01b"),
    # -- numbers ------------------------------------------------------------
    ("int_zero", 0),
    ("int_positive", 42),
    ("int_negative", -7),
    ("int_max_safe_integer", 9007199254740991),
    ("float_simple", 1.5),
    ("float_negative", -3.25),
    ("float_tenth", 0.1),
    ("float_1e_minus_4_no_exponent", 0.0001),
    ("nan", NAN),
    ("inf", INF),
    ("neg_inf", -INF),
    # -- booleans / None ----------------------------------------------------
    ("true", True),
    ("false", False),
    ("none", None),
    # -- containers ----------------------------------------------------------
    ("empty_list", []),
    ("empty_dict", {}),
    ("flat_list", [1, "a", True, None]),
    ("nested_lists", [[1, 2], [], ["x"]]),
    ("list_with_nonfinite", [NAN, INF, -INF]),
    ("flat_dict_insertion_order", {"k": "v", "n": 1}),
    ("nested_dict", {"outer": {"inner": [1, 2.5]}, "list": [{"a": None}]}),
    ("dict_key_with_quote", {"it's": 1}),
    ("dict_value_with_quotes", {"msg": 'say "hi"'}),
]

# ---------------------------------------------------------------------------
# pyJsonDumps vectors: expected == json.dumps(value, sort_keys=True)
# ---------------------------------------------------------------------------

JSON_VALUES = [
    # -- scalars --------------------------------------------------------------
    ("null", None),
    ("true", True),
    ("false", False),
    ("int_zero", 0),
    ("int_positive", 42),
    ("int_negative", -7),
    # -- int vs float distinction (the FloatConstraintMap contract) ----------
    ("float_root_integral_zero", 0.0),
    ("float_root_integral_hundred", 100.0),
    ("float_root_negative_zero", -0.0),
    ("float_root_simple", 1.5),
    ("float_root_negative", -3.25),
    ("float_root_1e15_integral", 1e15),
    ("float_root_1e_minus_4", 0.0001),
    # -- non-finite (Python allow_nan=True literals) --------------------------
    ("nan_root", NAN),
    ("inf_root", INF),
    ("neg_inf_root", -INF),
    # -- strings: ensure_ascii escaping ---------------------------------------
    ("empty_string", ""),
    ("plain_ascii", "hello"),
    ("short_escapes", 'q"b\\s\nn\rr\tt\bb\ff'),
    ("control_chars", "\x00\x1f\x7f"),
    ("nonascii_bmp_escaped", "caf\xe9 \u2713"),
    ("astral_surrogate_pair", "\U0001f600"),
    ("astral_in_context", "a\U0001f600b"),
    ("lone_surrogate_ud800", "\ud800"),
    # -- containers + separators ----------------------------------------------
    ("empty_list", []),
    ("empty_dict", {}),
    ("flat_list", [1, 2.5, "a", True, None]),
    ("nested_arrays", [[1], [2, [3]]]),
    ("separators_shape", {"a": [1, 2], "b": {"c": 1}}),
    # -- key sorting by code point --------------------------------------------
    ("sort_basic", {"b": 1, "a": 2, "m": 3}),
    ("sort_case_sensitive", {"a": 2, "Z": 1}),
    ("sort_prefix_shorter_first", {"ab": 1, "a": 2}),
    ("sort_empty_key_first", {"a": 2, "": 1}),
    # THE classic UTF-16 vs code-point divergence: U+FF5F (BMP, one unit
    # 0xFF5F) sorts BEFORE U+10000 (astral; leading surrogate unit 0xD800
    # would sort it first under JS default sort).
    ("sort_codepoint_vs_utf16_ff5f_vs_astral", {"\U00010000": 2, "\uff5f": 1}),
    ("sort_uffff_vs_astral", {"\U0001f600": 2, "\uffff": 1}),
    ("sort_astral_prefix", {"\U0001f600a": 1, "\U0001f600": 2}),
    # -- float-marked keys inside objects (registry machinery) ----------------
    ("float_marked_nested", {"count": 3, "limit": 0.5, "threshold": 2.0}),
    ("float_deep_in_subobject", {"outer": {"max": 10.0, "name": "x"}, "n": 1}),
    # -- mixed document --------------------------------------------------------
    (
        "mixed_document",
        {
            "enum": ["a", "b"],
            "maximum": 64.0,
            "minLength": 1,
            "pattern": "^[a-z]+$",
            "nested": {"exclusiveMinimum": 0.0, "items": [1, "x", None]},
        },
    ),
]


def main() -> None:
    doc = {
        "_comment": (
            "Generated by js-sdk/scripts/gen-pyrepr-fixtures.py. Expected "
            "strings are CPython repr(value) / json.dumps(value, "
            "sort_keys=True) output; do not edit by hand. Inputs use the "
            "$float / $nonfinite tags documented in the generator."
        ),
        "python_version": sys.version.split()[0],
        "repr_cases": [
            {"name": name, "input": enc(value), "expected": repr(value)}
            for name, value in REPR_VALUES
        ],
        "json_cases": [
            {
                "name": name,
                "input": enc(value),
                "expected": json.dumps(value, sort_keys=True),
            }
            for name, value in JSON_VALUES
        ],
    }
    json.dump(doc, sys.stdout, indent=2, ensure_ascii=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
