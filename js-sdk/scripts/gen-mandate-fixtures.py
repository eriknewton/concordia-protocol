#!/usr/bin/env python3
"""Generate mandate-MODELS parity fixtures FROM the Concordia Python reference.

Run from the repo root (or anywhere with `concordia` importable). Emits a JSON
document to stdout. The JS test suite (tests/mandate.test.ts) asserts that the
TypeScript mandate-models layer produces:
  - identical enum values (`TemporalMode`, `MandateStatus`),
  - identical `to_dict()` output -- key names, INSERTION ORDER, and
    conditional-omission rules -- for `DelegationLink`, `ValidityWindow`,
    `Mandate`, and `MandateVerificationResult`,
  - identical `from_dict()` round-trips, including the unknown-status fail-safe
    (Python silently defaults an unrecognized status to ACTIVE) and the
    required-field KeyError / unknown-mode ValueError behavior,
  - byte-identical canonical JSON for the static `MANDATE_JSON_SCHEMA` and
    `CONSTRAINT_PATTERNS` constants.

This is the parity source of truth: every expected value here comes straight
from `concordia.models.mandate`, never hand-authored. Synced into the JS test
surface by scripts/sync-fixtures-from-python.mjs.

DELIBERATELY OUT OF SCOPE (deferred to the engine PR, mirroring the JS split):
signing, jsonschema validation, temporal/delegation/revocation verification,
and the full `verify_mandate` from `concordia/mandate.py`. Only the data layer
is exercised here.
"""

from __future__ import annotations

import json
import sys

from concordia.models.mandate import (
    CONSTRAINT_PATTERNS,
    MANDATE_JSON_SCHEMA,
    DelegationLink,
    Mandate,
    MandateStatus,
    MandateVerificationResult,
    TemporalMode,
    ValidityWindow,
)


def _stable_canonical(value) -> str:
    """JCS-equivalent canonical JSON for static, float-free schema dicts.

    Matches concordia.signing.canonical_json (sorted keys, no whitespace, raw
    UTF-8 / ensure_ascii=False) for the schema/constraint constants, which
    contain only strings/ints/bools/None/lists/objects -- no floats -- so the
    plain json.dumps with these flags is byte-identical to _stable_stringify.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _enum_map(enum_cls) -> dict:
    return {member.name: member.value for member in enum_cls}


def main() -> None:
    # ------------------------------------------------------------------
    # Enum value parity.
    # ------------------------------------------------------------------
    enums = {
        "TemporalMode": _enum_map(TemporalMode),
        "MandateStatus": _enum_map(MandateStatus),
    }

    # ------------------------------------------------------------------
    # DelegationLink.to_dict() / from_dict() cases.
    # Covers: minimal (defaults), scope_restriction present, scope_restriction
    # explicitly None (omitted), custom algorithm.
    # ------------------------------------------------------------------
    delegation_to_dict_cases = []

    def _dl_case(name: str, link: DelegationLink) -> None:
        delegation_to_dict_cases.append(
            {"name": name, "to_dict": link.to_dict()}
        )

    _dl_case("minimal_defaults", DelegationLink(delegator="a", delegate="b"))
    _dl_case(
        "with_scope_restriction",
        DelegationLink(
            delegator="did:web:root",
            delegate="did:web:leaf",
            scope_restriction={"max_spend": 100},
            delegated_at="2026-05-14T00:00:00Z",
            signature="c2ln",
            algorithm="EdDSA",
        ),
    )
    _dl_case(
        "explicit_none_scope_omitted",
        DelegationLink(
            delegator="a",
            delegate="b",
            scope_restriction=None,
            delegated_at="2026-05-14T00:00:00Z",
        ),
    )
    _dl_case(
        "es256_algorithm",
        DelegationLink(
            delegator="a",
            delegate="b",
            signature="sig",
            algorithm="ES256",
        ),
    )
    _dl_case(
        "empty_dict_scope_restriction_emitted",
        # scope_restriction={} is NOT None, so Python EMITS it (the guard is
        # `is not None`, not truthiness). Pins that distinction.
        DelegationLink(delegator="a", delegate="b", scope_restriction={}),
    )

    # from_dict round-trips (and required-field behavior).
    delegation_from_dict_cases = [
        {
            "name": "full_roundtrip",
            "input": {
                "delegator": "did:web:root",
                "delegate": "did:web:leaf",
                "delegated_at": "2026-05-14T00:00:00Z",
                "signature": "c2ln",
                "algorithm": "ES256",
                "scope_restriction": {"max_spend": 100},
            },
            "to_dict": DelegationLink.from_dict(
                {
                    "delegator": "did:web:root",
                    "delegate": "did:web:leaf",
                    "delegated_at": "2026-05-14T00:00:00Z",
                    "signature": "c2ln",
                    "algorithm": "ES256",
                    "scope_restriction": {"max_spend": 100},
                }
            ).to_dict(),
        },
        {
            "name": "minimal_applies_defaults",
            "input": {"delegator": "a", "delegate": "b"},
            "to_dict": DelegationLink.from_dict(
                {"delegator": "a", "delegate": "b"}
            ).to_dict(),
        },
    ]

    # Present-null vs absent-default: Python `data.get(key, default)` applies the
    # default ONLY when the key is ABSENT. A key PRESENT with `None` keeps `None`
    # (NOT the default), and `to_dict` then re-emits it verbatim for the three
    # always-emitted link fields (delegated_at/signature/algorithm). The fixture
    # records the Python-produced to_dict so the JS round-trip is byte-checked.
    # Guards against a `?? default` regression that would collapse the null.
    for fld in ("delegated_at", "signature", "algorithm"):
        delegation_from_dict_cases.append(
            {
                "name": f"explicit_null_{fld}_kept",
                "input": {"delegator": "a", "delegate": "b", fld: None},
                "to_dict": DelegationLink.from_dict(
                    {"delegator": "a", "delegate": "b", fld: None}
                ).to_dict(),
            }
        )

    # Missing required field raises KeyError in Python.
    delegation_from_dict_errors = []
    for ename, bad in [
        ("missing_delegator", {"delegate": "b"}),
        ("missing_delegate", {"delegator": "a"}),
    ]:
        try:
            DelegationLink.from_dict(bad)
            err = None
        except KeyError as exc:
            err = str(exc)  # repr-quoted key, e.g. "'delegator'"
        delegation_from_dict_errors.append(
            {"name": ename, "input": bad, "error": err}
        )

    # ------------------------------------------------------------------
    # ValidityWindow.to_dict() / from_dict() cases.
    # ------------------------------------------------------------------
    validity_to_dict_cases = []

    def _vw_case(name: str, vw: ValidityWindow) -> None:
        validity_to_dict_cases.append({"name": name, "to_dict": vw.to_dict()})

    _vw_case("sequence_minimal", ValidityWindow(mode=TemporalMode.SEQUENCE))
    _vw_case(
        "windowed_full",
        ValidityWindow(
            mode=TemporalMode.WINDOWED,
            not_before="2026-05-14T00:00:00Z",
            not_after="2026-06-14T00:00:00Z",
            max_uses=5,
        ),
    )
    _vw_case(
        "sequence_with_key",
        ValidityWindow(
            mode=TemporalMode.SEQUENCE, sequence_key="session-123"
        ),
    )
    _vw_case(
        "state_bound",
        ValidityWindow(
            mode=TemporalMode.STATE_BOUND, state_condition="balance_positive"
        ),
    )
    _vw_case(
        "all_fields",
        ValidityWindow(
            mode=TemporalMode.WINDOWED,
            not_before="2026-05-14T00:00:00Z",
            not_after="2026-06-14T00:00:00Z",
            sequence_key="k",
            state_condition="c",
            max_uses=10,
        ),
    )
    _vw_case(
        "max_uses_zero_emitted",
        # max_uses=0 is NOT None -> EMITTED (guard is `is not None`). Pins that
        # an int 0 is not dropped by a truthiness slip.
        ValidityWindow(mode=TemporalMode.WINDOWED, max_uses=0),
    )

    validity_from_dict_cases = []
    for vname, vin in [
        ("windowed", {"mode": "windowed", "not_before": "2026-05-14T00:00:00Z", "not_after": "2026-06-14T00:00:00Z"}),
        ("sequence", {"mode": "sequence", "sequence_key": "k"}),
        ("state_bound_extra_max_uses", {"mode": "state_bound", "state_condition": "c", "max_uses": 3}),
    ]:
        validity_from_dict_cases.append(
            {
                "name": vname,
                "input": vin,
                "to_dict": ValidityWindow.from_dict(vin).to_dict(),
            }
        )

    validity_from_dict_errors = []
    # Missing mode -> KeyError.
    try:
        ValidityWindow.from_dict({"not_before": "x"})
        merr = None
    except KeyError as exc:
        merr = str(exc)
    validity_from_dict_errors.append(
        {"name": "missing_mode", "input": {"not_before": "x"}, "error": merr}
    )
    # Unknown mode value -> ValueError from TemporalMode(...). The error text is
    # `f"{value!r} is not a valid TemporalMode"`, so it uses Python `repr()` on
    # the offending value. A non-string mode (the value is parsed JSON, so it can
    # be a list / dict / number / bool / null) must repr BYTE-IDENTICALLY: `[]`
    # not JS `String([])` -> `""`, `{}` not `"[object Object]"`. These cases pin
    # the pyRepr port against a `String(value)` regression.
    invalid_mode_values = [
        ("unknown_mode", "bogus"),
        ("invalid_mode_empty_list", []),
        ("invalid_mode_empty_dict", {}),
        ("invalid_mode_list", ["a", "b"]),
        ("invalid_mode_dict", {"k": "v"}),
        ("invalid_mode_int", 123),
        ("invalid_mode_float", 1.5),
        ("invalid_mode_bool_true", True),
        ("invalid_mode_bool_false", False),
        ("invalid_mode_null", None),
        # --- repr() string-QUOTE divergence -------------------------------
        # CPython picks the quote: single by default, but DOUBLE when the string
        # has a `'` and no `"`; if it has BOTH, single quotes with the `'`
        # backslash-escaped. A naive `'${value}'` port produces `'a'b'`
        # (unbalanced) instead of `"a'b"`. These pin the quote-selection rule.
        ("invalid_mode_str_single_quote", "a'b"),       # -> "a'b"
        ("invalid_mode_str_double_quote", 'a"b'),       # -> 'a"b'
        ("invalid_mode_str_both_quotes", "a'b\"c"),     # -> '...' with escaped '
        # --- repr() ESCAPE divergence -------------------------------------
        # \n \r \t and the C0 controls escape inside the repr; a raw-passthrough
        # port would emit a literal newline/tab and diverge byte-for-byte.
        ("invalid_mode_str_newline", "line\nbreak"),
        ("invalid_mode_str_tab", "tab\tx"),
        ("invalid_mode_str_carriage_return", "carriage\rreturn"),
        ("invalid_mode_str_null_byte", "null\x00byte"),
        ("invalid_mode_str_control_chars", "\x00\x01\x1f"),
        ("invalid_mode_str_del_char", "del\x7fhere"),
        ("invalid_mode_str_backslash", "back\\slash"),
        # \x80-\x9f (C1) and U+2028/U+2029 separators are NON-printable ->
        # escaped; nbsp \xa0 likewise. Printable unicode (accent, emoji) stays
        # literal. These pin the Unicode-printability boundary of the port.
        ("invalid_mode_str_c1_control", "c1\x85here"),
        ("invalid_mode_str_line_separator", "ls x"),
        ("invalid_mode_str_nbsp", "nb\xa0sp"),
        ("invalid_mode_str_printable_accent", "caf\xe9"),
        ("invalid_mode_str_printable_emoji", "emoji\U0001f600x"),
        # --- recursive repr with the divergent string cases nested --------
        ("invalid_mode_nested_quote_in_list", ["a'b", 'c"d']),
        (
            "invalid_mode_nested_dict",
            {"k'1": 'v"2', "n": [True, 3, None], "nl": "x\ny"},
        ),
    ]
    for ename, mode_val in invalid_mode_values:
        try:
            ValidityWindow.from_dict({"mode": mode_val})
            verr = None
        except ValueError as exc:
            verr = str(exc)
        validity_from_dict_errors.append(
            {"name": ename, "input": {"mode": mode_val}, "error": verr}
        )

    # --- repr() NON-FINITE FLOAT divergence -------------------------------
    # NaN / Infinity / -Infinity cannot survive a STANDARD-JSON round-trip into
    # the JS test (Python json.dump emits the non-standard `NaN`/`Infinity`
    # literals, which JS JSON.parse rejects), yet they CAN reach pyRepr as an
    # in-memory JS value. CPython reprs them as `nan` / `inf` / `-inf` (NOT JS
    # `String(NaN)` -> `"NaN"`). To keep the fixture parseable by the JS test
    # while still asserting Python-produced error text, the `mode` value is
    # recorded as a SENTINEL the test materializes into the real JS float before
    # calling validityWindowFromDict. The `error` string is straight from
    # Python's str(ValueError), so parity is still Python-sourced.
    special_float_cases = [
        ("invalid_mode_float_nan", float("nan"), "nan"),
        ("invalid_mode_float_inf", float("inf"), "inf"),
        ("invalid_mode_float_neg_inf", float("-inf"), "-inf"),
    ]
    for ename, mode_val, sentinel in special_float_cases:
        try:
            ValidityWindow.from_dict({"mode": mode_val})
            verr = None
        except ValueError as exc:
            verr = str(exc)
        validity_from_dict_errors.append(
            {
                "name": ename,
                # __special_float__ sentinel: the JS test rebuilds NaN/+Inf/-Inf
                # from this tag (a raw NaN in the JSON file would break
                # JSON.parse). The error text below is Python-produced.
                "input": {"mode": {"__special_float__": sentinel}},
                "error": verr,
            }
        )

    # ------------------------------------------------------------------
    # Mandate.to_dict() cases -- the load-bearing surface. Exercises every
    # conditional-omission branch and the truthiness-vs-not-None distinction.
    # ------------------------------------------------------------------
    mandate_to_dict_cases = []

    def _m_case(name: str, mandate: Mandate) -> None:
        mandate_to_dict_cases.append({"name": name, "to_dict": mandate.to_dict()})

    # Bare defaults: only the six always-present keys (validity None,
    # constraints/{} and metadata/{} empty -> omitted, signature "" -> omitted).
    _m_case("bare_defaults", Mandate())

    _m_case(
        "full_no_signature",
        Mandate(
            mandate_id="urn:concordia:mandate:m1",
            issuer="did:web:issuer",
            subject="did:web:subject",
            issued_at="2026-05-14T00:00:00Z",
            validity=ValidityWindow(
                mode=TemporalMode.WINDOWED,
                not_before="2026-05-14T00:00:00Z",
                not_after="2026-06-14T00:00:00Z",
            ),
            constraints={"max_spend": {"amount": 100, "currency": "USD"}},
            delegation_chain=[
                DelegationLink(
                    delegator="did:web:issuer",
                    delegate="did:web:subject",
                    delegated_at="2026-05-14T00:00:00Z",
                    signature="sig",
                )
            ],
            revocation_endpoint="https://issuer.example/revoke",
            revoked_at="2026-05-20T00:00:00Z",
            metadata={"note": "test"},
        ),
    )

    _m_case(
        "with_signature",
        Mandate(
            mandate_id="urn:concordia:mandate:m2",
            issuer="i",
            subject="s",
            issued_at="2026-05-14T00:00:00Z",
            constraints={"k": "v"},
            signature="c2ln",
        ),
    )

    _m_case(
        "empty_collections_omitted",
        # constraints={}, delegation_chain=[], metadata={} all OMITTED via the
        # truthiness guard; revocation_endpoint/revoked_at None -> omitted.
        Mandate(
            mandate_id="urn:concordia:mandate:m3",
            issuer="i",
            subject="s",
            issued_at="2026-05-14T00:00:00Z",
            constraints={},
            delegation_chain=[],
            metadata={},
        ),
    )

    _m_case(
        "empty_string_endpoint_emitted",
        # revocation_endpoint="" is NOT None -> EMITTED (guard `is not None`).
        # revoked_at="" likewise EMITTED. Pins the not-None vs truthiness split:
        # these empty STRINGS survive where empty COLLECTIONS would be dropped.
        Mandate(
            mandate_id="urn:concordia:mandate:m4",
            issuer="i",
            subject="s",
            issued_at="2026-05-14T00:00:00Z",
            constraints={"k": "v"},
            revocation_endpoint="",
            revoked_at="",
        ),
    )

    _m_case(
        "status_revoked",
        Mandate(
            mandate_id="urn:concordia:mandate:m5",
            issuer="i",
            subject="s",
            issued_at="2026-05-14T00:00:00Z",
            constraints={"k": "v"},
            status=MandateStatus.REVOKED,
            algorithm="ES256",
        ),
    )

    _m_case(
        "multi_link_chain",
        Mandate(
            mandate_id="urn:concordia:mandate:m6",
            issuer="root",
            subject="leaf",
            issued_at="2026-05-14T00:00:00Z",
            constraints={"k": "v"},
            delegation_chain=[
                DelegationLink(
                    delegator="root",
                    delegate="mid",
                    delegated_at="2026-05-14T00:00:00Z",
                    signature="s1",
                    scope_restriction={"max_spend": 500},
                ),
                DelegationLink(
                    delegator="mid",
                    delegate="leaf",
                    delegated_at="2026-05-14T01:00:00Z",
                    signature="s2",
                ),
            ],
        ),
    )

    _m_case(
        "unicode_fields",
        Mandate(
            mandate_id="urn:concordia:mandate:m7",
            issuer="did:web:café",
            subject="did:web:sübject",
            issued_at="2026-05-14T00:00:00Z",
            constraints={"note": "héllo ✓"},
        ),
    )

    # ------------------------------------------------------------------
    # Mandate.from_dict() cases, including the unknown-status FAIL-SAFE and
    # round-trips through to_dict.
    # ------------------------------------------------------------------
    mandate_from_dict_cases = []

    def _mfd(name: str, data: dict) -> None:
        mandate_from_dict_cases.append(
            {
                "name": name,
                "input": data,
                "to_dict": Mandate.from_dict(data).to_dict(),
            }
        )

    _mfd(
        "full_roundtrip",
        {
            "mandate_id": "urn:concordia:mandate:m1",
            "issuer": "i",
            "subject": "s",
            "issued_at": "2026-05-14T00:00:00Z",
            "algorithm": "EdDSA",
            "status": "active",
            "validity": {"mode": "windowed", "not_before": "2026-05-14T00:00:00Z", "not_after": "2026-06-14T00:00:00Z"},
            "constraints": {"k": "v"},
            "delegation_chain": [
                {"delegator": "i", "delegate": "s", "delegated_at": "2026-05-14T00:00:00Z", "signature": "sig", "algorithm": "EdDSA"}
            ],
            "revocation_endpoint": "https://x/revoke",
            "revoked_at": "2026-05-20T00:00:00Z",
            "metadata": {"note": "n"},
            "signature": "c2ln",
        },
    )
    _mfd(
        "empty_dict_applies_all_defaults",
        {},
    )
    _mfd(
        "unknown_status_defaults_active",
        # Python: `try MandateStatus("bogus") except ValueError -> ACTIVE`.
        # The serialized status must come back "active", NOT "bogus".
        {
            "mandate_id": "urn:concordia:mandate:m8",
            "issuer": "i",
            "subject": "s",
            "issued_at": "2026-05-14T00:00:00Z",
            "constraints": {"k": "v"},
            "status": "bogus",
        },
    )
    _mfd(
        "missing_status_defaults_active",
        {
            "mandate_id": "urn:concordia:mandate:m9",
            "issuer": "i",
            "subject": "s",
            "issued_at": "2026-05-14T00:00:00Z",
            "constraints": {"k": "v"},
        },
    )

    # Present-null vs absent-default. Python `data.get(key, default)` keeps a
    # key-PRESENT `None` (it does NOT fall back to the default). For the five
    # always-emitted scalar keys (mandate_id/issuer/subject/issued_at/algorithm)
    # a present-null SURVIVES into to_dict as `null`; for the truthiness-guarded
    # keys (constraints/metadata/signature) a present-null is kept as None then
    # OMITTED by `if x:`. Each case records the Python to_dict so the JS
    # round-trip is byte-checked -- catching any `?? default` regression.
    for fld in (
        "mandate_id",
        "issuer",
        "subject",
        "issued_at",
        "algorithm",
        "signature",
        "constraints",
        "metadata",
    ):
        _mfd(f"explicit_null_{fld}", {fld: None})

    # Full explicit-null dict: every field present with `null`. Always-emitted
    # keys come back `null`; status fails the enum lookup and falls SAFE to
    # ACTIVE ("active"); truthiness-guarded keys are dropped. Pins the entire
    # null-handling contract in one round-trip.
    _mfd(
        "all_fields_explicit_null",
        {
            "mandate_id": None,
            "issuer": None,
            "subject": None,
            "issued_at": None,
            "algorithm": None,
            "status": None,
            "constraints": None,
            "metadata": None,
            "signature": None,
            "revocation_endpoint": None,
            "revoked_at": None,
        },
    )

    # ------------------------------------------------------------------
    # MandateVerificationResult.to_dict() cases. Pure data carrier (the engine
    # that populates it is deferred); exercise the optional-field omission and
    # the embedded mandate.to_dict().
    # ------------------------------------------------------------------
    result_to_dict_cases = []

    def _r_case(name: str, result: MandateVerificationResult) -> None:
        result_to_dict_cases.append({"name": name, "to_dict": result.to_dict()})

    _r_case(
        "minimal_invalid",
        MandateVerificationResult(valid=False),
    )
    _r_case(
        "valid_with_checks",
        MandateVerificationResult(
            valid=True,
            mandate_id="urn:concordia:mandate:m1",
            issuer="i",
            subject="s",
            checks={"schema": True, "issuer_signature": True},
            warnings=["no revocation endpoint"],
        ),
    )
    _r_case(
        "resolver_fields",
        MandateVerificationResult(
            valid=False,
            mandate_id="urn:concordia:mandate:m1",
            issuer="i",
            subject="s",
            checks={"schema": True},
            errors=["revoked"],
            failure_reason="mandate_revoked",
            revoked_at="2026-05-20T00:00:00Z",
            tier="did-vc",
            mandate=Mandate(
                mandate_id="urn:concordia:mandate:m1",
                issuer="i",
                subject="s",
                issued_at="2026-05-14T00:00:00Z",
                constraints={"k": "v"},
                status=MandateStatus.REVOKED,
            ),
        ),
    )
    _r_case(
        "empty_string_failure_reason_emitted",
        # failure_reason="" is NOT None -> EMITTED. revoked_at="" / tier=""
        # likewise. Pins not-None semantics on the optional result fields.
        MandateVerificationResult(
            valid=False,
            failure_reason="",
            revoked_at="",
            tier="",
        ),
    )

    # ------------------------------------------------------------------
    # Static constants -- byte-identical canonical JSON.
    # ------------------------------------------------------------------
    schema_constants = {
        "MANDATE_JSON_SCHEMA": {
            "value": MANDATE_JSON_SCHEMA,
            "canonical": _stable_canonical(MANDATE_JSON_SCHEMA),
        },
        "CONSTRAINT_PATTERNS": {
            "value": CONSTRAINT_PATTERNS,
            "canonical": _stable_canonical(CONSTRAINT_PATTERNS),
        },
    }

    doc = {
        "_comment": (
            "Generated by js-sdk/scripts/gen-mandate-fixtures.py from "
            "concordia.models.mandate. All to_dict/from_dict outputs, error "
            "strings, enum values, and canonical schema bytes are "
            "Python-produced; do not edit by hand. Mandate signing/verification "
            "(concordia/mandate.py) is DEFERRED to the engine PR and is not "
            "exercised here."
        ),
        "enums": enums,
        "delegation_to_dict_cases": delegation_to_dict_cases,
        "delegation_from_dict_cases": delegation_from_dict_cases,
        "delegation_from_dict_errors": delegation_from_dict_errors,
        "validity_to_dict_cases": validity_to_dict_cases,
        "validity_from_dict_cases": validity_from_dict_cases,
        "validity_from_dict_errors": validity_from_dict_errors,
        "mandate_to_dict_cases": mandate_to_dict_cases,
        "mandate_from_dict_cases": mandate_from_dict_cases,
        "result_to_dict_cases": result_to_dict_cases,
        "schema_constants": schema_constants,
    }

    json.dump(doc, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
