#!/usr/bin/env python3
"""Generate schema-validator + approval-receipt parity fixtures FROM Python.

Run from the repo root (or anywhere with `concordia` importable). Emits a JSON
document to stdout. The JS test suite (tests/schema-validator.test.ts) asserts
that the TypeScript validators produce byte-identical error lists and that the
ApprovalReceipt verifier produces byte-identical typed results.

This is the parity source of truth: every expected error string and verification
result comes straight from `concordia.schema_validator` /
`concordia.approval_receipt`, never hand-authored. Synced into the JS test
surface by scripts/sync-fixtures-from-python.mjs.

The generator imports jsonschema + cryptography (the reference's own deps); run
it under python3.12 (the jsonschema version whose message templates the JS port
reproduces).
"""

from __future__ import annotations

import copy
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia import signing
from concordia.approval_receipt import verify_approval_receipt
from concordia.schema_validator import (
    validate_approval_receipt,
    validate_attestation,
    validate_fulfillment_attestation,
    validate_message,
)


# Deterministic Ed25519 key for the signed-receipt cases.
SEED = bytes(range(32))
OTHER_SEED = bytes(range(100, 132))


def _kp_from_seed(seed: bytes) -> signing.KeyPair:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return signing.KeyPair(private_key=sk, public_key=sk.public_key())


def _clone(obj):
    return copy.deepcopy(obj)


# ---------------------------------------------------------------------------
# Message envelope cases
# ---------------------------------------------------------------------------

VALID_MESSAGE = {
    "concordia": "0.5.0",
    "type": "negotiate.offer",
    "id": "m1",
    "session_id": "s1",
    "timestamp": "2026-05-10T14:22:08Z",
    "from": {"agent_id": "agent-a"},
    "body": {},
    "signature": "sig",
}


def _message_cases() -> list[dict]:
    cases: list[dict] = []

    def add(name, mutate):
        msg = _clone(VALID_MESSAGE)
        mutate(msg)
        cases.append(
            {"name": name, "message": msg, "expected": validate_message(msg)}
        )

    add("valid", lambda m: None)
    add("valid_with_optionals", lambda m: m.update(
        {"to": [{"agent_id": "b"}], "prev_hash": "ph", "in_reply_to": "r",
         "thread": "t", "ttl": 30, "reasoning": "because",
         "from": {"agent_id": "a", "principal_id": "p"}}))
    add("bad_enum_type", lambda m: m.__setitem__("type", "negotiate.foo"))
    add("bad_pattern_concordia", lambda m: m.__setitem__("concordia", "bad"))
    add("missing_id", lambda m: m.pop("id"))
    add("missing_multiple", lambda m: (m.pop("id"), m.pop("signature")))
    add("nested_required", lambda m: m.__setitem__("from", {}))
    add("array_path_required", lambda m: m.__setitem__(
        "to", [{"agent_id": "b"}, {}]))
    add("union_type_principal", lambda m: m.__setitem__(
        "from", {"agent_id": "a", "principal_id": 5}))
    add("min_length_id", lambda m: m.__setitem__("id", ""))
    add("ttl_minimum", lambda m: m.__setitem__("ttl", -1))
    add("ttl_not_integer", lambda m: m.__setitem__("ttl", 1.5))
    add("timestamp_bad_format", lambda m: m.__setitem__("timestamp", "nope"))
    add("timestamp_naive_no_tz", lambda m: m.__setitem__(
        "timestamp", "2026-05-10T14:22:08"))
    add("timestamp_nonstring", lambda m: m.__setitem__("timestamp", 12345))
    add("type_not_string", lambda m: m.__setitem__("type", 5))
    add("body_not_object", lambda m: m.__setitem__("body", "x"))
    add("from_not_object", lambda m: m.__setitem__("from", "x"))
    add("to_not_array", lambda m: m.__setitem__("to", "x"))
    add("multi_path_errors", lambda m: (
        m.__setitem__("concordia", "bad"),
        m.__setitem__("type", "negotiate.foo"),
        m.__setitem__("ttl", -1)))
    add("empty_object", lambda m: m.clear())
    return cases


# ---------------------------------------------------------------------------
# ApprovalReceipt schema cases
# ---------------------------------------------------------------------------

VALID_RECEIPT = {
    "artifact_type": "ApprovalReceipt",
    "id": "urn:concordia:receipt:7f2e1a93",
    "issued_at": "2026-05-10T14:22:08Z",
    "expires_at": "2026-05-10T15:22:08Z",
    "approver": {
        "identity": "did:web:acme.example#procurement-lead",
        "role": "procurement_authority",
    },
    "scope": {
        "decision": "approve",
        "offer_hash": "sha256:" + "a" * 64,
        "amount": "150000.00 USD",
        "threshold_crossed": "100000.00 USD",
    },
    "references": [
        {
            "type": "negotiation_session",
            "id": "a2cn:session:9e4d2c11",
            "relationship": "approves",
        }
    ],
    "signature": {"alg": "Ed25519", "value": "abc"},
}


def _receipt_schema_cases() -> list[dict]:
    cases: list[dict] = []

    def add(name, mutate):
        r = _clone(VALID_RECEIPT)
        mutate(r)
        cases.append(
            {"name": name, "receipt": r, "expected": validate_approval_receipt(r)}
        )

    add("valid", lambda r: None)
    add("bad_const_artifact_type",
        lambda r: r.__setitem__("artifact_type", "WrongType"))
    add("bad_enum_decision",
        lambda r: r["scope"].__setitem__("decision", "maybe"))
    add("bad_pattern_offer_hash",
        lambda r: r["scope"].__setitem__("offer_hash", "notahash"))
    add("offer_hash_wrong_len",
        lambda r: r["scope"].__setitem__("offer_hash", "sha256:abc"))
    add("missing_signature", lambda r: r.pop("signature"))
    add("missing_multiple_top",
        lambda r: (r.pop("id"), r.pop("approver")))
    add("bad_format_issued_at",
        lambda r: r.__setitem__("issued_at", "not-a-date"))
    add("issued_at_nonstring",
        lambda r: r.__setitem__("issued_at", 12345))
    add("contains_missing_approves",
        lambda r: r.__setitem__("references",
                                [{"type": "mandate", "id": "x",
                                  "relationship": "fulfills"}]))
    add("references_empty", lambda r: r.__setitem__("references", []))
    add("references_not_array", lambda r: r.__setitem__("references", "x"))
    add("scope_not_object", lambda r: r.__setitem__("scope", "x"))
    add("scope_missing_required",
        lambda r: r.__setitem__("scope", {"decision": "approve"}))
    add("approver_missing_identity",
        lambda r: r.__setitem__("approver", {"role": "x"}))
    add("signature_bad_alg",
        lambda r: r["signature"].__setitem__("alg", "RS256"))
    add("signature_missing_value",
        lambda r: r["signature"].pop("value"))
    add("identity_empty",
        lambda r: r["approver"].__setitem__("identity", ""))
    add("ref_item_missing_id",
        lambda r: r.__setitem__("references",
                                [{"type": "negotiation_session",
                                  "relationship": "approves"}]))
    add("additional_props_allowed",
        lambda r: r.__setitem__("extra_field", "ok"))
    add("scope_additional_allowed",
        lambda r: r["scope"].__setitem__("extra", 1))
    add("empty_object", lambda r: r.clear())
    add("deny_decision",
        lambda r: r["scope"].__setitem__("decision", "deny"))
    return cases


# ---------------------------------------------------------------------------
# FulfillmentAttestation schema + companion-invariant cases
# ---------------------------------------------------------------------------

VALID_FULFILLMENT = {
    "attestation_type": "FulfillmentAttestation",
    "id": "urn:concordia:fulfillment:0001",
    "issued_at": "2026-05-10T14:22:08Z",
    "agreement_attestation_id": "att-123",
    "fulfillment": {"status": "fulfilled_clean"},
    "references": [
        {"id": "att-123", "type": "attestation", "relationship": "fulfills"}
    ],
    "signature": {"alg": "Ed25519", "value": "v"},
}


def _fulfillment_cases() -> list[dict]:
    cases: list[dict] = []

    def add(name, mutate):
        f = _clone(VALID_FULFILLMENT)
        mutate(f)
        cases.append(
            {"name": name, "attestation": f,
             "expected": validate_fulfillment_attestation(f)}
        )

    add("valid", lambda f: None)
    add("bad_const_type",
        lambda f: f.__setitem__("attestation_type", "Wrong"))
    add("bad_status_enum",
        lambda f: f["fulfillment"].__setitem__("status", "nope"))
    add("missing_required",
        lambda f: f.pop("signature"))
    add("references_empty", lambda f: f.__setitem__("references", []))
    add("contains_no_fulfills",
        lambda f: f.__setitem__("references",
                                [{"id": "x", "type": "attestation",
                                  "relationship": "relates"}]))
    add("equality_invariant_violated",
        lambda f: f["references"][0].__setitem__("id", "different"))
    add("equality_invariant_ok_multi",
        lambda f: f.__setitem__("references",
                                [{"id": "other", "type": "receipt",
                                  "relationship": "supersedes"},
                                 {"id": "att-123", "type": "attestation",
                                  "relationship": "fulfills"}]))
    add("mediation_then_requires_meta",
        lambda f: f["fulfillment"].__setitem__(
            "status", "fulfilled_with_mediation"))
    add("mediation_with_meta_ok",
        lambda f: (f["fulfillment"].__setitem__(
            "status", "fulfilled_with_mediation"),
            f.__setitem__("meta", {"mediator_invoked": True})))
    add("mediation_meta_wrong_const",
        lambda f: (f["fulfillment"].__setitem__(
            "status", "fulfilled_with_mediation"),
            f.__setitem__("meta", {"mediator_invoked": False})))
    add("agreement_id_nonstring_skips_invariant",
        lambda f: f.__setitem__("agreement_attestation_id", 5))
    add("empty_object", lambda f: f.clear())
    return cases


# ---------------------------------------------------------------------------
# ApprovalReceipt VERIFICATION cases (the 7c consumer)
# ---------------------------------------------------------------------------

# A fixed "now" the JS side injects so the expiry check is deterministic.
FIXED_NOW_ISO = "2026-05-10T14:30:00+00:00"


def _signed_receipt(kp, offer, *, decision="approve", expires="2026-05-10T15:22:08Z"):
    """Build a receipt whose offer_hash matches `offer` and sign it with `kp`."""
    import hashlib
    offer_hash = "sha256:" + hashlib.sha256(
        signing.canonical_json(offer)
    ).hexdigest()
    receipt = {
        "artifact_type": "ApprovalReceipt",
        "id": "urn:concordia:receipt:abc",
        "issued_at": "2026-05-10T14:22:08Z",
        "expires_at": expires,
        "approver": {"identity": "did:web:acme.example#lead"},
        "scope": {
            "decision": decision,
            "offer_hash": offer_hash,
            "amount": "100 USD",
            "threshold_crossed": "50 USD",
        },
        "references": [
            {"type": "negotiation_session", "id": "sess-1",
             "relationship": "approves"}
        ],
        "signature": {"alg": "Ed25519", "value": ""},
    }
    sig = signing.sign_message(receipt, kp)
    receipt["signature"]["value"] = sig
    return receipt


def _verify_cases() -> list[dict]:
    from datetime import datetime

    kp = _kp_from_seed(SEED)
    other_kp = _kp_from_seed(OTHER_SEED)
    now = datetime.fromisoformat(FIXED_NOW_ISO)
    cases: list[dict] = []

    OFFER = {"price": 100, "qty": 5, "item": "widget"}

    def add(name, receipt, offer, *, pubkey_b64=None, now_override=None):
        nowval = now_override if now_override is not None else now
        result = verify_approval_receipt(
            receipt, offer, now=nowval,
            issuer_public_key=(_kp_from_seed(SEED).public_key
                               if pubkey_b64 == "self"
                               else (other_kp.public_key
                                     if pubkey_b64 == "other" else None)),
        )
        cases.append({
            "name": name,
            "receipt": receipt,
            "offer": offer,
            "now": FIXED_NOW_ISO,
            "issuer_public_key_b64": (
                kp.public_key_b64() if pubkey_b64 == "self"
                else other_kp.public_key_b64() if pubkey_b64 == "other"
                else None),
            "expected": result.to_dict(),
        })

    # 1. Fully valid (correct key, in-window, matching offer hash).
    valid_receipt = _signed_receipt(kp, OFFER)
    add("valid_approve", valid_receipt, OFFER, pubkey_b64="self")

    # 2. Valid deny decision.
    deny_receipt = _signed_receipt(kp, OFFER, decision="deny")
    add("valid_deny", deny_receipt, OFFER, pubkey_b64="self")

    # 3. No issuer key -> signature_invalid.
    add("no_issuer_key", _signed_receipt(kp, OFFER), OFFER, pubkey_b64=None)

    # 4. Wrong key -> signature_invalid.
    add("wrong_key", _signed_receipt(kp, OFFER), OFFER, pubkey_b64="other")

    # 5. Tampered receipt (signature no longer valid).
    tampered = _signed_receipt(kp, OFFER)
    tampered["scope"]["amount"] = "999 USD"
    add("tampered_signature", tampered, OFFER, pubkey_b64="self")

    # 6. Expired (expires before now).
    expired = _signed_receipt(kp, OFFER, expires="2026-05-10T14:00:00Z")
    add("expired", expired, OFFER, pubkey_b64="self")

    # 7. Offer hash mismatch (verify against a DIFFERENT offer).
    add("offer_hash_mismatch", _signed_receipt(kp, OFFER),
        {"price": 999, "qty": 1}, pubkey_b64="self")

    # 8. Schema-invalid receipt WITH an approves ref -> schema_invalid.
    schema_bad = _signed_receipt(kp, OFFER)
    schema_bad["scope"]["offer_hash"] = "not-a-hash"  # breaks pattern (re-sign? no: keep)
    # Re-sign so the signature is valid but schema still fails on pattern.
    schema_bad["signature"]["value"] = ""
    schema_bad["signature"]["value"] = signing.sign_message(schema_bad, kp)
    add("schema_invalid_with_approves", schema_bad, OFFER, pubkey_b64="self")

    # 9. Schema-invalid receipt WITHOUT an approves ref ->
    #    missing_approves_reference.
    no_approves = _signed_receipt(kp, OFFER)
    no_approves["references"] = [
        {"type": "mandate", "id": "m", "relationship": "fulfills"}
    ]
    no_approves["scope"]["offer_hash"] = "bad"  # also schema-invalid
    no_approves["signature"]["value"] = ""
    no_approves["signature"]["value"] = signing.sign_message(no_approves, kp)
    add("schema_invalid_missing_approves", no_approves, OFFER, pubkey_b64="self")

    # 10. Schema-valid but missing approves (valid schema, no approves link).
    #     Build a receipt whose references pass schema (has type+relationship)
    #     but none is an `approves` negotiation_session.
    valid_no_approves = _signed_receipt(kp, OFFER)
    valid_no_approves["references"] = [
        {"type": "mandate", "id": "m", "relationship": "fulfills"}
    ]
    valid_no_approves["signature"]["value"] = ""
    valid_no_approves["signature"]["value"] = signing.sign_message(
        valid_no_approves, kp)
    add("schema_valid_missing_approves", valid_no_approves, OFFER,
        pubkey_b64="self")

    # 11. Signature alg not Ed25519 -> signature_invalid (schema enum allows only
    #     Ed25519, so this is caught at schema; build to hit the post-schema
    #     branch we need a schema-valid receipt with alg Ed25519 but we want the
    #     alg-check path). Skip: schema enforces Ed25519, so the explicit
    #     alg-check branch is only reachable when schema passes AND alg differs,
    #     which the schema forbids. Documented, not generated.

    # 12. SUB-MINUTE-OFFSET expiry that must NOT be falsely expired. CPython's
    #     fromisoformat parses `+00:00:30`; `Date.parse` returns NaN on it, which
    #     made the old TS verifier compute `NaN >= now` -> false -> WRONGLY
    #     `expired`. `expires_at` here is 15:22:08+00:00:30 == 15:22:08-00:00:30
    #     wait -- the offset SUBTRACTS to reach UTC: 15:22:08 minus 30s == 15:21:38
    #     UTC, still well after now (14:30 UTC), so a correct parser reports
    #     not_expired=true. This is the exact false-expired regression the fix
    #     closes; the expected dict is Python-produced (Python parses it right).
    submin = _signed_receipt(kp, OFFER, expires="2026-05-10T15:22:08+00:00:30")
    add("subminute_offset_not_expired", submin, OFFER, pubkey_b64="self")

    # 13. Comma-fractional + no-colon-offset expiry (alternate spelling Python
    #     emits but `Date.parse` mishandles). Far future -> not expired.
    altspell = _signed_receipt(
        kp, OFFER, expires="2026-05-10T15:22:08,250000+0000")
    add("comma_fraction_offset_not_expired", altspell, OFFER, pubkey_b64="self")

    return cases


# ---------------------------------------------------------------------------
# date-time FORMAT-CHECK + EXPIRY-PARSE parity (the two codex date-time gaps)
# ---------------------------------------------------------------------------
#
# These pin CPython-3.12 `fromisoformat` parity for the `date-time` format check
# (_is_date_time) and the expiry parse (_parse_datetime -> epoch ms) on the
# alternate-spelling forms the TS layer previously rejected/mis-parsed. Expecteds
# come straight from Python (datetime.fromisoformat over the same Z-replace), never
# hand-authored.

def _py_format_ok(value: str) -> bool:
    """Mirror concordia.schema_validator._is_date_time for a string input."""
    from datetime import datetime
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _py_epoch_ms(value: str):
    """Mirror concordia.approval_receipt._parse_datetime -> epoch ms (floored), or None.

    Catches BOTH ValueError (malformed) AND OverflowError. A year-9999 (or
    year-0001) civil time with a tz offset parses through `fromisoformat`, but
    `.astimezone(timezone.utc)` raises OverflowError when the UTC instant leaves
    [datetime.min, datetime.max]. The reference verifier does NOT catch that, so
    such a receipt is not honored; here we surface it as None (a parse failure)
    so the TS parser's fail-closed `null` matches Python's reject.
    """
    from datetime import datetime, timezone
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        parsed = parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None
    delta = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
    total_us = (
        delta.days * 86_400_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )
    return total_us // 1000  # floor to whole ms (verifier compares at ms)


def _datetime_format_cases() -> list[dict]:
    # (name, value) -- every alternate-spelling form, plus naive/garbage rejects.
    forms = [
        ("z_suffix", "2026-05-10T14:22:08Z"),
        ("offset_colon", "2026-05-10T14:22:08+00:00"),
        ("offset_no_colon", "2026-05-10T14:22:08+0000"),
        ("offset_hour_only", "2026-05-10T14:22:08+00"),
        ("comma_fraction", "2026-05-10T14:22:08,5+00:00"),
        ("dot_fraction", "2026-05-10T14:22:08.5+00:00"),
        ("basic_form", "20260510T142208Z"),
        ("basic_offset_no_colon", "20260510T142208+0000"),
        ("basic_offset_hour_only", "20260510T142208+00"),
        ("subminute_offset", "2026-05-10T14:22:08+00:00:30"),
        ("subminute_offset_neg", "2026-05-10T14:22:08-00:00:30"),
        ("space_separator", "2026-05-10 14:22:08+00:00"),
        ("frac_truncate_over_6", "2026-05-10T14:22:08.123456789Z"),
        ("hh_mm_only_z", "2026-05-10T14:22Z"),
        ("week_date_offset", "2026-W19-5T14:22:08+00:00"),
        ("basic_week_date", "2026W195T142208+0000"),
        ("large_offset_14h", "2026-05-10T14:22:08+14:00"),
        ("offset_24h_rejected", "2026-05-10T14:22:08+24:00"),
        ("hour_24_rejected", "2026-05-10T24:00:00+00:00"),
        ("bad_month_rejected", "2026-13-10T00:00:00Z"),
        ("non_leap_feb29_rejected", "2026-02-29T00:00:00Z"),
        ("leap_feb29_ok", "2024-02-29T00:00:00Z"),
        ("naive_no_offset_rejected", "2026-05-10T14:22:08"),
        ("date_only_rejected", "2026-05-10"),
        ("garbage_rejected", "nope"),
        ("zero_offset_comma_fraction", "2026-05-10T14:22:08+00,99"),
        # Year-9999 overflow (finding #3): `fromisoformat` succeeds, so the FORMAT
        # check returns True for these (the OverflowError is only raised later by
        # `astimezone` in the expiry parse). Pin that the format check stays True
        # so TS's `isCpythonIsoDateTime` is not over-strict on the format axis.
        ("year9999_neg_offset_format_ok", "9999-12-31T23:59:59-14:00"),
        ("year0001_pos_offset_format_ok", "0001-01-01T00:00:00+23:59"),
    ]
    return [
        {"name": n, "value": v, "expected": _py_format_ok(v)} for n, v in forms
    ]


def _datetime_parse_cases() -> list[dict]:
    # (name, value) -- expiry-parse epoch ms straight from Python. Includes the
    # forms `Date.parse` returned NaN on (the false-expired regression source).
    forms = [
        ("z_suffix", "2026-05-10T14:22:08Z"),
        ("offset_colon", "2026-05-10T14:22:08+00:00"),
        ("offset_no_colon", "2026-05-10T14:22:08+0000"),
        ("offset_hour_only", "2026-05-10T14:22:08+00"),
        ("comma_fraction", "2026-05-10T14:22:08,5+00:00"),
        ("dot_fraction", "2026-05-10T14:22:08.5+00:00"),
        ("basic_form", "20260510T142208Z"),
        ("subminute_offset", "2026-05-10T14:22:08+00:00:30"),
        ("subminute_offset_neg", "2026-05-10T14:22:08-00:00:30"),
        ("zero_offset_comma_fraction", "2026-05-10T14:22:08+00,99"),
        ("zero_offset_dot_fraction_neg", "2026-05-10T14:22:08-00:00.30"),
        ("nonzero_offset_fraction", "2026-05-10T14:22:08+01:02:03.5"),
        ("naive_utc", "2026-05-10T14:22:08"),
        ("frac_truncate_over_6", "2026-05-10T14:22:08.123456789Z"),
        ("garbage_null", "nope"),
        # Year-9999 overflow (finding #3, THE FIX). `fromisoformat` parses these,
        # but `_parse_datetime`'s `astimezone(timezone.utc)` raises OverflowError
        # when the offset pushes the UTC instant past datetime.max / before
        # datetime.min -> the receipt is NOT honored. `_py_epoch_ms` returns None;
        # the TS parser's fail-closed guard returns null. Reject, not clamp.
        ("year9999_neg_offset_overflow_null", "9999-12-31T23:59:59-14:00"),
        ("year9999_extreme_neg_offset_null", "9999-12-31T23:59:59-23:59"),
        ("year0001_pos_offset_underflow_null", "0001-01-01T00:00:00+23:59"),
        # Boundary: still in range either side of the datetime.max tipping point.
        ("year9999_offset0_in_range", "9999-12-31T23:59:59+00:00"),
        ("year9999_neg1min_just_overflow_null", "9999-12-31T23:59:00-00:01"),
        ("year9999_neg1min_just_in_range", "9999-12-31T23:58:59-00:01"),
    ]
    return [
        {"name": n, "value": v, "expected": _py_epoch_ms(v)} for n, v in forms
    ]


# ---------------------------------------------------------------------------
# DEFERRED boundary: validate_attestation (uses $ref / $defs / oneOf)
# ---------------------------------------------------------------------------

VALID_ATTESTATION = {
    "concordia_attestation": "0.1.0",
    "attestation_id": "att_1",
    "session_id": "s1",
    "timestamp": "2026-05-10T14:22:08Z",
    "outcome": {
        "status": "agreed",
        "rounds": 1,
        "duration_seconds": 1.0,
        "resolution_mechanism": "direct",
    },
    "parties": [
        {
            "agent_id": "a",
            "role": "buyer",
            "behavior": {},
            "signature": "",
        }
    ],
    "meta": {"extensions_used": [], "mediator_invoked": False},
    "transcript_hash": "sha256:" + "a" * 64,
}


def _deferred_attestation_case() -> dict:
    """Capture Python's validate_attestation output for the DEFERRED surface.

    The attestation schema uses $ref / $defs / oneOf, which the JS internal
    validator does not yet support, so validate_attestation is NOT ported in this
    slice. This boundary case pins Python's expected output so the follow-up PR
    has a parity target, and a skipped JS test documents the deferral.
    """
    bad = copy.deepcopy(VALID_ATTESTATION)
    bad["validity_temporal"] = {"mode": "absolute"}  # incomplete oneOf branch
    return {
        "valid_attestation": VALID_ATTESTATION,
        "valid_expected": validate_attestation(VALID_ATTESTATION),
        "bad_oneof_attestation": bad,
        "bad_oneof_expected": validate_attestation(bad),
    }


def main() -> None:
    doc = {
        "_comment": (
            "Generated by js-sdk/scripts/gen-schema-validator-fixtures.py from "
            "concordia.schema_validator + concordia.approval_receipt. Error lists "
            "and verification results are Python-produced; do not edit by hand."
        ),
        "seed_hex": SEED.hex(),
        "public_key_b64": _kp_from_seed(SEED).public_key_b64(),
        "message_cases": _message_cases(),
        "approval_receipt_schema_cases": _receipt_schema_cases(),
        "fulfillment_cases": _fulfillment_cases(),
        "verify_cases": _verify_cases(),
        "datetime_format_cases": _datetime_format_cases(),
        "datetime_parse_cases": _datetime_parse_cases(),
        "deferred_attestation": _deferred_attestation_case(),
    }
    json.dump(doc, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
