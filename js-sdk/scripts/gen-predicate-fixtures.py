#!/usr/bin/env python3
"""Generate v0.6 signed-predicate parity fixtures FROM the Concordia Python reference.

Run from the repo root (or anywhere with `concordia` importable). Emits a JSON
document to stdout. The JS test suite (tests/predicate.test.ts) asserts that the
TypeScript predicate layer produces:
  - byte-identical canonical signing bytes (`serialize_predicate_canonical`),
  - byte-identical Ed25519 signatures (`sign_predicate`),
  - identical verification outcomes (`verify_predicate`: valid flag,
    failure_reason, per-check booleans),
  - identical type-profile / write-validation error lists
    (`validate_condition_for_profile`, `validate_predicate_for_write`),
  - identical attestation-level reference normalization (`_validate_reference`).

This is the parity source of truth: every expected value here comes straight
from `concordia.predicate` / `concordia.predicate_type_profiles` /
`concordia.attestation`, never hand-authored. Synced into the JS test surface
by scripts/sync-fixtures-from-python.mjs.
"""

from __future__ import annotations

import copy
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia import signing
from concordia.attestation import _validate_reference
from concordia.predicate import (
    Predicate,
    serialize_predicate_canonical,
    sign_predicate,
    validate_predicate_for_write,
    verify_predicate,
)
from concordia.predicate_type_profiles import (
    get_predicate_type_profile,
    validate_condition_for_profile,
)


def _kp_from_seed(seed: bytes) -> signing.KeyPair:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return signing.KeyPair(private_key=sk, public_key=sk.public_key())


# Fixed 32-byte seed so the fixtures are fully deterministic and reproducible
# across runs and machines. The raw private key IS the Ed25519 seed in both the
# Python `cryptography` lib and JS `@noble/curves`.
SEED = bytes(range(32))
OTHER_SEED = bytes(range(100, 132))

# The four built-in type ids the profile registry knows. Far-future expiry on
# every signed predicate so the lifecycle check never trips on wall-clock drift.
AUTHORITY_GATE = "urn:concordia:predicate-type:authority_gate:v1"
APPROVAL_GATE = "urn:concordia:predicate-type:approval_gate:v1"
PROCUREMENT = "urn:concordia:predicate-type:procurement_eligibility:v1"
POLICY_GATE = "urn:concordia:predicate-type:policy_gate:v1"
NON_DETERMINISTIC = "urn:concordia:predicate-type:non_deterministic_test:v1"

FAR_FUTURE = "2126-06-14T00:00:00Z"
ISSUED = "2026-05-14T00:00:00Z"


def _base_predicate(**overrides) -> dict:
    base = {
        "predicate_id": "urn:concordia:predicate:pred_min_001",
        "type": AUTHORITY_GATE,
        "authority": "urn:concordia:authority:procurement",
        "issuer": "did:web:issuer.example#key-1",
        "subject": "did:web:buyer.example#agent",
        "condition": {"result": "satisfied"},
        "issued_at": ISSUED,
        "expires_at": FAR_FUTURE,
        "references": [],
        "algorithm": "EdDSA",
        "status": "active",
        "signature": "",
    }
    base.update(overrides)
    return base


def _sign_case(name: str, kp: signing.KeyPair, predicate_input: dict) -> dict:
    signed = sign_predicate(copy.deepcopy(predicate_input), kp)
    signed_dict = signed.to_dict()
    # Python verifies its own signed predicate.
    result = verify_predicate(signed)
    assert result.valid, (name, result.to_dict())
    return {
        "name": name,
        # The exact dict the signed Predicate serializes to (includes the
        # metadata.issuer_public_key_b64 the signer injects and the signature).
        "signed_predicate": signed_dict,
        "expected_canonical": serialize_predicate_canonical(signed).decode("utf-8"),
        "expected_signature": signed.signature,
        "expected_verify": result.to_dict(),
    }


def _verify_case(name: str, predicate_dict: dict) -> dict:
    """A verification case for an already-built predicate dict (no re-signing)."""
    result = verify_predicate(copy.deepcopy(predicate_dict))
    return {
        "name": name,
        "predicate": predicate_dict,
        "expected_verify": result.to_dict(),
    }


def _build_deferred_revocation_fixture(kp: signing.KeyPair) -> dict:
    """Pin the DEFERRED `revocation_records` parity boundary (Finding 5).

    Builds ONE signed predicate that references an artifact, then captures the
    Python `verify_predicate` outcome BOTH without revocation records (valid)
    and WITH a revocation record that revokes the referenced artifact (REVOKED,
    `checks.revocation_records == False`). The JS SDK does not yet port the
    `concordia.cmpc` revocation path, so the JS test asserts the
    no-revocation-records outcome today and `it.skip`s the with-revocation
    outcome until the cmpc port lands -- this fixture is the Python-generated
    expectation that future PR must match.
    """
    from datetime import datetime, timezone

    from concordia.cmpc.types import RevocationRecord

    ref_id = "urn:concordia:predicate:revoked_parent"
    predicate_input = _base_predicate(
        predicate_id="urn:concordia:predicate:pred_with_revoked_ref",
        references=[{"type": "predicate", "id": ref_id, "relationship": "extends"}],
    )
    signed = sign_predicate(copy.deepcopy(predicate_input), kp)
    signed_dict = signed.to_dict()

    # Without revocation records: the JS SDK reproduces this TODAY.
    without = verify_predicate(copy.deepcopy(signed))
    assert without.valid, without.to_dict()

    # With a revocation record covering the referenced artifact: Python fails
    # REVOKED. The JS SDK defers this (cmpc not ported).
    record = RevocationRecord(
        revocation_id="urn:concordia:revocation:rev_001",
        revoked_artifact_id=ref_id,
        revoked_artifact_type="predicate",
        revocation_scope="single_artifact",
        issuer_did="did:web:authority.example",
        issued_at="2026-05-15T00:00:00Z",
        effective_at="2026-05-15T00:00:00Z",
        reason="compromised",
        references=[],
    )
    fixed_now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    with_records = verify_predicate(
        copy.deepcopy(signed),
        revocation_records={ref_id: record},
        now=fixed_now,
    )
    assert not with_records.valid and with_records.failure_reason == "revoked", (
        with_records.to_dict()
    )

    return {
        "_comment": (
            "DEFERRED in this PR: the revocation_records/now path depends on the "
            "unported concordia.cmpc module. JS asserts expected_verify_without "
            "today; expected_verify_with is the Python expectation the future "
            "cmpc-port PR must match (JS test is it.skip until then)."
        ),
        "signed_predicate": signed_dict,
        "referenced_artifact_id": ref_id,
        "revocation_record": record.to_dict(),
        "now": fixed_now.isoformat(),
        "expected_verify_without": without.to_dict(),
        "expected_verify_with": with_records.to_dict(),
    }


def main() -> None:
    kp = _kp_from_seed(SEED)
    other_kp = _kp_from_seed(OTHER_SEED)

    # ------------------------------------------------------------------
    # Sign + verify cases: round-trip signed predicates that VERIFY VALID.
    # ------------------------------------------------------------------
    sign_cases = [
        _sign_case("authority_gate_satisfied", kp, _base_predicate()),
        _sign_case(
            "authority_gate_denied",
            kp,
            _base_predicate(
                predicate_id="urn:concordia:predicate:pred_denied",
                condition={"result": "denied"},
            ),
        ),
        _sign_case(
            "approval_gate_alias",
            kp,
            _base_predicate(
                predicate_id="urn:concordia:predicate:pred_approval",
                type=APPROVAL_GATE,
            ),
        ),
        _sign_case(
            "procurement_eligibility",
            kp,
            _base_predicate(
                predicate_id="urn:concordia:predicate:pred_proc",
                type=PROCUREMENT,
                condition={
                    "result": "satisfied",
                    "operation": "purchase",
                    "limit": {"amount": 5000, "currency": "USD"},
                },
            ),
        ),
        _sign_case(
            "policy_gate_all_any",
            kp,
            _base_predicate(
                predicate_id="urn:concordia:predicate:pred_policy",
                type=POLICY_GATE,
                condition={
                    "result": "satisfied",
                    "all": ["a", "b"],
                    "any": ["c"],
                },
            ),
        ),
        _sign_case(
            "with_references",
            kp,
            _base_predicate(
                predicate_id="urn:concordia:predicate:pred_refs",
                references=[
                    {
                        "type": "predicate",
                        "id": "urn:concordia:predicate:parent",
                        "relationship": "extends",
                    },
                    {
                        "type": "receipt",
                        "id": "urn:concordia:receipt:r1",
                        "relationship": "fulfills",
                        "version": "1.0",
                    },
                ],
            ),
        ),
        _sign_case(
            "with_optional_fields",
            kp,
            _base_predicate(
                predicate_id="urn:concordia:predicate:pred_opt",
                validity={"mode": "absolute", "from": ISSUED, "until": FAR_FUTURE},
                constraints={"max_uses": 3},
                revocation_endpoint="https://issuer.example/revoke",
            ),
        ),
        _sign_case(
            "unicode_fields",
            kp,
            _base_predicate(
                predicate_id="urn:concordia:predicate:pred_unicode",
                subject="did:web:café.example#agént",
            ),
        ),
    ]

    # ------------------------------------------------------------------
    # Verification failure cases: predicates that VERIFY INVALID. Each is
    # signed-then-mutated (or built unsigned) so the JS verifier must reproduce
    # the same failure_reason and check map.
    # ------------------------------------------------------------------
    verify_fail_cases = []

    # Tampered: flip a field after signing -> bad signature.
    signed_ok = sign_predicate(_base_predicate(), kp)
    tampered = signed_ok.to_dict()
    tampered["subject"] = "did:web:attacker.example#agent"
    verify_fail_cases.append(_verify_case("tampered_subject", tampered))

    # Wrong public key in metadata: sign, then overwrite metadata pubkey.
    wrongkey = sign_predicate(_base_predicate(), kp).to_dict()
    wrongkey["metadata"] = {"issuer_public_key_b64": other_kp.public_key_b64()}
    verify_fail_cases.append(_verify_case("wrong_public_key", wrongkey))

    # Missing signature entirely.
    no_sig = sign_predicate(_base_predicate(), kp).to_dict()
    no_sig["signature"] = ""
    verify_fail_cases.append(_verify_case("missing_signature", no_sig))

    # No issuer public key in metadata -> UNKNOWN_AUTHORITY.
    no_pubkey = sign_predicate(_base_predicate(), kp).to_dict()
    no_pubkey.pop("metadata", None)
    verify_fail_cases.append(_verify_case("no_issuer_pubkey", no_pubkey))

    # Expired (status active but expires_at in the past) -> EXPIRED.
    expired = sign_predicate(
        _base_predicate(expires_at="2000-01-01T00:00:00Z"), kp
    ).to_dict()
    verify_fail_cases.append(_verify_case("expired_by_timestamp", expired))

    # Status revoked -> REVOKED.
    revoked = sign_predicate(_base_predicate(), kp).to_dict()
    revoked["status"] = "revoked"
    verify_fail_cases.append(_verify_case("status_revoked", revoked))

    # Status suspended -> REVOKED reason.
    suspended = sign_predicate(_base_predicate(), kp).to_dict()
    suspended["status"] = "suspended"
    verify_fail_cases.append(_verify_case("status_suspended", suspended))

    # expected_subject mismatch in metadata -> WRONG_SUBJECT.
    subj_mismatch = sign_predicate(
        _base_predicate(
            metadata={"expected_subject": "did:web:someone.else#agent"}
        ),
        kp,
    ).to_dict()
    verify_fail_cases.append(_verify_case("expected_subject_mismatch", subj_mismatch))

    # Schema invalid: predicate_id without the required urn prefix (built
    # unsigned; schema check fails before signature).
    bad_urn = _base_predicate(predicate_id="not-a-urn")
    bad_urn["signature"] = "ignored"
    verify_fail_cases.append(_verify_case("bad_predicate_id_urn", bad_urn))

    # Schema invalid: bad algorithm.
    bad_alg = _base_predicate(algorithm="RS256")
    bad_alg["signature"] = "ignored"
    verify_fail_cases.append(_verify_case("bad_algorithm", bad_alg))

    # ------------------------------------------------------------------
    # validate_condition_for_profile cases: type-profile gate error lists.
    # ------------------------------------------------------------------
    profile_cases = [
        {
            "name": "authority_satisfied_ok",
            "type_id": AUTHORITY_GATE,
            "condition": {"result": "satisfied"},
            "expected_errors": validate_condition_for_profile(
                AUTHORITY_GATE, {"result": "satisfied"}
            ),
        },
        {
            "name": "authority_bad_enum",
            "type_id": AUTHORITY_GATE,
            "condition": {"result": "maybe"},
            "expected_errors": validate_condition_for_profile(
                AUTHORITY_GATE, {"result": "maybe"}
            ),
        },
        {
            "name": "authority_result_int",
            "type_id": AUTHORITY_GATE,
            "condition": {"result": 5},
            "expected_errors": validate_condition_for_profile(
                AUTHORITY_GATE, {"result": 5}
            ),
        },
        {
            "name": "authority_no_result_no_validation",
            "type_id": AUTHORITY_GATE,
            "condition": {"foo": "bar"},
            "expected_errors": validate_condition_for_profile(
                AUTHORITY_GATE, {"foo": "bar"}
            ),
        },
        {
            "name": "non_deterministic_with_result",
            "type_id": NON_DETERMINISTIC,
            "condition": {"result": "satisfied"},
            "expected_errors": validate_condition_for_profile(
                NON_DETERMINISTIC, {"result": "satisfied"}
            ),
        },
        {
            "name": "non_deterministic_no_result_ok",
            "type_id": NON_DETERMINISTIC,
            "condition": {"foo": "bar"},
            "expected_errors": validate_condition_for_profile(
                NON_DETERMINISTIC, {"foo": "bar"}
            ),
        },
        {
            "name": "unregistered_type",
            "type_id": "urn:concordia:predicate-type:unknown:v1",
            "condition": {"result": "satisfied"},
            "expected_errors": validate_condition_for_profile(
                "urn:concordia:predicate-type:unknown:v1", {"result": "satisfied"}
            ),
        },
        {
            "name": "condition_not_object",
            "type_id": AUTHORITY_GATE,
            "condition": "nope",
            "expected_errors": validate_condition_for_profile(AUTHORITY_GATE, "nope"),
        },
        {
            "name": "procurement_operation_wrong_type",
            "type_id": PROCUREMENT,
            "condition": {"result": "satisfied", "operation": 5},
            "expected_errors": validate_condition_for_profile(
                PROCUREMENT, {"result": "satisfied", "operation": 5}
            ),
        },
        {
            "name": "procurement_limit_wrong_type",
            "type_id": PROCUREMENT,
            "condition": {"result": "satisfied", "limit": "x"},
            "expected_errors": validate_condition_for_profile(
                PROCUREMENT, {"result": "satisfied", "limit": "x"}
            ),
        },
        {
            "name": "procurement_multi_error",
            "type_id": PROCUREMENT,
            "condition": {"result": "bad", "operation": 5, "limit": "x"},
            "expected_errors": validate_condition_for_profile(
                PROCUREMENT, {"result": "bad", "operation": 5, "limit": "x"}
            ),
        },
        {
            "name": "policy_all_wrong_type",
            "type_id": POLICY_GATE,
            "condition": {"result": "satisfied", "all": "x"},
            "expected_errors": validate_condition_for_profile(
                POLICY_GATE, {"result": "satisfied", "all": "x"}
            ),
        },
        {
            "name": "policy_any_wrong_type",
            "type_id": POLICY_GATE,
            "condition": {"result": "satisfied", "any": "x"},
            "expected_errors": validate_condition_for_profile(
                POLICY_GATE, {"result": "satisfied", "any": "x"}
            ),
        },
    ]

    # ------------------------------------------------------------------
    # validate_predicate_for_write cases: full write-validation error lists.
    # Each entry records the exact ValueError text (or None when valid).
    # ------------------------------------------------------------------
    def _write_error(predicate: dict) -> str | None:
        try:
            validate_predicate_for_write(copy.deepcopy(predicate))
            return None
        except ValueError as exc:
            return str(exc)

    write_cases = [
        {
            "name": "valid_authority_gate",
            "predicate": _base_predicate(signature="x"),
            "expected_error": _write_error(_base_predicate(signature="x")),
        },
        {
            "name": "missing_required_fields",
            "predicate": {"predicate_id": "urn:concordia:predicate:x"},
            "expected_error": _write_error({"predicate_id": "urn:concordia:predicate:x"}),
        },
        {
            "name": "predicate_type_alias_rejected_on_write",
            "predicate": {
                **{k: v for k, v in _base_predicate(signature="x").items() if k != "type"},
                "predicate_type": AUTHORITY_GATE,
            },
            "expected_error": _write_error(
                {
                    **{k: v for k, v in _base_predicate(signature="x").items() if k != "type"},
                    "predicate_type": AUTHORITY_GATE,
                }
            ),
        },
        {
            "name": "additional_property_rejected",
            "predicate": _base_predicate(signature="x", surprise="boom"),
            "expected_error": _write_error(_base_predicate(signature="x", surprise="boom")),
        },
        {
            "name": "bad_status",
            "predicate": _base_predicate(signature="x", status="bogus"),
            "expected_error": _write_error(_base_predicate(signature="x", status="bogus")),
        },
        {
            "name": "empty_condition",
            "predicate": _base_predicate(signature="x", condition={}),
            "expected_error": _write_error(_base_predicate(signature="x", condition={})),
        },
        {
            "name": "references_not_array",
            "predicate": _base_predicate(signature="x", references="nope"),
            "expected_error": _write_error(_base_predicate(signature="x", references="nope")),
        },
        {
            "name": "bad_reference_entry",
            "predicate": _base_predicate(
                signature="x", references=[{"type": "predicate"}]
            ),
            "expected_error": _write_error(
                _base_predicate(signature="x", references=[{"type": "predicate"}])
            ),
        },
        {
            "name": "non_deterministic_profile_result_violation",
            "predicate": _base_predicate(
                signature="x", type=NON_DETERMINISTIC, condition={"result": "satisfied"}
            ),
            "expected_error": _write_error(
                _base_predicate(
                    signature="x",
                    type=NON_DETERMINISTIC,
                    condition={"result": "satisfied"},
                )
            ),
        },
    ]

    # ------------------------------------------------------------------
    # _validate_reference cases (the attestation helper predicate reuses):
    # normalized-output for valid refs, ValueError text for invalid ones.
    # ------------------------------------------------------------------
    def _ref_case(name: str, ref, index: int) -> dict:
        try:
            normalized = _validate_reference(copy.deepcopy(ref), index)
            return {"name": name, "ref": ref, "index": index, "normalized": normalized, "error": None}
        except ValueError as exc:
            return {"name": name, "ref": ref, "index": index, "normalized": None, "error": str(exc)}

    reference_cases = [
        _ref_case(
            "minimal_valid",
            {"type": "predicate", "id": "urn:x", "relationship": "extends"},
            0,
        ),
        _ref_case(
            "with_optionals_passthrough",
            {
                "type": "receipt",
                "id": "urn:r",
                "relationship": "fulfills",
                "version": "1",
                "signed_at": "2026-05-14T00:00:00Z",
                "signer_did": "did:web:x",
                "extensions": {"k": "v"},
            },
            0,
        ),
        _ref_case(
            "drops_unknown_optional",
            {"type": "predicate", "id": "urn:x", "relationship": "extends", "ignored": "drop"},
            1,
        ),
        _ref_case("not_a_dict", "string", 0),
        _ref_case("missing_keys", {"type": "predicate"}, 2),
        _ref_case("empty_type", {"type": "", "id": "x", "relationship": "extends"}, 0),
        _ref_case("empty_id", {"type": "predicate", "id": "", "relationship": "extends"}, 0),
        _ref_case(
            "empty_relationship",
            {"type": "predicate", "id": "x", "relationship": ""},
            0,
        ),
        _ref_case(
            "opaque_unknown_vocab",
            {"type": "custom_type", "id": "urn:x", "relationship": "custom_rel"},
            0,
        ),
        # --- Finding 3 (reference diagnostics): a non-dict reference of every
        # JSON-representable type must be REJECTED with Python's exact
        # `type(ref).__name__` in the message. Earlier fixtures only covered the
        # string case; these pin the int/float/bool/None/list type names so a
        # regression to a `dict` fallback (the prior TS bug) is caught.
        _ref_case("not_a_dict_int", 5, 0),
        _ref_case("not_a_dict_float", 3.5, 0),
        _ref_case("not_a_dict_bool", True, 0),
        _ref_case("not_a_dict_none", None, 0),
        _ref_case("not_a_dict_list", [1, 2], 3),
    ]

    # ------------------------------------------------------------------
    # Finding 1 (condition strict-dict): non-dict condition probes that Python
    # rejects via `isinstance(condition, dict)`. JSON cannot carry a JS class
    # instance, but Python rejecting a list / string / int IS the contract a JS
    # class instance / Date must satisfy. Both the profile gate
    # ("condition must be an object") and the schema check
    # ("condition must be a non-empty object") are pinned.
    # ------------------------------------------------------------------
    condition_type_cases = []
    for cname, cval in [
        ("list_condition", ["result"]),
        ("string_condition", "nope"),
        ("int_condition", 5),
        ("bool_condition", True),
        ("none_condition", None),
        ("empty_dict_condition", {}),
    ]:
        condition_type_cases.append(
            {
                "name": cname,
                "type_id": AUTHORITY_GATE,
                "condition": cval,
                # Profile-gate error list (validate_condition_for_profile).
                "expected_profile_errors": validate_condition_for_profile(
                    AUTHORITY_GATE, cval
                ),
                # Full write-validation error text (validate_predicate_for_write),
                # which runs the schema check ("condition must be a non-empty
                # object") AND the profile gate.
                "expected_write_error": _write_error(
                    _base_predicate(signature="x", condition=cval)
                ),
            }
        )

    # ------------------------------------------------------------------
    # Finding 2 (metadata coercion): Python `sign_predicate` does
    # `dict(data.get("metadata") or {})`. A truthy non-mapping raises (int/float/
    # bool not iterable; str/list not a key/value sequence); a falsy value
    # collapses to `{}`. The fixture records, per metadata value, whether Python
    # SIGNS (coerces) or RAISES. The JS contract: `signPredicate` throws iff
    # Python raises (a loose spread would fail-open by silently coercing `5`).
    # ------------------------------------------------------------------
    def _signs_with_metadata(metadata_value) -> bool:
        p = _base_predicate(
            predicate_id="urn:concordia:predicate:pred_meta", metadata=metadata_value
        )
        try:
            sign_predicate(copy.deepcopy(p), kp)
            return True
        except Exception:
            return False

    metadata_cases = []
    for mname, mval in [
        ("metadata_int", 5),
        ("metadata_float", 3.5),
        ("metadata_bool_true", True),
        ("metadata_nonempty_string", "str"),
        ("metadata_nonempty_list", [1, 2]),
        ("metadata_empty_object", {}),
        ("metadata_empty_list", []),
        ("metadata_zero", 0),
        ("metadata_empty_string", ""),
        ("metadata_null", None),
    ]:
        metadata_cases.append(
            {
                "name": mname,
                "metadata": mval,
                # True == Python signs (coerces); False == Python raises.
                "signs": _signs_with_metadata(mval),
            }
        )

    # ------------------------------------------------------------------
    # Finding 4 (ISO-8601 error strings): predicates whose issued_at / expires_at
    # are malformed. Python surfaces `datetime.fromisoformat`'s exact text in the
    # write/verify error list (e.g. "Invalid isoformat string: 'not-a-time'",
    # "month must be in 1..12", "hour must be in 0..23"). Each case records the
    # full write-validation error so the JS `Invalid isoformat string` /
    # field-range replication is asserted, not a generic placeholder.
    # ------------------------------------------------------------------
    iso_error_cases = []
    for iname, field, bad in [
        ("issued_at_garbage", "issued_at", "not-a-time"),
        ("expires_at_garbage", "expires_at", "garbage"),
        ("issued_at_empty", "issued_at", ""),
        ("issued_at_slashes", "issued_at", "2026/05/14"),
        ("expires_at_bad_month", "expires_at", "2026-13-01T00:00:00Z"),
        ("expires_at_bad_hour", "expires_at", "2026-05-14T25:00:00Z"),
        ("expires_at_bad_day", "expires_at", "2026-05-32T00:00:00Z"),
        ("expires_at_bad_minute", "expires_at", "2026-05-14T00:60:00Z"),
        ("expires_at_bad_second", "expires_at", "2026-05-14T00:00:60Z"),
        ("expires_at_feb29_nonleap", "expires_at", "2026-02-29T00:00:00Z"),
        ("expires_at_zsuffix_malformed", "expires_at", "bogusZvalue"),
    ]:
        pred = _base_predicate(signature="x", **{field: bad})
        iso_error_cases.append(
            {
                "name": iname,
                "predicate": pred,
                "expected_write_error": _write_error(copy.deepcopy(pred)),
            }
        )

    # ------------------------------------------------------------------
    # Finding 5 (DEFERRED revocation_records): this PR does NOT port the
    # `concordia.cmpc` revocation path. The fixture below records what Python
    # produces WITH revocation_records (a REVOKED failure) for the SAME predicate
    # that, WITHOUT revocation_records, verifies VALID -- pinning the boundary so
    # the future cmpc-port PR has a Python-generated expectation to match. The JS
    # test marks this `it.skip` until the cmpc layer is ported.
    # ------------------------------------------------------------------
    deferred_revocation = _build_deferred_revocation_fixture(kp)

    doc = {
        "_comment": (
            "Generated by js-sdk/scripts/gen-predicate-fixtures.py from "
            "concordia.predicate / concordia.predicate_type_profiles / "
            "concordia.attestation. All canonical bytes, signatures, verify "
            "outcomes, and validation error lists are Python-produced; do not "
            "edit by hand."
        ),
        "seed_hex": SEED.hex(),
        "public_key_b64": kp.public_key_b64(),
        "other_public_key_b64": other_kp.public_key_b64(),
        "sign_cases": sign_cases,
        "verify_fail_cases": verify_fail_cases,
        "profile_cases": profile_cases,
        "write_cases": write_cases,
        "reference_cases": reference_cases,
        "condition_type_cases": condition_type_cases,
        "metadata_cases": metadata_cases,
        "iso_error_cases": iso_error_cases,
        "deferred_revocation": deferred_revocation,
    }

    json.dump(doc, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
