"""Mutation-test battery (negative test) over the two published interop vectors.

The A2A #1920 thread set a negative-test bar: mutate every published
digest/field one at a time and require the verifier to REJECT the tampered
artifact. This module runs that battery against Concordia's OWN two published
worked vectors, field by field, through each vector's ACTUAL verification path:

  - docs/interop/a2a-1920-fulfillment-sample/ (fulfillment_attestation.json)
  - docs/interop/a2a-1404-receipt-revocation-vector/ (decision_object.json,
    offer.json, approval_receipt.json, revocation_A.json,
    cascade_decision_deny.json)

For every object it enumerates a single-field mutation per field (value flip /
digest tamper / signature tamper, key drop, and unknown-key injection) and
requires the object's real verifier to reject it. It then pins:

  - the per-object catch rate (rejections / mutations),
  - the EXACT set of ACCEPTED mutations ("escapes"), each documented below with
    its mechanism, so a NEW escape (a regression that lets a tamper through)
    fails CI, and a FIXED escape ALSO fails (prompting the allowlist update),
  - JCS key-order invariance: reordering object keys is a canonical no-op and
    MUST be accepted; it is not a tamper,
  - that Concordia's own canonicalizer is independent of the ``rfc8785``
    reference library (the SDK does not secretly delegate to it).

The one known escape is an "outside the signed preimage" structural case, NOT a
forgery vector: it cannot alter a load-bearing field. See the results doc
Review/A2A/Concordia_Vector_Mutation_Battery_2026-07-25.md for the full writeup.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import sys
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from concordia import verify_approval_receipt
from concordia.canonicalization import canonicalize_jcs
from concordia.cmpc import (
    RevocationRecord,
    verify_cascade_decision_record,
    verify_revocation_record,
)
from concordia.schema_validator import validate_fulfillment_attestation
from concordia.signing import canonical_json

REPO_ROOT = Path(__file__).resolve().parent.parent
D1920 = REPO_ROOT / "docs" / "interop" / "a2a-1920-fulfillment-sample"
D1404 = REPO_ROOT / "docs" / "interop" / "a2a-1404-receipt-revocation-vector"
# A wall-clock at which both the #1404 parent A and child B are live (matches
# the published verify.py), so failures come from the mutation, not expiry.
FIXED_NOW = datetime(2026, 5, 10, 14, 25, 0, tzinfo=timezone.utc)
JsonObject = dict[str, Any]
MutationKind = Literal["value", "drop", "inject"]
MutationResult = tuple[str, MutationKind, JsonObject]
EscapeSet = set[tuple[str, MutationKind]]
Verifier = Callable[[JsonObject], bool]


def _json(path: Path) -> JsonObject:
    return cast(JsonObject, json.loads(path.read_text()))


def _pubkey(b64url: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(b64url))


# ---------------------------------------------------------------------------
# Generic single-field mutation enumerator.
# ---------------------------------------------------------------------------
def _mutate_scalar(value: Any) -> Any:
    """Return a minimally different scalar (bool flip / int bump / char edit).

    For hex-shaped strings (sha256 digests) it flips the last hex nibble, so a
    'value' mutation of a digest field is a genuine one-character digest tamper.
    """
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, float):
        return value + 1.0
    if isinstance(value, str):
        if value == "":
            return "x"
        last = value[-1]
        if last in "0123456789abcdef":
            return value[:-1] + ("0" if last != "0" else "1")
        return value[:-1] + ("A" if last != "A" else "B")
    if value is None:
        return "MUTATED"
    return value


def _ref(root: Any, path: list[str | int]) -> Any:
    cur = root
    for step in path:
        cur = cur[step]
    return cur


def _mutations(obj: JsonObject) -> Iterator[MutationResult]:
    """Yield (field_path, kind, mutated_copy) for every single-field mutation.

    Kinds:
      - "value":  change one scalar leaf (digest/signature tamper, bool/int flip)
      - "drop":   delete one key (or list element's key)
      - "inject": add one unknown key ('__mut_probe__') into one object
    Every mutation touches exactly one field and yields a fresh deep copy.
    """

    def walk(node: Any, path: list[str | int]) -> Iterator[MutationResult]:
        if isinstance(node, dict):
            for key in list(node.keys()):
                child_path = path + [key]
                child = node[key]
                if isinstance(child, (dict, list)):
                    yield from walk(child, child_path)
                else:
                    mutated = copy.deepcopy(obj)
                    _ref(mutated, path)[key] = _mutate_scalar(child)
                    yield (".".join(map(str, child_path)), "value", mutated)
                mutated = copy.deepcopy(obj)
                del _ref(mutated, path)[key]
                yield (".".join(map(str, child_path)), "drop", mutated)
            mutated = copy.deepcopy(obj)
            _ref(mutated, path)["__mut_probe__"] = "MUT"
            yield (".".join(map(str, path)) or "<root>", "inject", mutated)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                child_path = path + [index]
                if isinstance(child, (dict, list)):
                    yield from walk(child, child_path)
                else:
                    mutated = copy.deepcopy(obj)
                    _ref(mutated, path)[index] = _mutate_scalar(child)
                    yield (".".join(map(str, child_path)), "value", mutated)

    yield from walk(obj, [])


def _run_battery(
    obj: JsonObject, verifier: Verifier
) -> tuple[int, int, EscapeSet]:
    """Return (rejected, total, escapes) for one object under one verifier.

    An escape = the verifier ACCEPTED a mutation that actually changed the
    stored JSON. No-op mutations (a copy that equals the original) are skipped.
    """
    assert verifier(obj) is True, "baseline artifact must verify (ACCEPT)"
    rejected = 0
    total = 0
    escapes: EscapeSet = set()
    for field_path, kind, mutated in _mutations(obj):
        if mutated == obj:
            continue
        total += 1
        accepted = False
        try:
            accepted = verifier(mutated)
        except Exception:
            accepted = False
        if accepted:
            escapes.add((field_path, kind))
        else:
            rejected += 1
    return rejected, total, escapes


# ---------------------------------------------------------------------------
# Per-vector verifiers: each mirrors what the published verify.py actually runs.
# ---------------------------------------------------------------------------
def _verifier_1920_fulfillment() -> Verifier:
    sample = _json(D1920 / "sample.json")
    pubkey = _pubkey(cast(str, sample["public_key_b64url"]))
    join = cast(JsonObject, sample["join_keys"])

    def verify(att: JsonObject) -> bool:
        if validate_fulfillment_attestation(att) != []:
            return False
        try:
            signable = {k: v for k, v in att.items() if k != "signature"}
            pubkey.verify(
                base64.urlsafe_b64decode(att["signature"]["value"]),
                canonical_json(signable),
            )
        except Exception:
            return False
        return bool(
            att.get("charge_ref") == join["charge_ref"]
            and att.get("action_ref") == join["action_ref"]
        )

    return verify


def _verifier_1404_decision_object() -> Verifier:
    hashes = cast(JsonObject, _json(D1404 / "vector.json")["hashes"])
    expected = cast(str, hashes["decision_id"])

    def verify(decision_object: JsonObject) -> bool:
        return (
            "sha256:" + hashlib.sha256(canonicalize_jcs(decision_object)).hexdigest()
            == expected
        )

    return verify


def _verifier_1404_offer() -> Verifier:
    receipt = _json(D1404 / "approval_receipt.json")
    public_keys = cast(JsonObject, _json(D1404 / "vector.json")["public_keys_b64url"])
    approver_pk = _pubkey(cast(str, public_keys["approver"]))

    def verify(offer: JsonObject) -> bool:
        return bool(
            verify_approval_receipt(
                receipt, offer, now=FIXED_NOW, issuer_public_key=approver_pk
            ).valid
        )

    return verify


def _verifier_1404_receipt() -> Verifier:
    offer = _json(D1404 / "offer.json")
    public_keys = cast(JsonObject, _json(D1404 / "vector.json")["public_keys_b64url"])
    approver_pk = _pubkey(cast(str, public_keys["approver"]))

    def verify(receipt: JsonObject) -> bool:
        return bool(
            verify_approval_receipt(
                receipt, offer, now=FIXED_NOW, issuer_public_key=approver_pk
            ).valid
        )

    return verify


def _verifier_1404_revocation() -> Verifier:
    public_keys = cast(JsonObject, _json(D1404 / "vector.json")["public_keys_b64url"])
    issuer_pk = _pubkey(cast(str, public_keys["revocation_issuer"]))

    def verify(record: JsonObject) -> bool:
        try:
            return bool(
                verify_revocation_record(RevocationRecord.from_dict(record), issuer_pk)
            )
        except Exception:
            return False

    return verify


def _verifier_1404_deny() -> Verifier:
    public_keys = cast(JsonObject, _json(D1404 / "vector.json")["public_keys_b64url"])
    issuer_pk = _pubkey(cast(str, public_keys["revocation_issuer"]))

    def verify(deny: JsonObject) -> bool:
        return bool(verify_cascade_decision_record(deny, issuer_pk))

    return verify


# ---------------------------------------------------------------------------
# Documented battery expectations. Totals track the FROZEN published fixtures;
# escapes are the exact accepted-mutation set, each with a mechanism note.
# ---------------------------------------------------------------------------
# name -> (fixture file, verifier factory, rejected, total, expected_escapes)
_BATTERY: dict[str, tuple[Path, Callable[[], Verifier], int, int, EscapeSet]] = {
    "1920/fulfillment_attestation.json": (
        D1920 / "fulfillment_attestation.json",
        _verifier_1920_fulfillment,
        63,
        63,
        set(),  # signature wrapper is schema-closed as of 0.9.0.
    ),
    "1404/decision_object.json": (
        D1404 / "decision_object.json",
        _verifier_1404_decision_object,
        13,
        13,
        set(),  # content-addressed: every field is inside SHA-256(JCS(.)).
    ),
    "1404/offer.json": (
        D1404 / "offer.json",
        _verifier_1404_offer,
        15,
        15,
        set(),  # every field feeds request_digest / scope.offer_hash.
    ),
    "1404/approval_receipt.json": (
        D1404 / "approval_receipt.json",
        _verifier_1404_receipt,
        63,
        63,
        set(),  # signature wrapper is schema-closed as of 0.9.0.
    ),
    "1404/revocation_A.json": (
        D1404 / "revocation_A.json",
        _verifier_1404_revocation,
        32,
        33,
        # ESCAPE (normalization, VERY LOW): dropping `cascade_depth` is accepted.
        # verify_revocation_record verifies a TYPED RevocationRecord; the vector
        # path calls RevocationRecord.from_dict first, and cascade_depth has
        # dataclass default 3 == the fixture value, so from_dict re-fills the
        # identical value before canonicalization and the signature still
        # verifies. It "escapes" ONLY because the omitted value equals the
        # default; any non-default value would diverge the canonical bytes and
        # reject. Contrast the cascade-decision path, which is deliberately
        # raw-mapping-strict (additionalProperties:false, refuses typed input).
        {("cascade_depth", "drop")},
    ),
    "1404/cascade_decision_deny.json": (
        D1404 / "cascade_decision_deny.json",
        _verifier_1404_deny,
        35,
        35,
        set(),  # raw-mapping strict verifier: every single-field mutation rejects.
    ),
}


def test_mutation_battery_catch_rate_and_escapes() -> None:
    """Every published field, mutated one at a time, is rejected except the
    exact documented escape set. Regression guard on both directions."""
    for name, (path, factory, exp_rejected, exp_total, exp_escapes) in _BATTERY.items():
        obj = _json(path)
        rejected, total, escapes = _run_battery(obj, factory())
        assert total == exp_total, f"{name}: battery size drifted ({total} != {exp_total})"
        assert escapes == exp_escapes, (
            f"{name}: escape set changed. got={sorted(escapes)} "
            f"expected={sorted(exp_escapes)}. A new escape is a regression; a "
            f"removed escape means update this allowlist + the results doc."
        )
        assert rejected == exp_rejected, (
            f"{name}: rejected {rejected} != {exp_rejected}"
        )
        assert rejected == total - len(exp_escapes)


def test_mutation_battery_headline_numbers() -> None:
    """Pin the headline catch rate reported in the results doc."""
    v1920 = _BATTERY["1920/fulfillment_attestation.json"]
    assert (v1920[2], v1920[3]) == (63, 63)
    total_1404 = sum(v[3] for k, v in _BATTERY.items() if k.startswith("1404/"))
    rej_1404 = sum(v[2] for k, v in _BATTERY.items() if k.startswith("1404/"))
    assert (rej_1404, total_1404) == (158, 159)
    grand_rejected = sum(v[2] for v in _BATTERY.values())
    grand_total = sum(v[3] for v in _BATTERY.values())
    assert (grand_rejected, grand_total) == (221, 222)


def test_jcs_key_reorder_is_a_canonical_noop_not_a_tamper() -> None:
    """Reordering object keys MUST be accepted: JCS sorts keys, so it does not
    change the signed/hashed bytes. A verifier that rejected it would be wrong."""

    def reordered(obj: JsonObject) -> JsonObject:
        # Reverse the top-level key order; JSON round-trip preserves insertion
        # order, so this produces a genuinely reordered dict.
        return {k: obj[k] for k in reversed(list(obj.keys()))}

    for name, (path, factory, *_rest) in _BATTERY.items():
        obj = _json(path)
        verify = factory()
        assert verify(obj) is True, f"{name} baseline must ACCEPT"
        assert verify(reordered(obj)) is True, (
            f"{name}: key reorder must remain ACCEPTED (JCS is order-independent)"
        )


def test_sdk_canonicalizer_is_independent_of_rfc8785() -> None:
    """Concordia's own canonicalizer does NOT delegate to the rfc8785 reference
    library. Proven by canonicalizing in a fresh subprocess that imports only
    the SDK, then asserting `rfc8785` never entered sys.modules."""
    probe = (
        "import sys, json\n"
        "from concordia.signing import canonical_json\n"
        "from concordia.canonicalization import canonicalize_jcs\n"
        "obj = {'b': 2, 'a': [1, {'z': True, 'y': 'x'}], 'c': 'unicode-\\u00e9'}\n"
        "assert canonical_json(obj)\n"
        "assert canonicalize_jcs(obj)\n"
        "print('rfc8785' in sys.modules)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "False", (
        f"SDK canonicalizer pulled in rfc8785: {out.stdout!r} {out.stderr!r}"
    )
