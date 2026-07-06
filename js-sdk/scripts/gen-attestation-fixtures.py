#!/usr/bin/env python3
"""Generate reputation-attestation parity fixtures FROM the Concordia Python reference.

Run from the repo root (or anywhere with `concordia` importable). Emits a JSON
document to stdout. The JS test suite (tests/attestation.test.ts) replays these
Python-produced runs against the TypeScript attestation layer and asserts
byte-level parity of: the full attestation object produced over a real concluded
Session (header fields, outcome with conditional terms_count, per-party
behavioral records and their Python Ed25519 signatures, transcript_hash, meta,
references, validity_temporal, and the 4-line summary), the
validate_validity_temporal normalization + error text, the is_valid_now temporal
checks, the generate_receipt_summary formatting, and the no-raw-terms PRIVACY
INVARIANT (the attestation is searched for any leaked term value).

This is the parity source of truth: every attestation, signature, normalized
object, and error string here comes straight from `concordia.attestation` driven
over `concordia.session`, never hand-authored. Messages are real signed
envelopes (the same field shape `concordia.message.build_envelope` produces,
signed with `sign_message` over deterministic seeded keys, with a fixed
timestamp and sequential ids), and the per-party attestation signatures are real
`sign_message` outputs, so the JS suite verifies the SAME Python signatures with
the SAME keys.

Because `generate_attestation` stamps a random `attestation_id` and a wall-clock
`timestamp` (neither is part of the signed per-party bytes), each emitted case
records the Python `attestation_id` and `timestamp` so the JS side can inject
them as overrides and compare the ENTIRE object byte-for-byte.

Imports `cryptography` (the signing dep). Run under python3.12 (the same Python
the rest of the engine fixtures target) unless PYTHON is overridden.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia import attestation as att
from concordia import signing
from concordia.message import GENESIS_HASH, compute_hash
from concordia.session import Session
from concordia.types import (
    AgentIdentity,
    MessageType,
    PartyRole,
    ResolutionMechanism,
)


# Deterministic seeds so the fixtures are reproducible across runs and machines.
SEED_A = bytes(range(32))
SEED_B = bytes(range(100, 132))


def _kp_from_seed(seed: bytes) -> signing.KeyPair:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return signing.KeyPair(private_key=sk, public_key=sk.public_key())


KP_A = _kp_from_seed(SEED_A)
KP_B = _kp_from_seed(SEED_B)

AGENT_A = "did:concordia:agent:alpha"
AGENT_B = "did:concordia:agent:beta"

KEYS = {AGENT_A: KP_A, AGENT_B: KP_B}

T0 = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)

_MSG_COUNTER = {"n": 0}


def _next_msg_id() -> str:
    _MSG_COUNTER["n"] += 1
    return f"msg_{_MSG_COUNTER['n']:08d}"


def _resolver(agent_id: str):
    kp = KEYS.get(agent_id)
    return kp.public_key if kp else None


def _make_msg(*, msg_type, sender_kp, sender_id, session_id, prev_hash, body, reasoning=None):
    msg = {
        "concordia": "0.1.0",
        "type": msg_type.value,
        "id": _next_msg_id(),
        "session_id": session_id,
        "timestamp": "2026-05-29T12:00:00Z",
        "from": AgentIdentity(agent_id=sender_id).to_dict(),
        "prev_hash": prev_hash,
        "body": body,
    }
    if reasoning:
        msg["reasoning"] = reasoning
    msg["signature"] = signing.sign_message(msg, sender_kp)
    return msg


OPEN_BODY = {
    "terms": {
        "price": {"type": "numeric", "value": 1000},
        "qty": {"type": "numeric", "value": 10},
    }
}
OFFER_BODY_1 = {"terms": {"price": {"value": 1000}, "qty": {"value": 10}}}
OFFER_BODY_2 = {"terms": {"price": {"value": 900}, "qty": {"value": 10}}}
OFFER_BODY_3 = {"terms": {"price": {"value": 850}, "qty": {"value": 12}}}

# Any literal numeric term VALUE that appears in the negotiation bodies. The
# privacy check asserts NONE of these leak into the attestation (only their
# COUNT, terms_count, is allowed). The string forms are what canonical JSON would
# serialize a leaked value as.
LEAKABLE_TERM_VALUES = [1000, 10, 900, 850, 12]


def _build_concluded_session(name, steps, *, add_b=True, seconds_per_step=1):
    """Drive a fresh Session through `steps` to a terminal/expired state."""
    session = Session(session_id=f"ses_{name}")
    session.created_at = T0
    session.add_party(AGENT_A, PartyRole.INITIATOR, KP_A.public_key)
    if add_b:
        session.add_party(AGENT_B, PartyRole.RESPONDER, KP_B.public_key)

    prev_hash = GENESIS_HASH
    for i, step in enumerate(steps):
        sender_id = step["sender"]
        msg = _make_msg(
            msg_type=step["type"],
            sender_kp=KEYS[sender_id],
            sender_id=sender_id,
            session_id=session.session_id,
            prev_hash=prev_hash,
            body=step.get("body", {}),
            reasoning=step.get("reasoning"),
        )
        session.apply_message(msg, _resolver)
        if session.concluded_at is not None:
            session.concluded_at = T0 + timedelta(seconds=(i + 1) * seconds_per_step)
        prev_hash = compute_hash(msg)
    return session


def _attestation_case(name, session, key_pairs, *, kwargs=None):
    """Generate a real attestation and capture it for byte-parity replay."""
    kwargs = kwargs or {}
    attestation = att.generate_attestation(session, key_pairs, **kwargs)
    # Capture the public keys (b64) so the JS suite can verify the per-party
    # Python signatures with the same keys.
    return {
        "name": name,
        # The JS suite replays the SAME session by re-driving the transcript;
        # we hand it the transcript + parties + the deterministic clock anchor.
        "session": {
            "session_id": session.session_id,
            "parties": [
                {"agent_id": aid, "role": role.value}
                for aid, role in session.parties.items()
            ],
            "transcript": session.transcript,
            "created_at_ms": int(T0.timestamp() * 1000),
            "concluded_at_ms": (
                int(session.concluded_at.timestamp() * 1000)
                if session.concluded_at is not None
                else None
            ),
            "state": session.state.value,
        },
        # Which agents were given a signing key (the rest get "" signatures).
        "signing_agents": list(key_pairs.keys()),
        # The kwargs the JS side must pass (resolution_mechanism etc.), plus the
        # non-deterministic header values to inject as overrides for full parity.
        "kwargs": {
            "category": kwargs.get("category"),
            "value_range": kwargs.get("value_range"),
            "resolution_mechanism": (
                kwargs["resolution_mechanism"].value
                if "resolution_mechanism" in kwargs
                else None
            ),
            "references": kwargs.get("references"),
            "validity_temporal": kwargs.get("validity_temporal"),
        },
        "attestation_id": attestation["attestation_id"],
        "timestamp": attestation["timestamp"],
        "expected": attestation,
    }


def _key_b64_map():
    return {
        AGENT_A: KP_A.public_key_b64(),
        AGENT_B: KP_B.public_key_b64(),
    }


def main() -> None:
    cases = []

    # Case 1: AGREED full negotiation, both parties signed, with terms_count.
    s = _build_concluded_session(
        "agree_full",
        [
            {"sender": AGENT_A, "type": MessageType.OPEN, "body": OPEN_BODY},
            {"sender": AGENT_B, "type": MessageType.ACCEPT_SESSION, "body": {}},
            {"sender": AGENT_A, "type": MessageType.OFFER, "body": OFFER_BODY_1, "reasoning": "opening"},
            {"sender": AGENT_B, "type": MessageType.COUNTER, "body": OFFER_BODY_2},
            {"sender": AGENT_A, "type": MessageType.OFFER, "body": OFFER_BODY_3},
            {"sender": AGENT_B, "type": MessageType.ACCEPT, "body": {}},
        ],
    )
    cases.append(
        _attestation_case(
            "agree_full",
            s,
            {AGENT_A: KP_A, AGENT_B: KP_B},
            kwargs={
                "category": "electronics.cameras",
                "value_range": "1000-5000_USD",
                "resolution_mechanism": ResolutionMechanism.DIRECT,
            },
        )
    )

    # Case 2: REJECTED via DECLINE_SESSION straight from PROPOSED (no terms read
    # past OPEN; terms_count present because OPEN carried terms).
    s = _build_concluded_session(
        "decline_session",
        [
            {"sender": AGENT_A, "type": MessageType.OPEN, "body": OPEN_BODY},
            {"sender": AGENT_B, "type": MessageType.DECLINE_SESSION, "body": {}},
        ],
    )
    cases.append(
        _attestation_case("decline_session", s, {AGENT_A: KP_A, AGENT_B: KP_B})
    )

    # Case 3: AGREED but only ONE agent supplied a key -> the other party gets an
    # empty-string signature. Exercises the keyPairs-miss branch.
    s = _build_concluded_session(
        "partial_keys",
        [
            {"sender": AGENT_A, "type": MessageType.OPEN, "body": OPEN_BODY},
            {"sender": AGENT_B, "type": MessageType.ACCEPT_SESSION, "body": {}},
            {"sender": AGENT_A, "type": MessageType.OFFER, "body": OFFER_BODY_1},
            {"sender": AGENT_B, "type": MessageType.COMMIT, "body": {}},
        ],
    )
    cases.append(
        _attestation_case(
            "partial_keys",
            s,
            {AGENT_A: KP_A},  # B intentionally omitted
            kwargs={"resolution_mechanism": ResolutionMechanism.SPLIT},
        )
    )

    # Case 4: OPEN with NO terms key -> terms is None -> terms_count == 0 ->
    # the `terms_count` key is OMITTED from outcome. Then expire().
    s = Session(session_id="ses_no_terms")
    s.created_at = T0
    s.add_party(AGENT_A, PartyRole.INITIATOR, KP_A.public_key)
    s.add_party(AGENT_B, PartyRole.RESPONDER, KP_B.public_key)
    ph = GENESIS_HASH
    m = _make_msg(
        msg_type=MessageType.OPEN,
        sender_kp=KP_A,
        sender_id=AGENT_A,
        session_id=s.session_id,
        prev_hash=ph,
        body={},  # no terms
    )
    s.apply_message(m, _resolver)
    s.expire()
    s.concluded_at = T0 + timedelta(seconds=3)
    cases.append(
        _attestation_case("expired_no_terms", s, {AGENT_A: KP_A, AGENT_B: KP_B})
    )

    # Case 5: AGREED with attestation-level references[] + validity_temporal
    # (absolute mode). Exercises reference normalization (drop unknown keys,
    # preserve optional keys) and validity_temporal normalization.
    s = _build_concluded_session(
        "with_refs_vt",
        [
            {"sender": AGENT_A, "type": MessageType.OPEN, "body": OPEN_BODY},
            {"sender": AGENT_B, "type": MessageType.ACCEPT_SESSION, "body": {}},
            {"sender": AGENT_A, "type": MessageType.OFFER, "body": OFFER_BODY_1},
            {"sender": AGENT_B, "type": MessageType.ACCEPT, "body": {}},
        ],
    )
    cases.append(
        _attestation_case(
            "with_refs_vt",
            s,
            {AGENT_A: KP_A, AGENT_B: KP_B},
            kwargs={
                "references": [
                    {
                        "type": "receipt",
                        "id": "rcpt_001",
                        "relationship": "fulfills",
                        "version": "1.0",
                        "signer_did": AGENT_A,
                        "ignored_extra_key": "DROP_ME",
                    },
                    {
                        # unknown type + relationship preserved as opaque strings
                        "type": "future_v0x_type",
                        "id": "x_123",
                        "relationship": "future_rel",
                    },
                ],
                "validity_temporal": {
                    "mode": "absolute",
                    "from": "2026-05-29T00:00:00Z",
                    "until": "2026-06-29T00:00:00Z",
                },
            },
        )
    )

    # ------------------------------------------------------------------
    # PARITY-STRICTNESS (codex review 2026-05-29): three malformed-input cases
    # where the TS port was MORE LENIENT than Python. Each case captures
    # Python's exact accept/reject + value/error so the JS side matches.
    # ------------------------------------------------------------------

    # FINDING 1 -- references strictness. Python `generate_attestation` does
    # `if references: [_validate_reference(ref, i) for i, ref in enumerate(...)]`.
    # A present NON-list truthy `references` is iterated (a dict by its KEYS, a
    # string by its CHARS -> each a `str` -> _validate_reference RAISES; a
    # non-iterable int/float/bool -> enumerate RAISES TypeError). An empty
    # dict/list (falsy) yields []. A valid list is validated element-wise.
    reference_strictness_cases = []

    def _ref_case(name, references):
        """Run generate_attestation over a fresh AGREED session with the given
        `references` arg; capture accept (normalized refs) or reject (error)."""
        s_local = _build_concluded_session(
            f"refstrict_{name}",
            [
                {"sender": AGENT_A, "type": MessageType.OPEN, "body": OPEN_BODY},
                {"sender": AGENT_B, "type": MessageType.ACCEPT_SESSION, "body": {}},
                {"sender": AGENT_A, "type": MessageType.OFFER, "body": OFFER_BODY_1},
                {"sender": AGENT_B, "type": MessageType.ACCEPT, "body": {}},
            ],
        )
        entry = {
            "name": name,
            "session": {
                "session_id": s_local.session_id,
                "parties": [
                    {"agent_id": aid, "role": role.value}
                    for aid, role in s_local.parties.items()
                ],
                "transcript": s_local.transcript,
                "created_at_ms": int(T0.timestamp() * 1000),
                "concluded_at_ms": (
                    int(s_local.concluded_at.timestamp() * 1000)
                    if s_local.concluded_at is not None
                    else None
                ),
                "state": s_local.state.value,
            },
            "references": references,
        }
        try:
            r = att.generate_attestation(s_local, {AGENT_A: KP_A, AGENT_B: KP_B}, references=references)
            entry["expected_references"] = r["references"]
            entry["expected_error"] = None
        except Exception as e:  # noqa: BLE001 -- capture ValueError/TypeError text
            entry["expected_references"] = None
            entry["expected_error"] = str(e)
            entry["expected_error_type"] = type(e).__name__
        reference_strictness_cases.append(entry)

    # falsy -> [] (empty list and empty dict are BOTH falsy in Python).
    _ref_case("empty_list", [])
    _ref_case("empty_dict", {})
    _ref_case("none", None)
    # valid list -> validated element-wise.
    _ref_case(
        "valid_list",
        [{"type": "receipt", "id": "r1", "relationship": "fulfills"}],
    )
    # truthy non-list dict -> iterated by KEYS (strings) -> got str.
    _ref_case("nonempty_dict", {"a": 1, "b": 2})
    # truthy non-list string -> iterated by CHARS (strings) -> got str.
    _ref_case("string", "abc")
    # truthy non-sized int -> the L3 count cap's len() RAISES TypeError
    # "object of type 'int' has no len()" BEFORE enumerate is reached.
    _ref_case("int", 5)
    # truthy non-sized float -> "object of type 'float' has no len()".
    _ref_case("float", 1.5)
    # truthy non-sized bool -> "object of type 'bool' has no len()".
    _ref_case("bool_true", True)
    # a list whose element is a non-dict -> _validate_reference RAISES got <type>.
    _ref_case("list_of_int", [7])
    _ref_case("list_of_str", ["x"])
    # --- L3 hardening (Python PR #95): MAX_REFERENCES count cap, checked via
    # len() BEFORE any per-element validation or iteration.
    _ref_case(
        "count_at_cap",
        [{"type": "receipt", "id": f"att_{i:08x}", "relationship": "references"}
         for i in range(32)],
    )
    _ref_case(
        "count_over_cap",
        [{"type": "receipt", "id": f"att_{i:08x}", "relationship": "references"}
         for i in range(33)],
    )
    # A 33-KEY dict: Python len(dict) is its key count, so the COUNT CAP fires
    # before the per-element "got str" rejection -- pins len-before-iteration.
    _ref_case("dict_over_cap", {f"k{i}": i for i in range(33)})

    # FINDING 3 -- terms_count. Python `if session.terms: terms_count =
    # len(session.terms)`. `session.terms` is `body.get("terms")` from the OPEN
    # message, UNVALIDATED, so a malformed value flows in. A truthy non-sized
    # value (int/float/bool) -> len() RAISES TypeError; a truthy string/list ->
    # its len(); a falsy value -> guard skips, terms_count omitted.
    terms_count_cases = []

    def _terms_case(name, open_terms_body):
        """Build a session whose OPEN body carries `open_terms_body`, expire it,
        and capture generate_attestation's accept (outcome) or reject (error)."""
        s_local = Session(session_id=f"ses_terms_{name}")
        s_local.created_at = T0
        s_local.add_party(AGENT_A, PartyRole.INITIATOR, KP_A.public_key)
        s_local.add_party(AGENT_B, PartyRole.RESPONDER, KP_B.public_key)
        m = _make_msg(
            msg_type=MessageType.OPEN,
            sender_kp=KP_A,
            sender_id=AGENT_A,
            session_id=s_local.session_id,
            prev_hash=GENESIS_HASH,
            body=open_terms_body,
        )
        s_local.apply_message(m, _resolver)
        s_local.expire()
        s_local.concluded_at = T0 + timedelta(seconds=3)
        entry = {
            "name": name,
            "session": {
                "session_id": s_local.session_id,
                "parties": [
                    {"agent_id": aid, "role": role.value}
                    for aid, role in s_local.parties.items()
                ],
                "transcript": s_local.transcript,
                "created_at_ms": int(T0.timestamp() * 1000),
                "concluded_at_ms": int(s_local.concluded_at.timestamp() * 1000),
                "state": s_local.state.value,
            },
            # The raw terms value the session ended up holding (diagnostic).
            "session_terms": s_local.terms,
        }
        try:
            r = att.generate_attestation(s_local, {AGENT_A: KP_A, AGENT_B: KP_B})
            entry["expected_terms_count"] = r["outcome"].get("terms_count")
            entry["expected_terms_count_present"] = "terms_count" in r["outcome"]
            entry["expected_error"] = None
        except Exception as e:  # noqa: BLE001
            entry["expected_terms_count"] = None
            entry["expected_terms_count_present"] = None
            entry["expected_error"] = str(e)
            entry["expected_error_type"] = type(e).__name__
        terms_count_cases.append(entry)

    # truthy dict -> key count (2). Uses non-leakable term ids; values are NOT
    # emitted (only the count is), so no privacy concern.
    _terms_case("dict_two", {"terms": {"a": {"v": 1}, "b": {"v": 2}}})
    # truthy string -> char count (3); Python len("abc") == 3.
    _terms_case("string_three", {"terms": "abc"})
    # truthy list -> element count (3). Plain small ints, none leakable.
    _terms_case("list_three", {"terms": [1, 2, 3]})
    # falsy empty dict -> guard skips -> terms_count OMITTED.
    _terms_case("empty_dict", {"terms": {}})
    # absent terms key -> None -> falsy -> OMITTED.
    _terms_case("absent", {})
    # truthy int -> Python len(5) RAISES TypeError 'int' has no len().
    _terms_case("int", {"terms": 7})
    # truthy float -> 'float' has no len().
    _terms_case("float", {"terms": 2.5})
    # truthy bool -> 'bool' has no len().
    _terms_case("bool_true", {"terms": True})

    # ------------------------------------------------------------------
    # L3 meta hardening (Python PR #95): value_range is an enumerated bucket
    # vocabulary + shape-validated currency; category is a capped dotted
    # taxonomy path. Both validated fail-closed at issuance, gated by Python
    # truthiness (falsy -> omitted, not rejected). Errors NEVER echo the
    # invalid input. Each case captures Python's exact accept (meta) or
    # reject (error text) for byte-identical TS replay.
    # ------------------------------------------------------------------
    l3_meta_cases = []
    _OMIT = object()

    def _meta_case(name, *, category=_OMIT, value_range=_OMIT):
        s_local = _build_concluded_session(
            f"l3meta_{name}",
            [
                {"sender": AGENT_A, "type": MessageType.OPEN, "body": OPEN_BODY},
                {"sender": AGENT_B, "type": MessageType.ACCEPT_SESSION, "body": {}},
                {"sender": AGENT_A, "type": MessageType.OFFER, "body": OFFER_BODY_1},
                {"sender": AGENT_B, "type": MessageType.ACCEPT, "body": {}},
            ],
        )
        kwargs = {}
        # `kwargs` carries ONLY the supplied keys, so the JS replay can
        # distinguish "omitted" from "passed None/null" ('category' in kwargs).
        if category is not _OMIT:
            kwargs["category"] = category
        if value_range is not _OMIT:
            kwargs["value_range"] = value_range
        entry = {
            "name": name,
            "session": {
                "session_id": s_local.session_id,
                "parties": [
                    {"agent_id": aid, "role": role.value}
                    for aid, role in s_local.parties.items()
                ],
                "transcript": s_local.transcript,
                "created_at_ms": int(T0.timestamp() * 1000),
                "concluded_at_ms": (
                    int(s_local.concluded_at.timestamp() * 1000)
                    if s_local.concluded_at is not None
                    else None
                ),
                "state": s_local.state.value,
            },
            "kwargs": kwargs,
        }
        try:
            r = att.generate_attestation(
                s_local, {AGENT_A: KP_A, AGENT_B: KP_B}, **kwargs
            )
            entry["expected_meta"] = r["meta"]
            entry["expected_error"] = None
        except (ValueError, TypeError) as e:
            entry["expected_meta"] = None
            entry["expected_error"] = str(e)
            entry["expected_error_type"] = type(e).__name__
        l3_meta_cases.append(entry)

    # Every bucket accepted (with USD), pinning the full vocabulary.
    for bucket in att.VALUE_RANGE_BUCKETS:
        _meta_case(f"bucket_{bucket}", value_range=f"{bucket}_USD")
    # Currency codes are shape-validated, not enumerated.
    for ccy in ("EUR", "JPY", "GBP"):
        _meta_case(f"currency_{ccy}", value_range=f"1000-5000_{ccy}")
    # Free-text deal terms: the L3 exploit itself.
    _meta_case("vr_free_text", value_range="I will pay $4,350 for the camera")
    _meta_case("vr_prose_terms", value_range="price=4350 USD, qty=1, ship to 90210")
    # Exact-price encoding through a range-shaped string.
    _meta_case("vr_exact_price_range", value_range="4350-4351_USD")
    # Non-vocabulary band (previously accepted).
    _meta_case("vr_non_vocab_band", value_range="500-1500_USD")
    # Currency shape violations.
    _meta_case("vr_lowercase_ccy", value_range="1000-5000_usd")
    _meta_case("vr_four_letter_ccy", value_range="1000-5000_USDT")
    _meta_case("vr_no_ccy", value_range="1000-5000")
    _meta_case("vr_space_before_ccy", value_range="1000-5000 USD")
    # Structure violations, incl. the trailing-newline anchor probe: Python
    # uses \Z; the TS port's non-multiline $ must reject identically.
    _meta_case("vr_trailing_newline", value_range="1000-5000_USD\n")
    _meta_case("vr_trailing_space", value_range="1000-5000_USD ")
    _meta_case("vr_leading_space", value_range=" 1000-5000_USD")
    _meta_case("vr_bucket_only", value_range="_USD")
    # Non-string truthy values are REJECTED (no coercion)...
    _meta_case("vr_int", value_range=123)
    _meta_case("vr_list", value_range=["1000-5000_USD"])
    _meta_case("vr_true", value_range=True)
    # ...but FALSY values are SKIPPED by Python's `if value_range:` gate.
    _meta_case("vr_empty_string_skipped", value_range="")
    _meta_case("vr_zero_skipped", value_range=0)
    _meta_case("vr_empty_list_skipped", value_range=[])
    _meta_case("vr_none_skipped", value_range=None)
    # category: taxonomy paths accepted.
    _meta_case("cat_single", category="electronics")
    _meta_case("cat_dotted", category="electronics.cameras.mirrorless")
    _meta_case("cat_hyphen_underscore", category="a_b.c-d.e2")
    _meta_case("cat_at_cap", category="x" * att.MAX_CATEGORY_LENGTH)
    # category: prose and malformed rejected.
    _meta_case("cat_prose", category="Selling 4 units at $1200 each")
    _meta_case("cat_space", category="electronics cameras")
    _meta_case("cat_uppercase", category="Electronics")
    _meta_case("cat_double_dot", category="electronics..cameras")
    _meta_case("cat_leading_dot", category=".electronics")
    _meta_case("cat_trailing_dot", category="electronics.")
    _meta_case("cat_over_cap", category="x" * (att.MAX_CATEGORY_LENGTH + 1))
    _meta_case("cat_trailing_newline", category="electronics\n")
    _meta_case("cat_non_string", category={"a": 1})
    _meta_case("cat_empty_skipped", category="")
    # Both supplied and valid together.
    _meta_case(
        "both_valid",
        category="electronics.cameras",
        value_range="1000-5000_USD",
    )
    # category is validated FIRST (meta build order), so when both are bad
    # the category error text is the one raised -- pins validation order.
    _meta_case(
        "both_invalid_category_first",
        category="Bad Category",
        value_range="bad range",
    )

    # ------------------------------------------------------------------
    # validate_validity_temporal: normalization + error text.
    # ------------------------------------------------------------------
    vt_norm_cases = []

    def _vt_norm(name, vt):
        vt_norm_cases.append(
            {"name": name, "input": vt, "expected": att._validate_validity_temporal(vt)}
        )

    _vt_norm(
        "absolute",
        {"mode": "absolute", "from": "2026-01-01T00:00:00Z", "until": "2026-02-01T00:00:00Z"},
    )
    _vt_norm(
        "relative",
        {"mode": "relative", "from": "2026-01-01T00:00:00Z", "duration_seconds": 3600},
    )
    _vt_norm(
        "window",
        {
            "mode": "window",
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-01-02T00:00:00Z",
            "duration_seconds": 3600,
        },
    )
    # naive (no offset) timestamps -> treated as UTC; still normalizes/round-trips.
    _vt_norm(
        "absolute_naive",
        {"mode": "absolute", "from": "2026-01-01T00:00:00", "until": "2026-02-01T00:00:00"},
    )
    # Alternate VALID ISO-8601 spellings `fromisoformat` accepts -- the strict
    # parser must NOT over-reject these legitimate forms (no regression from the
    # fail-open fix). Explicit +HH:MM offset, +HHMM (no colon) offset, and a
    # comma fractional-second second all parse to real instants in BOTH runtimes.
    _vt_norm(
        "absolute_explicit_offset",
        {
            "mode": "absolute",
            "from": "2026-01-01T00:00:00+00:00",
            "until": "2026-02-01T00:00:00+00:00",
        },
    )
    _vt_norm(
        "absolute_offset_no_colon",
        {
            "mode": "absolute",
            "from": "2026-01-01T00:00:00+0000",
            "until": "2026-02-01T00:00:00+0000",
        },
    )
    _vt_norm(
        "absolute_comma_fraction",
        {
            "mode": "absolute",
            "from": "2026-01-01T00:00:00,500Z",
            "until": "2026-02-01T00:00:00Z",
        },
    )

    vt_error_cases = []

    def _vt_err(name, vt):
        try:
            att._validate_validity_temporal(vt)
            raise AssertionError(f"{name}: expected ValueError")
        except ValueError as e:
            vt_error_cases.append({"name": name, "input": vt, "expected_error": str(e)})

    _vt_err("not_a_dict", "nope")
    _vt_err("bad_mode", {"mode": "bogus"})
    _vt_err("none_mode", {"mode": None})
    _vt_err("absolute_missing", {"mode": "absolute"})
    _vt_err(
        "absolute_until_not_after",
        {"mode": "absolute", "from": "2026-02-01T00:00:00Z", "until": "2026-01-01T00:00:00Z"},
    )
    _vt_err(
        "absolute_equal",
        {"mode": "absolute", "from": "2026-01-01T00:00:00Z", "until": "2026-01-01T00:00:00Z"},
    )
    _vt_err("relative_missing", {"mode": "relative", "from": "2026-01-01T00:00:00Z"})
    _vt_err(
        "relative_zero_duration",
        {"mode": "relative", "from": "2026-01-01T00:00:00Z", "duration_seconds": 0},
    )
    _vt_err(
        "relative_float_duration",
        {"mode": "relative", "from": "2026-01-01T00:00:00Z", "duration_seconds": 1.5},
    )
    _vt_err("window_missing", {"mode": "window", "start": "2026-01-01T00:00:00Z"})
    _vt_err(
        "window_end_not_after",
        {
            "mode": "window",
            "start": "2026-01-02T00:00:00Z",
            "end": "2026-01-01T00:00:00Z",
            "duration_seconds": 60,
        },
    )
    _vt_err(
        "window_duration_exceeds_span",
        {
            "mode": "window",
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-01-01T01:00:00Z",  # 3600s span
            "duration_seconds": 7200,
        },
    )
    # SUB-MILLISECOND span fail-open (fixed 2026-06-01; residual left out of scope
    # by the PR #43 RFC-822 fix). The real span is 0.999001s, so Python compares
    # `1 > (end - start).total_seconds()` == `1 > 0.999001` -> True -> REJECT. A TS
    # port that FLOORS both endpoints to whole epoch ms reads a flat 1.000s span
    # and wrongly ACCEPTS (`1 > 1.0` is False). The fix recomputes the window span
    # at microsecond precision (cpythonIsoDateTimeToEpochMicros). These two cases
    # pin the dot- and comma-fraction spellings -- both reject identically here.
    _vt_err(
        "window_duration_exceeds_span_subms",
        {
            "mode": "window",
            "start": "2026-06-01T00:00:00.000999Z",  # 999 microseconds
            "end": "2026-06-01T00:00:01.000000Z",
            "duration_seconds": 1,  # 0.999001s real span < 1s
        },
    )
    _vt_err(
        "window_duration_exceeds_span_subms_comma",
        {
            "mode": "window",
            "start": "2026-06-01T00:00:00,000999Z",  # comma fractional spelling
            "end": "2026-06-01T00:00:01.000000Z",
            "duration_seconds": 1,
        },
    )
    _vt_err(
        "from_not_string",
        {"mode": "absolute", "from": 123, "until": "2026-02-01T00:00:00Z"},
    )
    # FAIL-OPEN FIX (2026-06-01): RFC-822 / RFC-1123 / locale date spellings that
    # JS `Date.parse` ACCEPTS but Python `datetime.fromisoformat` REJECTS with a
    # ValueError. The strict parser must reject these too (fail-CLOSED, Python
    # parity) so the TS SDK never honors a `validity_temporal` timestamp the
    # reference rejects. Each raises the "is not a valid ISO 8601 timestamp:"
    # prefix; the detail half is implementation-specific and not asserted.
    _vt_err(
        "absolute_rfc822_from",
        {
            "mode": "absolute",
            "from": "Mon, 01 Jun 2026 00:00:00 GMT",
            "until": "2026-07-01T00:00:00Z",
        },
    )
    _vt_err(
        "absolute_rfc1123_until",
        {
            "mode": "absolute",
            "from": "2026-06-01T00:00:00Z",
            "until": "Wed, 01 Jul 2026 00:00:00 GMT",
        },
    )
    _vt_err(
        "relative_locale_month_name",
        {"mode": "relative", "from": "June 1, 2026", "duration_seconds": 3600},
    )
    _vt_err(
        "window_slash_date_start",
        {
            "mode": "window",
            "start": "2026/06/01",
            "end": "2026-06-02T00:00:00Z",
            "duration_seconds": 60,
        },
    )

    # ------------------------------------------------------------------
    # is_valid_now: temporal containment.
    # ------------------------------------------------------------------
    valid_now_cases = []

    def _valid_now(name, attestation_obj, now_iso):
        now_dt = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
        valid_now_cases.append(
            {
                "name": name,
                "attestation": attestation_obj,
                "now_iso": now_iso,
                "now_ms": int(now_dt.timestamp() * 1000),
                "expected": att.is_valid_now(attestation_obj, now_dt),
            }
        )

    ABS = {
        "validity_temporal": {
            "mode": "absolute",
            "from": "2026-01-01T00:00:00Z",
            "until": "2026-02-01T00:00:00Z",
        }
    }
    _valid_now("absolute_inside", ABS, "2026-01-15T00:00:00Z")
    _valid_now("absolute_before", ABS, "2025-12-31T23:59:59Z")
    _valid_now("absolute_after", ABS, "2026-02-01T00:00:01Z")
    _valid_now("absolute_at_from", ABS, "2026-01-01T00:00:00Z")  # inclusive
    _valid_now("absolute_at_until", ABS, "2026-02-01T00:00:00Z")  # exclusive

    REL = {
        "validity_temporal": {
            "mode": "relative",
            "from": "2026-01-01T00:00:00Z",
            "duration_seconds": 86400,
        }
    }
    _valid_now("relative_inside", REL, "2026-01-01T12:00:00Z")
    _valid_now("relative_after", REL, "2026-01-02T00:00:01Z")

    WIN = {
        "validity_temporal": {
            "mode": "window",
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-01-02T00:00:00Z",
            "duration_seconds": 3600,
        }
    }
    _valid_now("window_fits", WIN, "2026-01-01T12:00:00Z")
    _valid_now("window_tail_too_short", WIN, "2026-01-01T23:30:00Z")  # <3600s left
    _valid_now("window_before", WIN, "2025-12-31T00:00:00Z")

    _valid_now("no_constraint", {}, "2026-01-01T00:00:00Z")
    _valid_now("vt_not_dict", {"validity_temporal": "nope"}, "2026-01-01T00:00:00Z")
    _valid_now("vt_no_mode", {"validity_temporal": {}}, "2026-01-01T00:00:00Z")
    _valid_now(
        "vt_unknown_mode",
        {"validity_temporal": {"mode": "weird"}},
        "2026-01-01T00:00:00Z",
    )

    # FINDING 2 -- is_valid_now duration_seconds uses Python int(...) at lines
    # 141/155 (NOT the TS-lenient Number(...)). is_valid_now does NOT re-run the
    # validator, so a hand-built attestation can carry a FRACTIONAL or STRING
    # duration. Python int() truncates a float toward zero and parses an
    # integer-formatted string. These cases still return a boolean (no raise).
    REL_FRAC = {
        "validity_temporal": {
            "mode": "relative",
            "from": "2026-01-01T00:00:00Z",
            "duration_seconds": 86400.9,  # int(86400.9) == 86400
        }
    }
    # at from+86400s exactly: until == that instant -> exclusive -> False.
    _valid_now("relative_frac_at_trunc_boundary", REL_FRAC, "2026-01-02T00:00:00Z")
    # one second before the truncated boundary -> inside -> True.
    _valid_now("relative_frac_inside", REL_FRAC, "2026-01-01T23:59:59Z")
    # integer-formatted string duration -> int("86400") == 86400.
    REL_STR = {
        "validity_temporal": {
            "mode": "relative",
            "from": "2026-01-01T00:00:00Z",
            "duration_seconds": "86400",
        }
    }
    _valid_now("relative_str_int_inside", REL_STR, "2026-01-01T12:00:00Z")
    # window fractional duration -> int(3600.9) == 3600.
    WIN_FRAC = {
        "validity_temporal": {
            "mode": "window",
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-01-02T00:00:00Z",
            "duration_seconds": 3600.9,
        }
    }
    _valid_now("window_frac_fits", WIN_FRAC, "2026-01-01T12:00:00Z")
    # window string-int duration.
    WIN_STR = {
        "validity_temporal": {
            "mode": "window",
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-01-02T00:00:00Z",
            "duration_seconds": "3600",
        }
    }
    _valid_now("window_str_int_fits", WIN_STR, "2026-01-01T12:00:00Z")
    # window mode SHORT-CIRCUITS before reading duration when now is outside the
    # [start, end] range -> a bad duration is NOT evaluated -> returns False
    # WITHOUT raising. Parity-critical: the int() coercion must sit AFTER the
    # range check, exactly as Python.
    WIN_BAD_DUR_OUTSIDE = {
        "validity_temporal": {
            "mode": "window",
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-01-02T00:00:00Z",
            "duration_seconds": "not-a-number",
        }
    }
    _valid_now("window_bad_dur_but_now_before", WIN_BAD_DUR_OUTSIDE, "2025-12-31T00:00:00Z")

    # is_valid_now cases where Python's int(duration_seconds) RAISES (a
    # non-integer-formatted string -> ValueError; None -> TypeError). The TS
    # port must REJECT here, not silently coerce (Number("xyz") -> NaN).
    valid_now_error_cases = []

    def _valid_now_err(name, attestation_obj, now_iso):
        now_dt = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
        try:
            att.is_valid_now(attestation_obj, now_dt)
            raise AssertionError(f"{name}: expected int()-coercion error")
        except (ValueError, TypeError) as e:
            valid_now_error_cases.append(
                {
                    "name": name,
                    "attestation": attestation_obj,
                    "now_iso": now_iso,
                    "now_ms": int(now_dt.timestamp() * 1000),
                    "expected_error": str(e),
                    "expected_error_type": type(e).__name__,
                }
            )

    # relative, non-numeric string -> int("abc") ValueError. `now` is inside the
    # range concept but int() is read unconditionally for relative mode.
    _valid_now_err(
        "relative_str_bad",
        {
            "validity_temporal": {
                "mode": "relative",
                "from": "2026-01-01T00:00:00Z",
                "duration_seconds": "abc",
            }
        },
        "2026-01-01T12:00:00Z",
    )
    # relative, float-formatted string -> int("1.5") ValueError.
    _valid_now_err(
        "relative_str_float",
        {
            "validity_temporal": {
                "mode": "relative",
                "from": "2026-01-01T00:00:00Z",
                "duration_seconds": "1.5",
            }
        },
        "2026-01-01T00:00:00.5Z",
    )
    # relative, None -> int(None) TypeError.
    _valid_now_err(
        "relative_none",
        {
            "validity_temporal": {
                "mode": "relative",
                "from": "2026-01-01T00:00:00Z",
                "duration_seconds": None,
            }
        },
        "2026-01-01T12:00:00Z",
    )
    # window, bad string -- but now MUST be inside [start, end] so the duration
    # read is reached (outside short-circuits before the read, see case above).
    _valid_now_err(
        "window_str_bad_now_inside",
        {
            "validity_temporal": {
                "mode": "window",
                "start": "2026-01-01T00:00:00Z",
                "end": "2026-01-02T00:00:00Z",
                "duration_seconds": "xyz",
            }
        },
        "2026-01-01T12:00:00Z",
    )

    # ------------------------------------------------------------------
    # generate_receipt_summary: standalone formatting cases.
    # ------------------------------------------------------------------
    summary_cases = []

    def _summary(name, receipt):
        summary_cases.append(
            {"name": name, "receipt": receipt, "expected": att.generate_receipt_summary(receipt)}
        )

    _summary(
        "two_parties_category",
        {
            "parties": [{"agent_id": AGENT_A}, {"agent_id": AGENT_B}],
            "meta": {"category": "electronics"},
            "outcome": {"status": "agreed"},
            "transcript_hash": "sha256:" + ("a" * 64),
        },
    )
    _summary(
        "one_party_no_topic",
        {
            "parties": [{"agent_id": "short"}],
            "meta": {},
            "outcome": {"status": "rejected"},
            "transcript_hash": "sha256:" + ("b" * 64),
        },
    )
    _summary(
        "empty_did_and_no_status",
        {
            "parties": [{"agent_id": ""}, {"agent_id": ""}],
            "meta": {},
            "outcome": {},
            "transcript_hash": "",
        },
    )
    _summary(
        "topic_fallback_to_topic_key",
        {
            "parties": [],
            "meta": {"topic": "fallback-topic"},
            "outcome": {"status": "expired"},
            "transcript_hash": "noprefix" + ("c" * 16),
        },
    )
    _summary(
        "long_did_truncation",
        {
            "parties": [
                {"agent_id": "did:concordia:agent:verylongidentifier"},
                {"agent_id": "x" * 17},
            ],
            "meta": {"category": ""},  # empty -> falls through to N/A
            "outcome": {"status": "agreed"},
            "transcript_hash": "sha256:" + ("d" * 64),
        },
    )

    doc = {
        "_comment": (
            "Generated by js-sdk/scripts/gen-attestation-fixtures.py from "
            "concordia.attestation driven over concordia.session. Attestations, "
            "per-party Ed25519 signatures, normalized temporal objects, error "
            "text, and summaries are Python-produced; do not edit by hand."
        ),
        "seeds": {
            "agent_a": {"id": AGENT_A, "seed_hex": SEED_A.hex(), "public_key_b64": KP_A.public_key_b64()},
            "agent_b": {"id": AGENT_B, "seed_hex": SEED_B.hex(), "public_key_b64": KP_B.public_key_b64()},
        },
        "public_keys_b64": _key_b64_map(),
        "attestation_version": att.ATTESTATION_VERSION,
        "leakable_term_values": LEAKABLE_TERM_VALUES,
        "cases": cases,
        "vt_norm_cases": vt_norm_cases,
        "vt_error_cases": vt_error_cases,
        "valid_now_cases": valid_now_cases,
        "valid_now_error_cases": valid_now_error_cases,
        "summary_cases": summary_cases,
        # Parity-strictness (codex review 2026-05-29): the three malformed-input
        # findings where TS was more lenient than Python.
        "reference_strictness_cases": reference_strictness_cases,
        "terms_count_cases": terms_count_cases,
        # L3 meta hardening (Python PR #95): value_range bucket vocabulary +
        # category taxonomy, captured accept/reject from the Python reference.
        "l3_meta_cases": l3_meta_cases,
    }

    json.dump(doc, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
