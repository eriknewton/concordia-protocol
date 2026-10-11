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

import copy
import json
import sys
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia import attestation as att
from concordia import signing
from concordia.schema_validator import validate_attestation
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


def _attestation_reason_class(errors: list[str]) -> str | None:
    if not errors:
        return None
    if any("draft-newton-agreement-evidence-00 version grammar" in error for error in errors):
        return "version_grammar"
    if any("draft-newton-agreement-evidence-00 structure" in error for error in errors):
        return "draft_structure"
    if any("free-text field must not contain obvious raw deal terms" in error for error in errors):
        return "privacy"
    return "schema"


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

    # Case 3: AGREED with split resolution. Since attestation 0.6.0, every
    # listed party must have a signing key; the keyless refusal is covered by a
    # dedicated JS test rather than a successful fixture case.
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
            "split_resolution",
            s,
            {AGENT_A: KP_A, AGENT_B: KP_B},
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
    _vt_err(
        "from_not_string",
        {"mode": "absolute", "from": 123, "until": "2026-02-01T00:00:00Z"},
    )
    _vt_err(
        "absolute_naive",
        {"mode": "absolute", "from": "2026-01-01T00:00:00", "until": "2026-02-01T00:00:00"},
    )
    _vt_err(
        "absolute_explicit_offset",
        {
            "mode": "absolute",
            "from": "2026-01-01T00:00:00+00:00",
            "until": "2026-02-01T00:00:00+00:00",
        },
    )
    _vt_err(
        "absolute_offset_no_colon",
        {
            "mode": "absolute",
            "from": "2026-01-01T00:00:00+0000",
            "until": "2026-02-01T00:00:00+0000",
        },
    )
    _vt_err(
        "absolute_comma_fraction",
        {
            "mode": "absolute",
            "from": "2026-01-01T00:00:00,500Z",
            "until": "2026-02-01T00:00:00Z",
        },
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
        "absolute_over_reference_maximum",
        {
            "mode": "absolute",
            "from": "2026-01-01T00:00:00Z",
            "until": "2026-04-02T00:00:01Z",
        },
    )
    _vt_err(
        "relative_over_reference_maximum",
        {
            "mode": "relative",
            "from": "2026-01-01T00:00:00Z",
            "duration_seconds": 7_776_001,
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
    _valid_now("absolute_at_until", ABS, "2026-02-01T00:00:00Z")  # inclusive

    REL = {
        "validity_temporal": {
            "mode": "relative",
            "from": "2026-01-01T00:00:00Z",
            "duration_seconds": 86400,
        }
    }
    _valid_now("relative_inside", REL, "2026-01-01T12:00:00Z")
    _valid_now("relative_after", REL, "2026-01-02T00:00:01Z")

    _valid_now("no_constraint", {}, "2026-01-01T00:00:00Z")
    _valid_now(
        "v05_missing_required_constraint",
        {"concordia_attestation": "0.5.0"},
        "2026-01-01T00:00:00Z",
    )
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
        "2026-01-01T00:00:00.500Z",
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

    # ------------------------------------------------------------------
    # Attestation validation mutation corpus. Every verdict is produced by
    # Python `validate_attestation`; JS consumes the same vectors and compares
    # accept/reject plus the reason class. This deliberately covers the fields
    # read by the 0.6.0 draft-structure companion, not only JSON Schema.
    # ------------------------------------------------------------------
    base_attestation = copy.deepcopy(
        next(case["expected"] for case in cases if case["name"] == "with_refs_vt")
    )
    mutation_corpus = []

    def _add_mutation(name: str, mutate, note: str = "") -> None:
        candidate = copy.deepcopy(base_attestation)
        mutate(candidate)
        errors = validate_attestation(candidate)
        if name.endswith("_python_accept") and errors:
            raise AssertionError(f"{name} must be accepted by Python: {errors}")
        mutation_corpus.append(
            {
                "name": name,
                "input": candidate,
                "expected": "accept" if not errors else "reject",
                "expected_reason_class": _attestation_reason_class(errors),
                "expected_errors": errors,
                "note": note,
            }
        )

    def _refresh_party_countersignatures(candidate: dict) -> None:
        countersignatures = {}
        for index, party in enumerate(candidate["parties"]):
            agent_id = party.get("agent_id")
            if not isinstance(agent_id, str) or agent_id in countersignatures:
                continue
            key_pair = (KP_A, KP_B)[index]
            countersignatures[agent_id] = att.countersign_attestation(candidate, key_pair)
        candidate["countersignatures"] = countersignatures

    def _set_party_agent_id(candidate: dict, index: int, agent_id: str) -> None:
        candidate["parties"][index]["agent_id"] = agent_id
        _refresh_party_countersignatures(candidate)

    def _duplicate_party_agent_id(candidate: dict) -> None:
        candidate["parties"][1]["agent_id"] = candidate["parties"][0]["agent_id"]
        _refresh_party_countersignatures(candidate)

    def _set_version_with_duplicate_party(candidate: dict, version: str) -> None:
        candidate["concordia_attestation"] = version
        _duplicate_party_agent_id(candidate)

    def _set_version_and_mutate(candidate: dict, version: str, mutate) -> None:
        candidate["concordia_attestation"] = version
        mutate(candidate)

    def _add_root_fulfillment(candidate: dict) -> None:
        candidate["fulfillment"] = None

    def _set_validity_window_mode(candidate: dict) -> None:
        candidate["validity_temporal"] = {
            "mode": "window",
            "from": "2026-01-01T00:00:00Z",
            "until": "2026-01-02T00:00:00Z",
        }

    def _add_reference_extensions(candidate: dict) -> None:
        candidate["references"][0]["extensions"] = {}

    _add_mutation("valid_baseline", lambda _: None)

    for key in (
        "concordia_attestation",
        "attestation_id",
        "session_id",
        "timestamp",
        "outcome",
        "parties",
        "meta",
        "transcript_hash",
        "chain_head",
        "message_count",
        "validity_temporal",
        "countersignatures",
        "summary",
        "references",
    ):
        _add_mutation(f"root_remove_{key}", lambda a, k=key: a.pop(k, None))
    _add_mutation("root_extra_member", lambda a: a.__setitem__("extra_member", True))

    _add_mutation("attestation_id_256_ascii_octets", lambda a: a.__setitem__("attestation_id", "a" * 256))
    _add_mutation("attestation_id_257_ascii_octets", lambda a: a.__setitem__("attestation_id", "a" * 257))
    _add_mutation("session_id_85_cjk_255_octets", lambda a: a.__setitem__("session_id", "界" * 85))
    _add_mutation("session_id_86_cjk_258_octets", lambda a: a.__setitem__("session_id", "界" * 86))
    _add_mutation("attestation_id_non_nfc", lambda a: a.__setitem__("attestation_id", "att_e\u0301"))
    _add_mutation("attestation_id_lone_surrogate", lambda a: a.__setitem__("attestation_id", "att_\ud800"))
    _add_mutation("attestation_id_zero_width", lambda a: a.__setitem__("attestation_id", "att_\u200b"))
    _add_mutation("attestation_id_bidi_override", lambda a: a.__setitem__("attestation_id", "att_\u202e"))
    _add_mutation(
        "attestation_id_bom_python_accept",
        lambda a: a.__setitem__("attestation_id", "att_\ufeff"),
        "Python's whitespace predicate does not classify U+FEFF as whitespace.",
    )

    for version in ("0.5.0", "0.5.9", "0.6.0", "0.6.1", "1.0.0", "00.6.0", "0.6.0\n", "bogus"):
        _add_mutation(
            "version_" + version.encode("unicode_escape").decode("ascii").replace("\\", "_"),
            lambda a, v=version: a.__setitem__("concordia_attestation", v),
        )
    _add_mutation(
        "version_0.6.1_duplicate_party_ids",
        lambda a: _set_version_with_duplicate_party(a, "0.6.1"),
    )
    _add_mutation(
        "version_1.0.0_duplicate_party_ids",
        lambda a: _set_version_with_duplicate_party(a, "1.0.0"),
    )

    for digits in range(1, 10):
        frac = "1" * digits
        _add_mutation(
            f"timestamp_fraction_{digits}",
            lambda a, f=frac: a.__setitem__("timestamp", f"2026-05-29T12:00:00.{f}Z"),
        )
    _add_mutation("timestamp_no_fraction", lambda a: a.__setitem__("timestamp", "2026-05-29T12:00:00Z"))

    _add_mutation("outcome_remove_status", lambda a: a["outcome"].pop("status", None))
    _add_mutation("outcome_extra_member", lambda a: a["outcome"].__setitem__("extra", True))
    _add_mutation("outcome_rounds_float", lambda a: a["outcome"].__setitem__("rounds", 1.5))
    _add_mutation("outcome_terms_count_zero", lambda a: a["outcome"].__setitem__("terms_count", 0))

    _add_mutation("parties_remove_agent_id", lambda a: a["parties"][0].pop("agent_id", None))
    _add_mutation("parties_extra_member", lambda a: a["parties"][0].__setitem__("extra", True))
    _add_mutation("parties_duplicate_agent_ids", _duplicate_party_agent_id)
    _add_mutation("party_agent_id_256_ascii_octets", lambda a: _set_party_agent_id(a, 0, "p" * 256))
    _add_mutation("party_agent_id_257_ascii_octets", lambda a: _set_party_agent_id(a, 0, "p" * 257))
    _add_mutation("party_agent_id_zero_width", lambda a: _set_party_agent_id(a, 0, "agent\u200b"))
    _add_mutation("party_agent_id_bom_python_accept", lambda a: _set_party_agent_id(a, 0, "agent\ufeff"))
    _add_mutation("party_signature_noncanonical_final", lambda a: a["parties"][0].__setitem__("signature", a["parties"][0]["signature"][:85] + "B=="))
    _add_mutation("party_signature_canonical_final_A", lambda a: a["parties"][0].__setitem__("signature", a["parties"][0]["signature"][:85] + "A=="))

    _add_mutation("meta_extra_member", lambda a: a["meta"].__setitem__("extra", True))
    _add_mutation("meta_extensions_used_at_cap", lambda a: a["meta"].__setitem__("extensions_used", [f"e{i}" for i in range(16)]))
    _add_mutation("meta_extensions_used_over_cap", lambda a: a["meta"].__setitem__("extensions_used", [f"e{i}" for i in range(17)]))
    _add_mutation("meta_extension_64_octets", lambda a: a["meta"].__setitem__("extensions_used", ["e" * 64]))
    _add_mutation("meta_extension_65_octets", lambda a: a["meta"].__setitem__("extensions_used", ["e" * 65]))

    _add_mutation("root_add_fulfillment", _add_root_fulfillment)
    for version in ("0.4.0", "0.5.0"):
        version_name = version.replace(".", "_")
        _add_mutation(
            f"version_{version_name}_root_add_fulfillment",
            lambda a, v=version: _set_version_and_mutate(a, v, _add_root_fulfillment),
        )
    _add_mutation("reference_extra_member", lambda a: a["references"][0].__setitem__("extra", True))
    _add_mutation("reference_add_extensions", _add_reference_extensions)
    for version in ("0.4.0", "0.5.0"):
        version_name = version.replace(".", "_")
        _add_mutation(
            f"version_{version_name}_reference_add_extensions",
            lambda a, v=version: _set_version_and_mutate(a, v, _add_reference_extensions),
        )
    _add_mutation("reference_extra_and_missing_order", lambda a: (a["references"][0].pop("type", None), a["references"][0].__setitem__("extra", True)))
    _add_mutation("reference_remove_type", lambda a: a["references"][0].pop("type", None))
    _add_mutation("reference_id_256_ascii_octets", lambda a: a["references"][0].__setitem__("id", "r" * 256))
    _add_mutation("reference_id_257_ascii_octets", lambda a: a["references"][0].__setitem__("id", "r" * 257))
    _add_mutation("reference_id_85_cjk_255_octets", lambda a: a["references"][0].__setitem__("id", "界" * 85))
    _add_mutation("reference_id_86_cjk_258_octets", lambda a: a["references"][0].__setitem__("id", "界" * 86))
    _add_mutation("reference_id_non_nfc", lambda a: a["references"][0].__setitem__("id", "ref_e\u0301"))
    _add_mutation("reference_id_lone_surrogate", lambda a: a["references"][0].__setitem__("id", "ref_\ud800"))
    _add_mutation("reference_id_zero_width", lambda a: a["references"][0].__setitem__("id", "ref\u200b"))
    _add_mutation("reference_id_bidi_override", lambda a: a["references"][0].__setitem__("id", "ref\u202e"))
    _add_mutation("reference_id_bom_python_accept", lambda a: a["references"][0].__setitem__("id", "ref\ufeff"))
    for digits in range(1, 10):
        frac = "1" * digits
        _add_mutation(
            f"reference_signed_at_fraction_{digits}",
            lambda a, f=frac: a["references"][0].__setitem__("signed_at", f"2026-05-29T12:00:00.{f}Z"),
        )

    _add_mutation(
        "validity_absolute_at_reference_cap",
        lambda a: a.__setitem__(
            "validity_temporal",
            {"mode": "absolute", "from": "2026-01-01T00:00:00Z", "until": "2026-04-01T00:00:00Z"},
        ),
    )
    _add_mutation(
        "validity_absolute_past_reference_cap_python_accept",
        lambda a: a.__setitem__(
            "validity_temporal",
            {"mode": "absolute", "from": "2026-01-01T00:00:00Z", "until": "2026-04-01T00:00:01Z"},
        ),
        "Python's draft-structure path caps relative lifetimes only.",
    )
    _add_mutation(
        "validity_relative_at_reference_cap",
        lambda a: a.__setitem__(
            "validity_temporal",
            {"mode": "relative", "from": "2026-01-01T00:00:00Z", "duration_seconds": 7_776_000},
        ),
    )
    _add_mutation(
        "validity_relative_past_reference_cap",
        lambda a: a.__setitem__(
            "validity_temporal",
            {"mode": "relative", "from": "2026-01-01T00:00:00Z", "duration_seconds": 7_776_001},
        ),
    )
    _add_mutation("validity_window_mode", _set_validity_window_mode)
    for version in ("0.4.0", "0.5.0"):
        version_name = version.replace(".", "_")
        _add_mutation(
            f"version_{version_name}_validity_window_mode",
            lambda a, v=version: _set_version_and_mutate(a, v, _set_validity_window_mode),
        )

    _add_mutation("countersignature_remove_signer", lambda a: a["countersignatures"].pop(a["parties"][0]["agent_id"], None))
    _add_mutation("countersignature_extra_signer", lambda a: a["countersignatures"].__setitem__("did:concordia:agent:gamma", a["countersignatures"][a["parties"][0]["agent_id"]]))
    _add_mutation("countersignature_name_bidi", lambda a: a["countersignatures"].__setitem__("did:concordia:agent:\u202egamma", a["countersignatures"].pop(a["parties"][0]["agent_id"])))
    _add_mutation("countersignature_value_noncanonical_final", lambda a: a["countersignatures"].__setitem__(a["parties"][0]["agent_id"], a["countersignatures"][a["parties"][0]["agent_id"]][:85] + "B=="))

    issuance_reference_cases = []

    def _issuance_ref_case(name: str, references) -> None:
        s_local = _build_concluded_session(
            f"issueref_{name}",
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
                "concluded_at_ms": int(s_local.concluded_at.timestamp() * 1000),
                "state": s_local.state.value,
            },
            "references": references,
        }
        try:
            r = att.generate_attestation(
                s_local,
                {AGENT_A: KP_A, AGENT_B: KP_B},
                references=references,
            )
            validation_errors = validate_attestation(r)
            entry["expected_references"] = r["references"]
            entry["expected_error"] = None
            entry["expected_validate_errors"] = validation_errors
            entry["expected_validate_reason_class"] = _attestation_reason_class(validation_errors)
        except Exception as e:  # noqa: BLE001
            entry["expected_references"] = None
            entry["expected_error"] = str(e)
            entry["expected_error_type"] = type(e).__name__
            entry["expected_validate_errors"] = None
            entry["expected_validate_reason_class"] = None
        issuance_reference_cases.append(entry)

    _issuance_ref_case(
        "bom_id_round_trips_to_validator",
        [{"type": "receipt", "id": "ref\ufeff", "relationship": "fulfills"}],
    )
    _issuance_ref_case(
        "extra_and_missing_reports_extra_first",
        [{"id": "ref_extra_missing", "relationship": "fulfills", "extra": True}],
    )
    _issuance_ref_case(
        "reference_extensions_rejected_by_shared_parser",
        [{"type": "receipt", "id": "ref_extensions", "relationship": "fulfills", "extensions": {}}],
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
        "mutation_corpus": mutation_corpus,
        "issuance_reference_cases": issuance_reference_cases,
    }

    # The mutation corpus intentionally includes escaped lone-surrogate cases;
    # ensure_ascii=True keeps those vectors representable as JSON bytes.
    json.dump(doc, sys.stdout, ensure_ascii=True, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
