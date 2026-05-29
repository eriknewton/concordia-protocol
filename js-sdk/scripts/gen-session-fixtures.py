#!/usr/bin/env python3
"""Generate session-lifecycle parity fixtures FROM the Concordia Python reference.

Run from the repo root (or anywhere with `concordia` importable). Emits a JSON
document to stdout. The JS test suite (tests/session.test.ts) replays these
Python-produced runs against the TypeScript `Session` and asserts byte-level
parity of: the transition table, every applied-message outcome (state,
round_count, prev_hash, behavior records + their `to_dict()`, duration),
invalid-transition and invalid-signature error text, the `MessageType(...)`
enum-coercion error text, expire/make_dormant outcomes, the `_compute_concession`
arithmetic, and `compute_hash` / `validate_chain`.

This is the parity source of truth: every state, hash, signature, and error
string here comes straight from `concordia.session` / `concordia.message` /
`concordia.signing`, never hand-authored. Messages are real signed envelopes
(the same field shape `concordia.message.build_envelope` produces, signed with
`sign_message` over deterministic seeded keys, with a fixed timestamp and
sequential ids for full reproducibility), so the JS suite verifies the SAME
Python signatures with the SAME keys. Synced into the JS test surface by
scripts/sync-fixtures-from-python.mjs.

Imports `cryptography` (the signing dep). Run under python3.12 (the same Python
the rest of the engine fixtures target) unless PYTHON is overridden.
"""

from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concordia import signing
from concordia.message import (
    GENESIS_HASH,
    compute_hash,
    validate_chain,
)
from concordia.session import (
    InvalidSignatureError,
    InvalidTransitionError,
    Session,
    _TRANSITIONS,
)
from concordia.types import (
    AgentIdentity,
    MessageType,
    PartyRole,
    SessionState,
)


# Deterministic seeds so the fixtures are reproducible across runs and machines.
SEED_A = bytes(range(32))
SEED_B = bytes(range(100, 132))
SEED_UNKNOWN = bytes(range(200, 232))


def _kp_from_seed(seed: bytes) -> signing.KeyPair:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return signing.KeyPair(private_key=sk, public_key=sk.public_key())


KP_A = _kp_from_seed(SEED_A)
KP_B = _kp_from_seed(SEED_B)
KP_UNKNOWN = _kp_from_seed(SEED_UNKNOWN)

AGENT_A = "did:concordia:agent:alpha"
AGENT_B = "did:concordia:agent:beta"

KEYS = {
    AGENT_A: KP_A,
    AGENT_B: KP_B,
}

# A frozen clock anchor so durations are deterministic. The JS suite drives the
# Session with the SAME injected clock values.
T0 = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)
T0_MS = int(T0.timestamp() * 1000)


def _resolver(agent_id: str):
    kp = KEYS.get(agent_id)
    return kp.public_key if kp else None


# Deterministic message-id counter. `build_envelope` defaults to a random
# uuid4-based id, which would make every signature (and thus every hash) differ
# on each run and break fixture reproducibility. We supply sequential ids so the
# generated document is byte-stable across runs and machines.
_MSG_COUNTER = {"n": 0}


def _next_msg_id() -> str:
    _MSG_COUNTER["n"] += 1
    return f"msg_{_MSG_COUNTER['n']:08d}"


def _behavior_block(session: Session) -> dict:
    """Capture every agent's raw BehaviorRecord fields + its to_dict()."""
    out = {}
    for agent_id in session.parties:
        b = session.get_behavior(agent_id)
        out[agent_id] = {
            "raw": {
                "offers_made": b.offers_made,
                "concessions": b.concessions,
                "concession_magnitude": b.concession_magnitude,
                "signals_shared": b.signals_shared,
                "constraints_declared": b.constraints_declared,
                "constraints_violated": b.constraints_violated,
                "reasoning_provided": b.reasoning_provided,
                "withdrawal": b.withdrawal,
                "response_time_avg_seconds": b.response_time_avg_seconds,
            },
            "to_dict": b.to_dict(),
        }
    return out


def _make_msg(
    *,
    msg_type: MessageType,
    sender_kp: signing.KeyPair,
    sender_id: str,
    session_id: str,
    prev_hash: str,
    body: dict,
    reasoning: str | None = None,
) -> dict:
    # Replicate `build_envelope`'s field shape with a FIXED timestamp + a
    # deterministic id, then sign with the same `sign_message` primitive
    # `build_envelope` uses. `build_envelope` stamps `datetime.now()`, which would
    # make signatures/hashes differ on each run; pinning the timestamp here makes
    # the fixture fully reproducible while preserving the exact envelope shape.
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


def _build_run(name: str, steps: list[dict], add_b: bool = True) -> dict:
    """Drive a fresh Session through `steps`, capturing a snapshot per step.

    Each step is {"sender": agent_id, "type": MessageType, "body": dict,
    optional "reasoning"}. The clock advances 1s per step so durationSeconds is
    deterministic and non-trivial.
    """
    # Python's Session has no injectable clock, so we pin created_at after
    # construction and overwrite concluded_at to a deterministic offset; the JS
    # suite injects a clock returning the same values, reproducing Python's
    # `max(0, int((concluded - created).total_seconds()))`.
    session = Session(session_id=f"ses_{name}")
    # Pin created_at deterministically.
    session.created_at = T0
    session.add_party(AGENT_A, PartyRole.INITIATOR, KP_A.public_key)
    if add_b:
        session.add_party(AGENT_B, PartyRole.RESPONDER, KP_B.public_key)

    prev_hash = GENESIS_HASH
    step_snapshots = []
    transcript_for_chain = []
    for i, step in enumerate(steps):
        sender_id = step["sender"]
        sender_kp = KEYS[sender_id]
        msg = _make_msg(
            msg_type=step["type"],
            sender_kp=sender_kp,
            sender_id=sender_id,
            session_id=session.session_id,
            prev_hash=prev_hash,
            body=step.get("body", {}),
            reasoning=step.get("reasoning"),
        )
        # Pin concluded_at deterministically: i+1 seconds after T0.
        new_state = session.apply_message(msg, _resolver)
        # If this step concluded the session, fix concluded_at to a deterministic
        # value (T0 + (i+1) seconds) so duration is reproducible.
        if session.concluded_at is not None:
            from datetime import timedelta

            session.concluded_at = T0 + timedelta(seconds=i + 1)
        prev_hash = compute_hash(msg)
        transcript_for_chain.append(msg)
        step_snapshots.append(
            {
                "message": msg,
                "expected_state": new_state.value,
                "round_count": session.round_count,
                "prev_hash": session.prev_hash,
                "behaviors": _behavior_block(session),
                "terms": session.terms,
                "is_terminal": session.is_terminal,
            }
        )

    # Duration is deterministic only when the session concluded (concluded_at was
    # pinned above). For an ongoing session `duration_seconds()` reads the wall
    # clock, which is not reproducible, so we emit null and the JS suite skips the
    # duration assertion for it. When concluded, duration == (terminal step index
    # + 1), reproduced by a 2-value clock queue on the JS side.
    duration = session.duration_seconds() if session.concluded_at is not None else None

    return {
        "name": name,
        "session_id": session.session_id,
        "add_b": add_b,
        "steps": step_snapshots,
        "final_state": session.state.value,
        "round_count": session.round_count,
        "concluded": session.concluded_at is not None,
        "duration_seconds": duration,
        "transcript_valid_chain": validate_chain(transcript_for_chain),
    }


# Term-space bodies used across runs.
OPEN_BODY = {
    "terms": {
        "price": {"type": "numeric", "value": 1000},
        "qty": {"type": "numeric", "value": 10},
    }
}
OFFER_BODY_1 = {"terms": {"price": {"value": 1000}, "qty": {"value": 10}}}
OFFER_BODY_2 = {"terms": {"price": {"value": 900}, "qty": {"value": 10}}}
OFFER_BODY_3 = {"terms": {"price": {"value": 850}, "qty": {"value": 12}}}


def main() -> None:
    # ------------------------------------------------------------------
    # Transition table: serialize _TRANSITIONS as a list the JS suite compares
    # against its own table, ensuring the legal (from,type)->to set matches.
    # ------------------------------------------------------------------
    transition_table = [
        {
            "from": from_state.value,
            "type": msg_type.value,
            "to": to_state.value,
        }
        for (from_state, msg_type), to_state in _TRANSITIONS.items()
    ]

    # ------------------------------------------------------------------
    # Happy-path runs covering every terminal path + reactivation.
    # ------------------------------------------------------------------
    runs = []

    # Run 1: OPEN -> ACCEPT_SESSION -> OFFER -> COUNTER -> OFFER -> ACCEPT (AGREED)
    runs.append(
        _build_run(
            "agree_full",
            [
                {"sender": AGENT_A, "type": MessageType.OPEN, "body": OPEN_BODY},
                {"sender": AGENT_B, "type": MessageType.ACCEPT_SESSION, "body": {}},
                {
                    "sender": AGENT_A,
                    "type": MessageType.OFFER,
                    "body": OFFER_BODY_1,
                    "reasoning": "opening offer",
                },
                {"sender": AGENT_B, "type": MessageType.COUNTER, "body": OFFER_BODY_2},
                {"sender": AGENT_A, "type": MessageType.OFFER, "body": OFFER_BODY_3},
                {"sender": AGENT_B, "type": MessageType.ACCEPT, "body": {}},
            ],
        )
    )

    # Run 2: OPEN -> DECLINE_SESSION (REJECTED straight from PROPOSED)
    runs.append(
        _build_run(
            "decline_session",
            [
                {"sender": AGENT_A, "type": MessageType.OPEN, "body": OPEN_BODY},
                {"sender": AGENT_B, "type": MessageType.DECLINE_SESSION, "body": {}},
            ],
        )
    )

    # Run 3: OPEN -> ACCEPT_SESSION -> SIGNAL -> CONSTRAIN -> INQUIRE ->
    #        PROPOSE_MEDIATOR -> RESOLVE -> WITHDRAW (REJECTED) — exercises every
    #        ACTIVE-keeping message + the WITHDRAW terminal + withdrawal flag.
    runs.append(
        _build_run(
            "active_messages_then_withdraw",
            [
                {"sender": AGENT_A, "type": MessageType.OPEN, "body": OPEN_BODY},
                {"sender": AGENT_B, "type": MessageType.ACCEPT_SESSION, "body": {}},
                {"sender": AGENT_A, "type": MessageType.SIGNAL, "body": {}},
                {"sender": AGENT_A, "type": MessageType.CONSTRAIN, "body": {}},
                {"sender": AGENT_B, "type": MessageType.INQUIRE, "body": {}},
                {"sender": AGENT_B, "type": MessageType.PROPOSE_MEDIATOR, "body": {}},
                {"sender": AGENT_A, "type": MessageType.RESOLVE, "body": {}},
                {"sender": AGENT_B, "type": MessageType.WITHDRAW, "body": {}},
            ],
        )
    )

    # Run 4: OPEN -> ACCEPT_SESSION -> REJECT (REJECTED)
    runs.append(
        _build_run(
            "active_reject",
            [
                {"sender": AGENT_A, "type": MessageType.OPEN, "body": OPEN_BODY},
                {"sender": AGENT_B, "type": MessageType.ACCEPT_SESSION, "body": {}},
                {"sender": AGENT_A, "type": MessageType.REJECT, "body": {}},
            ],
        )
    )

    # Run 5: OPEN -> ACCEPT_SESSION -> OFFER -> COMMIT (AGREED via COMMIT)
    runs.append(
        _build_run(
            "active_commit",
            [
                {"sender": AGENT_A, "type": MessageType.OPEN, "body": OPEN_BODY},
                {"sender": AGENT_B, "type": MessageType.ACCEPT_SESSION, "body": {}},
                {"sender": AGENT_A, "type": MessageType.OFFER, "body": OFFER_BODY_1},
                {"sender": AGENT_B, "type": MessageType.COMMIT, "body": {}},
            ],
        )
    )

    # Run 6: OPEN with NO terms key — exercises terms == None preservation.
    runs.append(
        _build_run(
            "open_no_terms",
            [
                {"sender": AGENT_A, "type": MessageType.OPEN, "body": {}},
                {"sender": AGENT_B, "type": MessageType.ACCEPT_SESSION, "body": {}},
            ],
        )
    )

    # Run 7: OPEN with explicit null terms — dict.get null-preservation.
    runs.append(
        _build_run(
            "open_null_terms",
            [
                {"sender": AGENT_A, "type": MessageType.OPEN, "body": {"terms": None}},
            ],
        )
    )

    # ------------------------------------------------------------------
    # expire() + make_dormant() runs (post-transcript out-of-band transitions).
    # We expose the lifecycle expectations directly.
    # ------------------------------------------------------------------
    lifecycle_cases = []

    # expire from PROPOSED (valid)
    s = Session(session_id="ses_expire_proposed")
    s.expire()
    lifecycle_cases.append(
        {"name": "expire_from_proposed", "ops": ["expire"], "expected_state": s.state.value}
    )

    # expire from ACTIVE (valid): OPEN -> ACCEPT_SESSION -> expire
    s = Session(session_id="ses_expire_active")
    s.add_party(AGENT_A, PartyRole.INITIATOR, KP_A.public_key)
    s.add_party(AGENT_B, PartyRole.RESPONDER, KP_B.public_key)
    ph = GENESIS_HASH
    for sender, mt, body in (
        (AGENT_A, MessageType.OPEN, OPEN_BODY),
        (AGENT_B, MessageType.ACCEPT_SESSION, {}),
    ):
        m = _make_msg(
            msg_type=mt,
            sender_kp=KEYS[sender],
            sender_id=sender,
            session_id=s.session_id,
            prev_hash=ph,
            body=body,
        )
        s.apply_message(m, _resolver)
        ph = compute_hash(m)
    s.expire()
    lifecycle_cases.append(
        {
            "name": "expire_from_active",
            "preface": "open_accept",
            "ops": ["expire"],
            "expected_state": s.state.value,
        }
    )

    # make_dormant from EXPIRED (valid)
    s = Session(session_id="ses_dormant_from_expired")
    s.expire()
    s.make_dormant()
    lifecycle_cases.append(
        {
            "name": "dormant_from_expired",
            "ops": ["expire", "make_dormant"],
            "expected_state": s.state.value,
            "reactivatable": s.reactivatable,
        }
    )

    # ------------------------------------------------------------------
    # Invalid-transition cases: each raises InvalidTransitionError with text.
    # We capture the exact message string.
    # ------------------------------------------------------------------
    invalid_transitions = []

    def _capture_invalid_transition(name, setup_steps, bad_step):
        s = Session(session_id=f"ses_{name}")
        s.add_party(AGENT_A, PartyRole.INITIATOR, KP_A.public_key)
        s.add_party(AGENT_B, PartyRole.RESPONDER, KP_B.public_key)
        ph = GENESIS_HASH
        for sender, mt, body in setup_steps:
            m = _make_msg(
                msg_type=mt,
                sender_kp=KEYS[sender],
                sender_id=sender,
                session_id=s.session_id,
                prev_hash=ph,
                body=body,
            )
            s.apply_message(m, _resolver)
            ph = compute_hash(m)
        sender, mt, body = bad_step
        bad_msg = _make_msg(
            msg_type=mt,
            sender_kp=KEYS[sender],
            sender_id=sender,
            session_id=s.session_id,
            prev_hash=ph,
            body=body,
        )
        try:
            s.apply_message(bad_msg, _resolver)
            raise AssertionError(f"{name}: expected InvalidTransitionError")
        except InvalidTransitionError as e:
            invalid_transitions.append(
                {
                    "name": name,
                    "state_before": s.state.value,
                    "message": bad_msg,
                    "expected_error": str(e),
                }
            )

    # ACCEPT in PROPOSED (no ACCEPT_SESSION yet)
    _capture_invalid_transition(
        "accept_in_proposed",
        [(AGENT_A, MessageType.OPEN, OPEN_BODY)],
        (AGENT_B, MessageType.ACCEPT, {}),
    )
    # OFFER in PROPOSED
    _capture_invalid_transition(
        "offer_in_proposed",
        [(AGENT_A, MessageType.OPEN, OPEN_BODY)],
        (AGENT_A, MessageType.OFFER, OFFER_BODY_1),
    )
    # OPEN again after OPEN (PROPOSED + OPEN maps to PROPOSED, so NOT invalid) —
    # instead test ACCEPT_SESSION twice (PROPOSED -> ACTIVE, then ACTIVE +
    # ACCEPT_SESSION is invalid).
    _capture_invalid_transition(
        "accept_session_in_active",
        [
            (AGENT_A, MessageType.OPEN, OPEN_BODY),
            (AGENT_B, MessageType.ACCEPT_SESSION, {}),
        ],
        (AGENT_A, MessageType.ACCEPT_SESSION, {}),
    )
    # DECLINE_SESSION in ACTIVE
    _capture_invalid_transition(
        "decline_session_in_active",
        [
            (AGENT_A, MessageType.OPEN, OPEN_BODY),
            (AGENT_B, MessageType.ACCEPT_SESSION, {}),
        ],
        (AGENT_A, MessageType.DECLINE_SESSION, {}),
    )
    # OFFER after AGREED (terminal): OPEN->ACCEPT_SESSION->ACCEPT then OFFER
    _capture_invalid_transition(
        "offer_after_agreed",
        [
            (AGENT_A, MessageType.OPEN, OPEN_BODY),
            (AGENT_B, MessageType.ACCEPT_SESSION, {}),
            (AGENT_A, MessageType.ACCEPT, {}),
        ],
        (AGENT_A, MessageType.OFFER, OFFER_BODY_1),
    )

    # expire/make_dormant invalid-transition error text.
    invalid_lifecycle = []

    s = Session(session_id="ses_expire_invalid")
    s.expire()  # now EXPIRED
    try:
        s.expire()
        raise AssertionError("expected InvalidTransitionError on double expire")
    except InvalidTransitionError as e:
        invalid_lifecycle.append(
            {"name": "expire_when_expired", "state": s.state.value, "expected_error": str(e)}
        )

    s = Session(session_id="ses_dormant_invalid")
    # PROPOSED -> make_dormant is invalid (needs REJECTED or EXPIRED)
    try:
        s.make_dormant()
        raise AssertionError("expected InvalidTransitionError on dormant from proposed")
    except InvalidTransitionError as e:
        invalid_lifecycle.append(
            {
                "name": "dormant_from_proposed",
                "state": s.state.value,
                "expected_error": str(e),
            }
        )

    # ------------------------------------------------------------------
    # Invalid-signature cases. Each yields InvalidSignatureError with text.
    # ------------------------------------------------------------------
    invalid_signatures = []

    base_open = _make_msg(
        msg_type=MessageType.OPEN,
        sender_kp=KP_A,
        sender_id=AGENT_A,
        session_id="ses_sig",
        prev_hash=GENESIS_HASH,
        body=OPEN_BODY,
    )

    def _fresh_session():
        s = Session(session_id="ses_sig")
        s.add_party(AGENT_A, PartyRole.INITIATOR, KP_A.public_key)
        s.add_party(AGENT_B, PartyRole.RESPONDER, KP_B.public_key)
        return s

    # (a) missing from.agent_id
    msg_no_from = dict(base_open)
    msg_no_from["from"] = {}
    s = _fresh_session()
    try:
        s.apply_message(msg_no_from, _resolver)
        raise AssertionError("expected InvalidSignatureError (no agent_id)")
    except InvalidSignatureError as e:
        invalid_signatures.append(
            {"name": "missing_agent_id", "message": msg_no_from, "expected_error": str(e)}
        )

    # (b) missing signature
    msg_no_sig = {k: v for k, v in base_open.items() if k != "signature"}
    s = _fresh_session()
    try:
        s.apply_message(msg_no_sig, _resolver)
        raise AssertionError("expected InvalidSignatureError (no signature)")
    except InvalidSignatureError as e:
        invalid_signatures.append(
            {"name": "missing_signature", "message": msg_no_sig, "expected_error": str(e)}
        )

    # (c) unknown agent identity (resolver returns None)
    msg_unknown = _make_msg(
        msg_type=MessageType.OPEN,
        sender_kp=KP_UNKNOWN,
        sender_id="did:concordia:agent:ghost",
        session_id="ses_sig",
        prev_hash=GENESIS_HASH,
        body=OPEN_BODY,
    )
    s = _fresh_session()
    try:
        s.apply_message(msg_unknown, _resolver)
        raise AssertionError("expected InvalidSignatureError (unknown agent)")
    except InvalidSignatureError as e:
        invalid_signatures.append(
            {
                "name": "unknown_agent",
                "message": msg_unknown,
                "expected_error": str(e),
            }
        )

    # (d) tampered payload (valid sig, mutated content)
    tampered = json.loads(json.dumps(base_open))
    tampered["body"]["terms"]["price"]["value"] = 9999
    s = _fresh_session()
    try:
        s.apply_message(tampered, _resolver)
        raise AssertionError("expected InvalidSignatureError (tampered)")
    except InvalidSignatureError as e:
        invalid_signatures.append(
            {"name": "tampered_payload", "message": tampered, "expected_error": str(e)}
        )

    # (e) flipped signature byte (still base64url, decodes to 64 bytes)
    raw = bytearray(base64.urlsafe_b64decode(base_open["signature"]))
    raw[0] ^= 0x01
    flipped = dict(base_open)
    flipped["signature"] = base64.urlsafe_b64encode(bytes(raw)).decode()
    s = _fresh_session()
    try:
        s.apply_message(flipped, _resolver)
        raise AssertionError("expected InvalidSignatureError (flipped sig)")
    except InvalidSignatureError as e:
        invalid_signatures.append(
            {"name": "flipped_signature", "message": flipped, "expected_error": str(e)}
        )

    # ------------------------------------------------------------------
    # Unknown MessageType value: MessageType(message["type"]) raises ValueError.
    # We capture the exact text. The message is otherwise validly signed so the
    # signature check passes and the enum-coercion is reached. We cover a plain
    # bogus value PLUS quote-containing / escape-containing values so the JS
    # CPython-repr() quote-selection + escaping (single quote default; double
    # quote when the value contains `'` and not `"`; backslash-escape the active
    # quote, backslash, and \t/\n/\r) is exercised against Python's exact text.
    # ------------------------------------------------------------------
    unknown_type_cases = []
    _bogus_n = {"i": 0}

    def _add_unknown_type(name: str, type_value):
        # Sign a message whose `type` is a bogus value. build_envelope requires a
        # MessageType, so hand-build + sign a raw dict with the same envelope
        # shape. The signature is over the bogus-typed dict so verification passes
        # and the MessageType(...) enum-coercion is the failing step.
        _bogus_n["i"] += 1
        msg = {
            "concordia": "0.1.0",
            "type": type_value,
            "id": f"msg_bogus{_bogus_n['i']:02d}",
            "session_id": "ses_unknown_type",
            "timestamp": "2026-05-29T12:00:00Z",
            "from": AgentIdentity(agent_id=AGENT_A).to_dict(),
            "prev_hash": GENESIS_HASH,
            "body": {},
        }
        msg["signature"] = signing.sign_message(msg, KP_A)
        s = _fresh_session()
        s.session_id = "ses_unknown_type"
        try:
            s.apply_message(msg, _resolver)
            raise AssertionError(f"{name}: expected ValueError on unknown MessageType")
        except ValueError as e:
            unknown_type_cases.append(
                {"name": name, "message": msg, "expected_error": str(e)}
            )

    _add_unknown_type("bogus_type", "negotiate.bogus")
    # Single quote present, no double quote -> CPython switches to double quotes:
    #   "negotiate.o'ops" is not a valid MessageType
    _add_unknown_type("single_quote_in_type", "negotiate.o'ops")
    # Both quotes present -> CPython stays on single quote and escapes the single:
    #   'has"both\'quotes' is not a valid MessageType
    _add_unknown_type("both_quotes_in_type", "has\"both'quotes")
    # Double quote only -> default single quote, double left bare:
    #   'say "hi"' is not a valid MessageType
    _add_unknown_type("double_quote_in_type", 'say "hi"')
    # Control chars use named escapes (\t \n \r) inside single quotes.
    _add_unknown_type("tab_in_type", "tab\there")
    _add_unknown_type("newline_in_type", "new\nline")
    _add_unknown_type("backslash_in_type", "back\\slash")

    # ------------------------------------------------------------------
    # body-shape parity: Python does `message.get("body", {}).get(...)` ONLY for
    # OPEN, OFFER, COUNTER. A present-but-non-mapping `body` (list / string /
    # number / bool / null) raises AttributeError on `.get(...)` -> the message
    # is REJECTED. An ABSENT body uses the `{}` default -> ACCEPTED. A valid
    # mapping body (or empty mapping) -> ACCEPTED. Message types that never read
    # `body` (e.g. SIGNAL) are NOT affected by a non-mapping body -> ACCEPTED.
    #
    # Each case records the exact accept/reject Python produces (and, on accept,
    # the resulting state + terms) so the JS suite asserts identical behavior.
    # `body_present=False` means the `body` key is omitted entirely.
    # ------------------------------------------------------------------
    body_shape_cases = []

    def _drive_to_active(s):
        """OPEN -> ACCEPT_SESSION so the session is ACTIVE for OFFER/COUNTER."""
        ph = GENESIS_HASH
        for sender, mt, body in (
            (AGENT_A, MessageType.OPEN, OPEN_BODY),
            (AGENT_B, MessageType.ACCEPT_SESSION, {}),
        ):
            m = _make_msg(
                msg_type=mt,
                sender_kp=KEYS[sender],
                sender_id=sender,
                session_id=s.session_id,
                prev_hash=ph,
                body=body,
            )
            s.apply_message(m, _resolver)
            ph = compute_hash(m)
        return ph

    def _add_body_shape(name, msg_type, body, *, body_present=True, preface=None):
        s = _fresh_session()
        s.session_id = f"ses_body_{name}"
        if preface == "active":
            ph = _drive_to_active(s)
        else:
            ph = GENESIS_HASH
        sender = AGENT_A
        msg = {
            "concordia": "0.1.0",
            "type": msg_type.value,
            "id": f"msg_body_{name}",
            "session_id": s.session_id,
            "timestamp": "2026-05-29T12:00:00Z",
            "from": AgentIdentity(agent_id=sender).to_dict(),
            "prev_hash": ph,
        }
        if body_present:
            msg["body"] = body
        msg["signature"] = signing.sign_message(msg, KEYS[sender])
        record = {
            "name": name,
            "type": msg_type.value,
            "preface": preface,
            "message": msg,
        }
        try:
            new_state = s.apply_message(msg, _resolver)
            record["accept"] = True
            record["expected_state"] = new_state.value
            record["terms"] = s.terms
            record["round_count"] = s.round_count
        except AttributeError:
            # Python's `body.get(...)` on a non-mapping -> REJECT (fail closed).
            record["accept"] = False
        body_shape_cases.append(record)

    # --- OPEN (read in PROPOSED) -------------------------------------------
    _add_body_shape("open_valid_object", MessageType.OPEN, {"terms": {"p": {"value": 1}}})
    _add_body_shape("open_empty_object", MessageType.OPEN, {})
    _add_body_shape("open_absent", MessageType.OPEN, None, body_present=False)
    _add_body_shape("open_list", MessageType.OPEN, [1, 2, 3])
    _add_body_shape("open_string", MessageType.OPEN, "nope")
    _add_body_shape("open_number", MessageType.OPEN, 5)
    _add_body_shape("open_bool", MessageType.OPEN, True)
    _add_body_shape("open_null", MessageType.OPEN, None)  # present-null REJECTS

    # --- OFFER (read in ACTIVE) --------------------------------------------
    _add_body_shape(
        "offer_valid_object",
        MessageType.OFFER,
        {"terms": {"p": {"value": 900}}},
        preface="active",
    )
    _add_body_shape("offer_empty_object", MessageType.OFFER, {}, preface="active")
    _add_body_shape("offer_absent", MessageType.OFFER, None, body_present=False, preface="active")
    _add_body_shape("offer_list", MessageType.OFFER, [1, 2], preface="active")
    _add_body_shape("offer_string", MessageType.OFFER, "nope", preface="active")
    _add_body_shape("offer_number", MessageType.OFFER, 7, preface="active")
    _add_body_shape("offer_bool", MessageType.OFFER, False, preface="active")
    _add_body_shape("offer_null", MessageType.OFFER, None, preface="active")

    # --- COUNTER (read in ACTIVE) ------------------------------------------
    _add_body_shape("counter_list", MessageType.COUNTER, [9], preface="active")
    _add_body_shape("counter_null", MessageType.COUNTER, None, preface="active")
    _add_body_shape(
        "counter_valid_object",
        MessageType.COUNTER,
        {"terms": {"p": {"value": 800}}},
        preface="active",
    )

    # --- SIGNAL (NEVER reads body) -> a non-mapping body is ACCEPTED -------
    _add_body_shape("signal_list_accepted", MessageType.SIGNAL, [1, 2, 3], preface="active")
    _add_body_shape("signal_string_accepted", MessageType.SIGNAL, "anything", preface="active")
    _add_body_shape("signal_null_accepted", MessageType.SIGNAL, None, preface="active")

    # ------------------------------------------------------------------
    # _compute_concession parity vectors (the static method, exercised directly).
    # Covers: numeric movement, prev==0 skip, missing-term skip, no-overlap (0.0),
    # bool-as-numeric (Python isinstance(bool, (int,float)) is True), non-numeric
    # values skipped, multi-term average.
    # ------------------------------------------------------------------
    concession_cases = []

    def _add_concession(name, prev, curr):
        concession_cases.append(
            {
                "name": name,
                "prev": prev,
                "curr": curr,
                "expected": Session._compute_concession(prev, curr),
            }
        )

    _add_concession(
        "single_numeric_move",
        {"price": {"value": 1000}},
        {"price": {"value": 900}},
    )
    _add_concession(
        "two_term_average",
        {"price": {"value": 1000}, "qty": {"value": 10}},
        {"price": {"value": 900}, "qty": {"value": 8}},
    )
    _add_concession(
        "prev_zero_skipped",
        {"price": {"value": 0}, "qty": {"value": 10}},
        {"price": {"value": 5}, "qty": {"value": 9}},
    )
    _add_concession(
        "missing_term_skipped",
        {"price": {"value": 1000}, "extra": {"value": 5}},
        {"price": {"value": 950}},
    )
    _add_concession(
        "no_overlap_zero",
        {"price": {"value": 1000}},
        {"qty": {"value": 10}},
    )
    _add_concession(
        "non_numeric_skipped",
        {"label": {"value": "blue"}, "price": {"value": 1000}},
        {"label": {"value": "red"}, "price": {"value": 800}},
    )
    _add_concession(
        "bool_as_numeric",
        {"flag": {"value": True}},
        {"flag": {"value": False}},
    )
    _add_concession(
        "float_movement",
        {"rate": {"value": 1.5}},
        {"rate": {"value": 1.25}},
    )
    _add_concession(
        "increase_counts",
        {"price": {"value": 1000}},
        {"price": {"value": 1100}},
    )
    _add_concession(
        "no_change_zero",
        {"price": {"value": 1000}},
        {"price": {"value": 1000}},
    )

    # ------------------------------------------------------------------
    # compute_hash + validate_chain parity vectors.
    # ------------------------------------------------------------------
    hash_cases = []
    for payload in (
        {"a": 1},
        {"type": "negotiate.offer", "body": {"terms": {"price": {"value": 100}}}},
        {"signature": "abc", "z": 1, "a": 2},  # signature NOT stripped in compute_hash
        {"unicode": "héllo ✓", "n": -3.25},
    ):
        hash_cases.append({"input": payload, "expected_hash": compute_hash(payload)})

    # A valid chain (built from a real run) + an invalid chain (broken link).
    chain_run = runs[0]["steps"]
    valid_chain = [step["message"] for step in chain_run]
    broken_chain = [json.loads(json.dumps(m)) for m in valid_chain]
    if len(broken_chain) >= 2:
        broken_chain[1]["prev_hash"] = "sha256:" + ("f" * 64)
    chain_cases = [
        {"name": "valid_chain", "messages": valid_chain, "expected": validate_chain(valid_chain)},
        {
            "name": "broken_link",
            "messages": broken_chain,
            "expected": validate_chain(broken_chain),
        },
        {"name": "empty_chain", "messages": [], "expected": validate_chain([])},
        {
            "name": "bad_genesis",
            "messages": [
                {**json.loads(json.dumps(valid_chain[0])), "prev_hash": "sha256:" + ("1" * 64)}
            ],
            "expected": validate_chain(
                [
                    {
                        **json.loads(json.dumps(valid_chain[0])),
                        "prev_hash": "sha256:" + ("1" * 64),
                    }
                ]
            ),
        },
    ]

    doc = {
        "_comment": (
            "Generated by js-sdk/scripts/gen-session-fixtures.py from "
            "concordia.session / concordia.message / concordia.signing. States, "
            "hashes, signatures, behavior records, and error text are "
            "Python-produced; do not edit by hand."
        ),
        "seeds": {
            "agent_a": {"id": AGENT_A, "seed_hex": SEED_A.hex(), "public_key_b64": KP_A.public_key_b64()},
            "agent_b": {"id": AGENT_B, "seed_hex": SEED_B.hex(), "public_key_b64": KP_B.public_key_b64()},
        },
        "genesis_hash": GENESIS_HASH,
        "t0_ms": T0_MS,
        "transition_table": transition_table,
        "runs": runs,
        "lifecycle_cases": lifecycle_cases,
        "invalid_transitions": invalid_transitions,
        "invalid_lifecycle": invalid_lifecycle,
        "invalid_signatures": invalid_signatures,
        "unknown_type_cases": unknown_type_cases,
        "body_shape_cases": body_shape_cases,
        "concession_cases": concession_cases,
        "hash_cases": hash_cases,
        "chain_cases": chain_cases,
    }

    json.dump(doc, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
