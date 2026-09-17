"""Hand-written runner CHECK vectors shared by the JS and Python reference-runner tests.

These never enter the generated, drift-checked corpus under ``conformance/``
(they are written into a temporary suite by each test); they exist so both
runners are held to the SAME verdict on the same bytes for behaviour the
generated vectors do not cover. Two rules are pinned here:

- the INTEGER-REJECTION RULE stated in both runners: an integer outside
  +/-(2**53 - 1) is rejected iff it reaches canonicalization, and never
  otherwise. Four probes carry the "never otherwise" half, each a real
  accepted vector plus the unsafe integer somewhere no profile canonicalizes:
  an unused ``context`` member (Codex P1, 2026-09-16 delta-12 gate: the JS
  runner rejected it anywhere in the document), an unused ``input`` member of
  chain-session-transition-v1, and an extra key under agent-profile-v1's
  ``trust_signals`` and under one of its reputation assertions (Codex P1 and
  Grok lens A, 2026-09-17 delta-13 gate: round 13's JS runner rejected any
  unsafe integer under ``input``, while the Python runner drops those and
  accepts). One mutation vector carries the other half (the integer inside a
  message that message-chain-v1 canonicalizes: both reject).
- the transcript cap both runners enforce on receipt-set-binding-v1
  (MAX_SET_BINDING_TRANSCRIPT_MESSAGES): an over-cap vector is fed through
  both runners and both must reject it BY THE CAP'S OWN REASON (Grok lens A,
  2026-09-17 delta-13 gate: the cap's literal was cross-pinned but nothing
  ran an over-cap vector, so deleting the ``if`` and keeping the constant
  stayed green).

Stdout is verdict-only by design ([OK]/[FAIL] plus the [SUMMARY] line). The
reason is observable only through each runner's ``--explain`` flag, which
prints ``[EXPLAIN] <id> reject: <reason>`` to stderr and leaves stdout
unchanged; the cap check asserts on that line in both runners.
"""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parent.parent
FULL_SUITE = REPO_ROOT / "conformance" / "vectors"

# Beyond Number.MAX_SAFE_INTEGER (2**53 - 1) and at the 1e21 magnitude where
# JavaScript's Number#toString switches to exponential form, so a post-parse
# guard alone cannot see it.
UNSAFE_INTEGER = 10**21

# Ingest regression (2026-09-16 delta-11 gate, Codex P1; scope narrowed in
# round 13): the unsafe integer sits INSIDE ``input``, where message-chain-v1
# canonicalizes it, so both runners reject. It never reaches signature
# verification in either runner.
UNSAFE_INTEGER_INPUT_VECTOR: dict[str, Any] = {
    "schema_version": "concordia-conformance-vector/v1-draft",
    "id": "check-unsafe-integer-ingest",
    "title": (
        "A bare plain-decimal integer at the 1e21 magnitude inside input, where "
        "message-chain-v1 canonicalizes it, is rejected by both runners: the JS "
        "runner from the source text (String(JSON.parse(literal)) is already "
        "exponential), the Python runner from rfc8785's integer domain."
    ),
    "source_fixture": "delta-11 gate, Codex P1 (2026-09-16 fix round 12)",
    "record_type": "message_chain",
    "verification_profile": "message-chain-v1",
    "expected": "reject",
    "expected_reason_class": "ingest",
    "context": {},
    "input": {
        "messages": [
            {
                "concordia": "0.1.0",
                "id": "msg_check_unsafe_integer_ingest_0001",
                "session_id": "sess_check_unsafe_integer_ingest_0001",
                "type": "negotiate.open",
                "from": {"agent_id": "did:concordia:agent:unsafe-integer-initiator"},
                "to": [{"agent_id": "did:concordia:agent:unsafe-integer-responder"}],
                "timestamp": "2026-09-16T00:00:00Z",
                "prev_hash": f"sha256:{'0' * 64}",
                "body": {"terms": {"quantity": UNSAFE_INTEGER}},
                "reasoning": (
                    "Ingest-boundary canary: quantity is a bare plain-decimal "
                    "integer beyond Number.MAX_SAFE_INTEGER (2^53 - 1), at the "
                    "1e21 magnitude where JS Number#toString switches to "
                    "exponential notation and can defeat a post-parse-only "
                    "unsafe-integer guard. Never reaches signature "
                    "verification: canonicalization rejects it first."
                ),
                "signature": "not-a-real-signature-ingest-must-reject-before-verification-runs",
            }
        ]
    },
}

UNUSED_METADATA_PROBE_ID = "check-unsafe-integer-unused-metadata"
UNUSED_METADATA_PROBE_KEY = "unused_probe_unsafe_integer"
TRANSITION_INPUT_PROBE_ID = "check-unsafe-integer-unused-transition-input"
AGENT_PROFILE_TRUST_SIGNALS_PROBE_ID = "check-unsafe-integer-agent-profile-trust-signals-extra"
AGENT_PROFILE_REPUTATION_PROBE_ID = "check-unsafe-integer-agent-profile-reputation-extra"
# Every probe that must stay ACCEPTED by both runners, in manifest order.
ACCEPTED_PROBE_IDS = (
    UNUSED_METADATA_PROBE_ID,
    TRANSITION_INPUT_PROBE_ID,
    AGENT_PROFILE_TRUST_SIGNALS_PROBE_ID,
    AGENT_PROFILE_REPUTATION_PROBE_ID,
)

OVER_CAP_PROBE_ID = "check-transcript-over-cap"
# Must match MAX_SET_BINDING_TRANSCRIPT_MESSAGES in both runners and both
# SDKs; read from the shared fixture the cross-pin tests already read.
SET_BINDING_LIMITS = Path(__file__).resolve().parent / "fixtures" / "set_binding_limits.json"
# The cap's own reason, verbatim from both runners (must match the reject
# in verify_receipt_set_binding_profile, conformance/reference-runner/
# runner.py, and verifyReceiptSetBindingProfile, conformance/reference-
# runner-js/runner.mjs).
OVER_CAP_REASON = "transcript exceeds the maximum message count"
OVER_CAP_EXPLAIN_LINE = f"[EXPLAIN] {OVER_CAP_PROBE_ID} reject: {OVER_CAP_REASON}"
EXPECTED_OVER_CAP_SUMMARY = "[SUMMARY] positive=0 mutation=1 canary=0 ok=1 fail=0"


def load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def unused_metadata_probe_vector() -> dict[str, Any]:
    """A real accepted vector with the same unsafe integer in a ``context``
    member no profile reads: nothing canonicalizes it, so both runners must
    still ACCEPT. Before round 13 the JS runner rejected the whole file."""
    vector = copy.deepcopy(load_json(FULL_SUITE / "positive" / "pos-1404-decision-id.json"))
    vector["id"] = UNUSED_METADATA_PROBE_ID
    vector["title"] = (
        "pos-1404-decision-id with an unsafe plain-decimal integer in an unused "
        "context member: it never reaches canonicalization, so it is not a rejection."
    )
    vector["context"][UNUSED_METADATA_PROBE_KEY] = UNSAFE_INTEGER
    return vector


def transition_input_probe_vector() -> dict[str, Any]:
    """An accepted chain-session-transition-v1 vector with the unsafe integer
    in an unused member of ``input`` itself: the transition profile
    canonicalizes nothing, so both runners must still ACCEPT. Round 13's JS
    runner rejected it (any unsafe integer under ``input``)."""
    vector = copy.deepcopy(
        load_json(FULL_SUITE / "positive" / "transition-synthetic-cmpc-legal-proposed-to-open.json")
    )
    vector["id"] = TRANSITION_INPUT_PROBE_ID
    vector["title"] = (
        "transition-synthetic-cmpc-legal-proposed-to-open with an unsafe plain-decimal "
        "integer in an unused input member: the transition profile canonicalizes "
        "nothing, so it is not a rejection."
    )
    vector["input"][UNUSED_METADATA_PROBE_KEY] = UNSAFE_INTEGER
    return vector


def agent_profile_probe_vector(*, under_reputation_assertion: bool) -> dict[str, Any]:
    """An accepted agent-profile-v1 vector with the unsafe integer as an
    EXTRA key under ``trust_signals`` (or under its first reputation
    assertion): both sub-objects are read with allow_extra, so the profile's
    canonical form drops the key, the signature still verifies, and both
    runners must still ACCEPT."""
    vector = copy.deepcopy(load_json(FULL_SUITE / "positive" / "pos-synthetic-agent-profile.json"))
    trust_signals = cast(dict[str, Any], vector["input"]["trust_signals"])
    if under_reputation_assertion:
        vector["id"] = AGENT_PROFILE_REPUTATION_PROBE_ID
        vector["title"] = (
            "pos-synthetic-agent-profile with an unsafe plain-decimal integer as an extra "
            "key of a reputation assertion: dropped from the canonical form, so it is "
            "not a rejection."
        )
        cast(list[dict[str, Any]], trust_signals["reputation"])[0][UNUSED_METADATA_PROBE_KEY] = (
            UNSAFE_INTEGER
        )
    else:
        vector["id"] = AGENT_PROFILE_TRUST_SIGNALS_PROBE_ID
        vector["title"] = (
            "pos-synthetic-agent-profile with an unsafe plain-decimal integer as an extra "
            "key of trust_signals: dropped from the canonical form, so it is not a "
            "rejection."
        )
        trust_signals[UNUSED_METADATA_PROBE_KEY] = UNSAFE_INTEGER
    return vector


def over_cap_vector() -> dict[str, Any]:
    """The accepted receipt-set-binding-v1 vector with its transcript padded
    to one message over the cap. Everything a runner checks BEFORE the cap
    (the receipt, its signatures and countersignatures) is the real vector's
    and passes; the padding is empty objects, which the cap refuses by count
    before either runner reads a single message. That is what makes the
    check discriminating: with the cap's ``if`` deleted, a runner would go
    on to read the padding and reject for a different reason, and the
    ``[EXPLAIN]`` assertion on the cap's own reason would fail."""
    cap = cast(int, load_json(SET_BINDING_LIMITS)["max_set_binding_transcript_messages"])
    vector = copy.deepcopy(
        load_json(FULL_SUITE / "positive" / "pos-synthetic-receipt-set-binding-reconstruction.json")
    )
    vector["id"] = OVER_CAP_PROBE_ID
    vector["title"] = (
        "pos-synthetic-receipt-set-binding-reconstruction with its transcript padded to "
        "one message over MAX_SET_BINDING_TRANSCRIPT_MESSAGES: rejected by the cap, "
        "before any per-message work."
    )
    vector["expected"] = "reject"
    vector["expected_reason_class"] = "transcript_cap"
    messages = cast(list[dict[str, Any]], vector["input"]["messages"])
    messages.extend({} for _ in range(cap + 1 - len(messages)))
    assert len(messages) == cap + 1
    return vector


EXPECTED_INTEGER_RULE_SUMMARY = "[SUMMARY] positive=4 mutation=1 canary=0 ok=5 fail=0"


def _write_suite(
    tmp_path: Path,
    positive: list[dict[str, Any]],
    mutation: list[dict[str, Any]],
) -> Path:
    """Write the given vectors into a temporary suite, with the frozen
    schemas copied in so a profile that validates a schema before
    canonicalizing can reach the canonicalization step. Returns the suite's
    ``conformance/vectors`` dir."""
    tmp_root = tmp_path / "suite"
    manifest = load_json(FULL_SUITE / "manifest.json")
    files = cast(dict[str, list[str]], manifest["files"])
    for rel_path in files["schemas"]:
        dest = tmp_root / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / rel_path, dest)

    rel_paths: dict[str, list[str]] = {"positive": [], "mutation": []}
    for section, vectors in (("positive", positive), ("mutation", mutation)):
        for vector in vectors:
            rel_path = f"conformance/vectors/{section}/{vector['id']}.json"
            rel_paths[section].append(rel_path)
            path = tmp_root / rel_path
            path.parent.mkdir(parents=True, exist_ok=True)
            # json.dumps writes an int in plain decimal: the literal form under test.
            path.write_text(json.dumps(vector, indent=2) + "\n", encoding="utf-8")

    mini_manifest = {
        "counts": {
            "positive": len(positive),
            "mutation": len(mutation),
            "canary": 0,
            "diag_canonical_bytes": 0,
        },
        "files": {
            "positive": rel_paths["positive"],
            "mutation": rel_paths["mutation"],
            "canary": [],
            "diag_canonical_bytes": [],
            "schemas": files["schemas"],
        },
    }
    manifest_path = tmp_root / "conformance" / "vectors" / "manifest.json"
    manifest_path.write_text(
        json.dumps(mini_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return tmp_root / "conformance" / "vectors"


def write_integer_rule_suite(tmp_path: Path) -> Path:
    """The four accepted probes (positive) and the canonicalized-integer
    vector (mutation); see the module docstring."""
    return _write_suite(
        tmp_path,
        positive=[
            unused_metadata_probe_vector(),
            transition_input_probe_vector(),
            agent_profile_probe_vector(under_reputation_assertion=False),
            agent_profile_probe_vector(under_reputation_assertion=True),
        ],
        mutation=[UNSAFE_INTEGER_INPUT_VECTOR],
    )


def write_over_cap_suite(tmp_path: Path) -> Path:
    """The one over-cap vector (mutation); see the module docstring."""
    return _write_suite(tmp_path, positive=[], mutation=[over_cap_vector()])
