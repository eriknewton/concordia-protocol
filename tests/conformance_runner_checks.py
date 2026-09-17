"""Hand-written runner CHECK vectors shared by the JS and Python reference-runner tests.

These never enter the generated, drift-checked corpus under ``conformance/``
(they are written into a temporary suite by each test); they exist so both
runners are held to the SAME verdict on the same bytes for behaviour the
generated vectors do not cover. The one rule they currently pin is the
INTEGER-REJECTION RULE stated in both runners: an integer outside
+/-(2**53 - 1) is rejected iff it reaches canonicalization (it lies under the
vector's ``input``); one anywhere else, such as an unused ``context`` member,
is not a rejection (Codex P1, 2026-09-16 delta-12 gate: the JS runner
rejected it anywhere in the document, the Python runner only at
canonicalization).

Only the verdict is observable through a runner's output ([OK]/[FAIL] plus
the [SUMMARY] line); the reason is not printed, so these checks pin that the
two runners agree on the verdict, not on the reason.
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


EXPECTED_INTEGER_RULE_SUMMARY = "[SUMMARY] positive=1 mutation=1 canary=0 ok=2 fail=0"


def write_integer_rule_suite(tmp_path: Path) -> Path:
    """One positive (the unused-metadata probe) and one mutation (the input
    vector) in a temporary suite, with the frozen schemas copied in so a
    profile that validates a schema before canonicalizing can reach the
    canonicalization step. Returns the suite's ``conformance/vectors`` dir."""
    tmp_root = tmp_path / "suite"
    manifest = load_json(FULL_SUITE / "manifest.json")
    files = cast(dict[str, list[str]], manifest["files"])
    for rel_path in files["schemas"]:
        dest = tmp_root / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / rel_path, dest)

    probe_rel = f"conformance/vectors/positive/{UNUSED_METADATA_PROBE_ID}.json"
    input_rel = "conformance/vectors/mutation/check-unsafe-integer-ingest.json"
    for rel_path, vector in (
        (probe_rel, unused_metadata_probe_vector()),
        (input_rel, UNSAFE_INTEGER_INPUT_VECTOR),
    ):
        path = tmp_root / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        # json.dumps writes the int in plain decimal: the literal form under test.
        path.write_text(json.dumps(vector, indent=2) + "\n", encoding="utf-8")

    mini_manifest = {
        "counts": {"positive": 1, "mutation": 1, "canary": 0, "diag_canonical_bytes": 0},
        "files": {
            "positive": [probe_rel],
            "mutation": [input_rel],
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
