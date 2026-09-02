"""A2A #2031: the independent ERDL Decision Object v1.5 conformance runner.

Covers `docs/interop/a2a-2031-erdl-v15/runner.py`, an independently authored
implementation of the ERDL RUNNER_CONTRACT R1-R6 built from the contract text
and the published vector set alone.

The suite is in two halves:

* **Synthetic tests, always run.** Every detection rule is exercised against a
  hand-built decision object, and each one is checked twice: it fires on the
  mutated object and stays silent on the clean one. A rule that cannot be shown
  to fail on a planted divergence is not evidence of anything, and several of
  these rules (the `gloss` exclusion, the JCS domain guards) are not exercised
  by the v1.5 corpus at all.
* **Corpus tests, skipped when the upstream vector file is absent.** The
  vectors are OpenOBA's, not this repository's, so they are referenced by
  digest rather than vendored. Point `ERDL_V15_VECTORS` at a local copy to run
  them; CI runs the synthetic half.

The canonical bytes are additionally cross-checked against the INDEPENDENT
`rfc8785` reference canonicalizer, so agreement is between two separately
authored implementations rather than a restatement of one.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import rfc8785

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNNER_PATH = REPO_ROOT / "docs" / "interop" / "a2a-2031-erdl-v15" / "runner.py"
COMMITTED_CANONICAL_HEX = (
    REPO_ROOT
    / "docs"
    / "interop"
    / "a2a-2031-erdl-v15"
    / "concordia-python-erdl-do-v15-output.json.txt"
)

#: SHA-256 of the exact upstream vector file this artifact was measured against.
VECTORS_SHA256 = "d8adf32b7c691bdb3d805fdb0b3f7ac327dc16388cd59a4dfe757d9555e1778c"


def _load_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("erdl_do_v15_runner", RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before executing: @dataclass resolves annotations through
    # sys.modules[cls.__module__], which is absent for a path-loaded module.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_named(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = _load_runner()


# ---------------------------------------------------------------------------
# Synthetic decision object
# ---------------------------------------------------------------------------


def _base_decision_object() -> dict[str, Any]:
    """A minimal v1.5 decision object that trips no rule.

    `audit.hash` is filled in by `_seal` so the object is self-consistent by
    construction; every mutation test then plants exactly one divergence.
    """
    return {
        "spec": "decision-object-v1.5",
        "decision_id": "019b5c5a-0000-7000-8000-00000000aaaa",
        "timestamp": "2026-08-22T00:00:00.000Z",
        "compliance_profile": {
            "profile_id": "erdl-compliance-v1.5",
            "jurisdictions": ["CN"],
            "risk_level": "low",
            "activated_fields": ["autonomy_level"],
        },
        "autonomy_level": "L2",
        "agent": {"id": "did:erdl:sha256:unit-test-agent", "role": "guardian"},
        "context": {"operation": "read"},
        "policies": [
            {
                "id": "rule-unit",
                "when": {"eq": [{"field": "context.operation"}, "read"]},
                "then": "ALLOW",
                "author_id": "author-independent",
            }
        ],
        "evaluation": {
            "matched_rules": [
                {
                    "rule_id": "rule-unit",
                    "canonical_tree": {"eq": [{"field": "context.operation"}, "read"]},
                }
            ],
            "knowledge_references": [{"entry_id": "kb-001", "entry_version": "v1"}],
        },
        "result": {"decision": "ALLOW", "reason": "Decision: ALLOW"},
        "human_oversight": {"required": False},
        "audit": {
            "mode": "hash",
            "hash": "sha256:" + "0" * 64,
            "previous_hash": None,
            "preimage_version": runner.PREIMAGE_VERSION,
            "chain_id": "chain-unit",
            "chain_seq": 0,
        },
    }


def _seal(decision_object: dict[str, Any]) -> dict[str, Any]:
    """Recompute and store `audit.hash` so the object passes Check 1."""
    sealed = copy.deepcopy(decision_object)
    sealed["audit"]["hash"] = runner.recompute_audit_hash(sealed)[0]
    return sealed


def _verify(decision_object: dict[str, Any]) -> Any:
    return runner.verify_decision_object("unit", "unit", decision_object)


# ---------------------------------------------------------------------------
# JCS domain guards (not exercised by the v1.5 corpus)
# ---------------------------------------------------------------------------


def test_safe_integer_boundary_is_accepted() -> None:
    """2^53 - 1 is exactly representable, so it canonicalizes."""
    assert runner.canonical_bytes({"n": runner.MAX_SAFE_INTEGER}) == b'{"n":9007199254740991}'


@pytest.mark.parametrize("value", [2**53, -(2**53), 2**64])
def test_unsafe_integer_is_rejected(value: int) -> None:
    """Beyond the IEEE-754 safe range two conforming runners can disagree."""
    with pytest.raises(runner.DomainError, match="safe range"):
        runner.canonical_bytes({"n": value})


def test_lone_surrogate_is_rejected() -> None:
    """An unpaired surrogate has no UTF-8 encoding; fail closed, never crash."""
    with pytest.raises(runner.DomainError, match="surrogate"):
        runner.canonical_bytes({"s": "bad\ud800tail"})


def test_lone_surrogate_in_object_key_is_rejected() -> None:
    with pytest.raises(runner.DomainError, match="surrogate"):
        runner.canonical_bytes({"bad\udfffkey": 1})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -0.0])
def test_non_representable_floats_are_rejected(value: float) -> None:
    with pytest.raises(runner.DomainError):
        runner.canonical_bytes({"n": value})


def test_domain_validation_reports_every_offending_path() -> None:
    """A malformed artifact should be diagnosable, not merely refused."""
    with pytest.raises(runner.DomainError) as excinfo:
        runner.canonical_bytes({"a": 2**53, "b": {"c": 2**60}})
    message = str(excinfo.value)
    assert "$.a" in message and "$.b.c" in message


def test_non_ascii_is_emitted_as_raw_utf8() -> None:
    """RFC 8785 escapes only the seven mandatory escapes and control chars."""
    assert runner.canonical_bytes({"k": "é中"}) == '{"k":"é中"}'.encode()


# ---------------------------------------------------------------------------
# R1 / R2: preimage construction
# ---------------------------------------------------------------------------


def test_canonical_bytes_agree_with_independent_rfc8785_reference() -> None:
    """Two separately authored canonicalizers land on the same bytes."""
    preimage = runner.flat_preimage(_seal(_base_decision_object()))
    assert runner.canonical_bytes(preimage) == rfc8785.dumps(preimage)


def test_flat_preimage_deletes_exactly_the_excluded_fields() -> None:
    decision_object = _seal(_base_decision_object())
    decision_object["signature"] = "sig"
    decision_object["signing_key_id"] = "key-1"
    preimage = runner.flat_preimage(decision_object)
    assert "hash" not in preimage["audit"]
    assert "signature" not in preimage and "signing_key_id" not in preimage
    # Everything else participates unconditionally: no whitelist, no projection.
    assert set(preimage) == set(decision_object) - {"signature", "signing_key_id"}
    assert set(preimage["audit"]) == set(decision_object["audit"]) - {"hash"}


def test_signature_field_deletion_is_a_no_op_in_hash_mode() -> None:
    """R2: the defensive deletion must not change the bytes when absent."""
    decision_object = _seal(_base_decision_object())
    assert "signature" not in decision_object
    with_deletion = runner.canonical_bytes(runner.flat_preimage(decision_object))
    manual = copy.deepcopy(decision_object)
    del manual["audit"]["hash"]
    assert with_deletion == runner.canonical_bytes(manual)


def test_recomputed_hash_matches_a_sealed_object() -> None:
    decision_object = _seal(_base_decision_object())
    assert _verify(decision_object).check1 == "MATCH"


def test_blanking_audit_hash_is_not_deletion() -> None:
    """R1 forbids blanking: the two produce different JCS bytes."""
    decision_object = _seal(_base_decision_object())
    blanked = copy.deepcopy(decision_object)
    blanked["audit"]["hash"] = ""
    assert runner.canonical_bytes(runner.flat_preimage(decision_object)) != runner.canonical_bytes(
        blanked
    )


def test_deleting_the_whole_audit_is_the_defect_the_canary_catches() -> None:
    """R5's mechanism, on a synthetic object rather than only on K01.

    A decision object sealed by the *defective* rule (delete the whole `audit`)
    verifies MATCH under that same defective rule and MISMATCH under the
    correct one. That asymmetry is the entire discriminating power of the
    canary, so it is asserted directly.
    """
    decision_object = _base_decision_object()
    without_audit = copy.deepcopy(decision_object)
    del without_audit["audit"]
    defective_hash = "sha256:" + hashlib.sha256(runner.canonical_bytes(without_audit)).hexdigest()
    decision_object["audit"]["hash"] = defective_hash

    correct, _ = runner.recompute_audit_hash(decision_object)
    assert correct != defective_hash
    assert _verify(decision_object).check1 == "MISMATCH"


def test_policy_hash_excludes_itself_and_gloss() -> None:
    """R2: `gloss` is a render product, so it never enters the policy preimage.

    The v1.5 corpus carries no policy with a `gloss` member, so this rule is
    implemented from the contract text and can only be evidenced here.
    """
    policy = {
        "id": "rule-unit",
        "when": {"eq": [{"field": "context.operation"}, "read"]},
        "then": "ALLOW",
    }
    bare = runner.recompute_policy_hash(policy)
    assert runner.recompute_policy_hash({**policy, "hash": "sha256:" + "f" * 64}) == bare
    assert runner.recompute_policy_hash({**policy, "gloss": "human readable"}) == bare
    # A real rule-content change must still move the hash.
    assert runner.recompute_policy_hash({**policy, "then": "DENY"}) != bare


def test_profile_hash_excludes_itself_only() -> None:
    profile = {"profile_id": "erdl-compliance-v1.5", "jurisdictions": ["CN"]}
    bare = runner.recompute_profile_hash(profile)
    assert runner.recompute_profile_hash({**profile, "profile_hash": "sha256:" + "f" * 64}) == bare
    assert runner.recompute_profile_hash({**profile, "risk_level": "low"}) != bare


def test_intra_field_hash_divergence_is_surfaced_as_a_note() -> None:
    """A stale `profile_hash` must never pass silently."""
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["profile_hash"] = "sha256:" + "e" * 64
    result = _verify(_seal(decision_object))
    assert result.check1 == "MATCH"
    assert any("profile_hash does not recompute" in note for note in result.notes)


# ---------------------------------------------------------------------------
# Version gate
# ---------------------------------------------------------------------------


def test_unsupported_version_terminates_before_producing_bytes() -> None:
    """Contract section 4: a version-gated DO must have no oracle key."""
    decision_object = _seal(_base_decision_object())
    decision_object["audit"]["preimage_version"] = "erdl-do-v1.3-hash-flat"
    result = _verify(decision_object)
    assert result.applicable is False
    assert result.check1 == "NOT_APPLICABLE"
    assert result.canonical_hex is None
    assert result.codes == ["version_unsupported"]


def test_supported_version_produces_bytes() -> None:
    result = _verify(_seal(_base_decision_object()))
    assert result.applicable is True and result.canonical_hex is not None


# ---------------------------------------------------------------------------
# R3: single decision object, P1 -> P6
# ---------------------------------------------------------------------------


def test_clean_object_trips_no_semantic_rule() -> None:
    assert _verify(_seal(_base_decision_object())).codes == []


def test_jurisdiction_outside_the_authoritative_set_is_p1() -> None:
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["jurisdictions"] = ["XX"]
    assert "jurisdiction_mismatch" in _verify(_seal(decision_object)).codes


@pytest.mark.parametrize("code", sorted(runner.AUTHORITATIVE_JURISDICTIONS))
def test_each_authoritative_jurisdiction_is_accepted(code: str) -> None:
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["jurisdictions"] = [code]
    assert "jurisdiction_mismatch" not in _verify(_seal(decision_object)).codes


def test_activated_field_absent_from_the_object_is_p2() -> None:
    decision_object = _base_decision_object()
    del decision_object["autonomy_level"]
    assert "compliance_field_missing" in _verify(_seal(decision_object)).codes


def test_activated_dotted_field_is_resolved_through_nesting() -> None:
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["activated_fields"] = ["agent.role"]
    assert "compliance_field_missing" not in _verify(_seal(decision_object)).codes
    decision_object["compliance_profile"]["activated_fields"] = ["agent.aid"]
    assert "compliance_field_missing" in _verify(_seal(decision_object)).codes


def test_critical_risk_without_activated_signature_is_p2() -> None:
    """R3 names this case explicitly."""
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["risk_level"] = "critical"
    decision_object["human_oversight"]["required"] = True
    assert "compliance_field_missing" in _verify(_seal(decision_object)).codes


def test_critical_risk_with_activated_but_absent_signature_is_p2() -> None:
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["risk_level"] = "critical"
    decision_object["compliance_profile"]["activated_fields"].append("signature")
    decision_object["human_oversight"]["required"] = True
    assert "compliance_field_missing" in _verify(_seal(decision_object)).codes


@pytest.mark.parametrize("risk", ["high", "critical"])
def test_elevated_risk_without_human_oversight_is_p3(risk: str) -> None:
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["risk_level"] = risk
    decision_object["compliance_profile"]["activated_fields"].append("signature")
    decision_object["signature"] = "sig"
    assert "oversight_missing" in _verify(_seal(decision_object)).codes
    decision_object["human_oversight"]["required"] = True
    assert "oversight_missing" not in _verify(_seal(decision_object)).codes


def test_low_risk_without_human_oversight_is_not_a_breach() -> None:
    assert "oversight_missing" not in _verify(_seal(_base_decision_object())).codes


def test_policy_authored_by_the_deciding_agent_is_p4() -> None:
    decision_object = _base_decision_object()
    decision_object["policies"][0]["author_id"] = decision_object["agent"]["id"]
    assert "sod_violation" in _verify(_seal(decision_object)).codes


def test_canonical_tree_node_order_swap_is_p5() -> None:
    decision_object = _base_decision_object()
    decision_object["evaluation"]["matched_rules"][0]["canonical_tree"] = {
        "eq": ["read", {"field": "context.operation"}]
    }
    assert "tree_snapshot_divergence" in _verify(_seal(decision_object)).codes


def test_canonical_tree_literal_precision_change_is_p5() -> None:
    """"0.95" and "0.950" are different canonical bytes, so the tree diverged."""
    decision_object = _base_decision_object()
    decision_object["policies"][0]["when"] = {"eq": [{"field": "context.amount"}, "0.95"]}
    decision_object["evaluation"]["matched_rules"][0]["canonical_tree"] = {
        "eq": [{"field": "context.amount"}, "0.950"]
    }
    assert "tree_snapshot_divergence" in _verify(_seal(decision_object)).codes


def test_matched_rule_with_no_policy_is_p5() -> None:
    decision_object = _base_decision_object()
    decision_object["evaluation"]["matched_rules"][0]["rule_id"] = "rule-absent"
    assert "tree_snapshot_divergence" in _verify(_seal(decision_object)).codes


def test_unresolvable_knowledge_reference_is_p6() -> None:
    decision_object = _base_decision_object()
    decision_object["evaluation"]["knowledge_references"] = [{"entry_id": "kb-nonexistent"}]
    assert "content_unresolvable" in _verify(_seal(decision_object)).codes


def test_resolvable_universe_is_a_runner_input() -> None:
    """The contract defers this rule elsewhere, so the universe is configurable."""
    decision_object = _seal(_base_decision_object())
    assert "content_unresolvable" in runner.verify_decision_object(
        "unit", "unit", decision_object, resolvable_entry_ids=["kb-other"]
    ).codes


# ---------------------------------------------------------------------------
# R3 priority
# ---------------------------------------------------------------------------


def test_priority_ladder_is_the_contract_order() -> None:
    assert runner.SINGLE_DO_PRIORITY == (
        "jurisdiction_mismatch",
        "compliance_field_missing",
        "oversight_missing",
        "sod_violation",
        "tree_snapshot_divergence",
        "content_unresolvable",
    )
    assert runner.CHAIN_PRIORITY == (
        "hash_mismatch",
        "version_unsupported",
        "chain_genesis_mismatch",
        "previous_hash_dangling",
        "chain_seq_gap",
        "mode_mixed_chain",
        "time_regression",
    )


def test_p1_outranks_p2_and_p2_is_reported_as_also_present() -> None:
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["jurisdictions"] = ["XX"]
    del decision_object["autonomy_level"]
    result = _verify(_seal(decision_object))
    ordered = [b.code for b in runner._ordered_single(result)]
    assert ordered[0] == "jurisdiction_mismatch"
    assert "compliance_field_missing" in ordered[1:]


def test_a_warning_never_masks_a_breach() -> None:
    """P6 is warning-level and MUST stay last."""
    decision_object = _base_decision_object()
    decision_object["evaluation"]["matched_rules"][0]["canonical_tree"] = {"eq": []}
    decision_object["evaluation"]["knowledge_references"] = [{"entry_id": "kb-gone"}]
    ordered = [b.code for b in runner._ordered_single(_verify(_seal(decision_object)))]
    assert ordered == ["tree_snapshot_divergence", "content_unresolvable"]


def test_hash_mismatch_outranks_the_semantic_ladder() -> None:
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["jurisdictions"] = ["XX"]
    sealed = _seal(decision_object)
    sealed["audit"]["hash"] = "sha256:" + "1" * 64
    ordered = [b.code for b in runner._ordered_single(_verify(sealed))]
    assert ordered[0] == "hash_mismatch"


# ---------------------------------------------------------------------------
# Chain rules
# ---------------------------------------------------------------------------


def _chain(length: int = 3) -> list[dict[str, Any]]:
    """Build a well-formed serially anchored chain."""
    members: list[dict[str, Any]] = []
    previous: str | None = None
    for index in range(length):
        member = _base_decision_object()
        member["decision_id"] = f"019b5c5a-0000-7000-8000-0000000000{index:02d}"
        member["audit"]["chain_seq"] = index
        member["audit"]["previous_hash"] = previous
        member = _seal(member)
        previous = member["audit"]["hash"]
        members.append(member)
    return members


def _chain_codes(members: list[dict[str, Any]]) -> list[str]:
    results = [
        runner.verify_decision_object(f"unit[{i}]", "unit", m) for i, m in enumerate(members)
    ]
    return [b.code for b in runner.detect_chain_breaches(members, results)]


def test_well_formed_chain_trips_nothing() -> None:
    assert _chain_codes(_chain()) == []


def test_genesis_with_a_previous_hash_is_a_genesis_mismatch() -> None:
    members = _chain()
    members[0]["audit"]["previous_hash"] = "sha256:" + "e" * 64
    assert "chain_genesis_mismatch" in _chain_codes(members)


def test_broken_previous_hash_link_is_dangling() -> None:
    members = _chain()
    members[1]["audit"]["previous_hash"] = "sha256:" + "f" * 64
    assert "previous_hash_dangling" in _chain_codes(members)


def test_non_consecutive_chain_seq_is_a_gap() -> None:
    members = _chain()
    members[1]["audit"]["chain_seq"] = 2
    members[2]["audit"]["chain_seq"] = 3
    assert "chain_seq_gap" in _chain_codes(members)


def test_mixed_audit_mode_is_a_mixed_chain() -> None:
    members = _chain()
    members[1]["audit"]["mode"] = "signature"
    assert "mode_mixed_chain" in _chain_codes(members)


def test_backwards_timestamp_is_a_time_regression() -> None:
    members = _chain()
    members[2]["timestamp"] = "2026-08-21T00:00:00.000Z"
    assert "time_regression" in _chain_codes(members)


def test_member_hash_mismatch_is_lifted_to_the_chain_and_outranks_the_rest() -> None:
    members = _chain()
    members[1]["audit"]["hash"] = "sha256:" + "1" * 64
    codes = _chain_codes(members)
    assert codes[0] == "hash_mismatch"


def test_member_version_gate_is_lifted_to_the_chain() -> None:
    members = _chain()
    members[1]["audit"]["preimage_version"] = "erdl-do-v1.3-hash-flat"
    assert "version_unsupported" in _chain_codes(members)


# ---------------------------------------------------------------------------
# Vector enumeration and oracle keys
# ---------------------------------------------------------------------------


def test_oracle_key_shapes_follow_contract_section_4() -> None:
    single = {"id": "V-X", "decision_object": {}}
    pair = {"id": "V-Y", "base_do": {}, "tampered_do": {}}
    chain = {"id": "V-Z", "chain": [{}, {}]}
    assert [k for k, _ in runner.enumerate_objects(single)] == ["V-X"]
    assert [k for k, _ in runner.enumerate_objects(pair)] == ["V-Y-base", "V-Y-tampered"]
    assert [k for k, _ in runner.enumerate_objects(chain)] == ["V-Z[0]", "V-Z[1]"]


def test_unrecognised_vector_shape_fails_closed() -> None:
    with pytest.raises(ValueError, match="unrecognised vector shape"):
        runner.enumerate_objects({"id": "V-Q", "something_else": {}})


def test_run_rejects_a_document_for_another_preimage_version() -> None:
    with pytest.raises(ValueError, match="preimage_version"):
        runner.run({"preimage_version": "erdl-do-v1.3-hash-flat", "vectors": []})


def test_also_present_is_checked_in_both_directions() -> None:
    """A breach that holds but is not declared is a defect, and so is the reverse."""
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["jurisdictions"] = ["XX"]
    del decision_object["autonomy_level"]
    vector = {
        "id": "V-SYNTH",
        "category": "synthetic",
        "decision_object": _seal(decision_object),
        "expected": {"type": "BREACH", "breach": "jurisdiction_mismatch"},
    }
    undeclared = runner.verify_vector(vector)
    assert undeclared.reported == "jurisdiction_mismatch"
    assert any("not declared in also_present" in f for f in undeclared.findings)

    vector["expected"]["also_present"] = ["compliance_field_missing"]
    assert runner.verify_vector(vector).findings == []

    vector["expected"]["also_present"] = ["compliance_field_missing", "sod_violation"]
    overdeclared = runner.verify_vector(vector)
    assert any("do not hold" in f for f in overdeclared.findings)


def test_declared_resolvable_set_disagreement_is_reported() -> None:
    vector = {
        "id": "V-SYNTH-R",
        "category": "synthetic",
        "decision_object": _seal(_base_decision_object()),
        "expected": {"type": "MATCH", "resolvable_entry_ids": ["kb-elsewhere"]},
    }
    assert any("resolvable_entry_ids" in f for f in runner.verify_vector(vector).findings)


# ---------------------------------------------------------------------------
# Corpus tests (upstream vectors required)
# ---------------------------------------------------------------------------


def _vectors_path() -> Path | None:
    override = os.environ.get("ERDL_V15_VECTORS")
    if override and Path(override).is_file():
        return Path(override)
    return None


requires_vectors = pytest.mark.skipif(
    _vectors_path() is None,
    reason="upstream decision-object-vectors-v1.5.json not available; "
    "set ERDL_V15_VECTORS to a local copy",
)


@pytest.fixture(scope="module")
def corpus() -> Any:
    path = _vectors_path()
    assert path is not None
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == VECTORS_SHA256, (
        "the vector file does not match the digest this artifact was measured "
        "against; re-measure before trusting any count"
    )
    return runner.run(json.loads(raw.decode("utf-8")))


@requires_vectors
def test_every_vector_matches_its_declared_expectation(corpus: Any) -> None:
    failures = [v.vector_id for v in corpus.vectors if not v.outcome_ok]
    assert failures == []
    assert corpus.vector_outcome_ok == corpus.vector_total == 78


@requires_vectors
def test_object_and_check1_counts_are_reported_separately(corpus: Any) -> None:
    """The two granularities upstream wording collapses into one "78/78"."""
    assert corpus.object_total == 108
    assert corpus.object_applicable == 107
    assert corpus.check1_not_applicable == 1
    assert corpus.check1_match == 90
    assert corpus.check1_mismatch == 17
    assert corpus.check1_match + corpus.check1_mismatch == corpus.object_applicable


@requires_vectors
def test_canonical_hex_has_exactly_the_applicable_keys(corpus: Any) -> None:
    canonical_hex = corpus.canonical_hex()
    assert len(canonical_hex) == 107
    assert "V-DO-v15-C07[1]" not in canonical_hex
    assert all(len(v) % 2 == 0 and v for v in canonical_hex.values())


@requires_vectors
def test_k01_check1_is_mismatch(corpus: Any) -> None:
    """R5: the canary's acceptance criterion on the runner side."""
    canary = corpus.canary()
    assert canary is not None and canary.check1 == "MISMATCH"


@requires_vectors
def test_corpus_produces_no_findings(corpus: Any) -> None:
    assert corpus.findings == []


@requires_vectors
def test_planted_corpus_defects_are_all_caught() -> None:
    """78/78 is only evidence if the runner can fail. Prove it can.

    Each mutation repairs or breaks exactly one thing the corpus depends on,
    including sealing K01 so a defective runner would call it MATCH. A
    mutation the runner absorbs silently would mean the corresponding rule is
    decorative.
    """
    path = _vectors_path()
    assert path is not None
    document = json.loads(path.read_text(encoding="utf-8"))

    def vector(doc: dict[str, Any], vector_id: str) -> dict[str, Any]:
        return next(v for v in doc["vectors"] if v["id"] == vector_id)

    def seal_canary(doc: dict[str, Any]) -> None:
        canary = vector(doc, "V-DO-v15-K01")["decision_object"]
        canary["audit"]["hash"] = runner.recompute_audit_hash(canary)[0]

    def restore_tampered(doc: dict[str, Any]) -> None:
        pair = vector(doc, "V-DO-v15-A01")
        pair["tampered_do"] = copy.deepcopy(pair["base_do"])

    def realign_tree(doc: dict[str, Any]) -> None:
        obj = vector(doc, "V-DO-v15-A09")["decision_object"]
        obj["evaluation"]["matched_rules"][0]["canonical_tree"] = copy.deepcopy(
            obj["policies"][0]["when"]
        )

    mutations: dict[str, Any] = {
        "corrupt a passing audit.hash": lambda d: vector(d, "V-DO-v15-D01")[
            "decision_object"
        ]["audit"].update(hash="sha256:" + "0" * 64),
        "restore a tampered side": restore_tampered,
        "seal the K01 canary": seal_canary,
        "un-trip the version gate": lambda d: vector(d, "V-DO-v15-C07")["chain"][1][
            "audit"
        ].update(preimage_version=runner.PREIMAGE_VERSION),
        "plant an undeclared simultaneous breach": lambda d: vector(d, "V-COMP-F03")[
            "decision_object"
        ]["agent"].pop("aid"),
        "de-conflict the SoD policy author": lambda d: vector(d, "V-COMP-F05")[
            "decision_object"
        ]["policies"][0].update(author_id="author-openoba"),
        "realign a divergent canonical_tree": realign_tree,
        "close the chain_seq gap": lambda d: vector(d, "V-DO-v15-C03")["chain"][1][
            "audit"
        ].update(chain_seq=1),
        "remove the time regression": lambda d: vector(d, "V-DO-v15-C05")["chain"][2].update(
            timestamp="2026-08-23T00:00:00.000Z"
        ),
        "normalise the sentinel jurisdiction": lambda d: vector(d, "V-COMP-F10")[
            "decision_object"
        ]["compliance_profile"].update(jurisdictions=["CN"]),
    }

    absorbed: list[str] = []
    for label, mutate in mutations.items():
        mutated = copy.deepcopy(document)
        mutate(mutated)
        report = runner.run(mutated)
        caught = report.vector_outcome_ok != report.vector_total or bool(report.findings)
        if not caught:
            absorbed.append(label)
    assert absorbed == []


@requires_vectors
def test_committed_output_matches_a_fresh_run(corpus: Any) -> None:
    """Byte drift in the published artifact is a hard failure."""
    published = json.loads(COMMITTED_CANONICAL_HEX.read_text(encoding="utf-8"))
    assert published["k01_check1"] == "MISMATCH"
    assert published["canonical_hex"] == corpus.canonical_hex()


# ---------------------------------------------------------------------------
# The shipped answer-key verifier (runs without the upstream vectors)
# ---------------------------------------------------------------------------


def test_shipped_verifier_passes() -> None:
    """`verify.py` re-derives every published byte string and exits 0.

    It uses the independent `rfc8785` package rather than Concordia's own
    canonicalizer, so this is a cross-check between two separately authored
    implementations, not a restatement of one.
    """
    verify = _load_named(RUNNER_PATH.parent / "verify.py", "erdl_do_v15_verify")
    assert verify.main() == 0


def test_shipped_verifier_catches_a_planted_divergence(tmp_path: Path) -> None:
    """An unproven guard is not evidence, so the guard is made to fail.

    Each planted defect is one the verifier exists to catch: bytes that parse
    but are not canonical form, a preimage that kept `audit.hash`, a canary
    reported as MATCH, and a broken chain anchor.
    """
    verify = _load_named(RUNNER_PATH.parent / "verify.py", "erdl_do_v15_verify_neg")
    envelope = json.loads(COMMITTED_CANONICAL_HEX.read_text(encoding="utf-8"))

    canary_match = copy.deepcopy(envelope)
    canary_match["k01_check1"] = "MATCH"
    with pytest.raises(verify.VerificationError, match="MISMATCH"):
        verify.verify_envelope(canary_match)

    dropped = copy.deepcopy(envelope)
    dropped["canonical_hex"].pop("V-DO-v15-D01")
    with pytest.raises(verify.VerificationError, match="canonical_hex keys"):
        verify.verify_envelope(dropped)

    version_gated = copy.deepcopy(envelope)
    # Swap rather than add, so the key count stays 107 and the version-gate
    # check is the one that has to catch this.
    version_gated["canonical_hex"].pop("V-DO-v15-D01")
    version_gated["canonical_hex"]["V-DO-v15-C07[1]"] = "7b7d"
    with pytest.raises(verify.VerificationError, match="version-gated"):
        verify.verify_envelope(version_gated)

    # Valid JSON, valid UTF-8, but keys out of RFC 8785 order.
    not_canonical = {"V-DO-v15-D01": b'{"b":1,"a":2}'.hex()}
    with pytest.raises(verify.VerificationError, match="not RFC 8785 canonical"):
        verify.verify_canonical_bytes(not_canonical)

    # Canonical bytes that kept the field R2 requires deleted.
    kept_hash = rfc8785.dumps(
        {"audit": {"hash": "sha256:" + "0" * 64, "preimage_version": runner.PREIMAGE_VERSION}}
    )
    with pytest.raises(verify.VerificationError, match="audit.hash"):
        verify.verify_canonical_bytes({"V-X": kept_hash.hex()})

    broken_anchor = copy.deepcopy(envelope["canonical_hex"])
    member1 = json.loads(bytes.fromhex(broken_anchor["V-DO-v15-C01[1]"]).decode())
    member1["audit"]["previous_hash"] = "sha256:" + "f" * 64
    broken_anchor["V-DO-v15-C01[1]"] = rfc8785.dumps(member1).hex()
    with pytest.raises(verify.VerificationError, match="previous_hash"):
        verify.verify_chain_anchoring(broken_anchor)

    assert tmp_path.exists()
