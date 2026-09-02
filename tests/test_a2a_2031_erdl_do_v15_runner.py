"""A2A #2031: the independent ERDL Decision Object v1.5 hash-layer runner.

Covers `conformance/erdl-do-v1.5/runner.py`, an independently authored
implementation of the ERDL RUNNER_CONTRACT hash, field and chain layer, built
from the contract text and the published vector set alone. It is a submission
candidate, not a conforming runner: only upstream can run Check 2.

The suite is in two halves:

* **Synthetic tests, always run.** Every detection rule is exercised against a
  hand-built decision object, and each one is checked twice: it fires on the
  mutated object and stays silent on the clean one. A rule that cannot be shown
  to fail on a planted divergence is not evidence of anything, and several of
  these rules (the `gloss` exclusion, the JCS domain guards, the cross-object
  breach ranking, the chain semantic merge) are not exercised by the v1.5
  corpus at all.
* **Corpus tests, skipped when the upstream vector file is absent.** The
  vectors are OpenOBA's, not this repository's, so they are referenced by
  digest rather than vendored. Point `ERDL_V15_VECTORS` at a local copy to run
  them; CI runs the synthetic half.

The canonical bytes are additionally cross-checked against the INDEPENDENT
`rfc8785` reference canonicalizer, so agreement is between two separately
authored implementations rather than a restatement of one. `rfc8785` is a
declared dev dependency in `pyproject.toml` (`[project.optional-dependencies]
dev`), which is what the `test` CI job installs, so the module-level import
below cannot turn into a collection error on CI.
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
ARTIFACT_DIR = REPO_ROOT / "conformance" / "erdl-do-v1.5"
RUNNER_PATH = ARTIFACT_DIR / "runner.py"
COMMITTED_CANONICAL_HEX = ARTIFACT_DIR / "concordia-python-erdl-do-v15-output.json"

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


def test_k01_counter_requires_its_declared_breach_type() -> None:
    """K01's special Check 1 rule must not bypass expected.type."""
    decision_object = _seal(_base_decision_object())
    decision_object["audit"]["hash"] = "sha256:" + "1" * 64
    vector = {
        "id": runner.CANARY_VECTOR_ID,
        "category": "synthetic",
        "decision_object": decision_object,
        "expected": {
            "type": "BREACH",
            "breach": runner.CANARY_EXPECTATION,
        },
    }
    baseline = runner.verify_vector(vector)
    assert baseline.outcome_ok
    assert runner.RunReport([baseline]).vector_outcome_ok == 1

    for incorrect_type in ("MATCH", "nonsense"):
        mutated = copy.deepcopy(vector)
        mutated["expected"]["type"] = incorrect_type
        result = runner.verify_vector(mutated)
        assert not result.outcome_ok, incorrect_type
        assert runner.RunReport([result]).vector_outcome_ok == 0, incorrect_type


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


def test_intra_field_hash_divergence_survives_a_matching_flat_hash() -> None:
    """A stale `profile_hash` does NOT necessarily break the flat hash.

    This is the refutation of the justification the earlier revision of the
    README gave for demoting intra-field divergence to a suppressible note.
    `profile_hash` is an ordinary field inside the decision object, so it
    participates in the R1 preimage as itself: once the emitter recomputes
    `audit.hash` afterwards, Check 1 passes with the divergence still inside.
    The note is therefore the ONLY surface for it, which is why the note is a
    finding rather than a diagnostic that a vector kind can suppress.
    """
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["profile_hash"] = "sha256:" + "e" * 64
    result = _verify(_seal(decision_object))
    assert result.check1 == "MATCH"
    assert "hash_mismatch" not in result.codes
    assert any("does not recompute" in str(note) for note in result.notes)


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


def _ranked_codes(decision_object: dict[str, Any]) -> list[str]:
    """Report order for one decision object, through the production path.

    Ranking is done by `verify_vector`, so asserting it here exercises the code
    a run actually takes rather than a helper kept alive only by its tests.
    """
    result = runner.verify_vector(
        {
            "id": "V-RANK",
            "category": "synthetic",
            "decision_object": decision_object,
            "expected": {"type": "MATCH"},
        }
    )
    return ([result.reported] if result.reported else []) + result.also_present


def test_p1_outranks_p2_and_p2_is_reported_as_also_present() -> None:
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["jurisdictions"] = ["XX"]
    del decision_object["autonomy_level"]
    ordered = _ranked_codes(_seal(decision_object))
    assert ordered[0] == "jurisdiction_mismatch"
    assert "compliance_field_missing" in ordered[1:]


def test_a_warning_never_masks_a_breach() -> None:
    """P6 is warning-level and MUST stay last."""
    decision_object = _base_decision_object()
    decision_object["evaluation"]["matched_rules"][0]["canonical_tree"] = {"eq": []}
    decision_object["evaluation"]["knowledge_references"] = [{"entry_id": "kb-gone"}]
    ordered = _ranked_codes(_seal(decision_object))
    assert ordered == ["tree_snapshot_divergence", "content_unresolvable"]


def test_chain_priority_is_extended_by_the_semantic_ladder_not_replaced() -> None:
    assert runner.CHAIN_FULL_PRIORITY == runner.CHAIN_PRIORITY + runner.SINGLE_DO_PRIORITY
    assert runner.CHAIN_FULL_PRIORITY[-1] == "content_unresolvable"


def test_time_anchoring_codes_are_declared_unimplemented() -> None:
    """R3's third group is named as absent rather than left to inference.

    The contract binds `clock_drift_detected` / `timestamp_anchor_missing` to
    the signature layer and states no detection rule for either inside the
    permitted input set, so implementing them would be a guess. The gap is
    declared instead, and nothing in the artifact may claim full R3.
    """
    assert runner.UNIMPLEMENTED_R3_CODES == (
        "clock_drift_detected",
        "timestamp_anchor_missing",
    )
    source = RUNNER_PATH.read_text(encoding="utf-8")
    for code in runner.UNIMPLEMENTED_R3_CODES:
        # Named in the declaration, and nowhere used as a detection result.
        assert f'"{code}"' in source
        assert f'Breach("{code}"' not in source


def test_hash_mismatch_outranks_the_semantic_ladder() -> None:
    decision_object = _base_decision_object()
    decision_object["compliance_profile"]["jurisdictions"] = ["XX"]
    sealed = _seal(decision_object)
    sealed["audit"]["hash"] = "sha256:" + "1" * 64
    assert _ranked_codes(sealed)[0] == "hash_mismatch"


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


def _reanchor_chain(members: list[dict[str, Any]]) -> None:
    """Re-seal a synthetic chain so a planted shape defect is isolated."""
    previous: str | None = None
    for member in members:
        member["audit"]["previous_hash"] = previous
        member["audit"]["hash"] = runner.recompute_audit_hash(member)[0]
        previous = member["audit"]["hash"]


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


def _plant_string_chain_seq_gap(members: list[dict[str, Any]]) -> None:
    for member, chain_seq in zip(members, ("0", "2", "3"), strict=True):
        member["audit"]["chain_seq"] = chain_seq


def _plant_numeric_timestamps(members: list[dict[str, Any]]) -> None:
    for member, timestamp in zip(members, (1, 3, 2), strict=True):
        member["timestamp"] = timestamp


def _remove_genesis_chain_seq(members: list[dict[str, Any]]) -> None:
    members[0]["audit"].pop("chain_seq")


def _remove_genesis_timestamp(members: list[dict[str, Any]]) -> None:
    members[0].pop("timestamp")


@pytest.mark.parametrize(
    ("mutate", "finding_fragment"),
    [
        pytest.param(
            _plant_string_chain_seq_gap,
            "audit.chain_seq is str",
            id="sequence-gap-encoded-as-strings",
        ),
        pytest.param(
            _plant_numeric_timestamps,
            "timestamp is int",
            id="numeric-time-regression",
        ),
        pytest.param(
            _remove_genesis_chain_seq,
            "audit.chain_seq is NoneType",
            id="missing-genesis-chain-seq",
        ),
        pytest.param(
            _remove_genesis_timestamp,
            "timestamp is NoneType",
            id="missing-genesis-timestamp",
        ),
    ],
)
def test_malformed_chain_detector_inputs_fail_closed(
    mutate: Any, finding_fragment: str
) -> None:
    """Wrong detector-input types become findings, never silent MATCHes."""
    members = _chain()
    mutate(members)
    _reanchor_chain(members)

    result = runner.verify_vector(_chain_vector(members))

    assert result.reported is None  # no contract breach code is invented
    assert any(finding_fragment in finding for finding in result.findings)


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


def _pair_vector(base: dict[str, Any], tampered: dict[str, Any], **expected: Any) -> dict[str, Any]:
    return {
        "id": "V-PAIR",
        "category": "synthetic",
        "base_do": base,
        "tampered_do": tampered,
        "expected": {"type": "BREACH", "breach": "hash_mismatch", **expected},
    }


def _chain_vector(members: list[dict[str, Any]], **expected: Any) -> dict[str, Any]:
    return {
        "id": "V-CHAIN",
        "category": "synthetic",
        "chain": members,
        "expected": {"type": "MATCH", **expected},
    }


def test_a_base_side_warning_never_outranks_a_tampered_side_breach() -> None:
    """Priority is a property of the vector, not of decision-object order.

    Ranking within each object and then concatenating let a P6 warning on the
    object that happens to come first be reported as the vector's primary
    breach, demoting a real `hash_mismatch` on the second object to
    `also_present`. All breaches are collected across the vector and ranked
    once, so the base side cannot mask the tampered side.
    """
    base = _base_decision_object()
    base["evaluation"]["knowledge_references"] = [{"entry_id": "kb-gone"}]
    tampered = _base_decision_object()
    tampered["audit"]["hash"] = "sha256:" + "1" * 64

    result = runner.verify_vector(
        _pair_vector(_seal(base), tampered, also_present=["content_unresolvable"])
    )
    assert result.reported == "hash_mismatch"
    assert result.also_present == ["content_unresolvable"]
    assert result.outcome_ok and result.findings == []


def test_a_chain_members_semantic_breach_is_merged_not_discarded() -> None:
    """R3 forbids silent passes, and a chain member is still a decision object.

    The chain detectors lift only `hash_mismatch` and `version_unsupported`
    from the members. Computing a member's P1-P6 breaches and then dropping
    them would report a defective chain as a clean MATCH with zero findings.
    """
    for planted, code in (
        (lambda m: m["evaluation"].update(knowledge_references=[{"entry_id": "kb-gone"}]),
         "content_unresolvable"),
        (lambda m: m["evaluation"]["matched_rules"][0].update(canonical_tree={"eq": []}),
         "tree_snapshot_divergence"),
        (lambda m: m["compliance_profile"].update(jurisdictions=["XX"]),
         "jurisdiction_mismatch"),
    ):
        members = [_base_decision_object() for _ in range(3)]
        planted(members[1])
        previous: str | None = None
        for index, member in enumerate(members):
            member["decision_id"] = f"019b5c5a-0000-7000-8000-0000000000{index:02d}"
            member["audit"]["chain_seq"] = index
            member["audit"]["previous_hash"] = previous
            member["audit"]["hash"] = runner.recompute_audit_hash(member)[0]
            previous = member["audit"]["hash"]

        result = runner.verify_vector(_chain_vector(members))
        assert result.reported == code, code
        assert not result.outcome_ok
        assert result.findings


def test_a_chain_level_breach_still_outranks_a_members_semantic_breach() -> None:
    """Merging must not reorder: every chain code outranks every P1-P6 code."""
    members = _chain(2)
    members[1]["audit"]["chain_seq"] = 5
    members[1]["compliance_profile"]["jurisdictions"] = ["XX"]
    members[1] = _seal(members[1])
    result = runner.verify_vector(_chain_vector(members))
    assert result.reported == "chain_seq_gap"
    assert "jurisdiction_mismatch" in result.also_present


def test_an_intra_field_divergence_on_a_pair_is_a_finding() -> None:
    """The recorded exception is keyed to one object and one field, not to a kind.

    Suppressing every note on every pair vector made an identical defect a
    finding on a single-DO vector and silent on a pair. Only the exact
    `V-COMP-F02-tampered` profile-hash case is excused, and it is printed.
    """
    base = _base_decision_object()
    base["compliance_profile"]["profile_hash"] = "sha256:" + "a" * 64
    result = runner.verify_vector(
        _pair_vector(_seal(base), _seal(_base_decision_object()), type="MATCH", breach=None)
    )
    assert any("profile_hash" in finding for finding in result.findings)
    assert result.excused_notes == []


def test_the_recorded_note_exception_is_excused_and_still_reported() -> None:
    key, subject = next(iter(runner.KNOWN_INTRA_FIELD_EXCEPTIONS))
    assert key == "V-COMP-F02-tampered"
    assert subject == "compliance_profile.profile_hash"
    # The exception is scoped to that one key: the same subject elsewhere is a
    # finding, which the previous test asserts on a pair.
    assert len(runner.KNOWN_INTRA_FIELD_EXCEPTIONS) == 1


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda do: do.pop("compliance_profile"), id="profile-removed"),
        pytest.param(lambda do: do.pop("evaluation"), id="evaluation-removed"),
        pytest.param(lambda do: do["agent"].pop("id"), id="agent-id-removed"),
        pytest.param(
            lambda do: do["compliance_profile"].update(jurisdictions="XX"),
            id="jurisdictions-bare-string",
        ),
        pytest.param(
            lambda do: do["evaluation"]["matched_rules"][0].pop("canonical_tree"),
            id="canonical-tree-removed",
        ),
        pytest.param(lambda do: do["policies"][0].pop("when"), id="policy-when-removed"),
        pytest.param(lambda do: do["human_oversight"].update(required="yes"), id="oversight-str"),
        pytest.param(lambda do: do.update(policies={}), id="policies-not-a-list"),
    ],
)
def test_a_malformed_decision_object_fails_closed(mutate: Any) -> None:
    """Every P1-P6 detector returns None on a container it cannot read.

    That is right for a detector, which must not invent a breach code the
    contract does not define, and wrong for the runner: without a shape guard a
    structurally broken object walks the whole ladder in silence. The bare
    string `jurisdictions` is the sharpest case, because `str` is a `Sequence`.
    """
    decision_object = _base_decision_object()
    mutate(decision_object)
    decision_object["audit"]["hash"] = runner.recompute_audit_hash(decision_object)[0]
    vector = {
        "id": "V-SHAPE",
        "category": "synthetic",
        "decision_object": decision_object,
        "expected": {"type": "MATCH"},
    }
    assert runner.verify_vector(vector).findings


def test_a_well_formed_object_trips_no_shape_finding() -> None:
    assert runner._shape_problems(_seal(_base_decision_object())) == []


def test_declared_resolvable_set_disagreement_is_reported() -> None:
    vector = {
        "id": "V-SYNTH-R",
        "category": "synthetic",
        "decision_object": _seal(_base_decision_object()),
        "expected": {"type": "MATCH", "resolvable_entry_ids": ["kb-elsewhere"]},
    }
    result = runner.verify_vector(vector)
    assert not result.outcome_ok
    assert any("resolvable_entry_ids" in f for f in result.findings)


def test_vector_counter_requires_both_auxiliary_expected_fields() -> None:
    """The 78/78 counter covers also_present and resolvable_entry_ids too."""
    vector = {
        "id": "V-SYNTH-COUNT",
        "category": "synthetic",
        "decision_object": _seal(_base_decision_object()),
        "expected": {
            "type": "MATCH",
            "also_present": [],
            "resolvable_entry_ids": ["kb-001"],
        },
    }
    baseline = runner.verify_vector(vector)
    assert baseline.outcome_ok
    assert runner.RunReport([baseline]).vector_outcome_ok == 1

    for field, divergent_value in (
        ("also_present", ["sod_violation"]),
        ("resolvable_entry_ids", ["kb-elsewhere"]),
    ):
        mutated = copy.deepcopy(vector)
        mutated["expected"][field] = divergent_value
        result = runner.verify_vector(mutated)
        assert not result.outcome_ok, field
        assert runner.RunReport([result]).vector_outcome_ok == 0, field


# ---------------------------------------------------------------------------
# Pinned-input binding
# ---------------------------------------------------------------------------


def test_the_runner_pins_the_corpus_digest_the_suite_measured() -> None:
    assert runner.PINNED_VECTORS_SHA256 == VECTORS_SHA256


def test_a_substituted_same_version_corpus_is_refused(tmp_path: Path) -> None:
    """Version agreement is not evidence that a number describes the pinned input.

    A substituted file still declares `erdl-do-v1.5-hash-flat`, still parses,
    and still produces plausible counts. The read is therefore bound to the
    digest, with no override flag.
    """
    substituted = tmp_path / "decision-object-vectors-v1.5.json"
    substituted.write_text(
        json.dumps({"preimage_version": runner.PREIMAGE_VERSION, "vectors": []}),
        encoding="utf-8",
    )
    with pytest.raises(runner.PinnedInputError, match="pinned upstream corpus"):
        runner.load_pinned_vectors(substituted)


def test_the_cli_writes_no_output_for_a_substituted_corpus(tmp_path: Path) -> None:
    substituted = tmp_path / "vectors.json"
    substituted.write_text(
        json.dumps({"preimage_version": runner.PREIMAGE_VERSION, "vectors": []}),
        encoding="utf-8",
    )
    out = tmp_path / "submission.json"
    assert runner.main([str(substituted), "--submission-out", str(out)]) == 2
    assert not out.exists()


def test_the_runner_has_no_digest_opt_out() -> None:
    """A named escape hatch would make every published number conditional."""
    source = RUNNER_PATH.read_text(encoding="utf-8")
    assert "load_pinned_vectors(args.vectors)" in source
    for flag in ("--unsafe", "--no-verify-digest", "--skip-digest", "--force"):
        assert flag not in source


def test_the_submitted_envelope_names_the_corpus_it_describes() -> None:
    envelope = json.loads(COMMITTED_CANONICAL_HEX.read_text(encoding="utf-8"))
    assert VECTORS_SHA256 in envelope["method"]


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
def test_the_only_excused_diagnostic_is_the_recorded_one(corpus: Any) -> None:
    """A suppression is only legitimate if it is scoped, reasoned and visible."""
    assert len(corpus.excused_notes) == 1
    assert "V-COMP-F02-tampered" in corpus.excused_notes[0]
    assert "profile_hash" in corpus.excused_notes[0]


@requires_vectors
def test_no_corpus_object_trips_the_shape_guard(corpus: Any) -> None:
    """The guard's requirements are measured properties of all 108 objects."""
    assert [
        str(note)
        for obj in corpus.objects
        for note in obj.notes
        if note.subject == "shape"
    ] == []


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
def test_planted_r3_path_defects_on_real_vectors_are_all_caught() -> None:
    """The exact adversarial cases the corpus itself cannot reach.

    Each of these was absorbed silently or mis-ranked by an earlier revision.
    They are planted on real corpus vectors rather than synthetic ones so the
    regression is anchored to the same objects the published numbers describe.
    """
    path = _vectors_path()
    assert path is not None
    document = json.loads(path.read_text(encoding="utf-8"))

    def vector(doc: dict[str, Any], vector_id: str) -> dict[str, Any]:
        return next(v for v in doc["vectors"] if v["id"] == vector_id)

    def seal(decision_object: dict[str, Any]) -> None:
        decision_object["audit"]["hash"] = runner.recompute_audit_hash(decision_object)[0]

    def reanchor(chain: list[dict[str, Any]]) -> None:
        previous: str | None = None
        for member in chain:
            member["audit"]["previous_hash"] = previous
            seal(member)
            previous = member["audit"]["hash"]

    def chain_member_p6(doc: dict[str, Any]) -> None:
        chain = vector(doc, "V-DO-v15-C01")["chain"]
        chain[1]["evaluation"]["knowledge_references"] = [{"entry_id": "kb-planted-missing"}]
        reanchor(chain)

    def chain_member_p5(doc: dict[str, Any]) -> None:
        chain = vector(doc, "V-DO-v15-C01")["chain"]
        chain[1]["evaluation"]["matched_rules"][0]["canonical_tree"] = {"eq": []}
        reanchor(chain)

    def pair_base_warning(doc: dict[str, Any]) -> None:
        pair = vector(doc, "V-DO-v15-A01")
        pair["base_do"]["evaluation"]["knowledge_references"] = [
            {"entry_id": "kb-planted-missing"}
        ]
        seal(pair["base_do"])

    def pair_base_profile_hash(doc: dict[str, Any]) -> None:
        pair = vector(doc, "V-DO-v15-A01")
        pair["base_do"]["compliance_profile"]["profile_hash"] = "sha256:" + "a" * 64
        seal(pair["base_do"])

    def pair_base_policy_hash(doc: dict[str, Any]) -> None:
        pair = vector(doc, "V-DO-v15-A01")
        pair["base_do"]["policies"][0]["hash"] = "sha256:" + "b" * 64
        seal(pair["base_do"])

    def single_stale_profile_hash(doc: dict[str, Any]) -> None:
        decision_object = vector(doc, "V-DO-v15-D01")["decision_object"]
        decision_object["compliance_profile"]["profile_hash"] = "sha256:" + "c" * 64
        seal(decision_object)

    def malformed_jurisdictions(doc: dict[str, Any]) -> None:
        decision_object = vector(doc, "V-DO-v15-D01")["decision_object"]
        decision_object["compliance_profile"]["jurisdictions"] = "XX"
        seal(decision_object)

    mutations: dict[str, Any] = {
        "P6 planted in a chain member": chain_member_p6,
        "P5 planted in a chain member": chain_member_p5,
        "P6 planted on a tamper pair's base side": pair_base_warning,
        "stale profile_hash on a tamper pair's base side": pair_base_profile_hash,
        "stale policy hash on a tamper pair's base side": pair_base_policy_hash,
        "stale profile_hash re-sealed so Check 1 still passes": single_stale_profile_hash,
        "jurisdictions replaced by a bare string sentinel": malformed_jurisdictions,
    }

    absorbed: list[str] = []
    for label, mutate in mutations.items():
        mutated = copy.deepcopy(document)
        mutate(mutated)
        report = runner.run(mutated)
        if report.vector_outcome_ok == report.vector_total and not report.findings:
            absorbed.append(label)
    assert absorbed == []


@requires_vectors
def test_a_base_side_warning_does_not_mask_the_tampered_hash_mismatch() -> None:
    """The mis-ranking case, asserted on its outcome rather than only on failure."""
    path = _vectors_path()
    assert path is not None
    document = json.loads(path.read_text(encoding="utf-8"))
    pair = next(v for v in document["vectors"] if v["id"] == "V-DO-v15-A01")
    pair["base_do"]["evaluation"]["knowledge_references"] = [{"entry_id": "kb-planted-missing"}]
    pair["base_do"]["audit"]["hash"] = runner.recompute_audit_hash(pair["base_do"])[0]

    result = runner.verify_vector(pair)
    assert result.reported == "hash_mismatch"
    assert result.also_present == ["content_unresolvable"]


@requires_vectors
def test_committed_output_matches_a_fresh_run(corpus: Any) -> None:
    """Byte drift in the published artifact is a hard failure."""
    published = json.loads(COMMITTED_CANONICAL_HEX.read_text(encoding="utf-8"))
    assert published["k01_check1"] == "MISMATCH"
    assert published["canonical_hex"] == corpus.canonical_hex()


# ---------------------------------------------------------------------------
# The shipped envelope self-check (runs without the upstream vectors)
# ---------------------------------------------------------------------------


def test_shipped_envelope_check_passes() -> None:
    """`verify_envelope.py` re-derives every published byte string and exits 0.

    It uses the independent `rfc8785` package rather than Concordia's own
    canonicalizer, so this is a cross-check between two separately authored
    implementations, not a restatement of one. It is not an answer-key
    verifier: it holds no oracle and cannot establish Check 2 or R5.
    """
    verify = _load_named(ARTIFACT_DIR / "verify_envelope.py", "erdl_do_v15_verify")
    assert verify.main([]) == 0


def test_shipped_envelope_check_takes_the_path_as_an_argument(tmp_path: Path) -> None:
    """The submission rename must not strand the shipped check."""
    verify = _load_named(ARTIFACT_DIR / "verify_envelope.py", "erdl_do_v15_verify_argv")
    renamed = tmp_path / "concordia-python-output.json"
    renamed.write_text(COMMITTED_CANONICAL_HEX.read_text(encoding="utf-8"), encoding="utf-8")
    assert verify.main([str(renamed)]) == 0


def test_shipped_envelope_key_grammar_discriminates() -> None:
    """A character-class check that accepts everything is not a grammar check."""
    verify = _load_named(ARTIFACT_DIR / "verify_envelope.py", "erdl_do_v15_verify_keys")
    for accepted in ("V-DO-v15-D01", "V-COMP-F02-tampered", "V-DO-v15-C01[0]"):
        verify.split_key(accepted)
    for rejected in (
        "V-X-base-base",
        "V-X-tampered-base",
        "totally-bogus-key",
        "V-DO-v15-C01[01]",
        "V-DO-v15-C01[-1]",
    ):
        with pytest.raises(verify.VerificationError):
            verify.split_key(rejected)
    with pytest.raises(verify.VerificationError, match="both sides"):
        verify.verify_key_grammar({"V-Y-base": "00"})
    with pytest.raises(verify.VerificationError, match="gap"):
        verify.verify_key_grammar({"V-Z[0]": "00", "V-Z[2]": "00"})
    # The one hole the contract requires is permitted by name, not by class.
    verify.verify_key_grammar({"V-DO-v15-C07[0]": "00", "V-DO-v15-C07[2]": "00"})

    # An attacker-controlled decimal must be rejected from cardinality alone;
    # it must never become the upper bound of an allocated range/set.
    huge_index = "9" * 10_000
    with pytest.raises(verify.VerificationError, match="cardinality"):
        verify.verify_key_grammar({f"V-Z[{huge_index}]": "00"})


def test_shipped_envelope_check_requires_the_corpus_pin() -> None:
    verify = _load_named(ARTIFACT_DIR / "verify_envelope.py", "erdl_do_v15_verify_pin")
    envelope = json.loads(COMMITTED_CANONICAL_HEX.read_text(encoding="utf-8"))
    envelope["method"] = "Python, contract-only"
    with pytest.raises(verify.VerificationError, match="pinned corpus digest"):
        verify.verify_envelope(envelope)


def test_shipped_envelope_check_catches_a_planted_divergence(tmp_path: Path) -> None:
    """An unproven guard is not evidence, so the guard is made to fail.

    Each planted defect is one the check exists to catch: bytes that parse
    but are not canonical form, a preimage that kept `audit.hash`, a canary
    reported as MATCH, and a broken chain anchor.
    """
    verify = _load_named(ARTIFACT_DIR / "verify_envelope.py", "erdl_do_v15_verify_neg")
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
