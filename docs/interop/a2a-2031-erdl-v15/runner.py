#!/usr/bin/env python3
"""Independent Python conformance runner for ERDL Decision Object v1.5.

Implements the RUNNER_CONTRACT requirements R1-R6 from the contract text
alone. The only ERDL material consulted while writing this file was
`RUNNER_CONTRACT.en.md` and `decision-object-vectors-v1.5.json`; the
reference verifier, the answers file, the verifier guide, the generated
conformance report, and every other implementation were not read. See the
README in this directory for the recorded independence boundary.

What the contract states directly, and what this file therefore implements
without inference:

  R1  audit.hash = "sha256:" + hex(sha256(utf8(JCS(DO - audit.hash))))
      Deletion, never blanking; every other field participates.
  R2  The preimage excludes `audit.hash`, `signature` and `signing_key_id`.
      Intra-field hashes (`policies[].hash`, `compliance_profile.profile_hash`)
      exclude the field being computed; `policies[].hash` also excludes
      `gloss`.
  R3  Breach codes are exposed, never silently passed, in the stated
      priority, and each vector's `expected.also_present` is checked in both
      directions.
  R4  Check 1 (recomputed hash vs the artifact's self-reported `audit.hash`)
      is performed here. Check 2 (recomputed canonical bytes vs the
      independent answers file) is performed by whoever holds the oracle;
      this runner emits the `canonical_hex` map that Check 2 consumes and
      makes no claim about its outcome.
  R5  `V-DO-v15-K01` must come out Check 1 = MISMATCH.
  R6  JCS is implemented in-repo (`concordia.canonicalization`, an
      independently authored RFC 8785 canonicalizer written for Concordia's
      own signing surface). No ERDL SDK and no third-party JCS package is
      used, and the answers file is never opened.

Detection rules the contract names but defines elsewhere (in
`docs/VERIFIER-GUIDE.md` and RFC-002, neither of which was read) were
derived from the vector corpus and are documented, rule by rule, in the
README. Each derived rule was checked to fire on exactly the vectors that
declare it and on no others.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from concordia.canonicalization import canonicalize_jcs  # noqa: E402

# --------------------------------------------------------------------------
# Contract constants
# --------------------------------------------------------------------------

#: The v1.5 preimage constant. A decision object whose `audit.preimage_version`
#: differs is out of scope for this pipeline: the runner terminates early with
#: `version_unsupported` and, per contract section 4, emits no canonical bytes
#: for it.
PREIMAGE_VERSION = "erdl-do-v1.5-hash-flat"

#: RUNNER_CONTRACT R3 narrows `jurisdiction_mismatch` to "the jurisdiction code
#: is not in the authoritative six-jurisdiction set" but does not enumerate the
#: set. These six are the complete set of codes the v1.5 corpus treats as
#: legitimate; the only other code appearing anywhere in the corpus is the
#: sentinel `XX`, on the two vectors that declare `jurisdiction_mismatch`.
AUTHORITATIVE_JURISDICTIONS = frozenset({"BR", "CN", "EU", "IN", "SG", "US"})

#: Risk levels that require human oversight to be recorded as required.
OVERSIGHT_REQUIRED_RISK_LEVELS = frozenset({"high", "critical"})

#: Risk level that additionally requires `signature` among the activated fields.
SIGNATURE_REQUIRED_RISK_LEVEL = "critical"

#: IEEE-754 double integer safety bound. JCS defers number formatting to
#: ECMA-262, where integers beyond this magnitude are not exactly
#: representable, so two conforming implementations can disagree on the bytes.
#: Reject rather than emit bytes that are not reproducible.
MAX_SAFE_INTEGER = 2**53 - 1

#: Knowledge entries the content layer can resolve. The contract defers
#: `content_unresolvable` detection to a document outside the permitted input
#: set, so the resolvable universe is a runner input rather than an inference.
#: This default is cross-checked at runtime against every vector that declares
#: `expected.resolvable_entry_ids`; a disagreement is reported, not absorbed.
DEFAULT_RESOLVABLE_ENTRY_IDS: tuple[str, ...] = ("kb-001",)

#: RUNNER_CONTRACT R3, single decision object, P1 -> P6. `content_unresolvable`
#: is warning-level and MUST stay last so a warning can never mask a breach.
SINGLE_DO_PRIORITY: tuple[str, ...] = (
    "jurisdiction_mismatch",
    "compliance_field_missing",
    "oversight_missing",
    "sod_violation",
    "tree_snapshot_divergence",
    "content_unresolvable",
)

#: RUNNER_CONTRACT R3, chain priority order.
CHAIN_PRIORITY: tuple[str, ...] = (
    "hash_mismatch",
    "version_unsupported",
    "chain_genesis_mismatch",
    "previous_hash_dangling",
    "chain_seq_gap",
    "mode_mixed_chain",
    "time_regression",
)

#: The gate codes evaluated on a single decision object before the P1-P6
#: semantic ladder: the version gate terminates early, and R1/R4 Check 1 is the
#: hash gate. `SINGLE_DO_PRIORITY` follows.
SINGLE_DO_FULL_PRIORITY: tuple[str, ...] = (
    "version_unsupported",
    "hash_mismatch",
) + SINGLE_DO_PRIORITY

#: `V-DO-v15-K01` declares this label rather than one of the R3 breach codes.
#: R5 defines its acceptance directly: Check 1 MISMATCH (and Check 2 MATCH,
#: which only the oracle holder can evaluate).
CANARY_EXPECTATION = "canary_mismatch"
CANARY_VECTOR_ID = "V-DO-v15-K01"

#: Identity recorded in the submission envelope described by the upstream
#: third-party submission guide.
SUBMISSION_RUNNER_NAME = "concordia-python"
SUBMISSION_METHOD = (
    "Python, contract-only, self-built JCS (RFC 8785) + hashlib SHA-256; "
    "no ERDL SDK, no third-party canonicalizer, answers file never opened"
)
SUBMISSION_ARTIFACT = (
    "https://github.com/eriknewton/concordia-protocol/tree/main/"
    "docs/interop/a2a-2031-erdl-v15"
)


class DomainError(ValueError):
    """A value cannot be canonicalized reproducibly under JCS."""


# --------------------------------------------------------------------------
# JCS domain validation and canonical bytes
# --------------------------------------------------------------------------


def validate_jcs_domain(value: Any, path: str = "$") -> None:
    """Reject values whose JCS serialization is not reproducible.

    Three classes, each of which would otherwise produce bytes that another
    conforming implementation could legitimately disagree with:

    * integers outside the IEEE-754 safe range (JCS number formatting defers
      to ECMA-262, whose doubles cannot hold them exactly);
    * non-finite floats and negative zero, which JCS cannot represent;
    * unpaired UTF-16 surrogates, which have no UTF-8 encoding at all and
      which JSON implementations disagree about (some escape them, some
      raise).

    The canonicalizer this runner delegates to already rejects the float and
    surrogate classes. This pass adds the safe-integer bound and reports every
    offending path rather than only the first, so a malformed artifact is
    diagnosable rather than merely refused.
    """
    problems: list[str] = []
    _walk_domain(value, path, problems)
    if problems:
        raise DomainError("; ".join(problems))


def _walk_domain(value: Any, path: str, problems: list[str]) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            problems.append(
                f"{path}: integer {value} exceeds the IEEE-754 safe range "
                f"(|n| > {MAX_SAFE_INTEGER}); JCS bytes would not be reproducible"
            )
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            problems.append(f"{path}: non-finite float {value!r} is not JCS-representable")
        elif value == 0.0 and math.copysign(1.0, value) < 0:
            problems.append(f"{path}: negative zero is not JCS-representable")
        return
    if isinstance(value, str):
        for index, char in enumerate(value):
            if 0xD800 <= ord(char) <= 0xDFFF:
                problems.append(
                    f"{path}[char {index}]: unpaired UTF-16 surrogate "
                    f"U+{ord(char):04X} has no UTF-8 encoding"
                )
                break
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                problems.append(f"{path}: non-string object key {key!r}")
                continue
            _walk_domain(key, f"{path}.{key}<key>", problems)
            _walk_domain(item, f"{path}.{key}", problems)
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _walk_domain(item, f"{path}[{index}]", problems)
        return
    if value is None:
        return
    problems.append(f"{path}: value of type {type(value).__name__} is not JSON")


def canonical_bytes(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes for ``value``."""
    validate_jcs_domain(value)
    return canonicalize_jcs(value)


def sha256_prefixed(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


# --------------------------------------------------------------------------
# R1 / R2: preimages
# --------------------------------------------------------------------------


def flat_preimage(decision_object: Mapping[str, Any]) -> dict[str, Any]:
    """Return the R1 preimage: the DO with the R2-excluded fields deleted.

    `audit.hash` is deleted (never blanked: the two produce different JCS
    bytes, which is exactly what the K01 canary detects). `signature` and
    `signing_key_id` are deleted defensively; in hash mode they are absent and
    the deletion is a no-op.
    """
    clone = copy.deepcopy(dict(decision_object))
    audit = clone.get("audit")
    if isinstance(audit, dict):
        audit.pop("hash", None)
    clone.pop("signature", None)
    clone.pop("signing_key_id", None)
    return clone


def recompute_audit_hash(decision_object: Mapping[str, Any]) -> tuple[str, bytes]:
    """Return ``(recomputed audit.hash, canonical preimage bytes)``."""
    payload = canonical_bytes(flat_preimage(decision_object))
    return sha256_prefixed(payload), payload


def recompute_policy_hash(policy: Mapping[str, Any]) -> str:
    """Return the R2 intra-field hash for one policy.

    The field being computed is removed, and `gloss` is excluded because it is
    a render product rather than rule content. The v1.5 corpus carries no
    policy with a `gloss` member, so the exclusion is implemented from the
    contract text and exercised only by this repository's own tests.
    """
    clone = copy.deepcopy(dict(policy))
    clone.pop("hash", None)
    clone.pop("gloss", None)
    return sha256_prefixed(canonical_bytes(clone))


def recompute_profile_hash(profile: Mapping[str, Any]) -> str:
    """Return the R2 intra-field hash for `compliance_profile`."""
    clone = copy.deepcopy(dict(profile))
    clone.pop("profile_hash", None)
    return sha256_prefixed(canonical_bytes(clone))


def resolve_field_path(decision_object: Mapping[str, Any], dotted: str) -> bool:
    """Return True when ``dotted`` resolves to a present member of the DO."""
    node: Any = decision_object
    for segment in dotted.split("."):
        if not isinstance(node, Mapping) or segment not in node:
            return False
        node = node[segment]
    return True


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Breach:
    code: str
    detail: str

    def __str__(self) -> str:  # pragma: no cover - diagnostic only
        return f"{self.code}: {self.detail}"


@dataclass
class DecisionObjectResult:
    """Per-decision-object outcome. ``key`` is the oracle key from section 4."""

    key: str
    vector_id: str
    applicable: bool
    check1: str  # "MATCH" | "MISMATCH" | "NOT_APPLICABLE"
    stored_hash: str | None
    recomputed_hash: str | None
    canonical_hex: str | None
    breaches: list[Breach] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def codes(self) -> list[str]:
        return [breach.code for breach in self.breaches]


@dataclass
class VectorResult:
    vector_id: str
    category: str
    kind: str  # "single" | "pair" | "chain"
    objects: list[DecisionObjectResult]
    reported: str | None
    also_present: list[str]
    expected_type: str
    expected_breach: str | None
    expected_also_present: list[str]
    outcome_ok: bool
    findings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# R3: single-decision-object breach detection
# --------------------------------------------------------------------------


def detect_jurisdiction_mismatch(decision_object: Mapping[str, Any]) -> Breach | None:
    profile = decision_object.get("compliance_profile")
    if not isinstance(profile, Mapping):
        return None
    codes = profile.get("jurisdictions")
    if not isinstance(codes, Sequence) or isinstance(codes, str):
        return None
    unknown = [c for c in codes if c not in AUTHORITATIVE_JURISDICTIONS]
    if not unknown:
        return None
    return Breach(
        "jurisdiction_mismatch",
        "jurisdiction code(s) not in the authoritative six-jurisdiction set "
        f"{sorted(AUTHORITATIVE_JURISDICTIONS)}: {unknown}",
    )


def detect_compliance_field_missing(decision_object: Mapping[str, Any]) -> Breach | None:
    profile = decision_object.get("compliance_profile")
    if not isinstance(profile, Mapping):
        return None
    activated = profile.get("activated_fields")
    activated_list: list[str] = list(activated) if isinstance(activated, list) else []

    # R3 states this case explicitly: risk_level=critical whose activated_fields
    # does not include `signature`.
    if profile.get("risk_level") == SIGNATURE_REQUIRED_RISK_LEVEL and (
        "signature" not in activated_list
    ):
        return Breach(
            "compliance_field_missing",
            "risk_level=critical but activated_fields does not include 'signature'",
        )

    absent = [
        name for name in activated_list if not resolve_field_path(decision_object, name)
    ]
    if absent:
        return Breach(
            "compliance_field_missing",
            f"activated field(s) declared but absent from the decision object: {absent}",
        )
    return None


def detect_oversight_missing(decision_object: Mapping[str, Any]) -> Breach | None:
    profile = decision_object.get("compliance_profile")
    if not isinstance(profile, Mapping):
        return None
    risk = profile.get("risk_level")
    if risk not in OVERSIGHT_REQUIRED_RISK_LEVELS:
        return None
    oversight = decision_object.get("human_oversight")
    required = oversight.get("required") if isinstance(oversight, Mapping) else None
    if required is True:
        return None
    return Breach(
        "oversight_missing",
        f"risk_level={risk} but human_oversight.required is {required!r}",
    )


def detect_sod_violation(decision_object: Mapping[str, Any]) -> Breach | None:
    """Separation of duties: no policy may be authored by the deciding agent."""
    agent = decision_object.get("agent")
    agent_id = agent.get("id") if isinstance(agent, Mapping) else None
    if not agent_id:
        return None
    policies = decision_object.get("policies")
    if not isinstance(policies, list):
        return None
    offenders = [
        p.get("id")
        for p in policies
        if isinstance(p, Mapping) and p.get("author_id") == agent_id
    ]
    if not offenders:
        return None
    return Breach(
        "sod_violation",
        f"policy author_id equals the deciding agent.id {agent_id!r}: {offenders}",
    )


def detect_tree_snapshot_divergence(decision_object: Mapping[str, Any]) -> Breach | None:
    """The recorded `canonical_tree` must equal the matched policy's `when`.

    Comparison is on canonical bytes, so a node-order swap or a literal
    precision change ("0.95" vs "0.950") diverges even though the two trees
    look equivalent to a human reader.
    """
    evaluation = decision_object.get("evaluation")
    if not isinstance(evaluation, Mapping):
        return None
    matched = evaluation.get("matched_rules")
    if not isinstance(matched, list):
        return None
    policies = decision_object.get("policies")
    by_id: dict[str, Mapping[str, Any]] = {}
    if isinstance(policies, list):
        for policy in policies:
            if isinstance(policy, Mapping) and isinstance(policy.get("id"), str):
                by_id[policy["id"]] = policy

    divergent: list[str] = []
    for entry in matched:
        if not isinstance(entry, Mapping):
            continue
        rule_id = entry.get("rule_id")
        policy = by_id.get(rule_id) if isinstance(rule_id, str) else None
        if policy is None:
            divergent.append(f"{rule_id}: no policy with that id")
            continue
        if canonical_bytes(entry.get("canonical_tree")) != canonical_bytes(policy.get("when")):
            divergent.append(f"{rule_id}: canonical_tree differs from the policy 'when'")
    if not divergent:
        return None
    return Breach("tree_snapshot_divergence", "; ".join(divergent))


def detect_content_unresolvable(
    decision_object: Mapping[str, Any], resolvable_entry_ids: Iterable[str]
) -> Breach | None:
    """Warning-level (P6): a knowledge reference the content layer cannot resolve."""
    evaluation = decision_object.get("evaluation")
    if not isinstance(evaluation, Mapping):
        return None
    references = evaluation.get("knowledge_references")
    if not isinstance(references, list):
        return None
    known = set(resolvable_entry_ids)
    unresolvable = [
        ref.get("entry_id")
        for ref in references
        if isinstance(ref, Mapping) and ref.get("entry_id") not in known
    ]
    if not unresolvable:
        return None
    return Breach(
        "content_unresolvable",
        f"knowledge reference(s) not resolvable against {sorted(known)}: {unresolvable}",
    )


def detect_semantic_breaches(
    decision_object: Mapping[str, Any], resolvable_entry_ids: Iterable[str]
) -> list[Breach]:
    """Return every holding P1-P6 breach, already in contract priority order."""
    known = list(resolvable_entry_ids)
    candidates = {
        "jurisdiction_mismatch": detect_jurisdiction_mismatch(decision_object),
        "compliance_field_missing": detect_compliance_field_missing(decision_object),
        "oversight_missing": detect_oversight_missing(decision_object),
        "sod_violation": detect_sod_violation(decision_object),
        "tree_snapshot_divergence": detect_tree_snapshot_divergence(decision_object),
        "content_unresolvable": detect_content_unresolvable(decision_object, known),
    }
    return [candidates[code] for code in SINGLE_DO_PRIORITY if candidates[code] is not None]  # type: ignore[misc]


# --------------------------------------------------------------------------
# Per-decision-object verification
# --------------------------------------------------------------------------


def version_supported(decision_object: Mapping[str, Any]) -> bool:
    audit = decision_object.get("audit")
    if not isinstance(audit, Mapping):
        return False
    return audit.get("preimage_version") == PREIMAGE_VERSION


def verify_decision_object(
    key: str,
    vector_id: str,
    decision_object: Mapping[str, Any],
    resolvable_entry_ids: Iterable[str] = DEFAULT_RESOLVABLE_ENTRY_IDS,
) -> DecisionObjectResult:
    """Run the version gate, R1/R4 Check 1, R2 intra-field hashes and R3."""
    audit = decision_object.get("audit")
    stored = audit.get("hash") if isinstance(audit, Mapping) else None

    if not version_supported(decision_object):
        declared = audit.get("preimage_version") if isinstance(audit, Mapping) else None
        return DecisionObjectResult(
            key=key,
            vector_id=vector_id,
            applicable=False,
            check1="NOT_APPLICABLE",
            stored_hash=stored if isinstance(stored, str) else None,
            recomputed_hash=None,
            canonical_hex=None,
            breaches=[
                Breach(
                    "version_unsupported",
                    f"audit.preimage_version is {declared!r}, not {PREIMAGE_VERSION!r}; "
                    "the runner terminates before producing canonical bytes",
                )
            ],
        )

    recomputed, payload = recompute_audit_hash(decision_object)
    matched = isinstance(stored, str) and recomputed == stored
    result = DecisionObjectResult(
        key=key,
        vector_id=vector_id,
        applicable=True,
        check1="MATCH" if matched else "MISMATCH",
        stored_hash=stored if isinstance(stored, str) else None,
        recomputed_hash=recomputed,
        canonical_hex=payload.hex(),
    )
    if not matched:
        result.breaches.append(
            Breach(
                "hash_mismatch",
                f"recomputed {recomputed} does not equal the self-reported {stored!r}",
            )
        )

    # R2 intra-field hashes. These are diagnostics rather than breach codes:
    # the contract names no code for them, and a divergence necessarily also
    # breaks the whole-DO flat hash, which is reported as `hash_mismatch`.
    profile = decision_object.get("compliance_profile")
    if isinstance(profile, Mapping) and isinstance(profile.get("profile_hash"), str):
        recomputed_profile = recompute_profile_hash(profile)
        if recomputed_profile != profile["profile_hash"]:
            result.notes.append(
                "compliance_profile.profile_hash does not recompute "
                f"(stored {profile['profile_hash']}, recomputed {recomputed_profile})"
            )
    policies = decision_object.get("policies")
    if isinstance(policies, list):
        for policy in policies:
            if not isinstance(policy, Mapping) or not isinstance(policy.get("hash"), str):
                continue
            recomputed_policy = recompute_policy_hash(policy)
            if recomputed_policy != policy["hash"]:
                result.notes.append(
                    f"policies[{policy.get('id')!r}].hash does not recompute "
                    f"(stored {policy['hash']}, recomputed {recomputed_policy})"
                )

    result.breaches.extend(detect_semantic_breaches(decision_object, resolvable_entry_ids))
    return result


# --------------------------------------------------------------------------
# Chain verification
# --------------------------------------------------------------------------


def detect_chain_breaches(
    members: Sequence[Mapping[str, Any]], results: Sequence[DecisionObjectResult]
) -> list[Breach]:
    """Return every holding chain-level breach, in contract priority order.

    Derived rules, each of which fires on exactly the vector that declares it:

    * `chain_genesis_mismatch` - the seq-0 member's `previous_hash` is not null.
    * `previous_hash_dangling` - a non-genesis member's `previous_hash` is not
      the predecessor's self-reported `audit.hash`.
    * `chain_seq_gap`          - `audit.chain_seq` does not increase by one.
    * `mode_mixed_chain`       - the members do not agree on `audit.mode`.
    * `time_regression`        - a member's `timestamp` precedes its
      predecessor's.

    `hash_mismatch` and `version_unsupported` are lifted from the per-member
    results so the chain priority order can rank them against the rest.
    """
    found: dict[str, Breach] = {}

    member_mismatch = [r.key for r in results if "hash_mismatch" in r.codes]
    if member_mismatch:
        found["hash_mismatch"] = Breach(
            "hash_mismatch", f"member(s) failed Check 1: {member_mismatch}"
        )
    member_unsupported = [r.key for r in results if "version_unsupported" in r.codes]
    if member_unsupported:
        found["version_unsupported"] = Breach(
            "version_unsupported",
            f"member(s) declare a preimage_version other than {PREIMAGE_VERSION!r}: "
            f"{member_unsupported}",
        )

    audits: list[Mapping[str, Any]] = [
        m.get("audit") if isinstance(m.get("audit"), Mapping) else {} for m in members
    ]

    if audits and audits[0].get("chain_seq") == 0 and audits[0].get("previous_hash") is not None:
        found["chain_genesis_mismatch"] = Breach(
            "chain_genesis_mismatch",
            f"genesis member previous_hash is {audits[0].get('previous_hash')!r}, expected null",
        )

    dangling: list[str] = []
    gaps: list[str] = []
    regressions: list[str] = []
    for index in range(1, len(members)):
        previous, current = audits[index - 1], audits[index]
        if current.get("previous_hash") != previous.get("hash"):
            dangling.append(
                f"member {index} previous_hash {current.get('previous_hash')!r} "
                f"does not equal member {index - 1} audit.hash {previous.get('hash')!r}"
            )
        prev_seq, cur_seq = previous.get("chain_seq"), current.get("chain_seq")
        if isinstance(prev_seq, int) and isinstance(cur_seq, int) and cur_seq != prev_seq + 1:
            gaps.append(f"chain_seq goes {prev_seq} -> {cur_seq} between members {index - 1} and {index}")
        prev_ts, cur_ts = members[index - 1].get("timestamp"), members[index].get("timestamp")
        if isinstance(prev_ts, str) and isinstance(cur_ts, str) and cur_ts < prev_ts:
            regressions.append(f"member {index} timestamp {cur_ts} precedes {prev_ts}")

    if dangling:
        found["previous_hash_dangling"] = Breach("previous_hash_dangling", "; ".join(dangling))
    if gaps:
        found["chain_seq_gap"] = Breach("chain_seq_gap", "; ".join(gaps))
    if regressions:
        found["time_regression"] = Breach("time_regression", "; ".join(regressions))

    modes = {a.get("mode") for a in audits if a.get("mode") is not None}
    if len(modes) > 1:
        found["mode_mixed_chain"] = Breach(
            "mode_mixed_chain", f"members mix audit.mode values: {sorted(str(m) for m in modes)}"
        )

    return [found[code] for code in CHAIN_PRIORITY if code in found]


# --------------------------------------------------------------------------
# Vector enumeration
# --------------------------------------------------------------------------


def enumerate_objects(vector: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    """Return ``(oracle key, decision object)`` for every DO in ``vector``.

    Key shapes are fixed by contract section 4: ``<id>`` for a single-DO
    vector, ``<id>-base`` / ``<id>-tampered`` for a tamper pair, and
    ``<id>[i]`` for the i-th chain member.
    """
    vector_id = vector["id"]
    if "decision_object" in vector:
        return [(vector_id, vector["decision_object"])]
    if "chain" in vector:
        return [(f"{vector_id}[{i}]", do) for i, do in enumerate(vector["chain"])]
    if "base_do" in vector and "tampered_do" in vector:
        return [
            (f"{vector_id}-base", vector["base_do"]),
            (f"{vector_id}-tampered", vector["tampered_do"]),
        ]
    raise ValueError(f"{vector_id}: unrecognised vector shape {sorted(vector)}")


def vector_kind(vector: Mapping[str, Any]) -> str:
    if "decision_object" in vector:
        return "single"
    if "chain" in vector:
        return "chain"
    return "pair"


def verify_vector(
    vector: Mapping[str, Any],
    resolvable_entry_ids: Iterable[str] = DEFAULT_RESOLVABLE_ENTRY_IDS,
) -> VectorResult:
    """Verify one vector and compare the outcome against its own `expected`."""
    vector_id = vector["id"]
    kind = vector_kind(vector)
    known = list(resolvable_entry_ids)
    findings: list[str] = []

    expected = vector.get("expected", {})
    expected_type = expected.get("type", "")
    expected_breach = expected.get("breach")
    expected_also = list(expected.get("also_present", []))

    declared_resolvable = expected.get("resolvable_entry_ids")
    if declared_resolvable is not None and sorted(declared_resolvable) != sorted(known):
        findings.append(
            f"vector declares resolvable_entry_ids {sorted(declared_resolvable)} but the "
            f"runner is configured with {sorted(known)}"
        )

    objects = [
        verify_decision_object(key, vector_id, do, known)
        for key, do in enumerate_objects(vector)
    ]

    if kind == "chain":
        holding = detect_chain_breaches([do for _, do in enumerate_objects(vector)], objects)
    else:
        holding = []
        seen: set[str] = set()
        for result in objects:
            for breach in _ordered_single(result):
                if breach.code not in seen:
                    seen.add(breach.code)
                    holding.append(breach)

    reported = holding[0].code if holding else None
    also_present = [b.code for b in holding[1:]]

    # R3: declared also_present items must actually hold, and anything holding
    # that is not declared is a defect. Checked in both directions.
    if sorted(also_present) != sorted(expected_also):
        undeclared = sorted(set(also_present) - set(expected_also))
        unheld = sorted(set(expected_also) - set(also_present))
        if undeclared:
            findings.append(f"breach(es) hold but are not declared in also_present: {undeclared}")
        if unheld:
            findings.append(f"also_present declares breach(es) that do not hold: {unheld}")

    outcome_ok = _outcome_matches(vector_id, expected_type, expected_breach, reported, objects)
    if not outcome_ok:
        findings.append(
            f"expected {expected_type}"
            + (f"/{expected_breach}" if expected_breach else "")
            + f", runner reported {reported or 'MATCH'}"
        )

    for result in objects:
        findings.extend(f"{result.key}: {note}" for note in result.notes if kind != "pair")

    return VectorResult(
        vector_id=vector_id,
        category=vector.get("category", ""),
        kind=kind,
        objects=objects,
        reported=reported,
        also_present=also_present,
        expected_type=expected_type,
        expected_breach=expected_breach,
        expected_also_present=expected_also,
        outcome_ok=outcome_ok,
        findings=findings,
    )


def _ordered_single(result: DecisionObjectResult) -> list[Breach]:
    by_code = {b.code: b for b in result.breaches}
    return [by_code[code] for code in SINGLE_DO_FULL_PRIORITY if code in by_code]


def _outcome_matches(
    vector_id: str,
    expected_type: str,
    expected_breach: str | None,
    reported: str | None,
    objects: Sequence[DecisionObjectResult],
) -> bool:
    if expected_breach == CANARY_EXPECTATION:
        # R5: the canary's acceptance criterion is stated directly in the
        # contract, not as one of the R3 codes.
        return vector_id == CANARY_VECTOR_ID and all(o.check1 == "MISMATCH" for o in objects)
    if expected_type == "MATCH":
        return reported is None
    if expected_type == "BREACH":
        return reported == expected_breach
    return False


# --------------------------------------------------------------------------
# Run report
# --------------------------------------------------------------------------


@dataclass
class RunReport:
    vectors: list[VectorResult]

    # Counts are reported at two distinct granularities on purpose. The
    # per-vector expected-outcome count and the raw per-object Check 1 MATCH
    # count are different measurements of different things, and conflating
    # them is what makes "78/78 MATCH" ambiguous.
    @property
    def vector_total(self) -> int:
        return len(self.vectors)

    @property
    def vector_outcome_ok(self) -> int:
        return sum(1 for v in self.vectors if v.outcome_ok)

    @property
    def objects(self) -> list[DecisionObjectResult]:
        return [o for v in self.vectors for o in v.objects]

    @property
    def object_total(self) -> int:
        return len(self.objects)

    @property
    def object_applicable(self) -> int:
        return sum(1 for o in self.objects if o.applicable)

    @property
    def check1_match(self) -> int:
        return sum(1 for o in self.objects if o.check1 == "MATCH")

    @property
    def check1_mismatch(self) -> int:
        return sum(1 for o in self.objects if o.check1 == "MISMATCH")

    @property
    def check1_not_applicable(self) -> int:
        return sum(1 for o in self.objects if o.check1 == "NOT_APPLICABLE")

    @property
    def findings(self) -> list[str]:
        return [f"{v.vector_id}: {f}" for v in self.vectors for f in v.findings]

    def canonical_hex(self) -> dict[str, str]:
        """The Check 2 submission map: one key per applicable decision object.

        Contract section 4: a decision object whose `audit.preimage_version` is
        not this version's constant MUST NOT appear, because the runner
        terminates at the version gate and never produces bytes for it.
        """
        out: dict[str, str] = {}
        for obj in self.objects:
            if obj.canonical_hex is None:
                continue
            out[obj.key] = obj.canonical_hex
        return out

    def canary(self) -> DecisionObjectResult | None:
        for obj in self.objects:
            if obj.key == CANARY_VECTOR_ID:
                return obj
        return None


def submission_envelope(
    report: "RunReport",
    runner_name: str = SUBMISSION_RUNNER_NAME,
    artifact: str = SUBMISSION_ARTIFACT,
    date: str | None = None,
) -> dict[str, Any]:
    """Build the third-party submission payload.

    Shape and keying are fixed by the upstream submission guide: `<id>` for a
    standalone DO, `<id>-base` / `<id>-tampered` for a tamper pair, `<id>[i]`
    for a chain member, and no key at all for a version-gated DO.
    """
    canary = report.canary()
    return {
        "runner": runner_name,
        "method": SUBMISSION_METHOD,
        "date": date or dt.date.today().isoformat(),
        "artifact": artifact,
        "k01_check1": canary.check1 if canary else "ABSENT",
        "canonical_hex": report.canonical_hex(),
    }


def run(
    vector_document: Mapping[str, Any],
    resolvable_entry_ids: Iterable[str] = DEFAULT_RESOLVABLE_ENTRY_IDS,
) -> RunReport:
    """Verify every vector in ``vector_document``."""
    declared = vector_document.get("preimage_version")
    if declared != PREIMAGE_VERSION:
        raise ValueError(
            f"vector document declares preimage_version {declared!r}, "
            f"this runner implements {PREIMAGE_VERSION!r}"
        )
    known = list(resolvable_entry_ids)
    return RunReport([verify_vector(v, known) for v in vector_document["vectors"]])


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _summary_lines(report: RunReport) -> list[str]:
    canary = report.canary()
    return [
        "ERDL Decision Object v1.5 - independent Python runner",
        "",
        f"vectors                     : {report.vector_total}",
        f"vectors matching expected   : {report.vector_outcome_ok}/{report.vector_total}",
        f"decision objects enumerated : {report.object_total}",
        f"  contractually applicable  : {report.object_applicable}",
        f"  excluded by version gate  : {report.check1_not_applicable}",
        f"Check 1 raw MATCH           : {report.check1_match}/{report.object_applicable}",
        f"Check 1 raw MISMATCH        : {report.check1_mismatch}/{report.object_applicable}",
        f"canonical_hex keys emitted  : {len(report.canonical_hex())}",
        f"K01 Check 1                 : {canary.check1 if canary else 'ABSENT'} "
        "(R5 requires MISMATCH)",
        "Check 2                     : NOT RUN - the answers file is out of scope "
        "for this runner (R6); the emitted canonical_hex is its input",
        f"findings                    : {len(report.findings)}",
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("vectors", type=Path, help="path to decision-object-vectors-v1.5.json")
    parser.add_argument(
        "--submission-out",
        type=Path,
        default=None,
        help="write the submission envelope (runner/method/date/k01_check1/canonical_hex)",
    )
    parser.add_argument("--report-out", type=Path, default=None)
    parser.add_argument("--runner-name", default=SUBMISSION_RUNNER_NAME)
    parser.add_argument("--artifact-url", default=SUBMISSION_ARTIFACT)
    parser.add_argument("--date", default=None, help="ISO date recorded in the submission")
    parser.add_argument(
        "--resolvable-entry-ids",
        default=",".join(DEFAULT_RESOLVABLE_ENTRY_IDS),
        help="comma-separated knowledge entry ids the content layer can resolve",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    document = json.loads(args.vectors.read_text(encoding="utf-8"))
    known = [s for s in args.resolvable_entry_ids.split(",") if s]
    report = run(document, known)

    for line in _summary_lines(report):
        print(line)
    if report.findings:
        print("\nfindings:")
        for finding in report.findings:
            print(f"  - {finding}")

    if args.submission_out:
        args.submission_out.parent.mkdir(parents=True, exist_ok=True)
        args.submission_out.write_text(
            json.dumps(
                submission_envelope(
                    report,
                    runner_name=args.runner_name,
                    artifact=args.artifact_url,
                    date=args.date or dt.date.today().isoformat(),
                ),
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    if args.report_out:
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(
            json.dumps(
                {
                    "vector_total": report.vector_total,
                    "vector_outcome_ok": report.vector_outcome_ok,
                    "object_total": report.object_total,
                    "object_applicable": report.object_applicable,
                    "check1_match": report.check1_match,
                    "check1_mismatch": report.check1_mismatch,
                    "check1_not_applicable": report.check1_not_applicable,
                    "canonical_hex_keys": len(report.canonical_hex()),
                    "findings": report.findings,
                    "vectors": [
                        {
                            "id": v.vector_id,
                            "kind": v.kind,
                            "expected_type": v.expected_type,
                            "expected_breach": v.expected_breach,
                            "reported": v.reported,
                            "also_present": v.also_present,
                            "outcome_ok": v.outcome_ok,
                            "objects": [
                                {"key": o.key, "check1": o.check1, "breaches": o.codes}
                                for o in v.objects
                            ],
                        }
                        for v in report.vectors
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    ok = report.vector_outcome_ok == report.vector_total and not report.findings
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
