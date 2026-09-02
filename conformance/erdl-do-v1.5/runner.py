#!/usr/bin/env python3
"""Independent Python runner for the ERDL Decision Object v1.5 hash layer.

This is an independent submission candidate, not a conforming runner. Only
upstream can run Check 2 (R4) against the answers file, and only upstream can
register an implementation, so nothing here declares conformance. What this
file does claim is stated at the granularity it was measured, and the parts of
the contract it does not implement are named rather than left to inference.

Implemented from the contract text alone. The only ERDL material consulted
while writing this file was `RUNNER_CONTRACT.en.md` and
`decision-object-vectors-v1.5.json`; the reference verifier, the answers file,
the verifier guide, the generated conformance report, and every other
implementation were not read. See the README in this directory for the
recorded independence boundary.

What the contract states directly, and what this file therefore implements
without inference:

  R1  audit.hash = "sha256:" + hex(sha256(utf8(JCS(DO - audit.hash))))
      Deletion, never blanking; every other field participates.
  R2  The preimage excludes `audit.hash`, `signature` and `signing_key_id`.
      Intra-field hashes (`policies[].hash`, `compliance_profile.profile_hash`)
      exclude the field being computed; `policies[].hash` also excludes
      `gloss`.
  R3  PARTIAL. The single-decision-object P1-P6 ladder and the chain priority
      order are implemented and exposed, and each vector's
      `expected.also_present` is checked in both directions. The third group
      R3 names, time anchoring (`clock_drift_detected` /
      `timestamp_anchor_missing`), is NOT implemented: the contract binds it
      to the signature layer, defines no detection rule for it inside the
      permitted input set, and the v1.5 corpus is a hash-mode corpus that
      cannot exercise it. Guessing a rule would be worse than declaring the
      gap, so it is declared. See `UNIMPLEMENTED_R3_CODES`.
  R4  Check 1 (recomputed hash vs the artifact's self-reported `audit.hash`)
      is performed here. Check 2 (recomputed canonical bytes vs the
      independent answers file) is performed by whoever holds the oracle;
      this runner emits the `canonical_hex` map that Check 2 consumes and
      makes no claim about its outcome. The contract is explicit that passing
      only one of the two gates does not constitute conformance.
  R5  `V-DO-v15-K01` must come out Check 1 = MISMATCH. That half is checked
      here; the Check 2 = MATCH half is upstream's to run.
  R6  JCS is implemented in-repo (`concordia.canonicalization`, an
      independently authored RFC 8785 canonicalizer written for Concordia's
      own signing surface). No ERDL SDK and no third-party JCS package is
      used, and the answers file is never opened.

Detection rules the contract names but defines elsewhere (in
`docs/VERIFIER-GUIDE.md` and RFC-002, neither of which was read) were
derived from the vector corpus and are documented, rule by rule, in the
README. Each derived rule was checked to fire on exactly the vectors that
declare it and on no others.

The CLI reads only the pinned upstream vector file: a corpus whose SHA-256 is
not `PINNED_VECTORS_SHA256` is refused before any measurement is taken, so a
substituted same-version file cannot silently produce a published number.
There is no opt-out flag.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import math
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
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

#: SHA-256 of the exact upstream `decision-object-vectors-v1.5.json` every
#: published number in this directory was measured against. The CLI refuses any
#: other corpus. A same-version substituted file is the failure mode this
#: guards: it would still declare `preimage_version: erdl-do-v1.5-hash-flat`,
#: still parse, and still produce plausible counts, so version agreement is not
#: sufficient evidence that a published number describes the pinned input.
PINNED_VECTORS_SHA256 = "d8adf32b7c691bdb3d805fdb0b3f7ac327dc16388cd59a4dfe757d9555e1778c"

#: Exact byte length of the pinned corpus above. The digest is the authority;
#: the size is an allocation guard checked before the file is read. Because a
#: byte-for-byte digest pin already rejects any re-encoding, accepting another
#: size would add denial-of-service surface without accepting another valid
#: corpus.
PINNED_VECTORS_BYTES = 490_038
READ_CHUNK_BYTES = 64 * 1024

#: RUNNER_CONTRACT R3 names three groups of code. This runner implements the
#: single-decision-object ladder and the chain order; it does NOT implement the
#: time-anchoring group, which R3 introduces as "(with the signature layer)".
#: The contract states no detection rule for either code, the rule it defers to
#: (`docs/VERIFIER-GUIDE.md` section 4.1) is outside the permitted input set,
#: and the v1.5 corpus is hash-mode, so nothing in the permitted inputs could
#: even falsify a guess. Named here so that "R3 implemented" is never read as
#: covering them.
UNIMPLEMENTED_R3_CODES: tuple[str, ...] = (
    "clock_drift_detected",
    "timestamp_anchor_missing",
)

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

#: The permitted contract text defines the P1-P6 order for one decision object,
#: but does not define how a tamper pair's two independently ranked outcomes are
#: aggregated. This runner applies the same global ladder once across both sides
#: so a base-side warning cannot mask a tampered-side breach. It is a disclosed
#: runner policy, not a claim that the contract specifies pair aggregation.
PAIR_FULL_PRIORITY: tuple[str, ...] = SINGLE_DO_FULL_PRIORITY

#: Ranking for a chain vector once the members' own P1-P6 findings are merged
#: into the chain-level ones. The contract states two orders and this is their
#: concatenation, which preserves both: every chain code outranks every
#: semantic code, the chain codes keep their stated order, the P1-P6 ladder
#: keeps its stated order, and `content_unresolvable` stays last overall so a
#: warning still cannot mask a breach.
CHAIN_FULL_PRIORITY: tuple[str, ...] = CHAIN_PRIORITY + SINGLE_DO_PRIORITY

#: Chain-level codes that `detect_chain_breaches` already lifts from the
#: members with chain-scoped detail. Merging the per-member copy would only
#: duplicate them.
CHAIN_LIFTED_CODES = frozenset({"hash_mismatch", "version_unsupported"})

#: The one intra-field-hash divergence in the pinned corpus that is the vector's
#: own content rather than a defect: `V-COMP-F02` is the swapped-profile tamper,
#: so its tampered side carries a `compliance_profile` that no longer matches
#: its stale `profile_hash`. Keyed to the exact oracle key and the exact field,
#: with the reason recorded, so that every other intra-field divergence
#: anywhere in the corpus still becomes a finding. This is an exception, not a
#: class: it is counted and printed, never dropped silently.
KNOWN_INTRA_FIELD_EXCEPTIONS: dict[tuple[str, str], str] = {
    ("V-COMP-F02-tampered", "compliance_profile.profile_hash"): (
        "V-COMP-F02 is the swapped-profile tamper; the stale profile_hash is "
        "the tamper this vector encodes, not a runner defect"
    ),
}

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
    "no ERDL SDK, no third-party canonicalizer, answers file never opened; "
    "hash/field/chain layer only, time-anchoring codes not implemented; "
    f"measured against decision-object-vectors-v1.5.json sha256:{PINNED_VECTORS_SHA256}"
)
SUBMISSION_ARTIFACT = (
    "https://github.com/eriknewton/concordia-protocol/tree/main/"
    "conformance/erdl-do-v1.5"
)


class DomainError(ValueError):
    """A value cannot be canonicalized reproducibly under JCS."""


class PinnedInputError(ValueError):
    """The supplied vector file is not the pinned upstream corpus."""


def load_pinned_vectors(path: Path) -> dict[str, Any]:
    """Read the vector document, refusing anything but the pinned corpus.

    Fail-closed by construction and with no override: every number this
    directory publishes is a statement about one specific file, and a
    substituted file that still declares `erdl-do-v1.5-hash-flat` would parse
    and produce counts that look exactly as legitimate. Binding the read to the
    digest is what makes "measured against the upstream corpus" checkable
    rather than asserted.
    """
    try:
        path_size = path.stat().st_size
    except OSError as exc:
        raise PinnedInputError(f"{path}: cannot stat vector file: {exc}") from exc
    if path_size != PINNED_VECTORS_BYTES:
        raise PinnedInputError(
            f"{path}: byte length {path_size} is not the pinned upstream corpus length "
            f"{PINNED_VECTORS_BYTES}; refusing before allocation"
        )

    digest_state = hashlib.sha256()
    raw = bytearray()
    try:
        with path.open("rb") as source:
            opened_size = os.fstat(source.fileno()).st_size
            if opened_size != PINNED_VECTORS_BYTES:
                raise PinnedInputError(
                    f"{path}: opened byte length {opened_size} is not the pinned "
                    f"upstream corpus length {PINNED_VECTORS_BYTES}"
                )
            while chunk := source.read(READ_CHUNK_BYTES):
                if len(raw) + len(chunk) > PINNED_VECTORS_BYTES:
                    raise PinnedInputError(
                        f"{path}: vector file grew beyond the pinned corpus length "
                        f"{PINNED_VECTORS_BYTES} while reading"
                    )
                digest_state.update(chunk)
                raw.extend(chunk)
    except OSError as exc:
        raise PinnedInputError(f"{path}: cannot read vector file: {exc}") from exc

    if len(raw) != PINNED_VECTORS_BYTES:
        raise PinnedInputError(
            f"{path}: read {len(raw)} bytes, expected {PINNED_VECTORS_BYTES}; "
            "the vector file changed while reading"
        )
    digest = digest_state.hexdigest()
    if digest != PINNED_VECTORS_SHA256:
        raise PinnedInputError(
            f"{path}: SHA-256 {digest} is not the pinned upstream corpus "
            f"{PINNED_VECTORS_SHA256}; refusing to measure a substituted vector "
            "file. Re-pin deliberately if upstream reissued the vectors."
        )
    return json.loads(bytes(raw).decode("utf-8"))


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


@dataclass(frozen=True)
class Note:
    """A diagnostic the contract names no breach code for.

    ``subject`` is the thing that diverged, stable enough to key a recorded
    exception against. Notes are findings by default; see
    ``KNOWN_INTRA_FIELD_EXCEPTIONS`` for the single recorded exception.
    """

    subject: str
    detail: str

    def __str__(self) -> str:
        return f"{self.subject}: {self.detail}"


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
    notes: list[Note] = field(default_factory=list)
    profile_hash_check: str = "NOT_CHECKED"
    policy_hash_checks: list[str] = field(default_factory=list)

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
    #: True only when all four compared expected fields reproduce: type,
    #: breach, also_present, and (when declared) resolvable_entry_ids.
    outcome_ok: bool
    findings: list[str] = field(default_factory=list)
    #: Notes matched by a recorded exception rather than raised as findings.
    #: Kept and counted so a suppression is always visible in the run output.
    excused_notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Structural shape guard
# --------------------------------------------------------------------------

#: Containers every decision object in the pinned corpus carries, with the type
#: each detector below assumes. The P1-P6 detectors return None when a
#: container is absent or the wrong type, which is the right behaviour for a
#: detector (it must not invent a breach code the contract does not define) but
#: the wrong behaviour for the runner as a whole: a structurally broken object
#: would then walk the whole semantic ladder in silence. The shape guard is
#: what stops that, and it fails closed as a finding rather than as an invented
#: breach code.
#:
#: Every requirement here is a measured property of all 108 decision objects in
#: the pinned corpus, not a guess about the schema. Optional members
#: (`knowledge_references`, `profile_hash`, `policies[].hash`) are type-checked
#: only when present, because the corpus does not carry them everywhere.
_REQUIRED_MAPPINGS = ("audit", "agent", "compliance_profile", "evaluation", "human_oversight")


def _shape_problems(decision_object: Mapping[str, Any]) -> list[str]:
    """Return one message per structural assumption the object breaks."""
    problems: list[str] = []

    def require(condition: bool, message: str) -> bool:
        if not condition:
            problems.append(message)
        return condition

    if not isinstance(decision_object, Mapping):
        return [f"decision object is {type(decision_object).__name__}, not an object"]

    for name in _REQUIRED_MAPPINGS:
        node = decision_object.get(name)
        require(
            isinstance(node, Mapping),
            f"{name} is {type(node).__name__}, expected an object",
        )

    timestamp = decision_object.get("timestamp")
    require(
        isinstance(timestamp, str),
        f"timestamp is {type(timestamp).__name__}, expected a string; "
        "chain time ordering cannot be applied",
    )

    audit = decision_object.get("audit")
    if isinstance(audit, Mapping):
        require(
            isinstance(audit.get("preimage_version"), str),
            "audit.preimage_version is not a string; the version gate cannot be applied",
        )
        require(isinstance(audit.get("mode"), str), "audit.mode is not a string")
        chain_seq = audit.get("chain_seq")
        require(
            type(chain_seq) is int,
            f"audit.chain_seq is {type(chain_seq).__name__}, expected an integer; "
            "chain ordering cannot be applied",
        )

    agent = decision_object.get("agent")
    if isinstance(agent, Mapping):
        require(isinstance(agent.get("id"), str), "agent.id is not a string")

    profile = decision_object.get("compliance_profile")
    if isinstance(profile, Mapping):
        # `str` is a Sequence, so a bare "XX" would otherwise be read as a
        # jurisdiction list and silently accepted by P1.
        require(
            isinstance(profile.get("jurisdictions"), list),
            f"compliance_profile.jurisdictions is "
            f"{type(profile.get('jurisdictions')).__name__}, expected a list",
        )
        require(
            isinstance(profile.get("activated_fields"), list),
            f"compliance_profile.activated_fields is "
            f"{type(profile.get('activated_fields')).__name__}, expected a list",
        )
        require(
            isinstance(profile.get("risk_level"), str),
            "compliance_profile.risk_level is not a string; P2 and P3 both read it",
        )
        if "profile_hash" in profile:
            require(
                isinstance(profile.get("profile_hash"), str),
                "compliance_profile.profile_hash is present but not a string",
            )

    oversight = decision_object.get("human_oversight")
    if isinstance(oversight, Mapping):
        require(
            isinstance(oversight.get("required"), bool),
            "human_oversight.required is not a boolean",
        )

    policies = decision_object.get("policies")
    if require(
        isinstance(policies, list),
        f"policies is {type(policies).__name__}, expected a list",
    ):
        assert isinstance(policies, list)
        for index, policy in enumerate(policies):
            if not require(
                isinstance(policy, Mapping), f"policies[{index}] is not an object"
            ):
                continue
            for member, kind in (("id", str), ("author_id", str), ("when", Mapping)):
                require(
                    isinstance(policy.get(member), kind),
                    f"policies[{index}].{member} is "
                    f"{type(policy.get(member)).__name__}, expected {kind.__name__}",
                )
            if "hash" in policy:
                require(
                    isinstance(policy.get("hash"), str),
                    f"policies[{index}].hash is present but not a string",
                )

    evaluation = decision_object.get("evaluation")
    if isinstance(evaluation, Mapping):
        matched = evaluation.get("matched_rules")
        if require(
            isinstance(matched, list),
            f"evaluation.matched_rules is {type(matched).__name__}, expected a list",
        ):
            assert isinstance(matched, list)
            for index, entry in enumerate(matched):
                if not require(
                    isinstance(entry, Mapping),
                    f"evaluation.matched_rules[{index}] is not an object",
                ):
                    continue
                require(
                    isinstance(entry.get("rule_id"), str),
                    f"evaluation.matched_rules[{index}].rule_id is not a string",
                )
                require(
                    isinstance(entry.get("canonical_tree"), Mapping),
                    f"evaluation.matched_rules[{index}].canonical_tree is "
                    f"{type(entry.get('canonical_tree')).__name__}, expected an object",
                )
        references = evaluation.get("knowledge_references")
        if references is not None:
            if require(
                isinstance(references, list),
                f"evaluation.knowledge_references is "
                f"{type(references).__name__}, expected a list",
            ):
                assert isinstance(references, list)
                for index, reference in enumerate(references):
                    if not require(
                        isinstance(reference, Mapping),
                        f"evaluation.knowledge_references[{index}] is not an object",
                    ):
                        continue
                    require(
                        isinstance(reference.get("entry_id"), str),
                        f"evaluation.knowledge_references[{index}].entry_id is not a string",
                    )

    return problems


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
    """Run the shape guard, the version gate, Check 1, R2 intra-field and R3."""
    audit = decision_object.get("audit")
    stored = audit.get("hash") if isinstance(audit, Mapping) else None
    shape = [
        Note("shape", problem) for problem in _shape_problems(decision_object)
    ]

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
            notes=shape,
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
        notes=shape,
    )
    if not matched:
        result.breaches.append(
            Breach(
                "hash_mismatch",
                f"recomputed {recomputed} does not equal the self-reported {stored!r}",
            )
        )

    # R2 intra-field hashes. These are diagnostics rather than breach codes
    # because the contract names no code for an intra-field divergence, and
    # inventing one would be a guess. They are NOT harmless: a stale
    # `profile_hash` or `policies[].hash` participates in the flat preimage as
    # an ordinary field, so once the emitter recomputes `audit.hash` afterwards
    # the whole-object hash matches and Check 1 passes with the divergence
    # still inside. The repository's own
    # `test_intra_field_hash_divergence_survives_a_matching_flat_hash` asserts
    # exactly that. So every note is a finding unless it is one of the
    # recorded, key-scoped exceptions in `KNOWN_INTRA_FIELD_EXCEPTIONS`.
    profile = decision_object.get("compliance_profile")
    if isinstance(profile, Mapping) and isinstance(profile.get("profile_hash"), str):
        recomputed_profile = recompute_profile_hash(profile)
        result.profile_hash_check = (
            "MATCH" if recomputed_profile == profile["profile_hash"] else "MISMATCH"
        )
        if recomputed_profile != profile["profile_hash"]:
            result.notes.append(
                Note(
                    "compliance_profile.profile_hash",
                    "does not recompute (stored "
                    f"{profile['profile_hash']}, recomputed {recomputed_profile})",
                )
            )
    policies = decision_object.get("policies")
    if isinstance(policies, list):
        for policy in policies:
            if not isinstance(policy, Mapping) or not isinstance(policy.get("hash"), str):
                continue
            recomputed_policy = recompute_policy_hash(policy)
            result.policy_hash_checks.append(
                "MATCH" if recomputed_policy == policy["hash"] else "MISMATCH"
            )
            if recomputed_policy != policy["hash"]:
                result.notes.append(
                    Note(
                        f"policies[{policy.get('id')!r}].hash",
                        "does not recompute (stored "
                        f"{policy['hash']}, recomputed {recomputed_policy})",
                    )
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

    audits: list[Mapping[str, Any]] = []
    for member in members:
        audit = member.get("audit")
        audits.append(audit if isinstance(audit, Mapping) else {})

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
    resolvable_entry_ids_ok = declared_resolvable is None or sorted(
        declared_resolvable
    ) == sorted(known)
    if not resolvable_entry_ids_ok:
        findings.append(
            f"vector declares resolvable_entry_ids {sorted(declared_resolvable)} but the "
            f"runner is configured with {sorted(known)}"
        )

    objects = [
        verify_decision_object(key, vector_id, do, known)
        for key, do in enumerate_objects(vector)
    ]

    # Breaches are collected across every decision object of the vector into a
    # single dict keyed by code, then ranked ONCE. Ranking inside each object
    # and concatenating (the earlier shape of this code) let a low-priority
    # code on the first object outrank a high-priority code on the second, so a
    # base-side P6 warning could be reported as a pair's primary breach while
    # the tampered side's `hash_mismatch` was demoted to `also_present`. Global
    # ranking is what makes "first hit by priority" a property of the vector
    # rather than of object order.
    holding_map: dict[str, Breach] = {}

    def collect(breach: Breach, source_key: str) -> None:
        if breach.code in holding_map:
            return
        detail = breach.detail if source_key == vector_id else f"{source_key}: {breach.detail}"
        holding_map[breach.code] = Breach(breach.code, detail)

    if kind == "chain":
        for breach in detect_chain_breaches(
            [do for _, do in enumerate_objects(vector)], objects
        ):
            collect(breach, vector_id)
        # A chain member's own P1-P6 findings are part of the vector's R3
        # surface. Computing them and then dropping them is the silent pass R3
        # opens by forbidding, so they are merged here and ranked by
        # CHAIN_FULL_PRIORITY, which keeps both stated orders intact.
        for result in objects:
            for breach in result.breaches:
                if breach.code in CHAIN_LIFTED_CODES:
                    continue
                collect(breach, result.key)
        holding = [holding_map[code] for code in CHAIN_FULL_PRIORITY if code in holding_map]
    elif kind == "pair":
        for result in objects:
            for breach in result.breaches:
                collect(breach, result.key)
        holding = [holding_map[code] for code in PAIR_FULL_PRIORITY if code in holding_map]
    else:
        for breach in objects[0].breaches:
            collect(breach, objects[0].key)
        holding = [holding_map[code] for code in SINGLE_DO_FULL_PRIORITY if code in holding_map]

    reported = holding[0].code if holding else None
    also_present = [b.code for b in holding[1:]]

    # R3: declared also_present items must actually hold, and anything holding
    # that is not declared is a defect. Checked in both directions.
    also_present_ok = sorted(also_present) == sorted(expected_also)
    if not also_present_ok:
        undeclared = sorted(set(also_present) - set(expected_also))
        unheld = sorted(set(expected_also) - set(also_present))
        if undeclared:
            findings.append(f"breach(es) hold but are not declared in also_present: {undeclared}")
        if unheld:
            findings.append(f"also_present declares breach(es) that do not hold: {unheld}")

    primary_outcome_ok = _outcome_matches(
        vector_id, expected_type, expected_breach, reported, objects
    )
    if not primary_outcome_ok:
        findings.append(
            f"expected {expected_type}"
            + (f"/{expected_breach}" if expected_breach else "")
            + f", runner reported {reported or 'MATCH'}"
        )

    outcome_ok = primary_outcome_ok and also_present_ok and resolvable_entry_ids_ok

    # Notes are findings by default, on every vector kind. The single recorded
    # exception is scoped to one oracle key and one field, so an identical
    # divergence anywhere else is still reported.
    excused: list[str] = []
    for result in objects:
        for note in result.notes:
            reason = KNOWN_INTRA_FIELD_EXCEPTIONS.get((result.key, note.subject))
            text = str(note) if result.key == vector_id else f"{result.key}: {note}"
            if reason is None:
                findings.append(text)
            else:
                excused.append(f"{text} [recorded exception: {reason}]")

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
        excused_notes=excused,
    )


def _outcome_matches(
    vector_id: str,
    expected_type: str,
    expected_breach: str | None,
    reported: str | None,
    objects: Sequence[DecisionObjectResult],
) -> bool:
    if expected_breach == CANARY_EXPECTATION:
        # R5: the canary's acceptance criterion is stated directly in the
        # contract, not as one of the R3 codes. It remains the breach named by
        # the vector, so changing expected.type must not leave the vector green.
        return (
            vector_id == CANARY_VECTOR_ID
            and expected_type == "BREACH"
            and all(o.check1 == "MISMATCH" for o in objects)
        )
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
    # per-vector compared-expected-fields count and the raw per-object Check 1
    # MATCH count are different measurements of different things, and
    # conflating them is what makes "78/78 MATCH" ambiguous.
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
    def profile_hash_checked(self) -> int:
        return sum(1 for o in self.objects if o.profile_hash_check in {"MATCH", "MISMATCH"})

    @property
    def profile_hash_match(self) -> int:
        return sum(1 for o in self.objects if o.profile_hash_check == "MATCH")

    @property
    def profile_hash_mismatch(self) -> int:
        return sum(1 for o in self.objects if o.profile_hash_check == "MISMATCH")

    @property
    def policy_hash_checked(self) -> int:
        return sum(len(o.policy_hash_checks) for o in self.objects)

    @property
    def policy_hash_match(self) -> int:
        return sum(check == "MATCH" for o in self.objects for check in o.policy_hash_checks)

    @property
    def policy_hash_mismatch(self) -> int:
        return sum(check == "MISMATCH" for o in self.objects for check in o.policy_hash_checks)

    @property
    def findings(self) -> list[str]:
        return [f"{v.vector_id}: {f}" for v in self.vectors for f in v.findings]

    @property
    def excused_notes(self) -> list[str]:
        """Diagnostics matched by a recorded exception, printed rather than dropped."""
        return [f"{v.vector_id}: {n}" for v in self.vectors for n in v.excused_notes]

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

    def invariant_problems(self) -> list[str]:
        """Return internal accounting failures that make output unsafe to publish."""
        problems: list[str] = []
        canonical = self.canonical_hex()
        if len(canonical) != self.object_applicable:
            problems.append(
                f"canonical_hex count {len(canonical)} != applicable object count "
                f"{self.object_applicable}"
            )
        if self.check1_match + self.check1_mismatch != self.object_applicable:
            problems.append(
                "Check 1 MATCH + MISMATCH does not equal applicable object count"
            )
        if self.object_applicable + self.check1_not_applicable != self.object_total:
            problems.append(
                "applicable + NOT_APPLICABLE does not equal enumerated object count"
            )
        keys = [obj.key for obj in self.objects]
        if len(set(keys)) != len(keys):
            problems.append("decision-object oracle keys are not unique")
        for obj in self.objects:
            if obj.applicable != (obj.check1 in {"MATCH", "MISMATCH"}):
                problems.append(f"{obj.key}: applicability and Check 1 status disagree")
            if obj.applicable != (obj.canonical_hex is not None):
                problems.append(f"{obj.key}: applicability and canonical-byte presence disagree")
        return problems

    def assert_internal_invariants(self) -> None:
        problems = self.invariant_problems()
        if problems:
            raise ValueError("run accounting invariant failed: " + "; ".join(problems))

    @property
    def successful(self) -> bool:
        return (
            not self.invariant_problems()
            and self.vector_outcome_ok == self.vector_total
            and not self.findings
        )

    def submission_readiness_problems(self) -> list[str]:
        problems = self.invariant_problems()
        if self.vector_outcome_ok != self.vector_total:
            problems.append(
                f"only {self.vector_outcome_ok}/{self.vector_total} vector outcomes reproduced"
            )
        if self.findings:
            problems.append(f"run has {len(self.findings)} finding(s)")
        canary = self.canary()
        if canary is None:
            problems.append(f"required canary {CANARY_VECTOR_ID} is absent")
        elif canary.check1 != "MISMATCH":
            problems.append(
                f"required canary {CANARY_VECTOR_ID} Check 1 is {canary.check1}, not MISMATCH"
            )
        return problems


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
    problems = report.submission_readiness_problems()
    if problems:
        raise ValueError("refusing submission envelope for failed run: " + "; ".join(problems))
    canary = report.canary()
    assert canary is not None
    return {
        "runner": runner_name,
        "method": SUBMISSION_METHOD,
        "date": date or dt.date.today().isoformat(),
        "artifact": artifact,
        "k01_check1": canary.check1,
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
    report = RunReport([verify_vector(v, known) for v in vector_document["vectors"]])
    report.assert_internal_invariants()
    return report


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _summary_lines(report: RunReport) -> list[str]:
    canary = report.canary()
    return [
        "ERDL Decision Object v1.5 - independent Python runner",
        "",
        f"vectors                     : {report.vector_total}",
        f"vectors reproducing compared expected fields: "
        f"{report.vector_outcome_ok}/{report.vector_total}",
        f"decision objects enumerated : {report.object_total}",
        f"  contractually applicable  : {report.object_applicable}",
        f"  excluded by version gate  : {report.check1_not_applicable}",
        f"Check 1 raw MATCH           : {report.check1_match}/{report.object_applicable}",
        f"Check 1 raw MISMATCH        : {report.check1_mismatch}/{report.object_applicable}",
        f"canonical_hex keys emitted  : {len(report.canonical_hex())}",
        f"profile hashes checked      : {report.profile_hash_checked} "
        f"({report.profile_hash_match} MATCH, {report.profile_hash_mismatch} MISMATCH)",
        f"policy hashes checked       : {report.policy_hash_checked} "
        f"({report.policy_hash_match} MATCH, {report.policy_hash_mismatch} MISMATCH)",
        f"K01 Check 1                 : {canary.check1 if canary else 'ABSENT'} "
        "(R5 requires MISMATCH)",
        "Check 2                     : NOT RUN - the answers file is out of scope "
        "for this runner (R6); the emitted canonical_hex is its input",
        f"findings                    : {len(report.findings)}",
        f"excused diagnostics         : {len(report.excused_notes)} "
        "(recorded exceptions, listed below)",
        "R3 not implemented          : " + ", ".join(UNIMPLEMENTED_R3_CODES)
        + " (time anchoring, signature layer)",
        "status                      : independent submission candidate; "
        "Check 2 / oracle agreement and registration pending upstream verification",
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

    # Fail closed on a substituted corpus before anything is measured or
    # written. No override flag exists: an escape hatch here would make every
    # published number conditional on a promise that it was not used.
    try:
        document = load_pinned_vectors(args.vectors)
    except PinnedInputError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2
    known = [s for s in args.resolvable_entry_ids.split(",") if s]
    report = run(document, known)
    ok = report.successful

    for line in _summary_lines(report):
        print(line)
    if report.excused_notes:
        print("\nexcused diagnostics:")
        for note in report.excused_notes:
            print(f"  - {note}")
    if report.findings:
        print("\nfindings:")
        for finding in report.findings:
            print(f"  - {finding}")

    submission_payload: dict[str, Any] | None = None
    if args.submission_out:
        try:
            submission_payload = submission_envelope(
                report,
                runner_name=args.runner_name,
                artifact=args.artifact_url,
                date=args.date or dt.date.today().isoformat(),
            )
        except ValueError as exc:
            print(f"[FAIL] submission envelope not written: {exc}", file=sys.stderr)
            ok = False

    if args.submission_out and submission_payload is not None:
        args.submission_out.parent.mkdir(parents=True, exist_ok=True)
        args.submission_out.write_text(
            json.dumps(submission_payload, indent=2) + "\n",
            encoding="utf-8",
        )
    if args.report_out:
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(
            json.dumps(
                {
                    "vectors_sha256": PINNED_VECTORS_SHA256,
                    "r3_codes_not_implemented": list(UNIMPLEMENTED_R3_CODES),
                    "check2": "NOT_RUN",
                    "vector_total": report.vector_total,
                    "vector_outcome_ok": report.vector_outcome_ok,
                    "object_total": report.object_total,
                    "object_applicable": report.object_applicable,
                    "check1_match": report.check1_match,
                    "check1_mismatch": report.check1_mismatch,
                    "check1_not_applicable": report.check1_not_applicable,
                    "canonical_hex_keys": len(report.canonical_hex()),
                    "profile_hash_checked": report.profile_hash_checked,
                    "profile_hash_match": report.profile_hash_match,
                    "profile_hash_mismatch": report.profile_hash_mismatch,
                    "policy_hash_checked": report.policy_hash_checked,
                    "policy_hash_match": report.policy_hash_match,
                    "policy_hash_mismatch": report.policy_hash_mismatch,
                    "run_successful": ok,
                    "run_invariant_problems": report.invariant_problems(),
                    "findings": report.findings,
                    "excused_notes": report.excused_notes,
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

    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
