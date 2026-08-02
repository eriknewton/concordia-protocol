#!/usr/bin/env python3
"""Generate Concordia conformance vectors deterministically."""

from __future__ import annotations

import argparse
import base64
import copy
import difflib
import hashlib
import json
import re
import shutil
import sys
import tempfile
import warnings
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, TypeAlias

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from jsonschema import Draft202012Validator, FormatChecker, RefResolver

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from concordia.agent_profile import (  # noqa: E402
    AgentCapabilityProfile,
    Capabilities,
    Endpoints,
    Location,
    NegotiationProfile,
    ReputationAssertion,
    Sovereignty,
    TrustSignals,
)
from concordia.attestation import (  # noqa: E402
    countersign_attestation,
    verify_attestation,
    verify_attestation_countersignature,
)
from concordia.canonicalization import (
    canonicalize_jcs,  # noqa: E402
    canonicalize_mandate,  # noqa: E402
)
from concordia.cmpc.canonical import (  # noqa: E402
    canonicalize_atomic_activation_proof,
    canonicalize_cascade_decision_record,
    canonicalize_chain_session,
    canonicalize_closure_predicate,
    canonicalize_conditional_commitment,
    canonicalize_unwind_record,
)
from concordia.cmpc.schemas import (  # noqa: E402
    ATOMIC_ACTIVATION_PROOF_SCHEMA,
    CASCADE_DECISION_RECORD_SCHEMA,
    CHAIN_SESSION_SCHEMA,
    CLOSURE_PREDICATE_SCHEMA,
    CONDITIONAL_COMMITMENT_SCHEMA,
    REVOCATION_RECORD_SCHEMA,
    UNWIND_RECORD_SCHEMA,
    validate_cascade_decision_record,
    validate_chain_session,
    validate_closure_predicate,
)
from concordia.cmpc.signing import (  # noqa: E402
    sign_atomic_activation_proof,
    sign_conditional_commitment,
    sign_unwind_record,
    verify_atomic_activation_proof,
    verify_conditional_commitment,
    verify_unwind_record,
)
from concordia.cmpc.types import (  # noqa: E402
    AtomicActivationProof,
    ClosurePredicate,
    ConditionalCommitment,
    UnwindRecord,
)
from concordia.competence_proof import (  # noqa: E402
    build_merkle_tree,
    generate_merkle_proof,
    verify_merkle_proof,
)
from concordia.cosign import (  # noqa: E402
    build_cosigned_receipt,
    canonical_cosign_bytes,
    did_key_for,
    ed25519_did_key,
    keypair_signer,
    public_key_bytes_from_did_key,
)
from concordia.mandate import (  # noqa: E402
    sign_delegation,
    sign_mandate,
    verify_delegation_chain,
    verify_mandate,
)
from concordia.message import GENESIS_HASH, compute_hash  # noqa: E402
from concordia.models.mandate import (  # noqa: E402
    MANDATE_JSON_SCHEMA,
    DelegationLink,
    Mandate,
    TemporalMode,
    ValidityWindow,
)
from concordia.predicate import sign_predicate, verify_predicate  # noqa: E402
from concordia.receipt_bundle import _compute_summary  # noqa: E402
from concordia.schema_validator import (  # noqa: E402
    _RAW_TERM_PATTERNS,
    validate_approval_receipt,
)
from concordia.signing import KeyPair, canonical_json, sign_message  # noqa: E402

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+\Z")
SHA256_HEX_RE = re.compile(r"^sha256:[a-f0-9]{64}\Z")

ReasonClass: TypeAlias = Literal[
    "schema",
    "signature",
    "digest",
    "binding",
    "temporal",
    "privacy",
    "transition",
]
ExpectedOutcome: TypeAlias = Literal["accept", "reject"]
MutationKind: TypeAlias = Literal["value", "drop", "inject"]
MutationKey: TypeAlias = tuple[str, MutationKind]

VECTOR_SCHEMA_VERSION = "concordia-conformance-vector/v1-draft"
SUITE_VERSION = "v1-draft"
GENERATOR_COMMAND = "python3 scripts/conformance/generate_vectors.py"
CHECK_COMMAND = "python3 scripts/conformance/generate_vectors.py --check"
GENERATED_CHECK_EXCLUDED_DIRS = {"reference-runner", "reference-runner-js"}
GENERATED_CHECK_EXCLUDED_FILES = {"IMPLEMENTATIONS.md", "RUNNER_CONTRACT.md"}

INTEROP_1404 = REPO_ROOT / "docs" / "interop" / "a2a-1404-receipt-revocation-vector"
INTEROP_1920 = REPO_ROOT / "docs" / "interop" / "a2a-1920-fulfillment-sample"
CMPC_PRIMITIVES = REPO_ROOT / "tests" / "fixtures" / "cmpc_bilateral" / "primitives"
CMPC_STATE_MACHINE = (
    REPO_ROOT / "tests" / "fixtures" / "cmpc_bilateral" / "state_machine"
)
FIXED_NOW = datetime(2026, 5, 10, 14, 25, 0, tzinfo=timezone.utc)

SCHEMA_COPIES = {
    "approval_receipt.schema.json": REPO_ROOT / "schemas" / "approval_receipt.schema.json",
    "attestation.schema.json": REPO_ROOT / "schemas" / "attestation.schema.json",
    "revocation_record.schema.json": REPO_ROOT / "schemas" / "revocation_record.schema.json",
    "fulfillment_attestation.schema.json": REPO_ROOT
    / "schemas"
    / "fulfillment_attestation.schema.json",
    "receipt_bundle.schema.json": REPO_ROOT / "schemas" / "receipt_bundle.schema.json",
    "predicate.json": REPO_ROOT / "schemas" / "predicate.json",
    "reference.schema.json": REPO_ROOT / "schemas" / "reference.schema.json",
}

FIXTURE_DIRS = (INTEROP_1404, INTEROP_1920)
PROFILES = (
    "decision-object-v1",
    "offer-binding-v1",
    "receipt-v1",
    "revocation-v1",
    "cascade-decision-v1",
    "fulfillment-attestation-v1",
    "attestation-v1",
    "attestation-countersign-v1",
    "predicate-v1",
    "mandate-v1",
    "delegation-chain-v1",
    "cosign-v1",
    "conditional-commitment-v1",
    "atomic-activation-proof-v1",
    "unwind-record-v1",
    "closure-predicate-v1",
    "chain-session-v1",
    "chain-session-transition-v1",
    "agent-profile-v1",
    "competence-proof-v1",
    "receipt-bundle-v1",
    "message-chain-v1",
)
RECORD_TYPES = (
    "decision_object",
    "approval_receipt",
    "revocation_record",
    "cascade_decision_record",
    "fulfillment_attestation",
    "attestation",
    "predicate",
    "mandate",
    "cosign_receipt",
    "conditional_commitment",
    "atomic_activation_proof",
    "unwind_record",
    "closure_predicate",
    "chain_session",
    "chain_session_transition",
    "agent_profile",
    "competence_proof",
    "receipt_bundle",
    "message_chain",
)

SYNTHETIC_FIXTURE_ROOT = "synthetic"
SYNTHETIC_SOURCE_ATTESTATION = "synthetic/attestation"
SYNTHETIC_SOURCE_PREDICATE = "synthetic/predicate"
SYNTHETIC_SOURCE_MANDATE = "synthetic/mandate"
SYNTHETIC_SOURCE_COSIGN = "synthetic/cosign"
SYNTHETIC_SOURCE_CMPC = "synthetic/cmpc_bilateral"
SYNTHETIC_SOURCE_LONGTAIL = "synthetic/longtail"
SYNTHETIC_SEEDS = {
    "attestation_initiator": "conformance_attest_initiator_001",
    "attestation_responder": "conformance_attest_responder_001",
    "agent_profile_signer": "conformance_agent_profile_000001",
    "predicate_issuer": "conformance_pred_issuer_00000001",
    "mandate_issuer": "conformance_mand_issuer_00000001",
    "mandate_delegate": "conformance_mand_delegate_000001",
    "cosign_publisher": "conformance_cosign_publisher_001",
    "cosign_counterparty": "conformance_cosign_counter_00001",
    "cmpc_retailer": "conformance_cmpc_retailer_000001",
    "cmpc_wholesaler": "conformance_cmpc_wholesaler_0000",
    "cmpc_authority": "conformance_cmpc_authority_00000",
    "message_chain_initiator": "conformance_msg_initiator_000001",
    "message_chain_responder": "conformance_msg_responder_000001",
}

P2_A2_PREDICATE_MUTATION_FIXTURE = "vector_02"
P2_A2_PREDICATE_MUTATION_REASON = (
    "richest predicate fixture: nested condition, constraints, delegation_chain, "
    "metadata, revocation_endpoint, references, and windowed validity"
)
FORMAT_CHECKER = FormatChecker(formats=())


@FORMAT_CHECKER.checks("date-time", raises=ValueError)
def is_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return True
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.tzinfo is not None


class GenerationError(RuntimeError):
    """Vector generation failed."""


@dataclass(frozen=True)
class Vector:
    vector_id: str
    title: str
    source_fixture: str
    record_type: str
    verification_profile: str
    input_data: dict[str, Any]
    context: dict[str, Any]
    expected: str = "accept"
    expected_reason_class: str | None = None
    notes: str = ""
    canonical_preimage: bytes | None = None
    discriminates: str | None = None

    def to_json(self) -> dict[str, Any]:
        data = {
            "schema_version": VECTOR_SCHEMA_VERSION,
            "id": self.vector_id,
            "title": self.title,
            "source_fixture": self.source_fixture,
            "record_type": self.record_type,
            "verification_profile": self.verification_profile,
            "input": self.input_data,
            "context": self.context,
            "expected": self.expected,
            "expected_reason_class": self.expected_reason_class,
            "notes": self.notes,
        }
        if self.discriminates is not None:
            data["discriminates"] = self.discriminates
        return data


@dataclass(frozen=True)
class Evaluation:
    accepted: bool
    reason_class: ReasonClass | None = None


@dataclass(frozen=True)
class MutationFixture:
    battery_name: str
    fixture_label: str
    object_label: str
    object_name: str
    input_data: dict[str, Any]
    source_fixture: str
    record_type: str
    verification_profile: str
    context: dict[str, Any]
    sdk_rejected: int
    sdk_total: int
    sdk_escapes: frozenset[MutationKey]
    compare_typed_path: bool = True


@dataclass(frozen=True)
class MutationDivergence:
    battery_name: str
    field_path: str
    kind: MutationKind
    sdk_expected: ExpectedOutcome
    raw_expected: ExpectedOutcome


@dataclass(frozen=True)
class SyntheticCmpcFixtures:
    conditional_commitment: dict[str, Any]
    atomic_activation_proof: dict[str, Any]
    unwind_record: dict[str, Any]
    closure_predicate: dict[str, Any]
    chain_session: dict[str, Any]
    transition_vectors: dict[str, dict[str, Any]]
    seed_manifest: dict[str, Any]


@dataclass(frozen=True)
class SyntheticLongtailFixtures:
    agent_profile: dict[str, Any]
    receipt_bundle: dict[str, Any]
    competence_proof: dict[str, Any]
    message_chain: dict[str, Any]
    message_chain_position: dict[str, Any]
    receipt_set_binding: dict[str, Any]
    attestations: list[dict[str, Any]]
    seed_manifest: dict[str, Any]


@dataclass(frozen=True)
class SyntheticFixtures:
    attestation: dict[str, Any]
    attestation_seed_manifest: dict[str, Any]
    predicates: dict[str, dict[str, Any]]
    predicate_seed_manifest: dict[str, Any]
    direct_mandate: dict[str, Any]
    delegated_mandate: dict[str, Any]
    mandate_seed_manifest: dict[str, Any]
    cosigned_receipt: dict[str, Any]
    cosign_seed_manifest: dict[str, Any]
    cmpc: SyntheticCmpcFixtures
    longtail: SyntheticLongtailFixtures


def load_json(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode()


def private_key_from_seed(seed_ascii: str) -> Ed25519PrivateKey:
    seed = seed_ascii.encode("utf-8")
    if len(seed) != 32:
        raise GenerationError(f"Ed25519 seed is not 32 bytes: {seed_ascii!r}")
    return Ed25519PrivateKey.from_private_bytes(seed)


def key_pair_from_seed(seed_ascii: str) -> KeyPair:
    private_key = private_key_from_seed(seed_ascii)
    return KeyPair(private_key=private_key, public_key=private_key.public_key())


def sign_b64url(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    return b64url_encode(private_key.sign(payload))


def sha256_jcs(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonicalize_jcs(value)).hexdigest()


def without_signature(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "signature"}


def without_keys(value: Mapping[str, Any], keys: set[str]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in keys}


def strip_signatures_recursive(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: strip_signatures_recursive(item)
            for key, item in value.items()
            if key != "signature"
        }
    if isinstance(value, list):
        return [strip_signatures_recursive(item) for item in value]
    return value


def attestation_countersign_payload(attestation: dict[str, Any]) -> bytes:
    return canonical_json(
        strip_signatures_recursive(without_keys(attestation, {"countersignatures"}))
    )


def public_key_map(keys: Mapping[str, KeyPair]) -> dict[str, str]:
    return {
        agent_id: key_pair.public_key_b64()
        for agent_id, key_pair in sorted(keys.items())
    }


def parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def resolve_object(name: str, input_data: dict[str, Any], context: dict[str, Any]) -> Any:
    if name == "input":
        return input_data
    if not name.startswith("context."):
        raise GenerationError(f"unsupported object reference: {name}")
    current: Any = context
    for part in name.removeprefix("context.").split("."):
        if not isinstance(current, dict) or part not in current:
            raise GenerationError(f"missing context object: {name}")
        current = current[part]
    return current


def resolve_pointer(root: Any, pointer: str) -> Any:
    if pointer == "":
        return root
    if not pointer.startswith("/"):
        raise GenerationError(f"invalid JSON pointer: {pointer}")
    current = root
    for raw_part in pointer.split("/")[1:]:
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(part)]
        elif isinstance(current, dict):
            current = current[part]
        else:
            raise GenerationError(f"pointer crosses non-container: {pointer}")
    return current


def resolve_side(
    side: dict[str, str], input_data: dict[str, Any], context: dict[str, Any]
) -> Any:
    root = resolve_object(side["object"], input_data, context)
    return resolve_pointer(root, side["pointer"])


def walk_strings(value: Any) -> list[str]:
    strings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and key != "signature":
                strings.append(key)
            if key != "signature":
                strings.extend(walk_strings(child))
    elif isinstance(value, list):
        for child in value:
            strings.extend(walk_strings(child))
    elif isinstance(value, str):
        strings.append(value)
    return strings


def contains_raw_term(value: Any) -> bool:
    for item in walk_strings(value):
        for pattern in _RAW_TERM_PATTERNS:
            if pattern.search(item):
                return True
    return False


def mutate_scalar(value: Any) -> Any:
    """Return a minimally different scalar for one-field mutation vectors."""
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


def ref(root: Any, path: list[str | int]) -> Any:
    current = root
    for step in path:
        current = current[step]
    return current


def mutations(obj: dict[str, Any]) -> Iterator[tuple[str, MutationKind, dict[str, Any]]]:
    """Yield one fresh mutated copy per scalar value, key drop, and key injection."""

    def walk(node: Any, path: list[str | int]) -> Iterator[tuple[str, MutationKind, dict[str, Any]]]:
        if isinstance(node, dict):
            for key in list(node.keys()):
                child_path = path + [key]
                child = node[key]
                if isinstance(child, (dict, list)):
                    yield from walk(child, child_path)
                else:
                    mutated = copy.deepcopy(obj)
                    ref(mutated, path)[key] = mutate_scalar(child)
                    yield (".".join(map(str, child_path)), "value", mutated)

                mutated = copy.deepcopy(obj)
                del ref(mutated, path)[key]
                yield (".".join(map(str, child_path)), "drop", mutated)

            mutated = copy.deepcopy(obj)
            ref(mutated, path)["__mut_probe__"] = "MUT"
            yield (".".join(map(str, path)) or "<root>", "inject", mutated)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                child_path = path + [index]
                if isinstance(child, (dict, list)):
                    yield from walk(child, child_path)
                else:
                    mutated = copy.deepcopy(obj)
                    ref(mutated, path)[index] = mutate_scalar(child)
                    yield (".".join(map(str, child_path)), "value", mutated)

    yield from walk(obj, [])


def schema_store() -> dict[str, dict[str, Any]]:
    schemas: dict[str, dict[str, Any]] = {}
    for source in SCHEMA_COPIES.values():
        loaded = load_json(source)
        schema_id = loaded.get("$id")
        if isinstance(schema_id, str):
            schemas[schema_id] = loaded
    mandate_id = MANDATE_JSON_SCHEMA.get("$id")
    if isinstance(mandate_id, str):
        schemas[mandate_id] = MANDATE_JSON_SCHEMA
    return schemas


def schema_is_valid(schema: dict[str, Any], data: Any) -> bool:
    resolver = RefResolver.from_schema(schema, store=schema_store())
    return not any(
        Draft202012Validator(
            schema,
            resolver=resolver,
            format_checker=FORMAT_CHECKER,
        ).iter_errors(data)
    )


def has_approves_reference(receipt: dict[str, Any]) -> bool:
    references = receipt.get("references")
    if not isinstance(references, list):
        return False
    for reference in references:
        if not isinstance(reference, dict):
            continue
        if reference.get("relationship") == "approves" and reference.get("type") in {
            "negotiation_session",
            "a2cn:negotiation_session",
        }:
            return True
    return False


def has_revokes_reference(record: dict[str, Any]) -> bool:
    revoked_artifact_id = record.get("revoked_artifact_id")
    references = record.get("references")
    if not isinstance(revoked_artifact_id, str) or not isinstance(references, list):
        return False
    for reference in references:
        if not isinstance(reference, dict):
            continue
        if (
            reference.get("relationship") == "revokes"
            and reference.get("id") == revoked_artifact_id
        ):
            return True
    return False


def has_fulfills_reference(attestation: dict[str, Any]) -> bool:
    agreement_id = attestation.get("agreement_attestation_id")
    references = attestation.get("references")
    if not isinstance(agreement_id, str) or not isinstance(references, list):
        return False
    for reference in references:
        if not isinstance(reference, dict):
            continue
        if (
            reference.get("relationship") == "fulfills"
            and reference.get("id") == agreement_id
        ):
            return True
    return False


def verify_ed25519_signature(
    public_key_b64url: str,
    signature_b64url: str,
    payload: bytes,
) -> bool:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64url_decode(public_key_b64url))
        public_key.verify(b64url_decode(signature_b64url), payload)
        return True
    except Exception:
        return False


def evaluate_attestation_profile(vector: Vector) -> Evaluation:
    input_data = vector.input_data
    context = vector.context
    if context.get("forbid_raw_deal_terms") and contains_raw_term(input_data):
        return Evaluation(False, "privacy")
    schema = load_json(SCHEMA_COPIES["attestation.schema.json"])
    if not schema_is_valid(schema, input_data):
        return Evaluation(False, "schema")
    public_keys_b64 = context.get("public_keys_b64url")
    if not isinstance(public_keys_b64, dict):
        return Evaluation(False, "signature")
    try:
        public_keys = {
            str(agent_id): Ed25519PublicKey.from_public_bytes(
                b64url_decode(str(public_key_b64))
            )
            for agent_id, public_key_b64 in public_keys_b64.items()
        }
    except Exception:
        return Evaluation(False, "signature")
    parties = input_data.get("parties")
    if not isinstance(parties, list):
        return Evaluation(False, "schema")
    verified_parties: list[str] = []
    for party in parties:
        if not isinstance(party, dict):
            return Evaluation(False, "schema")
        agent_id = party.get("agent_id")
        signature = party.get("signature")
        if not isinstance(agent_id, str) or not isinstance(signature, str):
            return Evaluation(False, "signature")
        public_key = public_keys.get(agent_id)
        if public_key is None:
            return Evaluation(False, "signature")
        try:
            public_key.verify(
                b64url_decode(signature),
                canonical_json(without_signature(party)),
            )
        except Exception:
            return Evaluation(False, "signature")
        verified_parties.append(agent_id)
    expected_parties = context.get("expected_verified_parties")
    if expected_parties is not None and sorted(verified_parties) != sorted(
        expected_parties
    ):
        return Evaluation(False, "binding")
    return Evaluation(True)


def evaluate_attestation_countersign_profile(vector: Vector) -> Evaluation:
    input_data = vector.input_data
    context = vector.context
    schema = load_json(SCHEMA_COPIES["attestation.schema.json"])
    if not schema_is_valid(schema, input_data):
        return Evaluation(False, "schema")
    public_keys_b64 = context.get("public_keys_b64url")
    countersigners = context.get("countersigners")
    countersignatures = input_data.get("countersignatures")
    if (
        not isinstance(public_keys_b64, dict)
        or not isinstance(countersigners, list)
        or not isinstance(countersignatures, dict)
    ):
        return Evaluation(False, "signature")
    payload = attestation_countersign_payload(input_data)
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None:
        if "sha256:" + hashlib.sha256(payload).hexdigest() != expected_digest:
            return Evaluation(False, "digest")
    for signer in countersigners:
        if not isinstance(signer, str):
            return Evaluation(False, "binding")
        signature = countersignatures.get(signer)
        public_key_b64 = public_keys_b64.get(signer)
        if not isinstance(signature, str) or not isinstance(public_key_b64, str):
            return Evaluation(False, "signature")
        public_key = Ed25519PublicKey.from_public_bytes(b64url_decode(public_key_b64))
        if not verify_attestation_countersignature(input_data, signature, public_key):
            return Evaluation(False, "signature")
    return Evaluation(True)


def evaluate_predicate_profile(vector: Vector) -> Evaluation:
    input_data = vector.input_data
    context = vector.context
    schema = load_json(SCHEMA_COPIES["predicate.json"])
    if not schema_is_valid(schema, input_data):
        return Evaluation(False, "schema")
    if input_data.get("algorithm") != "EdDSA":
        return Evaluation(False, "signature")
    preimage = canonical_json(without_signature(input_data))
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None:
        if "sha256:" + hashlib.sha256(preimage).hexdigest() != expected_digest:
            return Evaluation(False, "digest")
    public_key_b64 = context.get("public_key_b64url")
    signature = input_data.get("signature")
    if not isinstance(public_key_b64, str) or not isinstance(signature, str):
        return Evaluation(False, "signature")
    if not verify_ed25519_signature(public_key_b64, signature, preimage):
        return Evaluation(False, "signature")
    result = verify_predicate(input_data, now=parse_datetime(context["now"]))
    if not result.valid:
        if result.failure_reason in {"expired", "revoked"}:
            return Evaluation(False, "temporal")
        return Evaluation(False, "schema")
    return Evaluation(True)


def evaluate_mandate_profile(vector: Vector, *, require_chain: bool = False) -> Evaluation:
    input_data = vector.input_data
    context = vector.context
    if not schema_is_valid(MANDATE_JSON_SCHEMA, input_data):
        return Evaluation(False, "schema")
    if input_data.get("algorithm") != "EdDSA":
        return Evaluation(False, "signature")
    preimage = canonicalize_mandate(input_data)
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None:
        if "sha256:" + hashlib.sha256(preimage).hexdigest() != expected_digest:
            return Evaluation(False, "digest")
    public_key_b64 = context.get("issuer_public_key_b64url")
    signature = input_data.get("signature")
    if not isinstance(public_key_b64, str) or not isinstance(signature, str):
        return Evaluation(False, "signature")
    if not verify_ed25519_signature(public_key_b64, signature, preimage):
        return Evaluation(False, "signature")
    delegation_public_keys: dict[str, Ed25519PublicKey] = {}
    for agent_id, delegation_public_key_b64 in context.get(
        "delegation_public_keys_b64url", {}
    ).items():
        delegation_public_keys[str(agent_id)] = Ed25519PublicKey.from_public_bytes(
            b64url_decode(str(delegation_public_key_b64))
        )
    if require_chain:
        chain = input_data.get("delegation_chain")
        if not isinstance(chain, list) or not chain:
            return Evaluation(False, "binding")
        links = [DelegationLink.from_dict(item) for item in chain]
        chain_valid, _ = verify_delegation_chain(
            links,
            str(input_data.get("issuer", "")),
            str(input_data.get("subject", "")),
            delegation_public_keys,
        )
        if not chain_valid:
            return Evaluation(False, "binding")
    result = verify_mandate(
        input_data,
        Ed25519PublicKey.from_public_bytes(b64url_decode(public_key_b64)),
        now=parse_datetime(context["now"]),
        action=context.get("action"),
        delegation_public_keys=delegation_public_keys,
        check_revocation_status=False,
    )
    if not result.valid:
        if result.checks.get("temporal_validity") is False:
            return Evaluation(False, "temporal")
        if result.checks.get("issuer_signature") is False:
            return Evaluation(False, "signature")
        if result.checks.get("delegation_chain") is False:
            return Evaluation(False, "binding")
        return Evaluation(False, "schema")
    return Evaluation(True)


def evaluate_cosign_profile(vector: Vector) -> Evaluation:
    input_data = vector.input_data
    context = vector.context
    counterparty_did = context.get("counterparty_did")
    publisher_did = context.get("publisher_did")
    public_key_b64 = context.get("counterparty_public_key_b64url")
    if not all(isinstance(value, str) for value in (counterparty_did, publisher_did, public_key_b64)):
        return Evaluation(False, "binding")
    if counterparty_did == publisher_did:
        return Evaluation(False, "binding")
    public_key_bytes = b64url_decode(str(public_key_b64))
    if ed25519_did_key(public_key_bytes) != counterparty_did:
        return Evaluation(False, "binding")
    if public_key_bytes_from_did_key(str(counterparty_did)) != public_key_bytes:
        return Evaluation(False, "binding")
    parties = input_data.get("parties")
    if not isinstance(parties, list):
        return Evaluation(False, "schema")
    matches = [
        party
        for party in parties
        if isinstance(party, dict) and party.get("agent_id") == counterparty_did
    ]
    if len(matches) != 1:
        return Evaluation(False, "binding")
    signature = matches[0].get("signature")
    if not isinstance(signature, str) or not signature:
        return Evaluation(False, "signature")
    preimage = canonical_cosign_bytes(input_data)
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None:
        if "sha256:" + hashlib.sha256(preimage).hexdigest() != expected_digest:
            return Evaluation(False, "digest")
    if not verify_ed25519_signature(str(public_key_b64), signature, preimage):
        return Evaluation(False, "signature")
    return Evaluation(True)


def evaluate_bare_signed_profile(
    vector: Vector,
    *,
    schema: dict[str, Any],
    preimage: bytes,
) -> Evaluation:
    input_data = vector.input_data
    context = vector.context
    if not schema_is_valid(schema, input_data):
        return Evaluation(False, "schema")
    if input_data.get("algorithm") != "EdDSA":
        return Evaluation(False, "signature")
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None:
        if "sha256:" + hashlib.sha256(preimage).hexdigest() != expected_digest:
            return Evaluation(False, "digest")
    public_key_b64 = context.get("public_key_b64url")
    signature = input_data.get("signature")
    if not isinstance(public_key_b64, str) or not isinstance(signature, str):
        return Evaluation(False, "signature")
    if not verify_ed25519_signature(public_key_b64, signature, preimage):
        return Evaluation(False, "signature")
    return Evaluation(True)


def evaluate_digest_checks(input_data: dict[str, Any], context: dict[str, Any]) -> Evaluation:
    checks = context.get("digest_checks", [])
    if not isinstance(checks, list):
        return Evaluation(False, "binding")
    for check in checks:
        if not isinstance(check, dict):
            return Evaluation(False, "binding")
        if check.get("kind") != "jcs-sha256-pointer":
            return Evaluation(False, "binding")
        try:
            source = resolve_object(str(check["source"]), input_data, context)
            target = resolve_side(check["target"], input_data, context)
        except (GenerationError, KeyError, TypeError, ValueError, IndexError):
            return Evaluation(False, "binding")
        if sha256_jcs(source) != target:
            return Evaluation(False, "digest")
    return Evaluation(True)


def evaluate_closure_predicate_profile(vector: Vector) -> Evaluation:
    input_data = vector.input_data
    context = vector.context
    if not schema_is_valid(CLOSURE_PREDICATE_SCHEMA, input_data):
        return Evaluation(False, "schema")
    preimage = canonicalize_closure_predicate(input_data)
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None:
        if "sha256:" + hashlib.sha256(preimage).hexdigest() != expected_digest:
            return Evaluation(False, "digest")
    digest_result = evaluate_digest_checks(input_data, context)
    if not digest_result.accepted:
        return digest_result
    return Evaluation(True)


def evaluate_chain_session_profile(vector: Vector) -> Evaluation:
    input_data = vector.input_data
    context = vector.context
    if not schema_is_valid(CHAIN_SESSION_SCHEMA, input_data):
        return Evaluation(False, "schema")
    preimage = canonicalize_chain_session(input_data)
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None:
        if "sha256:" + hashlib.sha256(preimage).hexdigest() != expected_digest:
            return Evaluation(False, "digest")
    return Evaluation(True)


LEGAL_CHAIN_TRANSITIONS: dict[str, set[str]] = {
    "PROPOSED": {"OPEN"},
    "OPEN": {"ACTIVATED", "DISSOLVED", "EXPIRED"},
    "ACTIVATED": set(),
    "DISSOLVED": set(),
    "EXPIRED": set(),
}


def transition_preconditions_hold(
    initial_session: dict[str, Any],
    target_state: str,
    transition_now: datetime,
) -> bool:
    source_state = initial_session.get("state")
    if source_state == "PROPOSED" and target_state == "OPEN":
        commitments = initial_session.get("commitments")
        participants = initial_session.get("participants")
        return (
            isinstance(commitments, list)
            and isinstance(participants, list)
            and len(commitments) == len(participants)
        )
    if source_state == "OPEN" and target_state == "ACTIVATED":
        activation_proof_id = initial_session.get("activation_proof_id")
        deadline = parse_datetime(str(initial_session.get("activation_deadline")))
        return isinstance(activation_proof_id, str) and transition_now < deadline
    if source_state == "OPEN" and target_state == "DISSOLVED":
        return isinstance(initial_session.get("unwind_record_id"), str)
    if source_state == "OPEN" and target_state == "EXPIRED":
        deadline = parse_datetime(str(initial_session.get("activation_deadline")))
        return (
            transition_now >= deadline
            and initial_session.get("activation_proof_id") is None
        )
    return True


def evaluate_chain_session_transition_profile(vector: Vector) -> Evaluation:
    input_data = vector.input_data
    if not isinstance(input_data, dict):
        return Evaluation(False, "transition")
    initial_session = input_data.get("initial_session")
    target_state = input_data.get("attempt_transition")
    transition_now_raw = input_data.get("transition_now")
    if (
        not isinstance(initial_session, dict)
        or not isinstance(target_state, str)
        or not isinstance(transition_now_raw, str)
    ):
        return Evaluation(False, "transition")
    try:
        if not schema_is_valid(CHAIN_SESSION_SCHEMA, initial_session):
            return Evaluation(False, "schema")
        transition_now = parse_datetime(transition_now_raw)
    except Exception:
        return Evaluation(False, "schema")
    source_state = initial_session.get("state")
    if not isinstance(source_state, str):
        return Evaluation(False, "transition")
    if target_state not in LEGAL_CHAIN_TRANSITIONS.get(source_state, set()):
        return Evaluation(False, "transition")
    if not transition_preconditions_hold(initial_session, target_state, transition_now):
        return Evaluation(False, "transition")
    return Evaluation(True)


AGENT_PROFILE_CANONICAL_FIELDS = (
    "type",
    "version",
    "agent_id",
    "name",
    "description",
    "capabilities",
    "negotiation_profile",
    "trust_signals",
    "endpoints",
    "location",
    "ttl",
    "updated_at",
)
AGENT_PROFILE_TOP_LEVEL_FIELDS = set(AGENT_PROFILE_CANONICAL_FIELDS) | {
    "signature",
    "verified",
}
AGENT_PROFILE_CAPABILITY_FIELDS = {
    "categories",
    "offer_types",
    "resolution_methods",
    "max_concurrent_sessions",
    "languages",
    "currencies",
}
AGENT_PROFILE_NEGOTIATION_FIELDS = {
    "style",
    "avg_rounds_to_agreement",
    "agreement_rate",
    "avg_session_duration_seconds",
    "concession_pattern",
}
AGENT_PROFILE_TRUST_SIGNAL_FIELDS = {
    "verascore_did",
    "verascore_tier",
    "verascore_composite",
    "sovereignty",
    "concordia_sessions_completed",
    "attestation_count",
    "concordia_preferred",
    "reputation",
}
AGENT_PROFILE_SOVEREIGNTY_FIELDS = {"L1", "L2", "L3", "L4"}
AGENT_PROFILE_REPUTATION_FIELDS = {
    "provider",
    "subject_did",
    "tier",
    "composite",
}
AGENT_PROFILE_ENDPOINT_FIELDS = {"negotiate", "a2a_card", "mcp_manifest"}
AGENT_PROFILE_LOCATION_FIELDS = {"regions", "jurisdictions"}


def require_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GenerationError("expected object")
    return value


def strict_subset_keys(
    payload: dict[str, Any],
    allowed: set[str],
    *,
    allow_extra: bool = False,
) -> bool:
    return allow_extra or set(payload).issubset(allowed)


def profile_subdict(
    payload: dict[str, Any],
    allowed: set[str],
    *,
    allow_extra: bool = False,
    drop_none: bool = False,
) -> dict[str, Any] | None:
    if not strict_subset_keys(payload, allowed, allow_extra=allow_extra):
        return None
    result = {key: payload[key] for key in sorted(allowed) if key in payload}
    if drop_none:
        result = {key: value for key, value in result.items() if value is not None}
    return result


def agent_profile_canonical_from_raw(input_data: dict[str, Any]) -> dict[str, Any] | None:
    if set(input_data) - AGENT_PROFILE_TOP_LEVEL_FIELDS:
        return None
    try:
        capabilities = profile_subdict(
            require_dict(input_data.get("capabilities")),
            AGENT_PROFILE_CAPABILITY_FIELDS,
        )
        negotiation_profile = profile_subdict(
            require_dict(input_data.get("negotiation_profile")),
            AGENT_PROFILE_NEGOTIATION_FIELDS,
        )
        trust_signals_raw = require_dict(input_data.get("trust_signals"))
        trust_signals = profile_subdict(
            trust_signals_raw,
            AGENT_PROFILE_TRUST_SIGNAL_FIELDS,
            allow_extra=True,
            drop_none=True,
        )
        if trust_signals is None:
            return None
        if "sovereignty" in trust_signals:
            sovereignty = profile_subdict(
                require_dict(trust_signals["sovereignty"]),
                AGENT_PROFILE_SOVEREIGNTY_FIELDS,
            )
            if sovereignty is None:
                return None
            trust_signals["sovereignty"] = sovereignty
        if "reputation" in trust_signals:
            reputation = trust_signals["reputation"]
            if not isinstance(reputation, list):
                return None
            normalized_reputation: list[dict[str, Any]] = []
            for assertion in reputation:
                if not isinstance(assertion, dict):
                    return None
                normalized = profile_subdict(
                    assertion,
                    AGENT_PROFILE_REPUTATION_FIELDS,
                    allow_extra=True,
                    drop_none=True,
                )
                if normalized is None or "provider" not in normalized:
                    return None
                normalized_reputation.append(normalized)
            trust_signals["reputation"] = normalized_reputation
        endpoints = profile_subdict(
            require_dict(input_data.get("endpoints")),
            AGENT_PROFILE_ENDPOINT_FIELDS,
            drop_none=True,
        )
        location = profile_subdict(
            require_dict(input_data.get("location")),
            AGENT_PROFILE_LOCATION_FIELDS,
        )
    except GenerationError:
        return None
    if any(
        item is None
        for item in (capabilities, negotiation_profile, endpoints, location)
    ):
        return None
    canonical: dict[str, Any] = {}
    for field_name in AGENT_PROFILE_CANONICAL_FIELDS:
        if field_name == "capabilities":
            canonical[field_name] = capabilities
        elif field_name == "negotiation_profile":
            canonical[field_name] = negotiation_profile
        elif field_name == "trust_signals":
            canonical[field_name] = trust_signals
        elif field_name == "endpoints":
            canonical[field_name] = endpoints
        elif field_name == "location":
            canonical[field_name] = location
        elif field_name in input_data:
            canonical[field_name] = input_data[field_name]
        else:
            return None
    return canonical


def evaluate_agent_profile_profile(vector: Vector) -> Evaluation:
    input_data = vector.input_data
    context = vector.context
    expected_fields = context.get("canonical_fields")
    if tuple(expected_fields or ()) != AGENT_PROFILE_CANONICAL_FIELDS:
        return Evaluation(False, "binding")
    canonical = agent_profile_canonical_from_raw(input_data)
    if canonical is None:
        return Evaluation(False, "schema")
    preimage = canonical_json(canonical)
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None:
        if "sha256:" + hashlib.sha256(preimage).hexdigest() != expected_digest:
            return Evaluation(False, "digest")
    public_key_b64 = context.get("public_key_b64url")
    signature = input_data.get("signature")
    if not isinstance(public_key_b64, str) or not isinstance(signature, str):
        return Evaluation(False, "signature")
    if not verify_ed25519_signature(public_key_b64, signature, preimage):
        return Evaluation(False, "signature")
    return Evaluation(True)


def evaluate_receipt_bundle_profile(vector: Vector) -> Evaluation:
    input_data = vector.input_data
    context = vector.context
    schema = load_json(SCHEMA_COPIES["receipt_bundle.schema.json"])
    if not schema_is_valid(schema, input_data):
        return Evaluation(False, "schema")
    signable = without_keys(input_data, {"agent_signature", "concordia_receipt_bundle"})
    preimage = canonical_json(signable)
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None:
        if "sha256:" + hashlib.sha256(preimage).hexdigest() != expected_digest:
            return Evaluation(False, "digest")
    public_key_b64 = context.get("public_key_b64url")
    signature = input_data.get("agent_signature")
    if not isinstance(public_key_b64, str) or not isinstance(signature, str):
        return Evaluation(False, "signature")
    if not verify_ed25519_signature(public_key_b64, signature, preimage):
        return Evaluation(False, "signature")
    return Evaluation(True)


def verify_conformance_merkle_proof(
    attestation_id: str,
    proof: dict[str, Any],
    root: str,
) -> bool:
    return verify_merkle_proof(attestation_id, proof, root)


def competence_proof_signable(input_data: dict[str, Any]) -> dict[str, Any]:
    return without_keys(input_data, {"agent_signature", "concordia_competence_proof"})


def evaluate_competence_proof_profile(vector: Vector) -> Evaluation:
    input_data = vector.input_data
    context = vector.context
    required = {
        "proof_id",
        "agent_id",
        "created_at",
        "claims",
        "attestation_merkle_root",
        "attestation_count",
        "merkle_proofs",
        "revealed_attestations",
        "agent_signature",
    }
    if not required.issubset(input_data):
        return Evaluation(False, "schema")
    claims = input_data.get("claims")
    attestation_count = input_data.get("attestation_count")
    if not isinstance(claims, dict) or claims.get("total_negotiations") != attestation_count:
        return Evaluation(False, "binding")
    root = input_data.get("attestation_merkle_root")
    merkle_proofs = input_data.get("merkle_proofs")
    revealed_attestations = input_data.get("revealed_attestations")
    if (
        not isinstance(root, str)
        or not isinstance(merkle_proofs, list)
        or not isinstance(revealed_attestations, list)
    ):
        return Evaluation(False, "schema")
    proofs_by_attestation_id: dict[str, dict[str, Any]] = {}
    for proof in merkle_proofs:
        if not isinstance(proof, dict) or not isinstance(proof.get("attestation_id"), str):
            return Evaluation(False, "schema")
        proofs_by_attestation_id[proof["attestation_id"]] = proof
    for attestation in revealed_attestations:
        if not isinstance(attestation, dict):
            return Evaluation(False, "schema")
        attestation_id = attestation.get("attestation_id")
        if not isinstance(attestation_id, str):
            return Evaluation(False, "schema")
        proof = proofs_by_attestation_id.get(attestation_id)
        if proof is None:
            return Evaluation(False, "binding")
        if not verify_conformance_merkle_proof(attestation_id, proof, root):
            return Evaluation(False, "binding")
    signable = competence_proof_signable(input_data)
    preimage = canonical_json(signable)
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None:
        if "sha256:" + hashlib.sha256(preimage).hexdigest() != expected_digest:
            return Evaluation(False, "digest")
    public_key_b64 = context.get("public_key_b64url")
    signature = input_data.get("agent_signature")
    if not isinstance(public_key_b64, str) or not isinstance(signature, str):
        return Evaluation(False, "signature")
    if not verify_ed25519_signature(public_key_b64, signature, preimage):
        return Evaluation(False, "signature")
    return Evaluation(True)


def message_chain_messages(input_data: dict[str, Any]) -> list[dict[str, Any]] | None:
    if set(input_data) not in ({"messages"}, {"messages", "receipt"}):
        return None
    messages = input_data.get("messages")
    if not isinstance(messages, list) or not messages:
        return None
    normalized: list[dict[str, Any]] = []
    for message in messages:
        if not isinstance(message, dict):
            return None
        normalized.append(message)
    return normalized


def attestation_version_at_least(value: Any, major: int, minor: int) -> bool:
    if not isinstance(value, str) or SEMVER_RE.match(value) is None:
        return False
    parts = value.split(".")
    return (int(parts[0]), int(parts[1])) >= (major, minor)


def evaluate_message_chain_receipt_binding(
    input_data: dict[str, Any],
    messages: list[dict[str, Any]],
    context: dict[str, Any],
) -> Evaluation:
    receipt = input_data.get("receipt")
    if receipt is None:
        return Evaluation(True)
    if not isinstance(receipt, dict):
        return Evaluation(False, "schema")

    schema = load_json(SCHEMA_COPIES["attestation.schema.json"])
    if not schema_is_valid(schema, receipt):
        return Evaluation(False, "schema")
    if not attestation_version_at_least(receipt.get("concordia_attestation"), 0, 3):
        return Evaluation(False, "binding")
    if not isinstance(receipt.get("chain_head"), str) or not SHA256_HEX_RE.match(
        receipt["chain_head"]
    ):
        return Evaluation(False, "binding")
    if (
        not isinstance(receipt.get("message_count"), int)
        or isinstance(receipt.get("message_count"), bool)
        or receipt["message_count"] < 1
    ):
        return Evaluation(False, "binding")

    public_keys = context.get("public_keys_b64url")
    parties = receipt.get("parties")
    countersignatures = receipt.get("countersignatures")
    if (
        not isinstance(public_keys, dict)
        or not isinstance(parties, list)
        or not isinstance(countersignatures, dict)
    ):
        return Evaluation(False, "signature")
    countersign_payload = attestation_countersign_payload(receipt)
    for party in parties:
        if not isinstance(party, dict):
            return Evaluation(False, "schema")
        agent_id = party.get("agent_id")
        signature = party.get("signature")
        if not isinstance(agent_id, str) or not isinstance(signature, str):
            return Evaluation(False, "signature")
        public_key_b64 = public_keys.get(agent_id)
        if not isinstance(public_key_b64, str):
            return Evaluation(False, "signature")
        if not verify_ed25519_signature(
            public_key_b64,
            signature,
            canonical_json(without_signature(party)),
        ):
            return Evaluation(False, "signature")
        countersignature = countersignatures.get(agent_id)
        if not isinstance(countersignature, str):
            return Evaluation(False, "signature")
        if not verify_ed25519_signature(
            public_key_b64,
            countersignature,
            countersign_payload,
        ):
            return Evaluation(False, "signature")

    if receipt["message_count"] != len(messages):
        return Evaluation(False, "binding")
    if receipt["chain_head"] != compute_hash(messages[-1]):
        return Evaluation(False, "binding")
    return Evaluation(True)


def evaluate_message_chain_profile(
    vector: Vector,
    *,
    skip_receipt_set_binding: bool = False,
) -> Evaluation:
    input_data = vector.input_data
    context = vector.context
    messages = message_chain_messages(input_data)
    if messages is None:
        return Evaluation(False, "schema")
    expected_count = context.get("expected_message_count")
    if expected_count is not None and expected_count != len(messages):
        return Evaluation(False, "binding")
    if messages[0].get("prev_hash") != GENESIS_HASH:
        return Evaluation(False, "binding")
    for index in range(1, len(messages)):
        if messages[index].get("prev_hash") != compute_hash(messages[index - 1]):
            return Evaluation(False, "binding")
    public_keys = context.get("public_keys_b64url")
    if not isinstance(public_keys, dict):
        return Evaluation(False, "signature")
    for message in messages:
        sender = message.get("from")
        if not isinstance(sender, dict):
            return Evaluation(False, "schema")
        agent_id = sender.get("agent_id")
        signature = message.get("signature")
        if not isinstance(agent_id, str) or not isinstance(signature, str):
            return Evaluation(False, "signature")
        public_key_b64 = public_keys.get(agent_id)
        if not isinstance(public_key_b64, str):
            return Evaluation(False, "signature")
        if not verify_ed25519_signature(
            public_key_b64,
            signature,
            canonical_json(without_signature(message)),
        ):
            return Evaluation(False, "signature")
    expected_hashes = context.get("expected_message_hashes")
    if expected_hashes is not None:
        if expected_hashes != [compute_hash(message) for message in messages]:
            return Evaluation(False, "digest")
    if not skip_receipt_set_binding:
        receipt_binding = evaluate_message_chain_receipt_binding(
            input_data,
            messages,
            context,
        )
        if not receipt_binding.accepted:
            return receipt_binding
    return Evaluation(True)


def verify_vector(vector: Vector) -> bool:
    return evaluate_vector(vector).accepted


def evaluate_vector(vector: Vector) -> Evaluation:
    profile = vector.verification_profile
    input_data = vector.input_data
    context = vector.context

    if profile == "decision-object-v1":
        if sha256_jcs(input_data) != context["expected_decision_id"]:
            return Evaluation(False, "digest")
        return Evaluation(True)

    if profile == "offer-binding-v1":
        for check in context["checks"]:
            kind = check["kind"]
            if kind == "jcs-sha256":
                source = resolve_object(check["source"], input_data, context)
                if sha256_jcs(source) != check["expected"]:
                    return Evaluation(False, "digest")
            elif kind == "json-pointer-equal":
                try:
                    left = resolve_side(check["left"], input_data, context)
                    right = resolve_side(check["right"], input_data, context)
                except (GenerationError, KeyError, TypeError, ValueError, IndexError):
                    return Evaluation(False, "binding")
                if left != right:
                    return Evaluation(False, "binding")
            else:
                raise GenerationError(f"unknown offer-binding check kind: {kind}")
        return Evaluation(True)

    if profile == "receipt-v1":
        if validate_approval_receipt(input_data) != []:
            return Evaluation(False, "schema")
        if not has_approves_reference(input_data):
            return Evaluation(False, "binding")
        signature = input_data.get("signature")
        if not isinstance(signature, dict) or signature.get("alg") != "Ed25519":
            return Evaluation(False, "signature")
        public_key = Ed25519PublicKey.from_public_bytes(
            b64url_decode(context["public_keys_b64url"]["issuer"])
        )
        try:
            public_key.verify(
                b64url_decode(str(signature.get("value", ""))),
                canonical_json(without_signature(input_data)),
            )
        except Exception:
            return Evaluation(False, "signature")
        if parse_datetime(input_data["expires_at"]) < parse_datetime(context["now"]):
            return Evaluation(False, "temporal")
        scope = input_data.get("scope")
        if not isinstance(scope, dict):
            return Evaluation(False, "binding")
        if sha256_jcs(context["offer"]) != scope.get("offer_hash"):
            return Evaluation(False, "binding")
        return Evaluation(True)

    if profile == "revocation-v1":
        if not schema_is_valid(REVOCATION_RECORD_SCHEMA, input_data):
            return Evaluation(False, "schema")
        if not has_revokes_reference(input_data):
            return Evaluation(False, "binding")
        signature = input_data.get("signature")
        if not isinstance(signature, dict) or signature.get("alg") != "EdDSA":
            return Evaluation(False, "signature")
        public_key = Ed25519PublicKey.from_public_bytes(
            b64url_decode(context["public_keys_b64url"]["issuer"])
        )
        try:
            public_key.verify(
                b64url_decode(str(signature.get("value", ""))),
                canonicalize_jcs(without_signature(input_data)),
            )
        except Exception:
            return Evaluation(False, "signature")
        return Evaluation(True)

    if profile == "cascade-decision-v1":
        try:
            validate_cascade_decision_record(input_data)
        except Exception:
            return Evaluation(False, "schema")
        preimage_bytes = canonicalize_cascade_decision_record(input_data)
        recomputed = hashlib.sha256(preimage_bytes).hexdigest()
        claimed_id = input_data.get("decision_id")
        if not isinstance(claimed_id, str) or recomputed != claimed_id:
            return Evaluation(False, "digest")
        expected = context.get("expected_decision_id")
        if expected is not None and f"sha256:{claimed_id}" != expected:
            return Evaluation(False, "digest")
        signature = input_data.get("signature")
        if not isinstance(signature, dict) or signature.get("alg") != "EdDSA":
            return Evaluation(False, "signature")
        public_key = Ed25519PublicKey.from_public_bytes(
            b64url_decode(context["public_keys_b64url"]["issuer"])
        )
        try:
            public_key.verify(b64url_decode(str(signature.get("value", ""))), preimage_bytes)
        except Exception:
            return Evaluation(False, "signature")
        return Evaluation(True)

    if profile == "fulfillment-attestation-v1":
        schema = load_json(SCHEMA_COPIES["fulfillment_attestation.schema.json"])
        if not schema_is_valid(schema, input_data):
            return Evaluation(False, "schema")
        if not has_fulfills_reference(input_data):
            return Evaluation(False, "binding")
        signature = input_data.get("signature")
        if not isinstance(signature, dict) or signature.get("alg") != "Ed25519":
            return Evaluation(False, "signature")
        public_key = Ed25519PublicKey.from_public_bytes(
            b64url_decode(context["public_key_b64url"])
        )
        signable = without_signature(input_data)
        canonical = canonical_json(signable)
        try:
            public_key.verify(b64url_decode(str(signature.get("value", ""))), canonical)
        except Exception:
            return Evaluation(False, "signature")
        expected_digest = context.get("canonical_sha256")
        if expected_digest is not None:
            if "sha256:" + hashlib.sha256(canonical).hexdigest() != expected_digest:
                return Evaluation(False, "digest")
        seed = context.get("seed_ed25519_ascii")
        if seed is not None:
            seed_bytes = seed.encode("utf-8")
            if len(seed_bytes) != 32:
                return Evaluation(False, "signature")
            private_key = Ed25519PrivateKey.from_private_bytes(seed_bytes)
            derived_public = b64url_encode(private_key.public_key().public_bytes_raw())
            if derived_public != context["public_key_b64url"]:
                return Evaluation(False, "signature")
            expected_signature = context.get("signature_b64url")
            if expected_signature is not None:
                derived_signature = b64url_encode(private_key.sign(canonical))
                if (
                    derived_signature != expected_signature
                    or derived_signature != input_data["signature"]["value"]
                ):
                    return Evaluation(False, "signature")
        join_keys = context.get("join_keys", {})
        if "charge_ref" in join_keys and input_data.get("charge_ref") != join_keys["charge_ref"]:
            return Evaluation(False, "binding")
        if "action_ref" in join_keys and input_data.get("action_ref") != join_keys["action_ref"]:
            return Evaluation(False, "binding")
        if context.get("forbid_raw_deal_terms") and contains_raw_term(input_data):
            return Evaluation(False, "privacy")
        return Evaluation(True)

    if profile == "attestation-v1":
        return evaluate_attestation_profile(vector)

    if profile == "attestation-countersign-v1":
        return evaluate_attestation_countersign_profile(vector)

    if profile == "predicate-v1":
        return evaluate_predicate_profile(vector)

    if profile == "mandate-v1":
        return evaluate_mandate_profile(vector)

    if profile == "delegation-chain-v1":
        return evaluate_mandate_profile(vector, require_chain=True)

    if profile == "cosign-v1":
        return evaluate_cosign_profile(vector)

    if profile == "conditional-commitment-v1":
        return evaluate_bare_signed_profile(
            vector,
            schema=CONDITIONAL_COMMITMENT_SCHEMA,
            preimage=canonicalize_conditional_commitment(input_data),
        )

    if profile == "atomic-activation-proof-v1":
        return evaluate_bare_signed_profile(
            vector,
            schema=ATOMIC_ACTIVATION_PROOF_SCHEMA,
            preimage=canonicalize_atomic_activation_proof(input_data),
        )

    if profile == "unwind-record-v1":
        return evaluate_bare_signed_profile(
            vector,
            schema=UNWIND_RECORD_SCHEMA,
            preimage=canonicalize_unwind_record(input_data),
        )

    if profile == "closure-predicate-v1":
        return evaluate_closure_predicate_profile(vector)

    if profile == "chain-session-v1":
        return evaluate_chain_session_profile(vector)

    if profile == "chain-session-transition-v1":
        return evaluate_chain_session_transition_profile(vector)

    if profile == "agent-profile-v1":
        return evaluate_agent_profile_profile(vector)

    if profile == "competence-proof-v1":
        return evaluate_competence_proof_profile(vector)

    if profile == "receipt-bundle-v1":
        return evaluate_receipt_bundle_profile(vector)

    if profile == "message-chain-v1":
        return evaluate_message_chain_profile(vector)

    raise GenerationError(f"unknown profile: {profile}")


def fixture_1404() -> dict[str, dict[str, Any]]:
    names = (
        "approval_receipt",
        "capability",
        "cascade_decision_deny",
        "decision_object",
        "offer",
        "revocation_A",
        "vector",
    )
    return {name: load_json(INTEROP_1404 / f"{name}.json") for name in names}


def fixture_1920() -> dict[str, dict[str, Any]]:
    return {
        "fulfillment_attestation": load_json(INTEROP_1920 / "fulfillment_attestation.json"),
        "sample": load_json(INTEROP_1920 / "sample.json"),
    }


ATTESTATION_TOP_LEVEL_ESCAPE_NOTE = (
    "accepted-structural: field is outside attestation-v1 party-signature preimages"
)
ATTESTATION_COUNTERSIGNATURE_ESCAPE_NOTE = (
    "accepted-structural: countersignatures are ignored by attestation-v1"
)
COUNTERSIGN_STRIPPED_PARTY_SIGNATURE_NOTE = (
    "accepted-structural: party signatures are stripped from the countersignature preimage"
)
COUNTERSIGN_EXTRA_MAP_ENTRY_NOTE = (
    "accepted-structural: extra countersignature map entry is outside the required signer set and preimage"
)
CLOSURE_SIGNATURE_NOT_VERIFIED_NOTE = (
    "accepted-structural: closure-predicate-v1 does not verify or commit /signature"
)
AGENT_PROFILE_TRUST_SIGNAL_TOLERANCE_NOTE = (
    "accepted-structural: unknown trust_signals keys are ignored by AgentProfile canonicalization"
)
AGENT_PROFILE_REPUTATION_TOLERANCE_NOTE = (
    "accepted-structural: unknown reputation assertion keys are ignored by AgentProfile canonicalization"
)
AGENT_PROFILE_VERIFIED_TOLERANCE_NOTE = (
    "accepted-structural: verified is store-local and excluded from AgentProfile.to_canonical_dict()"
)
COMPETENCE_PROOF_VERSION_TOLERANCE_NOTE = (
    "accepted-structural: concordia_competence_proof is excluded from CompetenceProof.to_signable_dict()"
)
RECEIPT_BUNDLE_VERSION_TOLERANCE_NOTE = (
    "accepted-structural: concordia_receipt_bundle is schema-valid metadata and excluded from the ReceiptBundle signable form"
)
CHAIN_POSITION_RESIGNED_SPLICE_TOLERANCE_NOTE = (
    "tolerated-accept: per-message signatures authenticate links, not the complete message set"
)
EXPECTED_MUTATION_TOTAL = 1484
EXPECTED_MUTATION_REJECTS = 1439
EXPECTED_MUTATION_ACCEPTS = 45
EXPECTED_CANARY_TOTAL = 5
EXPECTED_RAW_TYPED_DIVERGENCES = (
    MutationDivergence(
        battery_name="1404/revocation_A.json",
        field_path="cascade_depth",
        kind="drop",
        sdk_expected="accept",
        raw_expected="reject",
    ),
)
EXPECTED_RAW_ACCEPTED_MUTATIONS: frozenset[tuple[str, str, MutationKind]] = frozenset()
EXPECTED_MUTATION_BATTERY_COUNTS: dict[str, tuple[int, int, int]] = {
    "1404/approval_receipt.json": (63, 63, 0),
    "1404/cascade_decision_deny.json": (35, 35, 0),
    "1404/decision_object.json": (13, 13, 0),
    "1404/offer.json": (15, 15, 0),
    "1404/revocation_A.json": (33, 33, 0),
    "1920/fulfillment_attestation.json": (63, 63, 0),
    "synthetic/attestation/attestation.json::attestation-countersign-v1": (
        111,
        108,
        3,
    ),
    "synthetic/attestation/attestation.json::attestation-v1": (111, 78, 33),
    "synthetic/cosign/cosigned_receipt.json": (42, 42, 0),
    "synthetic/cmpc_bilateral/primitives/atomic_activation_proof.json": (30, 30, 0),
    "synthetic/cmpc_bilateral/primitives/chain_session.json": (25, 25, 0),
    "synthetic/cmpc_bilateral/primitives/closure_predicate.json": (40, 39, 1),
    "synthetic/cmpc_bilateral/primitives/conditional_commitment.json": (35, 35, 0),
    "synthetic/cmpc_bilateral/primitives/unwind_record.json": (28, 28, 0),
    "synthetic/longtail/agent_profile.json": (100, 96, 4),
    "synthetic/longtail/competence_proof.json": (157, 155, 2),
    "synthetic/longtail/message_chain.json": (99, 99, 0),
    "synthetic/longtail/message_chain_position.json": (4, 3, 1),
    "synthetic/longtail/receipt_set_binding.json": (4, 4, 0),
    "synthetic/longtail/receipt_bundle.json": (256, 255, 1),
    "synthetic/mandate/delegated_mandate.json": (82, 82, 0),
    "synthetic/mandate/mandate.json": (51, 51, 0),
    "synthetic/predicate/vector_02.json": (87, 87, 0),
}


def build_mutation_fixtures(
    f1404: dict[str, dict[str, Any]],
    f1920: dict[str, dict[str, Any]],
    synthetic: SyntheticFixtures,
) -> list[MutationFixture]:
    hashes = f1404["vector"]["hashes"]
    public_keys_1404 = f1404["vector"]["public_keys_b64url"]
    sample = f1920["sample"]
    attestation_public_keys = synthetic.attestation_seed_manifest[
        "agent_public_keys_b64url"
    ]
    attestation_parties = [
        party["agent_id"] for party in synthetic.attestation["parties"]
    ]
    countersign_preimage = attestation_countersign_payload(synthetic.attestation)
    predicate = synthetic.predicates[P2_A2_PREDICATE_MUTATION_FIXTURE]
    predicate_preimage = canonical_json(without_signature(predicate))
    action = {"max_spend": 500, "category": "software"}
    mandate_key_manifest = synthetic.mandate_seed_manifest[
        "seeds_PUBLIC_test_only_do_not_reuse"
    ]
    mandate_agent_ids = synthetic.mandate_seed_manifest["agent_ids"]
    mandate_issuer_key = mandate_key_manifest["mandate_issuer"]["public_key_b64url"]
    cosign_dids = synthetic.cosign_seed_manifest["dids"]
    cosign_key_manifest = synthetic.cosign_seed_manifest[
        "seeds_PUBLIC_test_only_do_not_reuse"
    ]
    cosign_preimage = canonical_cosign_bytes(synthetic.cosigned_receipt)
    cmpc_keys = synthetic.cmpc.seed_manifest["seeds_PUBLIC_test_only_do_not_reuse"]
    cmpc_retailer_key = cmpc_keys["cmpc_retailer"]["public_key_b64url"]
    cmpc_wholesaler_key = cmpc_keys["cmpc_wholesaler"]["public_key_b64url"]
    cmpc_authority_key = cmpc_keys["cmpc_authority"]["public_key_b64url"]
    longtail_keys = synthetic.longtail.seed_manifest["seeds_PUBLIC_test_only_do_not_reuse"]
    longtail_agent_ids = synthetic.longtail.seed_manifest["agent_ids"]
    agent_profile_preimage = canonical_json(
        agent_profile_canonical_from_raw(synthetic.longtail.agent_profile) or {}
    )
    receipt_bundle_preimage = canonical_json(
        without_keys(
            synthetic.longtail.receipt_bundle,
            {"agent_signature", "concordia_receipt_bundle"},
        )
    )
    competence_proof_preimage = canonical_json(
        competence_proof_signable(synthetic.longtail.competence_proof)
    )
    message_hashes = [
        compute_hash(message)
        for message in synthetic.longtail.message_chain["messages"]
    ]

    return [
        MutationFixture(
            battery_name="1920/fulfillment_attestation.json",
            fixture_label="1920",
            object_label="fulfillment-attestation",
            object_name="fulfillment_attestation",
            input_data=f1920["fulfillment_attestation"],
            source_fixture=INTEROP_1920.name,
            record_type="fulfillment_attestation",
            verification_profile="fulfillment-attestation-v1",
            context={
                "canonical_sha256": sample["canonical_sha256"],
                "forbid_raw_deal_terms": True,
                "join_keys": sample["join_keys"],
                "public_key_b64url": sample["public_key_b64url"],
                "seed_ed25519_ascii": sample["seed_ed25519_ascii"],
                "signature_b64url": sample["signature_b64url"],
            },
            sdk_rejected=63,
            sdk_total=63,
            sdk_escapes=frozenset(),
        ),
        MutationFixture(
            battery_name="1404/decision_object.json",
            fixture_label="1404",
            object_label="decision-object",
            object_name="decision_object",
            input_data=f1404["decision_object"],
            source_fixture=INTEROP_1404.name,
            record_type="decision_object",
            verification_profile="decision-object-v1",
            context={"expected_decision_id": hashes["decision_id"]},
            sdk_rejected=13,
            sdk_total=13,
            sdk_escapes=frozenset(),
        ),
        MutationFixture(
            battery_name="1404/offer.json",
            fixture_label="1404",
            object_label="offer",
            object_name="offer",
            input_data=f1404["offer"],
            source_fixture=INTEROP_1404.name,
            record_type="approval_receipt",
            verification_profile="offer-binding-v1",
            context={
                "checks": [
                    {
                        "kind": "jcs-sha256",
                        "source": "input",
                        "expected": hashes["request_digest"],
                    },
                    {
                        "kind": "jcs-sha256",
                        "source": "input",
                        "expected": hashes["receipt_offer_hash"],
                    },
                ]
            },
            sdk_rejected=15,
            sdk_total=15,
            sdk_escapes=frozenset(),
        ),
        MutationFixture(
            battery_name="1404/approval_receipt.json",
            fixture_label="1404",
            object_label="approval-receipt",
            object_name="approval_receipt",
            input_data=f1404["approval_receipt"],
            source_fixture=INTEROP_1404.name,
            record_type="approval_receipt",
            verification_profile="receipt-v1",
            context={
                "offer": f1404["offer"],
                "now": "2026-05-10T14:25:00Z",
                "public_keys_b64url": {"issuer": public_keys_1404["approver"]},
            },
            sdk_rejected=63,
            sdk_total=63,
            sdk_escapes=frozenset(),
        ),
        MutationFixture(
            battery_name="1404/revocation_A.json",
            fixture_label="1404",
            object_label="revocation-a",
            object_name="revocation_A",
            input_data=f1404["revocation_A"],
            source_fixture=INTEROP_1404.name,
            record_type="revocation_record",
            verification_profile="revocation-v1",
            context={
                "public_keys_b64url": {
                    "issuer": public_keys_1404["revocation_issuer"]
                }
            },
            sdk_rejected=32,
            sdk_total=33,
            sdk_escapes=frozenset({("cascade_depth", "drop")}),
        ),
        MutationFixture(
            battery_name="1404/cascade_decision_deny.json",
            fixture_label="1404",
            object_label="cascade-decision-deny",
            object_name="cascade_decision_deny",
            input_data=f1404["cascade_decision_deny"],
            source_fixture=INTEROP_1404.name,
            record_type="cascade_decision_record",
            verification_profile="cascade-decision-v1",
            context={
                "expected_decision_id": hashes["deny_decision_id"],
                "public_keys_b64url": {
                    "issuer": public_keys_1404["revocation_issuer"]
                },
            },
            sdk_rejected=35,
            sdk_total=35,
            sdk_escapes=frozenset(),
        ),
        MutationFixture(
            battery_name="synthetic/attestation/attestation.json::attestation-v1",
            fixture_label="synthetic",
            object_label="attestation",
            object_name="attestation",
            input_data=synthetic.attestation,
            source_fixture=SYNTHETIC_SOURCE_ATTESTATION,
            record_type="attestation",
            verification_profile="attestation-v1",
            context={
                "forbid_raw_deal_terms": True,
                "expected_verified_parties": attestation_parties,
                "public_keys_b64url": attestation_public_keys,
            },
            sdk_rejected=0,
            sdk_total=111,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name=(
                "synthetic/attestation/attestation.json::"
                "attestation-countersign-v1"
            ),
            fixture_label="synthetic",
            object_label="attestation-countersign",
            object_name="attestation_countersign",
            input_data=synthetic.attestation,
            source_fixture=SYNTHETIC_SOURCE_ATTESTATION,
            record_type="attestation",
            verification_profile="attestation-countersign-v1",
            context={
                "canonical_sha256": "sha256:"
                + hashlib.sha256(countersign_preimage).hexdigest(),
                "countersigners": attestation_parties,
                "public_keys_b64url": attestation_public_keys,
            },
            sdk_rejected=0,
            sdk_total=111,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name=(
                "synthetic/predicate/"
                f"{P2_A2_PREDICATE_MUTATION_FIXTURE}.json"
            ),
            fixture_label="synthetic",
            object_label="predicate-vector-02",
            object_name="predicate_vector_02",
            input_data=predicate,
            source_fixture=SYNTHETIC_SOURCE_PREDICATE,
            record_type="predicate",
            verification_profile="predicate-v1",
            context={
                "canonical_sha256": "sha256:"
                + hashlib.sha256(predicate_preimage).hexdigest(),
                "now": fixed_iso_now(),
                "public_key_b64url": synthetic.predicate_seed_manifest[
                    "seeds_PUBLIC_test_only_do_not_reuse"
                ]["predicate_issuer"]["public_key_b64url"],
            },
            sdk_rejected=0,
            sdk_total=87,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name="synthetic/mandate/mandate.json",
            fixture_label="synthetic",
            object_label="mandate",
            object_name="mandate",
            input_data=synthetic.direct_mandate,
            source_fixture=SYNTHETIC_SOURCE_MANDATE,
            record_type="mandate",
            verification_profile="mandate-v1",
            context={
                "action": action,
                "canonical_sha256": sha256_jcs(
                    without_signature(synthetic.direct_mandate)
                ),
                "issuer_public_key_b64url": mandate_issuer_key,
                "now": fixed_iso_now(),
            },
            sdk_rejected=0,
            sdk_total=51,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name="synthetic/mandate/delegated_mandate.json",
            fixture_label="synthetic",
            object_label="delegation-chain",
            object_name="delegation_chain",
            input_data=synthetic.delegated_mandate,
            source_fixture=SYNTHETIC_SOURCE_MANDATE,
            record_type="mandate",
            verification_profile="delegation-chain-v1",
            context={
                "action": action,
                "canonical_sha256": sha256_jcs(
                    without_signature(synthetic.delegated_mandate)
                ),
                "delegation_public_keys_b64url": {
                    mandate_agent_ids["issuer"]: mandate_key_manifest[
                        "mandate_issuer"
                    ]["public_key_b64url"],
                    mandate_agent_ids["delegate"]: mandate_key_manifest[
                        "mandate_delegate"
                    ]["public_key_b64url"],
                },
                "issuer_public_key_b64url": mandate_issuer_key,
                "now": fixed_iso_now(),
            },
            sdk_rejected=0,
            sdk_total=82,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name="synthetic/cosign/cosigned_receipt.json",
            fixture_label="synthetic",
            object_label="cosign",
            object_name="cosign_receipt",
            input_data=synthetic.cosigned_receipt,
            source_fixture=SYNTHETIC_SOURCE_COSIGN,
            record_type="cosign_receipt",
            verification_profile="cosign-v1",
            context={
                "canonical_sha256": "sha256:"
                + hashlib.sha256(cosign_preimage).hexdigest(),
                "counterparty_did": cosign_dids["counterparty"],
                "counterparty_public_key_b64url": cosign_key_manifest[
                    "cosign_counterparty"
                ]["public_key_b64url"],
                "publisher_did": cosign_dids["publisher"],
            },
            sdk_rejected=0,
            sdk_total=42,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name="synthetic/cmpc_bilateral/primitives/conditional_commitment.json",
            fixture_label="synthetic",
            object_label="cmpc-conditional-commitment",
            object_name="cmpc_conditional_commitment",
            input_data=synthetic.cmpc.conditional_commitment,
            source_fixture=SYNTHETIC_SOURCE_CMPC,
            record_type="conditional_commitment",
            verification_profile="conditional-commitment-v1",
            context={
                "canonical_sha256": sha256_jcs(
                    without_signature(synthetic.cmpc.conditional_commitment)
                ),
                "public_key_b64url": cmpc_retailer_key,
            },
            sdk_rejected=0,
            sdk_total=35,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name="synthetic/cmpc_bilateral/primitives/atomic_activation_proof.json",
            fixture_label="synthetic",
            object_label="cmpc-atomic-activation-proof",
            object_name="cmpc_atomic_activation_proof",
            input_data=synthetic.cmpc.atomic_activation_proof,
            source_fixture=SYNTHETIC_SOURCE_CMPC,
            record_type="atomic_activation_proof",
            verification_profile="atomic-activation-proof-v1",
            context={
                "canonical_sha256": sha256_jcs(
                    without_signature(synthetic.cmpc.atomic_activation_proof)
                ),
                "public_key_b64url": cmpc_wholesaler_key,
            },
            sdk_rejected=0,
            sdk_total=30,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name="synthetic/cmpc_bilateral/primitives/unwind_record.json",
            fixture_label="synthetic",
            object_label="cmpc-unwind-record",
            object_name="cmpc_unwind_record",
            input_data=synthetic.cmpc.unwind_record,
            source_fixture=SYNTHETIC_SOURCE_CMPC,
            record_type="unwind_record",
            verification_profile="unwind-record-v1",
            context={
                "canonical_sha256": sha256_jcs(
                    without_signature(synthetic.cmpc.unwind_record)
                ),
                "public_key_b64url": cmpc_retailer_key,
            },
            sdk_rejected=0,
            sdk_total=28,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name="synthetic/cmpc_bilateral/primitives/closure_predicate.json",
            fixture_label="synthetic",
            object_label="cmpc-closure-predicate",
            object_name="cmpc_closure_predicate",
            input_data=synthetic.cmpc.closure_predicate,
            source_fixture=SYNTHETIC_SOURCE_CMPC,
            record_type="closure_predicate",
            verification_profile="closure-predicate-v1",
            context={
                "canonical_sha256": sha256_jcs(
                    without_signature(synthetic.cmpc.closure_predicate)
                ),
                "chain_session": synthetic.cmpc.chain_session,
                "digest_checks": [
                    {
                        "kind": "jcs-sha256-pointer",
                        "source": "context.chain_session",
                        "target": {"object": "input", "pointer": "/references/0/digest"},
                    }
                ],
                "public_key_b64url": cmpc_authority_key,
            },
            sdk_rejected=0,
            sdk_total=40,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name="synthetic/cmpc_bilateral/primitives/chain_session.json",
            fixture_label="synthetic",
            object_label="cmpc-chain-session",
            object_name="cmpc_chain_session",
            input_data=synthetic.cmpc.chain_session,
            source_fixture=SYNTHETIC_SOURCE_CMPC,
            record_type="chain_session",
            verification_profile="chain-session-v1",
            context={
                "canonical_sha256": sha256_jcs(synthetic.cmpc.chain_session),
            },
            sdk_rejected=0,
            sdk_total=25,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name="synthetic/longtail/agent_profile.json",
            fixture_label="synthetic",
            object_label="agent-profile",
            object_name="agent_profile",
            input_data=synthetic.longtail.agent_profile,
            source_fixture=SYNTHETIC_SOURCE_LONGTAIL,
            record_type="agent_profile",
            verification_profile="agent-profile-v1",
            context={
                "canonical_fields": list(AGENT_PROFILE_CANONICAL_FIELDS),
                "canonical_sha256": "sha256:"
                + hashlib.sha256(agent_profile_preimage).hexdigest(),
                "public_key_b64url": longtail_keys["agent_profile_signer"][
                    "public_key_b64url"
                ],
            },
            sdk_rejected=0,
            sdk_total=100,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name="synthetic/longtail/competence_proof.json",
            fixture_label="synthetic",
            object_label="competence-proof",
            object_name="competence_proof",
            input_data=synthetic.longtail.competence_proof,
            source_fixture=SYNTHETIC_SOURCE_LONGTAIL,
            record_type="competence_proof",
            verification_profile="competence-proof-v1",
            context={
                "canonical_sha256": "sha256:"
                + hashlib.sha256(competence_proof_preimage).hexdigest(),
                "public_key_b64url": longtail_keys["attestation_initiator"][
                    "public_key_b64url"
                ],
            },
            sdk_rejected=0,
            sdk_total=157,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name="synthetic/longtail/receipt_bundle.json",
            fixture_label="synthetic",
            object_label="receipt-bundle",
            object_name="receipt_bundle",
            input_data=synthetic.longtail.receipt_bundle,
            source_fixture=SYNTHETIC_SOURCE_LONGTAIL,
            record_type="receipt_bundle",
            verification_profile="receipt-bundle-v1",
            context={
                "canonical_sha256": "sha256:"
                + hashlib.sha256(receipt_bundle_preimage).hexdigest(),
                "public_key_b64url": longtail_keys["attestation_initiator"][
                    "public_key_b64url"
                ],
            },
            sdk_rejected=0,
            sdk_total=256,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
        MutationFixture(
            battery_name="synthetic/longtail/message_chain.json",
            fixture_label="synthetic",
            object_label="message-chain",
            object_name="message_chain",
            input_data=synthetic.longtail.message_chain,
            source_fixture=SYNTHETIC_SOURCE_LONGTAIL,
            record_type="message_chain",
            verification_profile="message-chain-v1",
            context={
                "expected_message_count": 3,
                "expected_message_hashes": message_hashes,
                "public_keys_b64url": {
                    longtail_agent_ids["message_chain_initiator"]: longtail_keys[
                        "message_chain_initiator"
                    ]["public_key_b64url"],
                    longtail_agent_ids["message_chain_responder"]: longtail_keys[
                        "message_chain_responder"
                    ]["public_key_b64url"],
                },
            },
            sdk_rejected=0,
            sdk_total=99,
            sdk_escapes=frozenset(),
            compare_typed_path=False,
        ),
    ]


def outcome_name(accepted: bool) -> ExpectedOutcome:
    return "accept" if accepted else "reject"


def mutation_canonical_preimage(profile: str, input_data: dict[str, Any]) -> bytes | None:
    if profile in {"decision-object-v1", "offer-binding-v1"}:
        return canonicalize_jcs(input_data)
    if profile in {"receipt-v1", "revocation-v1", "fulfillment-attestation-v1"}:
        return canonical_json(without_signature(input_data))
    if profile == "cascade-decision-v1":
        return canonicalize_cascade_decision_record(input_data)
    if profile == "attestation-countersign-v1":
        return attestation_countersign_payload(input_data)
    if profile == "predicate-v1":
        return canonical_json(without_signature(input_data))
    if profile in {"mandate-v1", "delegation-chain-v1"}:
        return canonicalize_mandate(input_data)
    if profile == "cosign-v1":
        return canonical_cosign_bytes(input_data)
    if profile in {
        "conditional-commitment-v1",
        "atomic-activation-proof-v1",
        "unwind-record-v1",
        "closure-predicate-v1",
    }:
        return canonical_json(without_signature(input_data))
    if profile == "chain-session-v1":
        return canonicalize_chain_session(input_data)
    if profile == "agent-profile-v1":
        canonical = agent_profile_canonical_from_raw(input_data)
        return canonical_json(canonical) if canonical is not None else None
    if profile == "receipt-bundle-v1":
        return canonical_json(
            without_keys(input_data, {"agent_signature", "concordia_receipt_bundle"})
        )
    if profile == "competence-proof-v1":
        return canonical_json(competence_proof_signable(input_data))
    if profile == "message-chain-v1":
        return canonical_json(input_data)
    return None


def accepted_mutation_note(
    fixture: MutationFixture,
    field_path: str,
    kind: MutationKind,
) -> str:
    if fixture.verification_profile == "attestation-v1":
        if field_path.startswith("countersignatures"):
            return ATTESTATION_COUNTERSIGNATURE_ESCAPE_NOTE
        return ATTESTATION_TOP_LEVEL_ESCAPE_NOTE
    if fixture.verification_profile == "attestation-countersign-v1":
        if field_path in {"parties.0.signature", "parties.1.signature"} and kind == "value":
            return COUNTERSIGN_STRIPPED_PARTY_SIGNATURE_NOTE
        if field_path == "countersignatures" and kind == "inject":
            return COUNTERSIGN_EXTRA_MAP_ENTRY_NOTE
    if fixture.verification_profile == "closure-predicate-v1":
        if field_path == "signature" and kind == "value":
            return CLOSURE_SIGNATURE_NOT_VERIFIED_NOTE
    if fixture.verification_profile == "agent-profile-v1":
        if field_path == "trust_signals" and kind == "inject":
            return AGENT_PROFILE_TRUST_SIGNAL_TOLERANCE_NOTE
        if field_path.startswith("trust_signals.reputation.") and kind == "inject":
            return AGENT_PROFILE_REPUTATION_TOLERANCE_NOTE
        if field_path == "verified" and kind in {"value", "drop"}:
            return AGENT_PROFILE_VERIFIED_TOLERANCE_NOTE
    if fixture.verification_profile == "competence-proof-v1":
        if field_path == "concordia_competence_proof" and kind in {"value", "drop"}:
            return COMPETENCE_PROOF_VERSION_TOLERANCE_NOTE
    if fixture.verification_profile == "receipt-bundle-v1":
        if field_path == "concordia_receipt_bundle" and kind == "value":
            return RECEIPT_BUNDLE_VERSION_TOLERANCE_NOTE
    raise GenerationError(
        f"{fixture.battery_name}: accepted mutation lacks structural justification: "
        f"{kind} {field_path}"
    )


def assert_mutation_sanity(
    vectors: list[Vector],
    battery_summaries: list[dict[str, Any]],
    divergences: list[MutationDivergence],
    raw_accepts: set[tuple[str, str, MutationKind]],
) -> None:
    reject_count = sum(1 for vector in vectors if vector.expected == "reject")
    accept_count = sum(1 for vector in vectors if vector.expected == "accept")
    if len(vectors) != EXPECTED_MUTATION_TOTAL:
        raise GenerationError(
            f"mutation vector count drifted: {len(vectors)} != {EXPECTED_MUTATION_TOTAL}"
        )
    if (reject_count, accept_count) != (
        EXPECTED_MUTATION_REJECTS,
        EXPECTED_MUTATION_ACCEPTS,
    ):
        raise GenerationError(
            "mutation outcome split drifted: "
            f"{reject_count} reject / {accept_count} accept"
        )
    if tuple(divergences) != EXPECTED_RAW_TYPED_DIVERGENCES:
        rendered = [
            (
                item.battery_name,
                item.field_path,
                item.kind,
                item.sdk_expected,
                item.raw_expected,
            )
            for item in divergences
        ]
        raise GenerationError(
            "raw outcomes diverged from SDK typed-path outcomes outside D1: "
            f"{rendered}"
        )
    if raw_accepts != EXPECTED_RAW_ACCEPTED_MUTATIONS:
        raise GenerationError(
            "raw tolerated-accept set drifted: "
            f"{sorted(raw_accepts)} != {sorted(EXPECTED_RAW_ACCEPTED_MUTATIONS)}"
        )
    summary_counts = {
        str(summary["battery_name"]): (
            int(summary["total"]),
            int(summary["reject"]),
            int(summary["accept"]),
        )
        for summary in battery_summaries
    }
    if summary_counts != EXPECTED_MUTATION_BATTERY_COUNTS:
        raise GenerationError(
            "mutation battery counts drifted: "
            f"{summary_counts} != {EXPECTED_MUTATION_BATTERY_COUNTS}"
        )


def message_chain_position_context(
    synthetic: SyntheticFixtures,
) -> dict[str, Any]:
    longtail_keys = synthetic.longtail.seed_manifest["seeds_PUBLIC_test_only_do_not_reuse"]
    longtail_agent_ids = synthetic.longtail.seed_manifest["agent_ids"]
    return {
        "public_keys_b64url": {
            longtail_agent_ids["message_chain_initiator"]: longtail_keys[
                "message_chain_initiator"
            ]["public_key_b64url"],
            longtail_agent_ids["message_chain_responder"]: longtail_keys[
                "message_chain_responder"
            ]["public_key_b64url"],
        }
    }


def receipt_set_binding_context(synthetic: SyntheticFixtures) -> dict[str, Any]:
    longtail_keys = synthetic.longtail.seed_manifest["seeds_PUBLIC_test_only_do_not_reuse"]
    longtail_agent_ids = synthetic.longtail.seed_manifest["agent_ids"]
    return {
        "public_keys_b64url": {
            longtail_agent_ids["receipt_set_binding_initiator"]: longtail_keys[
                "message_chain_initiator"
            ]["public_key_b64url"],
            longtail_agent_ids["receipt_set_binding_responder"]: longtail_keys[
                "message_chain_responder"
            ]["public_key_b64url"],
        }
    }


def resign_chain_message(message: dict[str, Any], key_pair: KeyPair) -> dict[str, Any]:
    resigned = copy.deepcopy(message)
    resigned["signature"] = sign_message(resigned, key_pair)
    return resigned


def chain_position_vector(
    *,
    vector_id: str,
    title: str,
    input_data: dict[str, Any],
    context: dict[str, Any],
    notes: str = "",
    expected_reason_class: ReasonClass | None = None,
) -> Vector:
    probe = Vector(
        vector_id=vector_id,
        title=title,
        source_fixture=f"{SYNTHETIC_SOURCE_LONGTAIL}/message_chain_position.json",
        record_type="message_chain",
        verification_profile="message-chain-v1",
        input_data=input_data,
        context=copy.deepcopy(context),
    )
    evaluation = evaluate_vector(probe)
    if not evaluation.accepted and evaluation.reason_class is None:
        raise GenerationError(f"{vector_id}: reject missing expected_reason_class")
    return Vector(
        vector_id=vector_id,
        title=title,
        source_fixture=probe.source_fixture,
        record_type=probe.record_type,
        verification_profile=probe.verification_profile,
        input_data=input_data,
        context=probe.context,
        expected=outcome_name(evaluation.accepted),
        expected_reason_class=(
            None
            if evaluation.accepted
            else expected_reason_class or evaluation.reason_class
        ),
        notes=notes,
        canonical_preimage=canonical_json(input_data),
    )


def build_chain_position_vectors(
    synthetic: SyntheticFixtures,
) -> tuple[list[Vector], dict[str, Any]]:
    base_messages = synthetic.longtail.message_chain_position["messages"]
    if len(base_messages) != 4:
        raise GenerationError("message chain position fixture must have four messages")
    msg1, _msg2, msg3, msg4 = [copy.deepcopy(message) for message in base_messages]
    context = message_chain_position_context(synthetic)
    initiator_key = key_pair_from_seed(SYNTHETIC_SEEDS["message_chain_initiator"])
    responder_key = key_pair_from_seed(SYNTHETIC_SEEDS["message_chain_responder"])

    deletion_splice = copy.deepcopy(msg3)
    deletion_splice["prev_hash"] = compute_hash(msg1)
    deletion_splice_input = {"messages": [msg1, deletion_splice, copy.deepcopy(msg4)]}

    resigned_splice = resign_chain_message(deletion_splice, initiator_key)
    relinked_tail = copy.deepcopy(msg4)
    relinked_tail["prev_hash"] = compute_hash(resigned_splice)
    relinked_tail = resign_chain_message(relinked_tail, responder_key)
    resigned_splice_input = {"messages": [msg1, resigned_splice, relinked_tail]}

    reordered_input = {"messages": [msg1, copy.deepcopy(msg3), copy.deepcopy(_msg2), msg4]}

    genesis_substitution = copy.deepcopy(msg1)
    genesis_substitution["prev_hash"] = "sha256:" + ("1" * 64)
    genesis_input = {
        "messages": [
            genesis_substitution,
            copy.deepcopy(_msg2),
            copy.deepcopy(msg3),
            copy.deepcopy(msg4),
        ]
    }

    vectors = [
        chain_position_vector(
            vector_id="mut-synthetic-message-chain-position-0001",
            title="message_chain_position: deletion splice without resigning",
            input_data=deletion_splice_input,
            context=context,
            expected_reason_class="binding",
        ),
        chain_position_vector(
            vector_id="mut-synthetic-message-chain-position-0002",
            title="message_chain_position: deletion splice with resigned downstream links",
            input_data=resigned_splice_input,
            context=context,
            notes=CHAIN_POSITION_RESIGNED_SPLICE_TOLERANCE_NOTE,
        ),
        chain_position_vector(
            vector_id="mut-synthetic-message-chain-position-0003",
            title="message_chain_position: reorder messages two and three without resigning",
            input_data=reordered_input,
            context=context,
            expected_reason_class="binding",
        ),
        chain_position_vector(
            vector_id="mut-synthetic-message-chain-position-0004",
            title="message_chain_position: genesis prev_hash substitution",
            input_data=genesis_input,
            context=context,
            expected_reason_class="binding",
        ),
    ]
    summary = {
        "battery_name": "synthetic/longtail/message_chain_position.json",
        "source_fixture": f"{SYNTHETIC_SOURCE_LONGTAIL}/message_chain_position.json",
        "object_name": "message_chain_position",
        "record_type": "message_chain",
        "verification_profile": "message-chain-v1",
        "total": len(vectors),
        "reject": sum(1 for vector in vectors if vector.expected == "reject"),
        "accept": sum(1 for vector in vectors if vector.expected == "accept"),
        "selection_note": "explicit chain-position attack vectors over a four-message synthetic chain",
    }
    return vectors, summary


def receipt_set_binding_vector(
    *,
    vector_id: str,
    title: str,
    input_data: dict[str, Any],
    context: dict[str, Any],
    expected_reason_class: ReasonClass | None = None,
    notes: str = "",
    discriminates: str | None = None,
) -> Vector:
    probe = Vector(
        vector_id=vector_id,
        title=title,
        source_fixture=f"{SYNTHETIC_SOURCE_LONGTAIL}/receipt_set_binding.json",
        record_type="message_chain",
        verification_profile="message-chain-v1",
        input_data=input_data,
        context=copy.deepcopy(context),
    )
    evaluation = evaluate_vector(probe)
    if not evaluation.accepted and evaluation.reason_class is None:
        raise GenerationError(f"{vector_id}: reject missing expected_reason_class")
    return Vector(
        vector_id=vector_id,
        title=title,
        source_fixture=probe.source_fixture,
        record_type=probe.record_type,
        verification_profile=probe.verification_profile,
        input_data=input_data,
        context=probe.context,
        expected=outcome_name(evaluation.accepted),
        expected_reason_class=(
            None
            if evaluation.accepted
            else expected_reason_class or evaluation.reason_class
        ),
        notes=notes,
        canonical_preimage=canonical_json(input_data),
        discriminates=discriminates,
    )


def receipt_set_binding_key_map() -> dict[str, KeyPair]:
    return receipt_set_binding_key_by_agent()


def receipt_with_resigned_snapshot(
    receipt: dict[str, Any],
    updates: dict[str, Any],
) -> dict[str, Any]:
    key_by_agent = receipt_set_binding_key_map()
    mutated = copy.deepcopy(receipt)
    mutated.update(updates)
    return resign_attestation(mutated, key_by_agent)


def receipt_set_binding_resigned_splice(
    messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if len(messages) != 5:
        raise GenerationError("receipt set-binding transcript must have five messages")
    key_by_agent = receipt_set_binding_key_map()
    msg1, msg2, _removed, msg4, msg5 = [copy.deepcopy(message) for message in messages]
    msg4["prev_hash"] = compute_hash(msg2)
    msg4 = resign_chain_message(msg4, key_by_agent[msg4["from"]["agent_id"]])
    msg5["prev_hash"] = compute_hash(msg4)
    msg5 = resign_chain_message(msg5, key_by_agent[msg5["from"]["agent_id"]])
    return [msg1, msg2, msg4, msg5]


def build_receipt_set_binding_mutation_vectors(
    synthetic: SyntheticFixtures,
) -> tuple[list[Vector], dict[str, Any]]:
    base_pair = synthetic.longtail.receipt_set_binding
    base_receipt = base_pair["receipt"]
    base_messages = base_pair["messages"]
    context = receipt_set_binding_context(synthetic)

    altered_chain_head = {
        "messages": copy.deepcopy(base_messages),
        "receipt": receipt_with_resigned_snapshot(
            base_receipt,
            {"chain_head": "sha256:" + ("d4" * 32)},
        ),
    }
    altered_message_count = {
        "messages": copy.deepcopy(base_messages),
        "receipt": receipt_with_resigned_snapshot(
            base_receipt,
            {"message_count": len(base_messages) + 1},
        ),
    }
    truncated_transcript = {
        "messages": copy.deepcopy(base_messages[:-1]),
        "receipt": copy.deepcopy(base_receipt),
    }
    resigned_splice = {
        "messages": receipt_set_binding_resigned_splice(base_messages),
        "receipt": copy.deepcopy(base_receipt),
    }

    vectors = [
        receipt_set_binding_vector(
            vector_id="mut-synthetic-receipt-set-binding-0001",
            title="receipt_set_binding: countersigned chain_head does not match transcript head",
            input_data=altered_chain_head,
            context=context,
            expected_reason_class="binding",
        ),
        receipt_set_binding_vector(
            vector_id="mut-synthetic-receipt-set-binding-0002",
            title="receipt_set_binding: countersigned message_count is off by one",
            input_data=altered_message_count,
            context=context,
            expected_reason_class="binding",
        ),
        receipt_set_binding_vector(
            vector_id="mut-synthetic-receipt-set-binding-0003",
            title="receipt_set_binding: truncated transcript presented with original receipt",
            input_data=truncated_transcript,
            context=context,
            expected_reason_class="binding",
        ),
        receipt_set_binding_vector(
            vector_id="mut-synthetic-receipt-set-binding-0004",
            title="receipt_set_binding: re-signed deletion splice presented with original receipt",
            input_data=resigned_splice,
            context=context,
            expected_reason_class="binding",
        ),
    ]
    summary = {
        "battery_name": "synthetic/longtail/receipt_set_binding.json",
        "source_fixture": f"{SYNTHETIC_SOURCE_LONGTAIL}/receipt_set_binding.json",
        "object_name": "receipt_set_binding",
        "record_type": "message_chain",
        "verification_profile": "message-chain-v1",
        "total": len(vectors),
        "reject": sum(1 for vector in vectors if vector.expected == "reject"),
        "accept": sum(1 for vector in vectors if vector.expected == "accept"),
        "selection_note": (
            "explicit receipt set-binding attack vectors over a five-message "
            "agreed transcript"
        ),
    }
    return vectors, summary


def build_mutation_battery(
    synthetic: SyntheticFixtures | None = None,
) -> tuple[list[Vector], list[dict[str, Any]]]:
    f1404 = fixture_1404()
    f1920 = fixture_1920()
    if synthetic is None:
        synthetic = build_synthetic_fixtures()

    vectors: list[Vector] = []
    battery_summaries: list[dict[str, Any]] = []
    divergences: list[MutationDivergence] = []
    raw_accepts: set[tuple[str, str, MutationKind]] = set()

    for fixture in build_mutation_fixtures(f1404, f1920, synthetic):
        baseline = Vector(
            vector_id=f"baseline-{fixture.fixture_label}-{fixture.object_label}",
            title=f"{fixture.object_name}: baseline",
            source_fixture=fixture.source_fixture,
            record_type=fixture.record_type,
            verification_profile=fixture.verification_profile,
            input_data=fixture.input_data,
            context=fixture.context,
        )
        if not verify_vector(baseline):
            raise GenerationError(f"{fixture.battery_name}: baseline raw verifier rejected")

        object_total = 0
        object_accept = 0
        object_reject = 0
        for field_path, kind, mutated in mutations(fixture.input_data):
            if mutated == fixture.input_data:
                continue
            object_total += 1
            vector_id = (
                f"mut-{fixture.fixture_label}-{fixture.object_label}-{object_total:04d}"
            )
            probe = Vector(
                vector_id=vector_id,
                title=f"{fixture.object_name}: {kind} {field_path}",
                source_fixture=fixture.source_fixture,
                record_type=fixture.record_type,
                verification_profile=fixture.verification_profile,
                input_data=mutated,
                context=copy.deepcopy(fixture.context),
            )
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                evaluation = evaluate_vector(probe)
            expected = outcome_name(evaluation.accepted)
            if fixture.compare_typed_path:
                sdk_expected = outcome_name((field_path, kind) in fixture.sdk_escapes)
                if sdk_expected != expected:
                    divergences.append(
                        MutationDivergence(
                            battery_name=fixture.battery_name,
                            field_path=field_path,
                            kind=kind,
                            sdk_expected=sdk_expected,
                            raw_expected=expected,
                        )
                    )
            if evaluation.accepted:
                object_accept += 1
                if fixture.compare_typed_path:
                    raw_accepts.add((fixture.battery_name, field_path, kind))
                notes = accepted_mutation_note(fixture, field_path, kind)
            else:
                object_reject += 1
                notes = ""
            if not evaluation.accepted and evaluation.reason_class is None:
                raise GenerationError(
                    f"{vector_id}: reject missing expected_reason_class"
                )

            vectors.append(
                Vector(
                    vector_id=vector_id,
                    title=probe.title,
                    source_fixture=fixture.source_fixture,
                    record_type=fixture.record_type,
                    verification_profile=fixture.verification_profile,
                    input_data=mutated,
                    context=probe.context,
                    expected=expected,
                    expected_reason_class=evaluation.reason_class,
                    notes=notes,
                    canonical_preimage=mutation_canonical_preimage(
                        fixture.verification_profile, mutated
                    ),
                )
            )

        if object_total != fixture.sdk_total:
            raise GenerationError(
                f"{fixture.battery_name}: mutation count drifted "
                f"({object_total} != {fixture.sdk_total})"
            )
        if fixture.compare_typed_path:
            sdk_rejected = fixture.sdk_total - len(fixture.sdk_escapes)
            if sdk_rejected != fixture.sdk_rejected:
                raise GenerationError(
                    f"{fixture.battery_name}: SDK expectation table is internally inconsistent"
                )
        if object_accept + object_reject != object_total:
            raise GenerationError(f"{fixture.battery_name}: mutation split drifted")
        summary: dict[str, Any] = {
            "battery_name": fixture.battery_name,
            "source_fixture": fixture.source_fixture,
            "object_name": fixture.object_name,
            "record_type": fixture.record_type,
            "verification_profile": fixture.verification_profile,
            "total": object_total,
            "reject": object_reject,
            "accept": object_accept,
        }
        if fixture.object_name == "predicate_vector_02":
            summary["selection_note"] = P2_A2_PREDICATE_MUTATION_REASON
        battery_summaries.append(summary)

    position_vectors, position_summary = build_chain_position_vectors(synthetic)
    vectors.extend(position_vectors)
    battery_summaries.append(position_summary)

    receipt_vectors, receipt_summary = build_receipt_set_binding_mutation_vectors(
        synthetic
    )
    vectors.extend(receipt_vectors)
    battery_summaries.append(receipt_summary)

    vectors = sorted(vectors, key=lambda vector: vector.vector_id)
    battery_summaries = sorted(
        battery_summaries, key=lambda summary: str(summary["battery_name"])
    )
    assert_mutation_sanity(vectors, battery_summaries, divergences, raw_accepts)
    return vectors, battery_summaries


def build_mutation_vectors() -> list[Vector]:
    vectors, _ = build_mutation_battery()
    return vectors


def build_canary_preimage_includes_signature(
    f1920: dict[str, dict[str, Any]],
) -> Vector:
    sample = f1920["sample"]
    fulfillment = copy.deepcopy(f1920["fulfillment_attestation"])
    private_key = private_key_from_seed(sample["seed_ed25519_ascii"])
    placeholder = b64url_encode(b"\x00" * 64)
    preimage = copy.deepcopy(fulfillment)
    preimage["signature"]["value"] = placeholder
    fulfillment["signature"]["value"] = sign_b64url(private_key, canonical_json(preimage))
    return Vector(
        vector_id="canary-preimage-includes-signature",
        title="FulfillmentAttestation signature commits to a placeholder signature field",
        source_fixture=INTEROP_1920.name,
        record_type="fulfillment_attestation",
        verification_profile="fulfillment-attestation-v1",
        input_data=fulfillment,
        context={
            "forbid_raw_deal_terms": True,
            "join_keys": sample["join_keys"],
            "public_key_b64url": sample["public_key_b64url"],
            "signature_preimage_value": placeholder,
        },
        expected="reject",
        expected_reason_class="signature",
        notes="canary: rejects unless the runner includes the signature placeholder in the preimage",
        canonical_preimage=canonical_json(without_signature(fulfillment)),
        discriminates="preimage-includes-signature",
    )


def build_canary_schema_skipped(f1404: dict[str, dict[str, Any]]) -> Vector:
    vector_meta = f1404["vector"]
    seeds = vector_meta["signing_seeds_PUBLIC_test_only_do_not_reuse"]
    private_key = private_key_from_seed(seeds["revocation_issuer_ed25519_seed_ascii"])
    cascade = copy.deepcopy(f1404["cascade_decision_deny"])
    cascade["__canary_extra__"] = "schema-skipped"
    preimage = canonicalize_cascade_decision_record(cascade)
    cascade["decision_id"] = hashlib.sha256(preimage).hexdigest()
    preimage = canonicalize_cascade_decision_record(cascade)
    cascade["signature"]["value"] = sign_b64url(private_key, preimage)
    return Vector(
        vector_id="canary-schema-skipped",
        title="CascadeDecisionRecord with an extra top-level key signed and re-identified",
        source_fixture=INTEROP_1404.name,
        record_type="cascade_decision_record",
        verification_profile="cascade-decision-v1",
        input_data=cascade,
        context={
            "expected_decision_id": f"sha256:{cascade['decision_id']}",
            "public_keys_b64url": {
                "issuer": vector_meta["public_keys_b64url"]["revocation_issuer"]
            },
        },
        expected="reject",
        expected_reason_class="schema",
        notes="canary: rejects only if the cascade schema is enforced",
        canonical_preimage=preimage,
        discriminates="schema-skipped",
    )


def build_canary_decision_id_not_recomputed(
    f1404: dict[str, dict[str, Any]],
) -> Vector:
    vector_meta = f1404["vector"]
    seeds = vector_meta["signing_seeds_PUBLIC_test_only_do_not_reuse"]
    private_key = private_key_from_seed(seeds["revocation_issuer_ed25519_seed_ascii"])
    cascade = copy.deepcopy(f1404["cascade_decision_deny"])
    cascade["policy_version"] = f"{cascade['policy_version']}-canary"
    stale_decision_id = f1404["cascade_decision_deny"]["decision_id"]
    cascade["decision_id"] = stale_decision_id
    signature_preimage = canonical_json(without_signature(cascade))
    cascade["signature"]["value"] = sign_b64url(private_key, signature_preimage)
    return Vector(
        vector_id="canary-decision-id-not-recomputed",
        title="CascadeDecisionRecord with stale decision_id and freshly signed tampered body",
        source_fixture=INTEROP_1404.name,
        record_type="cascade_decision_record",
        verification_profile="cascade-decision-v1",
        input_data=cascade,
        context={
            "expected_decision_id": f"sha256:{stale_decision_id}",
            "public_keys_b64url": {
                "issuer": vector_meta["public_keys_b64url"]["revocation_issuer"]
            },
        },
        expected="reject",
        expected_reason_class="digest",
        notes="canary: rejects only if decision_id is recomputed from the body",
        canonical_preimage=canonicalize_cascade_decision_record(cascade),
        discriminates="decision-id-not-recomputed",
    )


def build_canary_chain_splice(synthetic: SyntheticFixtures) -> Vector:
    msg1, _msg2, msg3, msg4 = [
        copy.deepcopy(message)
        for message in synthetic.longtail.message_chain_position["messages"]
    ]
    chain = {"messages": [msg1, msg3, msg4]}
    return Vector(
        vector_id="canary-chain-splice",
        title="MessageChain with a deleted predecessor and independently valid signatures",
        source_fixture=f"{SYNTHETIC_SOURCE_LONGTAIL}/message_chain_position.json",
        record_type="message_chain",
        verification_profile="message-chain-v1",
        input_data=chain,
        context=message_chain_position_context(synthetic),
        expected="reject",
        expected_reason_class="binding",
        notes="canary: rejects only if the message-chain linkage walk is enforced",
        canonical_preimage=canonical_json(chain),
        discriminates="skip-linkage-walk",
    )


def build_canary_receipt_set_unchecked(synthetic: SyntheticFixtures) -> Vector:
    base_pair = synthetic.longtail.receipt_set_binding
    canary_input = {
        "messages": receipt_set_binding_resigned_splice(base_pair["messages"]),
        "receipt": copy.deepcopy(base_pair["receipt"]),
    }
    return Vector(
        vector_id="canary-receipt-set-unchecked",
        title="Receipt set-binding skipped over a re-signed transcript splice",
        source_fixture=f"{SYNTHETIC_SOURCE_LONGTAIL}/receipt_set_binding.json",
        record_type="message_chain",
        verification_profile="message-chain-v1",
        input_data=canary_input,
        context=receipt_set_binding_context(synthetic),
        expected="reject",
        expected_reason_class="binding",
        notes=(
            "canary: rejects only if the runner compares the 0.3.0 receipt "
            "chain_head and message_count to the presented transcript"
        ),
        canonical_preimage=canonical_json(canary_input),
        discriminates="receipt-set-unchecked",
    )


def evaluate_canary_regression(vector: Vector) -> Evaluation:
    if vector.discriminates == "preimage-includes-signature":
        input_data = vector.input_data
        context = vector.context
        schema = load_json(SCHEMA_COPIES["fulfillment_attestation.schema.json"])
        if not schema_is_valid(schema, input_data):
            return Evaluation(False, "schema")
        if not has_fulfills_reference(input_data):
            return Evaluation(False, "binding")
        signature = input_data.get("signature")
        if not isinstance(signature, dict) or signature.get("alg") != "Ed25519":
            return Evaluation(False, "signature")
        public_key = Ed25519PublicKey.from_public_bytes(
            b64url_decode(context["public_key_b64url"])
        )
        placeholder_preimage = copy.deepcopy(input_data)
        placeholder_preimage["signature"]["value"] = context["signature_preimage_value"]
        try:
            public_key.verify(
                b64url_decode(str(signature.get("value", ""))),
                canonical_json(placeholder_preimage),
            )
        except Exception:
            return Evaluation(False, "signature")
        join_keys = context.get("join_keys", {})
        if "charge_ref" in join_keys and input_data.get("charge_ref") != join_keys["charge_ref"]:
            return Evaluation(False, "binding")
        if "action_ref" in join_keys and input_data.get("action_ref") != join_keys["action_ref"]:
            return Evaluation(False, "binding")
        if context.get("forbid_raw_deal_terms") and contains_raw_term(input_data):
            return Evaluation(False, "binding")
        return Evaluation(True)

    if vector.discriminates == "schema-skipped":
        input_data = vector.input_data
        context = vector.context
        cascade_preimage_bytes = canonicalize_cascade_decision_record(input_data)
        claimed_id = input_data.get("decision_id")
        if not isinstance(claimed_id, str):
            return Evaluation(False, "digest")
        if hashlib.sha256(cascade_preimage_bytes).hexdigest() != claimed_id:
            return Evaluation(False, "digest")
        if context.get("expected_decision_id") != f"sha256:{claimed_id}":
            return Evaluation(False, "digest")
        signature = input_data.get("signature")
        if not isinstance(signature, dict) or signature.get("alg") != "EdDSA":
            return Evaluation(False, "signature")
        public_key = Ed25519PublicKey.from_public_bytes(
            b64url_decode(context["public_keys_b64url"]["issuer"])
        )
        try:
            public_key.verify(
                b64url_decode(str(signature.get("value", ""))),
                cascade_preimage_bytes,
            )
        except Exception:
            return Evaluation(False, "signature")
        return Evaluation(True)

    if vector.discriminates == "decision-id-not-recomputed":
        input_data = vector.input_data
        context = vector.context
        try:
            validate_cascade_decision_record(input_data)
        except Exception:
            return Evaluation(False, "schema")
        claimed_id = input_data.get("decision_id")
        if not isinstance(claimed_id, str):
            return Evaluation(False, "digest")
        if context.get("expected_decision_id") != f"sha256:{claimed_id}":
            return Evaluation(False, "digest")
        cascade_preimage_bytes = canonical_json(without_signature(input_data))
        signature = input_data.get("signature")
        if not isinstance(signature, dict) or signature.get("alg") != "EdDSA":
            return Evaluation(False, "signature")
        public_key = Ed25519PublicKey.from_public_bytes(
            b64url_decode(context["public_keys_b64url"]["issuer"])
        )
        try:
            public_key.verify(
                b64url_decode(str(signature.get("value", ""))),
                cascade_preimage_bytes,
            )
        except Exception:
            return Evaluation(False, "signature")
        return Evaluation(True)

    if vector.discriminates == "skip-linkage-walk":
        messages = message_chain_messages(vector.input_data)
        if messages is None:
            return Evaluation(False, "schema")
        public_keys = vector.context.get("public_keys_b64url")
        if not isinstance(public_keys, dict):
            return Evaluation(False, "signature")
        for message in messages:
            sender = message.get("from")
            if not isinstance(sender, dict):
                return Evaluation(False, "schema")
            agent_id = sender.get("agent_id")
            signature = message.get("signature")
            if not isinstance(agent_id, str) or not isinstance(signature, str):
                return Evaluation(False, "signature")
            public_key_b64 = public_keys.get(agent_id)
            if not isinstance(public_key_b64, str):
                return Evaluation(False, "signature")
            if not verify_ed25519_signature(
                public_key_b64,
                signature,
                canonical_json(without_signature(message)),
            ):
                return Evaluation(False, "signature")
        return Evaluation(True)

    if vector.discriminates == "receipt-set-unchecked":
        return evaluate_message_chain_profile(vector, skip_receipt_set_binding=True)

    raise GenerationError(f"{vector.vector_id}: missing canary regression")


def assert_canary_sanity(vectors: list[Vector]) -> None:
    if len(vectors) != EXPECTED_CANARY_TOTAL:
        raise GenerationError(
            f"canary vector count drifted: {len(vectors)} != {EXPECTED_CANARY_TOTAL}"
        )
    discriminators = {
        vector.discriminates for vector in vectors if vector.discriminates is not None
    }
    if discriminators != {
        "skip-linkage-walk",
        "receipt-set-unchecked",
        "preimage-includes-signature",
        "schema-skipped",
        "decision-id-not-recomputed",
    }:
        raise GenerationError(f"canary discriminator set drifted: {sorted(discriminators)}")
    for vector in vectors:
        if vector.expected != "reject":
            raise GenerationError(f"{vector.vector_id}: canary must expect reject")
        raw = evaluate_vector(vector)
        if raw.accepted:
            raise GenerationError(f"{vector.vector_id}: raw verifier accepted canary")
        if raw.reason_class != vector.expected_reason_class:
            raise GenerationError(
                f"{vector.vector_id}: expected reason {vector.expected_reason_class}, "
                f"got {raw.reason_class}"
            )
        regressed = evaluate_canary_regression(vector)
        if not regressed.accepted:
            raise GenerationError(
                f"{vector.vector_id}: regressed verifier did not false-accept "
                f"({regressed.reason_class})"
            )


def build_canary_vectors(synthetic: SyntheticFixtures | None = None) -> list[Vector]:
    f1404 = fixture_1404()
    f1920 = fixture_1920()
    if synthetic is None:
        synthetic = build_synthetic_fixtures()
    vectors = sorted(
        [
            build_canary_chain_splice(synthetic),
            build_canary_receipt_set_unchecked(synthetic),
            build_canary_preimage_includes_signature(f1920),
            build_canary_schema_skipped(f1404),
            build_canary_decision_id_not_recomputed(f1404),
        ],
        key=lambda vector: vector.vector_id,
    )
    assert_canary_sanity(vectors)
    return vectors


def fixed_iso_now() -> str:
    return FIXED_NOW.strftime("%Y-%m-%dT%H:%M:%SZ")


def seed_manifest_for(roles: Mapping[str, KeyPair]) -> dict[str, Any]:
    return {
        "warning": "PUBLIC deterministic conformance test seeds; do not reuse",
        "seeds_PUBLIC_test_only_do_not_reuse": {
            role: {
                "seed_ed25519_ascii": SYNTHETIC_SEEDS[role],
                "public_key_b64url": key_pair.public_key_b64(),
            }
            for role, key_pair in sorted(roles.items())
        },
    }


def build_synthetic_attestation() -> tuple[dict[str, Any], dict[str, Any]]:
    keys = {
        "attestation_initiator": key_pair_from_seed(
            SYNTHETIC_SEEDS["attestation_initiator"]
        ),
        "attestation_responder": key_pair_from_seed(
            SYNTHETIC_SEEDS["attestation_responder"]
        ),
    }
    agent_a = "did:concordia:agent:synthetic-initiator"
    agent_b = "did:concordia:agent:synthetic-responder"
    key_by_agent = {
        agent_a: keys["attestation_initiator"],
        agent_b: keys["attestation_responder"],
    }
    parties: list[dict[str, Any]] = [
        {
            "agent_id": agent_a,
            "role": "initiator",
            "behavior": {
                "offers_made": 3,
                "concessions": 1,
                "concession_magnitude": 0.25,
                "signals_shared": 1,
                "constraints_declared": 1,
                "constraints_violated": 0,
                "reasoning_provided": True,
                "withdrawal": False,
                "response_time_avg_seconds": 4.5,
            },
        },
        {
            "agent_id": agent_b,
            "role": "responder",
            "behavior": {
                "offers_made": 2,
                "concessions": 2,
                "concession_magnitude": 0.4,
                "signals_shared": 0,
                "constraints_declared": 1,
                "constraints_violated": 0,
                "reasoning_provided": True,
                "withdrawal": False,
                "response_time_avg_seconds": 6.0,
            },
        },
    ]
    for party in parties:
        party["signature"] = sign_message(party, key_by_agent[party["agent_id"]])

    attestation: dict[str, Any] = {
        "concordia_attestation": "0.3.0",
        "attestation_id": "att_conformance_p2a1_0001",
        "session_id": "sess_conformance_p2a1_0001",
        "timestamp": fixed_iso_now(),
        "outcome": {
            "status": "agreed",
            "rounds": 4,
            "duration_seconds": 312,
            "terms_count": 3,
            "resolution_mechanism": "direct",
        },
        "parties": parties,
        "meta": {
            "category": "software.tools",
            "value_range": "1000-5000_USD",
            "extensions_used": [],
            "mediator_invoked": False,
        },
        "transcript_hash": "sha256:" + ("a1" * 32),
        "chain_head": "sha256:" + ("b2" * 32),
        "message_count": 6,
        "fulfillment": None,
        "references": [
            {
                "type": "receipt",
                "id": "urn:concordia:receipt:synthetic-0001",
                "relationship": "references",
                "signed_at": fixed_iso_now(),
            }
        ],
        "summary": (
            "Agreement completed with four rounds, two active parties, "
            "and no mediation."
        ),
    }
    attestation["countersignatures"] = {
        agent_id: countersign_attestation(attestation, key_by_agent[agent_id])
        for agent_id in sorted(key_by_agent)
    }

    public_keys = {
        agent_id: key_pair.public_key_b64()
        for agent_id, key_pair in sorted(key_by_agent.items())
    }
    result = verify_attestation(
        attestation,
        {
            agent_id: key_pair.public_key
            for agent_id, key_pair in key_by_agent.items()
        },
    )
    if not result.valid:
        raise GenerationError(f"synthetic attestation did not verify: {result.errors}")
    for agent_id, signature in attestation["countersignatures"].items():
        if not verify_attestation_countersignature(
            attestation,
            signature,
            key_by_agent[agent_id].public_key,
        ):
            raise GenerationError(f"synthetic countersignature failed: {agent_id}")

    manifest = seed_manifest_for(keys)
    manifest["agent_public_keys_b64url"] = public_keys
    return attestation, manifest


def predicate_fixture_dirs() -> list[Path]:
    fixture_root = REPO_ROOT / "tests" / "fixtures" / "predicate_canonical"
    return [
        path
        for path in sorted(fixture_root.glob("vector_*"))
        if path.name not in {"vector_12", "vector_13_deterministic_gate_failure"}
    ]


def build_synthetic_predicates() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    key_pair = key_pair_from_seed(SYNTHETIC_SEEDS["predicate_issuer"])
    predicates: dict[str, dict[str, Any]] = {}
    for fixture_dir in predicate_fixture_dirs():
        raw = (fixture_dir / "expected_canonical.txt").read_text(
            encoding="utf-8"
        ).rstrip("\n")
        predicate = json.loads(raw)
        signed = sign_predicate(predicate, key_pair).to_dict()
        result = verify_predicate(signed, now=FIXED_NOW)
        if not result.valid:
            raise GenerationError(
                f"{fixture_dir.name}: synthetic predicate did not verify: "
                f"{result.failure_reason}"
            )
        predicates[fixture_dir.name] = signed
    return predicates, seed_manifest_for({"predicate_issuer": key_pair})


def simple_mandate_constraints() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "max_spend": {"type": "number", "maximum": 1000},
            "category": {"type": "string", "enum": ["software", "books"]},
        },
        "required": ["max_spend", "category"],
        "additionalProperties": False,
    }


def build_synthetic_mandates() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    issuer_key = key_pair_from_seed(SYNTHETIC_SEEDS["mandate_issuer"])
    delegate_key = key_pair_from_seed(SYNTHETIC_SEEDS["mandate_delegate"])
    issuer = did_key_for(issuer_key)
    delegate = did_key_for(delegate_key)
    subject = "did:web:agent.example#synthetic-subject"
    validity = ValidityWindow(
        mode=TemporalMode.WINDOWED,
        not_before="2026-05-01T00:00:00Z",
        not_after="2026-06-01T00:00:00Z",
    )
    direct = Mandate(
        mandate_id="urn:concordia:mandate:synthetic-direct-0001",
        issuer=issuer,
        subject=subject,
        issued_at=fixed_iso_now(),
        validity=validity,
        constraints=simple_mandate_constraints(),
        metadata={"fixture": "conformance-p2a1-direct"},
        algorithm="EdDSA",
    )
    signed_direct = sign_mandate(direct, issuer_key).to_dict()

    link_1 = sign_delegation(
        DelegationLink(
            delegator=issuer,
            delegate=delegate,
            delegated_at=fixed_iso_now(),
            scope_restriction={"max_spend": 1000},
            algorithm="EdDSA",
        ),
        issuer_key,
    )
    link_2 = sign_delegation(
        DelegationLink(
            delegator=delegate,
            delegate=subject,
            delegated_at=fixed_iso_now(),
            scope_restriction={"max_spend": 750},
            algorithm="EdDSA",
        ),
        delegate_key,
    )
    delegated = Mandate(
        mandate_id="urn:concordia:mandate:synthetic-delegated-0001",
        issuer=issuer,
        subject=subject,
        issued_at=fixed_iso_now(),
        validity=validity,
        constraints=simple_mandate_constraints(),
        delegation_chain=[link_1, link_2],
        metadata={"fixture": "conformance-p2a1-delegated"},
        algorithm="EdDSA",
    )
    signed_delegated = sign_mandate(delegated, issuer_key).to_dict()

    action = {"max_spend": 500, "category": "software"}
    direct_result = verify_mandate(
        signed_direct,
        issuer_key.public_key,
        now=FIXED_NOW,
        action=action,
        check_revocation_status=False,
    )
    if not direct_result.valid:
        raise GenerationError(f"synthetic mandate did not verify: {direct_result.errors}")
    delegated_result = verify_mandate(
        signed_delegated,
        issuer_key.public_key,
        now=FIXED_NOW,
        action=action,
        delegation_public_keys={
            issuer: issuer_key.public_key,
            delegate: delegate_key.public_key,
        },
        check_revocation_status=False,
    )
    if not delegated_result.valid:
        raise GenerationError(
            f"synthetic delegated mandate did not verify: {delegated_result.errors}"
        )

    manifest = seed_manifest_for(
        {
            "mandate_issuer": issuer_key,
            "mandate_delegate": delegate_key,
        }
    )
    manifest["agent_ids"] = {
        "issuer": issuer,
        "delegate": delegate,
        "subject": subject,
    }
    return signed_direct, signed_delegated, manifest


def build_synthetic_cosigned_receipt() -> tuple[dict[str, Any], dict[str, Any]]:
    publisher = key_pair_from_seed(SYNTHETIC_SEEDS["cosign_publisher"])
    counterparty = key_pair_from_seed(SYNTHETIC_SEEDS["cosign_counterparty"])
    publisher_did = did_key_for(publisher)
    counterparty_did = did_key_for(counterparty)
    receipt = build_cosigned_receipt(
        {
            "session_id": "concordia:session:conformance-cosign-0001",
            "counterparty_did": counterparty_did,
            "outcome": "agreed",
            "rounds": 4,
            "duration_seconds": 312,
            "terms_count": 3,
            "concessions_made": 2,
            "fulfillment_status": "fulfilled",
            "negotiation_competence": 90,
        },
        publisher_did,
        counterparty_signer=keypair_signer(counterparty),
    )
    preimage = canonical_cosign_bytes(receipt)
    counterparty_signature = receipt["parties"][1]["signature"]
    if not verify_ed25519_signature(
        counterparty.public_key_b64(),
        counterparty_signature,
        preimage,
    ):
        raise GenerationError("synthetic cosignature did not verify")
    manifest = seed_manifest_for(
        {
            "cosign_publisher": publisher,
            "cosign_counterparty": counterparty,
        }
    )
    manifest["dids"] = {
        "publisher": publisher_did,
        "counterparty": counterparty_did,
    }
    return receipt, manifest


def load_cmpc_primitive(name: str) -> dict[str, Any]:
    return load_json(CMPC_PRIMITIVES / f"{name}.json")


def load_cmpc_transitions() -> dict[str, dict[str, Any]]:
    return {
        path.stem: load_json(path)
        for path in sorted(CMPC_STATE_MACHINE.glob("*.json"))
    }


def normalize_transition_fixture(fixture: dict[str, Any]) -> dict[str, Any]:
    initial = {
        "chain_session_id": "urn:concordia:chain-session:transition-vector",
        "participants": ["did:web:r.test", "did:web:w.test"],
        "closure_predicate_ref": "urn:concordia:predicate:transition-vector",
        "state": "PROPOSED",
        "created_at": "2026-05-18T10:00:00+00:00",
        "activation_deadline": "2026-05-18T13:00:00+00:00",
        "activated_at": None,
        "dissolved_at": None,
        "commitments": [],
        "unwind_record_id": None,
        "activation_proof_id": None,
    }
    initial.update(fixture["initial_session"])
    return {
        "initial_session": initial,
        "attempt_transition": fixture["attempt_transition"],
        "transition_now": fixture["transition_now"],
        "expected": fixture["expected"],
    }


def build_synthetic_cmpc_fixtures() -> SyntheticCmpcFixtures:
    retailer_key = key_pair_from_seed(SYNTHETIC_SEEDS["cmpc_retailer"])
    wholesaler_key = key_pair_from_seed(SYNTHETIC_SEEDS["cmpc_wholesaler"])
    authority_key = key_pair_from_seed(SYNTHETIC_SEEDS["cmpc_authority"])

    chain_session = load_cmpc_primitive("chain_session")
    validate_chain_session(chain_session)

    raw_commitment = load_cmpc_primitive("conditional_commitment")
    commitment = ConditionalCommitment.from_dict({**raw_commitment, "signature": ""})
    signed_commitment_obj = sign_conditional_commitment(commitment, retailer_key)
    if not verify_conditional_commitment(signed_commitment_obj, retailer_key.public_key):
        raise GenerationError("synthetic CMPC conditional commitment did not verify")
    signed_commitment = signed_commitment_obj.to_dict()

    raw_proof = load_cmpc_primitive("atomic_activation_proof")
    proof = AtomicActivationProof.from_dict({**raw_proof, "signature": ""})
    signed_proof_obj = sign_atomic_activation_proof(proof, wholesaler_key)
    if not verify_atomic_activation_proof(signed_proof_obj, wholesaler_key.public_key):
        raise GenerationError("synthetic CMPC activation proof did not verify")
    signed_proof = signed_proof_obj.to_dict()

    raw_unwind = load_cmpc_primitive("unwind_record")
    unwind = UnwindRecord.from_dict({**raw_unwind, "signature": ""})
    signed_unwind_obj = sign_unwind_record(unwind, retailer_key)
    if not verify_unwind_record(signed_unwind_obj, retailer_key.public_key):
        raise GenerationError("synthetic CMPC unwind record did not verify")
    signed_unwind = signed_unwind_obj.to_dict()

    closure = load_cmpc_primitive("closure_predicate")
    closure["references"][0]["digest"] = sha256_jcs(chain_session)
    closure["signature"] = sign_b64url(
        authority_key.private_key,
        canonicalize_closure_predicate(closure),
    )
    validate_closure_predicate(closure)
    ClosurePredicate.from_dict(closure)

    transition_vectors = {
        name: normalize_transition_fixture(fixture)
        for name, fixture in load_cmpc_transitions().items()
    }
    for name, vector_input in transition_vectors.items():
        if not schema_is_valid(CHAIN_SESSION_SCHEMA, vector_input["initial_session"]):
            raise GenerationError(f"{name}: normalized transition fixture is invalid")

    manifest = seed_manifest_for(
        {
            "cmpc_retailer": retailer_key,
            "cmpc_wholesaler": wholesaler_key,
            "cmpc_authority": authority_key,
        }
    )
    manifest["dids"] = {
        "retailer": raw_commitment["committer_did"],
        "wholesaler": raw_proof["issuer_did"],
        "authority": closure["authority"],
    }
    manifest["closure_signature_profile"] = (
        "closure-predicate-v1 does not verify /signature; the deterministic "
        "fixture value is present only because the schema requires a non-empty field"
    )

    return SyntheticCmpcFixtures(
        conditional_commitment=signed_commitment,
        atomic_activation_proof=signed_proof,
        unwind_record=signed_unwind,
        closure_predicate=closure,
        chain_session=chain_session,
        transition_vectors=transition_vectors,
        seed_manifest=manifest,
    )


def resign_attestation(
    attestation: dict[str, Any],
    key_by_agent: Mapping[str, KeyPair],
) -> dict[str, Any]:
    signed = copy.deepcopy(attestation)
    signed.pop("countersignatures", None)
    for party in signed.get("parties", []):
        if not isinstance(party, dict):
            raise GenerationError("attestation party is not an object")
        agent_id = party.get("agent_id")
        if not isinstance(agent_id, str) or agent_id not in key_by_agent:
            raise GenerationError("attestation party has no deterministic key")
        party.pop("signature", None)
        party["signature"] = sign_message(party, key_by_agent[agent_id])
    signed["countersignatures"] = {
        agent_id: countersign_attestation(signed, key_by_agent[agent_id])
        for agent_id in sorted(key_by_agent)
    }
    return signed


def build_agent_profile_fixture(profile_key: KeyPair) -> dict[str, Any]:
    profile = AgentCapabilityProfile(
        agent_id="did:concordia:agent:profile-longtail",
        name="Conformance Profile Agent",
        description="Deterministic agent profile fixture for conformance.",
        capabilities=Capabilities(
            categories=["software.tools", "data.analysis"],
            offer_types=["basic", "conditional"],
            resolution_methods=["split_difference", "tradeoff_optimization"],
            max_concurrent_sessions=4,
            languages=["en", "es"],
            currencies=["USD", "EUR"],
        ),
        negotiation_profile=NegotiationProfile(
            style="collaborative",
            avg_rounds_to_agreement=3.5,
            agreement_rate=0.75,
            avg_session_duration_seconds=180.0,
            concession_pattern="graduated",
        ),
        trust_signals=TrustSignals(
            verascore_did="did:web:reputation.example:agent-longtail",
            verascore_tier="verified-sovereign",
            verascore_composite=91,
            sovereignty=Sovereignty(L1="Full", L2="Full", L3="Full", L4="Full"),
            concordia_sessions_completed=8,
            attestation_count=2,
            concordia_preferred=True,
            reputation=[
                ReputationAssertion(
                    provider="reputation.example",
                    subject_did="did:web:reputation.example:agent-longtail",
                    tier="verified-sovereign",
                    composite=91,
                )
            ],
        ),
        endpoints=Endpoints(
            negotiate="https://agent.example/.well-known/concordia",
            a2a_card="https://agent.example/.well-known/agent-card.json",
            mcp_manifest="https://agent.example/.well-known/mcp.json",
        ),
        location=Location(regions=["us-west1", "eu-west1"], jurisdictions=["US-CA", "EU"]),
        ttl=7200,
        updated_at=fixed_iso_now(),
    )
    profile.signature = sign_message(profile.to_canonical_dict(), profile_key)
    profile.verified = True
    if not profile.verify_signature(profile_key.public_key):
        raise GenerationError("synthetic agent profile did not verify")
    return profile.to_dict()


def build_receipt_bundle_fixture(
    agent_id: str,
    attestations: list[dict[str, Any]],
    key_pair: KeyPair,
) -> dict[str, Any]:
    signable = {
        "bundle_id": "bundle_aaaaaaaaaaaa",
        "agent_id": agent_id,
        "created_at": fixed_iso_now(),
        "attestations": attestations,
        "summary": _compute_summary(agent_id, attestations).to_dict(),
    }
    bundle = {
        "concordia_receipt_bundle": "0.1.0",
        **signable,
        "agent_signature": sign_message(signable, key_pair),
    }
    baseline = Vector(
        vector_id="baseline-synthetic-receipt-bundle",
        title="receipt bundle baseline",
        source_fixture=SYNTHETIC_SOURCE_LONGTAIL,
        record_type="receipt_bundle",
        verification_profile="receipt-bundle-v1",
        input_data=bundle,
        context={
            "canonical_sha256": "sha256:"
            + hashlib.sha256(canonical_json(signable)).hexdigest(),
            "public_key_b64url": key_pair.public_key_b64(),
        },
    )
    if not evaluate_receipt_bundle_profile(baseline).accepted:
        raise GenerationError("synthetic receipt bundle did not verify")
    return bundle


def build_competence_proof_fixture(
    agent_id: str,
    attestations: list[dict[str, Any]],
    key_pair: KeyPair,
) -> dict[str, Any]:
    attestation_ids = [att["attestation_id"] for att in attestations]
    root, layers = build_merkle_tree(attestation_ids)
    reveal_id = sorted(attestation_ids)[0]
    revealed = [att for att in attestations if att["attestation_id"] == reveal_id]
    signable = {
        "proof_id": "proof_aaaaaaaaaaaa",
        "agent_id": agent_id,
        "created_at": fixed_iso_now(),
        "claims": _compute_summary(agent_id, attestations).to_dict(),
        "attestation_merkle_root": root,
        "attestation_count": len(attestations),
        "merkle_proofs": [
            generate_merkle_proof(reveal_id, sorted(attestation_ids), layers)
        ],
        "revealed_attestations": revealed,
    }
    proof = {
        "concordia_competence_proof": "0.1.0",
        **signable,
        "agent_signature": sign_message(signable, key_pair),
    }
    baseline = Vector(
        vector_id="baseline-synthetic-competence-proof",
        title="competence proof baseline",
        source_fixture=SYNTHETIC_SOURCE_LONGTAIL,
        record_type="competence_proof",
        verification_profile="competence-proof-v1",
        input_data=proof,
        context={
            "canonical_sha256": "sha256:"
            + hashlib.sha256(canonical_json(signable)).hexdigest(),
            "public_key_b64url": key_pair.public_key_b64(),
        },
    )
    if not evaluate_competence_proof_profile(baseline).accepted:
        raise GenerationError("synthetic competence proof did not verify")
    return proof


def build_message(
    *,
    message_id: str,
    message_type: str,
    session_id: str,
    sender: dict[str, Any],
    body: dict[str, Any],
    key_pair: KeyPair,
    prev_hash: str,
    timestamp: str,
    recipients: list[dict[str, Any]] | None = None,
    in_reply_to: str | None = None,
    reasoning: str | None = None,
) -> dict[str, Any]:
    message: dict[str, Any] = {
        "concordia": "0.1.0",
        "type": message_type,
        "id": message_id,
        "session_id": session_id,
        "timestamp": timestamp,
        "from": sender,
        "prev_hash": prev_hash,
        "body": body,
    }
    if recipients is not None:
        message["to"] = recipients
    if in_reply_to is not None:
        message["in_reply_to"] = in_reply_to
    if reasoning is not None:
        message["reasoning"] = reasoning
    message["signature"] = sign_message(message, key_pair)
    return message


def build_message_chain_fixture(
    initiator_key: KeyPair,
    responder_key: KeyPair,
) -> dict[str, Any]:
    session_id = "sess_conformance_message_chain_0001"
    initiator = {"agent_id": "did:concordia:agent:chain-initiator"}
    responder = {"agent_id": "did:concordia:agent:chain-responder"}
    open_msg = build_message(
        message_id="msg_conformance_chain_0001",
        message_type="negotiate.open",
        session_id=session_id,
        sender=initiator,
        recipients=[responder],
        body={"terms": {"deliverable": "analysis", "rounds": 3}},
        key_pair=initiator_key,
        prev_hash=GENESIS_HASH,
        timestamp="2026-05-10T14:25:00Z",
        reasoning="Open deterministic conformance session.",
    )
    accept_session = build_message(
        message_id="msg_conformance_chain_0002",
        message_type="negotiate.accept_session",
        session_id=session_id,
        sender=responder,
        recipients=[initiator],
        body={"accepted": True},
        key_pair=responder_key,
        prev_hash=compute_hash(open_msg),
        timestamp="2026-05-10T14:26:00Z",
        in_reply_to=open_msg["id"],
    )
    offer = build_message(
        message_id="msg_conformance_chain_0003",
        message_type="negotiate.offer",
        session_id=session_id,
        sender=initiator,
        recipients=[responder],
        body={"offer": {"quality": "high", "delivery_days": 2}},
        key_pair=initiator_key,
        prev_hash=compute_hash(accept_session),
        timestamp="2026-05-10T14:27:00Z",
        in_reply_to=accept_session["id"],
        reasoning="First signed offer after session acceptance.",
    )
    chain = {"messages": [open_msg, accept_session, offer]}
    baseline = Vector(
        vector_id="baseline-synthetic-message-chain",
        title="message chain baseline",
        source_fixture=SYNTHETIC_SOURCE_LONGTAIL,
        record_type="message_chain",
        verification_profile="message-chain-v1",
        input_data=chain,
        context={
            "expected_message_count": 3,
            "expected_message_hashes": [compute_hash(message) for message in chain["messages"]],
            "public_keys_b64url": {
                initiator["agent_id"]: initiator_key.public_key_b64(),
                responder["agent_id"]: responder_key.public_key_b64(),
            },
        },
    )
    if not evaluate_message_chain_profile(baseline).accepted:
        raise GenerationError("synthetic message chain did not verify")
    return chain


def build_message_chain_position_fixture(
    initiator_key: KeyPair,
    responder_key: KeyPair,
) -> dict[str, Any]:
    session_id = "sess_conformance_chain_position_0001"
    initiator = {"agent_id": "did:concordia:agent:chain-initiator"}
    responder = {"agent_id": "did:concordia:agent:chain-responder"}
    open_msg = build_message(
        message_id="msg_conformance_chain_position_0001",
        message_type="negotiate.open",
        session_id=session_id,
        sender=initiator,
        recipients=[responder],
        body={"terms": {"deliverable": "chain-position-audit", "rounds": 4}},
        key_pair=initiator_key,
        prev_hash=GENESIS_HASH,
        timestamp="2026-05-10T15:00:00Z",
        reasoning="Open deterministic chain-position session.",
    )
    accept_session = build_message(
        message_id="msg_conformance_chain_position_0002",
        message_type="negotiate.accept_session",
        session_id=session_id,
        sender=responder,
        recipients=[initiator],
        body={"accepted": True},
        key_pair=responder_key,
        prev_hash=compute_hash(open_msg),
        timestamp="2026-05-10T15:01:00Z",
        in_reply_to=open_msg["id"],
    )
    offer = build_message(
        message_id="msg_conformance_chain_position_0003",
        message_type="negotiate.offer",
        session_id=session_id,
        sender=initiator,
        recipients=[responder],
        body={"offer": {"quality": "high", "delivery_days": 2}},
        key_pair=initiator_key,
        prev_hash=compute_hash(accept_session),
        timestamp="2026-05-10T15:02:00Z",
        in_reply_to=accept_session["id"],
        reasoning="Offer after session acceptance.",
    )
    counter_offer = build_message(
        message_id="msg_conformance_chain_position_0004",
        message_type="negotiate.counter_offer",
        session_id=session_id,
        sender=responder,
        recipients=[initiator],
        body={"offer": {"quality": "standard", "delivery_days": 1}},
        key_pair=responder_key,
        prev_hash=compute_hash(offer),
        timestamp="2026-05-10T15:03:00Z",
        in_reply_to=offer["id"],
        reasoning="Counter-offer preserves the fourth chain position.",
    )
    chain = {"messages": [open_msg, accept_session, offer, counter_offer]}
    baseline = Vector(
        vector_id="baseline-synthetic-message-chain-position",
        title="message chain position baseline",
        source_fixture=SYNTHETIC_SOURCE_LONGTAIL,
        record_type="message_chain",
        verification_profile="message-chain-v1",
        input_data=chain,
        context={
            "expected_message_count": 4,
            "expected_message_hashes": [
                compute_hash(message) for message in chain["messages"]
            ],
            "public_keys_b64url": {
                initiator["agent_id"]: initiator_key.public_key_b64(),
                responder["agent_id"]: responder_key.public_key_b64(),
            },
        },
    )
    if not evaluate_message_chain_profile(baseline).accepted:
        raise GenerationError("synthetic message chain position fixture did not verify")
    return chain


def compute_transcript_hash(messages: list[dict[str, Any]]) -> str:
    combined = b"".join(canonical_json(message) for message in messages)
    return "sha256:" + hashlib.sha256(combined).hexdigest()


def receipt_set_binding_key_by_agent() -> dict[str, KeyPair]:
    return {
        "did:concordia:agent:receipt-chain-initiator": key_pair_from_seed(
            SYNTHETIC_SEEDS["message_chain_initiator"]
        ),
        "did:concordia:agent:receipt-chain-responder": key_pair_from_seed(
            SYNTHETIC_SEEDS["message_chain_responder"]
        ),
    }


def build_receipt_set_binding_fixture() -> dict[str, Any]:
    key_by_agent = receipt_set_binding_key_by_agent()
    initiator = {"agent_id": "did:concordia:agent:receipt-chain-initiator"}
    responder = {"agent_id": "did:concordia:agent:receipt-chain-responder"}
    session_id = "sess_conformance_receipt_set_binding_0001"

    open_msg = build_message(
        message_id="msg_conformance_receipt_binding_0001",
        message_type="negotiate.open",
        session_id=session_id,
        sender=initiator,
        recipients=[responder],
        body={"proposal": {"workstream": "analysis", "assurance_level": "standard"}},
        key_pair=key_by_agent[initiator["agent_id"]],
        prev_hash=GENESIS_HASH,
        timestamp="2026-05-10T16:00:00Z",
        reasoning="Open deterministic receipt set-binding session.",
    )
    accept_session = build_message(
        message_id="msg_conformance_receipt_binding_0002",
        message_type="negotiate.accept_session",
        session_id=session_id,
        sender=responder,
        recipients=[initiator],
        body={"accepted": True},
        key_pair=key_by_agent[responder["agent_id"]],
        prev_hash=compute_hash(open_msg),
        timestamp="2026-05-10T16:01:00Z",
        in_reply_to=open_msg["id"],
    )
    offer = build_message(
        message_id="msg_conformance_receipt_binding_0003",
        message_type="negotiate.offer",
        session_id=session_id,
        sender=initiator,
        recipients=[responder],
        body={"offer": {"scope": "analysis-summary", "assurance": "standard"}},
        key_pair=key_by_agent[initiator["agent_id"]],
        prev_hash=compute_hash(accept_session),
        timestamp="2026-05-10T16:02:00Z",
        in_reply_to=accept_session["id"],
        reasoning="First offer in the deterministic receipt-binding chain.",
    )
    inquiry = build_message(
        message_id="msg_conformance_receipt_binding_0004",
        message_type="negotiate.inquire",
        session_id=session_id,
        sender=initiator,
        recipients=[responder],
        body={"questions": ["acceptance_criteria"]},
        key_pair=key_by_agent[initiator["agent_id"]],
        prev_hash=compute_hash(offer),
        timestamp="2026-05-10T16:03:00Z",
        in_reply_to=offer["id"],
        reasoning="Same-signer downstream message for splice coverage.",
    )
    accept_offer = build_message(
        message_id="msg_conformance_receipt_binding_0005",
        message_type="negotiate.accept_offer",
        session_id=session_id,
        sender=initiator,
        recipients=[responder],
        body={"accepted": True},
        key_pair=key_by_agent[initiator["agent_id"]],
        prev_hash=compute_hash(inquiry),
        timestamp="2026-05-10T16:04:00Z",
        in_reply_to=offer["id"],
        reasoning="Terminal agreement message for receipt set-binding.",
    )
    messages = [open_msg, accept_session, offer, inquiry, accept_offer]

    parties = [
        {
            "agent_id": initiator["agent_id"],
            "role": "initiator",
            "behavior": {
                "offers_made": 1,
                "concessions": 0,
                "concession_magnitude": 0.0,
                "signals_shared": 1,
                "constraints_declared": 1,
                "constraints_violated": 0,
                "reasoning_provided": True,
                "withdrawal": False,
                "response_time_avg_seconds": 2.0,
            },
        },
        {
            "agent_id": responder["agent_id"],
            "role": "responder",
            "behavior": {
                "offers_made": 0,
                "concessions": 0,
                "concession_magnitude": 0.0,
                "signals_shared": 1,
                "constraints_declared": 1,
                "constraints_violated": 0,
                "reasoning_provided": False,
                "withdrawal": False,
                "response_time_avg_seconds": 3.0,
            },
        },
    ]
    for party in parties:
        party["signature"] = sign_message(party, key_by_agent[party["agent_id"]])

    receipt = {
        "concordia_attestation": "0.3.0",
        "attestation_id": "att_conformance_receipt_set_binding_0001",
        "session_id": session_id,
        "timestamp": "2026-05-10T16:05:00Z",
        "outcome": {
            "status": "agreed",
            "rounds": 3,
            "duration_seconds": 300,
            "terms_count": 1,
            "resolution_mechanism": "direct",
        },
        "parties": parties,
        "meta": {
            "category": "software.tools",
            "extensions_used": [],
            "mediator_invoked": False,
        },
        "transcript_hash": compute_transcript_hash(messages),
        "chain_head": compute_hash(messages[-1]),
        "message_count": len(messages),
        "fulfillment": None,
        "references": [],
        "summary": (
            "Agreement completed with a deterministic transcript and no mediation."
        ),
    }
    receipt["countersignatures"] = {
        agent_id: countersign_attestation(receipt, key_by_agent[agent_id])
        for agent_id in sorted(key_by_agent)
    }
    pair = {"messages": messages, "receipt": receipt}
    context = {
        "public_keys_b64url": {
            agent_id: key_pair.public_key_b64()
            for agent_id, key_pair in sorted(key_by_agent.items())
        }
    }
    baseline = Vector(
        vector_id="baseline-synthetic-receipt-set-binding",
        title="receipt set-binding baseline",
        source_fixture=f"{SYNTHETIC_SOURCE_LONGTAIL}/receipt_set_binding.json",
        record_type="message_chain",
        verification_profile="message-chain-v1",
        input_data=pair,
        context=context,
    )
    if not evaluate_message_chain_profile(baseline).accepted:
        raise GenerationError("synthetic receipt set-binding fixture did not verify")
    return pair


def build_synthetic_longtail_fixtures(
    base_attestation: dict[str, Any],
) -> SyntheticLongtailFixtures:
    profile_key = key_pair_from_seed(SYNTHETIC_SEEDS["agent_profile_signer"])
    initiator_key = key_pair_from_seed(SYNTHETIC_SEEDS["attestation_initiator"])
    responder_key = key_pair_from_seed(SYNTHETIC_SEEDS["attestation_responder"])
    chain_initiator_key = key_pair_from_seed(SYNTHETIC_SEEDS["message_chain_initiator"])
    chain_responder_key = key_pair_from_seed(SYNTHETIC_SEEDS["message_chain_responder"])

    agent_a = "did:concordia:agent:synthetic-initiator"
    agent_b = "did:concordia:agent:synthetic-responder"
    key_by_agent = {agent_a: initiator_key, agent_b: responder_key}

    attestation_one = resign_attestation(base_attestation, key_by_agent)
    attestation_two = copy.deepcopy(base_attestation)
    attestation_two["attestation_id"] = "att_conformance_p2a4_0002"
    attestation_two["session_id"] = "sess_conformance_p2a4_0002"
    attestation_two["timestamp"] = "2026-05-10T14:35:00Z"
    attestation_two["chain_head"] = "sha256:" + ("c3" * 32)
    attestation_two["message_count"] = 4
    attestation_two["outcome"] = {
        "status": "rejected",
        "rounds": 2,
        "duration_seconds": 145,
        "terms_count": 2,
        "resolution_mechanism": "direct",
    }
    attestation_two["parties"][0]["behavior"]["offers_made"] = 1
    attestation_two["parties"][0]["behavior"]["concession_magnitude"] = 0.1
    attestation_two["parties"][1]["behavior"]["offers_made"] = 1
    attestation_two["parties"][1]["behavior"]["concession_magnitude"] = 0.2
    attestations = [
        attestation_one,
        resign_attestation(attestation_two, key_by_agent),
    ]

    profile = build_agent_profile_fixture(profile_key)
    receipt_bundle = build_receipt_bundle_fixture(agent_a, attestations, initiator_key)
    competence_proof = build_competence_proof_fixture(agent_a, attestations, initiator_key)
    message_chain = build_message_chain_fixture(chain_initiator_key, chain_responder_key)
    message_chain_position = build_message_chain_position_fixture(
        chain_initiator_key,
        chain_responder_key,
    )
    receipt_set_binding = build_receipt_set_binding_fixture()

    manifest = seed_manifest_for(
        {
            "agent_profile_signer": profile_key,
            "attestation_initiator": initiator_key,
            "attestation_responder": responder_key,
            "message_chain_initiator": chain_initiator_key,
            "message_chain_responder": chain_responder_key,
        }
    )
    manifest["agent_ids"] = {
        "agent_profile": profile["agent_id"],
        "receipt_bundle_agent": agent_a,
        "receipt_bundle_counterparty": agent_b,
        "message_chain_initiator": "did:concordia:agent:chain-initiator",
        "message_chain_responder": "did:concordia:agent:chain-responder",
        "receipt_set_binding_initiator": (
            "did:concordia:agent:receipt-chain-initiator"
        ),
        "receipt_set_binding_responder": (
            "did:concordia:agent:receipt-chain-responder"
        ),
    }
    manifest["agent_profile_canonical_fields"] = list(AGENT_PROFILE_CANONICAL_FIELDS)
    manifest["competence_proof_reveal"] = {
        "committed_attestation_count": len(attestations),
        "revealed_attestation_ids": [
            attestation["attestation_id"]
            for attestation in competence_proof["revealed_attestations"]
        ],
    }

    return SyntheticLongtailFixtures(
        agent_profile=profile,
        receipt_bundle=receipt_bundle,
        competence_proof=competence_proof,
        message_chain=message_chain,
        message_chain_position=message_chain_position,
        receipt_set_binding=receipt_set_binding,
        attestations=attestations,
        seed_manifest=manifest,
    )


def build_synthetic_fixtures() -> SyntheticFixtures:
    attestation, attestation_seed_manifest = build_synthetic_attestation()
    predicates, predicate_seed_manifest = build_synthetic_predicates()
    direct_mandate, delegated_mandate, mandate_seed_manifest = build_synthetic_mandates()
    cosigned_receipt, cosign_seed_manifest = build_synthetic_cosigned_receipt()
    cmpc = build_synthetic_cmpc_fixtures()
    longtail = build_synthetic_longtail_fixtures(attestation)
    return SyntheticFixtures(
        attestation=attestation,
        attestation_seed_manifest=attestation_seed_manifest,
        predicates=predicates,
        predicate_seed_manifest=predicate_seed_manifest,
        direct_mandate=direct_mandate,
        delegated_mandate=delegated_mandate,
        mandate_seed_manifest=mandate_seed_manifest,
        cosigned_receipt=cosigned_receipt,
        cosign_seed_manifest=cosign_seed_manifest,
        cmpc=cmpc,
        longtail=longtail,
    )


def synthetic_fixture_payloads(fixtures: SyntheticFixtures) -> dict[Path, Any]:
    payloads: dict[Path, Any] = {
        Path("synthetic/attestation/attestation.json"): fixtures.attestation,
        Path("synthetic/attestation/seed_manifest.json"): fixtures.attestation_seed_manifest,
        Path("synthetic/mandate/mandate.json"): fixtures.direct_mandate,
        Path("synthetic/mandate/delegated_mandate.json"): fixtures.delegated_mandate,
        Path("synthetic/mandate/seed_manifest.json"): fixtures.mandate_seed_manifest,
        Path("synthetic/cosign/cosigned_receipt.json"): fixtures.cosigned_receipt,
        Path("synthetic/cosign/seed_manifest.json"): fixtures.cosign_seed_manifest,
    }
    for name, predicate in sorted(fixtures.predicates.items()):
        payloads[Path("synthetic/predicate") / f"{name}.json"] = predicate
    payloads[Path("synthetic/predicate/seed_manifest.json")] = (
        fixtures.predicate_seed_manifest
    )
    cmpc_root = Path("synthetic/cmpc_bilateral")
    payloads[cmpc_root / "primitives/conditional_commitment.json"] = (
        fixtures.cmpc.conditional_commitment
    )
    payloads[cmpc_root / "primitives/atomic_activation_proof.json"] = (
        fixtures.cmpc.atomic_activation_proof
    )
    payloads[cmpc_root / "primitives/unwind_record.json"] = fixtures.cmpc.unwind_record
    payloads[cmpc_root / "primitives/closure_predicate.json"] = (
        fixtures.cmpc.closure_predicate
    )
    payloads[cmpc_root / "primitives/chain_session.json"] = fixtures.cmpc.chain_session
    for name, transition in sorted(fixtures.cmpc.transition_vectors.items()):
        payloads[cmpc_root / "state_machine" / f"{name}.json"] = transition
    payloads[cmpc_root / "seed_manifest.json"] = fixtures.cmpc.seed_manifest
    longtail_root = Path("synthetic/longtail")
    payloads[longtail_root / "agent_profile.json"] = fixtures.longtail.agent_profile
    payloads[longtail_root / "receipt_bundle.json"] = fixtures.longtail.receipt_bundle
    payloads[longtail_root / "competence_proof.json"] = (
        fixtures.longtail.competence_proof
    )
    payloads[longtail_root / "message_chain.json"] = fixtures.longtail.message_chain
    payloads[longtail_root / "message_chain_position.json"] = (
        fixtures.longtail.message_chain_position
    )
    payloads[longtail_root / "receipt_set_binding.json"] = (
        fixtures.longtail.receipt_set_binding
    )
    for index, attestation in enumerate(fixtures.longtail.attestations, start=1):
        payloads[longtail_root / f"attestation_{index:02d}.json"] = attestation
    payloads[longtail_root / "seed_manifest.json"] = fixtures.longtail.seed_manifest
    return payloads


def build_phase2_vectors(fixtures: SyntheticFixtures) -> list[Vector]:
    attestation = fixtures.attestation
    attestation_public_keys = fixtures.attestation_seed_manifest[
        "agent_public_keys_b64url"
    ]
    attestation_parties = [party["agent_id"] for party in attestation["parties"]]
    countersign_preimage = attestation_countersign_payload(attestation)
    raw_term_attestation = copy.deepcopy(attestation)
    raw_term_attestation["parties"][0]["behavior"]["note"] = (
        "price: USD 250 for 10 units"
    )

    action = {"max_spend": 500, "category": "software"}
    mandate_issuer_key = fixtures.mandate_seed_manifest[
        "seeds_PUBLIC_test_only_do_not_reuse"
    ]["mandate_issuer"]["public_key_b64url"]
    delegated_key_manifest = fixtures.mandate_seed_manifest[
        "seeds_PUBLIC_test_only_do_not_reuse"
    ]
    mandate_agent_ids = fixtures.mandate_seed_manifest["agent_ids"]

    cosign_receipt = fixtures.cosigned_receipt
    cosign_dids = fixtures.cosign_seed_manifest["dids"]
    cosign_public_key = fixtures.cosign_seed_manifest[
        "seeds_PUBLIC_test_only_do_not_reuse"
    ]["cosign_counterparty"]["public_key_b64url"]
    cosign_preimage = canonical_cosign_bytes(cosign_receipt)
    cmpc_key_manifest = fixtures.cmpc.seed_manifest[
        "seeds_PUBLIC_test_only_do_not_reuse"
    ]
    cmpc_retailer_key = cmpc_key_manifest["cmpc_retailer"]["public_key_b64url"]
    cmpc_wholesaler_key = cmpc_key_manifest["cmpc_wholesaler"]["public_key_b64url"]
    cmpc_authority_key = cmpc_key_manifest["cmpc_authority"]["public_key_b64url"]
    longtail_key_manifest = fixtures.longtail.seed_manifest[
        "seeds_PUBLIC_test_only_do_not_reuse"
    ]
    profile_preimage = canonical_json(
        agent_profile_canonical_from_raw(fixtures.longtail.agent_profile) or {}
    )
    receipt_bundle_preimage = canonical_json(
        without_keys(
            fixtures.longtail.receipt_bundle,
            {"agent_signature", "concordia_receipt_bundle"},
        )
    )
    competence_proof_preimage = canonical_json(
        competence_proof_signable(fixtures.longtail.competence_proof)
    )
    message_hashes = [
        compute_hash(message) for message in fixtures.longtail.message_chain["messages"]
    ]
    receipt_set_binding_hashes = [
        compute_hash(message)
        for message in fixtures.longtail.receipt_set_binding["messages"]
    ]
    longtail_agent_ids = fixtures.longtail.seed_manifest["agent_ids"]

    vectors: list[Vector] = [
        Vector(
            vector_id="pos-synthetic-attestation",
            title="Synthetic reputation Attestation validates and verifies both party signatures",
            source_fixture=SYNTHETIC_SOURCE_ATTESTATION,
            record_type="attestation",
            verification_profile="attestation-v1",
            input_data=attestation,
            context={
                "forbid_raw_deal_terms": True,
                "expected_verified_parties": attestation_parties,
                "public_keys_b64url": attestation_public_keys,
            },
        ),
        Vector(
            vector_id="privacy-synthetic-attestation-behavior-note",
            title="Synthetic Attestation rejects an injected raw deal term in a behavior note",
            source_fixture=SYNTHETIC_SOURCE_ATTESTATION,
            record_type="attestation",
            verification_profile="attestation-v1",
            input_data=raw_term_attestation,
            context={
                "forbid_raw_deal_terms": True,
                "expected_verified_parties": attestation_parties,
                "public_keys_b64url": attestation_public_keys,
            },
            expected="reject",
            expected_reason_class="privacy",
            notes=(
                "privacy-reject: SPEC 9.6.6 raw-deal-term scanner catches "
                "a party behavior note before schema/signature checks"
            ),
        ),
        Vector(
            vector_id="pos-synthetic-attestation-countersign",
            title="Synthetic Attestation countersignatures bind the issuance snapshot",
            source_fixture=SYNTHETIC_SOURCE_ATTESTATION,
            record_type="attestation",
            verification_profile="attestation-countersign-v1",
            input_data=attestation,
            context={
                "canonical_sha256": "sha256:"
                + hashlib.sha256(countersign_preimage).hexdigest(),
                "countersigners": attestation_parties,
                "public_keys_b64url": attestation_public_keys,
            },
            canonical_preimage=countersign_preimage,
        ),
        Vector(
            vector_id="pos-synthetic-mandate",
            title="Synthetic EdDSA Mandate validates, verifies, and authorizes the action",
            source_fixture=SYNTHETIC_SOURCE_MANDATE,
            record_type="mandate",
            verification_profile="mandate-v1",
            input_data=fixtures.direct_mandate,
            context={
                "action": action,
                "canonical_sha256": sha256_jcs(without_signature(fixtures.direct_mandate)),
                "issuer_public_key_b64url": mandate_issuer_key,
                "now": fixed_iso_now(),
            },
            canonical_preimage=canonicalize_mandate(fixtures.direct_mandate),
        ),
        Vector(
            vector_id="pos-synthetic-delegation-chain",
            title="Synthetic delegated Mandate verifies each chain link",
            source_fixture=SYNTHETIC_SOURCE_MANDATE,
            record_type="mandate",
            verification_profile="delegation-chain-v1",
            input_data=fixtures.delegated_mandate,
            context={
                "action": action,
                "canonical_sha256": sha256_jcs(without_signature(fixtures.delegated_mandate)),
                "delegation_public_keys_b64url": {
                    mandate_agent_ids["issuer"]: delegated_key_manifest[
                        "mandate_issuer"
                    ]["public_key_b64url"],
                    mandate_agent_ids["delegate"]: delegated_key_manifest[
                        "mandate_delegate"
                    ]["public_key_b64url"],
                },
                "issuer_public_key_b64url": mandate_issuer_key,
                "now": fixed_iso_now(),
            },
            canonical_preimage=canonicalize_mandate(fixtures.delegated_mandate),
        ),
        Vector(
            vector_id="pos-synthetic-cosign",
            title="Synthetic counterparty co-signature verifies and did:key matches",
            source_fixture=SYNTHETIC_SOURCE_COSIGN,
            record_type="cosign_receipt",
            verification_profile="cosign-v1",
            input_data=cosign_receipt,
            context={
                "canonical_sha256": "sha256:"
                + hashlib.sha256(cosign_preimage).hexdigest(),
                "counterparty_did": cosign_dids["counterparty"],
                "counterparty_public_key_b64url": cosign_public_key,
                "publisher_did": cosign_dids["publisher"],
            },
            canonical_preimage=cosign_preimage,
        ),
        Vector(
            vector_id="pos-synthetic-cmpc-conditional-commitment",
            title="Synthetic CMPC ConditionalCommitment validates and verifies",
            source_fixture=SYNTHETIC_SOURCE_CMPC,
            record_type="conditional_commitment",
            verification_profile="conditional-commitment-v1",
            input_data=fixtures.cmpc.conditional_commitment,
            context={
                "canonical_sha256": sha256_jcs(
                    without_signature(fixtures.cmpc.conditional_commitment)
                ),
                "public_key_b64url": cmpc_retailer_key,
            },
            canonical_preimage=canonicalize_conditional_commitment(
                fixtures.cmpc.conditional_commitment
            ),
        ),
        Vector(
            vector_id="pos-synthetic-cmpc-atomic-activation-proof",
            title="Synthetic CMPC AtomicActivationProof validates and verifies",
            source_fixture=SYNTHETIC_SOURCE_CMPC,
            record_type="atomic_activation_proof",
            verification_profile="atomic-activation-proof-v1",
            input_data=fixtures.cmpc.atomic_activation_proof,
            context={
                "canonical_sha256": sha256_jcs(
                    without_signature(fixtures.cmpc.atomic_activation_proof)
                ),
                "public_key_b64url": cmpc_wholesaler_key,
            },
            canonical_preimage=canonicalize_atomic_activation_proof(
                fixtures.cmpc.atomic_activation_proof
            ),
        ),
        Vector(
            vector_id="pos-synthetic-cmpc-unwind-record",
            title="Synthetic CMPC UnwindRecord validates and verifies",
            source_fixture=SYNTHETIC_SOURCE_CMPC,
            record_type="unwind_record",
            verification_profile="unwind-record-v1",
            input_data=fixtures.cmpc.unwind_record,
            context={
                "canonical_sha256": sha256_jcs(
                    without_signature(fixtures.cmpc.unwind_record)
                ),
                "public_key_b64url": cmpc_retailer_key,
            },
            canonical_preimage=canonicalize_unwind_record(fixtures.cmpc.unwind_record),
        ),
        Vector(
            vector_id="pos-synthetic-cmpc-closure-predicate",
            title="Synthetic CMPC ClosurePredicate validates and binds its chain-session digest",
            source_fixture=SYNTHETIC_SOURCE_CMPC,
            record_type="closure_predicate",
            verification_profile="closure-predicate-v1",
            input_data=fixtures.cmpc.closure_predicate,
            context={
                "canonical_sha256": sha256_jcs(
                    without_signature(fixtures.cmpc.closure_predicate)
                ),
                "chain_session": fixtures.cmpc.chain_session,
                "digest_checks": [
                    {
                        "kind": "jcs-sha256-pointer",
                        "source": "context.chain_session",
                        "target": {"object": "input", "pointer": "/references/0/digest"},
                    }
                ],
                "public_key_b64url": cmpc_authority_key,
            },
            notes=(
                "closure-predicate-v1 checks schema and committed digests; "
                "it does not verify /signature"
            ),
            canonical_preimage=canonicalize_closure_predicate(
                fixtures.cmpc.closure_predicate
            ),
        ),
        Vector(
            vector_id="pos-synthetic-cmpc-chain-session",
            title="Synthetic CMPC ChainSession validates and canonicalizes",
            source_fixture=SYNTHETIC_SOURCE_CMPC,
            record_type="chain_session",
            verification_profile="chain-session-v1",
            input_data=fixtures.cmpc.chain_session,
            context={
                "canonical_sha256": sha256_jcs(fixtures.cmpc.chain_session),
            },
            canonical_preimage=canonicalize_chain_session(fixtures.cmpc.chain_session),
        ),
        Vector(
            vector_id="pos-synthetic-agent-profile",
            title="Synthetic AgentProfile verifies its canonical signed form",
            source_fixture=SYNTHETIC_SOURCE_LONGTAIL,
            record_type="agent_profile",
            verification_profile="agent-profile-v1",
            input_data=fixtures.longtail.agent_profile,
            context={
                "canonical_fields": list(AGENT_PROFILE_CANONICAL_FIELDS),
                "canonical_sha256": "sha256:"
                + hashlib.sha256(profile_preimage).hexdigest(),
                "public_key_b64url": longtail_key_manifest["agent_profile_signer"][
                    "public_key_b64url"
                ],
            },
            notes=(
                "signed form is exactly AgentCapabilityProfile.to_canonical_dict(); "
                "signature and verified are excluded"
            ),
            canonical_preimage=profile_preimage,
        ),
        Vector(
            vector_id="pos-synthetic-competence-proof",
            title="Synthetic CompetenceProof verifies signature and one Merkle inclusion proof",
            source_fixture=SYNTHETIC_SOURCE_LONGTAIL,
            record_type="competence_proof",
            verification_profile="competence-proof-v1",
            input_data=fixtures.longtail.competence_proof,
            context={
                "canonical_sha256": "sha256:"
                + hashlib.sha256(competence_proof_preimage).hexdigest(),
                "public_key_b64url": longtail_key_manifest["attestation_initiator"][
                    "public_key_b64url"
                ],
            },
            notes=(
                "partial reveal: two attestation IDs are committed and one "
                "revealed attestation carries a Merkle inclusion proof"
            ),
            canonical_preimage=competence_proof_preimage,
        ),
        Vector(
            vector_id="pos-synthetic-receipt-bundle",
            title="Synthetic ReceiptBundle validates schema and verifies agent signature",
            source_fixture=SYNTHETIC_SOURCE_LONGTAIL,
            record_type="receipt_bundle",
            verification_profile="receipt-bundle-v1",
            input_data=fixtures.longtail.receipt_bundle,
            context={
                "canonical_sha256": "sha256:"
                + hashlib.sha256(receipt_bundle_preimage).hexdigest(),
                "public_key_b64url": longtail_key_manifest["attestation_initiator"][
                    "public_key_b64url"
                ],
            },
            canonical_preimage=receipt_bundle_preimage,
        ),
        Vector(
            vector_id="pos-synthetic-message-chain",
            title="Synthetic three-message chain verifies signatures and prev_hash links",
            source_fixture=SYNTHETIC_SOURCE_LONGTAIL,
            record_type="message_chain",
            verification_profile="message-chain-v1",
            input_data=fixtures.longtail.message_chain,
            context={
                "expected_message_count": 3,
                "expected_message_hashes": message_hashes,
                "public_keys_b64url": {
                    longtail_agent_ids["message_chain_initiator"]: longtail_key_manifest[
                        "message_chain_initiator"
                    ]["public_key_b64url"],
                    longtail_agent_ids["message_chain_responder"]: longtail_key_manifest[
                        "message_chain_responder"
                    ]["public_key_b64url"],
                },
            },
            notes=(
                "chain linkage is checked from GENESIS_HASH before per-message "
                "signature verification"
            ),
            canonical_preimage=canonical_json(fixtures.longtail.message_chain),
        ),
        Vector(
            vector_id="pos-synthetic-receipt-set-binding",
            title="Synthetic 0.3.0 receipt binds chain_head and message_count to an agreed transcript",
            source_fixture=f"{SYNTHETIC_SOURCE_LONGTAIL}/receipt_set_binding.json",
            record_type="message_chain",
            verification_profile="message-chain-v1",
            input_data=fixtures.longtail.receipt_set_binding,
            context={
                **receipt_set_binding_context(fixtures),
                "expected_message_count": 5,
                "expected_message_hashes": receipt_set_binding_hashes,
            },
            notes=(
                "receipt set-binding checks the transcript links and signatures, "
                "then verifies the 0.3.0 receipt countersignatures and compares "
                "chain_head/message_count to the presented transcript"
            ),
            canonical_preimage=canonical_json(fixtures.longtail.receipt_set_binding),
        ),
    ]

    for name, predicate in sorted(fixtures.predicates.items()):
        preimage = canonical_json(without_signature(predicate))
        vectors.append(
            Vector(
                vector_id=f"pos-synthetic-predicate-{name.replace('_', '-')}",
                title=f"Synthetic signed Predicate from canonical fixture {name}",
                source_fixture=SYNTHETIC_SOURCE_PREDICATE,
                record_type="predicate",
                verification_profile="predicate-v1",
                input_data=predicate,
                context={
                    "canonical_sha256": "sha256:"
                    + hashlib.sha256(preimage).hexdigest(),
                    "now": fixed_iso_now(),
                    "public_key_b64url": fixtures.predicate_seed_manifest[
                        "seeds_PUBLIC_test_only_do_not_reuse"
                    ]["predicate_issuer"]["public_key_b64url"],
                },
                canonical_preimage=preimage,
            )
        )

    for name, transition in sorted(fixtures.cmpc.transition_vectors.items()):
        expects_accept = transition["expected"] == "ok"
        vectors.append(
            Vector(
                vector_id=f"transition-synthetic-cmpc-{name.replace('_', '-')}",
                title=f"CMPC ChainSession transition fixture {name}",
                source_fixture=f"{SYNTHETIC_SOURCE_CMPC}/state_machine",
                record_type="chain_session_transition",
                verification_profile="chain-session-transition-v1",
                input_data=transition,
                context={},
                expected="accept" if expects_accept else "reject",
                expected_reason_class=None if expects_accept else "transition",
                notes=(
                    "legal transition" if expects_accept else "illegal transition"
                ),
            )
        )

    return sorted(vectors, key=lambda vector: vector.vector_id)


def build_vectors() -> list[Vector]:
    f1404 = fixture_1404()
    f1920 = fixture_1920()
    synthetic = build_synthetic_fixtures()
    hashes = f1404["vector"]["hashes"]
    public_keys_1404 = f1404["vector"]["public_keys_b64url"]
    sample = f1920["sample"]
    fulfillment = f1920["fulfillment_attestation"]
    signable_fulfillment = without_signature(fulfillment)

    vectors = [
        Vector(
            vector_id="pos-1404-decision-id",
            title="A2A 1404 decision_id recomputes from the decision object",
            source_fixture=INTEROP_1404.name,
            record_type="decision_object",
            verification_profile="decision-object-v1",
            input_data=f1404["decision_object"],
            context={"expected_decision_id": hashes["decision_id"]},
            canonical_preimage=canonicalize_jcs(f1404["decision_object"]),
        ),
        Vector(
            vector_id="pos-1404-capability-digest",
            title="A2A 1404 capability_digest recomputes from capability JSON",
            source_fixture=INTEROP_1404.name,
            record_type="approval_receipt",
            verification_profile="offer-binding-v1",
            input_data=f1404["capability"],
            context={
                "checks": [
                    {
                        "kind": "jcs-sha256",
                        "source": "input",
                        "expected": hashes["capability_digest"],
                    }
                ]
            },
            canonical_preimage=canonicalize_jcs(f1404["capability"]),
        ),
        Vector(
            vector_id="pos-1404-offer-digest",
            title="A2A 1404 request_digest and receipt_offer_hash recompute from offer JSON",
            source_fixture=INTEROP_1404.name,
            record_type="approval_receipt",
            verification_profile="offer-binding-v1",
            input_data=f1404["offer"],
            context={
                "checks": [
                    {
                        "kind": "jcs-sha256",
                        "source": "input",
                        "expected": hashes["request_digest"],
                    },
                    {
                        "kind": "jcs-sha256",
                        "source": "input",
                        "expected": hashes["receipt_offer_hash"],
                    },
                ]
            },
            canonical_preimage=canonicalize_jcs(f1404["offer"]),
        ),
        Vector(
            vector_id="pos-1404-receipt-decision-binding",
            title="A2A 1404 receipt decision equals the decision object",
            source_fixture=INTEROP_1404.name,
            record_type="approval_receipt",
            verification_profile="offer-binding-v1",
            input_data=f1404["approval_receipt"],
            context={
                "decision_object": f1404["decision_object"],
                "checks": [
                    {
                        "kind": "json-pointer-equal",
                        "left": {"object": "input", "pointer": "/scope/decision"},
                        "right": {
                            "object": "context.decision_object",
                            "pointer": "/decision",
                        },
                    }
                ],
            },
        ),
        Vector(
            vector_id="pos-1404-receipt-offer-binding",
            title="A2A 1404 receipt offer_hash equals the decision request_digest",
            source_fixture=INTEROP_1404.name,
            record_type="approval_receipt",
            verification_profile="offer-binding-v1",
            input_data=f1404["approval_receipt"],
            context={
                "decision_object": f1404["decision_object"],
                "checks": [
                    {
                        "kind": "json-pointer-equal",
                        "left": {"object": "input", "pointer": "/scope/offer_hash"},
                        "right": {
                            "object": "context.decision_object",
                            "pointer": "/request_digest",
                        },
                    }
                ],
            },
        ),
        Vector(
            vector_id="pos-1404-wrapped-decision-id-binding",
            title="A2A 1404 evidence extension names the recomputed decision_id",
            source_fixture=INTEROP_1404.name,
            record_type="approval_receipt",
            verification_profile="offer-binding-v1",
            input_data=f1404["approval_receipt"],
            context={
                "expected": {"decision_id": hashes["decision_id"]},
                "checks": [
                    {
                        "kind": "json-pointer-equal",
                        "left": {
                            "object": "input",
                            "pointer": "/references/0/extensions/a2a_1404_decision_id",
                        },
                        "right": {
                            "object": "context.expected",
                            "pointer": "/decision_id",
                        },
                    }
                ],
            },
        ),
        Vector(
            vector_id="pos-1404-ancestor-status-read-binding",
            title="A2A 1404 evidence extension names the ancestor status read",
            source_fixture=INTEROP_1404.name,
            record_type="approval_receipt",
            verification_profile="offer-binding-v1",
            input_data=f1404["approval_receipt"],
            context={
                "revocation_record": f1404["revocation_A"],
                "checks": [
                    {
                        "kind": "json-pointer-equal",
                        "left": {
                            "object": "input",
                            "pointer": "/references/0/extensions/a2a_1404_evidence_refs/ancestor_status_read",
                        },
                        "right": {
                            "object": "context.revocation_record",
                            "pointer": "/revocation_id",
                        },
                    }
                ],
            },
        ),
        Vector(
            vector_id="pos-1404-approval-receipt",
            title="A2A 1404 ApprovalReceipt validates, verifies, is live, and binds to the offer",
            source_fixture=INTEROP_1404.name,
            record_type="approval_receipt",
            verification_profile="receipt-v1",
            input_data=f1404["approval_receipt"],
            context={
                "offer": f1404["offer"],
                "now": "2026-05-10T14:25:00Z",
                "public_keys_b64url": {"issuer": public_keys_1404["approver"]},
            },
            canonical_preimage=canonical_json(without_signature(f1404["approval_receipt"])),
        ),
        Vector(
            vector_id="pos-1404-revocation-record",
            title="A2A 1404 RevocationRecord validates and verifies under the issuer key",
            source_fixture=INTEROP_1404.name,
            record_type="revocation_record",
            verification_profile="revocation-v1",
            input_data=f1404["revocation_A"],
            context={
                "public_keys_b64url": {
                    "issuer": public_keys_1404["revocation_issuer"]
                }
            },
            canonical_preimage=canonical_json(without_signature(f1404["revocation_A"])),
        ),
        Vector(
            vector_id="pos-1404-cascade-deny",
            title="A2A 1404 cascade terminal deny validates, recomputes, and verifies",
            source_fixture=INTEROP_1404.name,
            record_type="cascade_decision_record",
            verification_profile="cascade-decision-v1",
            input_data=f1404["cascade_decision_deny"],
            context={
                "expected_decision_id": hashes["deny_decision_id"],
                "public_keys_b64url": {
                    "issuer": public_keys_1404["revocation_issuer"]
                },
            },
            canonical_preimage=canonicalize_cascade_decision_record(
                f1404["cascade_decision_deny"]
            ),
        ),
        Vector(
            vector_id="pos-1920-fulfillment-attestation",
            title="A2A 1920 FulfillmentAttestation validates, verifies, and binds join keys",
            source_fixture=INTEROP_1920.name,
            record_type="fulfillment_attestation",
            verification_profile="fulfillment-attestation-v1",
            input_data=fulfillment,
            context={
                "canonical_sha256": sample["canonical_sha256"],
                "forbid_raw_deal_terms": True,
                "join_keys": sample["join_keys"],
                "public_key_b64url": sample["public_key_b64url"],
                "seed_ed25519_ascii": sample["seed_ed25519_ascii"],
                "signature_b64url": sample["signature_b64url"],
            },
            canonical_preimage=canonical_json(signable_fulfillment),
        ),
    ]

    vectors.extend(build_phase2_vectors(synthetic))
    return sorted(vectors, key=lambda vector: vector.vector_id)


def assert_vectors_execute(vectors: list[Vector]) -> None:
    for vector in vectors:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            got_accept = verify_vector(vector)
        expected_accept = vector.expected == "accept"
        if got_accept != expected_accept:
            raise GenerationError(
                f"{vector.vector_id}: expected {vector.expected}, "
                f"got {'accept' if got_accept else 'reject'}"
            )


def clean_output(root: Path) -> None:
    conformance = root / "conformance"
    for generated_child in ("vectors", "diag"):
        path = conformance / generated_child
        if path.exists():
            shutil.rmtree(path)


def copy_fixtures(dest_root: Path) -> list[str]:
    copied: list[str] = []
    fixtures_root = dest_root / "conformance" / "vectors" / "fixtures"
    for fixture_dir in FIXTURE_DIRS:
        for source in sorted(fixture_dir.glob("*.json")):
            rel = Path(fixture_dir.name) / source.name
            dest = fixtures_root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)
            copied.append((Path("conformance") / "vectors" / "fixtures" / rel).as_posix())
    return sorted(copied)


def copy_synthetic_fixtures(
    dest_root: Path,
    fixtures: SyntheticFixtures,
) -> list[str]:
    copied: list[str] = []
    fixtures_root = dest_root / "conformance" / "vectors" / "fixtures"
    for rel, payload in sorted(synthetic_fixture_payloads(fixtures).items()):
        dest = fixtures_root / rel
        write_json(dest, payload)
        copied.append((Path("conformance") / "vectors" / "fixtures" / rel).as_posix())
    return copied


def copy_schemas(dest_root: Path) -> list[str]:
    copied: list[str] = []
    schemas_root = dest_root / "conformance" / "vectors" / "schemas"
    for name, source in sorted(SCHEMA_COPIES.items()):
        dest = schemas_root / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
        copied.append((Path("conformance") / "vectors" / "schemas" / name).as_posix())

    cascade_name = "cascade_decision_record.schema.json"
    write_json(schemas_root / cascade_name, CASCADE_DECISION_RECORD_SCHEMA)
    copied.append(
        (Path("conformance") / "vectors" / "schemas" / cascade_name).as_posix()
    )

    cmpc_schemas = {
        "atomic_activation_proof.schema.json": ATOMIC_ACTIVATION_PROOF_SCHEMA,
        "chain_session.schema.json": CHAIN_SESSION_SCHEMA,
        "closure_predicate.schema.json": CLOSURE_PREDICATE_SCHEMA,
        "conditional_commitment.schema.json": CONDITIONAL_COMMITMENT_SCHEMA,
        "unwind_record.schema.json": UNWIND_RECORD_SCHEMA,
    }
    for name, schema in sorted(cmpc_schemas.items()):
        write_json(schemas_root / name, schema)
        copied.append(
            (Path("conformance") / "vectors" / "schemas" / name).as_posix()
        )

    mandate_name = "mandate.schema.json"
    write_json(schemas_root / mandate_name, MANDATE_JSON_SCHEMA)
    copied.append(
        (Path("conformance") / "vectors" / "schemas" / mandate_name).as_posix()
    )
    return sorted(copied)


def write_vector_group(
    dest_root: Path,
    vectors: list[Vector],
    *,
    section: Literal["positive", "mutation", "canary"],
) -> tuple[list[str], list[str]]:
    vector_files: list[str] = []
    diag_files: list[str] = []
    vector_root = dest_root / "conformance" / "vectors" / section
    diag_root = dest_root / "conformance" / "diag" / "canonical-bytes"

    for vector in vectors:
        vector_path = vector_root / f"{vector.vector_id}.json"
        write_json(vector_path, vector.to_json())
        vector_files.append(
            (Path("conformance") / "vectors" / section / vector_path.name).as_posix()
        )
        if vector.canonical_preimage is not None:
            diag_path = diag_root / f"{vector.vector_id}.jcs"
            diag_path.parent.mkdir(parents=True, exist_ok=True)
            diag_path.write_bytes(vector.canonical_preimage)
            diag_files.append(
                (
                    Path("conformance")
                    / "diag"
                    / "canonical-bytes"
                    / diag_path.name
                ).as_posix()
            )
    return sorted(vector_files), sorted(diag_files)


def write_manifest(
    dest_root: Path,
    *,
    fixture_files: list[str],
    schema_files: list[str],
    positive_files: list[str],
    mutation_files: list[str],
    mutation_batteries: list[dict[str, Any]],
    canary_files: list[str],
    diag_files: list[str],
) -> None:
    manifest = {
        "schema_version": "concordia-conformance-manifest/v1-draft",
        "suite_version": SUITE_VERSION,
        "generated_by": GENERATOR_COMMAND,
        "check_command": CHECK_COMMAND,
        "profiles": list(PROFILES),
        "record_types": list(RECORD_TYPES),
        "counts": {
            "fixtures": len(fixture_files),
            "schemas": len(schema_files),
            "positive": len(positive_files),
            "mutation": len(mutation_files),
            "canary": len(canary_files),
            "diag_canonical_bytes": len(diag_files),
        },
        "files": {
            "fixtures": fixture_files,
            "schemas": schema_files,
            "positive": positive_files,
            "mutation": mutation_files,
            "canary": canary_files,
            "diag_canonical_bytes": diag_files,
        },
        "mutation_batteries": mutation_batteries,
        "phase_notes": {
            "mutation": "P2-A2 extends the raw mutation battery to the P2-A1 profiles.",
            "cmpc": "P2-A3 adds CMPC bilateral primitive and chain-session transition profiles.",
            "longtail": "P2-A4 adds AgentProfile, CompetenceProof, ReceiptBundle, and MessageChain profiles.",
            "chain_position": "P2-B adds message-chain position vectors and a splice canary.",
            "receipt_set_binding": "P2-B adds 0.3.0 receipt chain_head/message_count set-binding vectors and a receipt-binding canary.",
            "canary": "C3/P2-B pins the runner-discrimination canaries.",
            "reference_runner": "C3 adds the clean-room reference runner.",
        },
    }
    write_json(dest_root / "conformance" / "vectors" / "manifest.json", manifest)


def generate(dest_root: Path) -> None:
    synthetic_fixtures = build_synthetic_fixtures()
    positive_vectors = build_vectors()
    mutation_vectors, mutation_batteries = build_mutation_battery(synthetic_fixtures)
    canary_vectors = build_canary_vectors(synthetic_fixtures)
    assert_vectors_execute(positive_vectors)
    assert_vectors_execute(mutation_vectors)
    assert_vectors_execute(canary_vectors)
    clean_output(dest_root)
    fixture_files = sorted(
        copy_fixtures(dest_root)
        + copy_synthetic_fixtures(dest_root, synthetic_fixtures)
    )
    schema_files = copy_schemas(dest_root)
    positive_files, positive_diag_files = write_vector_group(
        dest_root, positive_vectors, section="positive"
    )
    mutation_files, mutation_diag_files = write_vector_group(
        dest_root, mutation_vectors, section="mutation"
    )
    canary_files, canary_diag_files = write_vector_group(
        dest_root, canary_vectors, section="canary"
    )
    write_manifest(
        dest_root,
        fixture_files=fixture_files,
        schema_files=schema_files,
        positive_files=positive_files,
        mutation_files=mutation_files,
        mutation_batteries=mutation_batteries,
        canary_files=canary_files,
        diag_files=sorted(positive_diag_files + mutation_diag_files + canary_diag_files),
    )


def all_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file())


def diff_text(actual_path: Path, expected_path: Path, rel: Path) -> str:
    actual = actual_path.read_bytes() if actual_path.exists() else b""
    expected = expected_path.read_bytes() if expected_path.exists() else b""
    if actual == expected:
        return ""
    try:
        actual_lines = actual.decode("utf-8").splitlines(keepends=True)
        expected_lines = expected.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return f"Binary drift: {rel.as_posix()}\n"
    return "".join(
        difflib.unified_diff(
            actual_lines,
            expected_lines,
            fromfile=rel.as_posix(),
            tofile=f"generated {rel.as_posix()}",
        )
    )


def check_generated() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        generate(tmp_root)
        actual_root = REPO_ROOT / "conformance"
        expected_root = tmp_root / "conformance"
        actual_rels = {
            path.relative_to(actual_root)
            for path in all_files(actual_root)
            if path.name not in GENERATED_CHECK_EXCLUDED_FILES
            and path.relative_to(actual_root).parts[0] not in GENERATED_CHECK_EXCLUDED_DIRS
        }
        expected_rels = {path.relative_to(expected_root) for path in all_files(expected_root)}
        all_rels = sorted(actual_rels | expected_rels)
        diffs: list[str] = []
        for rel in all_rels:
            actual_path = actual_root / rel
            expected_path = expected_root / rel
            if rel not in actual_rels:
                diffs.append(f"Missing generated file: {rel.as_posix()}\n")
            elif rel not in expected_rels:
                diffs.append(f"Extra generated file: {rel.as_posix()}\n")
            file_diff = diff_text(actual_path, expected_path, rel)
            if file_diff:
                diffs.append(file_diff)

    if not diffs:
        print("[OK] conformance vectors match generated output")
        return 0
    print("[FAIL] conformance vectors drifted from generated output", file=sys.stderr)
    print(f"Regenerate with: {GENERATOR_COMMAND}", file=sys.stderr)
    for diff in diffs:
        print(diff, end="" if diff.endswith("\n") else "\n", file=sys.stderr)
    return 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate to a temporary directory and compare byte-for-byte",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.check:
        return check_generated()
    generate(REPO_ROOT)
    print("Wrote conformance/vectors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
