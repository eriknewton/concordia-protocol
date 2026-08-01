#!/usr/bin/env python3
"""Generate Concordia conformance vectors deterministically."""

from __future__ import annotations

import argparse
import base64
import copy
import difflib
import hashlib
import json
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
    from jsonschema import Draft202012Validator, RefResolver

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
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
    canonicalize_cascade_decision_record,
)
from concordia.cmpc.schemas import (  # noqa: E402
    CASCADE_DECISION_RECORD_SCHEMA,
    REVOCATION_RECORD_SCHEMA,
    validate_cascade_decision_record,
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
from concordia.models.mandate import (  # noqa: E402
    MANDATE_JSON_SCHEMA,
    DelegationLink,
    Mandate,
    TemporalMode,
    ValidityWindow,
)
from concordia.predicate import sign_predicate, verify_predicate  # noqa: E402
from concordia.schema_validator import (  # noqa: E402
    _RAW_TERM_PATTERNS,
    validate_approval_receipt,
)
from concordia.signing import KeyPair, canonical_json, sign_message  # noqa: E402

ReasonClass: TypeAlias = Literal[
    "schema",
    "signature",
    "digest",
    "binding",
    "temporal",
    "privacy",
]
ExpectedOutcome: TypeAlias = Literal["accept", "reject"]
MutationKind: TypeAlias = Literal["value", "drop", "inject"]
MutationKey: TypeAlias = tuple[str, MutationKind]

VECTOR_SCHEMA_VERSION = "concordia-conformance-vector/v1-draft"
SUITE_VERSION = "v1-draft"
GENERATOR_COMMAND = "python3 scripts/conformance/generate_vectors.py"
CHECK_COMMAND = "python3 scripts/conformance/generate_vectors.py --check"

INTEROP_1404 = REPO_ROOT / "docs" / "interop" / "a2a-1404-receipt-revocation-vector"
INTEROP_1920 = REPO_ROOT / "docs" / "interop" / "a2a-1920-fulfillment-sample"
FIXED_NOW = datetime(2026, 5, 10, 14, 25, 0, tzinfo=timezone.utc)

SCHEMA_COPIES = {
    "approval_receipt.schema.json": REPO_ROOT / "schemas" / "approval_receipt.schema.json",
    "attestation.schema.json": REPO_ROOT / "schemas" / "attestation.schema.json",
    "revocation_record.schema.json": REPO_ROOT / "schemas" / "revocation_record.schema.json",
    "fulfillment_attestation.schema.json": REPO_ROOT
    / "schemas"
    / "fulfillment_attestation.schema.json",
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
)

SYNTHETIC_FIXTURE_ROOT = "synthetic"
SYNTHETIC_SOURCE_ATTESTATION = "synthetic/attestation"
SYNTHETIC_SOURCE_PREDICATE = "synthetic/predicate"
SYNTHETIC_SOURCE_MANDATE = "synthetic/mandate"
SYNTHETIC_SOURCE_COSIGN = "synthetic/cosign"
SYNTHETIC_SEEDS = {
    "attestation_initiator": "conformance_attest_initiator_001",
    "attestation_responder": "conformance_attest_responder_001",
    "predicate_issuer": "conformance_pred_issuer_00000001",
    "mandate_issuer": "conformance_mand_issuer_00000001",
    "mandate_delegate": "conformance_mand_delegate_000001",
    "cosign_publisher": "conformance_cosign_publisher_001",
    "cosign_counterparty": "conformance_cosign_counter_00001",
}


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


@dataclass(frozen=True)
class MutationDivergence:
    battery_name: str
    field_path: str
    kind: MutationKind
    sdk_expected: ExpectedOutcome
    raw_expected: ExpectedOutcome


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
    return not any(Draft202012Validator(schema, resolver=resolver).iter_errors(data))


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
    result = verify_attestation(input_data, public_keys)
    if result.schema_errors:
        return Evaluation(False, "schema")
    if result.signature_errors:
        return Evaluation(False, "signature")
    expected_parties = context.get("expected_verified_parties")
    if expected_parties is not None and sorted(result.verified_parties) != sorted(
        expected_parties
    ):
        return Evaluation(False, "binding")
    return Evaluation(result.valid, None if result.valid else "binding")


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


TOLERATED_SIGNATURE_ESCAPE_NOTE = (
    "tolerated-escape: signature block is outside its own preimage"
)
EXPECTED_MUTATION_TOTAL = 222
EXPECTED_MUTATION_REJECTS = 220
EXPECTED_MUTATION_ACCEPTS = 2
EXPECTED_CANARY_TOTAL = 3
EXPECTED_RAW_TYPED_DIVERGENCES = (
    MutationDivergence(
        battery_name="1404/revocation_A.json",
        field_path="cascade_depth",
        kind="drop",
        sdk_expected="accept",
        raw_expected="reject",
    ),
)
EXPECTED_RAW_ACCEPTED_MUTATIONS: frozenset[tuple[str, str, MutationKind]] = frozenset(
    {
        ("1920/fulfillment_attestation.json", "signature", "inject"),
        ("1404/approval_receipt.json", "signature", "inject"),
    }
)


def build_mutation_fixtures(
    f1404: dict[str, dict[str, Any]], f1920: dict[str, dict[str, Any]]
) -> list[MutationFixture]:
    hashes = f1404["vector"]["hashes"]
    public_keys_1404 = f1404["vector"]["public_keys_b64url"]
    sample = f1920["sample"]

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
            sdk_rejected=62,
            sdk_total=63,
            sdk_escapes=frozenset({("signature", "inject")}),
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
            sdk_rejected=62,
            sdk_total=63,
            sdk_escapes=frozenset({("signature", "inject")}),
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
    return None


def assert_mutation_sanity(
    vectors: list[Vector],
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


def build_mutation_vectors() -> list[Vector]:
    f1404 = fixture_1404()
    f1920 = fixture_1920()

    vectors: list[Vector] = []
    divergences: list[MutationDivergence] = []
    raw_accepts: set[tuple[str, str, MutationKind]] = set()

    for fixture in build_mutation_fixtures(f1404, f1920):
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
            evaluation = evaluate_vector(probe)
            expected = outcome_name(evaluation.accepted)
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
                raw_accepts.add((fixture.battery_name, field_path, kind))
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
                    notes=TOLERATED_SIGNATURE_ESCAPE_NOTE if evaluation.accepted else "",
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
        sdk_rejected = fixture.sdk_total - len(fixture.sdk_escapes)
        if sdk_rejected != fixture.sdk_rejected:
            raise GenerationError(
                f"{fixture.battery_name}: SDK expectation table is internally inconsistent"
            )

    vectors = sorted(vectors, key=lambda vector: vector.vector_id)
    assert_mutation_sanity(vectors, divergences, raw_accepts)
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


def build_canary_vectors() -> list[Vector]:
    f1404 = fixture_1404()
    f1920 = fixture_1920()
    vectors = sorted(
        [
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
        "concordia_attestation": "0.2.0",
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


def build_synthetic_fixtures() -> SyntheticFixtures:
    attestation, attestation_seed_manifest = build_synthetic_attestation()
    predicates, predicate_seed_manifest = build_synthetic_predicates()
    direct_mandate, delegated_mandate, mandate_seed_manifest = build_synthetic_mandates()
    cosigned_receipt, cosign_seed_manifest = build_synthetic_cosigned_receipt()
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
        "phase_notes": {
            "mutation": "C2 converts the 222 mutation battery under raw conformance rules.",
            "canary": "C3 adds the three runner-discrimination canaries.",
            "reference_runner": "C3 adds the clean-room reference runner.",
        },
    }
    write_json(dest_root / "conformance" / "vectors" / "manifest.json", manifest)


def generate(dest_root: Path) -> None:
    synthetic_fixtures = build_synthetic_fixtures()
    positive_vectors = build_vectors()
    mutation_vectors = build_mutation_vectors()
    canary_vectors = build_canary_vectors()
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
            if path.name != "RUNNER_CONTRACT.md"
            and path.relative_to(actual_root).parts[0] != "reference-runner"
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
