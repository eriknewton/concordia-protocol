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
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, TypeAlias

from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from concordia.canonicalization import canonicalize_jcs  # noqa: E402
from concordia.cmpc.canonical import (  # noqa: E402
    canonicalize_cascade_decision_record,
)
from concordia.cmpc.schemas import (  # noqa: E402
    CASCADE_DECISION_RECORD_SCHEMA,
    REVOCATION_RECORD_SCHEMA,
    validate_cascade_decision_record,
)
from concordia.schema_validator import (  # noqa: E402
    _RAW_TERM_PATTERNS,
    validate_approval_receipt,
)
from concordia.signing import canonical_json  # noqa: E402

ReasonClass: TypeAlias = Literal["schema", "signature", "digest", "binding", "temporal"]
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
    "revocation_record.schema.json": REPO_ROOT / "schemas" / "revocation_record.schema.json",
    "fulfillment_attestation.schema.json": REPO_ROOT
    / "schemas"
    / "fulfillment_attestation.schema.json",
}

FIXTURE_DIRS = (INTEROP_1404, INTEROP_1920)
PROFILES = (
    "decision-object-v1",
    "offer-binding-v1",
    "receipt-v1",
    "revocation-v1",
    "cascade-decision-v1",
    "fulfillment-attestation-v1",
)
RECORD_TYPES = (
    "decision_object",
    "approval_receipt",
    "revocation_record",
    "cascade_decision_record",
    "fulfillment_attestation",
)


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

    def to_json(self) -> dict[str, Any]:
        return {
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


def sha256_jcs(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonicalize_jcs(value)).hexdigest()


def without_signature(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "signature"}


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


def schema_is_valid(schema: dict[str, Any], data: Any) -> bool:
    return not any(Draft202012Validator(schema).iter_errors(data))


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
            return Evaluation(False, "binding")
        return Evaluation(True)

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


def build_vectors() -> list[Vector]:
    f1404 = fixture_1404()
    f1920 = fixture_1920()
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
    return sorted(copied)


def write_vector_group(
    dest_root: Path,
    vectors: list[Vector],
    *,
    section: Literal["positive", "mutation"],
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
            "canary": 0,
            "diag_canonical_bytes": len(diag_files),
        },
        "files": {
            "fixtures": fixture_files,
            "schemas": schema_files,
            "positive": positive_files,
            "mutation": mutation_files,
            "canary": [],
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
    positive_vectors = build_vectors()
    mutation_vectors = build_mutation_vectors()
    assert_vectors_execute(positive_vectors)
    assert_vectors_execute(mutation_vectors)
    clean_output(dest_root)
    fixture_files = copy_fixtures(dest_root)
    schema_files = copy_schemas(dest_root)
    positive_files, positive_diag_files = write_vector_group(
        dest_root, positive_vectors, section="positive"
    )
    mutation_files, mutation_diag_files = write_vector_group(
        dest_root, mutation_vectors, section="mutation"
    )
    write_manifest(
        dest_root,
        fixture_files=fixture_files,
        schema_files=schema_files,
        positive_files=positive_files,
        mutation_files=mutation_files,
        diag_files=sorted(positive_diag_files + mutation_diag_files),
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
