#!/usr/bin/env python3
"""Clean-room reference runner for Concordia conformance vectors."""

from __future__ import annotations

import importlib.util

assert (
    importlib.util.find_spec("concordia") is None
), "conformance reference runner requires concordia to be absent from import path"

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import sys
import warnings
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import rfc8785

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from jsonschema import Draft202012Validator, RefResolver
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

Json = Any
Outcome = Literal["accept", "reject"]
Regression = Literal[
    "preimage-includes-signature",
    "schema-skipped",
    "decision-id-not-recomputed",
]

VECTOR_SCHEMA_VERSION = "concordia-conformance-vector/v1-draft"
PROFILE_ORDER = (
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
RECORD_TYPES = {
    "decision_object",
    "approval_receipt",
    "revocation_record",
    "cascade_decision_record",
    "fulfillment_attestation",
    "attestation",
    "predicate",
    "mandate",
    "cosign_receipt",
}
REQUIRED_VECTOR_FIELDS = {
    "schema_version",
    "id",
    "title",
    "source_fixture",
    "record_type",
    "verification_profile",
    "input",
    "context",
    "expected",
}
RAW_TERM_PATTERNS = (
    re.compile(r"[$€£¥]\s*\d", re.IGNORECASE),
    re.compile(r"\b(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|CNY|INR)\s*\d", re.IGNORECASE),
    re.compile(
        r"\b\d+(?:[.,]\d+)?\s*(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|CNY|INR)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bprice\s*:", re.IGNORECASE),
    re.compile(r"\b(?:qty|quantity)\s*[:=]?\s*\d+\b", re.IGNORECASE),
    re.compile(r"\b\d+\s*(?:units?|items?|pcs|pieces)\b", re.IGNORECASE),
)


class Reject(Exception):
    """The vector does not satisfy its verification profile."""


def reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is not allowed: {value}")


def load_json(path: Path) -> Json:
    return json.loads(path.read_text(encoding="utf-8"), parse_constant=reject_json_constant)


def b64url_decode(value: Json) -> bytes:
    if not isinstance(value, str):
        raise Reject("base64url value is not a string")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except Exception as exc:
        raise Reject("invalid base64url value") from exc


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode()


def jcs_bytes(value: Json) -> bytes:
    try:
        encoded = rfc8785.dumps(value)
    except Exception as exc:
        raise Reject("JCS canonicalization failed") from exc
    return bytes(encoded)


def sha256_jcs(value: Json) -> str:
    return "sha256:" + hashlib.sha256(jcs_bytes(value)).hexdigest()


def without_top_level(data: Json, keys: set[str]) -> dict[str, Json]:
    if not isinstance(data, dict):
        raise Reject("input is not an object")
    return {key: value for key, value in data.items() if key not in keys}


def parse_datetime(value: Json) -> datetime:
    if not isinstance(value, str):
        raise Reject("timestamp is not a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Reject("timestamp is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def schema_file(suite_base: Path, schema_name: str) -> Path:
    path = suite_base / "conformance" / "vectors" / "schemas" / schema_name
    if not path.is_file():
        raise Reject(f"schema is missing: {schema_name}")
    return path


def schema_store(suite_base: Path) -> dict[str, Json]:
    schemas: dict[str, Json] = {}
    schema_dir = suite_base / "conformance" / "vectors" / "schemas"
    for path in schema_dir.glob("*.json"):
        schema = load_json(path)
        if isinstance(schema, dict) and isinstance(schema.get("$id"), str):
            schemas[schema["$id"]] = schema
    return schemas


def validate_schema(suite_base: Path, schema_name: str, data: Json) -> None:
    schema = load_json(schema_file(suite_base, schema_name))
    resolver = RefResolver.from_schema(schema, store=schema_store(suite_base))
    errors = list(Draft202012Validator(schema, resolver=resolver).iter_errors(data))
    if errors:
        raise Reject("schema validation failed")


def resolve_object(name: Json, input_data: Json, context: Json) -> Json:
    if not isinstance(name, str):
        raise Reject("object reference is not a string")
    if name == "input":
        return input_data
    if not name.startswith("context."):
        raise Reject("unsupported object reference")
    current = context
    for part in name.removeprefix("context.").split("."):
        if not isinstance(current, dict) or part not in current:
            raise Reject("missing context object")
        current = current[part]
    return current


def resolve_pointer(root: Json, pointer: Json) -> Json:
    if not isinstance(pointer, str):
        raise Reject("JSON pointer is not a string")
    if pointer == "":
        return root
    if not pointer.startswith("/"):
        raise Reject("invalid JSON pointer")
    current = root
    for raw_part in pointer.split("/")[1:]:
        part = raw_part.replace("~1", "/").replace("~0", "~")
        try:
            if isinstance(current, list):
                current = current[int(part)]
            elif isinstance(current, dict):
                current = current[part]
            else:
                raise Reject("JSON pointer crosses a scalar")
        except (KeyError, IndexError, ValueError) as exc:
            raise Reject("JSON pointer is missing") from exc
    return current


def resolve_side(side: Json, input_data: Json, context: Json) -> Json:
    if not isinstance(side, dict):
        raise Reject("comparison side is not an object")
    root = resolve_object(side.get("object"), input_data, context)
    return resolve_pointer(root, side.get("pointer"))


def verify_ed25519(public_key_b64url: Json, signature_b64url: Json, payload: bytes) -> None:
    try:
        VerifyKey(b64url_decode(public_key_b64url)).verify(payload, b64url_decode(signature_b64url))
    except BadSignatureError as exc:
        raise Reject("signature verification failed") from exc
    except Exception as exc:
        raise Reject("signature verification failed") from exc


def has_reference(
    data: Json,
    *,
    relationship: str,
    allowed_types: set[str] | None = None,
    id_value: Json | None = None,
) -> bool:
    if not isinstance(data, dict):
        return False
    references = data.get("references")
    if not isinstance(references, list):
        return False
    for reference in references:
        if not isinstance(reference, dict):
            continue
        if reference.get("relationship") != relationship:
            continue
        if allowed_types is not None and reference.get("type") not in allowed_types:
            continue
        if id_value is not None and reference.get("id") != id_value:
            continue
        return True
    return False


def signature_envelope(input_data: Json, algorithm: str) -> Mapping[str, Json]:
    if not isinstance(input_data, dict):
        raise Reject("input is not an object")
    signature = input_data.get("signature")
    if not isinstance(signature, dict):
        raise Reject("signature is missing")
    if signature.get("alg") != algorithm:
        raise Reject("signature algorithm is wrong")
    return signature


def signed_preimage(
    input_data: Json,
    context: Json,
    regression: Regression | None,
) -> bytes:
    if regression == "preimage-includes-signature":
        if (
            isinstance(input_data, dict)
            and isinstance(context, dict)
            and "signature_preimage_value" in context
        ):
            preimage = copy.deepcopy(input_data)
            if not isinstance(preimage.get("signature"), dict):
                raise Reject("signature is missing")
            preimage["signature"]["value"] = context["signature_preimage_value"]
            return jcs_bytes(preimage)
        return jcs_bytes(input_data)
    return jcs_bytes(without_top_level(input_data, {"signature"}))


def strip_signatures_recursive(value: Json) -> Json:
    if isinstance(value, list):
        return [strip_signatures_recursive(item) for item in value]
    if isinstance(value, dict):
        return {
            key: strip_signatures_recursive(item)
            for key, item in value.items()
            if key != "signature"
        }
    return value


def countersign_preimage(input_data: Json) -> bytes:
    return jcs_bytes(
        strip_signatures_recursive(
            without_top_level(input_data, {"countersignatures"})
        )
    )


def cosign_preimage(input_data: Json) -> bytes:
    return jcs_bytes(strip_signatures_recursive(input_data))


def canonical_sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def bare_signature(input_data: Json) -> str:
    if not isinstance(input_data, dict):
        raise Reject("input is not an object")
    signature = input_data.get("signature")
    if not isinstance(signature, str) or not signature:
        raise Reject("signature is missing")
    return signature


def require_algorithm(input_data: Json, algorithm: str) -> None:
    if not isinstance(input_data, dict):
        raise Reject("input is not an object")
    if input_data.get("algorithm") != algorithm:
        raise Reject("signature algorithm is wrong")


def ed25519_did_key(public_key_bytes: bytes) -> str:
    if len(public_key_bytes) != 32:
        raise Reject("Ed25519 public key is not 32 bytes")
    return "did:key:z" + b64url_encode(b"\xed\x01" + public_key_bytes).rstrip("=")


def public_key_from_did_key(did: Json) -> bytes:
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise Reject("counterparty DID is not did:key")
    decoded = b64url_decode(did.removeprefix("did:key:z"))
    if len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        raise Reject("counterparty DID is not Ed25519 did:key")
    return decoded[2:]


def validate_json_schema_object(schema: Json) -> None:
    if not isinstance(schema, dict):
        raise Reject("constraint schema is not an object")
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        raise Reject("constraint schema is invalid") from exc


def validate_action(schema: Json, action: Json) -> None:
    if action is None:
        return
    validate_json_schema_object(schema)
    errors = list(Draft202012Validator(schema).iter_errors(action))
    if errors:
        raise Reject("action violates constraints")


def scope_restriction_to_schema(scope: Json) -> Json:
    if not isinstance(scope, dict) or not scope:
        raise Reject("scope restriction is invalid")
    json_schema_keys = {
        "$schema",
        "$id",
        "$ref",
        "$defs",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "allOf",
        "anyOf",
        "oneOf",
        "not",
        "enum",
        "const",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "pattern",
        "minItems",
        "maxItems",
        "format",
    }
    if any(key in json_schema_keys for key in scope):
        validate_json_schema_object(scope)
        return scope
    if set(scope) == {"max_spend"} and isinstance(scope.get("max_spend"), int | float):
        return {
            "type": "object",
            "properties": {
                "max_spend": {"type": "number", "maximum": scope["max_spend"]}
            },
        }
    raise Reject("scope restriction is unsupported")


def walk_key_strings(value: Json, pointer: str = "") -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_pointer = f"{pointer}/{key.replace('~', '~0').replace('/', '~1')}"
            items.append((key_pointer, key))
            items.extend(walk_key_strings(child, key_pointer))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            items.extend(walk_key_strings(child, f"{pointer}/{index}"))
    elif isinstance(value, str):
        items.append((pointer, value))
    return items


def contains_raw_term(input_data: Json) -> bool:
    for pointer, value in walk_key_strings(input_data):
        if pointer == "/signature/value" or pointer.endswith("/signature"):
            continue
        if pointer.startswith("/countersignatures/"):
            continue
        for pattern in RAW_TERM_PATTERNS:
            if pattern.search(value):
                return True
    return False


def require_vector_shape(vector: Json) -> tuple[str, Json, dict[str, Json], str]:
    if not isinstance(vector, dict):
        raise Reject("vector is not an object")
    missing = REQUIRED_VECTOR_FIELDS.difference(vector)
    if missing:
        raise Reject("vector is missing required fields")
    if vector["schema_version"] != VECTOR_SCHEMA_VERSION:
        raise Reject("vector schema_version is unsupported")
    vector_id = vector["id"]
    if not isinstance(vector_id, str) or not vector_id:
        raise Reject("vector id is invalid")
    record_type = vector["record_type"]
    if record_type not in RECORD_TYPES:
        raise Reject("record_type is unsupported")
    profile = vector["verification_profile"]
    if profile not in PROFILE_ORDER:
        raise Reject("verification_profile is unsupported")
    expected = vector["expected"]
    if expected not in {"accept", "reject"}:
        raise Reject("expected outcome is invalid")
    context = vector["context"]
    if not isinstance(context, dict):
        raise Reject("context is not an object")
    return vector_id, vector["input"], context, profile


def verify_decision_object(input_data: Json, context: dict[str, Json]) -> None:
    if sha256_jcs(input_data) != context.get("expected_decision_id"):
        raise Reject("decision digest mismatch")


def verify_offer_binding(input_data: Json, context: dict[str, Json]) -> None:
    checks = context.get("checks")
    if not isinstance(checks, list) or not checks:
        raise Reject("offer-binding checks are missing")
    for check in checks:
        if not isinstance(check, dict):
            raise Reject("offer-binding check is not an object")
        kind = check.get("kind")
        if kind == "jcs-sha256":
            source = resolve_object(check.get("source"), input_data, context)
            if sha256_jcs(source) != check.get("expected"):
                raise Reject("digest check failed")
        elif kind == "json-pointer-equal":
            left = resolve_side(check.get("left"), input_data, context)
            right = resolve_side(check.get("right"), input_data, context)
            if left != right:
                raise Reject("binding check failed")
        else:
            raise Reject("unknown offer-binding check kind")


def verify_receipt(
    suite_base: Path,
    input_data: Json,
    context: dict[str, Json],
    regression: Regression | None,
) -> None:
    validate_schema(suite_base, "approval_receipt.schema.json", input_data)
    if not has_reference(
        input_data,
        relationship="approves",
        allowed_types={"negotiation_session", "a2cn:negotiation_session"},
    ):
        raise Reject("approval reference is missing")
    signature = signature_envelope(input_data, "Ed25519")
    public_keys = context.get("public_keys_b64url")
    if not isinstance(public_keys, dict):
        raise Reject("issuer public key is missing")
    verify_ed25519(
        public_keys.get("issuer"),
        signature.get("value"),
        signed_preimage(input_data, context, regression),
    )
    if not isinstance(input_data, dict):
        raise Reject("receipt input is not an object")
    if parse_datetime(input_data.get("expires_at")) < parse_datetime(context.get("now")):
        raise Reject("receipt is expired")
    scope = input_data.get("scope")
    if not isinstance(scope, dict):
        raise Reject("receipt scope is missing")
    if sha256_jcs(context.get("offer")) != scope.get("offer_hash"):
        raise Reject("offer hash mismatch")


def verify_revocation(
    suite_base: Path,
    input_data: Json,
    context: dict[str, Json],
    regression: Regression | None,
) -> None:
    validate_schema(suite_base, "revocation_record.schema.json", input_data)
    if not isinstance(input_data, dict):
        raise Reject("revocation input is not an object")
    if not has_reference(
        input_data,
        relationship="revokes",
        id_value=input_data.get("revoked_artifact_id"),
    ):
        raise Reject("revocation reference is missing")
    signature = signature_envelope(input_data, "EdDSA")
    public_keys = context.get("public_keys_b64url")
    if not isinstance(public_keys, dict):
        raise Reject("issuer public key is missing")
    verify_ed25519(
        public_keys.get("issuer"),
        signature.get("value"),
        signed_preimage(input_data, context, regression),
    )


def cascade_preimage(input_data: Json) -> bytes:
    return jcs_bytes(without_top_level(input_data, {"decision_id", "signature"}))


def verify_cascade(
    suite_base: Path,
    input_data: Json,
    context: dict[str, Json],
    regression: Regression | None,
) -> None:
    if regression != "schema-skipped":
        validate_schema(suite_base, "cascade_decision_record.schema.json", input_data)
    if not isinstance(input_data, dict):
        raise Reject("cascade input is not an object")
    preimage = cascade_preimage(input_data)
    claimed_id = input_data.get("decision_id")
    if not isinstance(claimed_id, str):
        raise Reject("decision_id is missing")
    if regression != "decision-id-not-recomputed":
        if hashlib.sha256(preimage).hexdigest() != claimed_id:
            raise Reject("decision_id mismatch")
    expected_decision_id = context.get("expected_decision_id")
    if expected_decision_id is not None and f"sha256:{claimed_id}" != expected_decision_id:
        raise Reject("expected decision_id mismatch")
    signature = signature_envelope(input_data, "EdDSA")
    public_keys = context.get("public_keys_b64url")
    if not isinstance(public_keys, dict):
        raise Reject("issuer public key is missing")
    signature_preimage = (
        jcs_bytes(without_top_level(input_data, {"signature"}))
        if regression == "decision-id-not-recomputed"
        else preimage
    )
    verify_ed25519(public_keys.get("issuer"), signature.get("value"), signature_preimage)


def verify_fulfillment(
    suite_base: Path,
    input_data: Json,
    context: dict[str, Json],
    regression: Regression | None,
) -> None:
    validate_schema(suite_base, "fulfillment_attestation.schema.json", input_data)
    if not isinstance(input_data, dict):
        raise Reject("fulfillment input is not an object")
    if not has_reference(
        input_data,
        relationship="fulfills",
        id_value=input_data.get("agreement_attestation_id"),
    ):
        raise Reject("fulfillment reference is missing")
    signature = signature_envelope(input_data, "Ed25519")
    preimage = signed_preimage(input_data, context, regression)
    verify_ed25519(context.get("public_key_b64url"), signature.get("value"), preimage)
    canonical_sha256 = context.get("canonical_sha256")
    if canonical_sha256 is not None and "sha256:" + hashlib.sha256(preimage).hexdigest() != canonical_sha256:
        raise Reject("canonical digest mismatch")
    seed = context.get("seed_ed25519_ascii")
    if seed is not None:
        if not isinstance(seed, str):
            raise Reject("seed is not a string")
        seed_bytes = seed.encode("utf-8")
        if len(seed_bytes) != 32:
            raise Reject("seed is not 32 bytes")
        signing_key = SigningKey(seed_bytes)
        if b64url_encode(signing_key.verify_key.encode()) != context.get("public_key_b64url"):
            raise Reject("seed public key mismatch")
        signature_b64url = context.get("signature_b64url")
        if signature_b64url is not None:
            derived_signature = b64url_encode(signing_key.sign(preimage).signature)
            if derived_signature != signature_b64url or derived_signature != signature.get("value"):
                raise Reject("seed signature mismatch")
    join_keys = context.get("join_keys", {})
    if not isinstance(join_keys, dict):
        raise Reject("join_keys is not an object")
    if "charge_ref" in join_keys and input_data.get("charge_ref") != join_keys["charge_ref"]:
        raise Reject("charge_ref mismatch")
    if "action_ref" in join_keys and input_data.get("action_ref") != join_keys["action_ref"]:
        raise Reject("action_ref mismatch")
    if context.get("forbid_raw_deal_terms") and contains_raw_term(input_data):
        raise Reject("raw deal terms are present")


def verify_attestation(
    suite_base: Path,
    input_data: Json,
    context: dict[str, Json],
) -> None:
    if context.get("forbid_raw_deal_terms") and contains_raw_term(input_data):
        raise Reject("raw deal terms are present")
    validate_schema(suite_base, "attestation.schema.json", input_data)
    if not isinstance(input_data, dict):
        raise Reject("attestation input is not an object")
    public_keys = context.get("public_keys_b64url")
    if not isinstance(public_keys, dict):
        raise Reject("attestation public keys are missing")
    parties = input_data.get("parties")
    if not isinstance(parties, list):
        raise Reject("attestation parties are missing")
    verified: list[str] = []
    for party in parties:
        if not isinstance(party, dict):
            raise Reject("attestation party is not an object")
        agent_id = party.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            raise Reject("attestation party agent_id is missing")
        public_key = public_keys.get(agent_id)
        if not isinstance(public_key, str):
            raise Reject("attestation party public key is missing")
        verify_ed25519(public_key, bare_signature(party), jcs_bytes(without_top_level(party, {"signature"})))
        verified.append(agent_id)
    expected = context.get("expected_verified_parties")
    if expected is not None:
        if not isinstance(expected, list) or sorted(verified) != sorted(expected):
            raise Reject("attestation verified party set mismatch")


def verify_attestation_countersign(
    suite_base: Path,
    input_data: Json,
    context: dict[str, Json],
) -> None:
    validate_schema(suite_base, "attestation.schema.json", input_data)
    if not isinstance(input_data, dict):
        raise Reject("attestation input is not an object")
    public_keys = context.get("public_keys_b64url")
    countersigners = context.get("countersigners")
    countersignatures = input_data.get("countersignatures")
    if (
        not isinstance(public_keys, dict)
        or not isinstance(countersigners, list)
        or not isinstance(countersignatures, dict)
    ):
        raise Reject("attestation countersignature inputs are missing")
    preimage = countersign_preimage(input_data)
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None and canonical_sha256(preimage) != expected_digest:
        raise Reject("attestation countersignature digest mismatch")
    for signer in countersigners:
        if not isinstance(signer, str):
            raise Reject("countersigner is not a string")
        signature = countersignatures.get(signer)
        public_key = public_keys.get(signer)
        if not isinstance(signature, str) or not isinstance(public_key, str):
            raise Reject("countersignature or key is missing")
        verify_ed25519(public_key, signature, preimage)


def verify_predicate(
    suite_base: Path,
    input_data: Json,
    context: dict[str, Json],
) -> None:
    validate_schema(suite_base, "predicate.json", input_data)
    if not isinstance(input_data, dict):
        raise Reject("predicate input is not an object")
    require_algorithm(input_data, "EdDSA")
    preimage = jcs_bytes(without_top_level(input_data, {"signature"}))
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None and canonical_sha256(preimage) != expected_digest:
        raise Reject("predicate digest mismatch")
    public_key = context.get("public_key_b64url")
    if not isinstance(public_key, str):
        raise Reject("predicate public key is missing")
    verify_ed25519(public_key, bare_signature(input_data), preimage)
    if input_data.get("status") != "active":
        raise Reject("predicate is not active")
    now = parse_datetime(context.get("now"))
    if parse_datetime(input_data.get("expires_at")) < now:
        raise Reject("predicate is expired")


def mandate_preimage(input_data: Json) -> bytes:
    return jcs_bytes(without_top_level(input_data, {"signature"}))


def validate_mandate_common(
    suite_base: Path,
    input_data: Json,
    context: dict[str, Json],
) -> dict[str, Json]:
    validate_schema(suite_base, "mandate.schema.json", input_data)
    if not isinstance(input_data, dict):
        raise Reject("mandate input is not an object")
    require_algorithm(input_data, "EdDSA")
    preimage = mandate_preimage(input_data)
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None and canonical_sha256(preimage) != expected_digest:
        raise Reject("mandate digest mismatch")
    public_key = context.get("issuer_public_key_b64url")
    if not isinstance(public_key, str):
        raise Reject("mandate issuer public key is missing")
    verify_ed25519(public_key, bare_signature(input_data), preimage)
    if input_data.get("status", "active") != "active":
        raise Reject("mandate is not active")

    validity = input_data.get("validity")
    if not isinstance(validity, dict):
        raise Reject("mandate validity is missing")
    mode = validity.get("mode")
    now = parse_datetime(context.get("now"))
    if mode == "windowed":
        if parse_datetime(validity.get("not_before")) > now:
            raise Reject("mandate is not yet valid")
        if parse_datetime(validity.get("not_after")) < now:
            raise Reject("mandate is expired")
    elif mode == "sequence":
        if context.get("sequence_key") != validity.get("sequence_key"):
            raise Reject("mandate sequence key mismatch")
    elif mode == "state_bound":
        if context.get("state_active") is not True:
            raise Reject("mandate state is not active")
    else:
        raise Reject("mandate validity mode is unsupported")

    constraints = input_data.get("constraints")
    validate_json_schema_object(constraints)
    return input_data


def verify_mandate_profile(
    suite_base: Path,
    input_data: Json,
    context: dict[str, Json],
) -> None:
    mandate = validate_mandate_common(suite_base, input_data, context)
    validate_action(mandate.get("constraints"), context.get("action"))


def verify_delegation_chain_profile(
    suite_base: Path,
    input_data: Json,
    context: dict[str, Json],
) -> None:
    mandate = validate_mandate_common(suite_base, input_data, context)
    chain = mandate.get("delegation_chain")
    if not isinstance(chain, list) or not chain:
        raise Reject("delegation chain is missing")
    public_keys = context.get("delegation_public_keys_b64url")
    if not isinstance(public_keys, dict):
        raise Reject("delegation public keys are missing")
    if not isinstance(chain[0], dict) or chain[0].get("delegator") != mandate.get("issuer"):
        raise Reject("delegation chain root mismatch")
    if not isinstance(chain[-1], dict) or chain[-1].get("delegate") != mandate.get("subject"):
        raise Reject("delegation chain tail mismatch")

    effective_constraints: list[Json] = [mandate.get("constraints")]
    previous_delegate: Json | None = None
    for index, link in enumerate(chain):
        if not isinstance(link, dict):
            raise Reject("delegation link is not an object")
        if previous_delegate is not None and link.get("delegator") != previous_delegate:
            raise Reject("delegation chain continuity mismatch")
        delegator = link.get("delegator")
        if not isinstance(delegator, str):
            raise Reject("delegation link delegator is missing")
        public_key = public_keys.get(delegator)
        if not isinstance(public_key, str):
            raise Reject("delegation link public key is missing")
        require_algorithm(link, "EdDSA")
        verify_ed25519(public_key, bare_signature(link), jcs_bytes(without_top_level(link, {"signature"})))
        if "scope_restriction" in link:
            effective_constraints.append(scope_restriction_to_schema(link["scope_restriction"]))
        previous_delegate = link.get("delegate")

    if len(effective_constraints) == 1:
        validate_action(effective_constraints[0], context.get("action"))
    else:
        validate_action({"allOf": effective_constraints}, context.get("action"))


def verify_cosign(input_data: Json, context: dict[str, Json]) -> None:
    if not isinstance(input_data, dict):
        raise Reject("cosign input is not an object")
    counterparty_did = context.get("counterparty_did")
    publisher_did = context.get("publisher_did")
    public_key_b64url = context.get("counterparty_public_key_b64url")
    if (
        not isinstance(counterparty_did, str)
        or not isinstance(publisher_did, str)
        or not isinstance(public_key_b64url, str)
    ):
        raise Reject("cosign context is missing")
    if counterparty_did == publisher_did:
        raise Reject("counterparty DID equals publisher DID")
    public_key = b64url_decode(public_key_b64url)
    if ed25519_did_key(public_key) != counterparty_did:
        raise Reject("did:key derivation mismatch")
    if public_key_from_did_key(counterparty_did) != public_key:
        raise Reject("did:key decoding mismatch")
    parties = input_data.get("parties")
    if not isinstance(parties, list):
        raise Reject("cosign parties are missing")
    matches = [
        party
        for party in parties
        if isinstance(party, dict) and party.get("agent_id") == counterparty_did
    ]
    if len(matches) != 1:
        raise Reject("counterparty party entry is not unique")
    preimage = cosign_preimage(input_data)
    expected_digest = context.get("canonical_sha256")
    if expected_digest is not None and canonical_sha256(preimage) != expected_digest:
        raise Reject("cosign digest mismatch")
    verify_ed25519(public_key_b64url, bare_signature(matches[0]), preimage)


def verify_profile(
    suite_base: Path,
    profile: str,
    input_data: Json,
    context: dict[str, Json],
    regression: Regression | None,
) -> None:
    if profile == "decision-object-v1":
        verify_decision_object(input_data, context)
    elif profile == "offer-binding-v1":
        verify_offer_binding(input_data, context)
    elif profile == "receipt-v1":
        verify_receipt(suite_base, input_data, context, regression)
    elif profile == "revocation-v1":
        verify_revocation(suite_base, input_data, context, regression)
    elif profile == "cascade-decision-v1":
        verify_cascade(suite_base, input_data, context, regression)
    elif profile == "fulfillment-attestation-v1":
        verify_fulfillment(suite_base, input_data, context, regression)
    elif profile == "attestation-v1":
        verify_attestation(suite_base, input_data, context)
    elif profile == "attestation-countersign-v1":
        verify_attestation_countersign(suite_base, input_data, context)
    elif profile == "predicate-v1":
        verify_predicate(suite_base, input_data, context)
    elif profile == "mandate-v1":
        verify_mandate_profile(suite_base, input_data, context)
    elif profile == "delegation-chain-v1":
        verify_delegation_chain_profile(suite_base, input_data, context)
    elif profile == "cosign-v1":
        verify_cosign(input_data, context)
    else:
        raise Reject("unknown verification profile")


def evaluate_vector(
    suite_base: Path,
    vector: Json,
    regression: Regression | None,
) -> Outcome:
    try:
        _, input_data, context, profile = require_vector_shape(vector)
        verify_profile(suite_base, profile, input_data, context, regression)
    except Reject:
        return "reject"
    return "accept"


def suite_base_from_root(suite_root: Path) -> Path:
    if suite_root.name == "vectors" and suite_root.parent.name == "conformance":
        return suite_root.parent.parent
    return suite_root


def manifest_path_from_arg(path_arg: str) -> tuple[Path, Path]:
    suite_root = Path(path_arg).resolve()
    manifest_path = suite_root / "manifest.json" if suite_root.is_dir() else suite_root
    if not manifest_path.is_file():
        raise FileNotFoundError(f"manifest not found: {manifest_path}")
    return manifest_path, suite_base_from_root(manifest_path.parent)


def resolve_manifest_file(suite_base: Path, rel_path: str) -> Path:
    path = suite_base / rel_path
    if not path.is_file():
        raise FileNotFoundError(f"manifest file not found: {rel_path}")
    return path


def active_regression() -> Regression | None:
    raw = os.environ.get("RUNNER_REGRESS")
    if raw is None:
        return None
    if os.environ.get("CONCORDIA_CONFORMANCE_TEST_REGRESS") != "1":
        raise SystemExit(
            "RUNNER_REGRESS is test-only; set CONCORDIA_CONFORMANCE_TEST_REGRESS=1"
        )
    allowed: set[str] = {
        "preimage-includes-signature",
        "schema-skipped",
        "decision-id-not-recomputed",
    }
    if raw not in allowed:
        raise SystemExit(f"unknown RUNNER_REGRESS value: {raw}")
    return raw  # type: ignore[return-value]


def run_suite(suite_arg: str, regression: Regression | None) -> int:
    manifest_path, suite_base = manifest_path_from_arg(suite_arg)
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        print("[FAIL] manifest expected=object got=reject")
        return 1
    files = manifest.get("files")
    if not isinstance(files, dict):
        print("[FAIL] manifest.files expected=object got=reject")
        return 1

    totals = {"positive": 0, "mutation": 0, "canary": 0}
    failures = 0
    for section in ("positive", "mutation", "canary"):
        section_files = files.get(section)
        if not isinstance(section_files, list):
            print(f"[FAIL] manifest.files.{section} expected=list got=reject")
            failures += 1
            continue
        for rel_path in section_files:
            totals[section] += 1
            vector_id = str(rel_path)
            expected: Json = "<unreadable>"
            got: Outcome = "reject"
            try:
                if not isinstance(rel_path, str):
                    raise Reject("manifest path is not a string")
                vector_path = resolve_manifest_file(suite_base, rel_path)
                vector = load_json(vector_path)
                if isinstance(vector, dict) and isinstance(vector.get("id"), str):
                    vector_id = vector["id"]
                    expected = vector.get("expected", "<missing>")
                got = evaluate_vector(suite_base, vector, regression)
            except Exception:
                got = "reject"
            if expected == got:
                print(f"[OK] {vector_id}")
            else:
                failures += 1
                print(f"[FAIL] {vector_id} expected={expected} got={got}")

    executed = sum(totals.values())
    print(
        "[SUMMARY] "
        f"positive={totals['positive']} mutation={totals['mutation']} "
        f"canary={totals['canary']} ok={executed - failures} fail={failures}"
    )
    if executed == 0:
        print("[FAIL] zero vectors executed")
        return 1
    return 0 if failures == 0 else 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", help="path to conformance/vectors/ or manifest.json")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    return run_suite(args.suite, active_regression())


if __name__ == "__main__":
    sys.exit(main())
