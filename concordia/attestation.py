"""Reputation attestation generation (§9.6).

Every completed Concordia session — whether it ends in agreement, rejection,
or expiry — produces a Reputation Attestation: a signed, structured record
of what happened.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import unicodedata
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .cosign import canonical_cosign_bytes
from .message import compute_hash
from .signing import KeyPair, canonical_json, sign_message, verify_signature
from .types import (
    OutcomeStatus,
    ResolutionMechanism,
    SessionState,
)

if TYPE_CHECKING:
    from .session import Session

# C-H2 outcome-binding (Option B): v0.2.0 introduces the top-level
# ``countersignatures`` map. Each present party signs the canonical issuance
# snapshot of the WHOLE attestation (every ``signature`` key stripped, and the
# ``countersignatures`` map itself excluded), so the outcome / meta /
# transcript_hash are cryptographically bound at issuance -- not merely
# prover-asserted. A verifier that accepts a >=0.2.0 attestation MUST check this
# map (see ``receipt_bundle.verify_bundle``); a <0.2.0 attestation is read as
# outcome-unbound (legacy, prover-asserted) and is NOT credited, but is NOT an
# error either. See SPEC.md §9.6.
#
# v0.3.0 adds receipt set-binding: ``chain_head`` + ``message_count`` are
# included in the same countersigned issuance snapshot. Per-message signatures
# authenticate links; these two fields make the closing receipt commit to the
# transcript set.
#
# v0.6.0 implements draft-newton-agreement-evidence-00. Issuance uses the
# 0.6.0 closed member set; 0.5.0 remains above the verification floor, and
# below 0.5.0 exits as legacy before signature, freshness, or revocation work.
ATTESTATION_VERSION = "0.6.0"
_SET_BINDING_MIN = (0, 3)
_SEMVER_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z"
)
_SHA256_HEX_RE = re.compile(r"^sha256:[a-f0-9]{64}\Z")
_TIMESTAMP_Z_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,3})?Z\Z"
)
_SIGNATURE_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]{86}==\Z")
_BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_IMPLEMENTED_ATTESTATION_VERSION = (0, 6, 0)
_LEGACY_FLOOR_VERSION = (0, 5, 0)
_MAX_SAFE_INTEGER = (2**53) - 1
MAX_ATTESTATION_ARTIFACT_BYTES = 262_144
MAX_ATTESTATION_JSON_DEPTH = 16
MAX_PARTIES = 64
MAX_EXTENSIONS_USED = 16
MAX_SUMMARY_SCALARS = 1_024
MIN_MESSAGE_COUNT = 1
MAX_MESSAGE_COUNT = 10_000
MAX_RELYING_FRESHNESS_SECONDS = 90 * 24 * 60 * 60
MAX_RELYING_CLOCK_SKEW_SECONDS = 300
TERMINAL_STATES = ("current", "bound-only", "legacy", "not-bound")


@dataclass(frozen=True)
class AttestationVerificationPolicy:
    """Relying-side ceilings for draft-newton-agreement-evidence-00 Section 8."""

    max_evidence_age_seconds: int = MAX_RELYING_FRESHNESS_SECONDS
    max_validity_lifetime_seconds: int = MAX_RELYING_FRESHNESS_SECONDS
    clock_skew_seconds: int = MAX_RELYING_CLOCK_SKEW_SECONDS
    max_artifact_bytes: int = MAX_ATTESTATION_ARTIFACT_BYTES


@dataclass(frozen=True)
class AttestationTerminalResult:
    """Terminal-state verifier result with optional diagnostics."""

    terminal_state: str
    errors: list[str] = field(default_factory=list)
    verified_parties: list[str] = field(default_factory=list)
    signature_checks: int = 0
    revocation_checked: bool = False


class _AttestationStructureError(ValueError):
    """Internal marker for Section 10 step 2 not-bound failures."""


@dataclass(frozen=True)
class AttestationVerifyResult:
    """Result from end-to-end attestation verification."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    schema_errors: list[str] = field(default_factory=list)
    signature_errors: list[str] = field(default_factory=list)
    set_binding_errors: list[str] = field(default_factory=list)
    verified_parties: list[str] = field(default_factory=list)
    set_binding_state: str = "unknown"
    terminal_state: str = "unknown"

# v0.5 SPEC §11.5: generalized attestation-level references[] shape. Per
# §11.5.6 the four canonical type values are receipt, chain_session,
# predicate, mandate. Per §11.5.5 the four canonical relationship values
# are supersedes, extends, fulfills, references. Per §11.5.8 (MUST) unknown
# values for either field are preserved as opaque strings rather than
# rejected, for forward-compat with v0.x extensions.
REFERENCE_TYPES = ("receipt", "chain_session", "predicate", "mandate")
REFERENCE_RELATIONSHIPS = ("supersedes", "extends", "fulfills", "references")
WEAK_RELATIONSHIP = "references"

# draft-newton-agreement-evidence-00 Section 8.3 defines exactly these two
# modes for the attestation format. The removed 0.5.0 window mode is rejected
# at the structure step before any signature work.
VALIDITY_TEMPORAL_MODES = ("absolute", "relative")

# Reference-issuer policy for SPEC §9.7.1. The default window matches the
# specification's worked example. Callers may provide a narrower window, but
# the reference issuer refuses to sign any window spanning more than 90 days.
DEFAULT_ATTESTATION_VALIDITY_SECONDS = 90 * 24 * 60 * 60
MAX_ATTESTATION_VALIDITY_SECONDS = DEFAULT_ATTESTATION_VALIDITY_SECONDS

# L3 hardening (security audit 2026-06-09): attestation meta context is
# constrained at issuance so a party cannot stuff its own raw deal terms
# into the exported record (SPEC §9.6.6 privacy invariant: behavioral
# signals only, never deal terms).
#
# value_range is an ENUMERATED bucket vocabulary, not a free grammar. A
# regex that merely enforced "<low>-<high>_<CCY>" would still let an
# issuer encode the exact price (e.g. "4350-4351_USD"); fixing the bands
# to a 1-5-10 logarithmic scale caps the channel at order-of-magnitude
# granularity, which is exactly what SPEC §9.6.6 promises ("logarithmic
# buckets ... rather than exact amounts"). The full value is
# "<bucket>_<CURRENCY>" where CURRENCY is an ISO 4217-shaped 3-letter
# uppercase code (shape-validated, not enumerated).
VALUE_RANGE_BUCKETS = (
    "0-100",
    "100-500",
    "500-1000",
    "1000-5000",
    "5000-10000",
    "10000-50000",
    "50000-100000",
    "100000-500000",
    "500000-1000000",
    "1000000+",
)
# \Z (not $) so a trailing newline cannot smuggle past the anchor.
_VALUE_RANGE_PATTERN = re.compile(
    r"^(?:" + "|".join(re.escape(b) for b in VALUE_RANGE_BUCKETS) + r")_[A-Z]{3}\Z"
)

# category is a coarse dotted taxonomy path (e.g. "electronics.cameras").
# The character class excludes whitespace and punctuation so prose deal
# terms ("selling at $1200/unit") cannot ride in it; the length cap bounds
# the residual channel.
MAX_CATEGORY_LENGTH = 64
_CATEGORY_PATTERN = re.compile(r"^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\Z")

# references[] caps (L3 + exhaustion lens): bound the count, each string
# field, and the serialized size of the opaque extensions escape hatch.
MAX_REFERENCES = 32
MAX_REFERENCE_TYPE_LENGTH = 64
MAX_REFERENCE_RELATIONSHIP_LENGTH = 64
MAX_REFERENCE_ID_LENGTH = 256
MAX_REFERENCE_OPTIONAL_STRING_LENGTH = 256


def _reference_string(
    value: Any,
    path: str,
    *,
    max_octets: int,
    min_octets: int | None = 1,
) -> str:
    try:
        return _require_string(
            value,
            path,
            min_octets=min_octets,
            max_octets=max_octets,
            no_whitespace=True,
        )
    except _AttestationStructureError as exc:
        if "too short" in str(exc):
            raise ValueError(
                f"{path} must be a non-empty whitespace-free string per SPEC §11.5.6"
            ) from exc
        raise

def _version_tuple(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not _SEMVER_RE.match(value):
        raise _AttestationStructureError(
            "concordia_attestation must be three dot-separated non-negative "
            "integers without leading zeros"
        )
    parts = value.split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def _contains_forbidden_whitespace(value: str) -> bool:
    for ch in value:
        codepoint = ord(ch)
        if ch.isspace():
            return True
        if 0x0000 <= codepoint <= 0x001F:
            return True
        if 0x007F <= codepoint <= 0x009F:
            return True
        if 0x200B <= codepoint <= 0x200F:
            return True
        if 0x2028 <= codepoint <= 0x202E:
            return True
    return False


def _require_nfc(value: str, path: str) -> None:
    _reject_lone_surrogate_string(value, path)
    if unicodedata.normalize("NFC", value) != value:
        raise _AttestationStructureError(f"{path} must be Unicode NFC")


def _require_no_whitespace(value: str, path: str) -> None:
    if _contains_forbidden_whitespace(value):
        raise _AttestationStructureError(f"{path} must not contain whitespace")


def _utf8_len(value: str) -> int:
    return len(value.encode("utf-8"))


def _reject_lone_surrogate_string(value: str, path: str) -> None:
    for ch in value:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise _AttestationStructureError(f"{path} contains an unpaired surrogate")


def _reject_lone_surrogates(value: Any) -> None:
    stack = [("artifact", value)]
    while stack:
        path, current = stack.pop()
        if isinstance(current, str):
            _reject_lone_surrogate_string(current, path)
        elif isinstance(current, dict):
            for key, child in current.items():
                _reject_lone_surrogate_string(key, "object member name")
                stack.append((f"{path}.{key}", child))
        elif isinstance(current, list):
            for index, child in enumerate(current):
                stack.append((f"{path}[{index}]", child))


def _require_string(
    value: Any,
    path: str,
    *,
    min_octets: int | None = None,
    max_octets: int | None = None,
    no_whitespace: bool = False,
) -> str:
    if not isinstance(value, str):
        raise _AttestationStructureError(f"{path} must be a string")
    _require_nfc(value, path)
    if no_whitespace:
        _require_no_whitespace(value, path)
    octets = _utf8_len(value)
    if min_octets is not None and octets < min_octets:
        raise _AttestationStructureError(f"{path} is too short")
    if max_octets is not None and octets > max_octets:
        raise _AttestationStructureError(f"{path} is too long")
    return value


def _require_int(
    value: Any,
    path: str,
    *,
    minimum: int = 0,
    maximum: int = _MAX_SAFE_INTEGER,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise _AttestationStructureError(f"{path} must be an integer")
    if value < minimum or value > maximum:
        raise _AttestationStructureError(f"{path} outside allowed range")
    return value


def _require_number(
    value: Any,
    path: str,
    *,
    minimum: float = 0.0,
    maximum: float | None = None,
) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise _AttestationStructureError(f"{path} must be a number")
    if isinstance(value, int) and abs(value) > _MAX_SAFE_INTEGER:
        raise _AttestationStructureError(f"{path} outside allowed range")
    try:
        number = float(value)
    except OverflowError as exc:
        raise _AttestationStructureError(f"{path} outside allowed range") from exc
    if math.isnan(number) or math.isinf(number):
        raise _AttestationStructureError(f"{path} must be finite")
    if number < minimum or (maximum is not None and number > maximum):
        raise _AttestationStructureError(f"{path} outside allowed range")
    return number


def _parse_rfc3339_z(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP_Z_RE.match(value):
        raise _AttestationStructureError(
            f"{path} must be RFC 3339 date-time with Z offset and at most "
            "three fractional digits"
        )
    _require_nfc(value, path)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _AttestationStructureError(f"{path} is not a valid timestamp") from exc
    return parsed.astimezone(timezone.utc)


def _require_digest(value: Any, path: str) -> str:
    text = _require_string(value, path, no_whitespace=True)
    if not _SHA256_HEX_RE.match(text):
        raise _AttestationStructureError(f"{path} must be sha256:<64 lowercase hex>")
    return text


def _decode_strict_signature(value: Any, path: str) -> bytes:
    text = _require_string(value, path)
    if not _SIGNATURE_B64URL_RE.match(text):
        raise _AttestationStructureError(
            f"{path} must be an 88-character padded base64url Ed25519 signature"
        )
    # For a 64-octet input, the last payload character carries four unused
    # bits. Section 4.4 requires those bits to be zero before decoding.
    if (_BASE64URL_ALPHABET.index(text[85]) & 0x0F) != 0:
        raise _AttestationStructureError(f"{path} has non-zero unused bits")
    try:
        decoded = base64.b64decode(text, altchars=b"-_", validate=True)
    except binascii.Error as exc:
        raise _AttestationStructureError(f"{path} is not valid base64url") from exc
    if len(decoded) != 64:
        raise _AttestationStructureError(f"{path} must decode to 64 octets")
    return decoded


def _json_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _AttestationStructureError("duplicate JSON member name")
        obj[key] = value
    return obj


def _precheck_json_nesting(raw: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            # The raw pre-scan is load-bearing: it bounds parser recursion
            # before Python builds nested containers from untrusted bytes.
            if depth > MAX_ATTESTATION_JSON_DEPTH:
                raise _AttestationStructureError(
                    f"JSON nesting depth exceeds {MAX_ATTESTATION_JSON_DEPTH}"
                )
        elif byte in (0x5D, 0x7D):
            depth = max(0, depth - 1)


def _json_depth(value: Any) -> int:
    max_depth = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, parent_depth = stack.pop()
        if isinstance(current, dict):
            depth = parent_depth + 1
            max_depth = max(max_depth, depth)
            stack.extend((child, depth) for child in current.values())
        elif isinstance(current, list):
            depth = parent_depth + 1
            max_depth = max(max_depth, depth)
            stack.extend((child, depth) for child in current)
    return max_depth


def _loads_strict_json(received: bytes | str) -> dict[str, Any]:
    if isinstance(received, str):
        raw = received.encode("utf-8")
    else:
        raw = received
    _precheck_json_nesting(raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _AttestationStructureError("artifact is not well-formed UTF-8") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_json_object_no_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                _AttestationStructureError("non-finite JSON number")
            ),
        )
    except _AttestationStructureError:
        raise
    except ValueError as exc:
        raise _AttestationStructureError("artifact is not strict JSON") from exc
    if not isinstance(parsed, dict):
        raise _AttestationStructureError("attestation artifact must be a JSON object")
    _reject_lone_surrogates(parsed)
    if _json_depth(parsed) > MAX_ATTESTATION_JSON_DEPTH:
        raise _AttestationStructureError(
            f"JSON nesting depth exceeds {MAX_ATTESTATION_JSON_DEPTH}"
        )
    return parsed


def _require_closed_keys(
    obj: Mapping[str, Any],
    allowed: set[str],
    required: set[str],
    path: str,
) -> None:
    keys = set(obj.keys())
    missing = required - keys
    extra = keys - allowed
    if missing:
        raise _AttestationStructureError(f"{path} missing required members")
    if extra:
        raise _AttestationStructureError(f"{path} contains undefined members")


def _validate_value_range(value_range: Any) -> str:
    """Validate value_range against the enumerated bucket vocabulary.

    Fail-closed: anything outside "<bucket>_<CCY>" raises ValueError.
    The invalid input is deliberately NOT echoed back in the error
    (content-injection lens: attestation errors can land in logs and
    MCP responses).
    """
    if (
        not isinstance(value_range, str)
        or len(value_range) > 32
        or not _VALUE_RANGE_PATTERN.match(value_range)
    ):
        raise ValueError(
            "value_range must be '<bucket>_<CURRENCY>' where bucket is one "
            f"of {VALUE_RANGE_BUCKETS} and CURRENCY is a 3-letter uppercase "
            "code (e.g. '1000-5000_USD'); free-text values are rejected "
            "per SPEC §9.6.6 (attestations carry bucketed context, never "
            "raw deal terms)"
        )
    return value_range


def _validate_category(category: Any) -> str:
    """Validate category as a coarse dotted taxonomy path.

    Fail-closed: prose or oversized input raises ValueError. The invalid
    input is deliberately NOT echoed back in the error.
    """
    if (
        not isinstance(category, str)
        or len(category) > MAX_CATEGORY_LENGTH
        or not _CATEGORY_PATTERN.match(category)
    ):
        raise ValueError(
            "category must be a dotted lowercase taxonomy path of at most "
            f"{MAX_CATEGORY_LENGTH} chars matching "
            "'[a-z0-9_-]+(.[a-z0-9_-]+)*' (e.g. 'electronics.cameras'); "
            "free-text values are rejected per SPEC §9.6.6"
        )
    return category


def _parse_iso8601(ts: str, field_name: str) -> datetime:
    """Parse the attestation timestamp profile from Section 4.4."""
    try:
        return _parse_rfc3339_z(ts, field_name)
    except _AttestationStructureError as e:
        raise ValueError(str(e)) from e


def _validate_validity_temporal(vt: Any) -> dict[str, Any]:
    """Validate a validity_temporal tagged union. Returns the normalized dict."""
    if not isinstance(vt, dict):
        raise ValueError("validity_temporal must be a dict")
    allowed_by_mode = {
        "absolute": {"mode", "from", "until"},
        "relative": {"mode", "from", "duration_seconds"},
    }
    mode = vt.get("mode")
    if mode not in VALIDITY_TEMPORAL_MODES:
        raise ValueError(
            f"validity_temporal.mode {mode!r} not in {VALIDITY_TEMPORAL_MODES}"
        )
    extra = set(vt) - allowed_by_mode[mode]
    if extra:
        raise ValueError("validity_temporal carries undefined member(s)")
    if mode == "absolute":
        required: tuple[str, ...] = ("from", "until")
        missing = [k for k in required if k not in vt]
        if missing:
            raise ValueError(f"validity_temporal[absolute] missing: {missing}")
        frm = _parse_iso8601(vt["from"], "validity_temporal.from")
        until = _parse_iso8601(vt["until"], "validity_temporal.until")
        if until <= frm:
            raise ValueError("validity_temporal[absolute]: until must be after from")
        if (until - frm).total_seconds() > MAX_ATTESTATION_VALIDITY_SECONDS:
            raise ValueError(
                "validity_temporal[absolute] exceeds the reference issuer "
                "maximum lifetime of 7776000 seconds"
            )
        return {"mode": "absolute", "from": vt["from"], "until": vt["until"]}
    if mode == "relative":
        required = ("from", "duration_seconds")
        missing = [k for k in required if k not in vt]
        if missing:
            raise ValueError(f"validity_temporal[relative] missing: {missing}")
        _parse_iso8601(vt["from"], "validity_temporal.from")
        duration = vt["duration_seconds"]
        if not isinstance(duration, int) or duration < 1:
            raise ValueError(
                "validity_temporal[relative].duration_seconds must be a positive int"
            )
        if duration > MAX_ATTESTATION_VALIDITY_SECONDS:
            raise ValueError(
                "validity_temporal[relative] exceeds the reference issuer "
                "maximum lifetime of 7776000 seconds"
            )
        return {"mode": "relative", "from": vt["from"], "duration_seconds": duration}
    raise ValueError("validity_temporal mode is not supported")


def is_valid_now(
    attestation: dict[str, Any], now: datetime | None = None
) -> bool:
    """Return True if the attestation's validity_temporal contains ``now``.

    A pre-0.5 legacy attestation without ``validity_temporal`` returns True so
    callers can continue to inspect legacy signals. A 0.5+ artifact missing the
    required field returns False even when this helper is called without first
    running schema validation. Relying parties still apply their own age and
    lifetime policy under SPEC §9.7.1.
    """
    vt = attestation.get("validity_temporal")
    if vt is None:
        return not _attestation_version_at_least(
            attestation.get("concordia_attestation", ""), 0, 5
        )
    if not isinstance(vt, dict) or "mode" not in vt:
        return False
    now_dt = now or datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    mode = vt["mode"]
    if mode == "absolute":
        frm = _parse_iso8601(vt["from"], "validity_temporal.from")
        until = _parse_iso8601(vt["until"], "validity_temporal.until")
        return frm <= now_dt < until
    if mode == "relative":
        frm = _parse_iso8601(vt["from"], "validity_temporal.from")
        until = frm + timedelta(seconds=int(vt["duration_seconds"]))
        return frm <= now_dt < until
    return False


def _validate_reference(ref: Any, index: int) -> dict[str, Any]:
    """Validate a single attestation-level reference per SPEC §11.5.

    Required keys ``type``, ``id``, ``relationship`` are enforced
    structurally per §11.5.6. ``type`` and ``relationship`` values outside
    the canonical vocabularies (§11.5.5, §11.5.6) are preserved as opaque
    strings per the §11.5.8 MUST forward-compat clause. Read-side schemas
    accept non-empty strings per §11.5.5 and §11.5.8; the canonical
    vocabulary remains the emit-side default. draft-newton-agreement-evidence-00
    removes the reference ``extensions`` member. The -00 verifier applies that
    closed Table 6 member set at 0.5.0 and later.

    L3 hardening (security audit 2026-06-09): every string field is
    length-capped and whitespace-banned (legitimate identifiers such as
    UUIDs, DIDs, URNs, ISO timestamps, and semver never contain
    whitespace, so any \\s indicates prose). Legacy ``extensions`` are
    """
    if not isinstance(ref, dict):
        raise ValueError(
            f"references[{index}] must be a dict, got {type(ref).__name__} "
            f"per SPEC §11.5.6"
        )
    allowed_keys = {"id", "type", "relationship", "version", "signed_at", "signer_did"}
    if set(ref) - allowed_keys:
        raise ValueError(
            f"references[{index}] contains undefined member(s) for "
            "attestation format 0.6.0"
        )
    missing = [k for k in ("type", "id", "relationship") if k not in ref]
    if missing:
        raise ValueError(
            f"references[{index}] missing required keys {missing} "
            f"per SPEC §11.5.6 (id, type, relationship)"
        )
    ref_type = _reference_string(
        ref["type"],
        f"references[{index}].type",
        max_octets=MAX_REFERENCE_TYPE_LENGTH,
    )
    ref_id = _reference_string(
        ref["id"],
        f"references[{index}].id",
        max_octets=MAX_REFERENCE_ID_LENGTH,
    )
    relationship = _reference_string(
        ref["relationship"],
        f"references[{index}].relationship",
        max_octets=MAX_REFERENCE_RELATIONSHIP_LENGTH,
    )
    normalized: dict[str, Any] = {
        "type": ref_type,
        "id": ref_id,
        "relationship": relationship,
    }
    for optional_key in ("version", "signed_at", "signer_did"):
        if optional_key in ref:
            value = ref[optional_key]
            min_octets = 1 if optional_key == "signer_did" else None
            normalized[optional_key] = _reference_string(
                value,
                f"references[{index}].{optional_key}",
                min_octets=min_octets,
                max_octets=MAX_REFERENCE_OPTIONAL_STRING_LENGTH,
            )
    return normalized


def _validate_outcome_shape(outcome: Any) -> None:
    if not isinstance(outcome, dict):
        raise _AttestationStructureError("outcome must be an object")
    _require_closed_keys(
        outcome,
        {"status", "rounds", "duration_seconds", "terms_count", "resolution_mechanism"},
        {"status", "rounds", "duration_seconds"},
        "outcome",
    )
    status = _require_string(outcome["status"], "outcome.status", no_whitespace=True)
    if status not in {"agreed", "rejected", "expired", "withdrawn"}:
        raise _AttestationStructureError("outcome.status is not defined")
    _require_int(outcome["rounds"], "outcome.rounds")
    _require_int(outcome["duration_seconds"], "outcome.duration_seconds")
    if "terms_count" in outcome:
        _require_int(outcome["terms_count"], "outcome.terms_count", minimum=1)
    if "resolution_mechanism" in outcome:
        mechanism = _require_string(
            outcome["resolution_mechanism"],
            "outcome.resolution_mechanism",
            no_whitespace=True,
        )
        if mechanism not in {
            "direct",
            "split",
            "foa",
            "tradeoff",
            "escalation",
            "none",
        }:
            raise _AttestationStructureError(
                "outcome.resolution_mechanism is not defined"
            )


def _validate_behavior_shape(behavior: Any, path: str) -> None:
    if not isinstance(behavior, dict):
        raise _AttestationStructureError(f"{path} must be an object")
    allowed = {
        "offers_made",
        "concessions",
        "concession_magnitude",
        "signals_shared",
        "constraints_declared",
        "constraints_violated",
        "reasoning_provided",
        "withdrawal",
        "response_time_avg_seconds",
    }
    _require_closed_keys(behavior, allowed, set(), path)
    for key in (
        "offers_made",
        "concessions",
        "signals_shared",
        "constraints_declared",
        "constraints_violated",
    ):
        if key in behavior:
            _require_int(behavior[key], f"{path}.{key}")
    if "concession_magnitude" in behavior:
        _require_number(
            behavior["concession_magnitude"],
            f"{path}.concession_magnitude",
            maximum=1.0,
        )
    if "response_time_avg_seconds" in behavior:
        _require_number(
            behavior["response_time_avg_seconds"],
            f"{path}.response_time_avg_seconds",
        )
    for key in ("reasoning_provided", "withdrawal"):
        if key in behavior and not isinstance(behavior[key], bool):
            raise _AttestationStructureError(f"{path}.{key} must be boolean")


def _validate_parties_shape(parties: Any) -> list[str]:
    if not isinstance(parties, list):
        raise _AttestationStructureError("parties must be an array")
    if len(parties) < 2 or len(parties) > MAX_PARTIES:
        raise _AttestationStructureError("parties count outside allowed range")
    agent_ids: list[str] = []
    for index, party in enumerate(parties):
        path = f"parties[{index}]"
        if not isinstance(party, dict):
            raise _AttestationStructureError(f"{path} must be an object")
        _require_closed_keys(
            party,
            {"agent_id", "role", "behavior", "signature"},
            {"agent_id", "role", "behavior", "signature"},
            path,
        )
        agent_id = _require_string(
            party["agent_id"],
            f"{path}.agent_id",
            min_octets=1,
            max_octets=MAX_REFERENCE_ID_LENGTH,
            no_whitespace=True,
        )
        role = _require_string(party["role"], f"{path}.role", no_whitespace=True)
        if role not in {"initiator", "responder", "mediator", "witness"}:
            raise _AttestationStructureError(f"{path}.role is not defined")
        _validate_behavior_shape(party["behavior"], f"{path}.behavior")
        _decode_strict_signature(party["signature"], f"{path}.signature")
        agent_ids.append(agent_id)
    if len(set(agent_ids)) != len(agent_ids):
        raise _AttestationStructureError("parties agent identifiers must be distinct")
    return agent_ids


def _validate_meta_shape(meta: Any) -> None:
    if not isinstance(meta, dict):
        raise _AttestationStructureError("meta must be an object")
    _require_closed_keys(
        meta,
        {"category", "value_range", "extensions_used", "mediator_invoked"},
        set(),
        "meta",
    )
    if "category" in meta:
        try:
            _validate_category(meta["category"])
        except ValueError as exc:
            raise _AttestationStructureError("meta.category malformed") from exc
    if "value_range" in meta:
        try:
            _validate_value_range(meta["value_range"])
        except ValueError as exc:
            raise _AttestationStructureError("meta.value_range malformed") from exc
    if "extensions_used" in meta:
        extensions = meta["extensions_used"]
        if not isinstance(extensions, list) or len(extensions) > MAX_EXTENSIONS_USED:
            raise _AttestationStructureError("meta.extensions_used malformed")
        for index, extension in enumerate(extensions):
            _require_string(
                extension,
                f"meta.extensions_used[{index}]",
                min_octets=1,
                max_octets=64,
                no_whitespace=True,
            )
    if "mediator_invoked" in meta and not isinstance(meta["mediator_invoked"], bool):
        raise _AttestationStructureError("meta.mediator_invoked must be boolean")


def _validate_references_shape(references: Any) -> None:
    if not isinstance(references, list) or len(references) > MAX_REFERENCES:
        raise _AttestationStructureError("references malformed")
    for index, reference in enumerate(references):
        try:
            _validate_reference(reference, index)
        except ValueError as exc:
            raise _AttestationStructureError("references malformed") from exc
        if "signed_at" in reference:
            _parse_rfc3339_z(reference["signed_at"], f"references[{index}].signed_at")


def _validate_validity_temporal_shape(
    validity_temporal: Any,
) -> tuple[datetime, datetime, float]:
    if not isinstance(validity_temporal, dict):
        raise _AttestationStructureError("validity_temporal must be an object")
    mode = validity_temporal.get("mode")
    if mode == "absolute":
        _require_closed_keys(
            validity_temporal,
            {"mode", "from", "until"},
            {"mode", "from", "until"},
            "validity_temporal",
        )
        start = _parse_rfc3339_z(validity_temporal["from"], "validity_temporal.from")
        end = _parse_rfc3339_z(validity_temporal["until"], "validity_temporal.until")
        if end <= start:
            raise _AttestationStructureError("validity_temporal interval is empty")
        lifetime = (end - start).total_seconds()
        return start, end, lifetime
    if mode == "relative":
        _require_closed_keys(
            validity_temporal,
            {"mode", "from", "duration_seconds"},
            {"mode", "from", "duration_seconds"},
            "validity_temporal",
        )
        start = _parse_rfc3339_z(validity_temporal["from"], "validity_temporal.from")
        lifetime = _require_int(
            validity_temporal["duration_seconds"],
            "validity_temporal.duration_seconds",
            minimum=1,
        )
        if lifetime > MAX_RELYING_FRESHNESS_SECONDS:
            raise _AttestationStructureError("validity lifetime exceeds maximum")
        return start, start + timedelta(seconds=lifetime), lifetime
    raise _AttestationStructureError("validity_temporal mode is not defined")


def _validate_countersignature_shape(
    countersignatures: Any,
    agent_ids: list[str],
) -> None:
    if not isinstance(countersignatures, dict):
        raise _AttestationStructureError("countersignatures must be an object")
    if set(countersignatures.keys()) != set(agent_ids):
        raise _AttestationStructureError("countersignatures must match parties")
    for agent_id, signature in countersignatures.items():
        _require_string(
            agent_id,
            "countersignatures member name",
            min_octets=1,
            max_octets=MAX_REFERENCE_ID_LENGTH,
            no_whitespace=True,
        )
        _decode_strict_signature(signature, f"countersignatures[{agent_id}]")


def _validate_attestation_structure(
    attestation: dict[str, Any],
) -> tuple[tuple[int, int, int], datetime, datetime, datetime, float, list[str]]:
    version = _version_tuple(attestation.get("concordia_attestation", ""))
    if version < _LEGACY_FLOOR_VERSION:
        raise AssertionError("legacy artifacts must exit before structure validation")
    root_required = {
        "concordia_attestation",
        "attestation_id",
        "session_id",
        "timestamp",
        "outcome",
        "parties",
        "meta",
        "transcript_hash",
        "chain_head",
        "message_count",
        "validity_temporal",
        "countersignatures",
    }
    root_allowed = root_required | {"summary", "references"}
    _require_closed_keys(attestation, root_allowed, root_required, "attestation")
    _require_string(
        attestation["attestation_id"],
        "attestation_id",
        min_octets=1,
        max_octets=MAX_REFERENCE_ID_LENGTH,
        no_whitespace=True,
    )
    _require_string(
        attestation["session_id"],
        "session_id",
        min_octets=1,
        max_octets=MAX_REFERENCE_ID_LENGTH,
        no_whitespace=True,
    )
    timestamp = _parse_rfc3339_z(attestation["timestamp"], "timestamp")
    _validate_outcome_shape(attestation["outcome"])
    agent_ids = _validate_parties_shape(attestation["parties"])
    _validate_meta_shape(attestation["meta"])
    _require_digest(attestation["transcript_hash"], "transcript_hash")
    _require_digest(attestation["chain_head"], "chain_head")
    _require_int(
        attestation["message_count"],
        "message_count",
        minimum=MIN_MESSAGE_COUNT,
        maximum=MAX_MESSAGE_COUNT,
    )
    start, end, lifetime = _validate_validity_temporal_shape(
        attestation["validity_temporal"],
    )
    _validate_countersignature_shape(attestation["countersignatures"], agent_ids)
    if "summary" in attestation:
        summary = _require_string(attestation["summary"], "summary")
        if len(summary) > MAX_SUMMARY_SCALARS:
            raise _AttestationStructureError("summary is too long")
    if "references" in attestation:
        _validate_references_shape(attestation["references"])
    return version, timestamp, start, end, lifetime, agent_ids


def _map_state_to_outcome(state: SessionState) -> OutcomeStatus:
    """Map a terminal session state to an attestation outcome status."""
    mapping = {
        SessionState.AGREED: OutcomeStatus.AGREED,
        SessionState.REJECTED: OutcomeStatus.REJECTED,
        SessionState.EXPIRED: OutcomeStatus.EXPIRED,
    }
    return mapping.get(state, OutcomeStatus.REJECTED)


def _attestation_version_at_least(ver: str, major: int, minor: int) -> bool:
    """Return True iff ``ver`` is semver-shaped and at least ``major.minor``.

    Malformed or missing versions are treated as legacy for dual-accept
    read paths: reported as unbound, not raised as a parse error.
    """
    if not isinstance(ver, str) or not _SEMVER_RE.match(ver):
        return False
    parts = ver.split(".")
    return (int(parts[0]), int(parts[1])) >= (major, minor)


def evaluate_receipt_set_binding(
    attestation: dict[str, Any],
    transcript: list[dict[str, Any]] | None = None,
) -> tuple[str, list[str]]:
    """Validate the v0.3.0 receipt set-binding fields.

    Returns ``(state, errors)`` where ``state`` is one of:
      - ``"bound"``: >=0.3.0 fields are present, well-formed, and, when a
        transcript was supplied, match its final message hash and length.
      - ``"legacy_set_unbound"``: <0.3.0 or malformed version. This is
        reported, not an error, and must not be credited as set-bound.
      - ``"error"``: >=0.3.0 but required fields are missing, malformed, or do
        not match the supplied transcript.
    """
    ver = attestation.get("concordia_attestation", "")
    if not _attestation_version_at_least(ver, *_SET_BINDING_MIN):
        return "legacy_set_unbound", []

    errors: list[str] = []
    chain_head = attestation.get("chain_head")
    message_count = attestation.get("message_count")

    if not isinstance(chain_head, str) or not _SHA256_HEX_RE.match(chain_head):
        errors.append(
            f"version {ver} requires chain_head as sha256:<64 lowercase hex>"
        )
    if (
        not isinstance(message_count, int)
        or isinstance(message_count, bool)
        or message_count < 1
    ):
        errors.append(f"version {ver} requires message_count as an integer >= 1")

    if transcript is not None:
        if not isinstance(transcript, list):
            errors.append("transcript must be a list when verifying set binding")
        elif not transcript:
            errors.append("transcript must contain at least one message")
        else:
            expected_count = len(transcript)
            expected_head = compute_hash(transcript[-1])
            if (
                isinstance(message_count, int)
                and not isinstance(message_count, bool)
                and message_count != expected_count
            ):
                errors.append(
                    f"message_count mismatch: attestation has {message_count}, "
                    f"transcript has {expected_count}"
                )
            if (
                isinstance(chain_head, str)
                and _SHA256_HEX_RE.match(chain_head)
                and chain_head != expected_head
            ):
                errors.append(
                    "chain_head mismatch: attestation does not match transcript "
                    "final message hash"
                )

    if errors:
        return "error", errors
    return "bound", []


# ---------------------------------------------------------------------------
# C-H2 outcome-binding (Option B): issuance countersignature primitive.
#
# The payload a party countersigns is the canonical issuance snapshot of the
# WHOLE attestation: ``canonical_json(strip_signatures(att minus
# countersignatures))``. Because ``strip_signatures`` (reused verbatim from
# ``cosign.py``) recursively removes every ``"signature"`` key, the payload
# excludes every ``parties[*].signature`` and any future
# ``fulfillment.counterparty_attestation.signature``; we additionally exclude
# the top-level ``countersignatures`` map (which is NOT under a ``"signature"``
# key) so a countersignature never covers itself or a sibling's
# countersignature. Every party therefore signs byte-identical payload bytes,
# mutually independent -- exactly like the cosign lane.
#
# base64url is PADDED here (``urlsafe_b64encode(...).decode()``) to match the
# per-party ``sign_message`` convention and the JS SDK's strict, padding-
# requiring verifier. ``cosign.cosign_receipt`` returns UNPADDED for the compact
# receipt co-signature lane; do NOT reuse it on this lane.
# ---------------------------------------------------------------------------


def _countersign_payload(attestation: dict[str, Any]) -> bytes:
    """Canonical bytes a party countersigns: the issuance snapshot.

    ``canonical_json(strip_signatures({k: v ... if k != "countersignatures"}))``
    -- every ``"signature"`` key stripped recursively AND the top-level
    ``countersignatures`` map excluded, so the payload is stable and
    self-independent across all parties.
    """
    snapshot = {
        k: v for k, v in attestation.items() if k != "countersignatures"
    }
    return canonical_cosign_bytes(snapshot)


def countersign_attestation(attestation: dict[str, Any], key_pair: KeyPair) -> str:
    """Produce a party's padded-base64url Ed25519 countersignature.

    Signs ``_countersign_payload(attestation)`` with ``key_pair``. PADDED
    base64url, matching ``sign_message`` and the JS verifier.
    """
    raw = key_pair.private_key.sign(_countersign_payload(attestation))
    return base64.urlsafe_b64encode(raw).decode()


def verify_attestation_countersignature(
    attestation: dict[str, Any],
    sig_b64: str,
    public_key: Ed25519PublicKey,
) -> bool:
    """Verify one issuance countersignature over the attestation snapshot.

    Recomputes ``_countersign_payload(attestation)``, base64url-decodes the
    signature, and checks it under ``public_key``. Fail-closed: ANY exception
    (malformed base64, non-canonicalizable snapshot, wrong key, wrong type)
    returns ``False`` -- mirrors ``signing.verify_signature``.
    """
    try:
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        payload = _countersign_payload(attestation)
        raw = base64.urlsafe_b64decode(sig_b64)
        public_key.verify(raw, payload)
        return True
    except Exception:
        return False


def _policy_error(policy: AttestationVerificationPolicy) -> str | None:
    if policy.max_artifact_bytes > MAX_ATTESTATION_ARTIFACT_BYTES:
        return "configured artifact size exceeds Section 11.7 cap"
    if policy.max_evidence_age_seconds > MAX_RELYING_FRESHNESS_SECONDS:
        return "configured evidence age exceeds Section 8.1 cap"
    if policy.max_validity_lifetime_seconds > MAX_RELYING_FRESHNESS_SECONDS:
        return "configured validity lifetime exceeds Section 8.1 cap"
    if policy.clock_skew_seconds > MAX_RELYING_CLOCK_SKEW_SECONDS:
        return "configured clock skew exceeds Section 8.1 cap"
    for value in (
        policy.max_artifact_bytes,
        policy.max_evidence_age_seconds,
        policy.max_validity_lifetime_seconds,
        policy.clock_skew_seconds,
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return "configured relying-party policy is malformed"
    return None


def _not_bound(error: str, *, signature_checks: int = 0) -> AttestationTerminalResult:
    return AttestationTerminalResult(
        terminal_state="not-bound",
        errors=[error],
        signature_checks=signature_checks,
    )


def verify_attestation_artifact(
    received: bytes | str,
    key_resolver: Callable[[str], Ed25519PublicKey | None],
    *,
    expected_session_id: str,
    expected_party_ids: set[str] | frozenset[str],
    now: datetime | None = None,
    policy: AttestationVerificationPolicy | None = None,
    revocation_checker: Callable[[dict[str, Any]], bool | None] | None = None,
) -> AttestationTerminalResult:
    """Verify an attestation artifact under the four-state Section 10 result.

    The order is load-bearing: legacy version exit happens at step 2 before
    any signature, temporal, or revocation check, and every structural failure
    returns ``not-bound`` before key resolution.
    """
    active_policy = policy or AttestationVerificationPolicy()
    policy_failure = _policy_error(active_policy)
    if policy_failure is not None:
        return _not_bound(policy_failure)

    raw = received.encode("utf-8") if isinstance(received, str) else received
    if len(raw) > active_policy.max_artifact_bytes:
        return _not_bound("artifact exceeds maximum size")

    try:
        attestation = _loads_strict_json(raw)
        version = _version_tuple(attestation.get("concordia_attestation", ""))
        if version > _IMPLEMENTED_ATTESTATION_VERSION:
            return _not_bound("attestation version exceeds implemented ceiling")
        if version < _LEGACY_FLOOR_VERSION:
            return AttestationTerminalResult(terminal_state="legacy")
        (
            _version,
            timestamp,
            interval_start,
            interval_end,
            lifetime_seconds,
            agent_ids,
        ) = _validate_attestation_structure(attestation)
    except _AttestationStructureError as exc:
        return _not_bound(str(exc))
    except Exception:
        return _not_bound("attestation structure is malformed")

    resolved_keys: dict[str, Ed25519PublicKey] = {}
    try:
        for agent_id in agent_ids:
            public_key = key_resolver(agent_id)
            if not isinstance(public_key, Ed25519PublicKey):
                return _not_bound("party key could not be resolved")
            resolved_keys[agent_id] = public_key
    except Exception:
        return _not_bound("party key could not be resolved")

    signature_checks = 0
    for agent_id in agent_ids:
        signature = attestation["countersignatures"][agent_id]
        signature_checks += 1
        if not verify_attestation_countersignature(
            attestation,
            signature,
            resolved_keys[agent_id],
        ):
            return _not_bound(
                "countersignature verification failed",
                signature_checks=signature_checks,
            )

    now_dt = now or datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)
    now_utc = now_dt.astimezone(timezone.utc)
    skew = timedelta(seconds=active_policy.clock_skew_seconds)
    if timestamp - now_utc > skew or interval_start - now_utc > skew:
        return _not_bound(
            "attestation timestamp or interval start is future-dated",
            signature_checks=signature_checks,
        )
    if lifetime_seconds > active_policy.max_validity_lifetime_seconds:
        return _not_bound(
            "validity lifetime exceeds relying-party maximum",
            signature_checks=signature_checks,
        )
    if not (interval_start <= now_utc <= interval_end):
        return _not_bound(
            "current time is outside validity_temporal interval",
            signature_checks=signature_checks,
        )
    evidence_anchor = min(timestamp, interval_start)
    if (now_utc - evidence_anchor).total_seconds() > active_policy.max_evidence_age_seconds:
        return _not_bound(
            "evidence age exceeds relying-party maximum",
            signature_checks=signature_checks,
        )

    revocation_checked = False
    terminal_after_revocation = "bound-only"
    if revocation_checker is not None:
        try:
            revoked = revocation_checker(attestation)
        except Exception:
            revoked = None
        if revoked is True:
            return _not_bound("attestation is revoked", signature_checks=signature_checks)
        if revoked is False:
            revocation_checked = True
            terminal_after_revocation = "current"

    try:
        expected_session = _require_string(
            expected_session_id,
            "expected_session_id",
            min_octets=1,
            max_octets=MAX_REFERENCE_ID_LENGTH,
            no_whitespace=True,
        )
        if not isinstance(expected_party_ids, (set, frozenset)):
            return _not_bound(
                "expected_party_ids is malformed",
                signature_checks=signature_checks,
            )
        expected = {
            _require_string(
                party,
                "expected_party_ids member",
                min_octets=1,
                max_octets=MAX_REFERENCE_ID_LENGTH,
                no_whitespace=True,
            )
            for party in expected_party_ids
        }
    except _AttestationStructureError:
        return _not_bound(
            "relying-party binding inputs are malformed",
            signature_checks=signature_checks,
        )
    if attestation["session_id"] != expected_session:
        return _not_bound(
            "session_id does not match relying-party expectation",
            signature_checks=signature_checks,
        )
    if set(agent_ids) != expected:
        return _not_bound(
            "parties do not match relying-party expectation",
            signature_checks=signature_checks,
        )

    return AttestationTerminalResult(
        terminal_state=terminal_after_revocation,
        verified_parties=agent_ids,
        signature_checks=signature_checks,
        revocation_checked=revocation_checked,
    )


def verify_attestation(
    attestation: dict[str, Any],
    public_keys: Mapping[str, Ed25519PublicKey],
    transcript: list[dict[str, Any]] | None = None,
) -> AttestationVerifyResult:
    """Legacy verifier for artifacts below 0.5.0; not the -00 procedure.

    Artifacts whose ``concordia_attestation`` value is well formed and at or
    above 0.5.0 delegate to ``verify_attestation_artifact`` so the SDK reports
    one terminal-state answer for those bytes. Below 0.5.0, this keeps the old
    schema, party-signature, outcome-binding, and set-binding checks for callers
    that still inspect legacy artifacts.
    """
    schema_errors: list[str] = []
    signature_errors: list[str] = []
    set_binding_errors: list[str] = []
    warnings: list[str] = []
    verified_parties: list[str] = []
    set_binding_state = "unknown"

    try:
        if not isinstance(attestation, dict):
            return AttestationVerifyResult(
                valid=False,
                errors=["attestation must be a dict"],
                schema_errors=["attestation must be a dict"],
                set_binding_state="error",
                terminal_state="not-bound",
            )
        if not isinstance(public_keys, Mapping):
            signature_errors.append(
                "public_keys must map agent_id to Ed25519PublicKey"
            )
            public_keys = {}

        version_value = attestation.get("concordia_attestation")
        if isinstance(version_value, str) and _SEMVER_RE.match(version_value):
            version = _version_tuple(version_value)
            if version >= _LEGACY_FLOOR_VERSION:
                parties = attestation.get("parties")
                expected_parties = {
                    party.get("agent_id")
                    for party in parties
                    if isinstance(party, dict) and isinstance(party.get("agent_id"), str)
                } if isinstance(parties, list) else set()
                session_id = attestation.get("session_id")
                payload = json.dumps(
                    attestation,
                    separators=(",", ":"),
                    sort_keys=True,
                    ensure_ascii=False,
                ).encode("utf-8")
                terminal = verify_attestation_artifact(
                    payload,
                    lambda agent_id: public_keys.get(agent_id),
                    expected_session_id=session_id if isinstance(session_id, str) else "",
                    expected_party_ids=expected_parties,
                )
                errors = terminal.errors if terminal.terminal_state == "not-bound" else []
                warnings = (
                    ["attestation revocation status is undetermined"]
                    if terminal.terminal_state == "bound-only"
                    else []
                )
                return AttestationVerifyResult(
                    valid=terminal.terminal_state in {"current", "bound-only"},
                    errors=errors,
                    warnings=warnings,
                    signature_errors=errors,
                    verified_parties=terminal.verified_parties,
                    set_binding_state=terminal.terminal_state,
                    terminal_state=terminal.terminal_state,
                )

        from .schema_validator import validate_attestation

        schema_errors = validate_attestation(attestation)

        parties = attestation.get("parties")
        if not isinstance(parties, list):
            signature_errors.append("parties must be a list")
        else:
            for index, party in enumerate(parties):
                if not isinstance(party, dict):
                    signature_errors.append(f"parties[{index}] must be a dict")
                    continue
                party_dict = dict(party)
                agent_id = party_dict.get("agent_id")
                if not isinstance(agent_id, str) or not agent_id:
                    signature_errors.append(
                        f"parties[{index}] missing agent_id"
                    )
                    continue
                signature = party_dict.get("signature")
                if not isinstance(signature, str) or not signature:
                    signature_errors.append(
                        f"parties[{index}] ('{agent_id}') missing signature"
                    )
                    continue
                public_key = public_keys.get(agent_id)
                if not isinstance(public_key, Ed25519PublicKey):
                    signature_errors.append(
                        f"parties[{index}] ('{agent_id}') missing Ed25519 public key"
                    )
                    continue
                if verify_signature(party_dict, signature, public_key):
                    verified_parties.append(agent_id)
                else:
                    signature_errors.append(
                        f"parties[{index}] ('{agent_id}') invalid signature"
                    )

        # Import lazily because receipt_bundle uses the countersignature
        # primitive defined in this module. The shared evaluator keeps this
        # standalone path aligned with bundle and competence-proof verification.
        from .receipt_bundle import evaluate_outcome_binding

        outcome_binding_state, outcome_binding_error = evaluate_outcome_binding(
            attestation,
            lambda agent_id: public_keys.get(agent_id),
        )
        if outcome_binding_state == "error":
            signature_errors.append(
                outcome_binding_error or "attestation outcome binding failed"
            )
        elif outcome_binding_state == "unbound":
            warnings.append(
                "attestation is legacy outcome-unbound (<0.2.0); outcome is "
                "not authenticated"
            )

        set_binding_state, set_binding_errors = evaluate_receipt_set_binding(
            attestation,
            transcript,
        )
        if set_binding_state == "legacy_set_unbound":
            warnings.append(
                "attestation is legacy set-unbound (<0.3.0); chain_head and "
                "message_count are not credited as bound"
            )

        errors = [*schema_errors, *signature_errors, *set_binding_errors]
        return AttestationVerifyResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            schema_errors=schema_errors,
            signature_errors=signature_errors,
            set_binding_errors=set_binding_errors,
            verified_parties=verified_parties,
            set_binding_state=set_binding_state,
            terminal_state="legacy" if len(errors) == 0 else "not-bound",
        )
    except Exception:
        signature_errors.append("attestation verification failed closed")
        errors = [*schema_errors, *signature_errors, *set_binding_errors]
        return AttestationVerifyResult(
            valid=False,
            errors=errors,
            warnings=warnings,
            schema_errors=schema_errors,
            signature_errors=signature_errors,
            set_binding_errors=set_binding_errors,
            verified_parties=verified_parties,
            set_binding_state="error",
            terminal_state="not-bound",
        )


def generate_attestation(
    session: Session,
    key_pairs: dict[str, KeyPair],
    *,
    category: str | None = None,
    value_range: str | None = None,
    resolution_mechanism: ResolutionMechanism = ResolutionMechanism.DIRECT,
    references: list[dict[str, Any]] | None = None,
    validity_temporal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a reputation attestation from a concluded session.

    Args:
        session: The concluded Session.
        key_pairs: Mapping of agent_id → KeyPair for signing.
        category: Optional transaction category (e.g.
            'electronics.cameras'). Must be a dotted lowercase taxonomy
            path of at most 64 chars; free text is rejected (§9.6.6).
        value_range: Optional value bucket (e.g. '1000-5000_USD'). Must
            be '<bucket>_<CURRENCY>' where bucket is one of the
            VALUE_RANGE_BUCKETS logarithmic bands and CURRENCY is a
            3-letter uppercase code; free text is rejected (§9.6.6).
        resolution_mechanism: How agreement was reached.
        references: Optional list of attestation-level references per
            SPEC §11.5. Each entry is a dict with required keys
            ``{type, id, relationship}`` and optional keys
            ``{version, signed_at, signer_did}`` per the 0.6.0 attestation
            field definitions.
            Canonical ``type`` values: receipt, chain_session, predicate,
            mandate (§11.5.6). Canonical ``relationship`` values:
            supersedes, extends, fulfills, references (§11.5.5).
            Implementations preserve unknown values as opaque strings per
            §11.5.8 forward-compat. The layering boundary against
            envelope-level references is documented in §11.5.4. Added in
            v0.4.0 (WP2); ratified in v0.5 (SPEC §11.5).
        validity_temporal: Temporal validity window. Tagged
            union with two modes:
            ``{mode: "absolute", from, until}`` for fixed clock bounds,
            or ``{mode: "relative", from, duration_seconds}`` for "valid
            for N seconds from anchor."
            When absent, the reference issuer supplies an absolute 90-day
            window anchored at the attestation timestamp. Supplied windows
            may be narrower but may not exceed that declared reference-issuer
            maximum. Added in v0.4.0 (WP3); required on new issuance in v0.5.0.

    Returns:
        A dict conforming to the attestation schema (§9.6.2).
    """
    if not session.is_terminal and session.state != SessionState.EXPIRED:
        raise ValueError(
            f"Cannot generate attestation for session in state {session.state.value}"
        )

    outcome_status = _map_state_to_outcome(session.state)

    # Count terms from the open message body, if available
    terms_count = 0
    if session.terms:
        terms_count = len(session.terms)

    # Build outcome
    outcome: dict[str, Any] = {
        "status": outcome_status.value,
        "rounds": session.round_count,
        "duration_seconds": session.duration_seconds(),
    }
    if terms_count > 0:
        outcome["terms_count"] = terms_count
    outcome["resolution_mechanism"] = resolution_mechanism.value

    # Build party records with signatures
    missing_party_keys = set(session.parties) - set(key_pairs)
    if missing_party_keys:
        raise ValueError(
            "Cannot generate attestation: every listed party must have a signing key"
        )
    parties: list[dict[str, Any]] = []
    for agent_id, role in session.parties.items():
        behavior = session.get_behavior(agent_id)
        party_record: dict[str, Any] = {
            "agent_id": agent_id,
            "role": role.value,
            "behavior": behavior.to_dict(),
        }
        # Sign the party's behavioral record
        sig = sign_message(party_record, key_pairs[agent_id])
        party_record["signature"] = sig
        parties.append(party_record)

    if not session.transcript:
        raise ValueError(
            "Cannot generate attestation for session with empty transcript; "
            "v0.3.0 receipts require chain_head and message_count"
        )

    # Compute transcript commitments. ``transcript_hash`` is the legacy
    # whole-transcript digest; ``chain_head`` is the final message hash defined
    # by §9.3 and pins the chain through cascading prev_hash links.
    transcript_hash = _compute_transcript_hash(session.transcript)
    chain_head = compute_hash(session.transcript[-1])
    message_count = len(session.transcript)

    # Build meta
    meta: dict[str, Any] = {
        "extensions_used": [],
        "mediator_invoked": False,
    }
    # L3 hardening (security audit 2026-06-09): caller-supplied context is
    # validated fail-closed at issuance so raw deal terms can never ride
    # in an exported attestation (§9.6.6).
    if category:
        meta["category"] = _validate_category(category)
    if value_range:
        meta["value_range"] = _validate_value_range(value_range)

    # WP2 v0.4.0: validate and normalize references[] if supplied
    if references:
        if len(references) > MAX_REFERENCES:
            raise ValueError(
                f"references[] exceeds the maximum of {MAX_REFERENCES} "
                f"entries"
            )
        normalized_refs = [
            _validate_reference(ref, i) for i, ref in enumerate(references)
        ]
    else:
        normalized_refs = []

    issued_at = datetime.now(timezone.utc).replace(microsecond=0)
    timestamp = issued_at.strftime("%Y-%m-%dT%H:%M:%SZ")

    # WP3/v0.5: every newly issued attestation is time-bounded. A caller may
    # choose a narrower policy window; omitting it selects the documented
    # reference-issuer default rather than emitting unbounded evidence.
    if validity_temporal is None:
        default_until = issued_at + timedelta(
            seconds=DEFAULT_ATTESTATION_VALIDITY_SECONDS
        )
        validity_temporal = {
            "mode": "absolute",
            "from": timestamp,
            "until": default_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    normalized_vt = _validate_validity_temporal(validity_temporal)

    attestation: dict[str, Any] = {
        "concordia_attestation": ATTESTATION_VERSION,
        "attestation_id": f"att_{uuid.uuid4().hex[:8]}",
        "session_id": session.session_id,
        "timestamp": timestamp,
        "outcome": outcome,
        "parties": parties,
        "meta": meta,
        "transcript_hash": transcript_hash,
        "chain_head": chain_head,
        "message_count": message_count,
        "references": normalized_refs,
        "validity_temporal": normalized_vt,
    }

    # Attach a plaintext 4-line summary for quick human/agent inspection.
    attestation["summary"] = generate_receipt_summary(attestation)

    # C-H2 outcome-binding (Option B): one issuance countersignature per listed
    # party over the FULLY-ASSEMBLED snapshot (after summary).
    # Added LAST so the payload (`_countersign_payload`) excludes the map; the
    # helper also excludes it explicitly as belt-and-suspenders. The missing-key
    # guard above is the fail-closed invariant: a 0.6.0 issuer must never emit
    # signature:"" or omit a party countersignature.
    countersignatures: dict[str, str] = {
        agent_id: countersign_attestation(attestation, key_pairs[agent_id])
        for agent_id in session.parties
    }
    attestation["countersignatures"] = countersignatures

    return attestation


def generate_receipt_summary(receipt: dict[str, Any]) -> str:
    """Generate a 4-line plaintext summary of a session receipt/attestation.

    Format:
        Parties: <party_a_did_short>, <party_b_did_short>
        Topic: <topic or N/A>
        Outcome: <AGREED/REJECTED/EXPIRED>
        Transcript hash: <first 16 chars of hash>

    Args:
        receipt: A full attestation dict (as produced by generate_attestation).

    Returns:
        A four-line plaintext string (newline-separated).
    """
    def _short(did: str) -> str:
        if not did:
            return "unknown"
        # Keep last 12 chars for short display (or whole string if shorter).
        return did if len(did) <= 16 else f"...{did[-12:]}"

    parties = receipt.get("parties", []) or []
    party_ids = [p.get("agent_id", "") for p in parties]
    while len(party_ids) < 2:
        party_ids.append("")
    parties_line = f"Parties: {_short(party_ids[0])}, {_short(party_ids[1])}"

    meta = receipt.get("meta", {}) or {}
    topic = meta.get("category") or meta.get("topic") or "N/A"
    topic_line = f"Topic: {topic}"

    outcome = receipt.get("outcome", {}) or {}
    status = outcome.get("status", "")
    outcome_line = f"Outcome: {str(status).upper() if status else 'UNKNOWN'}"

    transcript_hash = receipt.get("transcript_hash", "") or ""
    # Strip sha256: prefix if present, take first 16 chars of the hex digest.
    digest = transcript_hash.split(":", 1)[1] if ":" in transcript_hash else transcript_hash
    hash_line = f"Transcript hash: {digest[:16]}"

    return "\n".join([parties_line, topic_line, outcome_line, hash_line])


def _compute_transcript_hash(transcript: list[dict[str, Any]]) -> str:
    """Compute a single SHA-256 hash over the entire transcript."""
    import hashlib

    from .signing import canonical_json

    combined = b""
    for msg in transcript:
        combined += canonical_json(msg)
    digest = hashlib.sha256(combined).hexdigest()
    return f"sha256:{digest}"
