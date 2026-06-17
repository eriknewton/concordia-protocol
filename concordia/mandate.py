"""Mandate verification engine for Concordia v0.4.0.

Verifies signed mandate credentials against five checks:
1. Issuer signature (EdDSA / ES256)
2. Validity window (three-mode temporal overlap)
3. Constraint schema compliance
4. Delegation chain integrity (if present)
5. Revocation status (if endpoint provided)

Does not depend on SD-JWT infrastructure but is structurally aligned with
the SD-JWT-based mandate model used by Prove Verified Agent / Mastercard VI.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

import jsonschema

from .models.mandate import (
    MANDATE_JSON_SCHEMA,
    DelegationLink,
    Mandate,
    MandateStatus,
    MandateVerificationResult,
    TemporalMode,
    ValidityWindow,
)
from .signing import (
    ES256KeyPair,
    KeyPair,
    sign_message,
    verify_signature,
)

_JSON_SCHEMA_KEYWORDS = frozenset(
    {
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
)


# ---------------------------------------------------------------------------
# Signing helpers
# ---------------------------------------------------------------------------

def sign_mandate(mandate: Mandate, key_pair: KeyPair | ES256KeyPair) -> Mandate:
    """Sign a mandate credential, returning a new Mandate with signature set.

    Signs over all fields except ``signature`` using canonical JSON.
    """
    mandate_dict = mandate.to_dict()
    # Remove signature field before signing
    mandate_dict.pop("signature", None)

    alg = mandate.algorithm
    sig = sign_message(mandate_dict, key_pair, alg=alg)
    mandate.signature = sig
    return mandate


def sign_delegation(
    link: DelegationLink,
    key_pair: KeyPair | ES256KeyPair,
) -> DelegationLink:
    """Sign a delegation link, returning the link with signature set."""
    link_dict = link.to_dict()
    link_dict.pop("signature", None)
    sig = sign_message(link_dict, key_pair, alg=link.algorithm)
    link.signature = sig
    return link


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def validate_mandate_schema(mandate_dict: dict[str, Any]) -> list[str]:
    """Validate a mandate dict against the JSON Schema.

    Returns a list of error messages (empty if valid).
    """
    errors: list[str] = []
    try:
        jsonschema.validate(mandate_dict, MANDATE_JSON_SCHEMA)
    except jsonschema.ValidationError as e:
        errors.append(f"Schema: {e.message}")
    except jsonschema.SchemaError as e:
        errors.append(f"Schema definition error: {e.message}")
    return errors


def validate_constraints(
    constraints: dict[str, Any],
    action: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    """Validate that constraints are well-formed and optionally check an action.

    If ``action`` is provided, validates the action against the constraints
    treated as a JSON Schema.

    Returns (compliant, errors).
    """
    errors: list[str] = []

    if not constraints:
        errors.append("Constraints must be non-empty")
        return False, errors

    # Check constraints are valid JSON Schema by attempting to compile
    try:
        jsonschema.Draft202012Validator.check_schema(constraints)
    except jsonschema.SchemaError as e:
        errors.append(f"Constraint schema invalid: {e.message}")
        return False, errors

    # If action provided, validate it against constraints-as-schema
    if action is not None:
        try:
            jsonschema.validate(action, constraints)
        except jsonschema.ValidationError as e:
            errors.append(f"Action violates constraint: {e.message}")
            return False, errors

    return True, errors


def _scope_restriction_to_schema(
    scope_restriction: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    """Convert a signed delegation scope restriction into JSON Schema.

    Supported forms are JSON Schema objects and the legacy shorthand
    ``{"max_spend": number}``. Unknown shorthands fail closed.
    """
    if not isinstance(scope_restriction, dict) or not scope_restriction:
        return None, ["unsupported_scope_restriction"]

    if any(key in _JSON_SCHEMA_KEYWORDS for key in scope_restriction):
        try:
            jsonschema.Draft202012Validator.check_schema(scope_restriction)
        except jsonschema.SchemaError as e:
            return None, [f"unsupported_scope_restriction: {e.message}"]
        return scope_restriction, []

    max_spend = scope_restriction.get("max_spend")
    if (
        set(scope_restriction) == {"max_spend"}
        and isinstance(max_spend, int | float)
        and not isinstance(max_spend, bool)
    ):
        return (
            {
                "type": "object",
                "properties": {
                    "max_spend": {
                        "type": "number",
                        "maximum": max_spend,
                    }
                },
            },
            [],
        )

    return None, [
        "unsupported_scope_restriction: expected JSON Schema or max_spend shorthand"
    ]


def compose_effective_constraints(
    constraints: dict[str, Any],
    chain: list[DelegationLink],
) -> tuple[dict[str, Any] | None, list[str]]:
    """Intersect mandate constraints with every delegation scope restriction."""
    schemas = [constraints]
    errors: list[str] = []

    for i, link in enumerate(chain):
        if link.scope_restriction is None:
            continue
        schema, scope_errors = _scope_restriction_to_schema(link.scope_restriction)
        if scope_errors:
            errors.extend(f"link {i}: {error}" for error in scope_errors)
            continue
        if schema is not None:
            schemas.append(schema)

    if errors:
        return None, errors
    if len(schemas) == 1:
        return constraints, []
    return {"allOf": schemas}, []


# ---------------------------------------------------------------------------
# Temporal validity
# ---------------------------------------------------------------------------

def check_temporal_validity(
    validity: ValidityWindow,
    now: datetime | None = None,
    sequence_key: str | None = None,
    state_active: bool | None = None,
) -> tuple[bool, list[str]]:
    """Check whether a mandate's validity window is currently satisfied.

    Args:
        validity: The mandate's validity window.
        now: Current time (defaults to UTC now). Used for windowed mode.
        sequence_key: The sequence key to match (sequence mode).
        state_active: Whether the named state condition is active (state_bound mode).

    Returns (valid, errors).
    """
    errors: list[str] = []

    if now is None:
        now = datetime.now(timezone.utc)

    if validity.mode == TemporalMode.WINDOWED:
        if validity.not_before is None or validity.not_after is None:
            errors.append("Windowed mode requires not_before and not_after")
            return False, errors

        try:
            nb = datetime.fromisoformat(validity.not_before.replace("Z", "+00:00"))
            na = datetime.fromisoformat(validity.not_after.replace("Z", "+00:00"))
        except ValueError as e:
            errors.append(f"Invalid timestamp format: {e}")
            return False, errors

        if now < nb:
            errors.append(f"Mandate not yet valid (not_before: {validity.not_before})")
            return False, errors
        if now > na:
            errors.append(f"Mandate expired (not_after: {validity.not_after})")
            return False, errors

    elif validity.mode == TemporalMode.SEQUENCE:
        if validity.sequence_key is None:
            errors.append("Sequence mode requires sequence_key")
            return False, errors
        if sequence_key is not None and sequence_key != validity.sequence_key:
            errors.append(
                f"Sequence key mismatch: mandate={validity.sequence_key}, "
                f"provided={sequence_key}"
            )
            return False, errors

    elif validity.mode == TemporalMode.STATE_BOUND:
        if validity.state_condition is None:
            errors.append("State-bound mode requires state_condition")
            return False, errors
        if state_active is not None and not state_active:
            errors.append(
                f"State condition '{validity.state_condition}' is not active"
            )
            return False, errors

    return True, errors


# ---------------------------------------------------------------------------
# Delegation chain verification
# ---------------------------------------------------------------------------

def verify_delegation_chain(
    chain: list[DelegationLink],
    issuer: str,
    subject: str,
    public_keys: dict[str, Any],
) -> tuple[bool, list[str]]:
    """Verify the integrity of a delegation chain.

    Checks:
    1. Chain starts from issuer and ends at subject
    2. Each link's delegator matches the previous link's delegate
    3. Each link's signature is valid against the delegator's public key

    Args:
        chain: Ordered list of delegation links.
        issuer: Expected root issuer.
        subject: Expected final delegate (mandate subject).
        public_keys: Map of agent_id -> public_key for signature verification.

    Returns (valid, errors).
    """
    errors: list[str] = []

    if not chain:
        return True, errors  # No chain = direct mandate, always valid

    # Check chain starts from issuer
    if chain[0].delegator != issuer:
        errors.append(
            f"Chain root mismatch: expected issuer={issuer}, "
            f"got delegator={chain[0].delegator}"
        )

    # Check chain ends at subject
    if chain[-1].delegate != subject:
        errors.append(
            f"Chain tail mismatch: expected subject={subject}, "
            f"got delegate={chain[-1].delegate}"
        )

    # Check link continuity and signatures
    for i, link in enumerate(chain):
        # Continuity: each link's delegator = previous link's delegate
        if i > 0 and link.delegator != chain[i - 1].delegate:
            errors.append(
                f"Chain break at link {i}: delegator={link.delegator} "
                f"!= previous delegate={chain[i - 1].delegate}"
            )

        # Signature verification
        pub_key = public_keys.get(link.delegator)
        if pub_key is None:
            errors.append(f"No public key for delegator '{link.delegator}' at link {i}")
            continue

        link_dict = link.to_dict()
        sig = link_dict.pop("signature", "")
        if not sig:
            errors.append(f"Missing signature at link {i}")
            continue

        if not verify_signature(link_dict, sig, pub_key, alg=link.algorithm):
            errors.append(f"Invalid signature at delegation link {i}")

    return len(errors) == 0, errors


# ---------------------------------------------------------------------------
# Revocation check
# ---------------------------------------------------------------------------

# Cap on the revocation-list response we are willing to read into memory. A
# revocation list is a small JSON array of identifiers; anything larger is
# either misconfigured or a resource-exhaustion attempt, so we refuse to keep
# reading past this bound rather than buffering an unbounded body.
_MAX_REVOCATION_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MiB


class RevocationEndpointError(ValueError):
    """The revocation endpoint URL failed validation (scheme/host/SSRF guard)."""


def _ip_is_disallowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True when ``ip`` is in a range we must never let a fetch reach.

    Blocks loopback, private (RFC1918 / unique-local), link-local, multicast,
    reserved, and the unspecified address. IPv4-mapped and 6to4/Teredo IPv6
    forms are unwrapped to their embedded IPv4 address first so an attacker
    cannot smuggle ``::ffff:127.0.0.1`` or ``::ffff:169.254.169.254`` past the
    guard.
    """
    # Unwrap IPv4-mapped / IPv4-compatible / 6to4 / Teredo so an embedded
    # private IPv4 address (e.g. the cloud metadata service 169.254.169.254)
    # cannot hide inside an IPv6 wrapper.
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is None and ip.teredo is not None:
            mapped = ip.teredo[1]
        if mapped is not None:
            ip = mapped

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_revocation_endpoint(endpoint: str) -> str:
    """Validate a revocation-endpoint URL before any network fetch.

    Enforces a strict allowlist so a (trusted-but-possibly-compromised or
    federated) issuer cannot turn the revocation check into a Server-Side
    Request Forgery primitive against the verifier's internal network or a
    cloud metadata service:

    - scheme MUST be ``https`` (no http, file, gopher, ftp, data, ...);
    - the host MUST be a literal IP or a hostname that resolves ONLY to
      public, routable addresses. Every address returned by name resolution
      is checked, so a hostname that resolves to a mix of public and private
      addresses (a DNS-rebinding trick) is rejected.

    Returns the validated endpoint unchanged. Raises
    :class:`RevocationEndpointError` on any failure.
    """
    try:
        parsed = urllib.parse.urlsplit(endpoint)
    except ValueError as exc:  # malformed URL
        raise RevocationEndpointError(f"Malformed revocation endpoint: {exc}") from exc

    if parsed.scheme != "https":
        raise RevocationEndpointError(
            "Revocation endpoint must use https (got "
            f"{parsed.scheme or 'no'} scheme)"
        )

    hostname = parsed.hostname
    if not hostname:
        raise RevocationEndpointError("Revocation endpoint has no host")

    # A trailing dot ("example.com.") is a valid FQDN form; normalise it away
    # so it cannot be used to dodge a host comparison and so resolution is
    # consistent.
    hostname = hostname.rstrip(".")
    if not hostname:
        raise RevocationEndpointError("Revocation endpoint has no host")

    # If the host is a literal IP (v4 or v6, including bracketed IPv6, octal
    # or hex IPv4 forms that ipaddress normalises), check it directly without
    # a DNS lookup.
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None
    if literal_ip is not None:
        if _ip_is_disallowed(literal_ip):
            raise RevocationEndpointError(
                f"Revocation endpoint host {hostname} is not a public address"
            )
        return endpoint

    # Hostname: resolve and require EVERY resolved address to be public. This
    # defeats a DNS-rebinding issuer that resolves to a public address on the
    # first lookup and a private one on the connect.
    try:
        infos = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise RevocationEndpointError(
            f"Revocation endpoint host {hostname} could not be resolved: {exc}"
        ) from exc

    resolved = {info[4][0] for info in infos}
    if not resolved:
        raise RevocationEndpointError(
            f"Revocation endpoint host {hostname} resolved to no addresses"
        )
    for addr in resolved:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:  # pragma: no cover - getaddrinfo returns valid IPs
            raise RevocationEndpointError(
                f"Revocation endpoint host {hostname} resolved to an "
                f"unparseable address {addr!r}"
            )
        if _ip_is_disallowed(ip):
            raise RevocationEndpointError(
                f"Revocation endpoint host {hostname} resolves to a "
                "non-public address"
            )

    return endpoint


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse to follow any redirect.

    Following a redirect would let an issuer point an already-validated https
    URL at an internal target via a 30x ``Location`` (re-validating each hop is
    possible but brittle; for a revocation list there is no legitimate reason
    to chase redirects, so we forbid them outright).
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise RevocationEndpointError(
            f"Revocation endpoint returned a disallowed redirect to {newurl}"
        )


# An opener that performs no redirect following and carries no proxy/auth
# handlers. Built once and reused.
_revocation_opener = urllib.request.build_opener(_NoRedirectHandler())


def check_revocation(
    mandate_id: str,
    endpoint: str,
    timeout: float = 5.0,
    *,
    allow_insecure_endpoint: bool = False,
) -> tuple[bool, list[str]]:
    """Check revocation status against a revocation list endpoint.

    The endpoint should return a JSON object with a ``revoked_ids`` array.
    If the mandate_id is in the list, the mandate is revoked.

    The endpoint URL is validated before any network access: by default it
    must be ``https`` and must not resolve to a private, loopback, link-local,
    multicast, or reserved address (SSRF guard). Redirects are never followed
    and the response body is size-bounded. Set ``allow_insecure_endpoint=True``
    ONLY for a trusted local test server; production verification must leave it
    at the secure default.

    If the endpoint is unreachable or fails validation, the mandate is treated
    as NOT verified (fail-closed per CLAUDE.md constraint #5: never silently
    degrade).

    Returns (not_revoked, errors).
    """
    errors: list[str] = []

    if not allow_insecure_endpoint:
        try:
            validate_revocation_endpoint(endpoint)
        except RevocationEndpointError as e:
            errors.append(f"Revocation endpoint rejected: {e}")
            return False, errors

    try:
        req = urllib.request.Request(
            endpoint,
            headers={"Accept": "application/json"},
            method="GET",
        )
        with _revocation_opener.open(req, timeout=timeout) as resp:
            raw = resp.read(_MAX_REVOCATION_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_REVOCATION_RESPONSE_BYTES:
                errors.append("Revocation response exceeds size limit")
                return False, errors
            data = json.loads(raw.decode("utf-8"))
            revoked_ids = data.get("revoked_ids", [])
            if mandate_id in revoked_ids:
                errors.append(f"Mandate '{mandate_id}' has been revoked")
                return False, errors
    except RevocationEndpointError as e:
        # A disallowed redirect surfaced through the opener.
        errors.append(f"Revocation endpoint rejected: {e}")
        return False, errors
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        # Fail-closed: unreachable endpoint = verification fails
        errors.append(f"Revocation endpoint unreachable: {e}")
        return False, errors
    except (json.JSONDecodeError, ValueError) as e:
        errors.append(f"Invalid revocation response: {e}")
        return False, errors

    return True, errors


# ---------------------------------------------------------------------------
# Full mandate verification
# ---------------------------------------------------------------------------

def verify_mandate(
    mandate: Mandate | dict[str, Any],
    issuer_public_key: Any,
    now: datetime | None = None,
    sequence_key: str | None = None,
    state_active: bool | None = None,
    action: dict[str, Any] | None = None,
    delegation_public_keys: dict[str, Any] | None = None,
    check_revocation_status: bool = True,
    revocation_timeout: float = 5.0,
    require_binding_context: bool = True,
    allow_insecure_revocation_endpoint: bool = False,
) -> MandateVerificationResult:
    """Verify a mandate credential against all five checks.

    Args:
        mandate: Mandate object or dict.
        issuer_public_key: The issuer's public key for signature verification.
        now: Override current time for temporal check.
        sequence_key: Sequence key for sequence-mode validity.
        state_active: Whether state condition is active (state_bound mode).
        action: Optional action dict to validate against mandate constraints.
        delegation_public_keys: Map of agent_id -> public_key for chain verification.
        check_revocation_status: Whether to check revocation endpoint.
        revocation_timeout: Timeout for revocation endpoint check.
        require_binding_context: When true, sequence and state-bound mandates
            require caller-provided binding context before authority is granted.
            Set false only for exploratory validation that is not granting
            authority.
        allow_insecure_revocation_endpoint: When true, skip the https-only and
            private-address SSRF guard on the revocation endpoint. Set true ONLY
            for a trusted local test server; production verification must leave
            it false.

    Returns a MandateVerificationResult.
    """
    # Convert dict to Mandate if needed
    if isinstance(mandate, dict):
        mandate_obj = Mandate.from_dict(mandate)
        mandate_dict = mandate
    else:
        mandate_obj = mandate
        mandate_dict = mandate.to_dict()

    result = MandateVerificationResult(
        valid=False,
        mandate_id=mandate_obj.mandate_id,
        issuer=mandate_obj.issuer,
        subject=mandate_obj.subject,
    )

    # --- Check 0: Schema validation ---
    schema_errors = validate_mandate_schema(mandate_dict)
    if schema_errors:
        result.checks["schema"] = False
        result.errors.extend(schema_errors)
        return result
    result.checks["schema"] = True

    # --- Check 1: Issuer signature ---
    sig = mandate_dict.get("signature", "")
    if not sig:
        result.checks["issuer_signature"] = False
        result.errors.append("Missing mandate signature")
        return result

    signable = {k: v for k, v in mandate_dict.items() if k != "signature"}
    sig_valid = verify_signature(
        signable, sig, issuer_public_key, alg=mandate_obj.algorithm
    )
    result.checks["issuer_signature"] = sig_valid
    if not sig_valid:
        result.errors.append("Invalid issuer signature")
        return result

    # --- Check 1b: Signed lifecycle status ---
    result.checks["lifecycle_status"] = mandate_obj.status == MandateStatus.ACTIVE
    if mandate_obj.status != MandateStatus.ACTIVE:
        result.failure_reason = f"mandate_{mandate_obj.status.value}"
        result.errors.append(
            f"Mandate lifecycle status is {mandate_obj.status.value!r}"
        )
        return result

    # --- Check 2: Temporal validity ---
    if mandate_obj.validity is not None:
        if (
            require_binding_context
            and mandate_obj.validity.mode == TemporalMode.SEQUENCE
            and sequence_key is None
        ):
            result.checks["temporal_validity"] = False
            result.failure_reason = "missing_sequence_context"
            result.errors.append("Sequence mandate requires sequence_key context")
            return result
        if (
            require_binding_context
            and mandate_obj.validity.mode == TemporalMode.STATE_BOUND
            and state_active is None
        ):
            result.checks["temporal_validity"] = False
            result.failure_reason = "missing_state_context"
            result.errors.append("State-bound mandate requires state_active context")
            return result
        temporal_valid, temporal_errors = check_temporal_validity(
            mandate_obj.validity,
            now=now,
            sequence_key=sequence_key,
            state_active=state_active,
        )
        result.checks["temporal_validity"] = temporal_valid
        if not temporal_valid:
            result.errors.extend(temporal_errors)
            return result
    else:
        result.checks["temporal_validity"] = True
        result.warnings.append("No validity window specified — mandate has no temporal bounds")

    # --- Check 3: Constraint compliance ---
    constraint_valid, constraint_errors = validate_constraints(
        mandate_obj.constraints
    )
    result.checks["constraint_compliance"] = constraint_valid
    if not constraint_valid:
        result.errors.extend(constraint_errors)
        return result

    # --- Check 4: Delegation chain ---
    if mandate_obj.delegation_chain:
        chain_keys = delegation_public_keys or {}
        chain_valid, chain_errors = verify_delegation_chain(
            mandate_obj.delegation_chain,
            mandate_obj.issuer,
            mandate_obj.subject,
            chain_keys,
        )
        result.checks["delegation_chain"] = chain_valid
        if not chain_valid:
            result.errors.extend(chain_errors)
            return result
        effective_constraints, scope_errors = compose_effective_constraints(
            mandate_obj.constraints,
            mandate_obj.delegation_chain,
        )
        result.checks["delegation_scope"] = effective_constraints is not None
        if effective_constraints is None:
            result.failure_reason = "unsupported_scope_restriction"
            result.errors.extend(scope_errors)
            return result
    else:
        result.checks["delegation_chain"] = True
        effective_constraints = mandate_obj.constraints

    # --- Check 4b: Effective action scope ---
    constraint_valid, constraint_errors = validate_constraints(
        effective_constraints,
        action=action,
    )
    result.checks["constraint_compliance"] = constraint_valid
    if not constraint_valid:
        result.errors.extend(constraint_errors)
        return result

    # --- Check 5: Revocation status ---
    if mandate_obj.revocation_endpoint and check_revocation_status:
        not_revoked, revocation_errors = check_revocation(
            mandate_obj.mandate_id,
            mandate_obj.revocation_endpoint,
            timeout=revocation_timeout,
            allow_insecure_endpoint=allow_insecure_revocation_endpoint,
        )
        result.checks["revocation_status"] = not_revoked
        if not not_revoked:
            result.errors.extend(revocation_errors)
            return result
    else:
        result.checks["revocation_status"] = True
        if mandate_obj.revocation_endpoint is None:
            result.warnings.append("No revocation endpoint — status not verified")

    # All checks passed
    result.valid = True
    return result
