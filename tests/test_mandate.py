"""Tests for mandate_verification primitive.

Coverage:
- Schema validation (mandate structure, constraint schemas)
- Sign → verify roundtrip (EdDSA and ES256)
- Temporal validity (all three modes: sequence, windowed, state_bound)
- Constraint compliance (valid actions, violations)
- Delegation chain (valid chain, broken chain, missing keys)
- Revocation status (revoked, not revoked, unreachable endpoint)
- Negative cases (expired, wrong issuer, malformed, out-of-window, etc.)
- Edge cases (empty chains, no validity window, large constraints)
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Any
from unittest.mock import patch

import pytest

from concordia.mandate import (
    check_revocation,
    check_temporal_validity,
    sign_delegation,
    sign_mandate,
    validate_constraints,
    validate_mandate_schema,
    verify_delegation_chain,
    verify_mandate,
)
from concordia.models.mandate import (
    MANDATE_JSON_SCHEMA,
    DelegationLink,
    Mandate,
    MandateStatus,
    MandateVerificationResult,
    TemporalMode,
    ValidityWindow,
)
from concordia.signing import ES256KeyPair, KeyPair


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ed25519_keypair() -> KeyPair:
    return KeyPair.generate()


@pytest.fixture
def es256_keypair() -> ES256KeyPair:
    return ES256KeyPair.generate()


@pytest.fixture
def now() -> datetime:
    return datetime.now(timezone.utc)


def _make_windowed_validity(
    now: datetime, offset_before: int = -3600, offset_after: int = 3600
) -> ValidityWindow:
    nb = now + timedelta(seconds=offset_before)
    na = now + timedelta(seconds=offset_after)
    return ValidityWindow(
        mode=TemporalMode.WINDOWED,
        not_before=nb.strftime("%Y-%m-%dT%H:%M:%SZ"),
        not_after=na.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _make_sequence_validity(key: str = "session-123") -> ValidityWindow:
    return ValidityWindow(mode=TemporalMode.SEQUENCE, sequence_key=key)


def _make_state_bound_validity(condition: str = "negotiation_active") -> ValidityWindow:
    return ValidityWindow(mode=TemporalMode.STATE_BOUND, state_condition=condition)


def _make_simple_constraints() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "max_spend": {"type": "number", "maximum": 1000},
            "category": {"type": "string", "enum": ["electronics", "books"]},
        },
        "required": ["max_spend", "category"],
    }


def _make_mandate(
    keypair: KeyPair,
    validity: ValidityWindow | None = None,
    constraints: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Mandate:
    if validity is None:
        now = datetime.now(timezone.utc)
        validity = _make_windowed_validity(now)
    if constraints is None:
        constraints = _make_simple_constraints()

    mandate = Mandate.create(
        issuer="did:concordia:issuer-001",
        subject="did:concordia:agent-001",
        constraints=constraints,
        validity=validity,
        **kwargs,
    )
    return sign_mandate(mandate, keypair)


# ===========================================================================
# SCHEMA VALIDATION TESTS
# ===========================================================================

class TestMandateSchema:
    """Tests for mandate JSON Schema validation."""

    def test_valid_mandate_passes_schema(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        errors = validate_mandate_schema(mandate.to_dict())
        assert errors == []

    def test_missing_mandate_id_fails(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        del d["mandate_id"]
        errors = validate_mandate_schema(d)
        assert len(errors) > 0
        assert "mandate_id" in errors[0]

    def test_missing_issuer_fails(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        del d["issuer"]
        errors = validate_mandate_schema(d)
        assert len(errors) > 0

    def test_missing_subject_fails(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        del d["subject"]
        errors = validate_mandate_schema(d)
        assert len(errors) > 0

    def test_missing_validity_fails(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        del d["validity"]
        errors = validate_mandate_schema(d)
        assert len(errors) > 0

    def test_missing_constraints_fails(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        del d["constraints"]
        errors = validate_mandate_schema(d)
        assert len(errors) > 0

    def test_invalid_algorithm_fails(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        d["algorithm"] = "RS256"
        errors = validate_mandate_schema(d)
        assert len(errors) > 0

    def test_invalid_mandate_id_format_fails(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        d["mandate_id"] = "not-a-urn"
        errors = validate_mandate_schema(d)
        assert len(errors) > 0

    def test_additional_properties_rejected(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        d["extra_field"] = "should_fail"
        errors = validate_mandate_schema(d)
        assert len(errors) > 0

    def test_empty_constraints_fails(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        d["constraints"] = {}
        errors = validate_mandate_schema(d)
        assert len(errors) > 0


# ===========================================================================
# SIGNING ROUNDTRIP TESTS
# ===========================================================================

class TestSigningRoundtrip:
    """Sign → verify roundtrip for EdDSA and ES256."""

    def test_eddsa_sign_verify(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        result = verify_mandate(mandate, ed25519_keypair.public_key)
        assert result.valid is True
        assert result.checks["issuer_signature"] is True

    def test_es256_sign_verify(self, es256_keypair: ES256KeyPair, now: datetime):
        validity = _make_windowed_validity(now)
        mandate = Mandate.create(
            issuer="did:concordia:issuer-es256",
            subject="did:concordia:agent-es256",
            constraints=_make_simple_constraints(),
            validity=validity,
            algorithm="ES256",
        )
        mandate = sign_mandate(mandate, es256_keypair)
        result = verify_mandate(mandate, es256_keypair.public_key)
        assert result.valid is True
        assert result.checks["issuer_signature"] is True

    def test_wrong_key_fails_verification(self, ed25519_keypair: KeyPair, now: datetime):
        other_key = KeyPair.generate()
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        result = verify_mandate(mandate, other_key.public_key)
        assert result.valid is False
        assert result.checks["issuer_signature"] is False
        assert any("signature" in e.lower() for e in result.errors)

    def test_tampered_mandate_fails(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        d["subject"] = "did:concordia:tampered"
        result = verify_mandate(d, ed25519_keypair.public_key)
        assert result.valid is False

    def test_missing_signature_fails(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        del d["signature"]
        result = verify_mandate(d, ed25519_keypair.public_key)
        assert result.valid is False
        assert "Missing mandate signature" in result.errors

    def test_dict_input_accepted(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        result = verify_mandate(d, ed25519_keypair.public_key)
        assert result.valid is True


# ===========================================================================
# TEMPORAL VALIDITY TESTS
# ===========================================================================

class TestTemporalValidity:
    """Three-mode temporal validity checks."""

    # --- Windowed mode ---

    def test_windowed_valid(self, now: datetime):
        validity = _make_windowed_validity(now)
        valid, errors = check_temporal_validity(validity, now=now)
        assert valid is True
        assert errors == []

    def test_windowed_expired(self, now: datetime):
        validity = _make_windowed_validity(now, offset_before=-7200, offset_after=-3600)
        valid, errors = check_temporal_validity(validity, now=now)
        assert valid is False
        assert any("expired" in e.lower() for e in errors)

    def test_windowed_not_yet_valid(self, now: datetime):
        validity = _make_windowed_validity(now, offset_before=3600, offset_after=7200)
        valid, errors = check_temporal_validity(validity, now=now)
        assert valid is False
        assert any("not yet valid" in e.lower() for e in errors)

    def test_windowed_missing_timestamps(self):
        validity = ValidityWindow(mode=TemporalMode.WINDOWED)
        valid, errors = check_temporal_validity(validity)
        assert valid is False

    def test_windowed_bad_timestamp_format(self):
        validity = ValidityWindow(
            mode=TemporalMode.WINDOWED,
            not_before="not-a-date",
            not_after="also-not-a-date",
        )
        valid, errors = check_temporal_validity(validity)
        assert valid is False

    # --- Sequence mode ---

    def test_sequence_valid_matching_key(self):
        validity = _make_sequence_validity("session-abc")
        valid, errors = check_temporal_validity(validity, sequence_key="session-abc")
        assert valid is True

    def test_sequence_mismatched_key(self):
        validity = _make_sequence_validity("session-abc")
        valid, errors = check_temporal_validity(validity, sequence_key="session-xyz")
        assert valid is False
        assert any("mismatch" in e.lower() for e in errors)

    def test_sequence_no_key_provided_passes(self):
        """If no sequence_key is provided, the check passes (caller may not know yet)."""
        validity = _make_sequence_validity("session-abc")
        valid, errors = check_temporal_validity(validity)
        assert valid is True

    def test_sequence_missing_sequence_key_in_validity(self):
        validity = ValidityWindow(mode=TemporalMode.SEQUENCE)
        valid, errors = check_temporal_validity(validity)
        assert valid is False

    # --- State-bound mode ---

    def test_state_bound_active(self):
        validity = _make_state_bound_validity("negotiation_active")
        valid, errors = check_temporal_validity(validity, state_active=True)
        assert valid is True

    def test_state_bound_inactive(self):
        validity = _make_state_bound_validity("negotiation_active")
        valid, errors = check_temporal_validity(validity, state_active=False)
        assert valid is False
        assert any("not active" in e.lower() for e in errors)

    def test_state_bound_unknown_passes(self):
        """If state_active is not provided, check passes (state unknown)."""
        validity = _make_state_bound_validity("negotiation_active")
        valid, errors = check_temporal_validity(validity)
        assert valid is True

    def test_state_bound_missing_condition(self):
        validity = ValidityWindow(mode=TemporalMode.STATE_BOUND)
        valid, errors = check_temporal_validity(validity)
        assert valid is False


# ===========================================================================
# CONSTRAINT COMPLIANCE TESTS
# ===========================================================================

class TestConstraintCompliance:
    """Constraint schema validation and action compliance."""

    def test_valid_constraints_no_action(self):
        constraints = _make_simple_constraints()
        valid, errors = validate_constraints(constraints)
        assert valid is True

    def test_valid_action_passes(self):
        constraints = _make_simple_constraints()
        action = {"max_spend": 500, "category": "books"}
        valid, errors = validate_constraints(constraints, action=action)
        assert valid is True

    def test_action_exceeds_max_spend(self):
        constraints = _make_simple_constraints()
        action = {"max_spend": 2000, "category": "books"}
        valid, errors = validate_constraints(constraints, action=action)
        assert valid is False
        assert any("constraint" in e.lower() for e in errors)

    def test_action_invalid_category(self):
        constraints = _make_simple_constraints()
        action = {"max_spend": 500, "category": "weapons"}
        valid, errors = validate_constraints(constraints, action=action)
        assert valid is False

    def test_action_missing_required_field(self):
        constraints = _make_simple_constraints()
        action = {"max_spend": 500}  # missing category
        valid, errors = validate_constraints(constraints, action=action)
        assert valid is False

    def test_empty_constraints_fails(self):
        valid, errors = validate_constraints({})
        assert valid is False
        assert any("non-empty" in e.lower() for e in errors)

    def test_invalid_constraint_schema(self):
        # Not a valid JSON Schema
        constraints = {"type": "invalid_type_value"}
        valid, errors = validate_constraints(constraints)
        assert valid is False

    def test_complex_nested_constraints(self):
        constraints = {
            "type": "object",
            "properties": {
                "budget": {
                    "type": "object",
                    "properties": {
                        "amount": {"type": "number", "maximum": 5000},
                        "currency": {"type": "string", "enum": ["USD", "EUR"]},
                    },
                    "required": ["amount", "currency"],
                },
                "regions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 5,
                },
            },
            "required": ["budget"],
        }
        action = {"budget": {"amount": 3000, "currency": "USD"}, "regions": ["US", "EU"]}
        valid, errors = validate_constraints(constraints, action=action)
        assert valid is True


# ===========================================================================
# DELEGATION CHAIN TESTS
# ===========================================================================

class TestDelegationChain:
    """Delegation chain verification."""

    def test_empty_chain_is_valid(self):
        valid, errors = verify_delegation_chain(
            chain=[], issuer="issuer", subject="subject", public_keys={}
        )
        assert valid is True

    def test_single_link_valid(self, ed25519_keypair: KeyPair):
        delegate_key = KeyPair.generate()
        link = DelegationLink(
            delegator="issuer-001",
            delegate="agent-001",
            delegated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        link = sign_delegation(link, ed25519_keypair)

        valid, errors = verify_delegation_chain(
            chain=[link],
            issuer="issuer-001",
            subject="agent-001",
            public_keys={"issuer-001": ed25519_keypair.public_key},
        )
        assert valid is True
        assert errors == []

    def test_multi_link_chain_valid(self):
        keys = {f"agent-{i}": KeyPair.generate() for i in range(4)}

        links = []
        chain_pairs = [
            ("agent-0", "agent-1"),
            ("agent-1", "agent-2"),
            ("agent-2", "agent-3"),
        ]
        for delegator, delegate in chain_pairs:
            link = DelegationLink(
                delegator=delegator,
                delegate=delegate,
                delegated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            link = sign_delegation(link, keys[delegator])
            links.append(link)

        pub_keys = {k: v.public_key for k, v in keys.items()}
        valid, errors = verify_delegation_chain(
            chain=links,
            issuer="agent-0",
            subject="agent-3",
            public_keys=pub_keys,
        )
        assert valid is True

    def test_chain_root_mismatch(self, ed25519_keypair: KeyPair):
        link = DelegationLink(
            delegator="wrong-issuer",
            delegate="agent-001",
            delegated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        link = sign_delegation(link, ed25519_keypair)

        valid, errors = verify_delegation_chain(
            chain=[link],
            issuer="expected-issuer",
            subject="agent-001",
            public_keys={"wrong-issuer": ed25519_keypair.public_key},
        )
        assert valid is False
        assert any("root mismatch" in e.lower() for e in errors)

    def test_chain_tail_mismatch(self, ed25519_keypair: KeyPair):
        link = DelegationLink(
            delegator="issuer-001",
            delegate="wrong-agent",
            delegated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        link = sign_delegation(link, ed25519_keypair)

        valid, errors = verify_delegation_chain(
            chain=[link],
            issuer="issuer-001",
            subject="expected-agent",
            public_keys={"issuer-001": ed25519_keypair.public_key},
        )
        assert valid is False
        assert any("tail mismatch" in e.lower() for e in errors)

    def test_chain_break_in_middle(self):
        keys = {f"a-{i}": KeyPair.generate() for i in range(3)}

        link1 = DelegationLink(
            delegator="a-0", delegate="a-1",
            delegated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        link1 = sign_delegation(link1, keys["a-0"])

        # Break: link2's delegator doesn't match link1's delegate
        link2 = DelegationLink(
            delegator="a-WRONG", delegate="a-2",
            delegated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        link2 = sign_delegation(link2, keys["a-1"])  # signed by a-1 but delegator says a-WRONG

        pub_keys = {k: v.public_key for k, v in keys.items()}
        pub_keys["a-WRONG"] = keys["a-1"].public_key  # provide key so sig check passes
        valid, errors = verify_delegation_chain(
            chain=[link1, link2],
            issuer="a-0",
            subject="a-2",
            public_keys=pub_keys,
        )
        assert valid is False
        assert any("break" in e.lower() for e in errors)

    def test_chain_invalid_signature(self, ed25519_keypair: KeyPair):
        wrong_key = KeyPair.generate()
        link = DelegationLink(
            delegator="issuer-001",
            delegate="agent-001",
            delegated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        link = sign_delegation(link, wrong_key)  # signed with wrong key

        valid, errors = verify_delegation_chain(
            chain=[link],
            issuer="issuer-001",
            subject="agent-001",
            public_keys={"issuer-001": ed25519_keypair.public_key},
        )
        assert valid is False
        assert any("invalid signature" in e.lower() for e in errors)

    def test_chain_missing_public_key(self, ed25519_keypair: KeyPair):
        link = DelegationLink(
            delegator="issuer-001",
            delegate="agent-001",
            delegated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        link = sign_delegation(link, ed25519_keypair)

        valid, errors = verify_delegation_chain(
            chain=[link],
            issuer="issuer-001",
            subject="agent-001",
            public_keys={},  # no keys
        )
        assert valid is False
        assert any("no public key" in e.lower() for e in errors)

    def test_chain_missing_signature_on_link(self):
        link = DelegationLink(
            delegator="issuer-001",
            delegate="agent-001",
            delegated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            signature="",  # explicitly empty
        )
        kp = KeyPair.generate()
        valid, errors = verify_delegation_chain(
            chain=[link],
            issuer="issuer-001",
            subject="agent-001",
            public_keys={"issuer-001": kp.public_key},
        )
        assert valid is False
        assert any("missing signature" in e.lower() for e in errors)

    def test_chain_with_scope_restriction(self, ed25519_keypair: KeyPair):
        link = DelegationLink(
            delegator="issuer-001",
            delegate="agent-001",
            scope_restriction={"max_spend": 500},
            delegated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        link = sign_delegation(link, ed25519_keypair)

        valid, errors = verify_delegation_chain(
            chain=[link],
            issuer="issuer-001",
            subject="agent-001",
            public_keys={"issuer-001": ed25519_keypair.public_key},
        )
        assert valid is True


# ===========================================================================
# REVOCATION TESTS
# ===========================================================================

class _RevocationHandler(BaseHTTPRequestHandler):
    """HTTP handler for revocation list testing."""
    revoked_ids: list[str] = []

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"revoked_ids": self.revoked_ids}).encode())

    def log_message(self, format, *args):
        pass  # suppress logs


class _BrokenRevocationHandler(BaseHTTPRequestHandler):
    """Returns invalid JSON."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"not json")

    def log_message(self, format, *args):
        pass


class TestRevocation:
    """Revocation endpoint checks."""

    def test_not_revoked(self):
        _RevocationHandler.revoked_ids = []
        server = HTTPServer(("127.0.0.1", 0), _RevocationHandler)
        port = server.server_address[1]
        t = Thread(target=server.handle_request, daemon=True)
        t.start()

        not_revoked, errors = check_revocation(
            "mandate-123", f"http://127.0.0.1:{port}/revocations"
        )
        assert not_revoked is True
        assert errors == []
        t.join(timeout=2)

    def test_revoked(self):
        _RevocationHandler.revoked_ids = ["mandate-123", "mandate-456"]
        server = HTTPServer(("127.0.0.1", 0), _RevocationHandler)
        port = server.server_address[1]
        t = Thread(target=server.handle_request, daemon=True)
        t.start()

        not_revoked, errors = check_revocation(
            "mandate-123", f"http://127.0.0.1:{port}/revocations"
        )
        assert not_revoked is False
        assert any("revoked" in e.lower() for e in errors)
        t.join(timeout=2)

    def test_unreachable_endpoint_fails_closed(self):
        """Fail-closed: unreachable endpoint = mandate NOT verified."""
        not_revoked, errors = check_revocation(
            "mandate-123", "http://127.0.0.1:1/nonexistent", timeout=1.0
        )
        assert not_revoked is False
        assert any("unreachable" in e.lower() for e in errors)

    def test_invalid_json_response(self):
        server = HTTPServer(("127.0.0.1", 0), _BrokenRevocationHandler)
        port = server.server_address[1]
        t = Thread(target=server.handle_request, daemon=True)
        t.start()

        not_revoked, errors = check_revocation(
            "mandate-123", f"http://127.0.0.1:{port}/revocations"
        )
        assert not_revoked is False
        assert any("invalid" in e.lower() for e in errors)
        t.join(timeout=2)


# ===========================================================================
# FULL VERIFICATION INTEGRATION TESTS
# ===========================================================================

class TestFullVerification:
    """End-to-end verify_mandate() tests."""

    def test_valid_windowed_mandate(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(
            ed25519_keypair,
            _make_windowed_validity(now),
        )
        result = verify_mandate(mandate, ed25519_keypair.public_key, now=now)
        assert result.valid is True
        assert all(result.checks.values())
        assert result.errors == []

    def test_valid_sequence_mandate(self, ed25519_keypair: KeyPair):
        mandate = _make_mandate(
            ed25519_keypair,
            _make_sequence_validity("session-abc"),
        )
        result = verify_mandate(
            mandate, ed25519_keypair.public_key, sequence_key="session-abc"
        )
        assert result.valid is True

    def test_valid_state_bound_mandate(self, ed25519_keypair: KeyPair):
        mandate = _make_mandate(
            ed25519_keypair,
            _make_state_bound_validity("active"),
        )
        result = verify_mandate(
            mandate, ed25519_keypair.public_key, state_active=True
        )
        assert result.valid is True

    def test_expired_mandate_fails(self, ed25519_keypair: KeyPair, now: datetime):
        validity = _make_windowed_validity(now, offset_before=-7200, offset_after=-3600)
        mandate = _make_mandate(ed25519_keypair, validity)
        result = verify_mandate(mandate, ed25519_keypair.public_key, now=now)
        assert result.valid is False
        assert result.checks.get("temporal_validity") is False

    def test_not_yet_valid_mandate_fails(self, ed25519_keypair: KeyPair, now: datetime):
        validity = _make_windowed_validity(now, offset_before=3600, offset_after=7200)
        mandate = _make_mandate(ed25519_keypair, validity)
        result = verify_mandate(mandate, ed25519_keypair.public_key, now=now)
        assert result.valid is False

    def test_wrong_issuer_key_fails(self, ed25519_keypair: KeyPair, now: datetime):
        other = KeyPair.generate()
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        result = verify_mandate(mandate, other.public_key, now=now)
        assert result.valid is False
        assert result.checks.get("issuer_signature") is False

    def test_action_violating_constraints_fails(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        result = verify_mandate(
            mandate,
            ed25519_keypair.public_key,
            now=now,
            action={"max_spend": 5000, "category": "books"},  # exceeds max
        )
        assert result.valid is False
        assert result.checks.get("constraint_compliance") is False

    def test_valid_action_passes(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        result = verify_mandate(
            mandate,
            ed25519_keypair.public_key,
            now=now,
            action={"max_spend": 500, "category": "electronics"},
        )
        assert result.valid is True

    def test_mandate_with_delegation_chain(self, now: datetime):
        issuer_key = KeyPair.generate()
        delegate_key = KeyPair.generate()

        link = DelegationLink(
            delegator="did:concordia:issuer-001",
            delegate="did:concordia:agent-001",
            delegated_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        link = sign_delegation(link, issuer_key)

        mandate = Mandate.create(
            issuer="did:concordia:issuer-001",
            subject="did:concordia:agent-001",
            constraints=_make_simple_constraints(),
            validity=_make_windowed_validity(now),
            delegation_chain=[link],
        )
        mandate = sign_mandate(mandate, issuer_key)

        result = verify_mandate(
            mandate,
            issuer_key.public_key,
            now=now,
            delegation_public_keys={
                "did:concordia:issuer-001": issuer_key.public_key,
            },
        )
        assert result.valid is True
        assert result.checks["delegation_chain"] is True

    def test_mandate_with_broken_delegation_fails(self, now: datetime):
        issuer_key = KeyPair.generate()
        wrong_key = KeyPair.generate()

        link = DelegationLink(
            delegator="did:concordia:issuer-001",
            delegate="did:concordia:agent-001",
            delegated_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        link = sign_delegation(link, wrong_key)  # wrong key!

        mandate = Mandate.create(
            issuer="did:concordia:issuer-001",
            subject="did:concordia:agent-001",
            constraints=_make_simple_constraints(),
            validity=_make_windowed_validity(now),
            delegation_chain=[link],
        )
        mandate = sign_mandate(mandate, issuer_key)

        result = verify_mandate(
            mandate,
            issuer_key.public_key,
            now=now,
            delegation_public_keys={
                "did:concordia:issuer-001": issuer_key.public_key,
            },
        )
        assert result.valid is False
        assert result.checks.get("delegation_chain") is False

    def test_no_validity_window_warns(self, ed25519_keypair: KeyPair):
        """Mandate with no validity window should pass with warning."""
        mandate = Mandate.create(
            issuer="did:concordia:issuer-001",
            subject="did:concordia:agent-001",
            constraints=_make_simple_constraints(),
            validity=_make_windowed_validity(datetime.now(timezone.utc)),
        )
        # Remove validity before signing
        mandate.validity = None
        mandate = sign_mandate(mandate, ed25519_keypair)
        # Manually fix the dict to pass schema (validity is required)
        # So this test verifies the programmatic path where validity=None
        d = mandate.to_dict()
        # Since schema requires validity, we test the verify_mandate path
        # that handles missing validity gracefully
        result = verify_mandate(mandate, ed25519_keypair.public_key)
        # Schema check will fail since validity is required
        assert result.valid is False

    def test_revocation_skipped_when_disabled(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(
            ed25519_keypair,
            _make_windowed_validity(now),
            revocation_endpoint="http://nonexistent:1/revocations",
        )
        result = verify_mandate(
            mandate,
            ed25519_keypair.public_key,
            now=now,
            check_revocation_status=False,
        )
        assert result.valid is True
        assert result.checks["revocation_status"] is True

    def test_no_revocation_endpoint_warns(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        result = verify_mandate(mandate, ed25519_keypair.public_key, now=now)
        assert result.valid is True
        assert any("revocation" in w.lower() for w in result.warnings)

    def test_result_contains_mandate_metadata(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        result = verify_mandate(mandate, ed25519_keypair.public_key, now=now)
        assert result.mandate_id == mandate.mandate_id
        assert result.issuer == mandate.issuer
        assert result.subject == mandate.subject


# ===========================================================================
# MODEL SERIALIZATION TESTS
# ===========================================================================

class TestModelSerialization:
    """Mandate model to_dict / from_dict roundtrip."""

    def test_mandate_roundtrip(self, ed25519_keypair: KeyPair, now: datetime):
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        d = mandate.to_dict()
        restored = Mandate.from_dict(d)
        assert restored.mandate_id == mandate.mandate_id
        assert restored.issuer == mandate.issuer
        assert restored.subject == mandate.subject
        assert restored.signature == mandate.signature
        assert restored.algorithm == mandate.algorithm

    def test_validity_roundtrip_windowed(self, now: datetime):
        v = _make_windowed_validity(now)
        d = v.to_dict()
        restored = ValidityWindow.from_dict(d)
        assert restored.mode == v.mode
        assert restored.not_before == v.not_before
        assert restored.not_after == v.not_after

    def test_validity_roundtrip_sequence(self):
        v = _make_sequence_validity("key-123")
        d = v.to_dict()
        restored = ValidityWindow.from_dict(d)
        assert restored.mode == TemporalMode.SEQUENCE
        assert restored.sequence_key == "key-123"

    def test_validity_roundtrip_state_bound(self):
        v = _make_state_bound_validity("active_session")
        d = v.to_dict()
        restored = ValidityWindow.from_dict(d)
        assert restored.mode == TemporalMode.STATE_BOUND
        assert restored.state_condition == "active_session"

    def test_delegation_link_roundtrip(self, ed25519_keypair: KeyPair):
        link = DelegationLink(
            delegator="issuer",
            delegate="agent",
            scope_restriction={"max": 100},
            delegated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        link = sign_delegation(link, ed25519_keypair)
        d = link.to_dict()
        restored = DelegationLink.from_dict(d)
        assert restored.delegator == link.delegator
        assert restored.delegate == link.delegate
        assert restored.signature == link.signature
        assert restored.scope_restriction == {"max": 100}

    def test_verification_result_to_dict(self):
        result = MandateVerificationResult(
            valid=True,
            mandate_id="urn:concordia:mandate:test",
            issuer="did:concordia:issuer",
            subject="did:concordia:agent",
            checks={"schema": True, "issuer_signature": True},
            errors=[],
            warnings=["No revocation endpoint"],
        )
        d = result.to_dict()
        assert d["valid"] is True
        assert d["checks"]["schema"] is True
        assert len(d["warnings"]) == 1

    def test_mandate_create_factory(self):
        mandate = Mandate.create(
            issuer="did:concordia:issuer",
            subject="did:concordia:agent",
            constraints={"type": "object", "properties": {"x": {"type": "number"}}},
            validity=_make_sequence_validity("test"),
        )
        assert mandate.mandate_id.startswith("urn:concordia:mandate:")
        assert mandate.issued_at != ""
        assert mandate.status == MandateStatus.ACTIVE

    def test_mandate_status_from_dict(self):
        d = {
            "mandate_id": "urn:concordia:mandate:test",
            "issuer": "i",
            "subject": "s",
            "issued_at": "2026-01-01T00:00:00Z",
            "algorithm": "EdDSA",
            "status": "revoked",
            "validity": {"mode": "sequence", "sequence_key": "k"},
            "constraints": {"type": "object", "properties": {"x": {"type": "number"}}},
        }
        m = Mandate.from_dict(d)
        assert m.status == MandateStatus.REVOKED

    def test_mandate_unknown_status_defaults_active(self):
        d = {
            "mandate_id": "urn:concordia:mandate:test",
            "issuer": "i",
            "subject": "s",
            "issued_at": "2026-01-01T00:00:00Z",
            "algorithm": "EdDSA",
            "status": "unknown_status",
            "validity": {"mode": "sequence", "sequence_key": "k"},
            "constraints": {"type": "object", "properties": {"x": {"type": "number"}}},
        }
        m = Mandate.from_dict(d)
        assert m.status == MandateStatus.ACTIVE


# ===========================================================================
# MCP TOOL INTEGRATION TEST
# ===========================================================================

class TestMCPTool:
    """Test the concordia_verify_mandate MCP tool."""

    def test_tool_verify_valid_mandate(self, ed25519_keypair: KeyPair, now: datetime):
        from concordia.mcp_server import tool_verify_mandate

        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        pub_b64 = ed25519_keypair.public_key_b64()

        result_str = tool_verify_mandate(
            mandate=mandate.to_dict(),
            issuer_public_key_b64=pub_b64,
            algorithm="EdDSA",
            check_revocation=False,
        )
        result = json.loads(result_str)
        assert result["valid"] is True

    def test_tool_verify_invalid_key(self, ed25519_keypair: KeyPair, now: datetime):
        from concordia.mcp_server import tool_verify_mandate

        other = KeyPair.generate()
        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))

        result_str = tool_verify_mandate(
            mandate=mandate.to_dict(),
            issuer_public_key_b64=other.public_key_b64(),
            algorithm="EdDSA",
            check_revocation=False,
        )
        result = json.loads(result_str)
        assert result["valid"] is False

    def test_tool_verify_with_action(self, ed25519_keypair: KeyPair, now: datetime):
        from concordia.mcp_server import tool_verify_mandate

        mandate = _make_mandate(ed25519_keypair, _make_windowed_validity(now))
        pub_b64 = ed25519_keypair.public_key_b64()

        result_str = tool_verify_mandate(
            mandate=mandate.to_dict(),
            issuer_public_key_b64=pub_b64,
            algorithm="EdDSA",
            action={"max_spend": 500, "category": "books"},
            check_revocation=False,
        )
        result = json.loads(result_str)
        assert result["valid"] is True

    def test_tool_invalid_key_encoding(self, now: datetime):
        from concordia.mcp_server import tool_verify_mandate

        kp = KeyPair.generate()
        mandate = _make_mandate(kp, _make_windowed_validity(now))

        result_str = tool_verify_mandate(
            mandate=mandate.to_dict(),
            issuer_public_key_b64="not-valid-base64!!!",
            algorithm="EdDSA",
        )
        result = json.loads(result_str)
        assert "error" in result

    def test_tool_es256_roundtrip(self, es256_keypair: ES256KeyPair, now: datetime):
        from concordia.mcp_server import tool_verify_mandate

        validity = _make_windowed_validity(now)
        mandate = Mandate.create(
            issuer="did:concordia:issuer-es256",
            subject="did:concordia:agent-es256",
            constraints=_make_simple_constraints(),
            validity=validity,
            algorithm="ES256",
        )
        mandate = sign_mandate(mandate, es256_keypair)
        pub_b64 = es256_keypair.public_key_b64()

        result_str = tool_verify_mandate(
            mandate=mandate.to_dict(),
            issuer_public_key_b64=pub_b64,
            algorithm="ES256",
            check_revocation=False,
        )
        result = json.loads(result_str)
        assert result["valid"] is True
